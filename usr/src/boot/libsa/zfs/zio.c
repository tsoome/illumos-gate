/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/sysmacros.h>
#include <sys/zfs_context.h>
#include <sys/vdev_impl.h>
#include <sys/zio_compress.h>
#include <sys/zio_checksum.h>

#define	ZIO_PIPELINE_CONTINUE		0x100
#define	ZIO_PIPELINE_STOP		0x101

extern int zio_checksum_error(zio_t *, zio_bad_cksum_t *);

static void zio_destroy(zio_t *);

void *
zio_buf_alloc(size_t size)
{
	size_t c = (size - 1) >> SPA_MINBLOCKSHIFT;

	VERIFY3U(c, <, SPA_MAXBLOCKSIZE >> SPA_MINBLOCKSHIFT);

	return (malloc(size));
}

void
zio_buf_free(void *buf, size_t size)
{
	size_t c = (size - 1) >> SPA_MINBLOCKSHIFT;

	VERIFY3U(c, <, SPA_MAXBLOCKSIZE >> SPA_MINBLOCKSHIFT);

	free(buf);
}

void
zio_push_transform(zio_t *zio, abd_t *data, uint64_t size, uint64_t bufsize,
    zio_transform_func_t *transform)
{
	zio_transform_t *zt = malloc(sizeof (zio_transform_t));
	if (zt == NULL) {
		zio->io_error = ENOMEM;
		return;
	}

	/*
	 * Ensure that anyone expecting this zio to contain a linear ABD isn't
	 * going to get a nasty surprise when they try to access the data.
	 */
	IMPLY(abd_is_linear(zio->io_abd), abd_is_linear(data));

	zt->zt_orig_abd = zio->io_abd;
	zt->zt_orig_size = zio->io_size;
	zt->zt_bufsize = bufsize;
	zt->zt_transform = transform;

	zt->zt_next = zio->io_transform_stack;
	zio->io_transform_stack = zt;

	zio->io_abd = data;
	zio->io_size = size;
}

void
zio_pop_transforms(zio_t *zio)
{
	zio_transform_t *zt;

	while ((zt = zio->io_transform_stack) != NULL) {
		if (zt->zt_transform != NULL)
			zt->zt_transform(zio,
			    zt->zt_orig_abd, zt->zt_orig_size);

		if (zt->zt_bufsize != 0)
			abd_free(zio->io_abd);

		zio->io_abd = zt->zt_orig_abd;
		zio->io_size = zt->zt_orig_size;
		zio->io_transform_stack = zt->zt_next;

		free(zt);
	}
}

static void
zio_subblock(zio_t *zio, abd_t *data, uint64_t size)
{
	ASSERT(zio->io_size > size);

	if (zio->io_type == ZIO_TYPE_READ)
		abd_copy(data, zio->io_abd, size);
}

static void
zio_decompress(zio_t *zio, abd_t *data, uint64_t size)
{
	if (zio->io_error == 0) {
		void *tmp = abd_borrow_buf(data, size);
		int ret = zio_decompress_data(BP_GET_COMPRESS(zio->io_bp),
		    zio->io_abd, tmp, zio->io_size, size);

		abd_return_buf_copy(data, tmp, size);

		if (ret != 0)
			zio->io_error = EIO;
	}
}

static zio_t *
zio_walk_parents(zio_t *cio, zio_link_t **zl)
{
	list_t *pl = &cio->io_parent_list;

	*zl = (*zl == NULL) ? list_head(pl) : list_next(pl, *zl);
	if (*zl == NULL)
		return (NULL);

	ASSERT((*zl)->zl_child == cio);
	return ((*zl)->zl_parent);
}

static zio_t *
zio_walk_children(zio_t *pio, zio_link_t **zl)
{
	list_t *cl = &pio->io_child_list;

	*zl = (*zl == NULL) ? list_head(cl) : list_next(cl, *zl);
	if (*zl == NULL)
		return (NULL);

	ASSERT((*zl)->zl_parent == pio);
	return ((*zl)->zl_child);
}

static zio_t *
zio_unique_parent(zio_t *cio)
{
	zio_link_t *zl = NULL;
	zio_t *pio = zio_walk_parents(cio, &zl);

	VERIFY3P(zio_walk_parents(cio, &zl), ==, NULL);
	return (pio);
}

static int
zio_add_child(zio_t *pio, zio_t *cio)
{
	zio_link_t *zl = malloc(sizeof (*zl));

	if (zl == NULL)
		return (ENOMEM);

        /*
         * Logical I/Os can have logical, gang, or vdev children.
         * Gang I/Os can have gang or vdev children.
         * Vdev I/Os can only have vdev children.
         * The following ASSERT captures all of these constraints.
         */
	ASSERT3S(cio->io_child_type, <=, pio->io_child_type);

	zl->zl_parent = pio;
	zl->zl_child = cio;

	ASSERT(pio->io_state[ZIO_WAIT_DONE] == 0);

	for (int w = 0; w < ZIO_WAIT_TYPES; w++)
		pio->io_children[cio->io_child_type][w] += !cio->io_state[w];

	list_insert_head(&pio->io_child_list, zl);
	list_insert_head(&cio->io_parent_list, zl);

	pio->io_child_count++;
	cio->io_parent_count++;
	return (0);
}

static void
zio_remove_child(zio_t *pio, zio_t *cio, zio_link_t *zl)
{
	ASSERT(zl->zl_parent == pio);
	ASSERT(zl->zl_child == cio);

	list_remove(&pio->io_child_list, zl);
	list_remove(&cio->io_parent_list, zl);

	pio->io_child_count--;
	cio->io_parent_count--;

	free(zl);
}

static boolean_t
zio_wait_for_children(zio_t *zio, uint8_t childbits, enum zio_wait_type wait)
{
	boolean_t waiting = B_FALSE;

	for (int c = 0; c < ZIO_CHILD_TYPES; c++) {
		if (!(ZIO_CHILD_BIT_IS_SET(childbits, c)))
			continue;

		uint64_t *countp = &zio->io_children[c][wait];
		if (*countp != 0) {
			zio->io_stage >>= 1;
			ASSERT3U(zio->io_stage, !=, ZIO_STAGE_OPEN);
			zio->io_stall = countp;
			waiting = B_TRUE;
			break;
		}
	}
	return (waiting);
}

static void
zio_notify_parent(zio_t *pio, zio_t *zio, enum zio_wait_type wait)
{
	uint64_t *countp = &pio->io_children[zio->io_child_type][wait];
	int *errorp = &pio->io_child_error[zio->io_child_type];

	if (zio->io_error && !(zio->io_flags & ZIO_FLAG_DONT_PROPAGATE))
		*errorp = zio_worst_error(*errorp, zio->io_error);
	pio->io_reexecute |= zio->io_reexecute;
	ASSERT3U(*countp, >, 0);

	(*countp)--;

	if (*countp == 0 && pio->io_stall == countp) {
		pio->io_stall = NULL;
		zio_execute(pio);
	}
}

static void
zio_inherit_child_errors(zio_t *zio, enum zio_child c)
{
	if (zio->io_child_error[c] != 0 && zio->io_error == 0)
		zio->io_error = zio->io_child_error[c];
}

static zio_t *
zio_create(zio_t *pio, spa_t *spa, const blkptr_t *bp,
    abd_t *data, uint64_t lsize, uint64_t psize, zio_done_func_t *done,
    void *private, zio_type_t type, enum zio_flag flags,
    vdev_t *vd, uint64_t offset, enum zio_stage stage, enum zio_stage pipeline)
{
	zio_t *zio;

	zio = calloc(1, sizeof (*zio));
	if (zio == NULL)
		return (zio);

	list_create(&zio->io_parent_list, sizeof (zio_link_t),
	    offsetof(zio_link_t, zl_parent_node));
	list_create(&zio->io_child_list, sizeof (zio_link_t),
	    offsetof(zio_link_t, zl_child_node));

	if (vd != NULL)
		zio->io_child_type = ZIO_CHILD_VDEV;
	else if (flags & ZIO_FLAG_GANG_CHILD)
		zio->io_child_type = ZIO_CHILD_GANG;
	else if (flags & ZIO_FLAG_DDT_CHILD)
		zio->io_child_type = ZIO_CHILD_DDT;
	else
		zio->io_child_type = ZIO_CHILD_LOGICAL;

	if (bp != NULL) {
		zio->io_bp = (blkptr_t *)bp;
		if (zio->io_child_type == ZIO_CHILD_LOGICAL)
			zio->io_logical = zio;
		if (zio->io_child_type > ZIO_CHILD_GANG && BP_IS_GANG(bp))
			pipeline |= ZIO_GANG_STAGES;
	}
	zio->io_spa = spa;
	zio->io_done = done;
	zio->io_private = private;
	zio->io_type = type;
	zio->io_vd = vd;
	zio->io_offset = offset;
	zio->io_abd = data;
	zio->io_size = psize;
	zio->io_lsize = lsize;
	zio->io_flags = flags;
	zio->io_stage = stage;
	zio->io_pipeline = pipeline;

	if (pio != NULL) {
		if (zio->io_logical == NULL)
			zio->io_logical = pio->io_logical;
		if (zio->io_child_type == ZIO_CHILD_GANG)
			zio->io_gang_leader = pio->io_gang_leader;
		if (zio_add_child(pio, zio) != 0) {
			zio_destroy(zio);
			zio = NULL;
		}
	}
	return (zio);
}

static void
zio_destroy(zio_t *zio)
{
	list_destroy(&zio->io_parent_list);
	list_destroy(&zio->io_child_list);
	free(zio);
}

zio_t *
zio_null(zio_t *pio, spa_t *spa, vdev_t *vd, zio_done_func_t *done,
    void *private, enum zio_flag flags)
{
	zio_t *zio;

	zio = zio_create(pio, spa, NULL, NULL, 0, 0, done, private,
	    ZIO_TYPE_NULL, flags, vd, 0, ZIO_STAGE_OPEN,
	    ZIO_INTERLOCK_PIPELINE);

	return (zio);
}

zio_t *
zio_root(spa_t *spa, zio_done_func_t *done, void *private, enum zio_flag flags)
{
	return (zio_null(NULL, spa, NULL, done, private, flags));
}

zio_t *
zio_read(zio_t *pio, spa_t *spa, const blkptr_t *bp,
    abd_t *data, uint64_t size, zio_done_func_t *done, void *private,
    enum zio_flag flags)
{
	zio_t *zio;

	// zfs_blkptr_verify(spa, bp);

	zio = zio_create(pio, spa, bp, data, size, size, done, private,
	    ZIO_TYPE_READ, flags, NULL, 0, ZIO_STAGE_OPEN, ZIO_READ_PIPELINE);

	return (zio);
}

zio_t *
zio_read_phys(zio_t *pio, vdev_t *vd, uint64_t offset, uint64_t size,
    abd_t *data, int checksum, zio_done_func_t *done, void *private,
    enum zio_flag flags, boolean_t labels)
{
	zio_t *zio;

	ASSERT(vd->vdev_children == 0);
	ASSERT(!labels || offset + size <= VDEV_LABEL_START_SIZE ||
	    offset >= vd->vdev_psize - VDEV_LABEL_END_SIZE);
	ASSERT3U(offset + size, <=, vd->vdev_psize);

	zio = zio_create(pio, vd->vdev_spa, 0, NULL, data, size, size, done,
	    private, ZIO_TYPE_READ, flags | ZIO_FLAG_PHYSICAL, vd,
	    offset, NULL, ZIO_STAGE_OPEN, ZIO_READ_PHYS_PIPELINE);

	zio->io_prop.zp_checksum = checksum;

	return (zio);
}

zio_t *
zio_write_phys(zio_t *pio, vdev_t *vd, uint64_t offset, uint64_t size,
    abd_t *data, int checksum, zio_done_func_t *done, void *private,
    enum zio_flag flags, boolean_t labels)
{
	zio_t *zio;

	ASSERT(vd->vdev_children == 0);
	ASSERT(!labels || offset + size <= VDEV_LABEL_START_SIZE ||
	    offset >= vd->vdev_psize - VDEV_LABEL_END_SIZE);
	ASSERT3U(offset + size, <=, vd->vdev_psize);

	zio = zio_create(pio, vd->vdev_spa, 0, NULL, data, size, size, done,
	    private, ZIO_TYPE_WRITE, flags | ZIO_FLAG_PHYSICAL, vd,
	    offset, NULL, ZIO_STAGE_OPEN, ZIO_WRITE_PHYS_PIPELINE);

	zio->io_prop.zp_checksum = checksum;

	if (zio_checksum_table[checksum].ci_flags & ZCHECKSUM_FLAG_EMBEDDED) {
		/*
		 * zec checksums are necessarily destructive -- they modify
		 * the end of the write buffer to hold the verifier/checksum.
		 * Therefore, we must make a local copy in case the data is
		 * being written to multiple places in parallel.
		 */
		abd_t *wbuf = abd_alloc_sametype(data, size);
		abd_copy(wbuf, data, size);

		zio_push_transform(zio, wbuf, size, size, NULL);
	}

	return (zio);
}

zio_t *
zio_vdev_child_io(zio_t *pio, blkptr_t *bp, vdev_t *vd, uint64_t offset,
    abd_t *data, uint64_t size, int type, enum zio_flag flags,
    zio_done_func_t *done, void *private)
{
	enum zio_stage pipeline = ZIO_VDEV_CHILD_PIPELINE;
	zio_t *zio;

	if (type == ZIO_TYPE_READ && bp != NULL) {
		pipeline |= ZIO_STAGE_CHECKSUM_VERIFY;
		pio->io_pipeline &= ~ZIO_STAGE_CHECKSUM_VERIFY;
	}

	if (vd->vdev_ops->vdev_op_leaf) {
                ASSERT0(vd->vdev_children);
                offset += VDEV_LABEL_START_SIZE;
        }

	flags |= ZIO_VDEV_CHILD_FLAGS(pio);

	zio = zio_create(pio, pio->io_spa, bp, data, size, size, done,
	    private, type, flags, vd, offset,
	    ZIO_STAGE_VDEV_IO_START >> 1, pipeline);

	zio->io_physdone = pio->io_physdone;
	if (vd->vdev_ops->vdev_op_leaf && zio->io_logical != NULL)
		zio->io_logical->io_phys_children++;

	return (zio);
}

static int
zio_read_bp_init(zio_t *zio)
{
	blkptr_t *bp = zio->io_bp;
	uint64_t psize =
	    BP_IS_EMBEDDED(bp) ? BPE_GET_PSIZE(bp) : BP_GET_PSIZE(bp);

	ASSERT3P(zio->io_bp, ==, &zio->io_bp_copy);

	if (BP_GET_COMPRESS(bp) != ZIO_COMPRESS_OFF &&
	    zio->io_child_type == ZIO_CHILD_LOGICAL &&
	    !(zio->io_flags & ZIO_FLAG_RAW_COMPRESS)) {
		zio_push_transform(zio, abd_alloc_sametype(zio->io_abd, psize),
		    psize, psize, zio_decompress);
	}

#if 0
	if (((BP_IS_PROTECTED(bp) && !(zio->io_flags & ZIO_FLAG_RAW_ENCRYPT)) ||
	    BP_HAS_INDIRECT_MAC_CKSUM(bp)) &&
	    zio->io_child_type == ZIO_CHILD_LOGICAL) {
		zio_push_transform(zio, abd_alloc_sametype(zio->io_abd, psize),
		    psize, psize, zio_decrypt);
	}
#endif

	if (BP_IS_EMBEDDED(bp) && BPE_GET_ETYPE(bp) == BP_EMBEDDED_TYPE_DATA) {
		int psize = BPE_GET_PSIZE(bp);
		void *data = abd_borrow_buf(zio->io_abd, psize);

		zio->io_pipeline = ZIO_INTERLOCK_PIPELINE;
		decode_embedded_bp_compressed(bp, data);
		abd_return_buf_copy(zio->io_abd, data, psize);
	} else {
		ASSERT(!BP_IS_EMBEDDED(bp));
		ASSERT3P(zio->io_bp, ==, &zio->io_bp_copy);
	}

	if (!DMU_OT_IS_METADATA(BP_GET_TYPE(bp)) && BP_GET_LEVEL(bp) == 0)
		zio->io_flags |= ZIO_FLAG_DONT_CACHE;

	if (BP_GET_TYPE(bp) == DMU_OT_DDT_ZAP)
		zio->io_flags |= ZIO_FLAG_DONT_CACHE;

	if (BP_GET_DEDUP(bp) && zio->io_child_type == ZIO_CHILD_LOGICAL)
		zio->io_pipeline = ZIO_DDT_READ_PIPELINE;

	return (ZIO_PIPELINE_CONTINUE);
}

static int
zio_free_bp_init(zio_t *zio)
{
	blkptr_t *bp = zio->io_bp;

	if (zio->io_child_type == ZIO_CHILD_LOGICAL) {
		if (BP_GET_DEDUP(bp))
			zio->io_pipeline = ZIO_DDT_FREE_PIPELINE;
	}

	ASSERT3P(zio->io_bp, ==, &zio->io_bp_copy);

	return (ZIO_PIPELINE_CONTINUE);
}

static zio_pipe_stage_t *zio_pipeline[];

void
zio_execute(zio_t *zio)
{
	while (zio->io_stage < ZIO_STAGE_DONE) {
		enum zio_stage pipeline = zio->io_pipeline;
		enum zio_stage stage = zio->io_stage;
		int rv;

		ASSERT(ISP2(stage));

		do {
			stage <<= 1;
		} while ((stage & pipeline) == 0);

		ASSERT(stage <= ZIO_STAGE_DONE);

		zio->io_stage = stage;
		rv = zio_pipeline[ilog2(stage) - 1](zio);

		if (rv == ZIO_PIPELINE_STOP)
			return;

		ASSERT(rv == ZIO_PIPELINE_CONTINUE);
	}
}

int
zio_wait(zio_t *zio)
{
	int error;

	ASSERT3P(zio->io_stage, ==, ZIO_STAGE_OPEN);
	zio_execute(zio);

	error = zio->io_error;
	zio_destroy(zio);

	return (error);
}

/*
 * loader does not really do async.
 */
void
zio_nowait(zio_t *zio)
{
	if (zio->io_child_type == ZIO_CHILD_LOGICAL &&
	    zio_unique_parent(zio) == NULL) {
		/*
		 * This is a logical async I/O with no parent to wait for it.
		 * We add it to the spa_async_root_zio "Godfather" I/O which
		 * will ensure they complete prior to unloading the pool.
		 */
		spa_t *spa = zio->io_spa;

		zio_add_child(spa->spa_async_zio_root, zio);
	}

	zio_execute(zio);
}

void
zio_vdev_io_redone(zio_t *zio)
{
	ASSERT(zio->io_stage == ZIO_STAGE_VDEV_IO_DONE);

	zio->io_stage >>= 1;
}

static int
zio_checksum_verify(zio_t *zio)
{
	zio_bad_cksum_t info;
	blkptr_t *bp = zio->io_bp;
	int error;

	ASSERT(zio->io_vd != NULL);

	if (bp == NULL) {
		/*
		 * This is zio_read_phys().
		 * We're either verifying a label checksum, or nothing at all.
		 */
		if (zio->io_prop.zp_checksum == ZIO_CHECKSUM_OFF)
			return (ZIO_PIPELINE_CONTINUE);

		ASSERT(zio->io_prop.zp_checksum == ZIO_CHECKSUM_LABEL);
	}

	if ((error = zio_checksum_error(zio, &info)) != 0) {
		zio->io_error = error;
        }

	return (ZIO_PIPELINE_CONTINUE);
}

/*
 * Called by RAID-Z to ensure we don't compute the checksum twice.
 */
void
zio_checksum_verified(zio_t *zio)
{
	zio->io_pipeline &= ~ZIO_STAGE_CHECKSUM_VERIFY;
}

static int
zio_worst_error(int e1, int e2)
{
	static int zio_error_rank[] = { 0, ENXIO, ECKSUM, EIO };
	int r1, r2;

	for (r1 = 0; r1 < sizeof (zio_error_rank) / sizeof (int); r1++)
		if (e1 == zio_error_rank[r1])
			break;

	for (r2 = 0; r2 < sizeof (zio_error_rank) / sizeof (int); r2++)
		if (e2 == zio_error_rank[r2])
			break;

	return (r1 > r2 ? e1 : e2);
}

static int
zio_ready(zio_t *zio)
{
	blkptr_t *bp = zio->io_bp;
	zio_t *pio, *pio_next;
	zio_link_t *zl = NULL;

	if (zio_wait_for_children(zio, ZIO_CHILD_GANG_BIT | ZIO_CHILD_DDT_BIT,
	    ZIO_WAIT_READY)) {
		return (ZIO_PIPELINE_STOP);
	}

	if (zio->io_ready) {
		zio->io_ready(zio);
	}

	// XXX
#if 0
	if (bp != NULL && bp != &zio->io_bp_copy)
		zio->io_bp_copy = *bp;
#endif

	if (zio->io_error != 0) {
		zio->io_pipeline = ZIO_INTERLOCK_PIPELINE;

		if (zio->io_flags & ZIO_FLAG_IO_ALLOCATING) {
			ASSERT(IO_IS_ALLOCATING(zio));
			ASSERT(zio->io_priority == ZIO_PRIORITY_ASYNC_WRITE);
			ASSERT(zio->io_metaslab_class != NULL);

			/*
			 * We were unable to allocate anything, unreserve and
			 * issue the next I/O to allocate.
			 */
			// zio_allocate_dispatch(zio->io_spa, zio->io_allocator);
		}
	}

	zio->io_state[ZIO_WAIT_READY] = 1;
	pio = zio_walk_parents(zio, &zl);
	/*
	 * As we notify zio's parents, new parents could be added.
	 * New parents go to the head of zio's io_parent_list, however,
	 * so we will (correctly) not notify them.  The remainder of zio's
	 * io_parent_list, from 'pio_next' onward, cannot change because
	 * all parents must wait for us to be done before they can be done.
	 */
	for (; pio != NULL; pio = pio_next) {
		pio_next = zio_walk_parents(zio, &zl);
		zio_notify_parent(pio, zio, ZIO_WAIT_READY);
	}

	if (zio->io_flags & ZIO_FLAG_NODATA) {
		if (BP_IS_GANG(bp)) {
			zio->io_flags &= ~ZIO_FLAG_NODATA;
		} else {
			ASSERT((uintptr_t)zio->io_abd < SPA_MAXBLOCKSIZE);
			zio->io_pipeline &= ~ZIO_VDEV_IO_STAGES;
		}
	}

	return (ZIO_PIPELINE_CONTINUE);
}

/*
 * ==========================================================================
 * I/O pipeline definition
 * ==========================================================================
 */
static zio_pipe_stage_t *zio_pipeline[] = {
	NULL,
	zio_read_bp_init,
	NULL, /* zio_write_bp_init, */
	zio_free_bp_init,
	NULL, /* zio_issue_async, */
	NULL, /* zio_write_compress, */
	NULL, /* zio_encrypt, */
	NULL, /* zio_checksum_generate, */
	NULL, /* zio_nop_write, */
	NULL, /* zio_ddt_read_start, */
	NULL, /* zio_ddt_read_done, */
	NULL, /* zio_ddt_write, */
	NULL, /* zio_ddt_free, */
	NULL, /* zio_gang_assemble, */
	NULL, /* zio_gang_issue, */
	NULL, /* zio_dva_throttle, */
	NULL, /* zio_dva_allocate, */
	NULL, /* zio_dva_free, */
	NULL, /* zio_dva_claim, */
	zio_ready,
	NULL, /* zio_vdev_io_start, */
	NULL, /* zio_vdev_io_done, */
	NULL, /* zio_vdev_io_assess, */
	zio_checksum_verify,
	NULL, /* zio_done */
};
