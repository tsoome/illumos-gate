/*
 * CDDL HEADER START
 *
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2014, 2019 by Delphix. All rights reserved.
 * Copyright 2019 Joyent, Inc.
 */

#include <stand.h>
#include <sys/param.h>
#include <sys/stddef.h>
#include <sys/types.h>
#include <sys/abd.h>
#include <sys/zfsimpl.h>
#include <sys/vdev_indirect_mapping.h>

/*
 * The indirect_child_t represents the vdev that we will read from, when we
 * need to read all copies of the data (e.g. for scrub or reconstruction).
 * For plain (non-mirror) top-level vdevs (i.e. is_vdev is not a mirror),
 * ic_vdev is the same as is_vdev.  However, for mirror top-level vdevs,
 * ic_vdev is a child of the mirror.
 */
typedef struct indirect_child {
	void *ic_data;
	vdev_t *ic_vdev;
} indirect_child_t;

/*
 * The indirect_split_t represents one mapped segment of an i/o to the
 * indirect vdev. For non-split (contiguously-mapped) blocks, there will be
 * only one indirect_split_t, with is_split_offset==0 and is_size==io_size.
 * For split blocks, there will be several of these.
 */
typedef struct indirect_split {
	list_node_t is_node; /* link on iv_splits */

	/*
	 * is_split_offset is the offset into the i/o.
	 * This is the sum of the previous splits' is_size's.
	 */
	uint64_t is_split_offset;

	vdev_t *is_vdev; /* top-level vdev */
	uint64_t is_target_offset; /* offset on is_vdev */
	uint64_t is_size;
	int is_children; /* number of entries in is_child[] */

	/*
	 * is_good_child is the child that we are currently using to
	 * attempt reconstruction.
	 */
	int is_good_child;

	indirect_child_t is_child[]; /* variable-length */
} indirect_split_t;

/*
 * The indirect_vsd_t is associated with each i/o to the indirect vdev.
 * It is the "Vdev-Specific Data" in the zio_t's io_vsd.
 */
typedef struct indirect_vsd {
	boolean_t iv_split_block;
	boolean_t iv_reconstruct;

	list_t iv_splits; /* list of indirect_split_t's */
} indirect_vsd_t;

static void
vdev_indirect_map_free(zio_t *zio)
{
	indirect_vsd_t *iv = zio->io_vsd;
	indirect_split_t *is;

	while ((is = list_head(&iv->iv_splits)) != NULL) {
		for (int c = 0; c < is->is_children; c++) {
			indirect_child_t *ic = &is->is_child[c];
			free(ic->ic_data);
		}
		list_remove(&iv->iv_splits, is);
		free(is);
	}
	free(iv);
}

static const zio_vsd_ops_t vdev_indirect_vsd_ops = {
	vdev_indirect_map_free,
	zio_vsd_default_cksum_report
};

static void
vdev_indirect_close(vdev_t *vd __unused)
{
}

static int
vdev_indirect_open(vdev_t *vd, uint64_t *psize, uint64_t *max_psize,
    uint64_t *ashift)
{
        *psize = *max_psize = vd->vdev_asize +
            VDEV_LABEL_START_SIZE + VDEV_LABEL_END_SIZE;
        *ashift = vd->vdev_ashift;
        return (0);
}

typedef struct remap_segment {
	vdev_t *rs_vd;
	uint64_t rs_offset;
	uint64_t rs_asize;
	uint64_t rs_split_offset;
	list_node_t rs_node;
} remap_segment_t;

static remap_segment_t *
rs_alloc(vdev_t *vd, uint64_t offset, uint64_t asize, uint64_t split_offset)
{
	remap_segment_t *rs = malloc(sizeof (remap_segment_t));

	if (rs != NULL) {
		rs->rs_vd = vd;
		rs->rs_offset = offset;
		rs->rs_asize = asize;
		rs->rs_split_offset = split_offset;
	}

	return (rs);
}

/*
 * Given an indirect vdev and an extent on that vdev, it duplicates the
 * physical entries of the indirect mapping that correspond to the extent
 * to a new array and returns a pointer to it. In addition, copied_entries
 * is populated with the number of mapping entries that were duplicated.
 *
 * Finally, since we are doing an allocation, it is up to the caller to
 * free the array allocated in this function.
 */
vdev_indirect_mapping_entry_phys_t *
vdev_indirect_mapping_duplicate_adjacent_entries(vdev_t *vd, uint64_t offset,
    uint64_t asize, uint64_t *copied_entries)
{
	vdev_indirect_mapping_entry_phys_t *duplicate_mappings = NULL;
	vdev_indirect_mapping_t *vim = vd->v_mapping;
	uint64_t entries = 0;

	vdev_indirect_mapping_entry_phys_t *first_mapping =
	    vdev_indirect_mapping_entry_for_offset(vim, offset);
	ASSERT3P(first_mapping, !=, NULL);

	vdev_indirect_mapping_entry_phys_t *m = first_mapping;
	while (asize > 0) {
		uint64_t size = DVA_GET_ASIZE(&m->vimep_dst);
		uint64_t inner_offset = offset - DVA_MAPPING_GET_SRC_OFFSET(m);
		uint64_t inner_size = MIN(asize, size - inner_offset);

		offset += inner_size;
		asize -= inner_size;
		entries++;
		m++;
	}

	size_t copy_length = entries * sizeof (*first_mapping);
	duplicate_mappings = malloc(copy_length);
	if (duplicate_mappings != NULL)
		bcopy(first_mapping, duplicate_mappings, copy_length);
	else
		entries = 0;

	*copied_entries = entries;

	return (duplicate_mappings);
}

static void
vdev_indirect_remap(vdev_t *vd, uint64_t offset, uint64_t asize, void *arg)
{
	list_t stack;
	spa_t *spa = vd->v_spa;
	zio_t *zio = arg;
	remap_segment_t *rs;

	list_create(&stack, sizeof (remap_segment_t),
	    offsetof(remap_segment_t, rs_node));

	rs = rs_alloc(vd, offset, asize, 0);
	if (rs == NULL) {
		printf("vdev_indirect_remap: out of memory.\n");
		zio->io_error = ENOMEM;
	}
	for (; rs != NULL; rs = list_remove_head(&stack)) {
		vdev_t *v = rs->rs_vd;
		uint64_t num_entries = 0;
		/* vdev_indirect_mapping_t *vim = v->v_mapping; */
		vdev_indirect_mapping_entry_phys_t *mapping =
		    vdev_indirect_mapping_duplicate_adjacent_entries(v,
		    rs->rs_offset, rs->rs_asize, &num_entries);

		if (num_entries == 0)
			zio->io_error = ENOMEM;

		for (uint64_t i = 0; i < num_entries; i++) {
			vdev_indirect_mapping_entry_phys_t *m = &mapping[i];
			uint64_t size = DVA_GET_ASIZE(&m->vimep_dst);
			uint64_t dst_offset = DVA_GET_OFFSET(&m->vimep_dst);
			uint64_t dst_vdev = DVA_GET_VDEV(&m->vimep_dst);
			uint64_t inner_offset = rs->rs_offset -
			    DVA_MAPPING_GET_SRC_OFFSET(m);
			uint64_t inner_size =
			    MIN(rs->rs_asize, size - inner_offset);
			vdev_t *dst_v = vdev_lookup_top(spa, dst_vdev);

			// if (dst_v->vdev_ops == &vdev_indirect_ops) {
			if (dst_v->v_read == vdev_indirect_read) {
				remap_segment_t *o;

				o = rs_alloc(dst_v, dst_offset + inner_offset,
				    inner_size, rs->rs_split_offset);
				if (o == NULL) {
					printf("vdev_indirect_remap: "
					    "out of memory.\n");
					zio->io_error = ENOMEM;
					break;
				}

				list_insert_head(&stack, o);
			}
			vdev_indirect_gather_splits(rs->rs_split_offset, dst_v,
			    dst_offset + inner_offset,
			    inner_size, arg);

			/*
			 * vdev_indirect_gather_splits can have memory
			 * allocation error, we can not recover from it.
			 */
			if (zio->io_error != 0)
				break;
			rs->rs_offset += inner_size;
			rs->rs_asize -= inner_size;
			rs->rs_split_offset += inner_size;
		}

		free(mapping);
		free(rs);
		if (zio->io_error != 0)
			break;
	}

	list_destroy(&stack);
}

static void
vdev_indirect_child_io_done(zio_t *zio)
{
	zio_t *pio = zio->io_private;

	pio->io_error = zio_worst_error(pio->io_error, zio->io_error);

	abd_put(zio->io_abd);
}

/*
 * This is a callback for vdev_indirect_remap() which allocates an
 * indirect_split_t for each split segment and adds it to iv_splits.
 */
static void
vdev_indirect_gather_splits(uint64_t split_offset, vdev_t *vd, uint64_t offset,
    uint64_t size, void *arg)
{
	int n = 1;
	zio_t *zio = arg;
	indirect_vsd_t *iv = zio->io_vsd;

	// if (vd->vdev_ops == &vdev_indirect_ops)
	if (vd->v_read == vdev_indirect_read)
		return;

	// if (vd->vdev_ops == &vdev_mirror_ops)
	if (vd->v_read == vdev_mirror_read)
		n = vd->v_nchildren;

	indirect_split_t *is =
	    malloc(offsetof(indirect_split_t, is_child[n]));
	if (is == NULL) {
		zio->io_error = ENOMEM;
		return;
	}
	bzero(is, offsetof(indirect_split_t, is_child[n]));

	is->is_children = n;
	is->is_size = size;
	is->is_split_offset = split_offset;
	is->is_target_offset = offset;
	is->is_vdev = vd;

	/*
	 * Note that we only consider multiple copies of the data for
	 * *mirror* vdevs.  We don't for "replacing" or "spare" vdevs, even
	 * though they use the same ops as mirror, because there's only one
	 * "good" copy under the replacing/spare.
	 */
	// if (vd->vdev_ops == &vdev_mirror_ops)
	if (vd->v_read == vdev_mirror_read) {
		int i = 0;
		vdev_t *kid;

		STAILQ_FOREACH(kid, &vd->v_children, v_childlink) {
			is->is_child[i++].ic_vdev = kid;
		}
	} else {
		is->is_child[0].ic_vdev = vd;
	}

	list_insert_tail(&iv->iv_splits, is);
}

static void
vdev_indirect_read_split_done(zio_t *zio)
{
	indirect_child_t *ic = zio->io_private;

	if (zio->io_error != 0) {
		/*
		 * Clear ic_data to indicate that we do not have data for this
		 * child.
		 */
		abd_free(ic->ic_data);
		ic->ic_data = NULL;
	}
}

static void
vdev_indirect_io_start(zio_t *zio)
{
	spa_t *spa = zio->io_spa;
	indirect_vsd_t *iv;
	indirect_split_t *first;

	iv = calloc(1, sizeof (*iv));
	if (iv == NULL) {
		zio->io_error = ENOMEM;
		return;
	}

	list_create(&iv->iv_splits,
	    sizeof (indirect_split_t), offsetof(indirect_split_t, is_node));

	zio->io_vsd = iv;
	zio->io_vsd_ops = &vdev_indirect_vsd_ops;

	// XXX
	if (zio->io_vd->v_mapping == NULL) {
		vdev_indirect_config_t *vic;

		vic = &zio->io_vd->vdev_indirect_config;
		zio->io_vd->v_mapping = vdev_indirect_mapping_open(spa,
		    &spa->spa_mos, vic->vic_mapping_object);
	}

	vdev_indirect_remap(zio->io_vd, zio->io_offset, zio->io_size, zio);
	if (zio->io_error != 0)
		return;

	first = list_head(&iv->iv_splits);
	if (first->is_size == zio->io_size) {
		/*
		 * This is not a split block; we are pointing to the entire
		 * data, which will checksum the same as the original data.
		 * Pass the BP down so that the child i/o can verify the
		 * checksum, and try a different location if available
		 * (e.g. on a mirror).
		 *
		 * While this special case could be handled the same as the
		 * general (split block) case, doing it this way ensures
		 * that the vast majority of blocks on indirect vdevs
		 * (which are not split) are handled identically to blocks
		 * on non-indirect vdevs.  This allows us to be less strict
		 * about performance in the general (but rare) case.
		 */
		zio_nowait(zio_vdev_child_io(zio, zio->io_bp, first->is_vdev,
		    first->is_target_offset, abd_get_offset(zio->io_abd, 0),
		    zio->io_size, zio->io_type, 0,
		    vdev_indirect_child_io_done, zio));
	} else {
		iv->iv_split_block = B_TRUE;
		/*
		 * Read one copy of each split segment, from the
		 * top-level vdev.  Since we don't know the
		 * checksum of each split individually, the child
		 * zio can't ensure that we get the right data.
		 * E.g. if it's a mirror, it will just read from a
		 * random (healthy) leaf vdev.  We have to verify
		 * the checksum in vdev_indirect_io_done().
		 */
		for (indirect_split_t *is = list_head(&iv->iv_splits);
		    is != NULL; is = list_next(&iv->iv_splits, is)) {
			zio_nowait(zio_vdev_child_io(zio, NULL,
			    is->is_vdev, is->is_target_offset,
			    abd_get_offset(zio->io_abd,
			    is->is_split_offset),
			    is->is_size, zio->io_type, 0,
			    vdev_indirect_child_io_done, zio));
		}
	}

	zio_execute(zio);
}

/*
 * Report a checksum error for a child.
 */
static void
vdev_indirect_checksum_error(zio_t *zio,
    indirect_split_t *is, indirect_child_t *ic)
{
	vdev_t *vd = ic->ic_vdev;

	if (zio->io_flags & ZIO_FLAG_SPECULATIVE)
		return;

	vd->vdev_stat.vs_checksum_errors++;

	zio_bad_cksum_t zbc = { 0 };
	abd_t *bad_abd = ic->ic_data;
	abd_t *good_abd = is->is_good_child->ic_data;
	(void) zfs_ereport_post_checksum(zio->io_spa, vd, &zio->io_bookmark,
	    zio, is->is_target_offset, is->is_size, good_abd, bad_abd, &zbc);
}

vdev_ops_t vdev_indirect_ops = {
	.vdev_op_open = vdev_indirect_open,
	.vdev_op_close = vdev_indirect_close,
	.vdev_op_asize = vdev_default_asize,
	.vdev_op_io_start = vdev_indirect_io_start,
	.vdev_op_io_done = vdev_indirect_io_done,
	.vdev_op_state_change = NULL,
	.vdev_op_need_resilver = NULL,
	.vdev_op_hold = NULL,
	.vdev_op_rele = NULL,
	.vdev_op_remap = vdev_indirect_remap,
	.vdev_op_xlate = NULL,
	.vdev_op_dumpio = NULL,
	.vdev_op_type = VDEV_TYPE_INDIRECT,	/* name of this vdev type */
	.vdev_op_leaf = B_FALSE			/* leaf vdev */
};
