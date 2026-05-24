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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, 2020 by Delphix. All rights reserved.
 * Copyright (c) 2017, Intel Corporation.
 * Copyright 2020 Joyent, Inc.
 * Copyright 2024 MNX Cloud, Inc.
 */

#include <sys/zfs_context.h>
#include <sys/zfsimpl.h>
#include <sys/vdev.h>
#include <sys/vdev_impl.h>
#include <sys/uberblock_impl.h>
#include <sys/zio.h>
#include <sys/nvpair.h>
#include <sys/zfs_bootenv.h>

uint64_t
vdev_label_offset(uint64_t psize, int l, uint64_t offset)
{
	uint64_t label_offset;

	if (l < VDEV_LABELS / 2)
		label_offset = 0;
	else
		label_offset = psize - VDEV_LABELS * sizeof (vdev_label_t);

	return (offset + l * sizeof (vdev_label_t) + label_offset);
}

/*
 * Returns back the vdev label associated with the passed in offset.
 */
int
vdev_label_number(uint64_t psize, uint64_t offset)
{
	int l;

	if (offset >= psize - VDEV_LABEL_END_SIZE) {
		offset -= psize - VDEV_LABEL_END_SIZE;
		offset += (VDEV_LABELS / 2) * sizeof (vdev_label_t);
	}
	l = offset / sizeof (vdev_label_t);
	return (l < VDEV_LABELS ? l : -1);
}

static void
vdev_label_read(zio_t *zio, vdev_t *vd, int l, abd_t *buf, uint64_t offset,
    uint64_t size, zio_done_func_t *done, void *private, int flags)
{
	zio_nowait(zio_read_phys(zio, vd,
	    vdev_label_offset(vd->vdev_psize, l, offset),
	    size, buf, ZIO_CHECKSUM_LABEL, done, private, flags, B_TRUE));
}

void
vdev_label_write(zio_t *zio, vdev_t *vd, int l, abd_t *buf, uint64_t offset,
    uint64_t size, zio_done_func_t *done, void *private, int flags)
{
	zio_nowait(zio_write_phys(zio, vd,
	    vdev_label_offset(vd->vdev_psize, l, offset),
	    size, buf, ZIO_CHECKSUM_LABEL, done, private, flags, B_TRUE));
}

/*
 * Returns the configuration from the label of the given vdev. For vdevs
 * which don't have a txg value stored on their label (i.e. spares/cache)
 * or have not been completely initialized (txg = 0) just return
 * the configuration from the first valid label we find. Otherwise,
 * find the most up-to-date label that does not exceed the specified
 * 'txg' value.
 */
nvlist_t *
vdev_label_read_config(vdev_t *vd, uint64_t txg)
{
	spa_t *spa = vd->vdev_spa;
	nvlist_t *config = NULL;
	vdev_phys_t *vp;
	abd_t *vp_abd;
	zio_t *zio;
	uint64_t best_txg = 0;
	uint64_t label_txg = 0;
	int error = 0;
	int flags = ZIO_FLAG_CONFIG_WRITER | ZIO_FLAG_CANFAIL |
	    ZIO_FLAG_SPECULATIVE;

	if (!vdev_readable(vd))
		return (NULL);

	vp_abd = abd_alloc_linear(sizeof (vdev_phys_t), B_TRUE);
	vp = abd_to_buf(vp_abd);

retry:
	for (int l = 0; l < VDEV_LABELS; l++) {
		nvlist_t *label = NULL;

		zio = zio_root(spa, NULL, NULL, flags);

		vdev_label_read(zio, vd, l, vp_abd,
		    offsetof(vdev_label_t, vl_vdev_phys),
		    sizeof (vdev_phys_t), NULL, NULL, flags);

		if (zio_wait(zio) == 0 &&
		    nvlist_unpack(vp->vp_nvlist, sizeof (vp->vp_nvlist),
		    &label, 0) == 0) {
			/*
			 * Auxiliary vdevs won't have txg values in their
			 * labels and newly added vdevs may not have been
			 * completely initialized so just return the
			 * configuration from the first valid label we
			 * encounter.
			 */
			error = nvlist_lookup_uint64(label,
			    ZPOOL_CONFIG_POOL_TXG, &label_txg);
			if ((error || label_txg == 0) && !config) {
				config = label;
				break;
			} else if (label_txg <= txg && label_txg > best_txg) {
				best_txg = label_txg;
				nvlist_free(config);
				config = fnvlist_dup(label);
			}
		}

		if (label != NULL) {
			nvlist_free(label);
			label = NULL;
		}
	}

	if (config == NULL && !(flags & ZIO_FLAG_TRYHARD)) {
		flags |= ZIO_FLAG_TRYHARD;
		goto retry;
	}

	/*
	 * We found a valid label but it didn't pass txg restrictions.
	 */
	if (config == NULL && label_txg != 0) {
		printf("label discarded as txg is too large "
		    "(%ju > %ju)", label_txg, txg);
	}

	abd_free(vp_abd);

	return (config);
}

/*
 * Done callback for vdev_label_read_bootenv_impl. If this is the first
 * callback to finish, store our abd in the callback pointer. Otherwise, we
 * just free our abd and return.
 */
static void
vdev_label_read_bootenv_done(zio_t *zio)
{
	zio_t *rio = zio->io_private;
	abd_t **cbp = rio->io_private;

	ASSERT3U(zio->io_size, ==, VDEV_PAD_SIZE);

	if (zio->io_error == 0) {
		if (*cbp == NULL) {
			/* Will free this buffer in vdev_label_read_bootenv. */
			*cbp = zio->io_abd;
		} else {
			abd_free(zio->io_abd);
		}
	} else {
		abd_free(zio->io_abd);
	}
}

static void
vdev_label_read_bootenv_impl(zio_t *zio, vdev_t *vd, int flags)
{
	for (int c = 0; c < vd->vdev_children; c++)
		vdev_label_read_bootenv_impl(zio, vd->vdev_child[c], flags);

	/*
	 * We just use the first label that has a correct checksum; the
	 * bootloader should have rewritten them all to be the same on boot,
	 * and any changes we made since boot have been the same across all
	 * labels.
	 */
	if (vd->vdev_ops->vdev_op_leaf && vdev_readable(vd)) {
		for (int l = 0; l < VDEV_LABELS; l++) {
			vdev_label_read(zio, vd, l,
			    abd_alloc_linear(VDEV_PAD_SIZE, B_FALSE),
			    offsetof(vdev_label_t, vl_be), VDEV_PAD_SIZE,
			    vdev_label_read_bootenv_done, zio, flags);
		}
	}
}

int
vdev_label_read_bootenv(vdev_t *rvd, nvlist_t *bootenv)
{
	nvlist_t *config;
	spa_t *spa = rvd->vdev_spa;
	abd_t *abd = NULL;
	int flags = ZIO_FLAG_CONFIG_WRITER | ZIO_FLAG_CANFAIL |
	    ZIO_FLAG_SPECULATIVE | ZIO_FLAG_TRYHARD;

	ASSERT(bootenv);

	zio_t *zio = zio_root(spa, NULL, &abd, flags);
	vdev_label_read_bootenv_impl(zio, rvd, flags);
	int err = zio_wait(zio);

	if (abd != NULL) {
		char *buf;
		vdev_boot_envblock_t *vbe = abd_to_buf(abd);

		vbe->vbe_version = ntohll(vbe->vbe_version);
		switch (vbe->vbe_version) {
		case VB_RAW:
			/*
			 * if we have textual data in vbe_bootenv, create nvlist
			 * with key "envmap".
			 */
			fnvlist_add_uint64(bootenv, BOOTENV_VERSION, VB_RAW);
			vbe->vbe_bootenv[sizeof (vbe->vbe_bootenv) - 1] = '\0';
			fnvlist_add_string(bootenv, GRUB_ENVMAP,
			    vbe->vbe_bootenv);
			break;

		case VB_NVLIST:
			err = nvlist_unpack(vbe->vbe_bootenv,
			    sizeof (vbe->vbe_bootenv), &config, 0);
			if (err == 0) {
				fnvlist_merge(bootenv, config);
				nvlist_free(config);
				break;
			}
			/* FALLTHROUGH */
		default:
			/* Check for FreeBSD zfs bootonce command string */
			buf = abd_to_buf(abd);
			if (*buf == '\0') {
				fnvlist_add_uint64(bootenv, BOOTENV_VERSION,
				    VB_NVLIST);
				break;
			}
			fnvlist_add_string(bootenv, FREEBSD_BOOTONCE, buf);
		}

		/*
		 * abd was allocated in vdev_label_read_bootenv_impl()
		 */
		abd_free(abd);
		/*
		 * If we managed to read any successfully,
		 * return success.
		 */
		return (0);
	}
	return (err);
}

int
vdev_label_write_bootenv(vdev_t *vd, nvlist_t *env)
{
	zio_t *zio;
	spa_t *spa = vd->vdev_spa;
	vdev_boot_envblock_t *bootenv;
	int flags = ZIO_FLAG_CONFIG_WRITER | ZIO_FLAG_CANFAIL;
	int error;
	size_t nvsize;
	char *nvbuf;

	error = nvlist_size(env, &nvsize, NV_ENCODE_XDR);
	if (error != 0)
		return (error);

	if (nvsize >= sizeof (bootenv->vbe_bootenv)) {
		return (E2BIG);
	}

	error = ENXIO;
	for (int c = 0; c < vd->vdev_children; c++) {
		int child_err;

		child_err = vdev_label_write_bootenv(vd->vdev_child[c], env);
		/*
		 * As long as any of the disks managed to write all of their
		 * labels successfully, return success.
		 */
		if (child_err == 0)
			error = child_err;
	}

	if (!vd->vdev_ops->vdev_op_leaf || vdev_is_dead(vd) ||
	    !vdev_writeable(vd)) {
		return (error);
	}
	ASSERT3U(sizeof (*bootenv), ==, VDEV_PAD_SIZE);
	abd_t *abd = abd_alloc_for_io(VDEV_PAD_SIZE, B_TRUE);
	abd_zero(abd, VDEV_PAD_SIZE);

	bootenv = abd_borrow_buf_copy(abd, VDEV_PAD_SIZE);
	nvbuf = bootenv->vbe_bootenv;
	nvsize = sizeof (bootenv->vbe_bootenv);

	bootenv->vbe_version = fnvlist_lookup_uint64(env, BOOTENV_VERSION);
	switch (bootenv->vbe_version) {
	case VB_RAW:
		if (nvlist_lookup_string(env, GRUB_ENVMAP, &nvbuf) == 0) {
			(void) strlcpy(bootenv->vbe_bootenv, nvbuf, nvsize);
		}
		error = 0;
		break;

	case VB_NVLIST:
		error = nvlist_pack(env, &nvbuf, &nvsize, NV_ENCODE_XDR,
		    KM_SLEEP);
		break;

	default:
		error = EINVAL;
		break;
	}

	if (error == 0) {
		bootenv->vbe_version = htonll(bootenv->vbe_version);
		abd_return_buf_copy(abd, bootenv, VDEV_PAD_SIZE);
	} else {
		abd_free(abd);
		return (error);
	}

retry:
	zio = zio_root(spa, NULL, NULL, flags);
	for (int l = 0; l < VDEV_LABELS; l++) {
		vdev_label_write(zio, vd, l, abd,
		    offsetof(vdev_label_t, vl_be),
		    VDEV_PAD_SIZE, NULL, NULL, flags);
	}

	error = zio_wait(zio);
	if (error != 0 && !(flags & ZIO_FLAG_TRYHARD)) {
		flags |= ZIO_FLAG_TRYHARD;
		goto retry;
	}

	abd_free(abd);
	return (error);
}

/*
 * ==========================================================================
 * uberblock load/sync
 * ==========================================================================
 */

/*
 * Consider the following situation: txg is safely synced to disk.  We've
 * written the first uberblock for txg + 1, and then we lose power.  When we
 * come back up, we fail to see the uberblock for txg + 1 because, say,
 * it was on a mirrored device and the replica to which we wrote txg + 1
 * is now offline.  If we then make some changes and sync txg + 1, and then
 * the missing replica comes back, then for a few seconds we'll have two
 * conflicting uberblocks on disk with the same txg.  The solution is simple:
 * among uberblocks with equal txg, choose the one with the latest timestamp.
 */
static int
vdev_uberblock_compare(const uberblock_t *ub1, const uberblock_t *ub2)
{
	int cmp = TREE_CMP(ub1->ub_txg, ub2->ub_txg);

	if (likely(cmp))
		return (cmp);

	cmp = TREE_CMP(ub1->ub_timestamp, ub2->ub_timestamp);
	if (likely(cmp))
		return (cmp);

	/*
	 * If MMP_VALID(ub) && MMP_SEQ_VALID(ub) then the host has an MMP-aware
	 * ZFS, e.g. zfsonlinux >= 0.7.
	 *
	 * If one ub has MMP and the other does not, they were written by
	 * different hosts, which matters for MMP.  So we treat no MMP/no SEQ as
	 * a 0 value.
	 *
	 * Since timestamp and txg are the same if we get this far, either is
	 * acceptable for importing the pool.
	 */
	unsigned int seq1 = 0;
	unsigned int seq2 = 0;

	if (MMP_VALID(ub1) && MMP_SEQ_VALID(ub1))
		seq1 = MMP_SEQ(ub1);

	if (MMP_VALID(ub2) && MMP_SEQ_VALID(ub2))
		seq2 = MMP_SEQ(ub2);

	return (TREE_CMP(seq1, seq2));
}

struct ubl_cbdata {
	uberblock_t	*ubl_ubbest;	/* Best uberblock */
	vdev_t		*ubl_vd;	/* vdev associated with the above */
};

static void
vdev_uberblock_load_done(zio_t *zio)
{
	vdev_t *vd = zio->io_vd;
	spa_t *spa = zio->io_spa;
	zio_t *rio = zio->io_private;
	uberblock_t *ub = abd_to_buf(zio->io_abd);
	struct ubl_cbdata *cbp = rio->io_private;

	ASSERT3U(zio->io_size, ==, VDEV_UBERBLOCK_SIZE(vd));

	if (zio->io_error == 0 && uberblock_verify(ub) == 0) {
		if (ub->ub_txg <= spa->spa_load_max_txg &&
		    vdev_uberblock_compare(ub, cbp->ubl_ubbest) > 0) {
			/*
			 * Keep track of the vdev in which this uberblock
			 * was found. We will use this information later
			 * to obtain the config nvlist associated with
			 * this uberblock.
			 */
			*cbp->ubl_ubbest = *ub;
			cbp->ubl_vd = vd;
		}
	}

	abd_free(zio->io_abd);
}

static void
vdev_uberblock_load_impl(zio_t *zio, vdev_t *vd, int flags,
    struct ubl_cbdata *cbp)
{
	for (int c = 0; c < vd->vdev_children; c++)
		vdev_uberblock_load_impl(zio, vd->vdev_child[c], flags, cbp);

	if (vd->vdev_ops->vdev_op_leaf && vdev_readable(vd)) {
		for (int l = 0; l < VDEV_LABELS; l++) {
			for (int n = 0; n < VDEV_UBERBLOCK_COUNT(vd); n++) {
				vdev_label_read(zio, vd, l,
				    abd_alloc_linear(VDEV_UBERBLOCK_SIZE(vd),
				    B_TRUE), VDEV_UBERBLOCK_OFFSET(vd, n),
				    VDEV_UBERBLOCK_SIZE(vd),
				    vdev_uberblock_load_done, zio, flags);
			}
		}
	}
}

/*
 * Reads the 'best' uberblock from disk along with its associated
 * configuration. First, we read the uberblock array of each label of each
 * vdev, keeping track of the uberblock with the highest txg in each array.
 * Then, we read the configuration from the same vdev as the best uberblock.
 */
void
vdev_uberblock_load(vdev_t *rvd, uberblock_t *ub, nvlist_t **config)
{
	zio_t *zio;
	spa_t *spa = rvd->vdev_spa;
	struct ubl_cbdata cb;
	int flags = ZIO_FLAG_CONFIG_WRITER | ZIO_FLAG_CANFAIL |
	    ZIO_FLAG_SPECULATIVE | ZIO_FLAG_TRYHARD;

	ASSERT(ub);
	ASSERT(config);

	bzero(ub, sizeof (uberblock_t));
	*config = NULL;

	cb.ubl_ubbest = ub;
	cb.ubl_vd = NULL;

	zio = zio_root(spa, NULL, &cb, flags);
	vdev_uberblock_load_impl(zio, rvd, flags, &cb);
	(void) zio_wait(zio);

	/*
	 * It's possible that the best uberblock was discovered on a label
	 * that has a configuration which was written in a future txg.
	 * Search all labels on this vdev to find the configuration that
	 * matches the txg for our uberblock.
	 */
	if (cb.ubl_vd != NULL) {
		printf("best uberblock found for spa %s. "
		    "txg %ju", spa->spa_name, ub->ub_txg);

		*config = vdev_label_read_config(cb.ubl_vd, ub->ub_txg);
		if (*config == NULL && spa->spa_extreme_rewind) {
			printf("failed to read label config. "
			    "Trying again without txg restrictions.");
			*config = vdev_label_read_config(cb.ubl_vd, UINT64_MAX);
		}
		if (*config == NULL) {
			printf("failed to read label config");
		}
	}
}
