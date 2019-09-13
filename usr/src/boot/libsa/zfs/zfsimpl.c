/*
 * Copyright (c) 2007 Doug Rabson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>

/*
 *	Stand-alone ZFS file reader.
 */

#include <stdbool.h>
#include <sys/endian.h>
#include <sys/stat.h>
#include <sys/stdint.h>
#include <sys/list.h>
#include <sys/nvpair.h>
#include <sys/uio.h>
#include <sys/zfs_bootenv.h>
#include <inttypes.h>
#include <libcrypto.h>

#include "zfsimpl.h"
#include "zfssubr.c"

typedef struct uio uio_t;

static spa_t *spa_find_by_dev(struct zfs_devdesc *);
static int dsl_wrapping_key_create(uint8_t *, zfs_keyformat_t,
    uint64_t, uint64_t, dsl_wrapping_key_t **);
static void dsl_wrapping_key_free(dsl_wrapping_key_t *);
static int zio_do_crypt_uio(uint64_t, crypto_key_t *, uint8_t *,
    uint_t, uio_t *, uio_t *, uint8_t *, uint_t);

struct zfsmount {
	const spa_t	*spa;
	objset_phys_t	objset;
	uint64_t	rootobj;
};

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

	indirect_child_t is_child[1]; /* variable-length */
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

/*
 * List of all vdevs, chained through v_alllink.
 */
static vdev_list_t zfs_vdevs;

/*
 * List of ZFS features supported for read
 */
static const char *features_for_read[] = {
	"org.illumos:lz4_compress",
	"com.delphix:hole_birth",
	"com.delphix:extensible_dataset",
	"com.delphix:embedded_data",
	"org.open-zfs:large_blocks",
	"org.illumos:sha512",
	"org.illumos:skein",
	"org.illumos:edonr",
	"org.zfsonlinux:large_dnode",
	"com.joyent:multi_vdev_crash_dump",
	"com.delphix:spacemap_histogram",
	"com.delphix:zpool_checkpoint",
	"com.delphix:spacemap_v2",
	"com.datto:encryption",
	"com.datto:bookmark_v2",
	"org.zfsonlinux:allocation_classes",
	"com.datto:resilver_defer",
	"com.delphix:device_removal",
	"com.delphix:obsolete_counts",
	NULL
};

/*
 * List of all pools, chained through spa_link.
 */
static spa_list_t zfs_pools;

static const dnode_phys_t *dnode_cache_obj;
static uint64_t dnode_cache_bn;
static char *dnode_cache_buf;

static int zio_read(const spa_t *spa, const blkptr_t *bp, void *buf);
static int zfs_get_root(const spa_t *spa, uint64_t *objid);
static int zfs_rlookup(const spa_t *spa, uint64_t objnum, char *result);
static int zap_lookup(const spa_t *spa, const dnode_phys_t *dnode,
    const char *name, uint64_t integer_size, uint64_t num_integers,
    void *value);
static int objset_get_dnode(const spa_t *, const objset_phys_t *, uint64_t,
    dnode_phys_t *);
static int dnode_read(const spa_t *, const dnode_phys_t *, off_t, void *,
    size_t);
static int vdev_indirect_read(vdev_t *, const blkptr_t *, void *, off_t,
    size_t);
static int vdev_mirror_read(vdev_t *, const blkptr_t *, void *, off_t,
    size_t);

static int
spa_wkey_to_nvlist(dsl_wrapping_key_t *wkey, nvlist_t **nvp)
{
	nvlist_t *nv;
	int rv;

	rv = nvlist_alloc(&nv, NV_UNIQUE_NAME, 0);
	if (rv != 0)
		return (rv);

	rv = nvlist_add_int32(nv, ZFS_PROP_KEYFORMAT, wkey->wk_keyformat);
	if (rv != 0)
		goto done;
	rv = nvlist_add_uint64(nv, ZFS_PROP_PBKDF2_SALT, wkey->wk_salt);
	if (rv != 0)
		goto done;
	rv = nvlist_add_uint64(nv, ZFS_PROP_PBKDF2_ITERS, wkey->wk_iters);
	if (rv != 0)
		goto done;
	rv = nvlist_add_uint8_array(nv, "wkeydata", wkey->wk_key.ck_data,
	    WRAPPING_KEY_LEN);

done:
	if (rv != 0) {
		nvlist_free(nv);
	} else {
		*nvp = nv;
	}
	return (rv);
}

nvlist_t *
spa_wkeys_to_nvlist(void)
{
	struct zfs_devdesc *dev;
	nvlist_t *nvp, *nvc;
	dsl_wrapping_key_t *wkey;
	spa_t *spa;
	char name[21];
	int rv;

	rv = archsw.arch_getdev((void **)&dev, NULL, NULL);
	if (rv != 0)
		return (NULL);

	spa = spa_find_by_dev(dev);
	free(dev);
	if (spa == NULL)
		return (NULL);

	if (avl_is_empty(&spa->spa_keystore.sk_wkeys))
		return (NULL);

	rv = nvlist_alloc(&nvp, NV_UNIQUE_NAME, 0);
	if (rv != 0)
		return (NULL);

	for (wkey = avl_first(&spa->spa_keystore.sk_wkeys);
	    wkey != NULL;
	    wkey = AVL_NEXT(&spa->spa_keystore.sk_wkeys, wkey)) {
		rv = spa_wkey_to_nvlist(wkey, &nvc);
		if (rv == 0) {
			snprintf(name, sizeof (name), "%jx",
			    (uintmax_t)wkey->wk_ddobj);
			rv = nvlist_add_nvlist(nvp, name, nvc);
			nvlist_free(nvc);
		}
		if (rv != 0) {
			nvlist_free(nvp);
			return (NULL);
		}
	}
	return (nvp);
}

void
spa_keystore_cleanup(spa_t *spa)
{
	dsl_wrapping_key_t *wkey;
	dsl_crypto_key_t *dck;
	dsl_key_mapping_t *mk;

	while ((wkey = avl_first(&spa->spa_keystore.sk_wkeys)) != NULL) {
		avl_remove(&spa->spa_keystore.sk_wkeys, wkey);
		dsl_wrapping_key_free(wkey);
	}

	while ((mk = avl_first(&spa->spa_keystore.sk_key_mappings)) != NULL) {
		avl_remove(&spa->spa_keystore.sk_key_mappings, mk);
		free(mk);
	}

	while ((dck = avl_first(&spa->spa_keystore.sk_dsl_keys)) != NULL) {
		avl_remove(&spa->spa_keystore.sk_dsl_keys, dck);
		bzero(dck, sizeof (*dck));
		free(dck);
	}
}

static void
zfs_init(void)
{
	STAILQ_INIT(&zfs_vdevs);
	STAILQ_INIT(&zfs_pools);

	dnode_cache_buf = malloc(SPA_MAXBLOCKSIZE);

	zfs_init_crc();
}

static bool
zfeature_is_supported(const char *guid)
{
	for (uint_t i = 0; features_for_read[i] != NULL; i++) {
		if (strcmp(guid, features_for_read[i]) == 0)
			return (true);
	}
	return (false);
}

static int
nvlist_check_features_for_read(nvlist_t *nvl)
{
	nvlist_t *features = NULL;
	int rc;

	/*
	 * We may have all features disabled.
	 */
	rc = nvlist_lookup_nvlist(nvl, ZPOOL_CONFIG_FEATURES_FOR_READ,
	    &features);
	switch (rc) {
	case 0:
		break;		/* Continue with checks */

	case ENOENT:
		return (0);	/* All features are disabled */

	default:
		return (rc);	/* Error while reading nvlist */
	}

	for (nvpair_t *nvp = nvlist_next_nvpair(features, NULL);
	    nvp != NULL; nvp = nvlist_next_nvpair(features, nvp)) {
		const char *name = nvpair_name(nvp);

		if (!zfeature_is_supported(name)) {
			rc = EIO;
			printf("ZFS: unsupported feature: %s\n", name);
			rc = EIO;
		}
	}

	return (rc);
}

static int
vdev_read_phys(vdev_t *vdev, const blkptr_t *bp, void *buf,
    off_t offset, size_t size)
{
	size_t psize;
	int rc;

	if (vdev->v_phys_read == NULL)
		return (ENOTSUP);

	if (bp) {
		psize = BP_GET_PSIZE(bp);
	} else {
		psize = size;
	}

	rc = vdev->v_phys_read(vdev, vdev->v_priv, offset, buf, psize);
	if (rc == 0) {
		if (bp != NULL)
			rc = zio_checksum_verify(vdev->v_spa, bp, buf);
	}

	return (rc);
}

static int
vdev_write_phys(vdev_t *vdev, void *buf, off_t offset, size_t size)
{
	if (vdev->v_phys_write == NULL)
		return (ENOTSUP);

	return (vdev->v_phys_write(vdev, offset, buf, size));
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

vdev_indirect_mapping_t *
vdev_indirect_mapping_open(spa_t *spa, objset_phys_t *os,
    uint64_t mapping_object)
{
	vdev_indirect_mapping_t *vim;
	vdev_indirect_mapping_phys_t *vim_phys;
	int rc;

	vim = calloc(1, sizeof (*vim));
	if (vim == NULL)
		return (NULL);

	vim->vim_dn = calloc(1, sizeof (*vim->vim_dn));
	if (vim->vim_dn == NULL) {
		free(vim);
		return (NULL);
	}

	rc = objset_get_dnode(spa, os, mapping_object, vim->vim_dn);
	if (rc != 0) {
		free(vim->vim_dn);
		free(vim);
		return (NULL);
	}

	vim->vim_spa = spa;
	vim->vim_phys = malloc(sizeof (*vim->vim_phys));
	if (vim->vim_phys == NULL) {
		free(vim->vim_dn);
		free(vim);
		return (NULL);
	}

	vim_phys = (vdev_indirect_mapping_phys_t *)DN_BONUS(vim->vim_dn);
	*vim->vim_phys = *vim_phys;

	vim->vim_objset = os;
	vim->vim_object = mapping_object;
	vim->vim_entries = NULL;

	vim->vim_havecounts =
	    (vim->vim_dn->dn_bonuslen > VDEV_INDIRECT_MAPPING_SIZE_V0);

	return (vim);
}

/*
 * Compare an offset with an indirect mapping entry; there are three
 * possible scenarios:
 *
 *     1. The offset is "less than" the mapping entry; meaning the
 *        offset is less than the source offset of the mapping entry. In
 *        this case, there is no overlap between the offset and the
 *        mapping entry and -1 will be returned.
 *
 *     2. The offset is "greater than" the mapping entry; meaning the
 *        offset is greater than the mapping entry's source offset plus
 *        the entry's size. In this case, there is no overlap between
 *        the offset and the mapping entry and 1 will be returned.
 *
 *        NOTE: If the offset is actually equal to the entry's offset
 *        plus size, this is considered to be "greater" than the entry,
 *        and this case applies (i.e. 1 will be returned). Thus, the
 *        entry's "range" can be considered to be inclusive at its
 *        start, but exclusive at its end: e.g. [src, src + size).
 *
 *     3. The last case to consider is if the offset actually falls
 *        within the mapping entry's range. If this is the case, the
 *        offset is considered to be "equal to" the mapping entry and
 *        0 will be returned.
 *
 *        NOTE: If the offset is equal to the entry's source offset,
 *        this case applies and 0 will be returned. If the offset is
 *        equal to the entry's source plus its size, this case does
 *        *not* apply (see "NOTE" above for scenario 2), and 1 will be
 *        returned.
 */
static int
dva_mapping_overlap_compare(const void *v_key, const void *v_array_elem)
{
	const uint64_t *key = v_key;
	const vdev_indirect_mapping_entry_phys_t *array_elem =
	    v_array_elem;
	uint64_t src_offset = DVA_MAPPING_GET_SRC_OFFSET(array_elem);

	if (*key < src_offset) {
		return (-1);
	} else if (*key < src_offset + DVA_GET_ASIZE(&array_elem->vimep_dst)) {
		return (0);
	} else {
		return (1);
	}
}

/*
 * Return array entry.
 */
static vdev_indirect_mapping_entry_phys_t *
vdev_indirect_mapping_entry(vdev_indirect_mapping_t *vim, uint64_t index)
{
	uint64_t size;
	off_t offset = 0;
	int rc;

	if (vim->vim_phys->vimp_num_entries == 0)
		return (NULL);

	if (vim->vim_entries == NULL) {
		uint64_t bsize;

		bsize = vim->vim_dn->dn_datablkszsec << SPA_MINBLOCKSHIFT;
		size = vim->vim_phys->vimp_num_entries *
		    sizeof (*vim->vim_entries);
		if (size > bsize) {
			size = bsize / sizeof (*vim->vim_entries);
			size *= sizeof (*vim->vim_entries);
		}
		vim->vim_entries = malloc(size);
		if (vim->vim_entries == NULL)
			return (NULL);
		vim->vim_num_entries = size / sizeof (*vim->vim_entries);
		offset = index * sizeof (*vim->vim_entries);
	}

	/* We have data in vim_entries */
	if (offset == 0) {
		if (index >= vim->vim_entry_offset &&
		    index <= vim->vim_entry_offset + vim->vim_num_entries) {
			index -= vim->vim_entry_offset;
			return (&vim->vim_entries[index]);
		}
		offset = index * sizeof (*vim->vim_entries);
	}

	vim->vim_entry_offset = index;
	size = vim->vim_num_entries * sizeof (*vim->vim_entries);
	rc = dnode_read(vim->vim_spa, vim->vim_dn, offset, vim->vim_entries,
	    size);
	if (rc != 0) {
		/* Read error, invalidate vim_entries. */
		free(vim->vim_entries);
		vim->vim_entries = NULL;
		return (NULL);
	}
	index -= vim->vim_entry_offset;
	return (&vim->vim_entries[index]);
}

/*
 * Returns the mapping entry for the given offset.
 *
 * It's possible that the given offset will not be in the mapping table
 * (i.e. no mapping entries contain this offset), in which case, the
 * return value value depends on the "next_if_missing" parameter.
 *
 * If the offset is not found in the table and "next_if_missing" is
 * B_FALSE, then NULL will always be returned. The behavior is intended
 * to allow consumers to get the entry corresponding to the offset
 * parameter, iff the offset overlaps with an entry in the table.
 *
 * If the offset is not found in the table and "next_if_missing" is
 * B_TRUE, then the entry nearest to the given offset will be returned,
 * such that the entry's source offset is greater than the offset
 * passed in (i.e. the "next" mapping entry in the table is returned, if
 * the offset is missing from the table). If there are no entries whose
 * source offset is greater than the passed in offset, NULL is returned.
 */
static vdev_indirect_mapping_entry_phys_t *
vdev_indirect_mapping_entry_for_offset(vdev_indirect_mapping_t *vim,
    uint64_t offset)
{
	ASSERT(vim->vim_phys->vimp_num_entries > 0);

	vdev_indirect_mapping_entry_phys_t *entry;

	uint64_t last = vim->vim_phys->vimp_num_entries - 1;
	uint64_t base = 0;

	/*
	 * We don't define these inside of the while loop because we use
	 * their value in the case that offset isn't in the mapping.
	 */
	uint64_t mid;
	int result;

	while (last >= base) {
		mid = base + ((last - base) >> 1);

		entry = vdev_indirect_mapping_entry(vim, mid);
		if (entry == NULL)
			break;
		result = dva_mapping_overlap_compare(&offset, entry);

		if (result == 0) {
			break;
		} else if (result < 0) {
			last = mid - 1;
		} else {
			base = mid + 1;
		}
	}
	return (entry);
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

static vdev_t *
vdev_lookup_top(spa_t *spa, uint64_t vdev)
{
	vdev_t *rvd;
	vdev_list_t *vlist;

	vlist = &spa->spa_root_vdev->v_children;
	STAILQ_FOREACH(rvd, vlist, v_childlink)
		if (rvd->v_id == vdev)
			break;

	return (rvd);
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

	if (vd->v_read == vdev_indirect_read)
		return;

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

static int
vdev_indirect_read(vdev_t *vdev, const blkptr_t *bp, void *buf,
    off_t offset, size_t bytes)
{
	zio_t zio;
	spa_t *spa = vdev->v_spa;
	indirect_vsd_t *iv;
	indirect_split_t *first;
	int rc = EIO;

	iv = calloc(1, sizeof (*iv));
	if (iv == NULL)
		return (ENOMEM);

	list_create(&iv->iv_splits,
	    sizeof (indirect_split_t), offsetof(indirect_split_t, is_node));

	bzero(&zio, sizeof (zio));
	zio.io_spa = spa;
	zio.io_bp = (blkptr_t *)bp;
	zio.io_data = buf;
	zio.io_size = bytes;
	zio.io_offset = offset;
	zio.io_vd = vdev;
	zio.io_vsd = iv;

	if (vdev->v_mapping == NULL) {
		vdev_indirect_config_t *vic;

		vic = &vdev->vdev_indirect_config;
		vdev->v_mapping = vdev_indirect_mapping_open(spa,
		    &spa->spa_mos, vic->vic_mapping_object);
	}

	vdev_indirect_remap(vdev, offset, bytes, &zio);
	if (zio.io_error != 0)
		return (zio.io_error);

	first = list_head(&iv->iv_splits);
	if (first->is_size == zio.io_size) {
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
		rc = first->is_vdev->v_read(first->is_vdev, zio.io_bp,
		    zio.io_data, first->is_target_offset, bytes);
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
			char *ptr = zio.io_data;

			rc = is->is_vdev->v_read(is->is_vdev, zio.io_bp,
			    ptr + is->is_split_offset, is->is_target_offset,
			    is->is_size);
		}
		if (zio_checksum_verify(spa, zio.io_bp, zio.io_data))
			rc = ECKSUM;
		else
			rc = 0;
	}

	vdev_indirect_map_free(&zio);
	if (rc == 0)
		rc = zio.io_error;

	return (rc);
}

static int
vdev_disk_read(vdev_t *vdev, const blkptr_t *bp, void *buf,
    off_t offset, size_t bytes)
{

	return (vdev_read_phys(vdev, bp, buf,
	    offset + VDEV_LABEL_START_SIZE, bytes));
}

static int
vdev_missing_read(vdev_t *vdev __unused, const blkptr_t *bp __unused,
    void *buf __unused, off_t offset __unused, size_t bytes __unused)
{

	return (ENOTSUP);
}

static int
vdev_mirror_read(vdev_t *vdev, const blkptr_t *bp, void *buf,
    off_t offset, size_t bytes)
{
	vdev_t *kid;
	int rc;

	rc = EIO;
	STAILQ_FOREACH(kid, &vdev->v_children, v_childlink) {
		if (kid->v_state != VDEV_STATE_HEALTHY)
			continue;
		rc = kid->v_read(kid, bp, buf, offset, bytes);
		if (!rc)
			return (0);
	}

	return (rc);
}

static int
vdev_replacing_read(vdev_t *vdev, const blkptr_t *bp, void *buf,
    off_t offset, size_t bytes)
{
	vdev_t *kid;

	/*
	 * Here we should have two kids:
	 * First one which is the one we are replacing and we can trust
	 * only this one to have valid data, but it might not be present.
	 * Second one is that one we are replacing with. It is most likely
	 * healthy, but we can't trust it has needed data, so we won't use it.
	 */
	kid = STAILQ_FIRST(&vdev->v_children);
	if (kid == NULL)
		return (EIO);
	if (kid->v_state != VDEV_STATE_HEALTHY)
		return (EIO);
	return (kid->v_read(kid, bp, buf, offset, bytes));
}

static vdev_t *
vdev_find(uint64_t guid)
{
	vdev_t *vdev;

	STAILQ_FOREACH(vdev, &zfs_vdevs, v_alllink)
		if (vdev->v_guid == guid)
			return (vdev);

	return (0);
}

static vdev_t *
vdev_create(uint64_t guid, vdev_read_t *vdev_read)
{
	vdev_t *vdev;
	vdev_indirect_config_t *vic;

	vdev = calloc(1, sizeof (vdev_t));
	if (vdev != NULL) {
		STAILQ_INIT(&vdev->v_children);
		vdev->v_guid = guid;
		vdev->v_read = vdev_read;

		/*
		 * root vdev has no read function, we use this fact to
		 * skip setting up data we do not need for root vdev.
		 * We only point root vdev from spa.
		 */
		if (vdev_read != NULL) {
			vic = &vdev->vdev_indirect_config;
			vic->vic_prev_indirect_vdev = UINT64_MAX;
			STAILQ_INSERT_TAIL(&zfs_vdevs, vdev, v_alllink);
		}
	}

	return (vdev);
}

static void
vdev_set_initial_state(vdev_t *vdev, nvlist_t *nvlist)
{
	uint64_t value;
	int rv;

	rv = nvlist_lookup_uint64(nvlist, ZPOOL_CONFIG_OFFLINE, &value);
	if (rv == 0 && value != 0)
		vdev->v_state = VDEV_STATE_OFFLINE;

	rv = nvlist_lookup_uint64(nvlist, ZPOOL_CONFIG_REMOVED, &value);
	if (rv == 0 && value != 0)
		vdev->v_state = VDEV_STATE_REMOVED;

	rv = nvlist_lookup_uint64(nvlist, ZPOOL_CONFIG_FAULTED, &value);
	if (rv == 0 && value != 0)
		vdev->v_state = VDEV_STATE_FAULTED;

	rv = nvlist_lookup_uint64(nvlist, ZPOOL_CONFIG_DEGRADED, &value);
	if (rv == 0 && value != 0)
		vdev->v_state = VDEV_STATE_DEGRADED;

	rv = nvlist_lookup_uint64(nvlist, ZPOOL_CONFIG_NOT_PRESENT, &value);
	if (rv == 0 && value != 0)
		vdev->v_state = VDEV_STATE_CANT_OPEN;

	rv = nvlist_lookup_uint64(nvlist, ZPOOL_CONFIG_IS_LOG, &value);
	if (rv == 0)
		vdev->v_islog = value != 0;
}

static int
vdev_init(uint64_t guid, nvlist_t *nvlist, vdev_t **vdevp)
{
	uint64_t id, ashift, asize, nparity;
	char *path;
	char *type;
	vdev_t *vdev;

	if (nvlist_lookup_uint64(nvlist, ZPOOL_CONFIG_ID, &id) ||
	    nvlist_lookup_string(nvlist, ZPOOL_CONFIG_TYPE, &type)) {
		return (ENOENT);
	}

	if (strcmp(type, VDEV_TYPE_MIRROR) != 0 &&
	    strcmp(type, VDEV_TYPE_DISK) != 0 &&
#ifdef ZFS_TEST
	    strcmp(type, VDEV_TYPE_FILE) != 0 &&
#endif
	    strcmp(type, VDEV_TYPE_RAIDZ) != 0 &&
	    strcmp(type, VDEV_TYPE_INDIRECT) != 0 &&
	    strcmp(type, VDEV_TYPE_REPLACING) != 0 &&
	    strcmp(type, VDEV_TYPE_HOLE) != 0) {
		printf("ZFS: can only boot from disk, mirror, raidz1, "
		    "raidz2 and raidz3 vdevs, got: %s\n", type);
		return (EIO);
	}

	if (strcmp(type, VDEV_TYPE_MIRROR) == 0)
		vdev = vdev_create(guid, vdev_mirror_read);
	else if (strcmp(type, VDEV_TYPE_RAIDZ) == 0)
		vdev = vdev_create(guid, vdev_raidz_read);
	else if (strcmp(type, VDEV_TYPE_REPLACING) == 0)
		vdev = vdev_create(guid, vdev_replacing_read);
	else if (strcmp(type, VDEV_TYPE_INDIRECT) == 0) {
		vdev_indirect_config_t *vic;

		vdev = vdev_create(guid, vdev_indirect_read);
		if (vdev != NULL) {
			vdev->v_state = VDEV_STATE_HEALTHY;
			vic = &vdev->vdev_indirect_config;

			(void) nvlist_lookup_uint64(nvlist,
			    ZPOOL_CONFIG_INDIRECT_OBJECT,
			    &vic->vic_mapping_object);
			(void) nvlist_lookup_uint64(nvlist,
			    ZPOOL_CONFIG_INDIRECT_BIRTHS,
			    &vic->vic_births_object);
			(void) nvlist_lookup_uint64(nvlist,
			    ZPOOL_CONFIG_PREV_INDIRECT_VDEV,
			    &vic->vic_prev_indirect_vdev);
		}
	} else if (strcmp(type, VDEV_TYPE_HOLE) == 0) {
		vdev = vdev_create(guid, vdev_missing_read);
	} else {
		vdev = vdev_create(guid, vdev_disk_read);
	}

	if (vdev == NULL)
		return (ENOMEM);

	vdev_set_initial_state(vdev, nvlist);
	vdev->v_id = id;
	if (nvlist_lookup_uint64(nvlist, ZPOOL_CONFIG_ASHIFT, &ashift) == 0)
		vdev->v_ashift = ashift;

	if (nvlist_lookup_uint64(nvlist, ZPOOL_CONFIG_ASIZE, &asize) == 0) {
		vdev->v_psize = asize +
		    VDEV_LABEL_START_SIZE + VDEV_LABEL_END_SIZE;
	}

	if (nvlist_lookup_uint64(nvlist, ZPOOL_CONFIG_NPARITY, &nparity) == 0)
		vdev->v_nparity = nparity;

	if (nvlist_lookup_string(nvlist, ZPOOL_CONFIG_PATH, &path) == 0) {
		char prefix[] = "/dev/dsk/";
		size_t len;

		len = strlen(prefix);
		if (memcmp(path, prefix, len) == 0) {
			path += len;
		}
		vdev->v_name = strdup(path);
		vdev->v_phys_path = NULL;
		vdev->v_devid = NULL;
		if (nvlist_lookup_string(nvlist, ZPOOL_CONFIG_PHYS_PATH,
		    &path) == 0) {
			vdev->v_phys_path = strdup(path);
		}
		if (nvlist_lookup_string(nvlist, ZPOOL_CONFIG_DEVID,
		    &path) == 0) {
			vdev->v_devid = strdup(path);
		}
	} else {
		char *name = NULL;

		if (strcmp(type, VDEV_TYPE_RAIDZ) == 0) {
			if (vdev->v_nparity < 1 ||
			    vdev->v_nparity > 3) {
				printf("ZFS: invalid raidz parity: %d\n",
				    vdev->v_nparity);
				return (EIO);
			}
			(void) asprintf(&name, "%s%d-%" PRIu64, type,
			    vdev->v_nparity, id);
		} else {
			(void) asprintf(&name, "%s-%" PRIu64, type, id);
		}
		vdev->v_name = name;
	}
	*vdevp = vdev;
	return (0);
}

/*
 * Find slot for vdev. We return either NULL to signal to use
 * STAILQ_INSERT_HEAD, or we return link element to be used with
 * STAILQ_INSERT_AFTER.
 */
static vdev_t *
vdev_find_previous(vdev_t *top_vdev, vdev_t *vdev)
{
	vdev_t *v, *previous;

	if (STAILQ_EMPTY(&top_vdev->v_children))
		return (NULL);

	previous = NULL;
	STAILQ_FOREACH(v, &top_vdev->v_children, v_childlink) {
		if (v->v_id > vdev->v_id)
			return (previous);

		if (v->v_id == vdev->v_id)
			return (v);

		if (v->v_id < vdev->v_id)
			previous = v;
	}
	return (previous);
}

static size_t
vdev_child_count(vdev_t *vdev)
{
	vdev_t *v;
	size_t count;

	count = 0;
	STAILQ_FOREACH(v, &vdev->v_children, v_childlink) {
		count++;
	}
	return (count);
}

/*
 * Insert vdev into top_vdev children list. List is ordered by v_id.
 */
static void
vdev_insert(vdev_t *top_vdev, vdev_t *vdev)
{
	vdev_t *previous;
	size_t count;

	/*
	 * The top level vdev can appear in random order, depending how
	 * the firmware is presenting the disk devices.
	 * However, we will insert vdev to create list ordered by v_id,
	 * so we can use either STAILQ_INSERT_HEAD or STAILQ_INSERT_AFTER
	 * as STAILQ does not have insert before.
	 */
	previous = vdev_find_previous(top_vdev, vdev);

	if (previous == NULL) {
		STAILQ_INSERT_HEAD(&top_vdev->v_children, vdev, v_childlink);
	} else if (previous->v_id == vdev->v_id) {
		/*
		 * This vdev was configured from label config,
		 * do not insert duplicate.
		 */
		return;
	} else {
		STAILQ_INSERT_AFTER(&top_vdev->v_children, previous, vdev,
		    v_childlink);
	}

	count = vdev_child_count(top_vdev);
	if (top_vdev->v_nchildren < count)
		top_vdev->v_nchildren = count;
}

static int
vdev_from_nvlist(spa_t *spa, uint64_t top_guid, nvlist_t *nvlist)
{
	vdev_t *top_vdev, *vdev;
	nvlist_t **kids = NULL;
	int rc;
	uint_t nkids;

	/* Get top vdev. */
	top_vdev = vdev_find(top_guid);
	if (top_vdev == NULL) {
		rc = vdev_init(top_guid, nvlist, &top_vdev);
		if (rc != 0)
			return (rc);
		top_vdev->v_spa = spa;
		top_vdev->v_top = top_vdev;
		vdev_insert(spa->spa_root_vdev, top_vdev);
	}

	/* Add children if there are any. */
	rc = nvlist_lookup_nvlist_array(nvlist, ZPOOL_CONFIG_CHILDREN,
	    &kids, &nkids);
	if (rc == 0) {
		for (uint_t i = 0; i < nkids; i++) {
			uint64_t guid;

			rc = nvlist_lookup_uint64(kids[i], ZPOOL_CONFIG_GUID,
			    &guid);
			if (rc != 0)
				break;

			rc = vdev_init(guid, kids[i], &vdev);
			if (rc != 0)
				break;

			vdev->v_spa = spa;
			vdev->v_top = top_vdev;
			vdev_insert(top_vdev, vdev);
		}
	} else {
		/*
		 * When there are no children, nvlist_lookup_nvlist_array()
		 * does return error, reset it because leaf devices have no
		 * children.
		 */
		if (rc == ENOENT)
			rc = 0;
	}

	return (rc);
}

static int
vdev_init_from_label(spa_t *spa, nvlist_t *nvlist)
{
	uint64_t pool_guid, top_guid;
	nvlist_t *vdevs;
	int rc;

	if (nvlist_lookup_uint64(nvlist, ZPOOL_CONFIG_POOL_GUID, &pool_guid) ||
	    nvlist_lookup_uint64(nvlist, ZPOOL_CONFIG_TOP_GUID, &top_guid) ||
	    nvlist_lookup_nvlist(nvlist, ZPOOL_CONFIG_VDEV_TREE, &vdevs)) {
		printf("ZFS: can't find vdev details\n");
		return (ENOENT);
	}

	rc = vdev_from_nvlist(spa, top_guid, vdevs);
	return (rc);
}

static void
vdev_set_state(vdev_t *vdev)
{
	vdev_t *kid;
	int good_kids;
	int bad_kids;

	STAILQ_FOREACH(kid, &vdev->v_children, v_childlink) {
		vdev_set_state(kid);
	}

	/*
	 * A mirror or raidz is healthy if all its kids are healthy. A
	 * mirror is degraded if any of its kids is healthy; a raidz
	 * is degraded if at most nparity kids are offline.
	 */
	if (STAILQ_FIRST(&vdev->v_children)) {
		good_kids = 0;
		bad_kids = 0;
		STAILQ_FOREACH(kid, &vdev->v_children, v_childlink) {
			if (kid->v_state == VDEV_STATE_HEALTHY)
				good_kids++;
			else
				bad_kids++;
		}
		if (bad_kids == 0) {
			vdev->v_state = VDEV_STATE_HEALTHY;
		} else {
			if (vdev->v_read == vdev_mirror_read) {
				if (good_kids) {
					vdev->v_state = VDEV_STATE_DEGRADED;
				} else {
					vdev->v_state = VDEV_STATE_OFFLINE;
				}
			} else if (vdev->v_read == vdev_raidz_read) {
				if (bad_kids > vdev->v_nparity) {
					vdev->v_state = VDEV_STATE_OFFLINE;
				} else {
					vdev->v_state = VDEV_STATE_DEGRADED;
				}
			}
		}
	}
}

static int
vdev_update_from_nvlist(uint64_t top_guid, nvlist_t *nvlist)
{
	vdev_t *vdev;
	nvlist_t **kids = NULL;
	int rc;
	uint_t nkids;

	/* Update top vdev. */
	vdev = vdev_find(top_guid);
	if (vdev != NULL)
		vdev_set_initial_state(vdev, nvlist);

	/* Update children if there are any. */
	rc = nvlist_lookup_nvlist_array(nvlist, ZPOOL_CONFIG_CHILDREN,
	    &kids, &nkids);
	if (rc == 0) {
		for (uint_t i = 0; i < nkids; i++) {
			uint64_t guid;

			rc = nvlist_lookup_uint64(kids[i], ZPOOL_CONFIG_GUID,
			    &guid);
			if (rc != 0)
				break;

			vdev = vdev_find(guid);
			if (vdev != NULL)
				vdev_set_initial_state(vdev, kids[i]);
		}
	} else {
		if (rc == ENOENT)
			rc = 0;
	}

	return (rc);
}

static int
vdev_init_from_nvlist(spa_t *spa, nvlist_t *nvlist)
{
	uint64_t pool_guid, vdev_children;
	nvlist_t *vdevs = NULL, **kids = NULL;
	int rc;
	uint_t nkids;

	if (nvlist_lookup_uint64(nvlist, ZPOOL_CONFIG_POOL_GUID, &pool_guid) ||
	    nvlist_lookup_uint64(nvlist, ZPOOL_CONFIG_VDEV_CHILDREN,
	    &vdev_children) ||
	    nvlist_lookup_nvlist(nvlist, ZPOOL_CONFIG_VDEV_TREE, &vdevs)) {
		printf("ZFS: can't find vdev details\n");
		return (ENOENT);
	}

	/* Wrong guid?! */
	if (spa->spa_guid != pool_guid) {
		return (EINVAL);
	}

	spa->spa_root_vdev->v_nchildren = vdev_children;

	rc = nvlist_lookup_nvlist_array(vdevs, ZPOOL_CONFIG_CHILDREN,
	    &kids, &nkids);

	/*
	 * MOS config has at least one child for root vdev.
	 */
	if (rc != 0)
		return (rc);

	for (uint_t i = 0; i < nkids; i++) {
		uint64_t guid;
		vdev_t *vdev;

		rc = nvlist_lookup_uint64(kids[i], ZPOOL_CONFIG_GUID, &guid);
		if (rc != 0)
			break;
		vdev = vdev_find(guid);
		/*
		 * Top level vdev is missing, create it.
		 */
		if (vdev == NULL)
			rc = vdev_from_nvlist(spa, guid, kids[i]);
		else
			rc = vdev_update_from_nvlist(guid, kids[i]);
		if (rc != 0)
			break;
	}

	/*
	 * Re-evaluate top-level vdev state.
	 */
	vdev_set_state(spa->spa_root_vdev);

	return (rc);
}

static spa_t *
spa_find_by_guid(uint64_t guid)
{
	spa_t *spa;

	STAILQ_FOREACH(spa, &zfs_pools, spa_link)
		if (spa->spa_guid == guid)
			return (spa);

	return (NULL);
}

static spa_t *
spa_find_by_name(const char *name)
{
	spa_t *spa;

	STAILQ_FOREACH(spa, &zfs_pools, spa_link)
		if (strcmp(spa->spa_name, name) == 0)
			return (spa);

	return (NULL);
}

static spa_t *
spa_find_by_dev(struct zfs_devdesc *dev)
{

	if (dev->dd.d_dev->dv_type != DEVT_ZFS)
		return (NULL);

	if (dev->pool_guid == 0)
		return (STAILQ_FIRST(&zfs_pools));

	return (spa_find_by_guid(dev->pool_guid));
}

dsl_wrapping_key_t *
spa_get_wkey(uint64_t pguid, uint64_t dguid)
{
	spa_t *spa = spa_find_by_guid(pguid);
	dsl_wrapping_key_t search_wkey, *wk = NULL;
	dnode_phys_t dir;
	dsl_dataset_phys_t *ds;
	uint64_t dir_obj, crypto_obj, dd_obj;

	/* get DSL dataset for dguid */
	if (objset_get_dnode(spa, &spa->spa_mos, dguid, &dir))
		return (wk);

	ds = (dsl_dataset_phys_t *)&dir.dn_bonus;
	dir_obj = ds->ds_dir_obj;

	/* get directory object */
	if (objset_get_dnode(spa, &spa->spa_mos, dir_obj, &dir))
		return (wk);

	if (zap_lookup(spa, &dir, DD_FIELD_CRYPTO_KEY_OBJ,
	    sizeof (crypto_obj), 1, &crypto_obj))
		return (wk);

	/* get DSL_CRYPTO_ROOT_DDOBJ */
	if (objset_get_dnode(spa, &spa->spa_mos, crypto_obj, &dir))
		return (wk);

	if (zap_lookup(spa, &dir, DSL_CRYPTO_KEY_ROOT_DDOBJ,
	    sizeof (dd_obj), 1, &dd_obj))
		return (wk);

	search_wkey.wk_ddobj = dd_obj;
	wk = avl_find(&spa->spa_keystore.sk_wkeys, &search_wkey, NULL);
	return (wk);
}

int
spa_set_wkey(uint64_t guid, uint8_t *wkeydata, zfs_keyformat_t keyformat,
    uint64_t salt, uint64_t iters, uint64_t ddobj)
{
	dsl_wrapping_key_t *wkey;
	spa_t *spa;
	int rv;

	spa = spa_find_by_guid(guid);
	if (spa == NULL)
		return (ENOENT);

	rv = dsl_wrapping_key_create(wkeydata, keyformat, salt, iters, &wkey);
	if (rv != 0)
		return (rv);

	wkey->wk_ddobj = ddobj;
	avl_add(&spa->spa_keystore.sk_wkeys, wkey);
	return (rv);
}

static int
spa_crypto_key_compare(const void *a, const void *b)
{
	const dsl_crypto_key_t *dcka = a;
	const dsl_crypto_key_t *dckb = b;

	if (dcka->dck_obj < dckb->dck_obj)
		return (-1);
	if (dcka->dck_obj > dckb->dck_obj)
		return (1);
	return (0);
}

static int
spa_key_mapping_compare(const void *a, const void *b)
{
	const dsl_key_mapping_t *kma = a;
	const dsl_key_mapping_t *kmb = b;

	if (kma->km_dsobj < kmb->km_dsobj)
		return (-1);
	if (kma->km_dsobj > kmb->km_dsobj)
		return (1);
	return (0);
}

static int
spa_wkey_compare(const void *a, const void *b)
{
	const dsl_wrapping_key_t *wka = a;
	const dsl_wrapping_key_t *wkb = b;

	if (wka->wk_ddobj < wkb->wk_ddobj)
		return (-1);
	if (wka->wk_ddobj > wkb->wk_ddobj)
		return (1);
	return (0);
}

static void
spa_keystore_init(spa_keystore_t *sk)
{
	avl_create(&sk->sk_dsl_keys, spa_crypto_key_compare,
	    sizeof (dsl_crypto_key_t),
	    offsetof(dsl_crypto_key_t, dck_avl_link));
	avl_create(&sk->sk_key_mappings, spa_key_mapping_compare,
	    sizeof (dsl_key_mapping_t),
	    offsetof(dsl_key_mapping_t, km_avl_link));
	avl_create(&sk->sk_wkeys, spa_wkey_compare, sizeof (dsl_wrapping_key_t),
	    offsetof(dsl_wrapping_key_t, wk_avl_link));
}

static spa_t *
spa_create(uint64_t guid, const char *name)
{
	spa_t *spa;

	if ((spa = calloc(1, sizeof (spa_t))) == NULL)
		return (NULL);
	if ((spa->spa_name = strdup(name)) == NULL) {
		free(spa);
		return (NULL);
	}
	spa->spa_guid = guid;
	spa->spa_root_vdev = vdev_create(guid, NULL);
	if (spa->spa_root_vdev == NULL) {
		free(spa->spa_name);
		free(spa);
		return (NULL);
	}
	spa->spa_root_vdev->v_name = strdup("root");

	spa_keystore_init(&spa->spa_keystore);

	STAILQ_INSERT_TAIL(&zfs_pools, spa, spa_link);

	return (spa);
}

static const char *
state_name(vdev_state_t state)
{
	static const char *names[] = {
		"UNKNOWN",
		"CLOSED",
		"OFFLINE",
		"REMOVED",
		"CANT_OPEN",
		"FAULTED",
		"DEGRADED",
		"ONLINE"
	};
	return (names[state]);
}

static int
pager_printf(const char *fmt, ...)
{
	char line[80];
	va_list args;

	va_start(args, fmt);
	vsnprintf(line, sizeof (line), fmt, args);
	va_end(args);
	return (pager_output(line));
}

#define	STATUS_FORMAT	"        %s %s\n"

static int
print_state(int indent, const char *name, vdev_state_t state)
{
	int i;
	char buf[512];

	buf[0] = 0;
	for (i = 0; i < indent; i++)
		strcat(buf, "  ");
	strcat(buf, name);
	return (pager_printf(STATUS_FORMAT, buf, state_name(state)));
}

static int
vdev_status(vdev_t *vdev, int indent)
{
	vdev_t *kid;
	int ret;

	if (vdev->v_islog) {
		(void) pager_output("        logs\n");
		indent++;
	}

	ret = print_state(indent, vdev->v_name, vdev->v_state);
	if (ret != 0)
		return (ret);

	STAILQ_FOREACH(kid, &vdev->v_children, v_childlink) {
		ret = vdev_status(kid, indent + 1);
		if (ret != 0)
			return (ret);
	}
	return (ret);
}

static int
spa_status(spa_t *spa)
{
	static char bootfs[ZFS_MAXNAMELEN];
	uint64_t rootid;
	vdev_list_t *vlist;
	vdev_t *vdev;
	int good_kids, bad_kids, degraded_kids, ret;
	vdev_state_t state;

	ret = pager_printf("  pool: %s\n", spa->spa_name);
	if (ret != 0)
		return (ret);

	if (zfs_get_root(spa, &rootid) == 0 &&
	    zfs_rlookup(spa, rootid, bootfs) == 0) {
		if (bootfs[0] == '\0')
			ret = pager_printf("bootfs: %s\n", spa->spa_name);
		else
			ret = pager_printf("bootfs: %s/%s\n", spa->spa_name,
			    bootfs);
		if (ret != 0)
			return (ret);
	}
	ret = pager_printf("config:\n\n");
	if (ret != 0)
		return (ret);
	ret = pager_printf(STATUS_FORMAT, "NAME", "STATE");
	if (ret != 0)
		return (ret);

	good_kids = 0;
	degraded_kids = 0;
	bad_kids = 0;
	vlist = &spa->spa_root_vdev->v_children;
	STAILQ_FOREACH(vdev, vlist, v_childlink) {
		if (vdev->v_state == VDEV_STATE_HEALTHY)
			good_kids++;
		else if (vdev->v_state == VDEV_STATE_DEGRADED)
			degraded_kids++;
		else
			bad_kids++;
	}

	state = VDEV_STATE_CLOSED;
	if (good_kids > 0 && (degraded_kids + bad_kids) == 0)
		state = VDEV_STATE_HEALTHY;
	else if ((good_kids + degraded_kids) > 0)
		state = VDEV_STATE_DEGRADED;

	ret = print_state(0, spa->spa_name, state);
	if (ret != 0)
		return (ret);

	STAILQ_FOREACH(vdev, vlist, v_childlink) {
		ret = vdev_status(vdev, 1);
		if (ret != 0)
			return (ret);
	}
	return (ret);
}

int
spa_all_status(void)
{
	spa_t *spa;
	int first = 1, ret = 0;

	STAILQ_FOREACH(spa, &zfs_pools, spa_link) {
		if (!first) {
			ret = pager_printf("\n");
			if (ret != 0)
				return (ret);
		}
		first = 0;
		ret = spa_status(spa);
		if (ret != 0)
			return (ret);
	}
	return (ret);
}

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

static int
vdev_uberblock_compare(const uberblock_t *ub1, const uberblock_t *ub2)
{
	unsigned int seq1 = 0;
	unsigned int seq2 = 0;
	int cmp = AVL_CMP(ub1->ub_txg, ub2->ub_txg);

	if (cmp != 0)
		return (cmp);

	cmp = AVL_CMP(ub1->ub_timestamp, ub2->ub_timestamp);
	if (cmp != 0)
		return (cmp);

	if (MMP_VALID(ub1) && MMP_SEQ_VALID(ub1))
		seq1 = MMP_SEQ(ub1);

	if (MMP_VALID(ub2) && MMP_SEQ_VALID(ub2))
		seq2 = MMP_SEQ(ub2);

	return (AVL_CMP(seq1, seq2));
}

static int
uberblock_verify(uberblock_t *ub)
{
	if (ub->ub_magic == BSWAP_64((uint64_t)UBERBLOCK_MAGIC)) {
		byteswap_uint64_array(ub, sizeof (uberblock_t));
	}

	if (ub->ub_magic != UBERBLOCK_MAGIC ||
	    !SPA_VERSION_IS_SUPPORTED(ub->ub_version))
		return (EINVAL);

	return (0);
}

static int
vdev_label_read(vdev_t *vd, int l, void *buf, uint64_t offset,
    size_t size)
{
	blkptr_t bp;
	off_t off;

	off = vdev_label_offset(vd->v_psize, l, offset);

	BP_ZERO(&bp);
	BP_SET_LSIZE(&bp, size);
	BP_SET_PSIZE(&bp, size);
	BP_SET_CHECKSUM(&bp, ZIO_CHECKSUM_LABEL);
	BP_SET_COMPRESS(&bp, ZIO_COMPRESS_OFF);
	DVA_SET_OFFSET(BP_IDENTITY(&bp), off);
	ZIO_SET_CHECKSUM(&bp.blk_cksum, off, 0, 0, 0);

	return (vdev_read_phys(vd, &bp, buf, off, size));
}

/*
 * We do need to be sure we write to correct location.
 * Our vdev label does consist of 4 fields:
 * pad1 (8k), reserved.
 * bootenv (8k), checksummed, previously reserved, may contain garbage.
 * vdev_phys (112k), checksummed
 * uberblock ring (128k), checksummed.
 *
 * Since bootenv area may contain garbage, we can not reliably read it, as
 * we can get checksum errors.
 * Next best thing is vdev_phys - it is just after bootenv. It still may
 * be corrupted, but in such case we will miss this one write.
 */
static int
vdev_label_write_validate(vdev_t *vd, int l, uint64_t offset)
{
	uint64_t off, o_phys;
	void *buf;
	size_t size = VDEV_PHYS_SIZE;
	int rc;

	o_phys = offsetof(vdev_label_t, vl_vdev_phys);
	off = vdev_label_offset(vd->v_psize, l, o_phys);

	/* off should be 8K from bootenv */
	if (vdev_label_offset(vd->v_psize, l, offset) + VDEV_PAD_SIZE != off)
		return (EINVAL);

	buf = malloc(size);
	if (buf == NULL)
		return (ENOMEM);

	/* Read vdev_phys */
	rc = vdev_label_read(vd, l, buf, o_phys, size);
	free(buf);
	return (rc);
}

static int
vdev_label_write(vdev_t *vd, int l, vdev_boot_envblock_t *be, uint64_t offset)
{
	zio_checksum_info_t *ci;
	zio_cksum_t cksum;
	off_t off;
	size_t size = VDEV_PAD_SIZE;
	int rc;

	if (vd->v_phys_write == NULL)
		return (ENOTSUP);

	off = vdev_label_offset(vd->v_psize, l, offset);

	rc = vdev_label_write_validate(vd, l, offset);
	if (rc != 0) {
		return (rc);
	}

	ci = &zio_checksum_table[ZIO_CHECKSUM_LABEL];
	be->vbe_zbt.zec_magic = ZEC_MAGIC;
	zio_checksum_label_verifier(&be->vbe_zbt.zec_cksum, off);
	ci->ci_func[0](be, size, NULL, &cksum);
	be->vbe_zbt.zec_cksum = cksum;

	return (vdev_write_phys(vd, be, off, size));
}

static int
vdev_write_bootenv_impl(vdev_t *vdev, vdev_boot_envblock_t *be)
{
	vdev_t *kid;
	int rv = 0, err;

	STAILQ_FOREACH(kid, &vdev->v_children, v_childlink) {
		if (kid->v_state != VDEV_STATE_HEALTHY)
			continue;
		err = vdev_write_bootenv_impl(kid, be);
		if (err != 0)
			rv = err;
	}

	/*
	 * Non-leaf vdevs do not have v_phys_write.
	 */
	if (vdev->v_phys_write == NULL)
		return (rv);

	for (int l = 0; l < VDEV_LABELS; l++) {
		err = vdev_label_write(vdev, l, be,
		    offsetof(vdev_label_t, vl_be));
		if (err != 0) {
			printf("failed to write bootenv to %s label %d: %d\n",
			    vdev->v_name ? vdev->v_name : "unknown", l, err);
			rv = err;
		}
	}
	return (rv);
}

int
vdev_write_bootenv(vdev_t *vdev, nvlist_t *nvl)
{
	vdev_boot_envblock_t *be;
	nvlist_t *nvp;
	uint64_t version;
	size_t size;
	char *data;
	int rv;

	rv = nvlist_size(nvl, &size, NV_ENCODE_XDR);
	if (rv != 0)
		return (rv);
	if (size > sizeof (be->vbe_bootenv))
		return (E2BIG);

	version = VB_RAW;
	nvp = vdev_read_bootenv(vdev);
	if (nvp != NULL) {
		rv = nvlist_lookup_uint64(nvp, BOOTENV_VERSION, &version);
		nvlist_free(nvp);
	}

	be = calloc(1, sizeof (*be));
	if (be == NULL)
		return (ENOMEM);

	switch (version) {
	case VB_RAW:
		/*
		 * If there is no envmap, we will just wipe bootenv.
		 */
		rv = nvlist_lookup_string(nvl, GRUB_ENVMAP, &data);
		(void) strlcpy(be->vbe_bootenv, data, sizeof (be->vbe_bootenv));
		break;

	case VB_NVLIST:
		size = sizeof (be->vbe_bootenv);
		data = be->vbe_bootenv;
		/* Remove BOOTENV_VERSION from on disk nvlist */
		(void) nvlist_remove(nvl, BOOTENV_VERSION, DATA_TYPE_UINT64);
		rv = nvlist_pack(nvl, &data, &size, NV_ENCODE_XDR, 0);
		nvlist_add_uint64(nvl, BOOTENV_VERSION, VB_NVLIST);
		break;

	default:
		rv = EINVAL;
		break;
	}

	if (rv == 0) {
		be->vbe_version = htobe64(version);
		rv = vdev_write_bootenv_impl(vdev, be);
	}
	free(be);
	return (rv);
}

/*
 * Read the bootenv area from pool label, return the nvlist from it.
 * We return from first successful read.
 */
nvlist_t *
vdev_read_bootenv(vdev_t *vdev)
{
	vdev_t *kid;
	nvlist_t *benv;
	vdev_boot_envblock_t *be;
	char *command;
	bool ok;
	int rv;

	STAILQ_FOREACH(kid, &vdev->v_children, v_childlink) {
		if (kid->v_state != VDEV_STATE_HEALTHY)
			continue;

		benv = vdev_read_bootenv(kid);
		if (benv != NULL)
			return (benv);
	}

	be = malloc(sizeof (*be));
	if (be == NULL)
		return (NULL);

	rv = 0;
	for (int l = 0; l < VDEV_LABELS; l++) {
		rv = vdev_label_read(vdev, l, be,
		    offsetof(vdev_label_t, vl_be),
		    sizeof (*be));
		if (rv == 0)
			break;
	}
	if (rv != 0) {
		free(be);
		return (NULL);
	}

	be->vbe_version = be64toh(be->vbe_version);
	switch (be->vbe_version) {
	case VB_RAW:
		/*
		 * if we have textual data in vbe_bootenv, create nvlist
		 * with key "envmap".
		 */
		rv = nvlist_alloc(&benv, NV_UNIQUE_NAME, 0);
		if (rv == 0) {
			if (*be->vbe_bootenv == '\0') {
				nvlist_add_uint64(benv, BOOTENV_VERSION,
				    VB_NVLIST);
				break;
			}
			nvlist_add_uint64(benv, BOOTENV_VERSION, VB_RAW);
			be->vbe_bootenv[sizeof (be->vbe_bootenv) - 1] = '\0';
			nvlist_add_string(benv, GRUB_ENVMAP, be->vbe_bootenv);
		}
		break;

	case VB_NVLIST:
		if (nvlist_unpack(be->vbe_bootenv, sizeof (be->vbe_bootenv),
		    &benv, 0) != 0)
			benv = NULL;
		else
			nvlist_add_uint64(benv, BOOTENV_VERSION, VB_NVLIST);
		break;

	default:
		command = (char *)be;
		ok = false;

		/* Check for legacy zfsbootcfg command string */
		for (int i = 0; command[i] != '\0'; i++) {
			if (iscntrl(command[i])) {
				ok = false;
				break;
			} else {
				ok = true;
			}
		}
		rv = nvlist_alloc(&benv, NV_UNIQUE_NAME, 0);
		if (rv == 0) {
			if (ok)
				nvlist_add_string(benv, FREEBSD_BOOTONCE,
				    command);
			else
				nvlist_add_uint64(benv, BOOTENV_VERSION,
				    VB_NVLIST);
		}
		break;
	}
	free(be);
	return (benv);
}

static uint64_t
vdev_get_label_asize(nvlist_t *nvl)
{
	nvlist_t *vdevs;
	uint64_t asize;
	char *type;

	asize = 0;
	/* Get vdev tree */
	if (nvlist_lookup_nvlist(nvl, ZPOOL_CONFIG_VDEV_TREE, &vdevs) != 0)
		goto done;

	/*
	 * Get vdev type. We will calculate asize for raidz, mirror and disk.
	 * For raidz, the asize is raw size of all children.
	 */
	if (nvlist_lookup_string(vdevs, ZPOOL_CONFIG_TYPE, &type) != 0)
		goto done;

	if (strcmp(type, VDEV_TYPE_MIRROR) != 0 &&
	    strcmp(type, VDEV_TYPE_DISK) != 0 &&
	    strcmp(type, VDEV_TYPE_RAIDZ) != 0)
		goto done;

	if (nvlist_lookup_uint64(vdevs, ZPOOL_CONFIG_ASIZE, &asize) != 0)
		goto done;

	if (strcmp(type, VDEV_TYPE_RAIDZ) == 0) {
		nvlist_t **kids;
		uint_t nkids;

		if (nvlist_lookup_nvlist_array(vdevs, ZPOOL_CONFIG_CHILDREN,
		    &kids, &nkids) != 0) {
			asize = 0;
			goto done;
		}

		asize /= nkids;
	}

	asize += VDEV_LABEL_START_SIZE + VDEV_LABEL_END_SIZE;
done:
	return (asize);
}

static nvlist_t *
vdev_label_read_config(vdev_t *vd, uint64_t txg)
{
	vdev_phys_t *label;
	uint64_t best_txg = 0;
	uint64_t label_txg = 0;
	uint64_t asize;
	nvlist_t *nvl = NULL, *tmp;
	int error;

	label = malloc(sizeof (vdev_phys_t));
	if (label == NULL)
		return (NULL);

	for (int l = 0; l < VDEV_LABELS; l++) {
		if (vdev_label_read(vd, l, label,
		    offsetof(vdev_label_t, vl_vdev_phys),
		    sizeof (vdev_phys_t)))
			continue;

		error = nvlist_unpack(label->vp_nvlist,
		    sizeof (label->vp_nvlist), &tmp, 0);
		if (error != 0)
			continue;

		error = nvlist_lookup_uint64(tmp, ZPOOL_CONFIG_POOL_TXG,
		    &label_txg);
		if (error != 0 || label_txg == 0) {
			nvlist_free(nvl);
			nvl = tmp;
			goto done;
		}

		if (label_txg <= txg && label_txg > best_txg) {
			best_txg = label_txg;
			nvlist_free(nvl);
			nvl = tmp;
			tmp = NULL;

			/*
			 * Use asize from pool config. We need this
			 * because we can get bad value from BIOS.
			 */
			asize = vdev_get_label_asize(nvl);
			if (asize != 0) {
				vd->v_psize = asize;
			}
		}
		nvlist_free(tmp);
	}

	if (best_txg == 0) {
		nvlist_free(nvl);
		nvl = NULL;
	}
done:
	free(label);
	return (nvl);
}

static void
vdev_uberblock_load(vdev_t *vd, uberblock_t *ub)
{
	uberblock_t *buf;

	buf = malloc(VDEV_UBERBLOCK_SIZE(vd));
	if (buf == NULL)
		return;

	for (int l = 0; l < VDEV_LABELS; l++) {
		for (int n = 0; n < VDEV_UBERBLOCK_COUNT(vd); n++) {
			if (vdev_label_read(vd, l, buf,
			    VDEV_UBERBLOCK_OFFSET(vd, n),
			    VDEV_UBERBLOCK_SIZE(vd)))
				continue;
			if (uberblock_verify(buf) != 0)
				continue;

			if (vdev_uberblock_compare(buf, ub) > 0)
				*ub = *buf;
		}
	}
	free(buf);
}

static int
vdev_probe(vdev_phys_read_t *_read, vdev_phys_write_t *_write, void *priv,
    spa_t **spap)
{
	vdev_t vtmp;
	spa_t *spa;
	vdev_t *vdev;
	nvlist_t *nvl;
	uint64_t val;
	uint64_t guid, vdev_children;
	uint64_t pool_txg, pool_guid;
	char *pool_name;
	int rc;

	/*
	 * Load the vdev label and figure out which
	 * uberblock is most current.
	 */
	memset(&vtmp, 0, sizeof (vtmp));
	vtmp.v_phys_read = _read;
	vtmp.v_phys_write = _write;
	vtmp.v_priv = priv;
	vtmp.v_psize = P2ALIGN(ldi_get_size(priv),
	    (uint64_t)sizeof (vdev_label_t));

	/* Test for minimum device size. */
	if (vtmp.v_psize < SPA_MINDEVSIZE)
		return (EIO);

	nvl = vdev_label_read_config(&vtmp, UINT64_MAX);
	if (nvl == NULL)
		return (EIO);

	if (nvlist_lookup_uint64(nvl, ZPOOL_CONFIG_VERSION, &val) != 0) {
		nvlist_free(nvl);
		return (EIO);
	}

	if (!SPA_VERSION_IS_SUPPORTED(val)) {
		printf("ZFS: unsupported ZFS version %u (should be %u)\n",
		    (unsigned)val, (unsigned)SPA_VERSION);
		nvlist_free(nvl);
		return (EIO);
	}

	/* Check ZFS features for read */
	rc = nvlist_check_features_for_read(nvl);
	if (rc != 0) {
		nvlist_free(nvl);
		return (EIO);
	}

	if (nvlist_lookup_uint64(nvl, ZPOOL_CONFIG_POOL_STATE, &val) != 0) {
		nvlist_free(nvl);
		return (EIO);
	}

	if (val == POOL_STATE_DESTROYED) {
		/* We don't boot only from destroyed pools. */
		nvlist_free(nvl);
		return (EIO);
	}

	if (nvlist_lookup_uint64(nvl, ZPOOL_CONFIG_POOL_TXG, &pool_txg) != 0 ||
	    nvlist_lookup_uint64(nvl, ZPOOL_CONFIG_POOL_GUID,
	    &pool_guid) != 0 ||
	    nvlist_lookup_string(nvl, ZPOOL_CONFIG_POOL_NAME,
	    &pool_name) != 0) {
		/*
		 * Cache and spare devices end up here - just ignore
		 * them.
		 */
		nvlist_free(nvl);
		return (EIO);
	}

	/*
	 * Create the pool if this is the first time we've seen it.
	 */
	spa = spa_find_by_guid(pool_guid);
	if (spa == NULL) {
		if (nvlist_lookup_uint64(nvl, ZPOOL_CONFIG_VDEV_CHILDREN,
		    &vdev_children) == 0)
			spa = spa_create(pool_guid, pool_name);
		if (spa == NULL) {
			nvlist_free(nvl);
			return (ENOMEM);
		}
		spa->spa_root_vdev->v_nchildren = vdev_children;
	}
	if (pool_txg > spa->spa_txg)
		spa->spa_txg = pool_txg;

	/*
	 * Get the vdev tree and create our in-core copy of it.
	 * If we already have a vdev with this guid, this must
	 * be some kind of alias (overlapping slices, dangerously dedicated
	 * disks etc).
	 */
	if (nvlist_lookup_uint64(nvl, ZPOOL_CONFIG_GUID, &guid) != 0) {
		nvlist_free(nvl);
		return (EIO);
	}
	vdev = vdev_find(guid);
	/* Has this vdev already been inited? */
	if (vdev && vdev->v_phys_read) {
		nvlist_free(nvl);
		return (EIO);
	}

	rc = vdev_init_from_label(spa, nvl);
	nvlist_free(nvl);
	if (rc != 0)
		return (rc);

	/*
	 * We should already have created an incomplete vdev for this
	 * vdev. Find it and initialise it with our read proc.
	 */
	vdev = vdev_find(guid);
	if (vdev != NULL) {
		vdev->v_phys_read = _read;
		vdev->v_phys_write = _write;
		vdev->v_priv = priv;
		vdev->v_psize = vtmp.v_psize;
		/*
		 * If no other state is set, mark vdev healthy.
		 */
		if (vdev->v_state == VDEV_STATE_UNKNOWN)
			vdev->v_state = VDEV_STATE_HEALTHY;
	} else {
		printf("ZFS: inconsistent nvlist contents\n");
		return (EIO);
	}

	if (vdev->v_islog)
		spa->spa_with_log = vdev->v_islog;

	/* Record boot vdev for spa. */
	if (spa->spa_boot_vdev == NULL)
		spa->spa_boot_vdev = vdev;

	/*
	 * Re-evaluate top-level vdev state.
	 */
	vdev_set_state(vdev->v_top);

	/*
	 * Ok, we are happy with the pool so far. Lets find
	 * the best uberblock and then we can actually access
	 * the contents of the pool.
	 */
	vdev_uberblock_load(vdev, &spa->spa_uberblock);

	if (spap != NULL)
		*spap = spa;
	return (0);
}

static int
ilog2(int n)
{
	int v;

	for (v = 0; v < 32; v++)
		if (n == (1 << v))
			return (v);
	return (-1);
}

static int
zio_read_gang(const spa_t *spa, const blkptr_t *bp, void *buf)
{
	blkptr_t gbh_bp;
	zio_gbh_phys_t zio_gb;
	char *pbuf;
	int i;

	/* Artificial BP for gang block header. */
	gbh_bp = *bp;
	BP_SET_PSIZE(&gbh_bp, SPA_GANGBLOCKSIZE);
	BP_SET_LSIZE(&gbh_bp, SPA_GANGBLOCKSIZE);
	BP_SET_CHECKSUM(&gbh_bp, ZIO_CHECKSUM_GANG_HEADER);
	BP_SET_COMPRESS(&gbh_bp, ZIO_COMPRESS_OFF);
	for (i = 0; i < SPA_DVAS_PER_BP; i++)
		DVA_SET_GANG(&gbh_bp.blk_dva[i], 0);

	/* Read gang header block using the artificial BP. */
	if (zio_read(spa, &gbh_bp, &zio_gb))
		return (EIO);

	pbuf = buf;
	for (i = 0; i < SPA_GBH_NBLKPTRS; i++) {
		blkptr_t *gbp = &zio_gb.zg_blkptr[i];

		if (BP_IS_HOLE(gbp))
			continue;
		if (zio_read(spa, gbp, pbuf))
			return (EIO);
		pbuf += BP_GET_PSIZE(gbp);
	}

	if (zio_checksum_verify(spa, bp, buf))
		return (EIO);
	return (0);
}

static void
zio_crypt_decode_params_bp(const blkptr_t *bp, uint8_t *salt, uint8_t *iv)
{
	uint64_t val64;
	uint32_t val32;

	/* for convenience, so callers don't need to check */
	if (BP_IS_AUTHENTICATED(bp)) {
		bzero(salt, ZIO_DATA_SALT_LEN);
		bzero(iv, ZIO_DATA_IV_LEN);
		return;
	}

	if (!BP_SHOULD_BYTESWAP(bp)) {
		bcopy(&bp->blk_dva[2].dva_word[0], salt, sizeof (uint64_t));
		bcopy(&bp->blk_dva[2].dva_word[1], iv, sizeof (uint64_t));

		val32 = (uint32_t)BP_GET_IV2(bp);
		bcopy(&val32, iv + sizeof (uint64_t), sizeof (uint32_t));
	} else {
		val64 = BSWAP_64(bp->blk_dva[2].dva_word[0]);
		bcopy(&val64, salt, sizeof (uint64_t));

		val64 = BSWAP_64(bp->blk_dva[2].dva_word[1]);
		bcopy(&val64, iv, sizeof (uint64_t));

		val32 = BSWAP_32((uint32_t)BP_GET_IV2(bp));
		bcopy(&val32, iv + sizeof (uint64_t), sizeof (uint32_t));
	}
}

static void
zio_crypt_decode_mac_bp(const blkptr_t *bp, uint8_t *mac)
{
	uint64_t val64;

	/* for convenience, so callers don't need to check */
	if (BP_GET_TYPE(bp) == DMU_OT_OBJSET) {
		bzero(mac, ZIO_DATA_MAC_LEN);
		return;
	}

	if (!BP_SHOULD_BYTESWAP(bp)) {
		bcopy(&bp->blk_cksum.zc_word[2], mac, sizeof (uint64_t));
		bcopy(&bp->blk_cksum.zc_word[3], mac + sizeof (uint64_t),
		    sizeof (uint64_t));
	} else {
		val64 = BSWAP_64(bp->blk_cksum.zc_word[2]);
		bcopy(&val64, mac, sizeof (uint64_t));

		val64 = BSWAP_64(bp->blk_cksum.zc_word[3]);
		bcopy(&val64, mac + sizeof (uint64_t), sizeof (uint64_t));
	}
}

static void
zio_crypt_bp_zero_nonportable_blkprop(blkptr_t *bp, uint64_t version)
{
	/*
	 * Version 0 did not properly zero out all non-portable fields
	 * as it should have done. We maintain this code so that we can
	 * do read-only imports of pools on this version.
	 */
	if (version == 0) {
		BP_SET_DEDUP(bp, 0);
		BP_SET_CHECKSUM(bp, 0);
		BP_SET_PSIZE(bp, SPA_MINBLOCKSIZE);
		return;
	}

	/*
	 * The hole_birth feature might set these fields even if this bp
	 * is a hole. We zero them out here to guarantee that raw sends
	 * will function with or without the feature.
	 */
	if (BP_IS_HOLE(bp)) {
		bp->blk_prop = 0ULL;
		return;
	}

	/*
	 * At L0 we want to verify these fields to ensure that data blocks
	 * can not be reinterpretted. For instance, we do not want an attacker
	 * to trick us into returning raw lz4 compressed data to the user
	 * by modifying the compression bits. At higher levels, we cannot
	 * enforce this policy since raw sends do not convey any information
	 * about indirect blocks, so these values might be different on the
	 * receive side. Fortunately, this does not open any new attack
	 * vectors, since any alterations that can be made to a higher level
	 * bp must still verify the correct order of the layer below it.
	 */
	if (BP_GET_LEVEL(bp) != 0) {
		BP_SET_BYTEORDER(bp, 0);
		BP_SET_COMPRESS(bp, 0);

		/*
		 * psize cannot be set to zero or it will trigger
		 * asserts, but the value doesn't really matter as
		 * long as it is constant.
		 */
		BP_SET_PSIZE(bp, SPA_MINBLOCKSIZE);
	}

	BP_SET_DEDUP(bp, 0);
	BP_SET_CHECKSUM(bp, 0);
}

static void
zio_crypt_bp_auth_init(uint64_t version, boolean_t should_bswap, blkptr_t *bp,
    blkptr_auth_buf_t *bab, uint_t *bab_len)
{
	blkptr_t tmpbp = *bp;

	if (should_bswap)
		byteswap_uint64_array(&tmpbp, sizeof (blkptr_t));

	zio_crypt_decode_mac_bp(&tmpbp, bab->bab_mac);

	/*
	 * We always MAC blk_prop in LE to ensure portability. This
	 * must be done after decoding the mac, since the endianness
	 * will get zero'd out here.
	 */
	zio_crypt_bp_zero_nonportable_blkprop(&tmpbp, version);
	bab->bab_prop = LE_64(tmpbp.blk_prop);
	bab->bab_pad = 0ULL;

	/* version 0 did not include the padding */
	*bab_len = sizeof (blkptr_auth_buf_t);
	if (version == 0)
		*bab_len -= sizeof (uint64_t);
}

static void
zio_crypt_bp_do_aad_updates(uint8_t **aadp, uint_t *aad_len, uint64_t version,
    boolean_t should_bswap, blkptr_t *bp)
{
	uint_t bab_len;
	blkptr_auth_buf_t bab;

	zio_crypt_bp_auth_init(version, should_bswap, bp, &bab, &bab_len);
	bcopy(&bab, *aadp, bab_len);
	*aadp += bab_len;
	*aad_len += bab_len;
}

static int
zio_crypt_init_uios_dnode(uint64_t version,
    uint8_t *plainbuf, uint8_t *cipherbuf, uint_t datalen, boolean_t byteswap,
    uio_t *puio, uio_t *cuio, uint_t *enc_len, uint8_t **authbuf,
    uint_t *auth_len, boolean_t *no_crypt)
{
	int ret;
	uint_t nr_src, nr_dst, crypt_len;
	uint_t aad_len = 0, nr_iovecs = 0, total_len = 0;
	uint_t i, j, max_dnp = datalen >> DNODE_SHIFT;
	iovec_t *src_iovecs = NULL, *dst_iovecs = NULL;
	uint8_t *src, *dst, *aadp;
	dnode_phys_t *dnp, *adnp, *sdnp, *ddnp;
	uint8_t *aadbuf = malloc(datalen);

	if (aadbuf == NULL)
		return (ENOMEM);

	src = cipherbuf;
	dst = plainbuf;
	nr_src = 1;
	nr_dst = 0;

	sdnp = (dnode_phys_t *)src;
	ddnp = (dnode_phys_t *)dst;
	aadp = aadbuf;

	/*
	 * Count the number of iovecs we will need to do the encryption by
	 * counting the number of bonus buffers that need to be encrypted.
	 */
	for (i = 0; i < max_dnp; i += sdnp[i].dn_extra_slots + 1) {
		/*
		 * This block may still be byteswapped. However, all of the
		 * values we use are either uint8_t's (for which byteswapping
		 * is a noop) or a * != 0 check, which will work regardless
		 * of whether or not we byteswap.
		 */
		if (sdnp[i].dn_type != DMU_OT_NONE &&
		    DMU_OT_IS_ENCRYPTED(sdnp[i].dn_bonustype) &&
		    sdnp[i].dn_bonuslen != 0) {
			nr_iovecs++;
		}
	}

	nr_src += nr_iovecs;
	nr_dst += nr_iovecs;

	if (nr_src != 0) {
		src_iovecs = malloc(nr_src * sizeof (iovec_t));
		if (src_iovecs == NULL) {
			ret = ENOMEM;
			goto error;
		}
	}

	if (nr_dst != 0) {
		dst_iovecs = malloc(nr_dst * sizeof (iovec_t));
		if (dst_iovecs == NULL) {
			ret = ENOMEM;
			goto error;
		}
	}

	nr_iovecs = 0;

	/*
	 * Iterate through the dnodes again, this time filling in the uios
	 * we allocated earlier. We also concatenate any data we want to
	 * authenticate onto aadbuf.
	 */
	for (i = 0; i < max_dnp; i += sdnp[i].dn_extra_slots + 1) {
		dnp = &sdnp[i];
		/* copy over the core fields and blkptrs (kept as plaintext) */
		bcopy(dnp, &ddnp[i], (uint8_t *)DN_BONUS(dnp) - (uint8_t *)dnp);
		if (dnp->dn_flags & DNODE_FLAG_SPILL_BLKPTR) {
			bcopy(DN_SPILL_BLKPTR(dnp), DN_SPILL_BLKPTR(&ddnp[i]),
			    sizeof (blkptr_t));
		}

		/*
		 * Handle authenticated data. We authenticate everything in
		 * the dnode that can be brought over when we do a raw send.
		 * This includes all of the core fields as well as the MACs
		 * stored in the bp checksums and all of the portable bits
		 * from blk_prop. We include the dnode padding here in case it
		 * ever gets used in the future. Some dn_flags and dn_used are
		 * not portable so we mask those out values out of the
		 * authenticated data.
		 */
		crypt_len = offsetof(dnode_phys_t, dn_blkptr);
		bcopy(dnp, aadp, crypt_len);
		adnp = (dnode_phys_t *)aadp;
		adnp->dn_flags &= DNODE_CRYPT_PORTABLE_FLAGS_MASK;
		adnp->dn_used = 0;
		aadp += crypt_len;
		aad_len += crypt_len;

		for (j = 0; j < dnp->dn_nblkptr; j++) {
			zio_crypt_bp_do_aad_updates(&aadp, &aad_len,
			    version, byteswap, &dnp->dn_blkptr[j]);
		}

		if (dnp->dn_flags & DNODE_FLAG_SPILL_BLKPTR) {
			zio_crypt_bp_do_aad_updates(&aadp, &aad_len,
			    version, byteswap, DN_SPILL_BLKPTR(dnp));
		}

		/*
		 * If this bonus buffer needs to be encrypted, we prepare an
		 * iovec_t. The encryption / decryption functions will fill
		 * this in for us with the encrypted or decrypted data.
		 * Otherwise we add the bonus buffer to the authenticated
		 * data buffer and copy it over to the destination. The
		 * encrypted iovec extends to DN_MAX_BONUS_LEN(dnp) so that
		 * we can guarantee alignment with the AES block size
		 * (128 bits).
		 */
		crypt_len = DN_MAX_BONUS_LEN(dnp);
		if (dnp->dn_type != DMU_OT_NONE &&
		    DMU_OT_IS_ENCRYPTED(dnp->dn_bonustype) &&
		    dnp->dn_bonuslen != 0) {
			src_iovecs[nr_iovecs].iov_base = DN_BONUS(dnp);
			src_iovecs[nr_iovecs].iov_len = crypt_len;
			dst_iovecs[nr_iovecs].iov_base = DN_BONUS(&ddnp[i]);
			dst_iovecs[nr_iovecs].iov_len = crypt_len;

			nr_iovecs++;
			total_len += crypt_len;
		} else {
			bcopy(DN_BONUS(dnp), DN_BONUS(&ddnp[i]), crypt_len);
			bcopy(DN_BONUS(dnp), aadp, crypt_len);
			aadp += crypt_len;
			aad_len += crypt_len;
		}
	}

	*no_crypt = (nr_iovecs == 0);
	*enc_len = total_len;
	*authbuf = aadbuf;
	*auth_len = aad_len;

	puio->uio_iov = dst_iovecs;
	puio->uio_iovcnt = nr_dst;
	cuio->uio_iov = src_iovecs;
	cuio->uio_iovcnt = nr_src;

	return (0);

error:
	free(aadbuf);
	free(src_iovecs);
	free(dst_iovecs);

	*enc_len = 0;
	*authbuf = NULL;
	*auth_len = 0;
	*no_crypt = B_FALSE;
	puio->uio_iov = NULL;
	puio->uio_iovcnt = 0;
	cuio->uio_iov = NULL;
	cuio->uio_iovcnt = 0;
	return (ret);
}

static int
zio_crypt_init_uios_normal(uint8_t *plainbuf,
    uint8_t *cipherbuf, uint_t datalen, uio_t *puio, uio_t *cuio,
    uint_t *enc_len)
{
	int ret;
	uint_t nr_plain = 1, nr_cipher = 2;
	iovec_t *plain_iovecs = NULL, *cipher_iovecs = NULL;

	/* allocate the iovecs for the plain and cipher data */
	plain_iovecs = malloc(nr_plain * sizeof (iovec_t));
	if (plain_iovecs == NULL) {
		ret = ENOMEM;
		goto error;
	}

	cipher_iovecs = malloc(nr_cipher * sizeof (iovec_t));
	if (cipher_iovecs == NULL) {
		ret = ENOMEM;
		goto error;
	}

	plain_iovecs[0].iov_base = (void *)plainbuf;
	plain_iovecs[0].iov_len = datalen;
	cipher_iovecs[0].iov_base = (void *)cipherbuf;
	cipher_iovecs[0].iov_len = datalen;

	*enc_len = datalen;
	puio->uio_iov = plain_iovecs;
	puio->uio_iovcnt = nr_plain;
	cuio->uio_iov = cipher_iovecs;
	cuio->uio_iovcnt = nr_cipher;

	return (0);

error:
	free(plain_iovecs);
	free(cipher_iovecs);

	*enc_len = 0;
	puio->uio_iov = NULL;
	puio->uio_iovcnt = 0;
	cuio->uio_iov = NULL;
	cuio->uio_iovcnt = 0;
	return (ret);
}

static int
zio_crypt_init_uios(uint64_t version, dmu_object_type_t ot,
    uint8_t *plainbuf, uint8_t *cipherbuf, uint_t datalen, boolean_t byteswap,
    uint8_t *mac, uio_t *puio, uio_t *cuio, uint_t *enc_len, uint8_t **authbuf,
    uint_t *auth_len, boolean_t *no_crypt)
{
	int ret;
	iovec_t *mac_iov;

	/* route to handler */
	switch (ot) {
	case DMU_OT_INTENT_LOG:
		/* We do not expect to read ZIL */
		ret = EIO;
		break;
	case DMU_OT_DNODE:
		ret = zio_crypt_init_uios_dnode(version, plainbuf,
		    cipherbuf, datalen, byteswap, puio, cuio, enc_len, authbuf,
		    auth_len, no_crypt);

		break;
	default:
		ret = zio_crypt_init_uios_normal(plainbuf, cipherbuf,
		    datalen, puio, cuio, enc_len);
		*authbuf = NULL;
		*auth_len = 0;
		*no_crypt = B_FALSE;
		break;
	}

	if (ret != 0)
		goto error;

	/* populate the uios */
	puio->uio_segflg = UIO_SYSSPACE;
	cuio->uio_segflg = UIO_SYSSPACE;

	mac_iov = ((iovec_t *)&cuio->uio_iov[cuio->uio_iovcnt - 1]);
	mac_iov->iov_base = mac;
	mac_iov->iov_len = ZIO_DATA_MAC_LEN;

	return (0);

error:
	return (ret);
}

static void
zio_crypt_destroy_uio(uio_t *uio)
{
	free(uio->uio_iov);
}

static int
zio_do_crypt_data(zio_crypt_key_t *key,
    dmu_object_type_t ot, boolean_t byteswap, uint8_t *salt, uint8_t *iv,
    uint8_t *mac, uint_t datalen, uint8_t *plainbuf, uint8_t *cipherbuf,
    boolean_t *no_crypt)
{
	int ret;
	uint64_t crypt = key->zk_crypt;
	uint_t keydata_len = zio_crypt_table[crypt].ci_keylen;
	uint_t enc_len, auth_len;
	uio_t puio, cuio;
	uint8_t enc_keydata[MASTER_KEY_MAX_LEN];
	crypto_key_t tmp_ckey, *ckey = NULL;
	uint8_t *authbuf = NULL;

	bzero(&puio, sizeof (uio_t));
	bzero(&cuio, sizeof (uio_t));

	/* create uios for encryption */
	ret = zio_crypt_init_uios(key->zk_version, ot, plainbuf,
	    cipherbuf, datalen, byteswap, mac, &puio, &cuio, &enc_len,
	    &authbuf, &auth_len, no_crypt);
	if (ret != 0)
		return (ret);

	/*
	 * If the needed key is the current one, just use it. Otherwise we
	 * need to generate a temporary one from the given salt + master key.
	 */

	if (bcmp(salt, key->zk_salt, ZIO_DATA_SALT_LEN) == 0) {
		ckey = &key->zk_current_key;
	} else {
		ret = hkdf_sha512(key->zk_master_keydata, keydata_len, NULL, 0,
		    salt, ZIO_DATA_SALT_LEN, enc_keydata, keydata_len);
		if (ret != 0)
			goto error;

		tmp_ckey.ck_format = CRYPTO_KEY_RAW;
		tmp_ckey.ck_data = enc_keydata;
		tmp_ckey.ck_length = CRYPTO_BYTES2BITS(keydata_len);

		ckey = &tmp_ckey;
	}

	/* perform the encryption / decryption */
	ret = zio_do_crypt_uio(key->zk_crypt, ckey, iv, enc_len,
	    &puio, &cuio, authbuf, auth_len);
	if (ret != 0)
		goto error;

	free(authbuf);
	if (ckey == &tmp_ckey)
		bzero(enc_keydata, keydata_len);
	zio_crypt_destroy_uio(&puio);
	zio_crypt_destroy_uio(&cuio);

	return (0);

error:
	free(authbuf);
	if (ckey == &tmp_ckey)
		bzero(enc_keydata, keydata_len);
	zio_crypt_destroy_uio(&puio);
	zio_crypt_destroy_uio(&cuio);

	return (ret);
}

static int
spa_do_crypt(spa_t *spa, // const zbookmark_phys_t *zb,
    dmu_object_type_t ot, boolean_t bswap, uint8_t *salt,
    uint8_t *iv, uint8_t *mac, uint_t datalen, void *data,
    boolean_t *no_crypt)
{
	int ret;
	dsl_crypto_key_t *dck = NULL;
	uint8_t *plainbuf = NULL, *cipherbuf = NULL;

/*
	ret = spa_keystore_lookup_key(spa, objset, &dck);
	if (ret != 0) {
		ret = EACCES;
		return (ret);
	}
*/
	plainbuf = malloc(datalen);
	cipherbuf = malloc(datalen);

	if (plainbuf == NULL || cipherbuf == NULL) {
		free(plainbuf);
		free(cipherbuf);
		return (ENOMEM);
	}
	bcopy(data, cipherbuf, datalen);
	dck = avl_first(&spa->spa_keystore.sk_dsl_keys);
	ret = EIO;
	while (dck != NULL) {
		ret = zio_do_crypt_data(&dck->dck_key, ot, bswap, salt, iv,
		    mac, datalen, plainbuf, cipherbuf, no_crypt);
		if (ret == 0)
			break;
		dck = AVL_NEXT(&spa->spa_keystore.sk_dsl_keys, dck);
	}

	if (ret == 0) {
		bcopy(plainbuf, data, datalen);
	}
	bzero(plainbuf, datalen);
	bzero(cipherbuf, datalen);
	free(plainbuf);
	free(cipherbuf);
	return (ret);
}

static int
zio_decrypt(const spa_t *spa, const blkptr_t *bp, void *data, uint64_t size)
{
	int ret;
//	uint64_t lsize = BP_GET_LSIZE(bp);
	dmu_object_type_t ot = BP_GET_TYPE(bp);
	uint8_t salt[ZIO_DATA_SALT_LEN];
	uint8_t iv[ZIO_DATA_IV_LEN];
	uint8_t mac[ZIO_DATA_MAC_LEN];
	boolean_t no_crypt = B_FALSE;

	if (BP_HAS_INDIRECT_MAC_CKSUM(bp)) {
		printf("%s: BP_HAS_INDIRECT_MAC_CKSUM\n", __func__);
		return (EIO);
	}

	if (BP_IS_AUTHENTICATED(bp)) {
		printf("%s: BP_IS_AUTHENTICATED\n", __func__);
		return (EIO);
	}

	zio_crypt_decode_params_bp(bp, salt, iv);
	if (ot == DMU_OT_INTENT_LOG) {
		printf("%s: DMU_OT_INTENT_LOG\n", __func__);
	} else {
		zio_crypt_decode_mac_bp(bp, mac);
	}

	ret = spa_do_crypt((spa_t *)spa, BP_GET_TYPE(bp),
	    BP_SHOULD_BYTESWAP(bp), salt, iv, mac, size, data,
	    &no_crypt);
//	if (no_crypt)
//		abd_copy(data, zio->io_abd, size);

	if (ret == ECKSUM)
		ret = EIO;

	return (ret);
}

static int
zio_read(const spa_t *spa, const blkptr_t *bp, void *buf)
{
	int cpfunc = BP_GET_COMPRESS(bp);
	uint64_t align, size;
	void *pbuf;
	int i, ndva, error;

	/*
	 * Process data embedded in block pointer
	 */
	if (BP_IS_EMBEDDED(bp)) {
		ASSERT(BPE_GET_ETYPE(bp) == BP_EMBEDDED_TYPE_DATA);

		size = BPE_GET_PSIZE(bp);
		ASSERT(size <= BPE_PAYLOAD_SIZE);

		if (cpfunc != ZIO_COMPRESS_OFF)
			pbuf = malloc(size);
		else
			pbuf = buf;

		if (pbuf == NULL)
			return (ENOMEM);

		decode_embedded_bp_compressed(bp, pbuf);
		error = 0;

		if (cpfunc != ZIO_COMPRESS_OFF) {
			error = zio_decompress_data(cpfunc, pbuf,
			    size, buf, BP_GET_LSIZE(bp));
			free(pbuf);
		}
		if (error != 0)
			printf("ZFS: i/o error - unable to decompress "
			    "block pointer data, error %d\n", error);
		return (error);
	}

	error = EIO;

	/* The encrypted BP's use last DVA slot for encryption parameters. */
	ndva = SPA_DVAS_PER_BP;
	if (BP_IS_ENCRYPTED(bp))
		ndva--;

	for (i = 0; i < ndva; i++) {
		const dva_t *dva = &bp->blk_dva[i];
		vdev_t *vdev;
		vdev_list_t *vlist;
		uint64_t vdevid;
		off_t offset;

		if (!dva->dva_word[0] && !dva->dva_word[1])
			continue;

		vdevid = DVA_GET_VDEV(dva);
		offset = DVA_GET_OFFSET(dva);
		vlist = &spa->spa_root_vdev->v_children;
		STAILQ_FOREACH(vdev, vlist, v_childlink) {
			if (vdev->v_id == vdevid)
				break;
		}
		if (!vdev || !vdev->v_read)
			continue;

		size = BP_GET_PSIZE(bp);
		if (vdev->v_read == vdev_raidz_read) {
			align = 1ULL << vdev->v_ashift;
			if (P2PHASE(size, align) != 0)
				size = P2ROUNDUP(size, align);
		}
		if (size != BP_GET_PSIZE(bp) || cpfunc != ZIO_COMPRESS_OFF)
			pbuf = malloc(size);
		else
			pbuf = buf;

		if (pbuf == NULL) {
			error = ENOMEM;
			break;
		}

		if (DVA_GET_GANG(dva))
			error = zio_read_gang(spa, bp, pbuf);
		else
			error = vdev->v_read(vdev, bp, pbuf, offset, size);

		if (error == 0) {
			if (BP_IS_ENCRYPTED(bp)) {
				error = zio_decrypt(spa, bp, pbuf, size);
				if (error != 0)
					break;
			}

			if (cpfunc != ZIO_COMPRESS_OFF)
				error = zio_decompress_data(cpfunc, pbuf,
				    BP_GET_PSIZE(bp), buf, BP_GET_LSIZE(bp));
			else if (size != BP_GET_PSIZE(bp))
				bcopy(pbuf, buf, BP_GET_PSIZE(bp));
		}
		if (buf != pbuf)
			free(pbuf);
		if (error == 0)
			break;
	}
	if (error != 0)
		printf("ZFS: i/o error - all block copies unavailable\n");

	return (error);
}

static int
dnode_read(const spa_t *spa, const dnode_phys_t *dnode, off_t offset,
    void *buf, size_t buflen)
{
	int ibshift = dnode->dn_indblkshift - SPA_BLKPTRSHIFT;
	int bsize = dnode->dn_datablkszsec << SPA_MINBLOCKSHIFT;
	int nlevels = dnode->dn_nlevels;
	int i, rc;

	if (bsize > SPA_MAXBLOCKSIZE) {
		printf("ZFS: I/O error - blocks larger than %llu are not "
		    "supported\n", SPA_MAXBLOCKSIZE);
		return (EIO);
	}

	/*
	 * Handle odd block sizes, mirrors dmu_read_impl().  Data can't exist
	 * past the first block, so we'll clip the read to the portion of the
	 * buffer within bsize and zero out the remainder.
	 */
	if (dnode->dn_maxblkid == 0) {
		size_t newbuflen;

		newbuflen = offset > bsize ? 0 : MIN(buflen, bsize - offset);
		bzero((char *)buf + newbuflen, buflen - newbuflen);
		buflen = newbuflen;
	}

	/*
	 * Note: bsize may not be a power of two here so we need to do an
	 * actual divide rather than a bitshift.
	 */
	while (buflen > 0) {
		uint64_t bn = offset / bsize;
		int boff = offset % bsize;
		int ibn;
		const blkptr_t *indbp;
		blkptr_t bp;

		if (bn > dnode->dn_maxblkid) {
			printf("warning: zfs bug: bn %llx > dn_maxblkid %llx\n",
			    (unsigned long long)bn,
			    (unsigned long long)dnode->dn_maxblkid);
			/*
			 * zfs bug, will not return error
			 * return (EIO);
			 */
		}

		if (dnode == dnode_cache_obj && bn == dnode_cache_bn)
			goto cached;

		indbp = dnode->dn_blkptr;
		for (i = 0; i < nlevels; i++) {
			/*
			 * Copy the bp from the indirect array so that
			 * we can re-use the scratch buffer for multi-level
			 * objects.
			 */
			ibn = bn >> ((nlevels - i - 1) * ibshift);
			ibn &= ((1 << ibshift) - 1);
			bp = indbp[ibn];
			if (BP_IS_HOLE(&bp)) {
				memset(dnode_cache_buf, 0, bsize);
				break;
			}
			rc = zio_read(spa, &bp, dnode_cache_buf);
			if (rc)
				return (rc);
			indbp = (const blkptr_t *) dnode_cache_buf;
		}
		dnode_cache_obj = dnode;
		dnode_cache_bn = bn;
	cached:

		/*
		 * The buffer contains our data block. Copy what we
		 * need from it and loop.
		 */
		i = bsize - boff;
		if (i > buflen) i = buflen;
		memcpy(buf, &dnode_cache_buf[boff], i);
		buf = ((char *)buf) + i;
		offset += i;
		buflen -= i;
	}

	return (0);
}

/*
 * Lookup a value in a microzap directory.
 */
static int
mzap_lookup(const mzap_phys_t *mz, size_t size, const char *name,
    uint64_t *value)
{
	const mzap_ent_phys_t *mze;
	int chunks, i;

	/*
	 * Microzap objects use exactly one block. Read the whole
	 * thing.
	 */
	chunks = size / MZAP_ENT_LEN - 1;
	for (i = 0; i < chunks; i++) {
		mze = &mz->mz_chunk[i];
		if (strcmp(mze->mze_name, name) == 0) {
			*value = mze->mze_value;
			return (0);
		}
	}

	return (ENOENT);
}

/*
 * Compare a name with a zap leaf entry. Return non-zero if the name
 * matches.
 */
static int
fzap_name_equal(const zap_leaf_t *zl, const zap_leaf_chunk_t *zc,
    const char *name)
{
	size_t namelen;
	const zap_leaf_chunk_t *nc;
	const char *p;

	namelen = zc->l_entry.le_name_numints;

	nc = &ZAP_LEAF_CHUNK(zl, zc->l_entry.le_name_chunk);
	p = name;
	while (namelen > 0) {
		size_t len;

		len = namelen;
		if (len > ZAP_LEAF_ARRAY_BYTES)
			len = ZAP_LEAF_ARRAY_BYTES;
		if (memcmp(p, nc->l_array.la_array, len))
			return (0);
		p += len;
		namelen -= len;
		nc = &ZAP_LEAF_CHUNK(zl, nc->l_array.la_next);
	}

	return (1);
}

/*
 * Extract a uint64_t value from a zap leaf entry.
 */
static uint64_t
fzap_leaf_value(const zap_leaf_t *zl, const zap_leaf_chunk_t *zc)
{
	const zap_leaf_chunk_t *vc;
	int i;
	uint64_t value;
	const uint8_t *p;

	vc = &ZAP_LEAF_CHUNK(zl, zc->l_entry.le_value_chunk);
	for (i = 0, value = 0, p = vc->l_array.la_array; i < 8; i++) {
		value = (value << 8) | p[i];
	}

	return (value);
}

static void
stv(int len, void *addr, uint64_t value)
{
	switch (len) {
	case 1:
		*(uint8_t *)addr = value;
		return;
	case 2:
		*(uint16_t *)addr = value;
		return;
	case 4:
		*(uint32_t *)addr = value;
		return;
	case 8:
		*(uint64_t *)addr = value;
		return;
	}
}

/*
 * Extract a array from a zap leaf entry.
 */
static void
fzap_leaf_array(const zap_leaf_t *zl, const zap_leaf_chunk_t *zc,
    uint64_t integer_size, uint64_t num_integers, void *buf)
{
	uint64_t array_int_len = zc->l_entry.le_value_intlen;
	uint64_t value = 0;
	uint64_t *u64 = buf;
	char *p = buf;
	int len = MIN(zc->l_entry.le_value_numints, num_integers);
	int chunk = zc->l_entry.le_value_chunk;
	int byten = 0;

	if (integer_size == 8 && len == 1) {
		*u64 = fzap_leaf_value(zl, zc);
		return;
	}

	while (len > 0) {
		struct zap_leaf_array *la = &ZAP_LEAF_CHUNK(zl, chunk).l_array;
		int i;

		ASSERT3U(chunk, <, ZAP_LEAF_NUMCHUNKS(zl));
		for (i = 0; i < ZAP_LEAF_ARRAY_BYTES && len > 0; i++) {
			value = (value << 8) | la->la_array[i];
			byten++;
			if (byten == array_int_len) {
				stv(integer_size, p, value);
				byten = 0;
				len--;
				if (len == 0)
					return;
				p += integer_size;
			}
		}
		chunk = la->la_next;
	}
}

static int
fzap_check_size(uint64_t integer_size, uint64_t num_integers)
{

	switch (integer_size) {
	case 1:
	case 2:
	case 4:
	case 8:
		break;
	default:
		return (EINVAL);
	}

	if (integer_size * num_integers > ZAP_MAXVALUELEN)
		return (E2BIG);

	return (0);
}

static void
zap_leaf_free(zap_leaf_t *leaf)
{
	free(leaf->l_phys);
	free(leaf);
}

static int
zap_get_leaf_byblk(fat_zap_t *zap, uint64_t blk, zap_leaf_t **lp)
{
	int bs = FZAP_BLOCK_SHIFT(zap);
	int err;

	*lp = malloc(sizeof (**lp));
	if (*lp == NULL)
		return (ENOMEM);

	(*lp)->l_bs = bs;
	(*lp)->l_phys = malloc(1 << bs);

	if ((*lp)->l_phys == NULL) {
		free(*lp);
		return (ENOMEM);
	}
	err = dnode_read(zap->zap_spa, zap->zap_dnode, blk << bs, (*lp)->l_phys,
	    1 << bs);
	if (err != 0) {
		zap_leaf_free(*lp);
	}
	return (err);
}

static int
zap_table_load(fat_zap_t *zap, zap_table_phys_t *tbl, uint64_t idx,
    uint64_t *valp)
{
	int bs = FZAP_BLOCK_SHIFT(zap);
	uint64_t blk = idx >> (bs - 3);
	uint64_t off = idx & ((1 << (bs - 3)) - 1);
	uint64_t *buf;
	int rc;

	buf = malloc(1 << zap->zap_block_shift);
	if (buf == NULL)
		return (ENOMEM);
	rc = dnode_read(zap->zap_spa, zap->zap_dnode, (tbl->zt_blk + blk) << bs,
	    buf, 1 << zap->zap_block_shift);
	if (rc == 0)
		*valp = buf[off];
	free(buf);
	return (rc);
}

static int
zap_idx_to_blk(fat_zap_t *zap, uint64_t idx, uint64_t *valp)
{
	if (zap->zap_phys->zap_ptrtbl.zt_numblks == 0) {
		*valp = ZAP_EMBEDDED_PTRTBL_ENT(zap, idx);
		return (0);
	} else {
		return (zap_table_load(zap, &zap->zap_phys->zap_ptrtbl,
		    idx, valp));
	}
}

#define	ZAP_HASH_IDX(hash, n)	(((n) == 0) ? 0 : ((hash) >> (64 - (n))))
static int
zap_deref_leaf(fat_zap_t *zap, uint64_t h, zap_leaf_t **lp)
{
	uint64_t idx, blk;
	int err;

	idx = ZAP_HASH_IDX(h, zap->zap_phys->zap_ptrtbl.zt_shift);
	err = zap_idx_to_blk(zap, idx, &blk);
	if (err != 0)
		return (err);
	return (zap_get_leaf_byblk(zap, blk, lp));
}

#define	CHAIN_END	0xffff	/* end of the chunk chain */
#define	LEAF_HASH(l, h) \
	((ZAP_LEAF_HASH_NUMENTRIES(l)-1) & \
	((h) >> \
	(64 - ZAP_LEAF_HASH_SHIFT(l) - (l)->l_phys->l_hdr.lh_prefix_len)))
#define	LEAF_HASH_ENTPTR(l, h)	(&(l)->l_phys->l_hash[LEAF_HASH(l, h)])

static int
zap_leaf_lookup(zap_leaf_t *zl, uint64_t hash, const char *name,
    uint64_t integer_size, uint64_t num_integers, void *value)
{
	int rc;
	uint16_t *chunkp;
	struct zap_leaf_entry *le;

	/*
	 * Make sure this chunk matches our hash.
	 */
	if (zl->l_phys->l_hdr.lh_prefix_len > 0 &&
	    zl->l_phys->l_hdr.lh_prefix !=
	    hash >> (64 - zl->l_phys->l_hdr.lh_prefix_len))
		return (EIO);

	rc = ENOENT;
	for (chunkp = LEAF_HASH_ENTPTR(zl, hash);
	    *chunkp != CHAIN_END; chunkp = &le->le_next) {
		zap_leaf_chunk_t *zc;
		uint16_t chunk = *chunkp;

		le = ZAP_LEAF_ENTRY(zl, chunk);
		if (le->le_hash != hash)
			continue;
		zc = &ZAP_LEAF_CHUNK(zl, chunk);
		if (fzap_name_equal(zl, zc, name)) {
			if (zc->l_entry.le_value_intlen > integer_size) {
				rc = EINVAL;
			} else {
				fzap_leaf_array(zl, zc, integer_size,
				    num_integers, value);
				rc = 0;
			}
			break;
		}
	}
	return (rc);
}

/*
 * Lookup a value in a fatzap directory.
 */
static int
fzap_lookup(const spa_t *spa, const dnode_phys_t *dnode, zap_phys_t *zh,
    const char *name, uint64_t integer_size, uint64_t num_integers,
    void *value)
{
	int bsize = dnode->dn_datablkszsec << SPA_MINBLOCKSHIFT;
	fat_zap_t z;
	zap_leaf_t *zl;
	uint64_t hash;
	int rc;

	if (zh->zap_magic != ZAP_MAGIC)
		return (EIO);

	if ((rc = fzap_check_size(integer_size, num_integers)) != 0)
		return (rc);

	z.zap_block_shift = ilog2(bsize);
	z.zap_phys = zh;
	z.zap_spa = spa;
	z.zap_dnode = dnode;

	hash = zap_hash(zh->zap_salt, name);
	rc = zap_deref_leaf(&z, hash, &zl);
	if (rc != 0)
		return (rc);

	rc = zap_leaf_lookup(zl, hash, name, integer_size, num_integers, value);

	zap_leaf_free(zl);
	return (rc);
}

/*
 * Lookup a name in a zap object and return its value as a uint64_t.
 */
static int
zap_lookup(const spa_t *spa, const dnode_phys_t *dnode, const char *name,
    uint64_t integer_size, uint64_t num_integers, void *value)
{
	int rc;
	zap_phys_t *zap;
	size_t size = dnode->dn_datablkszsec << SPA_MINBLOCKSHIFT;

	zap = malloc(size);
	if (zap == NULL)
		return (ENOMEM);

	rc = dnode_read(spa, dnode, 0, zap, size);
	if (rc)
		goto done;

	switch (zap->zap_block_type) {
	case ZBT_MICRO:
		rc = mzap_lookup((const mzap_phys_t *)zap, size, name, value);
		break;
	case ZBT_HEADER:
		rc = fzap_lookup(spa, dnode, zap, name, integer_size,
		    num_integers, value);
		break;
	default:
		printf("ZFS: invalid zap_type=%" PRIx64 "\n",
		    zap->zap_block_type);
		rc = EIO;
	}
done:
	free(zap);
	return (rc);
}

/*
 * List a microzap directory.
 */
static int
mzap_list(const mzap_phys_t *mz, size_t size,
    int (*callback)(const char *, uint64_t))
{
	const mzap_ent_phys_t *mze;
	int chunks, i, rc;

	/*
	 * Microzap objects use exactly one block. Read the whole
	 * thing.
	 */
	rc = 0;
	chunks = size / MZAP_ENT_LEN - 1;
	for (i = 0; i < chunks; i++) {
		mze = &mz->mz_chunk[i];
		if (mze->mze_name[0]) {
			rc = callback(mze->mze_name, mze->mze_value);
			if (rc != 0)
				break;
		}
	}

	return (rc);
}

/*
 * List a fatzap directory.
 */
static int
fzap_list(const spa_t *spa, const dnode_phys_t *dnode, zap_phys_t *zh,
    int (*callback)(const char *, uint64_t))
{
	int bsize = dnode->dn_datablkszsec << SPA_MINBLOCKSHIFT;
	fat_zap_t z;
	int i, j, rc;

	if (zh->zap_magic != ZAP_MAGIC)
		return (EIO);

	z.zap_block_shift = ilog2(bsize);
	z.zap_phys = zh;

	/*
	 * This assumes that the leaf blocks start at block 1. The
	 * documentation isn't exactly clear on this.
	 */
	zap_leaf_t zl;
	zl.l_bs = z.zap_block_shift;
	zl.l_phys = malloc(bsize);
	if (zl.l_phys == NULL)
		return (ENOMEM);

	for (i = 0; i < zh->zap_num_leafs; i++) {
		off_t off = ((off_t)(i + 1)) << zl.l_bs;
		char name[256], *p;
		uint64_t value;

		if (dnode_read(spa, dnode, off, zl.l_phys, bsize)) {
			free(zl.l_phys);
			return (EIO);
		}

		for (j = 0; j < ZAP_LEAF_NUMCHUNKS(&zl); j++) {
			zap_leaf_chunk_t *zc, *nc;
			int namelen;

			zc = &ZAP_LEAF_CHUNK(&zl, j);
			if (zc->l_entry.le_type != ZAP_CHUNK_ENTRY)
				continue;
			namelen = zc->l_entry.le_name_numints;
			if (namelen > sizeof (name))
				namelen = sizeof (name);

			/*
			 * Paste the name back together.
			 */
			nc = &ZAP_LEAF_CHUNK(&zl, zc->l_entry.le_name_chunk);
			p = name;
			while (namelen > 0) {
				int len;
				len = namelen;
				if (len > ZAP_LEAF_ARRAY_BYTES)
					len = ZAP_LEAF_ARRAY_BYTES;
				memcpy(p, nc->l_array.la_array, len);
				p += len;
				namelen -= len;
				nc = &ZAP_LEAF_CHUNK(&zl, nc->l_array.la_next);
			}

			/*
			 * Assume the first eight bytes of the value are
			 * a uint64_t.
			 */
			value = fzap_leaf_value(&zl, zc);

			/* printf("%s 0x%jx\n", name, (uintmax_t)value); */
			rc = callback((const char *)name, value);
			if (rc != 0) {
				free(zl.l_phys);
				return (rc);
			}
		}
	}

	free(zl.l_phys);
	return (0);
}

static int zfs_printf(const char *name, uint64_t value __unused)
{

	printf("%s\n", name);

	return (0);
}

/*
 * List a zap directory.
 */
static int
zap_list(const spa_t *spa, const dnode_phys_t *dnode)
{
	zap_phys_t *zap;
	size_t size = dnode->dn_datablkszsec << SPA_MINBLOCKSHIFT;
	int rc;

	zap = malloc(size);
	if (zap == NULL)
		return (ENOMEM);

	rc = dnode_read(spa, dnode, 0, zap, size);
	if (rc == 0) {
		if (zap->zap_block_type == ZBT_MICRO)
			rc = mzap_list((const mzap_phys_t *)zap, size,
			    zfs_printf);
		else
			rc = fzap_list(spa, dnode, zap, zfs_printf);
	}
	free(zap);
	return (rc);
}

static int
objset_get_dnode(const spa_t *spa, const objset_phys_t *os, uint64_t objnum,
    dnode_phys_t *dnode)
{
	off_t offset;

	offset = objnum * sizeof (dnode_phys_t);
	return (dnode_read(spa, &os->os_meta_dnode, offset,
	    dnode, sizeof (dnode_phys_t)));
}

/*
 * Lookup a name in a microzap directory.
 */
static int
mzap_rlookup(const mzap_phys_t *mz, size_t size, char *name, uint64_t value)
{
	const mzap_ent_phys_t *mze;
	int chunks, i;

	/*
	 * Microzap objects use exactly one block. Read the whole
	 * thing.
	 */
	chunks = size / MZAP_ENT_LEN - 1;
	for (i = 0; i < chunks; i++) {
		mze = &mz->mz_chunk[i];
		if (value == mze->mze_value) {
			strcpy(name, mze->mze_name);
			return (0);
		}
	}

	return (ENOENT);
}

static void
fzap_name_copy(const zap_leaf_t *zl, const zap_leaf_chunk_t *zc, char *name)
{
	size_t namelen;
	const zap_leaf_chunk_t *nc;
	char *p;

	namelen = zc->l_entry.le_name_numints;

	nc = &ZAP_LEAF_CHUNK(zl, zc->l_entry.le_name_chunk);
	p = name;
	while (namelen > 0) {
		size_t len;
		len = namelen;
		if (len > ZAP_LEAF_ARRAY_BYTES)
			len = ZAP_LEAF_ARRAY_BYTES;
		memcpy(p, nc->l_array.la_array, len);
		p += len;
		namelen -= len;
		nc = &ZAP_LEAF_CHUNK(zl, nc->l_array.la_next);
	}

	*p = '\0';
}

static int
fzap_rlookup(const spa_t *spa, const dnode_phys_t *dnode, zap_phys_t *zh,
    char *name, uint64_t value)
{
	int bsize = dnode->dn_datablkszsec << SPA_MINBLOCKSHIFT;
	fat_zap_t z;
	uint64_t i;
	int j, rc;

	if (zh->zap_magic != ZAP_MAGIC)
		return (EIO);

	z.zap_block_shift = ilog2(bsize);
	z.zap_phys = zh;

	/*
	 * This assumes that the leaf blocks start at block 1. The
	 * documentation isn't exactly clear on this.
	 */
	zap_leaf_t zl;
	zl.l_bs = z.zap_block_shift;
	zl.l_phys = malloc(bsize);
	if (zl.l_phys == NULL)
		return (ENOMEM);

	for (i = 0; i < zh->zap_num_leafs; i++) {
		off_t off = ((off_t)(i + 1)) << zl.l_bs;

		rc = dnode_read(spa, dnode, off, zl.l_phys, bsize);
		if (rc != 0)
			goto done;

		for (j = 0; j < ZAP_LEAF_NUMCHUNKS(&zl); j++) {
			zap_leaf_chunk_t *zc;

			zc = &ZAP_LEAF_CHUNK(&zl, j);
			if (zc->l_entry.le_type != ZAP_CHUNK_ENTRY)
				continue;
			if (zc->l_entry.le_value_intlen != 8 ||
			    zc->l_entry.le_value_numints != 1)
				continue;

			if (fzap_leaf_value(&zl, zc) == value) {
				fzap_name_copy(&zl, zc, name);
				goto done;
			}
		}
	}

	rc = ENOENT;
done:
	free(zl.l_phys);
	return (rc);
}

static int
zap_rlookup(const spa_t *spa, const dnode_phys_t *dnode, char *name,
    uint64_t value)
{
	zap_phys_t *zap;
	size_t size = dnode->dn_datablkszsec << SPA_MINBLOCKSHIFT;
	int rc;

	zap = malloc(size);
	if (zap == NULL)
		return (ENOMEM);

	rc = dnode_read(spa, dnode, 0, zap, size);
	if (rc == 0) {
		if (zap->zap_block_type == ZBT_MICRO)
			rc = mzap_rlookup((const mzap_phys_t *)zap, size,
			    name, value);
		else
			rc = fzap_rlookup(spa, dnode, zap, name, value);
	}
	free(zap);
	return (rc);
}

static int
zfs_rlookup(const spa_t *spa, uint64_t objnum, char *result)
{
	char name[256];
	char component[256];
	uint64_t dir_obj, parent_obj, child_dir_zapobj;
	dnode_phys_t child_dir_zap, dataset, dir, parent;
	dsl_dir_phys_t *dd;
	dsl_dataset_phys_t *ds;
	char *p;
	int len;

	p = &name[sizeof (name) - 1];
	*p = '\0';

	if (objset_get_dnode(spa, &spa->spa_mos, objnum, &dataset)) {
		printf("ZFS: can't find dataset %ju\n", (uintmax_t)objnum);
		return (EIO);
	}
	ds = (dsl_dataset_phys_t *)&dataset.dn_bonus;
	dir_obj = ds->ds_dir_obj;

	for (;;) {
		if (objset_get_dnode(spa, &spa->spa_mos, dir_obj, &dir) != 0)
			return (EIO);
		dd = (dsl_dir_phys_t *)&dir.dn_bonus;

		/* Actual loop condition. */
		parent_obj = dd->dd_parent_obj;
		if (parent_obj == 0)
			break;

		if (objset_get_dnode(spa, &spa->spa_mos, parent_obj,
		    &parent) != 0)
			return (EIO);
		dd = (dsl_dir_phys_t *)&parent.dn_bonus;
		child_dir_zapobj = dd->dd_child_dir_zapobj;
		if (objset_get_dnode(spa, &spa->spa_mos, child_dir_zapobj,
		    &child_dir_zap) != 0)
			return (EIO);
		if (zap_rlookup(spa, &child_dir_zap, component, dir_obj) != 0)
			return (EIO);

		len = strlen(component);
		p -= len;
		memcpy(p, component, len);
		--p;
		*p = '/';

		/* Actual loop iteration. */
		dir_obj = parent_obj;
	}

	if (*p != '\0')
		++p;
	strcpy(result, p);

	return (0);
}

static int
get_key_material(uint64_t keyformat, uint64_t iters, uint64_t salt,
    uint8_t **wkeyp)
{
	char buf[WRAPPING_KEY_LEN];
	uint8_t *key;
	int ret;

	if (keyformat != ZFS_KEYFORMAT_PASSPHRASE)
		return (EINVAL);

	if (readpassphrase("Enter password: ", buf, WRAPPING_KEY_LEN) == NULL)
		return (EAGAIN);

	key = malloc(WRAPPING_KEY_LEN);
	salt = htole64(salt);
	ret = pkcs5_pbkdf2((const uint8_t *)buf, strlen(buf),
	    (const uint8_t *)&salt, sizeof (salt),
	    key, WRAPPING_KEY_LEN, iters);
	*wkeyp = key;
	return (ret);
}

static void
dsl_wrapping_key_free(dsl_wrapping_key_t *wkey)
{
	if (wkey->wk_key.ck_data) {
		bzero(wkey->wk_key.ck_data,
		    CRYPTO_BITS2BYTES(wkey->wk_key.ck_length));
		free(wkey->wk_key.ck_data);
	}

	free(wkey);
}

static int
dsl_wrapping_key_create(uint8_t *wkeydata, zfs_keyformat_t keyformat,
    uint64_t salt, uint64_t iters, dsl_wrapping_key_t **wkey_out)
{
	int ret;
	dsl_wrapping_key_t *wkey;

	/* allocate the wrapping key */
	wkey = malloc(sizeof (dsl_wrapping_key_t));
	if (!wkey)
		return (ENOMEM);

	/* allocate and initialize the underlying crypto key */
	wkey->wk_key.ck_data = malloc(WRAPPING_KEY_LEN);
	if (!wkey->wk_key.ck_data) {
		ret = ENOMEM;
		goto error;
	}

	wkey->wk_key.ck_length = CRYPTO_BYTES2BITS(WRAPPING_KEY_LEN);
	bcopy(wkeydata, wkey->wk_key.ck_data, WRAPPING_KEY_LEN);

	/* initialize the rest of the struct */
	wkey->wk_keyformat = keyformat;
	wkey->wk_salt = salt;
	wkey->wk_iters = iters;

	*wkey_out = wkey;
	return (0);

error:
	dsl_wrapping_key_free(wkey);

	*wkey_out = NULL;
	return (ret);
}

static void
zio_crypt_key_destroy(zio_crypt_key_t *key)
{
	/* zero out sensitive data */
	bzero(key, sizeof (zio_crypt_key_t));
}

static int
zio_do_crypt_uio(uint64_t crypt, crypto_key_t *key, uint8_t *ivbuf,
    uint_t datalen, uio_t *puio, uio_t *cuio, uint8_t *authbuf, uint_t auth_len)
{
	crypto_data_t plaindata, cipherdata;
	crypto_mechanism_t mech;
	CK_AES_CCM_PARAMS ccmp;
	CK_AES_GCM_PARAMS gcmp;
	const zio_crypt_info_t *ci = &zio_crypt_table[crypt];
	uint_t plain_full_len, maclen;
	int err;

	maclen = cuio->uio_iov[cuio->uio_iovcnt - 1].iov_len;
	mech.cm_type = ci->ci_crypt_type;

	plain_full_len = datalen + maclen;

	switch (ci->ci_crypt_type) {
	case ZC_TYPE_CCM:
		ccmp.ulNonceSize = ZIO_DATA_IV_LEN;
		ccmp.ulAuthDataSize = auth_len;
		ccmp.authData = authbuf;
		ccmp.ulMACSize = maclen;
		ccmp.nonce = ivbuf;
		ccmp.ulDataSize = plain_full_len;

		mech.cm_param = (char *)(&ccmp);
		mech.cm_param_len = sizeof (CK_AES_CCM_PARAMS);
		break;

	case ZC_TYPE_GCM:
		gcmp.ulIvLen = ZIO_DATA_IV_LEN;
		gcmp.ulIvBits = CRYPTO_BYTES2BITS(ZIO_DATA_IV_LEN);
		gcmp.ulAADLen = auth_len;
		gcmp.pAAD = authbuf;
		gcmp.ulTagBits = CRYPTO_BYTES2BITS(maclen);
		gcmp.pIv = ivbuf;

		mech.cm_param = (char *)(&gcmp);
		mech.cm_param_len = sizeof (CK_AES_GCM_PARAMS);
		break;

	default:
		return (ENOTSUP);
	}

	plaindata.cd_offset = 0;
	plaindata.cd_uio = puio;
	plaindata.cd_miscdata = NULL;
	plaindata.cd_length = plain_full_len;

	cipherdata.cd_offset = 0;
	cipherdata.cd_uio = cuio;
	cipherdata.cd_miscdata = NULL;
	cipherdata.cd_length = datalen + maclen;

	err = crypto_decrypt(&mech, &cipherdata, key, &plaindata);
	return (err);
}

static void
random_get_bytes(uint8_t *ptr, size_t len)
{
	uint64_t buf;
	size_t bytes;

	if (len < 1)
		return;

	bytes = sizeof (uint64_t);

	while (len != 0) {
		buf = random();
		if (len < bytes)
			bytes = len;
		bcopy(&buf, ptr, bytes);
		ptr += bytes;
		len -= bytes;
	}
}

int
zio_crypt_key_unwrap(crypto_key_t *cwkey, uint64_t crypt, uint64_t version,
    uint64_t guid, uint8_t *keydata, uint8_t *hmac_keydata, uint8_t *iv,
    uint8_t *mac, zio_crypt_key_t *key)
{
	int ret;
	uio_t puio, cuio;
	uint64_t aad[3];
	struct iovec plain_iovecs[2], cipher_iovecs[3];
	uint_t enc_len, keydata_len, aad_len;

	keydata_len = zio_crypt_table[crypt].ci_keylen;

	/* initialize uio_ts */
	plain_iovecs[0].iov_base = key->zk_master_keydata;
	plain_iovecs[0].iov_len = keydata_len;
	plain_iovecs[1].iov_base = key->zk_hmac_keydata;
	plain_iovecs[1].iov_len = SHA512_HMAC_KEYLEN;

	cipher_iovecs[0].iov_base = keydata;
	cipher_iovecs[0].iov_len = keydata_len;
	cipher_iovecs[1].iov_base = hmac_keydata;
	cipher_iovecs[1].iov_len = SHA512_HMAC_KEYLEN;
	cipher_iovecs[2].iov_base = mac;
	cipher_iovecs[2].iov_len = WRAPPING_MAC_LEN;

	switch (version) {
	case 0:
		aad_len = sizeof (uint64_t);
		aad[0] = LE_64(guid);
		break;
	case ZIO_CRYPT_KEY_CURRENT_VERSION:
		aad_len = sizeof (uint64_t) * 3;
		aad[0] = LE_64(guid);
		aad[1] = LE_64(crypt);
		aad[2] = LE_64(version);
		break;
	default:
		return (ENOTSUP);
	}

	enc_len = keydata_len + SHA512_HMAC_KEYLEN;
	puio.uio_iov = plain_iovecs;
	puio.uio_segflg = UIO_SYSSPACE;
	puio.uio_iovcnt = 2;
	cuio.uio_iov = cipher_iovecs;
	cuio.uio_iovcnt = 3;
	cuio.uio_segflg = UIO_SYSSPACE;

	/* decrypt the keys and store the result in the output buffers */
	ret = zio_do_crypt_uio(crypt, cwkey, iv, enc_len,
	    &puio, &cuio, (uint8_t *)aad, aad_len);
	if (ret != 0)
		goto error;

	random_get_bytes(key->zk_salt, ZIO_DATA_SALT_LEN);

	/* derive the current key from the master key */
	ret = hkdf_sha512(key->zk_master_keydata, keydata_len, NULL, 0,
	    key->zk_salt, ZIO_DATA_SALT_LEN, key->zk_current_keydata,
	    keydata_len);
	if (ret != 0)
		goto error;

	/* initialize keys for ICP */
	key->zk_current_key.ck_format = CRYPTO_KEY_RAW;
	key->zk_current_key.ck_data = key->zk_current_keydata;
	key->zk_current_key.ck_length = CRYPTO_BYTES2BITS(keydata_len);

	key->zk_hmac_key.ck_format = CRYPTO_KEY_RAW;
	key->zk_hmac_key.ck_data = key->zk_hmac_keydata;
	key->zk_hmac_key.ck_length = CRYPTO_BYTES2BITS(SHA512_HMAC_KEYLEN);

	key->zk_crypt = crypt;
	key->zk_version = version;
	key->zk_guid = guid;
	key->zk_salt_count = 0;

	return (0);
error:
	zio_crypt_key_destroy(key);
	return (ret);
}

static int
dsl_crypto_key_open(spa_t *spa, dsl_wrapping_key_t *wkey,
    uint64_t dckobj, dsl_crypto_key_t **dck_out)
{
	int ret;
	uint64_t crypt = 0, guid = 0, version = 0;
	uint8_t raw_keydata[MASTER_KEY_MAX_LEN];
	uint8_t raw_hmac_keydata[SHA512_HMAC_KEYLEN];
	uint8_t iv[WRAPPING_IV_LEN];
	uint8_t mac[WRAPPING_MAC_LEN];
	dnode_phys_t *keyobj;
	dsl_crypto_key_t *dck;

	keyobj = malloc(sizeof (*keyobj));
	if (keyobj == NULL)
		return (ENOMEM);

	dck = malloc(sizeof (*dck));
	if (dck == NULL) {
		ret = ENOMEM;
		goto error;
	}

	ret = objset_get_dnode(spa, &spa->spa_mos, dckobj, keyobj);
	if (ret != 0)
		goto error;

	/* fetch all of the values we need from the ZAP */
	/* we need to check for encryption root */
	ret = zap_lookup(spa, keyobj, DSL_CRYPTO_KEY_CRYPTO_SUITE, 8, 1,
	    &crypt);
	if (ret != 0)
		goto error;

	ret = zap_lookup(spa, keyobj, DSL_CRYPTO_KEY_GUID, 8, 1, &guid);
	if (ret != 0)
		goto error;

	ret = zap_lookup(spa, keyobj, DSL_CRYPTO_KEY_MASTER_KEY, 1,
	    MASTER_KEY_MAX_LEN, raw_keydata);
	if (ret != 0)
		goto error;

	ret = zap_lookup(spa, keyobj, DSL_CRYPTO_KEY_HMAC_KEY, 1,
	    SHA512_HMAC_KEYLEN, raw_hmac_keydata);
	if (ret != 0)
		goto error;

	ret = zap_lookup(spa, keyobj, DSL_CRYPTO_KEY_IV, 1,
	    WRAPPING_IV_LEN, iv);
	if (ret != 0)
		goto error;

	ret = zap_lookup(spa, keyobj, DSL_CRYPTO_KEY_MAC, 1,
	    WRAPPING_MAC_LEN, mac);
	if (ret != 0)
		goto error;

	/* the initial on-disk format for encryption did not have a version */
	(void) zap_lookup(spa, keyobj, DSL_CRYPTO_KEY_VERSION, 8, 1, &version);

	/*
	 * Unwrap the keys. If there is an error return EACCES to indicate
	 * an authentication failure.
	 */
	ret = zio_crypt_key_unwrap(&wkey->wk_key, crypt, version, guid,
            raw_keydata, raw_hmac_keydata, iv, mac, &dck->dck_key);
	if (ret != 0) {
		ret = EACCES;
		goto error;
	}

	dck->dck_wkey = wkey;
	dck->dck_obj = dckobj;
	*dck_out = dck;
error:
	if (ret != 0) {
		bzero(dck, sizeof (*dck));
		free(dck);
	}
	free(keyobj);
	return (ret);
}

static dsl_wrapping_key_t *
spa_keystore_load_wkey(spa_t *spa, uint64_t crypto_obj)
{
	int ret;
	uint64_t dd, keyformat, salt, iters;
	dnode_phys_t *keyobj;
	dsl_wrapping_key_t search_wkey;
	dsl_wrapping_key_t *wkey = NULL;
	avl_index_t where;
	uint8_t *wkeydata = NULL;

	keyobj = malloc(sizeof (*keyobj));
	if (keyobj == NULL)
		goto done;

	ret = objset_get_dnode(spa, &spa->spa_mos, crypto_obj, keyobj);
	if (ret != 0)
		goto done;

	ret = zap_lookup(spa, keyobj, DSL_CRYPTO_KEY_ROOT_DDOBJ, 8, 1, &dd);
	if (ret != 0)
		goto done;

	search_wkey.wk_ddobj = dd;
	wkey = avl_find(&spa->spa_keystore.sk_wkeys, &search_wkey, &where);
	if (wkey != NULL) {
		goto done;
	}

	ret = zap_lookup(spa, keyobj, ZFS_PROP_KEYFORMAT, 8, 1, &keyformat);
	if (ret != 0)
		goto done;

	ret = zap_lookup(spa, keyobj, ZFS_PROP_PBKDF2_SALT, 8, 1, &salt);
	if (ret != 0)
		goto done;

	ret = zap_lookup(spa, keyobj, ZFS_PROP_PBKDF2_ITERS, 8, 1, &iters);
	if (ret != 0)
		goto done;

	ret = get_key_material(keyformat, iters, salt, &wkeydata);
	if (ret != 0)
		goto done;

	ret = dsl_wrapping_key_create(wkeydata, keyformat, salt, iters, &wkey);
	if (ret != 0)
		goto done;

	wkey->wk_ddobj = dd;
	avl_insert(&spa->spa_keystore.sk_wkeys, wkey, where);

done:
	free(wkeydata);
	free(keyobj);
	return (wkey);
}

static int
zfs_lookup_dataset(spa_t *spa, const char *name, uint64_t *objnum)
{
	char element[256];
	uint64_t dir_obj, child_dir_zapobj;
	dnode_phys_t child_dir_zap, dir;
	dsl_dir_phys_t *dd;
	const char *p, *q;
	uint64_t crypto_obj;

	if (objset_get_dnode(spa, &spa->spa_mos,
	    DMU_POOL_DIRECTORY_OBJECT, &dir))
		return (EIO);
	if (zap_lookup(spa, &dir, DMU_POOL_ROOT_DATASET, sizeof (dir_obj),
	    1, &dir_obj))
		return (EIO);

	p = name;
	for (;;) {
		if (objset_get_dnode(spa, &spa->spa_mos, dir_obj, &dir))
			return (EIO);

		if (dir.dn_type == DMU_OTN_ZAP_METADATA) {
			if (zap_lookup(spa, &dir, DD_FIELD_CRYPTO_KEY_OBJ,
			    sizeof (crypto_obj), 1, &crypto_obj) == 0) {
				dsl_wrapping_key_t *wkey;
				dsl_crypto_key_t *dck;
				dsl_crypto_key_t search_dck;
				avl_index_t where;
				int rc;

				/* get wrapping key */
again:
				wkey = spa_keystore_load_wkey(spa, crypto_obj);
				if (wkey == NULL)
					return (EIO);

				search_dck.dck_obj = crypto_obj;
				if (avl_find(&spa->spa_keystore.sk_dsl_keys,
				    &search_dck, &where) == NULL) {
					rc = dsl_crypto_key_open(spa, wkey,
					    crypto_obj, &dck);
					if (rc == EACCES) {
						/* wrong wrapping key */
						avl_remove(
						    &spa->spa_keystore.sk_wkeys,
						     wkey);
						dsl_wrapping_key_free(wkey);
						goto again;
					}
					if (rc != 0)
						return (rc);
					avl_insert(
					    &spa->spa_keystore.sk_dsl_keys,
					    dck, where);
				}
			}
		}

		dd = (dsl_dir_phys_t *)&dir.dn_bonus;

		while (*p == '/')
			p++;
		/* Actual loop condition #1. */
		if (*p == '\0')
			break;

		q = strchr(p, '/');
		if (q) {
			memcpy(element, p, q - p);
			element[q - p] = '\0';
			p = q + 1;
		} else {
			strcpy(element, p);
			p += strlen(p);
		}

		child_dir_zapobj = dd->dd_child_dir_zapobj;
		if (objset_get_dnode(spa, &spa->spa_mos, child_dir_zapobj,
		    &child_dir_zap) != 0)
			return (EIO);

		/* Actual loop condition #2. */
		if (zap_lookup(spa, &child_dir_zap, element, sizeof (dir_obj),
		    1, &dir_obj) != 0)
			return (ENOENT);
	}

	*objnum = dd->dd_head_dataset_obj;
	return (0);
}

#pragma GCC diagnostic ignored "-Wstrict-aliasing"
static int
zfs_list_dataset(const spa_t *spa, uint64_t objnum)
{
	uint64_t dir_obj, child_dir_zapobj;
	dnode_phys_t child_dir_zap, dir, dataset;
	dsl_dataset_phys_t *ds;
	dsl_dir_phys_t *dd;

	if (objset_get_dnode(spa, &spa->spa_mos, objnum, &dataset)) {
		printf("ZFS: can't find dataset %ju\n", (uintmax_t)objnum);
		return (EIO);
	}
	ds = (dsl_dataset_phys_t *)&dataset.dn_bonus;
	dir_obj = ds->ds_dir_obj;

	if (objset_get_dnode(spa, &spa->spa_mos, dir_obj, &dir)) {
		printf("ZFS: can't find dirobj %ju\n", (uintmax_t)dir_obj);
		return (EIO);
	}
	dd = (dsl_dir_phys_t *)&dir.dn_bonus;

	child_dir_zapobj = dd->dd_child_dir_zapobj;
	if (objset_get_dnode(spa, &spa->spa_mos, child_dir_zapobj,
	    &child_dir_zap) != 0) {
		printf("ZFS: can't find child zap %ju\n", (uintmax_t)dir_obj);
		return (EIO);
	}

	return (zap_list(spa, &child_dir_zap) != 0);
}

int
zfs_callback_dataset(const spa_t *spa, uint64_t objnum,
    int (*callback)(const char *, uint64_t))
{
	uint64_t dir_obj, child_dir_zapobj;
	dnode_phys_t child_dir_zap, dir, dataset;
	dsl_dataset_phys_t *ds;
	dsl_dir_phys_t *dd;
	zap_phys_t *zap;
	size_t size;
	int err;

	err = objset_get_dnode(spa, &spa->spa_mos, objnum, &dataset);
	if (err != 0) {
		printf("ZFS: can't find dataset %ju\n", (uintmax_t)objnum);
		return (err);
	}
	ds = (dsl_dataset_phys_t *)&dataset.dn_bonus;
	dir_obj = ds->ds_dir_obj;

	err = objset_get_dnode(spa, &spa->spa_mos, dir_obj, &dir);
	if (err != 0) {
		printf("ZFS: can't find dirobj %ju\n", (uintmax_t)dir_obj);
		return (err);
	}
	dd = (dsl_dir_phys_t *)&dir.dn_bonus;

	child_dir_zapobj = dd->dd_child_dir_zapobj;
	err = objset_get_dnode(spa, &spa->spa_mos, child_dir_zapobj,
	    &child_dir_zap);
	if (err != 0) {
		printf("ZFS: can't find child zap %ju\n", (uintmax_t)dir_obj);
		return (err);
	}

	size = child_dir_zap.dn_datablkszsec << SPA_MINBLOCKSHIFT;
	zap = malloc(size);
	if (zap != NULL) {
		err = dnode_read(spa, &child_dir_zap, 0, zap, size);
		if (err != 0)
			goto done;

		if (zap->zap_block_type == ZBT_MICRO)
			err = mzap_list((const mzap_phys_t *)zap, size,
			    callback);
		else
			err = fzap_list(spa, &child_dir_zap, zap, callback);
	} else {
		err = ENOMEM;
	}
done:
	free(zap);
	return (err);
}

/*
 * Find the object set given the object number of its dataset object
 * and return its details in *objset
 */
static int
zfs_mount_dataset(const spa_t *spa, uint64_t objnum, objset_phys_t *objset)
{
	dnode_phys_t dataset;
	dsl_dataset_phys_t *ds;

	if (objset_get_dnode(spa, &spa->spa_mos, objnum, &dataset)) {
		printf("ZFS: can't find dataset %ju\n", (uintmax_t)objnum);
		return (EIO);
	}

	ds = (dsl_dataset_phys_t *)&dataset.dn_bonus;
	if (zio_read(spa, &ds->ds_bp, objset)) {
		printf("ZFS: can't read object set for dataset %ju\n",
		    (uintmax_t)objnum);
		return (EIO);
	}

	return (0);
}

/*
 * Find the object set pointed to by the BOOTFS property or the root
 * dataset if there is none and return its details in *objset
 */
static int
zfs_get_root(const spa_t *spa, uint64_t *objid)
{
	dnode_phys_t dir, propdir;
	uint64_t props, bootfs, root;

	*objid = 0;

	/*
	 * Start with the MOS directory object.
	 */
	if (objset_get_dnode(spa, &spa->spa_mos,
	    DMU_POOL_DIRECTORY_OBJECT, &dir)) {
		printf("ZFS: can't read MOS object directory\n");
		return (EIO);
	}

	/*
	 * Lookup the pool_props and see if we can find a bootfs.
	 */
	if (zap_lookup(spa, &dir, DMU_POOL_PROPS,
	    sizeof (props), 1, &props) == 0 &&
	    objset_get_dnode(spa, &spa->spa_mos, props, &propdir) == 0 &&
	    zap_lookup(spa, &propdir, "bootfs",
	    sizeof (bootfs), 1, &bootfs) == 0 && bootfs != 0) {
		*objid = bootfs;
		return (0);
	}
	/*
	 * Lookup the root dataset directory
	 */
	if (zap_lookup(spa, &dir, DMU_POOL_ROOT_DATASET,
	    sizeof (root), 1, &root) ||
	    objset_get_dnode(spa, &spa->spa_mos, root, &dir)) {
		printf("ZFS: can't find root dsl_dir\n");
		return (EIO);
	}

	/*
	 * Use the information from the dataset directory's bonus buffer
	 * to find the dataset object and from that the object set itself.
	 */
	dsl_dir_phys_t *dd = (dsl_dir_phys_t *)&dir.dn_bonus;
	*objid = dd->dd_head_dataset_obj;
	return (0);
}

static int
zfs_mount(const spa_t *spa, uint64_t rootobj, struct zfsmount *mnt)
{

	mnt->spa = spa;

	/*
	 * Find the root object set if not explicitly provided
	 */
	if (rootobj == 0 && zfs_get_root(spa, &rootobj)) {
		printf("ZFS: can't find root filesystem\n");
		return (EIO);
	}

	if (zfs_mount_dataset(spa, rootobj, &mnt->objset)) {
		printf("ZFS: can't open root filesystem\n");
		return (EIO);
	}

	mnt->rootobj = rootobj;

	return (0);
}

/*
 * callback function for feature name checks.
 */
static int
check_feature(const char *name, uint64_t value)
{
	int i;

	if (value == 0)
		return (0);
	if (name[0] == '\0')
		return (0);

	for (i = 0; features_for_read[i] != NULL; i++) {
		if (strcmp(name, features_for_read[i]) == 0)
			return (0);
	}
	printf("ZFS: unsupported feature: %s\n", name);
	return (EIO);
}

/*
 * Checks whether the MOS features that are active are supported.
 */
static int
check_mos_features(const spa_t *spa)
{
	dnode_phys_t dir;
	zap_phys_t *zap;
	uint64_t objnum;
	size_t size;
	int rc;

	if ((rc = objset_get_dnode(spa, &spa->spa_mos, DMU_OT_OBJECT_DIRECTORY,
	    &dir)) != 0)
		return (rc);
	if ((rc = zap_lookup(spa, &dir, DMU_POOL_FEATURES_FOR_READ,
	    sizeof (objnum), 1, &objnum)) != 0) {
		/*
		 * It is older pool without features. As we have already
		 * tested the label, just return without raising the error.
		 */
		if (rc == ENOENT)
			rc = 0;
		return (rc);
	}

	if ((rc = objset_get_dnode(spa, &spa->spa_mos, objnum, &dir)) != 0)
		return (rc);

	if (dir.dn_type != DMU_OTN_ZAP_METADATA)
		return (EIO);

	size = dir.dn_datablkszsec << SPA_MINBLOCKSHIFT;
	zap = malloc(size);
	if (zap == NULL)
		return (ENOMEM);

	if (dnode_read(spa, &dir, 0, zap, size)) {
		free(zap);
		return (EIO);
	}

	if (zap->zap_block_type == ZBT_MICRO)
		rc = mzap_list((const mzap_phys_t *)zap, size, check_feature);
	else
		rc = fzap_list(spa, &dir, zap, check_feature);

	free(zap);
	return (rc);
}

static int
load_nvlist(spa_t *spa, uint64_t obj, nvlist_t **value)
{
	dnode_phys_t dir;
	size_t size;
	int rc;
	char *nv;

	*value = NULL;
	if ((rc = objset_get_dnode(spa, &spa->spa_mos, obj, &dir)) != 0)
		return (rc);
	if (dir.dn_type != DMU_OT_PACKED_NVLIST &&
	    dir.dn_bonustype != DMU_OT_PACKED_NVLIST_SIZE) {
		return (EIO);
	}

	if (dir.dn_bonuslen != sizeof (uint64_t))
		return (EIO);

	size = *(uint64_t *)DN_BONUS(&dir);
	nv = malloc(size);
	if (nv == NULL)
		return (ENOMEM);

	rc = dnode_read(spa, &dir, 0, nv, size);
	if (rc != 0) {
		free(nv);
		nv = NULL;
		return (rc);
	}
	rc = nvlist_unpack(nv, size, value, 0);
	free(nv);
	return (rc);
}

static int
zfs_spa_init(spa_t *spa)
{
	dnode_phys_t dir;
	uint64_t config_object;
	nvlist_t *nvlist;
	int rc;

	if (zio_read(spa, &spa->spa_uberblock.ub_rootbp, &spa->spa_mos)) {
		printf("ZFS: can't read MOS of pool %s\n", spa->spa_name);
		return (EIO);
	}
	if (spa->spa_mos.os_type != DMU_OST_META) {
		printf("ZFS: corrupted MOS of pool %s\n", spa->spa_name);
		return (EIO);
	}

	if (objset_get_dnode(spa, &spa->spa_mos, DMU_POOL_DIRECTORY_OBJECT,
	    &dir)) {
		printf("ZFS: failed to read pool %s directory object\n",
		    spa->spa_name);
		return (EIO);
	}
	/* this is allowed to fail, older pools do not have salt */
	rc = zap_lookup(spa, &dir, DMU_POOL_CHECKSUM_SALT, 1,
	    sizeof (spa->spa_cksum_salt.zcs_bytes),
	    spa->spa_cksum_salt.zcs_bytes);

	rc = check_mos_features(spa);
	if (rc != 0) {
		printf("ZFS: pool %s is not supported\n", spa->spa_name);
		return (rc);
	}

	rc = zap_lookup(spa, &dir, DMU_POOL_CONFIG,
	    sizeof (config_object), 1, &config_object);
	if (rc != 0) {
		printf("ZFS: can not read MOS %s\n", DMU_POOL_CONFIG);
		return (EIO);
	}
	rc = load_nvlist(spa, config_object, &nvlist);
	if (rc != 0)
		return (rc);

	/*
	 * Update vdevs from MOS config. Note, we do skip encoding bytes
	 * here. See also vdev_label_read_config().
	 */
	rc = vdev_init_from_nvlist(spa, nvlist);
	nvlist_free(nvlist);
	return (rc);
}

static int
zfs_dnode_stat(const spa_t *spa, dnode_phys_t *dn, struct stat *sb)
{

	if (dn->dn_bonustype != DMU_OT_SA) {
		znode_phys_t *zp = (znode_phys_t *)dn->dn_bonus;

		sb->st_mode = zp->zp_mode;
		sb->st_uid = zp->zp_uid;
		sb->st_gid = zp->zp_gid;
		sb->st_size = zp->zp_size;
	} else {
		sa_hdr_phys_t *sahdrp;
		int hdrsize;
		size_t size = 0;
		void *buf = NULL;

		if (dn->dn_bonuslen != 0)
			sahdrp = (sa_hdr_phys_t *)DN_BONUS(dn);
		else {
			if ((dn->dn_flags & DNODE_FLAG_SPILL_BLKPTR) != 0) {
				blkptr_t *bp = DN_SPILL_BLKPTR(dn);
				int error;

				size = BP_GET_LSIZE(bp);
				buf = malloc(size);
				if (buf == NULL)
					error = ENOMEM;
				else
					error = zio_read(spa, bp, buf);

				if (error != 0) {
					free(buf);
					return (error);
				}
				sahdrp = buf;
			} else {
				return (EIO);
			}
		}
		hdrsize = SA_HDR_SIZE(sahdrp);
		sb->st_mode = *(uint64_t *)((char *)sahdrp + hdrsize +
		    SA_MODE_OFFSET);
		sb->st_uid = *(uint64_t *)((char *)sahdrp + hdrsize +
		    SA_UID_OFFSET);
		sb->st_gid = *(uint64_t *)((char *)sahdrp + hdrsize +
		    SA_GID_OFFSET);
		sb->st_size = *(uint64_t *)((char *)sahdrp + hdrsize +
		    SA_SIZE_OFFSET);
		free(buf);
	}

	return (0);
}

static int
zfs_dnode_readlink(const spa_t *spa, dnode_phys_t *dn, char *path, size_t psize)
{
	int rc = 0;

	if (dn->dn_bonustype == DMU_OT_SA) {
		sa_hdr_phys_t *sahdrp = NULL;
		size_t size = 0;
		void *buf = NULL;
		int hdrsize;
		char *p;

		if (dn->dn_bonuslen != 0) {
			sahdrp = (sa_hdr_phys_t *)DN_BONUS(dn);
		} else {
			blkptr_t *bp;

			if ((dn->dn_flags & DNODE_FLAG_SPILL_BLKPTR) == 0)
				return (EIO);
			bp = DN_SPILL_BLKPTR(dn);

			size = BP_GET_LSIZE(bp);
			buf = malloc(size);
			if (buf == NULL)
				rc = ENOMEM;
			else
				rc = zio_read(spa, bp, buf);
			if (rc != 0) {
				free(buf);
				return (rc);
			}
			sahdrp = buf;
		}
		hdrsize = SA_HDR_SIZE(sahdrp);
		p = (char *)((uintptr_t)sahdrp + hdrsize + SA_SYMLINK_OFFSET);
		memcpy(path, p, psize);
		free(buf);
		return (0);
	}
	/*
	 * Second test is purely to silence bogus compiler
	 * warning about accessing past the end of dn_bonus.
	 */
	if (psize + sizeof (znode_phys_t) <= dn->dn_bonuslen &&
	    sizeof (znode_phys_t) <= sizeof (dn->dn_bonus)) {
		memcpy(path, &dn->dn_bonus[sizeof (znode_phys_t)], psize);
	} else {
		rc = dnode_read(spa, dn, 0, path, psize);
	}
	return (rc);
}

struct obj_list {
	uint64_t		objnum;
	STAILQ_ENTRY(obj_list)	entry;
};

/*
 * Lookup a file and return its dnode.
 */
static int
zfs_lookup(const struct zfsmount *mnt, const char *upath, dnode_phys_t *dnode)
{
	int rc;
	uint64_t objnum;
	const spa_t *spa;
	dnode_phys_t dn;
	const char *p, *q;
	char element[256];
	char path[1024];
	int symlinks_followed = 0;
	struct stat sb;
	struct obj_list *entry, *tentry;
	STAILQ_HEAD(, obj_list) on_cache = STAILQ_HEAD_INITIALIZER(on_cache);

	spa = mnt->spa;
	if (mnt->objset.os_type != DMU_OST_ZFS) {
		printf("ZFS: unexpected object set type %ju\n",
		    (uintmax_t)mnt->objset.os_type);
		return (EIO);
	}

	if ((entry = malloc(sizeof (struct obj_list))) == NULL)
		return (ENOMEM);

	/*
	 * Get the root directory dnode.
	 */
	rc = objset_get_dnode(spa, &mnt->objset, MASTER_NODE_OBJ, &dn);
	if (rc) {
		free(entry);
		return (rc);
	}

	rc = zap_lookup(spa, &dn, ZFS_ROOT_OBJ, sizeof (objnum), 1, &objnum);
	if (rc) {
		free(entry);
		return (rc);
	}
	entry->objnum = objnum;
	STAILQ_INSERT_HEAD(&on_cache, entry, entry);

	rc = objset_get_dnode(spa, &mnt->objset, objnum, &dn);
	if (rc != 0)
		goto done;

	p = upath;
	while (p && *p) {
		rc = objset_get_dnode(spa, &mnt->objset, objnum, &dn);
		if (rc != 0)
			goto done;

		while (*p == '/')
			p++;
		if (*p == '\0')
			break;
		q = p;
		while (*q != '\0' && *q != '/')
			q++;

		/* skip dot */
		if (p + 1 == q && p[0] == '.') {
			p++;
			continue;
		}
		/* double dot */
		if (p + 2 == q && p[0] == '.' && p[1] == '.') {
			p += 2;
			if (STAILQ_FIRST(&on_cache) ==
			    STAILQ_LAST(&on_cache, obj_list, entry)) {
				rc = ENOENT;
				goto done;
			}
			entry = STAILQ_FIRST(&on_cache);
			STAILQ_REMOVE_HEAD(&on_cache, entry);
			free(entry);
			objnum = (STAILQ_FIRST(&on_cache))->objnum;
			continue;
		}
		if (q - p + 1 > sizeof (element)) {
			rc = ENAMETOOLONG;
			goto done;
		}
		memcpy(element, p, q - p);
		element[q - p] = 0;
		p = q;

		if ((rc = zfs_dnode_stat(spa, &dn, &sb)) != 0)
			goto done;
		if (!S_ISDIR(sb.st_mode)) {
			rc = ENOTDIR;
			goto done;
		}

		rc = zap_lookup(spa, &dn, element, sizeof (objnum), 1, &objnum);
		if (rc)
			goto done;
		objnum = ZFS_DIRENT_OBJ(objnum);

		if ((entry = malloc(sizeof (struct obj_list))) == NULL) {
			rc = ENOMEM;
			goto done;
		}
		entry->objnum = objnum;
		STAILQ_INSERT_HEAD(&on_cache, entry, entry);
		rc = objset_get_dnode(spa, &mnt->objset, objnum, &dn);
		if (rc)
			goto done;

		/*
		 * Check for symlink.
		 */
		rc = zfs_dnode_stat(spa, &dn, &sb);
		if (rc)
			goto done;
		if (S_ISLNK(sb.st_mode)) {
			if (symlinks_followed > 10) {
				rc = EMLINK;
				goto done;
			}
			symlinks_followed++;

			/*
			 * Read the link value and copy the tail of our
			 * current path onto the end.
			 */
			if (sb.st_size + strlen(p) + 1 > sizeof (path)) {
				rc = ENAMETOOLONG;
				goto done;
			}
			strcpy(&path[sb.st_size], p);

			rc = zfs_dnode_readlink(spa, &dn, path, sb.st_size);
			if (rc != 0)
				goto done;

			/*
			 * Restart with the new path, starting either at
			 * the root or at the parent depending whether or
			 * not the link is relative.
			 */
			p = path;
			if (*p == '/') {
				while (STAILQ_FIRST(&on_cache) !=
				    STAILQ_LAST(&on_cache, obj_list, entry)) {
					entry = STAILQ_FIRST(&on_cache);
					STAILQ_REMOVE_HEAD(&on_cache, entry);
					free(entry);
				}
			} else {
				entry = STAILQ_FIRST(&on_cache);
				STAILQ_REMOVE_HEAD(&on_cache, entry);
				free(entry);
			}
			objnum = (STAILQ_FIRST(&on_cache))->objnum;
		}
	}

	*dnode = dn;
done:
	STAILQ_FOREACH_SAFE(entry, &on_cache, entry, tentry)
		free(entry);
	return (rc);
}
