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
 * Copyright (c) 2011, 2018 by Delphix. All rights reserved.
 * Copyright 2017 Nexenta Systems, Inc.
 * Copyright (c) 2014 Integros [integros.com]
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 * Copyright 2019 Joyent, Inc.
 * Copyright (c) 2017, Intel Corporation.
 * Copyright (c) 2019, Datto Inc. All rights reserved.
 */

#include <sys/zfs_context.h>
#include <sys/nvpair.h>
#include <sys/vdev_impl.h>
#include <sys/vdev.h>
#include <sys/zfsimpl.h>

/*
 * Virtual device management.
 */

static vdev_ops_t *vdev_ops_table[] = {
	&vdev_root_ops,
	&vdev_raidz_ops,
	&vdev_mirror_ops,
	&vdev_replacing_ops,
	&vdev_spare_ops,
	&vdev_disk_ops,
	&vdev_file_ops,
	&vdev_missing_ops,
	&vdev_hole_ops,
	&vdev_indirect_ops,
	NULL
};

/*
 * Given a vdev type, return the appropriate ops vector.
 */
static vdev_ops_t *
vdev_getops(const char *type)
{
	vdev_ops_t *ops, **opspp;

	for (opspp = vdev_ops_table; (ops = *opspp) != NULL; opspp++)
		if (strcmp(ops->vdev_op_type, type) == 0)
			break;

	return (ops);
}

void
vdev_default_xlate(vdev_t *vd, const range_seg64_t *in, range_seg64_t *res)
{
	res->rs_start = in->rs_start;
	res->rs_end = in->rs_end;
}

uint64_t
vdev_default_asize(vdev_t *vd, uint64_t psize)
{
	uint64_t asize = P2ROUNDUP(psize, 1ULL << vd->vdev_top->vdev_ashift);
	uint64_t csize;

	for (int c = 0; c < vd->vdev_children; c++) {
		csize = vdev_psize_to_asize(vd->vdev_child[c], psize);
		asize = MAX(asize, csize);
	}

	return (asize);
}

vdev_t *
vdev_lookup_top(spa_t *spa, uint64_t vdev)
{
	vdev_t *rvd = spa->spa_root_vdev;

	if (vdev < rvd->vdev_children) {
		ASSERT(rvd->vdev_child[vdev] != NULL);
		return (rvd->vdev_child[vdev]);
	}

	return (NULL);
}

vdev_t *
vdev_lookup_by_guid(vdev_t *vd, uint64_t guid)
{
	vdev_t *mvd;

	if (vd->vdev_guid == guid)
		return (vd);

	for (int c = 0; c < vd->vdev_children; c++)
		if ((mvd = vdev_lookup_by_guid(vd->vdev_child[c], guid)) !=
		    NULL)
			return (mvd);

	return (NULL);
}

void
vdev_add_child(vdev_t *pvd, vdev_t *cvd)
{
	size_t oldsize, newsize;
	uint64_t id = cvd->vdev_id;
	vdev_t **newchild;

	ASSERT(cvd->vdev_parent == NULL);

	cvd->vdev_parent = pvd;

	if (pvd == NULL)
		return;

	ASSERT(id >= pvd->vdev_children || pvd->vdev_child[id] == NULL);

	oldsize = pvd->vdev_children * sizeof (vdev_t *);
	pvd->vdev_children = MAX(pvd->vdev_children, id + 1);
	newsize = pvd->vdev_children * sizeof (vdev_t *);

	newchild = malloc(newsize);
	if (pvd->vdev_child != NULL) {
		bcopy(pvd->vdev_child, newchild, oldsize);
		free(pvd->vdev_child);
	}

	pvd->vdev_child = newchild;
	pvd->vdev_child[id] = cvd;

	cvd->vdev_top = (pvd->vdev_top ? pvd->vdev_top: cvd);
	ASSERT(cvd->vdev_top->vdev_parent->vdev_parent == NULL);

	/*
	 * Walk up all ancestors to update guid sum.
	 */
	for (; pvd != NULL; pvd = pvd->vdev_parent)
		pvd->vdev_guid_sum += cvd->vdev_guid_sum;

	if (cvd->vdev_ops->vdev_op_leaf) {
		list_insert_head(&cvd->vdev_spa->spa_leaf_list, cvd);
		cvd->vdev_spa->spa_leaf_list_gen++;
	}
}

/*
 * Allocate and minimally initialize a vdev_t.
 */
vdev_t *
vdev_alloc_common(spa_t *spa, uint_t id, uint64_t guid, vdev_ops_t *ops)
{
	vdev_t *vd;
	vdev_indirect_config_t *vic;

	vd = malloc(sizeof (vdev_t));
	vic = &vd->vdev_indirect_config;

	if (spa->spa_root_vdev == NULL) {
		ASSERT(ops == &vdev_root_ops);
		spa->spa_root_vdev = vd;
		spa->spa_load_guid = spa_generate_guid(NULL);
	}

	if (guid == 0 && ops != &vdev_hole_ops) {
		if (spa->spa_root_vdev == vd) {
			/*
			 * The root vdev's guid will also be the pool guid,
			 * which must be unique among all pools.
			 */
			guid = spa_generate_guid(NULL);
		} else {
			/*
			 * Any other vdev's guid must be unique within the pool.
			 */
			guid = spa_generate_guid(spa);
		}
		ASSERT(!spa_guid_exists(spa_guid(spa), guid));
	}

	vd->vdev_spa = spa;
	vd->vdev_id = id;
	vd->vdev_guid = guid;
	vd->vdev_guid_sum = guid;
	vd->vdev_ops = ops;
	vd->vdev_state = VDEV_STATE_CLOSED;
	vd->vdev_ishole = (ops == &vdev_hole_ops);
	vic->vic_prev_indirect_vdev = UINT64_MAX;

	list_link_init(&vd->vdev_initialize_node);
	list_link_init(&vd->vdev_leaf_node);

	vdev_queue_init(vd);
	vdev_cache_init(vd);

	return (vd);
}

/*
 * Allocate a new vdev.  The 'alloctype' is used to control whether we are
 * creating a new vdev or loading an existing one - the behavior is slightly
 * different for each case.
 */
int
vdev_alloc(spa_t *spa, vdev_t **vdp, nvlist_t *nv, vdev_t *parent, uint_t id,
    int alloctype)
{
	vdev_ops_t *ops;
	char *type;
	uint64_t guid = 0, islog, nparity;
	vdev_t *vd;
	vdev_indirect_config_t *vic;
	vdev_alloc_bias_t alloc_bias = VDEV_BIAS_NONE;
	boolean_t top_level = (parent && !parent->vdev_parent);

	if (nvlist_lookup_string(nv, ZPOOL_CONFIG_TYPE, &type) != 0)
		return (EINVAL);

	if ((ops = vdev_getops(type)) == NULL)
		return (EINVAL);

	/*
	 * If this is a load, get the vdev guid from the nvlist.
	 * Otherwise, vdev_alloc_common() will generate one for us.
	 */
	if (alloctype == VDEV_ALLOC_LOAD) {
		uint64_t label_id;

		if (nvlist_lookup_uint64(nv, ZPOOL_CONFIG_ID, &label_id) ||
		    label_id != id)
			return (SET_ERROR(EINVAL));

		if (nvlist_lookup_uint64(nv, ZPOOL_CONFIG_GUID, &guid) != 0)
			return (SET_ERROR(EINVAL));
	} else if (alloctype == VDEV_ALLOC_SPARE) {
		if (nvlist_lookup_uint64(nv, ZPOOL_CONFIG_GUID, &guid) != 0)
			return (SET_ERROR(EINVAL));
	} else if (alloctype == VDEV_ALLOC_L2CACHE) {
		if (nvlist_lookup_uint64(nv, ZPOOL_CONFIG_GUID, &guid) != 0)
			return (SET_ERROR(EINVAL));
	} else if (alloctype == VDEV_ALLOC_ROOTPOOL) {
		if (nvlist_lookup_uint64(nv, ZPOOL_CONFIG_GUID, &guid) != 0)
			return (SET_ERROR(EINVAL));
	}

	/*
	 * The first allocated vdev must be of type 'root'.
	 */
	if (ops != &vdev_root_ops && spa->spa_root_vdev == NULL)
		return (SET_ERROR(EINVAL));

	/*
	 * Determine whether we're a log vdev.
	 */
	islog = 0;
	(void) nvlist_lookup_uint64(nv, ZPOOL_CONFIG_IS_LOG, &islog);
	if (islog && spa_version(spa) < SPA_VERSION_SLOGS)
		return (SET_ERROR(ENOTSUP));

	if (ops == &vdev_hole_ops && spa_version(spa) < SPA_VERSION_HOLES)
		return (SET_ERROR(ENOTSUP));

	/*
	 * Set the nparity property for RAID-Z vdevs.
	 */
	nparity = -1ULL;
	if (ops == &vdev_raidz_ops) {
		if (nvlist_lookup_uint64(nv, ZPOOL_CONFIG_NPARITY,
		    &nparity) == 0) {
			if (nparity == 0 || nparity > VDEV_RAIDZ_MAXPARITY)
				return (SET_ERROR(EINVAL));
			/*
			 * Previous versions could only support 1 or 2 parity
			 * device.
			 */
			if (nparity > 1 &&
			    spa_version(spa) < SPA_VERSION_RAIDZ2)
				return (SET_ERROR(ENOTSUP));
			if (nparity > 2 &&
			    spa_version(spa) < SPA_VERSION_RAIDZ3)
				return (SET_ERROR(ENOTSUP));
		} else {
			/*
			 * We require the parity to be specified for SPAs that
			 * support multiple parity levels.
			 */
			if (spa_version(spa) >= SPA_VERSION_RAIDZ2)
				return (SET_ERROR(EINVAL));
			/*
			 * Otherwise, we default to 1 parity device for RAID-Z.
			 */
			nparity = 1;
		}
	} else {
		nparity = 0;
	}
	ASSERT(nparity != -1ULL);

	/*
	 * If creating a top-level vdev, check for allocation classes input
	 */
	if (top_level && alloctype == VDEV_ALLOC_ADD) {
		char *bias;

		if (nvlist_lookup_string(nv, ZPOOL_CONFIG_ALLOCATION_BIAS,
		    &bias) == 0) {
			alloc_bias = vdev_derive_alloc_bias(bias);

			/* spa_vdev_add() expects feature to be enabled */
			if (alloc_bias != VDEV_BIAS_LOG &&
			    spa->spa_load_state != SPA_LOAD_CREATE &&
			    !spa_feature_is_enabled(spa,
			    SPA_FEATURE_ALLOCATION_CLASSES)) {
				return (SET_ERROR(ENOTSUP));
			}
		}
	}

	vd = vdev_alloc_common(spa, id, guid, ops);
	vic = &vd->vdev_indirect_config;

	vd->vdev_islog = islog;
	vd->vdev_nparity = nparity;
	if (top_level && alloc_bias != VDEV_BIAS_NONE)
		vd->vdev_alloc_bias = alloc_bias;

	if (nvlist_lookup_string(nv, ZPOOL_CONFIG_PATH, &vd->vdev_path) == 0)
		vd->vdev_path = spa_strdup(vd->vdev_path);
	if (nvlist_lookup_string(nv, ZPOOL_CONFIG_DEVID, &vd->vdev_devid) == 0)
		vd->vdev_devid = spa_strdup(vd->vdev_devid);
	if (nvlist_lookup_string(nv, ZPOOL_CONFIG_PHYS_PATH,
	    &vd->vdev_physpath) == 0)
		vd->vdev_physpath = spa_strdup(vd->vdev_physpath);
	if (nvlist_lookup_string(nv, ZPOOL_CONFIG_FRU, &vd->vdev_fru) == 0)
		vd->vdev_fru = spa_strdup(vd->vdev_fru);

	/*
	 * Set the whole_disk property.  If it's not specified, leave the value
	 * as -1.
	 */
	if (nvlist_lookup_uint64(nv, ZPOOL_CONFIG_WHOLE_DISK,
	    &vd->vdev_wholedisk) != 0)
		vd->vdev_wholedisk = -1ULL;

	ASSERT0(vic->vic_mapping_object);
	(void) nvlist_lookup_uint64(nv, ZPOOL_CONFIG_INDIRECT_OBJECT,
	    &vic->vic_mapping_object);
	ASSERT0(vic->vic_births_object);
	(void) nvlist_lookup_uint64(nv, ZPOOL_CONFIG_INDIRECT_BIRTHS,
	    &vic->vic_births_object);
	ASSERT3U(vic->vic_prev_indirect_vdev, ==, UINT64_MAX);
	(void) nvlist_lookup_uint64(nv, ZPOOL_CONFIG_PREV_INDIRECT_VDEV,
	    &vic->vic_prev_indirect_vdev);

	/*
	 * Look for the 'not present' flag.  This will only be set if the device
	 * was not present at the time of import.
	 */
	(void) nvlist_lookup_uint64(nv, ZPOOL_CONFIG_NOT_PRESENT,
	    &vd->vdev_not_present);

	/*
	 * Get the alignment requirement.
	 */
	(void) nvlist_lookup_uint64(nv, ZPOOL_CONFIG_ASHIFT, &vd->vdev_ashift);

	/*
	 * Retrieve the vdev creation time.
	 */
	(void) nvlist_lookup_uint64(nv, ZPOOL_CONFIG_CREATE_TXG,
	    &vd->vdev_crtxg);

	/*
	 * If we're a top-level vdev, try to load the allocation parameters.
	 */
	if (top_level &&
	    (alloctype == VDEV_ALLOC_LOAD || alloctype == VDEV_ALLOC_SPLIT)) {
		(void) nvlist_lookup_uint64(nv, ZPOOL_CONFIG_METASLAB_ARRAY,
		    &vd->vdev_ms_array);
		(void) nvlist_lookup_uint64(nv, ZPOOL_CONFIG_METASLAB_SHIFT,
		    &vd->vdev_ms_shift);
		(void) nvlist_lookup_uint64(nv, ZPOOL_CONFIG_ASIZE,
		    &vd->vdev_asize);
		(void) nvlist_lookup_uint64(nv, ZPOOL_CONFIG_REMOVING,
		    &vd->vdev_removing);
		(void) nvlist_lookup_uint64(nv, ZPOOL_CONFIG_VDEV_TOP_ZAP,
		    &vd->vdev_top_zap);
	} else {
		ASSERT0(vd->vdev_top_zap);
	}

	if (top_level && alloctype != VDEV_ALLOC_ATTACH) {
		ASSERT(alloctype == VDEV_ALLOC_LOAD ||
		    alloctype == VDEV_ALLOC_ADD ||
		    alloctype == VDEV_ALLOC_SPLIT ||
		    alloctype == VDEV_ALLOC_ROOTPOOL);
		/* Note: metaslab_group_create() is now deferred */
	}

	if (vd->vdev_ops->vdev_op_leaf &&
	    (alloctype == VDEV_ALLOC_LOAD || alloctype == VDEV_ALLOC_SPLIT)) {
		(void) nvlist_lookup_uint64(nv,
		    ZPOOL_CONFIG_VDEV_LEAF_ZAP, &vd->vdev_leaf_zap);
	} else {
		ASSERT0(vd->vdev_leaf_zap);
	}

	/*
	 * If we're a leaf vdev, try to load the DTL object and other state.
	 */

	if (vd->vdev_ops->vdev_op_leaf &&
	    (alloctype == VDEV_ALLOC_LOAD || alloctype == VDEV_ALLOC_L2CACHE ||
	    alloctype == VDEV_ALLOC_ROOTPOOL)) {
		if (alloctype == VDEV_ALLOC_LOAD) {
			(void) nvlist_lookup_uint64(nv, ZPOOL_CONFIG_DTL,
			    &vd->vdev_dtl_object);
			(void) nvlist_lookup_uint64(nv, ZPOOL_CONFIG_UNSPARE,
			    &vd->vdev_unspare);
		}

		if (alloctype == VDEV_ALLOC_ROOTPOOL) {
			uint64_t spare = 0;

			if (nvlist_lookup_uint64(nv, ZPOOL_CONFIG_IS_SPARE,
			    &spare) == 0 && spare)
				spa_spare_add(vd);
		}

		(void) nvlist_lookup_uint64(nv, ZPOOL_CONFIG_OFFLINE,
		    &vd->vdev_offline);

		(void) nvlist_lookup_uint64(nv, ZPOOL_CONFIG_RESILVER_TXG,
		    &vd->vdev_resilver_txg);

		if (nvlist_exists(nv, ZPOOL_CONFIG_RESILVER_DEFER))
			vdev_defer_resilver(vd);

		/*
		 * When importing a pool, we want to ignore the persistent fault
		 * state, as the diagnosis made on another system may not be
		 * valid in the current context.  Local vdevs will
		 * remain in the faulted state.
		 */
		if (spa_load_state(spa) == SPA_LOAD_OPEN) {
			(void) nvlist_lookup_uint64(nv, ZPOOL_CONFIG_FAULTED,
			    &vd->vdev_faulted);
			(void) nvlist_lookup_uint64(nv, ZPOOL_CONFIG_DEGRADED,
			    &vd->vdev_degraded);
			(void) nvlist_lookup_uint64(nv, ZPOOL_CONFIG_REMOVED,
			    &vd->vdev_removed);

			if (vd->vdev_faulted || vd->vdev_degraded) {
				char *aux;

				vd->vdev_label_aux =
				    VDEV_AUX_ERR_EXCEEDED;
				if (nvlist_lookup_string(nv,
				    ZPOOL_CONFIG_AUX_STATE, &aux) == 0 &&
				    strcmp(aux, "external") == 0)
					vd->vdev_label_aux = VDEV_AUX_EXTERNAL;
			}
		}
	}

	/*
	 * Add ourselves to the parent's list of children.
	 */
	vdev_add_child(parent, vd);

	*vdp = vd;

	return (0);
}

void
vdev_free(vdev_t *vd)
{
	spa_t *spa = vd->vdev_spa;

	ASSERT3P(vd->vdev_initialize_thread, ==, NULL);
	ASSERT3P(vd->vdev_trim_thread, ==, NULL);
	ASSERT3P(vd->vdev_autotrim_thread, ==, NULL);

	/*
	 * Scan queues are normally destroyed at the end of a scan. If the
	 * queue exists here, that implies the vdev is being removed while
	 * the scan is still running.
	 */
	if (vd->vdev_scan_io_queue != NULL) {
		mutex_enter(&vd->vdev_scan_io_queue_lock);
		dsl_scan_io_queue_destroy(vd->vdev_scan_io_queue);
		vd->vdev_scan_io_queue = NULL;
		mutex_exit(&vd->vdev_scan_io_queue_lock);
	}

	/*
	 * vdev_free() implies closing the vdev first.  This is simpler than
	 * trying to ensure complicated semantics for all callers.
	 */
	vdev_close(vd);

	ASSERT(!list_link_active(&vd->vdev_config_dirty_node));
	ASSERT(!list_link_active(&vd->vdev_state_dirty_node));

	/*
	 * Free all children.
	 */
	for (int c = 0; c < vd->vdev_children; c++)
		vdev_free(vd->vdev_child[c]);

	ASSERT(vd->vdev_child == NULL);
	ASSERT(vd->vdev_guid_sum == vd->vdev_guid);

	/*
	 * Discard allocation state.
	 */
	if (vd->vdev_mg != NULL) {
		vdev_metaslab_fini(vd);
		metaslab_group_destroy(vd->vdev_mg);
		vd->vdev_mg = NULL;
	}

	ASSERT0(vd->vdev_stat.vs_space);
	ASSERT0(vd->vdev_stat.vs_dspace);
	ASSERT0(vd->vdev_stat.vs_alloc);

	/*
	 * Remove this vdev from its parent's child list.
	 */
	vdev_remove_child(vd->vdev_parent, vd);

	ASSERT(vd->vdev_parent == NULL);
	ASSERT(!list_link_active(&vd->vdev_leaf_node));

	/*
	 * Clean up vdev structure.
	 */
	vdev_queue_fini(vd);
	vdev_cache_fini(vd);

	if (vd->vdev_path)
		spa_strfree(vd->vdev_path);
	if (vd->vdev_devid)
		spa_strfree(vd->vdev_devid);
	if (vd->vdev_physpath)
		spa_strfree(vd->vdev_physpath);
	if (vd->vdev_fru)
		spa_strfree(vd->vdev_fru);

	if (vd->vdev_isspare)
		spa_spare_remove(vd);
	if (vd->vdev_isl2cache)
		spa_l2cache_remove(vd);

	txg_list_destroy(&vd->vdev_ms_list);
	txg_list_destroy(&vd->vdev_dtl_list);

	mutex_enter(&vd->vdev_dtl_lock);
	space_map_close(vd->vdev_dtl_sm);
	for (int t = 0; t < DTL_TYPES; t++) {
		range_tree_vacate(vd->vdev_dtl[t], NULL, NULL);
		range_tree_destroy(vd->vdev_dtl[t]);
	}
	mutex_exit(&vd->vdev_dtl_lock);

	EQUIV(vd->vdev_indirect_births != NULL,
	    vd->vdev_indirect_mapping != NULL);
	if (vd->vdev_indirect_births != NULL) {
		vdev_indirect_mapping_close(vd->vdev_indirect_mapping);
		vdev_indirect_births_close(vd->vdev_indirect_births);
	}

	rw_destroy(&vd->vdev_indirect_rwlock);
	mutex_destroy(&vd->vdev_obsolete_lock);

	mutex_destroy(&vd->vdev_dtl_lock);
	mutex_destroy(&vd->vdev_stat_lock);
	mutex_destroy(&vd->vdev_probe_lock);
	mutex_destroy(&vd->vdev_scan_io_queue_lock);
	mutex_destroy(&vd->vdev_initialize_lock);
	mutex_destroy(&vd->vdev_initialize_io_lock);
	cv_destroy(&vd->vdev_initialize_io_cv);
	cv_destroy(&vd->vdev_initialize_cv);
	mutex_destroy(&vd->vdev_trim_lock);
	mutex_destroy(&vd->vdev_autotrim_lock);
	mutex_destroy(&vd->vdev_trim_io_lock);
	cv_destroy(&vd->vdev_trim_cv);
	cv_destroy(&vd->vdev_autotrim_cv);
	cv_destroy(&vd->vdev_trim_io_cv);

	if (vd == spa->spa_root_vdev)
		spa->spa_root_vdev = NULL;

	kmem_free(vd, sizeof (vdev_t));
}

uint64_t
vdev_psize_to_asize(vdev_t *vd, uint64_t psize)
{
	return (vd->vdev_ops->vdev_op_asize(vd, psize));
}
