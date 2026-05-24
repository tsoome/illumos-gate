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
 * Copyright (c) 2011, 2020 by Delphix. All rights reserved.
 * Copyright (c) 2017, Intel Corporation.
 * Copyright 2019 Joyent, Inc.
 * Copyright 2020 Joshua M. Clulow <josh@sysmgr.org>
 */

#ifndef _SYS_VDEV_IMPL_H
#define	_SYS_VDEV_IMPL_H

#include <sys/spa.h>
#include <sys/list.h>
#include <sys/zio.h>
#include <sys/range_tree.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * Virtual device operations
 */
typedef int     vdev_open_func_t(vdev_t *, uint64_t *, uint64_t *, uint64_t *);
typedef void    vdev_close_func_t(vdev_t *);
typedef uint64_t vdev_asize_func_t(vdev_t *, uint64_t);
typedef void    vdev_io_start_func_t(zio_t *);
typedef void    vdev_io_done_func_t(zio_t *);
typedef void    vdev_state_change_func_t(vdev_t *, int, int);
typedef boolean_t vdev_need_resilver_func_t(vdev_t *, uint64_t, size_t);
typedef void    vdev_hold_func_t(vdev_t *);
typedef void    vdev_rele_func_t(vdev_t *);

typedef void    vdev_remap_cb_t(uint64_t, vdev_t *, uint64_t, uint64_t, void *);
typedef void    vdev_remap_func_t(vdev_t *, uint64_t, uint64_t,
    vdev_remap_cb_t , void *);
/*
 * Given a target vdev, translates the logical range "in" to the physical
 * range "res"
 */
typedef void vdev_xlation_func_t(vdev_t *, const range_seg64_t *in,
    range_seg64_t *res);

typedef struct vdev_ops {
	vdev_open_func_t		*vdev_op_open;
	vdev_close_func_t		*vdev_op_close;
	vdev_asize_func_t		*vdev_op_asize;
	vdev_io_start_func_t		*vdev_op_io_start;
	vdev_io_done_func_t		*vdev_op_io_done;
	vdev_state_change_func_t	*vdev_op_state_change;
	vdev_need_resilver_func_t	*vdev_op_need_resilver;
	vdev_hold_func_t		*vdev_op_hold;
	vdev_rele_func_t		*vdev_op_rele;
	vdev_remap_func_t		*vdev_op_remap;
	/*
	 * For translating ranges from non-leaf vdevs (e.g. raidz) to leaves.
	 * Used when initializing vdevs. Isn't used by leaf ops.
	 */
	vdev_xlation_func_t		*vdev_op_xlate;
	char				vdev_op_type[16];
	boolean_t			vdev_op_leaf;
} vdev_ops_t;

/*
 * On-disk indirect vdev state.
 *
 * An indirect vdev is described exclusively in the MOS config of a pool.
 * The config for an indirect vdev includes several fields, which are
 * accessed in memory by a vdev_indirect_config_t.
 */
typedef struct vdev_indirect_config {
	/*
	 * Object (in MOS) which contains the indirect mapping. This object
	 * contains an array of vdev_indirect_mapping_entry_phys_t ordered by
	 * vimep_src. The bonus buffer for this object is a
	 * vdev_indirect_mapping_phys_t. This object is allocated when a vdev
	 * removal is initiated.
	 *
	 * Note that this object can be empty if none of the data on the vdev
	 * has been copied yet.
	 */
	uint64_t	vic_mapping_object;

	/*
	 * Object (in MOS) which contains the birth times for the mapping
	 * entries. This object contains an array of
	 * vdev_indirect_birth_entry_phys_t sorted by vibe_offset. The bonus
	 * buffer for this object is a vdev_indirect_birth_phys_t. This object
	 * is allocated when a vdev removal is initiated.
	 *
	 * Note that this object can be empty if none of the vdev has yet been
	 * copied.
	 */
	uint64_t	vic_births_object;

	/*
	 * This is the vdev ID which was removed previous to this vdev, or
	 * UINT64_MAX if there are no previously removed vdevs.
	 */
	uint64_t	vic_prev_indirect_vdev;
} vdev_indirect_config_t;

/*
 * Virtual device descriptor
 */
struct vdev {
	/*
	 * Common to all vdev types.
	 */
	uint64_t	vdev_id;	/* child number in vdev parent	*/
	uint64_t	vdev_guid;	/* unique ID for this vdev	*/
	uint64_t	vdev_guid_sum;	/* self guid + all child guids	*/
//	uint64_t	vdev_orig_guid;	/* orig. guid prior to remove	*/
	uint64_t	vdev_asize;	/* allocatable device capacity	*/
//	uint64_t	vdev_min_asize;	/* min acceptable asize		*/
	uint64_t	vdev_max_asize;	/* max acceptable asize		*/
	uint64_t	vdev_ashift;	/* block alignment shift	*/
	uint64_t	vdev_state;	/* see VDEV_STATE_* #defines	*/
//	uint64_t	vdev_prevstate;	/* used when reopening a vdev	*/
	vdev_ops_t	*vdev_ops;	/* vdev operations		*/
	spa_t		*vdev_spa;	/* spa for this vdev		*/
	void		*vdev_tsd;	/* type-specific data		*/
//	vnode_t		*vdev_name_vp;	/* vnode for pathname		*/
//	vnode_t		*vdev_devid_vp;	/* vnode for devid		*/
	vdev_t		*vdev_top;	/* top-level vdev		*/
	vdev_t		*vdev_parent;	/* parent vdev			*/
	vdev_t		**vdev_child;	/* array of children		*/
	uint64_t	vdev_children;	/* number of children		*/
	vdev_stat_t	vdev_stat;	/* virtual device statistics	*/
//	vdev_stat_ex_t	vdev_stat_ex;	/* extended statistics		*/
//	boolean_t	vdev_expanding;	/* expand the vdev?		*/
//	boolean_t	vdev_reopening;	/* reopen in progress?		*/
//	boolean_t	vdev_nonrot;	/* true if solid state		*/
	int		vdev_open_error; /* error on last open		*/
//	kthread_t	*vdev_open_thread; /* thread opening children	*/
//	uint64_t	vdev_crtxg;	/* txg when top-level was added */

	/*
	 * Top-level vdev state.
	 */
//	uint64_t	vdev_ms_array;	/* metaslab array object	*/
//	uint64_t	vdev_ms_shift;	/* metaslab size shift		*/
//	uint64_t	vdev_ms_count;	/* number of metaslabs		*/
//	metaslab_group_t *vdev_mg;	/* metaslab group		*/
//	metaslab_t	**vdev_ms;	/* metaslab array		*/
//	txg_list_t	vdev_ms_list;	/* per-txg dirty metaslab lists	*/
//	txg_list_t	vdev_dtl_list;	/* per-txg dirty DTL lists	*/
//	txg_node_t	vdev_txg_node;	/* per-txg dirty vdev linkage	*/
//	boolean_t	vdev_remove_wanted; /* async remove wanted?	*/
//	boolean_t	vdev_probe_wanted; /* async probe wanted?	*/
//	list_node_t	vdev_config_dirty_node; /* config dirty list	*/
//	list_node_t	vdev_state_dirty_node; /* state dirty list	*/
//	uint64_t	vdev_deflate_ratio; /* deflation ratio (x512)	*/
//	uint64_t	vdev_islog;	/* is an intent log device	*/
//	uint64_t	vdev_removing;	/* device is being removed?	*/
	boolean_t	vdev_ishole;	/* is a hole in the namespace	*/
//	uint64_t	vdev_top_zap;
//	vdev_alloc_bias_t vdev_alloc_bias; /* metaslab allocation bias	*/

	/* pool checkpoint related */
//	space_map_t	*vdev_checkpoint_sm;	/* contains reserved blocks */

	/* Initialize related */
//	boolean_t	vdev_initialize_exit_wanted;
//	vdev_initializing_state_t	vdev_initialize_state;
	list_node_t	vdev_initialize_node;
//	kthread_t	*vdev_initialize_thread;
//	/* Protects vdev_initialize_thread and vdev_initialize_state. */
//	kmutex_t	vdev_initialize_lock;
//	kcondvar_t	vdev_initialize_cv;
//	uint64_t	vdev_initialize_offset[TXG_SIZE];
//	uint64_t	vdev_initialize_last_offset;
//	range_tree_t	*vdev_initialize_tree;	/* valid while initializing */
//	uint64_t	vdev_initialize_bytes_est;
//	uint64_t	vdev_initialize_bytes_done;
//	time_t		vdev_initialize_action_time;	/* start and end time */

	/* for limiting outstanding I/Os (initialize and TRIM) */
//	kmutex_t	vdev_initialize_io_lock;
//	kcondvar_t	vdev_initialize_io_cv;
//	uint64_t	vdev_initialize_inflight;
//	kmutex_t	vdev_trim_io_lock;
//	kcondvar_t	vdev_trim_io_cv;
//	uint64_t	vdev_trim_inflight[2];

	/*
	 * Values stored in the config for an indirect or removing vdev.
	 */
	vdev_indirect_config_t	vdev_indirect_config;

	/*
	 * The vdev_indirect_rwlock protects the vdev_indirect_mapping
	 * pointer from changing on indirect vdevs (when it is condensed).
	 * Note that removing (not yet indirect) vdevs have different
	 * access patterns (the mapping is not accessed from open context,
	 * e.g. from zio_read) and locking strategy (e.g. svr_lock).
	 */
//	krwlock_t vdev_indirect_rwlock;
//	vdev_indirect_mapping_t *vdev_indirect_mapping;
//	vdev_indirect_births_t *vdev_indirect_births;

	/*
	 * Protects the vdev_scan_io_queue field itself as well as the
	 * structure's contents (when present).
	 */
//	kmutex_t	vdev_scan_io_queue_lock;
//	struct dsl_scan_io_queue	*vdev_scan_io_queue;

	/*
	 * Leaf vdev state.
	 */
	uint64_t	vdev_psize;	/* physical device capacity	*/
//	uint64_t	vdev_wholedisk;	/* true if this is a whole disk */
//	uint64_t	vdev_offline;	/* persistent offline state	*/
//	uint64_t	vdev_faulted;	/* persistent faulted state	*/
//	uint64_t	vdev_degraded;	/* persistent degraded state	*/
//	uint64_t	vdev_removed;	/* persistent removed state	*/
//	uint64_t	vdev_resilver_txg; /* persistent resilvering state */
	uint64_t	vdev_nparity;	/* number of parity devices for raidz */
//	char		*vdev_path;	/* vdev path (if any)		*/
//	char		*vdev_devid;	/* vdev devid (if any)		*/
//	char		*vdev_physpath;	/* vdev device path (if any)	*/
//	char		*vdev_fru;	/* physical FRU location	*/
//	uint64_t	vdev_not_present; /* not present during import	*/
//	uint64_t	vdev_unspare;	/* unspare when resilvering done */
//	boolean_t	vdev_nowritecache; /* true if flushwritecache failed */
//	boolean_t	vdev_has_trim;	/* TRIM is supported		*/
//	boolean_t	vdev_has_securetrim; /* secure TRIM is supported */
//	boolean_t	vdev_checkremove; /* temporary online test	*/
//	boolean_t	vdev_forcefault; /* force online fault		*/
//	boolean_t	vdev_splitting;	/* split or repair in progress  */
//	boolean_t	vdev_delayed_close; /* delayed device close?	*/
//	boolean_t	vdev_tmpoffline; /* device taken offline temporarily? */
//	boolean_t	vdev_detached;	/* device detached?		*/
//	boolean_t	vdev_cant_read;	/* vdev is failing all reads	*/
//	boolean_t	vdev_cant_write; /* vdev is failing all writes	*/
//	boolean_t	vdev_isspare;	/* was a hot spare		*/
//	boolean_t	vdev_isl2cache;	/* was a l2cache device		*/
//	boolean_t	vdev_resilver_deferred;  /* resilver deferred */
//	vdev_queue_t	vdev_queue;	/* I/O deadline schedule queue	*/
//	vdev_cache_t	vdev_cache;	/* physical block cache		*/
//	spa_aux_vdev_t	*vdev_aux;	/* for l2cache and spares vdevs	*/
//	zio_t		*vdev_probe_zio; /* root of current probe	*/
//	vdev_aux_t	vdev_label_aux;	/* on-disk aux state		*/
//	uint64_t	vdev_leaf_zap;
	list_node_t	vdev_leaf_node;		/* leaf vdev list */
};

#if 0
typedef struct vdev {
	STAILQ_ENTRY(vdev) v_childlink;	/* link in parent's child list */
	STAILQ_ENTRY(vdev) v_alllink;	/* link in global vdev list */
	vdev_list_t	v_children;	/* children of this vdev */
	const char	*v_name;	/* vdev name */
	const char	*v_phys_path;	/* vdev bootpath */
	const char	*v_devid;	/* vdev devid */
	uint64_t	v_guid;		/* vdev guid */
	uint64_t	v_id;		/* index in parent */
	uint64_t	vdev_asize;	/* allocatable device capacity  */
	uint64_t	v_psize;	/* physical device capacity */
	uint64_t	vdev_ashift;	/* offset to block shift */
	int		v_nparity;	/* # parity for raidz */
	struct vdev	*v_top;		/* parent vdev */
	size_t		v_nchildren;	/* # children */
	vdev_state_t	v_state;	/* current state */
	vdev_ops_t	*vdev_ops;
	vdev_phys_read_t *v_phys_read;	/* read from raw leaf vdev */
	vdev_phys_write_t *v_phys_write; /* write to raw leaf vdev */
	vdev_read_t	*v_read;	/* read from vdev */
	void		*v_priv;	/* data for read/write function */
	boolean_t	v_islog;
	struct spa	*v_spa;		/* link to spa */
	/*
	 * Values stored in the config for an indirect or removing vdev.
	 */
	vdev_indirect_config_t vdev_indirect_config;
	vdev_indirect_mapping_t *vdev_indirect_mapping;
} vdev_t;
#endif

#define	VDEV_RAIDZ_MAXPARITY	3

#define	VDEV_PAD_SIZE		(8 << 10)
/* 2 padding areas (vl_pad1 and vl_be) to skip */
#define	VDEV_SKIP_SIZE		VDEV_PAD_SIZE * 2
#define	VDEV_PHYS_SIZE		(112 << 10)
#define	VDEV_UBERBLOCK_RING	(128 << 10)

/*
 * MMP blocks occupy the last MMP_BLOCKS_PER_LABEL slots in the uberblock
 * ring when MMP is enabled.
 */
#define	MMP_BLOCKS_PER_LABEL	1

/* The largest uberblock we support is 8k. */
#define	MAX_UBERBLOCK_SHIFT	(13)
#define	VDEV_UBERBLOCK_SHIFT(vd)	\
	MIN(MAX((vd)->vdev_top->vdev_ashift, UBERBLOCK_SHIFT), \
	MAX_UBERBLOCK_SHIFT)
#define	VDEV_UBERBLOCK_COUNT(vd)	\
	(VDEV_UBERBLOCK_RING >> VDEV_UBERBLOCK_SHIFT(vd))
#define	VDEV_UBERBLOCK_OFFSET(vd, n)	\
	offsetof(vdev_label_t, vl_uberblock[(n) << VDEV_UBERBLOCK_SHIFT(vd)])
#define	VDEV_UBERBLOCK_SIZE(vd)		(1ULL << VDEV_UBERBLOCK_SHIFT(vd))

typedef struct vdev_phys {
	char		vp_nvlist[VDEV_PHYS_SIZE - sizeof (zio_eck_t)];
	zio_eck_t	vp_zbt;
} vdev_phys_t;

typedef enum vbe_vers {
	/* The bootenv file is stored as ascii text in the envblock */
	VB_RAW = 0,

	/*
	 * The bootenv file is converted to an nvlist and then packed into the
	 * envblock.
	 */
	VB_NVLIST = 1
} vbe_vers_t;

typedef struct vdev_boot_envblock {
	uint64_t	vbe_version;
	char		vbe_bootenv[VDEV_PAD_SIZE - sizeof (uint64_t) -
			sizeof (zio_eck_t)];
	zio_eck_t	vbe_zbt;
} vdev_boot_envblock_t;

CTASSERT(sizeof (vdev_boot_envblock_t) == VDEV_PAD_SIZE);

typedef struct vdev_label {
	char		vl_pad1[VDEV_PAD_SIZE];			/*  8K  */
	vdev_boot_envblock_t vl_be;				/*  8K  */
	vdev_phys_t	vl_vdev_phys;				/* 112K	*/
	char		vl_uberblock[VDEV_UBERBLOCK_RING];	/* 128K	*/
} vdev_label_t;							/* 256K total */

/*
 * vdev_dirty() flags
 */
#define	VDD_METASLAB	0x01
#define	VDD_DTL		0x02

/*
 * Size and offset of embedded boot loader region on each label.
 * The total size of the first two labels plus the boot area is 4MB.
 */
#define	VDEV_BOOT_OFFSET	(2 * sizeof (vdev_label_t))
#define	VDEV_BOOT_SIZE		(7ULL << 19)			/* 3.5M	*/

/*
 * Size of label regions at the start and end of each leaf device.
 */
#define	VDEV_LABEL_START_SIZE	(2 * sizeof (vdev_label_t) + VDEV_BOOT_SIZE)
#define	VDEV_LABEL_END_SIZE	(2 * sizeof (vdev_label_t))
#define	VDEV_LABELS		4

/*
 * Available vdev types.
 */
extern vdev_ops_t vdev_root_ops;
extern vdev_ops_t vdev_mirror_ops;
extern vdev_ops_t vdev_replacing_ops;
extern vdev_ops_t vdev_raidz_ops;
extern vdev_ops_t vdev_disk_ops;
extern vdev_ops_t vdev_file_ops;
extern vdev_ops_t vdev_missing_ops;
extern vdev_ops_t vdev_hole_ops;
extern vdev_ops_t vdev_spare_ops;
extern vdev_ops_t vdev_indirect_ops;

#ifdef  __cplusplus
}
#endif

#endif	/* _SYS_VDEV_IMPL_H */
