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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2012, 2018 by Delphix. All rights reserved.
 * Copyright (c) 2013 by Saso Kiselkov. All rights reserved.
 * Copyright 2019, Joyent, Inc.
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 */

#ifndef _ZIO_H
#define	_ZIO_H

#include <fs/zfs.h>
#include <sys/spa.h>
#include <sys/zio_compress.h>
#include <sys/zio_impl.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * Embedded checksum
 */
#define	ZEC_MAGIC	0x210da7ab10c7a11ULL

typedef struct zio_eck {
	uint64_t	zec_magic;	/* for validation, endianness	*/
	zio_cksum_t	zec_cksum;	/* 256-bit checksum		*/
} zio_eck_t;

/*
 * Gang block headers are self-checksumming and contain an array
 * of block pointers.
 */
#define	SPA_GANGBLOCKSIZE	SPA_MINBLOCKSIZE
#define	SPA_GBH_NBLKPTRS	((SPA_GANGBLOCKSIZE - \
	sizeof (zio_eck_t)) / sizeof (blkptr_t))
#define	SPA_GBH_FILLER		((SPA_GANGBLOCKSIZE - \
	sizeof (zio_eck_t) - \
	(SPA_GBH_NBLKPTRS * sizeof (blkptr_t))) /\
	sizeof (uint64_t))

typedef struct zio_gbh {
	blkptr_t		zg_blkptr[SPA_GBH_NBLKPTRS];
	uint64_t		zg_filler[SPA_GBH_FILLER];
	zio_eck_t		zg_tail;
} zio_gbh_phys_t;

enum zio_checksum {
	ZIO_CHECKSUM_INHERIT = 0,
	ZIO_CHECKSUM_ON,
	ZIO_CHECKSUM_OFF,
	ZIO_CHECKSUM_LABEL,
	ZIO_CHECKSUM_GANG_HEADER,
	ZIO_CHECKSUM_ZILOG,
	ZIO_CHECKSUM_FLETCHER_2,
	ZIO_CHECKSUM_FLETCHER_4,
	ZIO_CHECKSUM_SHA256,
	ZIO_CHECKSUM_ZILOG2,
	ZIO_CHECKSUM_NOPARITY,
	ZIO_CHECKSUM_SHA512,
	ZIO_CHECKSUM_SKEIN,
	ZIO_CHECKSUM_EDONR,
	ZIO_CHECKSUM_FUNCTIONS
};

#define	ZIO_CHECKSUM_ON_VALUE	ZIO_CHECKSUM_FLETCHER_4
#define	ZIO_CHECKSUM_DEFAULT	ZIO_CHECKSUM_ON

#define	ZIO_CHECKSUM_MASK	0xffULL
#define	ZIO_CHECKSUM_VERIFY	(1 << 8)

enum zio_flag {
	/*
	 * Flags inherited by gang, ddt, and vdev children,
	 * and that must be equal for two zios to aggregate
	 */
	ZIO_FLAG_DONT_AGGREGATE	= 1 << 0,
	ZIO_FLAG_IO_REPAIR	= 1 << 1,
	ZIO_FLAG_SELF_HEAL	= 1 << 2,
	ZIO_FLAG_RESILVER	= 1 << 3,
	ZIO_FLAG_SCRUB		= 1 << 4,
	ZIO_FLAG_SCAN_THREAD	= 1 << 5,
	ZIO_FLAG_PHYSICAL	= 1 << 6,

#define	ZIO_FLAG_AGG_INHERIT	(ZIO_FLAG_CANFAIL - 1)

	/*
	 * Flags inherited by ddt, gang, and vdev children.
	 */
	ZIO_FLAG_CANFAIL	= 1 << 7,	/* must be first for INHERIT */
	ZIO_FLAG_SPECULATIVE	= 1 << 8,
	ZIO_FLAG_CONFIG_WRITER	= 1 << 9,
	ZIO_FLAG_DONT_RETRY	= 1 << 10,
	ZIO_FLAG_DONT_CACHE	= 1 << 11,
	ZIO_FLAG_NODATA		= 1 << 12,
	ZIO_FLAG_INDUCE_DAMAGE	= 1 << 13,
	ZIO_FLAG_IO_ALLOCATING	= 1 << 14,

#define	ZIO_FLAG_DDT_INHERIT	(ZIO_FLAG_IO_RETRY - 1)
#define	ZIO_FLAG_GANG_INHERIT	(ZIO_FLAG_IO_RETRY - 1)

	/*
	 * Flags inherited by vdev children.
	 */
	ZIO_FLAG_IO_RETRY	= 1 << 15,	/* must be first for INHERIT */
	ZIO_FLAG_PROBE		= 1 << 16,
	ZIO_FLAG_TRYHARD	= 1 << 17,
	ZIO_FLAG_OPTIONAL	= 1 << 18,

#define	ZIO_FLAG_VDEV_INHERIT	(ZIO_FLAG_DONT_QUEUE - 1)

	/*
	 * Flags not inherited by any children.
	 */
	ZIO_FLAG_DONT_QUEUE	= 1 << 19,	/* must be first for INHERIT */
	ZIO_FLAG_DONT_PROPAGATE	= 1 << 20,
	ZIO_FLAG_IO_BYPASS	= 1 << 21,
	ZIO_FLAG_IO_REWRITE	= 1 << 22,
	ZIO_FLAG_RAW_COMPRESS	= 1 << 23,
	ZIO_FLAG_RAW_ENCRYPT	= 1 << 24,
	ZIO_FLAG_GANG_CHILD	= 1 << 25,
	ZIO_FLAG_DDT_CHILD	= 1 << 26,
	ZIO_FLAG_GODFATHER	= 1 << 27,
	ZIO_FLAG_NOPWRITE	= 1 << 28,
	ZIO_FLAG_REEXECUTED	= 1 << 29,
	ZIO_FLAG_DELEGATED	= 1 << 30,
};

#define	ZIO_VDEV_CHILD_FLAGS(zio)				\
	(((zio)->io_flags & ZIO_FLAG_VDEV_INHERIT) |		\
	ZIO_FLAG_DONT_PROPAGATE | ZIO_FLAG_CANFAIL)

#define	ZIO_CHILD_BIT(x)		(1 << (x))
#define	ZIO_CHILD_BIT_IS_SET(val, x)	((val) & (1 << (x)))

enum zio_child {
	ZIO_CHILD_VDEV = 0,
	ZIO_CHILD_GANG,
	ZIO_CHILD_DDT,
	ZIO_CHILD_LOGICAL,
	ZIO_CHILD_TYPES
};

#define	ZIO_CHILD_VDEV_BIT		ZIO_CHILD_BIT(ZIO_CHILD_VDEV)
#define	ZIO_CHILD_GANG_BIT		ZIO_CHILD_BIT(ZIO_CHILD_GANG)
#define	ZIO_CHILD_DDT_BIT		ZIO_CHILD_BIT(ZIO_CHILD_DDT)
#define	ZIO_CHILD_LOGICAL_BIT		ZIO_CHILD_BIT(ZIO_CHILD_LOGICAL)
#define	ZIO_CHILD_ALL_BITS					\
	(ZIO_CHILD_VDEV_BIT | ZIO_CHILD_GANG_BIT |		\
	ZIO_CHILD_DDT_BIT | ZIO_CHILD_LOGICAL_BIT)

enum zio_wait_type {
	ZIO_WAIT_READY = 0,
	ZIO_WAIT_DONE,
	ZIO_WAIT_TYPES
};

#define	ECKSUM		666

typedef void zio_done_func_t(zio_t *zio);

typedef struct zio_prop {
	enum zio_checksum	zp_checksum;
	enum zio_compress	zp_compress;
	dmu_object_type_t	zp_type;
	uint8_t			zp_level;
	uint8_t			zp_copies;
	boolean_t		zp_dedup;
	boolean_t		zp_dedup_verify;
	boolean_t		zp_nopwrite;
	uint32_t		zp_zpl_smallblk;
	boolean_t		zp_encrypt;
	boolean_t		zp_byteorder;
	// uint8_t			zp_salt[ZIO_DATA_SALT_LEN];
	// uint8_t			zp_iv[ZIO_DATA_IV_LEN];
	// uint8_t			zp_mac[ZIO_DATA_MAC_LEN];
} zio_prop_t;

typedef struct zio_cksum_report zio_cksum_report_t;

typedef void zio_cksum_finish_f(zio_cksum_report_t *rep,
    const abd_t *good_data);
typedef void zio_cksum_free_f(void *cbdata, size_t size);

struct zio_bad_cksum;		/* defined in zio_checksum.h */
// struct dnode_phys;

struct zio_cksum_report {
	struct zio_cksum_report	*zcr_next;
	nvlist_t		*zcr_ereport;
	nvlist_t		*zcr_detector;
	void			*zcr_cbdata;
	size_t			zcr_cbinfo;	/* passed to zcr_free() */
	uint64_t		zcr_align;
	uint64_t		zcr_length;
	zio_cksum_finish_f	*zcr_finish;
	zio_cksum_free_f	*zcr_free;

	/* internal use only */
	struct zio_bad_cksum	*zcr_ckinfo;	/* information from failure */
};

typedef void zio_vsd_cksum_report_f(zio_t *zio, zio_cksum_report_t *zcr,
    void *arg);

zio_vsd_cksum_report_f zio_vsd_default_cksum_report;

typedef struct zio_vsd_ops {
	zio_done_func_t		*vsd_free;
	zio_vsd_cksum_report_f	*vsd_cksum_report;
} zio_vsd_ops_t;

typedef void zio_transform_func_t(zio_t *, abd_t *, uint64_t);

typedef struct zio_transform {
	abd_t			*zt_orig_abd;
	uint64_t		zt_orig_size;
	uint64_t		zt_bufsize;
	zio_transform_func_t	*zt_transform;
	struct zio_transform	*zt_next;
} zio_transform_t;

typedef int zio_pipe_stage_t(zio_t *zio);

typedef struct zio_link {
	zio_t		*zl_parent;
	zio_t		*zl_child;
	list_node_t	zl_parent_node;
	list_node_t	zl_child_node;
} zio_link_t;

/* IO related arguments. */
struct zio {
	/* Core information about this I/O */
	zio_prop_t	io_prop;
	zio_type_t	io_type;
	spa_t		*io_spa;
	enum zio_child	io_child_type;
	uint8_t		io_reexecute;
	uint8_t		io_state[ZIO_WAIT_TYPES];
	blkptr_t	*io_bp;
	list_t		io_parent_list;
	list_t		io_child_list;
	zio_t		*io_logical;
	zio_transform_t	*io_transform_stack;

	/* Callback info */
	zio_done_func_t *io_ready;
	zio_done_func_t	*io_physdone;
	zio_done_func_t	*io_done;
	void		*io_private;

	/* Data represented by this I/O */
	abd_t		*io_abd;
	uint64_t	io_size;
	uint64_t	io_lsize;

	/* Stuff for the vdev stack */
	vdev_t		*io_vd;
	void		*io_vsd;
	const zio_vsd_ops_t *io_vsd_ops;
	uint64_t	io_offset;

	/* Internal pipeline state */
	enum zio_flag	io_flags;
	enum zio_stage	io_stage;
	enum zio_stage	io_pipeline;
	int		io_error;
	int		io_child_error[ZIO_CHILD_TYPES];
	uint64_t	io_children[ZIO_CHILD_TYPES][ZIO_WAIT_TYPES];
	uint64_t	io_child_count;
	uint64_t	io_phys_children;
	uint64_t	io_parent_count;
	uint64_t	*io_stall;
	zio_t		*io_gang_leader;

};

extern zio_t *zio_null(zio_t *pio, spa_t *spa, vdev_t *vd,
    zio_done_func_t *done, void *private, enum zio_flag flags);

extern zio_t *zio_root(spa_t *spa,
    zio_done_func_t *done, void *private, enum zio_flag flags);

extern zio_t *zio_read_phys(zio_t *pio, vdev_t *vd, uint64_t offset,
    uint64_t size, struct abd *data, int checksum,
    zio_done_func_t *done, void *private, enum zio_flag flags,
    boolean_t labels);

extern zio_t *zio_write_phys(zio_t *pio, vdev_t *vd, uint64_t offset,
    uint64_t size, struct abd *data, int checksum,
    zio_done_func_t *done, void *private, enum zio_flag flags,
    boolean_t labels);

extern int zio_wait(zio_t *zio);
extern void zio_nowait(zio_t *zio);
extern void zio_execute(zio_t *zio);

extern zio_t *zio_vdev_child_io(zio_t *zio, blkptr_t *bp, vdev_t *vd,
    uint64_t offset, struct abd *data, uint64_t size, int type,
    enum zio_flag flags, zio_done_func_t *done, void *private);

extern void zio_vdev_io_redone(zio_t *zio);

extern void zio_checksum_verified(zio_t *zio);
extern int zio_worst_error(int e1, int e2);

/*
 * Checksum ereport functions
 */
extern void zfs_ereport_start_checksum(spa_t *spa, vdev_t *vd,
    struct zio *zio, uint64_t offset,
    uint64_t length, void *arg, struct zio_bad_cksum *info);
extern void zfs_ereport_finish_checksum(zio_cksum_report_t *report,
    const abd_t *good_data, const abd_t *bad_data, boolean_t drop_if_identical);

/* If we have the good data in hand, this function can be used */
extern int zfs_ereport_post_checksum(spa_t *spa, vdev_t *vd,
    struct zio *zio, uint64_t offset,
    uint64_t length, const abd_t *good_data, const abd_t *bad_data,
    struct zio_bad_cksum *info);

#ifdef  __cplusplus
}
#endif

#endif	/* _ZIO_H */
