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
 * Copyright (c) 2011, 2019 by Delphix. All rights reserved.
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2014 Spectra Logic Corporation, All rights reserved.
 * Copyright 2013 Saso Kiselkov. All rights reserved.
 * Copyright (c) 2014 Integros [integros.com]
 * Copyright 2019 Joyent, Inc.
 * Copyright (c) 2017, 2019, Datto Inc. All rights reserved.
 * Copyright (c) 2017, Intel Corporation.
 * Copyright 2020 Joshua M. Clulow <josh@sysmgr.org>
 */

#ifndef _SYS_SPA_H
#define	_SYS_SPA_H

#include <sys/zfs_context.h>
#include <sys/nvpair.h>
#include <sys/sysmacros.h>
#include <sys/spa_checksum.h>
#include <sys/dmu.h>
#include <sys/bitops.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * Forward references that lots of things need.
 */
typedef struct spa spa_t;
typedef struct vdev vdev_t;
typedef struct zio zio_t;

#define	SPA_MINBLOCKSHIFT	9
#define	SPA_OLDMAXBLOCKSHIFT	17
#define	SPA_MAXBLOCKSHIFT	24
#define	SPA_MINBLOCKSIZE	(1ULL << SPA_MINBLOCKSHIFT)
#define	SPA_OLDMAXBLOCKSIZE	(1ULL << SPA_OLDMAXBLOCKSHIFT)
#define	SPA_MAXBLOCKSIZE	(1ULL << SPA_MAXBLOCKSHIFT)

#define	ASHIFT_MIN		9
#define	ASHIFT_MAX		16

/*
 * The DVA size encodings for LSIZE and PSIZE support blocks up to 32MB.
 * The ASIZE encoding should be at least 64 times larger (6 more bits)
 * to support up to 4-way RAID-Z mirror mode with worst-case gang block
 * overhead, three DVAs per bp, plus one more bit in case we do anything
 * else that expands the ASIZE.
 */
#define	SPA_LSIZEBITS		16	/* LSIZE up to 32M (2^16 * 512)	*/
#define	SPA_PSIZEBITS		16	/* PSIZE up to 32M (2^16 * 512)	*/
#define	SPA_ASIZEBITS		24	/* ASIZE up to 64 times larger	*/

/*
 * All SPA data is represented by 128-bit data virtual addresses (DVAs).
 * The members of the dva_t should be considered opaque outside the SPA.
 */
typedef struct dva {
	uint64_t	dva_word[2];
} dva_t;

/*
 * Some checksums/hashes need a 256-bit initialization salt. This salt is kept
 * secret and is suitable for use in MAC algorithms as the key.
 */
typedef struct zio_cksum_salt {
	uint8_t		zcs_bytes[32];
} zio_cksum_salt_t;

/*
 * Each block is described by its DVAs, time of birth, checksum, etc.
 * The word-by-word, bit-by-bit layout of the blkptr is as follows:
 *
 *	64	56	48	40	32	24	16	8	0
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * 0	|		vdev1		| GRID  |	  ASIZE		|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * 1	|G|			 offset1				|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * 2	|		vdev2		| GRID  |	  ASIZE		|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * 3	|G|			 offset2				|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * 4	|		vdev3		| GRID  |	  ASIZE		|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * 5	|G|			 offset3				|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * 6	|BDX|lvl| type	| cksum |E| comp|    PSIZE	|     LSIZE	|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * 7	|			padding					|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * 8	|			padding					|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * 9	|			physical birth txg			|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * a	|			logical birth txg			|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * b	|			fill count				|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * c	|			checksum[0]				|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * d	|			checksum[1]				|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * e	|			checksum[2]				|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * f	|			checksum[3]				|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 *
 * Legend:
 *
 * vdev		virtual device ID
 * offset	offset into virtual device
 * LSIZE	logical size
 * PSIZE	physical size (after compression)
 * ASIZE	allocated size (including RAID-Z parity and gang block headers)
 * GRID		RAID-Z layout information (reserved for future use)
 * cksum	checksum function
 * comp		compression function
 * G		gang block indicator
 * B		byteorder (endianness)
 * D		dedup
 * X		encryption (on version 30, which is not supported)
 * E		blkptr_t contains embedded data (see below)
 * lvl		level of indirection
 * type		DMU object type
 * phys birth	txg of block allocation; zero if same as logical birth txg
 * log. birth	transaction group in which the block was logically born
 * fill count	number of non-zero blocks under this bp
 * checksum[4]	256-bit checksum of the data this bp describes
 */

/*
 * "Embedded" blkptr_t's don't actually point to a block, instead they
 * have a data payload embedded in the blkptr_t itself.  See the comment
 * in blkptr.c for more details.
 *
 * The blkptr_t is laid out as follows:
 *
 *	64	56	48	40	32	24	16	8	0
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * 0	|      payload                                                  |
 * 1	|      payload                                                  |
 * 2	|      payload                                                  |
 * 3	|      payload                                                  |
 * 4	|      payload                                                  |
 * 5	|      payload                                                  |
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * 6	|BDX|lvl| type	| etype |E| comp| PSIZE|              LSIZE	|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * 7	|      payload                                                  |
 * 8	|      payload                                                  |
 * 9	|      payload                                                  |
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * a	|			logical birth txg			|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * b	|      payload                                                  |
 * c	|      payload                                                  |
 * d	|      payload                                                  |
 * e	|      payload                                                  |
 * f	|      payload                                                  |
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 *
 * Legend:
 *
 * payload		contains the embedded data
 * B (byteorder)	byteorder (endianness)
 * D (dedup)		padding (set to zero)
 * X			encryption (set to zero; see above)
 * E (embedded)		set to one
 * lvl			indirection level
 * type			DMU object type
 * etype		how to interpret embedded data (BP_EMBEDDED_TYPE_*)
 * comp			compression function of payload
 * PSIZE		size of payload after compression, in bytes
 * LSIZE		logical size of payload, in bytes
 *			note that 25 bits is enough to store the largest
 *			"normal" BP's LSIZE (2^16 * 2^9) in bytes
 * log. birth		transaction group in which the block was logically born
 *
 * Note that LSIZE and PSIZE are stored in bytes, whereas for non-embedded
 * bp's they are stored in units of SPA_MINBLOCKSHIFT.
 * Generally, the generic BP_GET_*() macros can be used on embedded BP's.
 * The B, D, X, lvl, type, and comp fields are stored the same as with normal
 * BP's so the BP_SET_* macros can be used with them.  etype, PSIZE, LSIZE must
 * be set with the BPE_SET_* macros.  BP_SET_EMBEDDED() should be called before
 * other macros, as they assert that they are only used on BP's of the correct
 * "embedded-ness".
 */

#define	BPE_GET_ETYPE(bp)	\
	(ASSERT(BP_IS_EMBEDDED(bp)), \
	BF64_GET((bp)->blk_prop, 40, 8))
#define	BPE_SET_ETYPE(bp, t)	do { \
	ASSERT(BP_IS_EMBEDDED(bp)); \
	BF64_SET((bp)->blk_prop, 40, 8, t); \
_NOTE(CONSTCOND) } while (0)

#define	BPE_GET_LSIZE(bp)	\
	(ASSERT(BP_IS_EMBEDDED(bp)), \
	BF64_GET_SB((bp)->blk_prop, 0, 25, 0, 1))
#define	BPE_SET_LSIZE(bp, x)	do { \
	ASSERT(BP_IS_EMBEDDED(bp)); \
	BF64_SET_SB((bp)->blk_prop, 0, 25, 0, 1, x); \
_NOTE(CONSTCOND) } while (0)

#define	BPE_GET_PSIZE(bp)	\
	(ASSERT(BP_IS_EMBEDDED(bp)), \
	BF64_GET_SB((bp)->blk_prop, 25, 7, 0, 1))
#define	BPE_SET_PSIZE(bp, x)	do { \
	ASSERT(BP_IS_EMBEDDED(bp)); \
	BF64_SET_SB((bp)->blk_prop, 25, 7, 0, 1, x); \
_NOTE(CONSTCOND) } while (0)

typedef enum bp_embedded_type {
	BP_EMBEDDED_TYPE_DATA,
	BP_EMBEDDED_TYPE_RESERVED, /* Reserved for an unintegrated feature. */
	NUM_BP_EMBEDDED_TYPES = BP_EMBEDDED_TYPE_RESERVED
} bp_embedded_type_t;

#define	BPE_NUM_WORDS 14
#define	BPE_PAYLOAD_SIZE (BPE_NUM_WORDS * sizeof (uint64_t))
#define	BPE_IS_PAYLOADWORD(bp, wp) \
	((wp) != &(bp)->blk_prop && (wp) != &(bp)->blk_birth)

#define	SPA_BLKPTRSHIFT	7		/* blkptr_t is 128 bytes	*/
#define	SPA_DVAS_PER_BP	3		/* Number of DVAs in a bp	*/

typedef struct blkptr {
	dva_t		blk_dva[SPA_DVAS_PER_BP]; /* Data Virtual Addresses */
	uint64_t	blk_prop;	/* size, compression, type, etc	    */
	uint64_t	blk_pad[2];	/* Extra space for the future	    */
	uint64_t	blk_phys_birth;	/* txg when block was allocated	    */
	uint64_t	blk_birth;	/* transaction group at birth	    */
	uint64_t	blk_fill;	/* fill count			    */
	zio_cksum_t	blk_cksum;	/* 256-bit checksum		    */
} blkptr_t;

/*
 * Macros to get and set fields in a bp or DVA.
 */
#define	DVA_GET_ASIZE(dva)	\
	BF64_GET_SB((dva)->dva_word[0], 0, SPA_ASIZEBITS, SPA_MINBLOCKSHIFT, 0)
#define	DVA_SET_ASIZE(dva, x)	\
	BF64_SET_SB((dva)->dva_word[0], 0, SPA_ASIZEBITS, \
	SPA_MINBLOCKSHIFT, 0, x)

#define	DVA_GET_GRID(dva)	BF64_GET((dva)->dva_word[0], 24, 8)
#define	DVA_SET_GRID(dva, x)	BF64_SET((dva)->dva_word[0], 24, 8, x)

#define	DVA_GET_VDEV(dva)	BF64_GET((dva)->dva_word[0], 32, 32)
#define	DVA_SET_VDEV(dva, x)	BF64_SET((dva)->dva_word[0], 32, 32, x)

#define	DVA_GET_OFFSET(dva)	\
	BF64_GET_SB((dva)->dva_word[1], 0, 63, SPA_MINBLOCKSHIFT, 0)
#define	DVA_SET_OFFSET(dva, x)	\
	BF64_SET_SB((dva)->dva_word[1], 0, 63, SPA_MINBLOCKSHIFT, 0, x)

#define	DVA_GET_GANG(dva)	BF64_GET((dva)->dva_word[1], 63, 1)
#define	DVA_SET_GANG(dva, x)	BF64_SET((dva)->dva_word[1], 63, 1, x)

#define	BP_GET_LSIZE(bp)	\
	(BP_IS_EMBEDDED(bp) ?	\
	(BPE_GET_ETYPE(bp) == BP_EMBEDDED_TYPE_DATA ? BPE_GET_LSIZE(bp) : 0): \
	BF64_GET_SB((bp)->blk_prop, 0, SPA_LSIZEBITS, SPA_MINBLOCKSHIFT, 1))
#define	BP_SET_LSIZE(bp, x)	do { \
	ASSERT(!BP_IS_EMBEDDED(bp)); \
	BF64_SET_SB((bp)->blk_prop, \
	    0, SPA_LSIZEBITS, SPA_MINBLOCKSHIFT, 1, x); \
_NOTE(CONSTCOND) } while (0)

#define	BP_GET_PSIZE(bp)	\
	BF64_GET_SB((bp)->blk_prop, 16, SPA_LSIZEBITS, SPA_MINBLOCKSHIFT, 1)
#define	BP_SET_PSIZE(bp, x)	\
	BF64_SET_SB((bp)->blk_prop, 16, SPA_LSIZEBITS, SPA_MINBLOCKSHIFT, 1, x)

#define	BP_GET_COMPRESS(bp)	BF64_GET((bp)->blk_prop, 32, 7)
#define	BP_SET_COMPRESS(bp, x)	BF64_SET((bp)->blk_prop, 32, 7, x)

#define	BP_GET_CHECKSUM(bp)	BF64_GET((bp)->blk_prop, 40, 8)
#define	BP_SET_CHECKSUM(bp, x)	BF64_SET((bp)->blk_prop, 40, 8, x)

#define	BP_GET_TYPE(bp)		BF64_GET((bp)->blk_prop, 48, 8)
#define	BP_SET_TYPE(bp, x)	BF64_SET((bp)->blk_prop, 48, 8, x)

#define	BP_GET_LEVEL(bp)	BF64_GET((bp)->blk_prop, 56, 5)
#define	BP_SET_LEVEL(bp, x)	BF64_SET((bp)->blk_prop, 56, 5, x)

#define	BP_IS_EMBEDDED(bp)	BF64_GET((bp)->blk_prop, 39, 1)

#define	BP_GET_DEDUP(bp)	BF64_GET((bp)->blk_prop, 62, 1)
#define	BP_SET_DEDUP(bp, x)	BF64_SET((bp)->blk_prop, 62, 1, x)

#define	BP_GET_BYTEORDER(bp)	BF64_GET((bp)->blk_prop, 63, 1)
#define	BP_SET_BYTEORDER(bp, x)	BF64_SET((bp)->blk_prop, 63, 1, x)

#define	BP_PHYSICAL_BIRTH(bp)		\
	((bp)->blk_phys_birth ? (bp)->blk_phys_birth : (bp)->blk_birth)

#define	BP_GET_ASIZE(bp)	\
	(DVA_GET_ASIZE(&(bp)->blk_dva[0]) + DVA_GET_ASIZE(&(bp)->blk_dva[1]) + \
		DVA_GET_ASIZE(&(bp)->blk_dva[2]))

#define	BP_GET_UCSIZE(bp) \
	((BP_GET_LEVEL(bp) > 0 || dmu_ot[BP_GET_TYPE(bp)].ot_metadata) ? \
	BP_GET_PSIZE(bp) : BP_GET_LSIZE(bp));

#define	BP_GET_NDVAS(bp)	\
	(!!DVA_GET_ASIZE(&(bp)->blk_dva[0]) + \
	!!DVA_GET_ASIZE(&(bp)->blk_dva[1]) + \
	!!DVA_GET_ASIZE(&(bp)->blk_dva[2]))

#define	DVA_EQUAL(dva1, dva2)	\
	((dva1)->dva_word[1] == (dva2)->dva_word[1] && \
	(dva1)->dva_word[0] == (dva2)->dva_word[0])

#define	DVA_IS_VALID(dva)	(DVA_GET_ASIZE(dva) != 0)

#define	BP_IDENTITY(bp)		(&(bp)->blk_dva[0])
#define	BP_IS_GANG(bp)		DVA_GET_GANG(BP_IDENTITY(bp))
#define	DVA_IS_EMPTY(dva)	((dva)->dva_word[0] == 0ULL &&  \
	(dva)->dva_word[1] == 0ULL)
#define	BP_IS_HOLE(bp)		DVA_IS_EMPTY(BP_IDENTITY(bp))
#define	BP_IS_OLDER(bp, txg)	(!BP_IS_HOLE(bp) && (bp)->blk_birth < (txg))

#define	BP_ZERO(bp)				\
{						\
	(bp)->blk_dva[0].dva_word[0] = 0;	\
	(bp)->blk_dva[0].dva_word[1] = 0;	\
	(bp)->blk_dva[1].dva_word[0] = 0;	\
	(bp)->blk_dva[1].dva_word[1] = 0;	\
	(bp)->blk_dva[2].dva_word[0] = 0;	\
	(bp)->blk_dva[2].dva_word[1] = 0;	\
	(bp)->blk_prop = 0;			\
	(bp)->blk_pad[0] = 0;			\
	(bp)->blk_pad[1] = 0;			\
	(bp)->blk_phys_birth = 0;		\
	(bp)->blk_birth = 0;			\
	(bp)->blk_fill = 0;			\
	ZIO_SET_CHECKSUM(&(bp)->blk_cksum, 0, 0, 0, 0);	\
}

#if BYTE_ORDER == _BIG_ENDIAN
#define	ZFS_HOST_BYTEORDER	(0ULL)
#else
#define	ZFS_HOST_BYTEORDER	(1ULL)
#endif

#define	BP_SHOULD_BYTESWAP(bp)	(BP_GET_BYTEORDER(bp) != ZFS_HOST_BYTEORDER)

#ifdef  __cplusplus
}
#endif

#endif	/* _SYS_SPA_H */
