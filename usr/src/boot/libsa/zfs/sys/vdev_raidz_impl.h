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
 * Copyright (C) 2016 Gvozden Nešković. All rights reserved.
 */

#ifndef _VDEV_RAIDZ_H
#define	_VDEV_RAIDZ_H

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/abd.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct raidz_col {
	uint64_t rc_devidx;		/* child device index for I/O */
	uint64_t rc_offset;		/* device offset */
	uint64_t rc_size;		/* I/O size */
	abd_t *rc_abd;			/* I/O data */
	void *rc_gdata;			/* XXX used to store the "good" version */
	int rc_error;			/* I/O error for this device */
	uint8_t rc_tried:1;		/* Did we attempt this I/O column? */
	uint8_t rc_skipped:1;		/* Did we skip this I/O column? */
} raidz_col_t;

typedef struct raidz_map {
	uint64_t rm_cols;		/* Regular column count */
	uint64_t rm_scols;		/* Count including skipped columns */
	uint64_t rm_bigcols;		/* Number of oversized columns */
	uint64_t rm_asize;		/* Actual total I/O size */
	uint64_t rm_missingdata;	/* Count of missing data devices */
	uint64_t rm_missingparity;	/* Count of missing parity devices */
	uint64_t rm_firstdatacol;	/* First data column/parity count */
	uint64_t rm_nskip;		/* Skipped sectors for padding */
	uint64_t rm_skipstart;		/* Column index of padding start */
	void *rm_abd_copy;		/* XXX rm_asize-buffer of copied data */
	uintptr_t rm_reports;		/* # of referencing checksum reports */
	uint8_t	rm_freed;		/* map no longer has referencing ZIO */
	uint8_t	rm_ecksuminjected;	/* checksum error was injected */
	raidz_col_t rm_col[];		/* Flexible array of I/O columns */
} raidz_map_t;

/* Powers of 2 in the Galois field. */
extern const uint8_t vdev_raidz_pow2[256] __attribute__((aligned(256)));
/* Logs of 2 in the Galois field defined above. */
extern const uint8_t vdev_raidz_log2[256] __attribute__((aligned(256)));

/*
 * Multiply a given number by 2 raised to the given power.
 */
static inline uint8_t
vdev_raidz_exp2(const uint8_t a, const unsigned exp)
{
	if (a == 0)
		return (0);

	return (vdev_raidz_pow2[(exp + (unsigned) vdev_raidz_log2[a]) % 255]);
}

#ifdef  __cplusplus
}
#endif

#endif	/* _VDEV_RAIDZ_H */
