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
 * Copyright (c) 2012, 2017 by Delphix. All rights reserved.
 * Copyright (c) 2014 Integros [integros.com]
 */

/* Portions Copyright 2010 Robert Milkowski */

#ifndef _SYS_ZIL_H
#define	_SYS_ZIL_H

#include <sys/types.h>
#include <sys/spa.h>
#include <sys/zio.h>
#include <sys/dmu.h>
#include <sys/zio_crypt.h>

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct zil_chain {
	uint64_t zc_pad;
	blkptr_t zc_next_blk;	/* next block in chain */
	uint64_t zc_nused;	/* bytes in log block used */
	zio_eck_t zc_eck;	/* block trailer */
} zil_chain_t;

#define	ZIL_MIN_BLKSZ	4096ULL

#ifdef  __cplusplus
}
#endif

#endif	/* _SYS_ZIL_H */
