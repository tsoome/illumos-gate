/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2017 Hayashi Naoyuki
 */

#ifndef	_ASM_CPU_H
#define	_ASM_CPU_H

#if !defined(_ASM)
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* XXXARM: These need implementing correctly */

/*
 * prefetch
 */
static __inline__ void
prefetch_read_many(void *addr)
{
}

static __inline__ void
prefetch_read_once(void *addr)
{
}

static __inline__ void
prefetch_write_many(void *addr)
{
}

static __inline__ void
prefetch_write_once(void *addr)
{
}

#ifdef	__cplusplus
}
#endif

#endif	/* !_ASM */

#endif	/* _ASM_CPU_H */
