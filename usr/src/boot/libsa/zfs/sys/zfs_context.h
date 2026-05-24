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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 * Copyright 2019 Joyent, Inc.
 */

#ifndef _SYS_ZFS_CONTEXT_H
#define	_SYS_ZFS_CONTEXT_H

#ifdef  __cplusplus
extern "C" {
#endif

#include <stand.h>
#include <sys/note.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/debug.h>
#include <sys/list.h>
#include <sys/stdint.h>
#include <sys/stddef.h>
#include <string.h>

#ifdef  __cplusplus
}
#endif

#define	KM_SLEEP	0x0000	/* can block for memory; success guaranteed */
#define	KM_NOSLEEP	0x0001	/* cannot block for memory; may fail */

#define	_zfs_expect(expr, value)	(__builtin_expect((expr), (value)))

#define	likely(x)	_zfs_expect((x) != 0, 1)
#define	unlikely(x)	_zfs_expect((x) != 0, 0)

#define	TREE_ISIGN(a)	(((a) > 0) - ((a) < 0))
#define	TREE_CMP(a, b)	(((a) > (b)) - ((a) < (b)))
#define	TREE_PCMP(a, b)	\
	(((uintptr_t)(a) > (uintptr_t)(b)) - ((uintptr_t)(a) < (uintptr_t)(b)))

#endif	/* _SYS_ZFS_CONTEXT_H */
