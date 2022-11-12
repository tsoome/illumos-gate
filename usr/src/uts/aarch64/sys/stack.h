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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2017 Hayashi Naoyuki
 */

#ifndef _SYS_STACK_H
#define	_SYS_STACK_H


#if !defined(_ASM)

#include <sys/types.h>

#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Stack alignment macros.
 */

#define	STACK_ALIGN32		8
#define	STACK_ENTRY_ALIGN32	8
#define	STACK_BIAS32		0
#define	SA32(x)			(((x)+(STACK_ALIGN32-1)) & ~(STACK_ALIGN32-1))
#define	MINFRAME32		0
#define	STACK_RESERVE32		0

#define	STACK_ALIGN64		16
#define	STACK_ENTRY_ALIGN64 	16
#define	STACK_BIAS64		0
#define	SA64(x)			(((x)+(STACK_ALIGN64-1)) & ~(STACK_ALIGN64-1))
#define	MINFRAME64		0
#define	STACK_RESERVE64		0

#define	STACK_ALIGN		STACK_ALIGN64
#define	STACK_ENTRY_ALIGN	STACK_ENTRY_ALIGN64
#define	STACK_BIAS		STACK_BIAS64
#define	SA(x)			SA64(x)
#define	MINFRAME		MINFRAME64
#define	STACK_RESERVE		STACK_RESERVE64

#if defined(_KERNEL) && !defined(_ASM)

#if defined(DEBUG)
#define	ASSERT_STACK_ALIGNED()						\
	{								\
		unsigned long sp;					\
		__asm("mov %0, sp": "=r" (sp));			\
		ASSERT((sp & (STACK_ALIGN - 1)) == 0);			\
	}
#else	/* DEBUG */
#define	ASSERT_STACK_ALIGNED()
#endif	/* DEBUG */

struct regs;

void traceregs(struct regs *);
void traceback(caddr_t);

#endif /* defined(_KERNEL) && !defined(_ASM) */

#define	STACK_GROWTH_DOWN /* stacks grow from high to low addresses */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_STACK_H */
