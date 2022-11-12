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
/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_TRAP_H
#define	_SYS_TRAP_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Trap type values
 */

#define T_UNKNOWN	0x00
#define T_FPEN		0x07
#define T_ILEXC		0x0E
#define T_SVC		0x15
#define T_IABT		0x20
#define T_IABT_EL1	0x21
#define T_PC_ALIGN	0x22
#define T_DABT		0x24
#define T_DABT_EL1	0x25
#define T_SP_ALIGN	0x26
#define T_FPU		0x2C
#define T_SERR		0x2F

#define T_BREAKPOINT		0x30
#define T_BREAKPOINT_EL1	0x31
#define T_SOFTWARE_STEP		0x32
#define T_SOFTWARE_STEP_EL1	0x33
#define T_WATCHPOINT		0x34
#define T_WATCHPOINT_EL1	0x35
#define T_BRK			0x3C

/*
 * Pseudo traps.
 */
#define	T_INTERRUPT		0x100
#define	T_FAULT			0x200
#define	T_AST			0x400
#define	T_SYSCALL		0x180

/*
 *  Definitions for fast system call subfunctions
 */
/*
 *  Definitions for fast system call subfunctions
 */
#define	T_GETHRTIME	1	/* Get high resolution time		*/
#define	T_GETHRVTIME	2	/* Get high resolution virtual time	*/
#define	T_GETHRESTIME	3	/* Get high resolution time		*/
#define	T_GETLGRP	4	/* Get home lgrpid			*/

#define	T_LASTFAST	4	/* Last valid subfunction		*/

#define	T_DTRACE_PID	0xc000
#define	T_DTRACE_RET	0xc001

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TRAP_H */
