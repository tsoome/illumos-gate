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
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_PRIVREGS_H
#define	_SYS_PRIVREGS_H

#include <sys/controlregs.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This file describes the cpu's privileged register set, and
 * how the machine state is saved on the stack when a trap occurs.
 */

/*
 * XXXARM: This should be in genassym.cf, but then this header needs the
 * assym.h, and I'm not sure what to do about that right now.
 */
#define	REGOFF_X0	(0*8)
#define	REGOFF_X1	(1*8)
#define	REGOFF_X2	(2*8)
#define	REGOFF_X3	(3*8)
#define	REGOFF_X4	(4*8)
#define	REGOFF_X5	(5*8)
#define	REGOFF_X6	(6*8)
#define	REGOFF_X7	(7*8)
#define	REGOFF_X8	(8*8)
#define	REGOFF_X9	(9*8)
#define	REGOFF_X10	(10*8)
#define	REGOFF_X11	(11*8)
#define	REGOFF_X12	(12*8)
#define	REGOFF_X13	(13*8)
#define	REGOFF_X14	(14*8)
#define	REGOFF_X15	(15*8)
#define	REGOFF_X16	(16*8)
#define	REGOFF_X17	(17*8)
#define	REGOFF_X18	(18*8)
#define	REGOFF_X19	(19*8)
#define	REGOFF_X20	(20*8)
#define	REGOFF_X21	(21*8)
#define	REGOFF_X22	(22*8)
#define	REGOFF_X23	(23*8)
#define	REGOFF_X24	(24*8)
#define	REGOFF_X25	(25*8)
#define	REGOFF_X26	(26*8)
#define	REGOFF_X27	(27*8)
#define	REGOFF_X28	(28*8)
#define	REGOFF_X29	(29*8)
#define	REGOFF_X30	(30*8)
#define	REGOFF_SP	(31*8)
#define	REGOFF_PC	(32*8)
#define	REGOFF_SPSR	(33*8)
#define	REG_FRAME	(34*8)

#ifndef _ASM

/*
 * This is NOT the structure to use for general purpose debugging;
 * see /proc for that.  This is NOT the structure to use to decode
 * the ucontext or grovel about in a core file; see <sys/regset.h>.
 */

struct regs {
	greg_t	r_x0;
	greg_t	r_x1;
	greg_t	r_x2;
	greg_t	r_x3;
	greg_t	r_x4;
	greg_t	r_x5;
	greg_t	r_x6;
	greg_t	r_x7;
	greg_t	r_x8;
	greg_t	r_x9;
	greg_t	r_x10;
	greg_t	r_x11;
	greg_t	r_x12;
	greg_t	r_x13;
	greg_t	r_x14;
	greg_t	r_x15;
	greg_t	r_x16;
	greg_t	r_x17;
	greg_t	r_x18;
	greg_t	r_x19;
	greg_t	r_x20;
	greg_t	r_x21;
	greg_t	r_x22;
	greg_t	r_x23;
	greg_t	r_x24;
	greg_t	r_x25;
	greg_t	r_x26;
	greg_t	r_x27;
	greg_t	r_x28;
#define	r_fp	r_x29
	greg_t	r_x29;
#define	r_lr	r_x30
	greg_t	r_x30;
	greg_t	r_sp;
	greg_t	r_pc;
	greg_t	r_spsr;
};

#ifdef _KERNEL
#define	lwptoregs(lwp)	((struct regs *)((lwp)->lwp_regs))
#define	USERMODE(spsr)	(((spsr) & PSR_M_MASK) == PSR_M_EL0t)

#endif /* _KERNEL */

#else	/* !_ASM */

#if defined(_MACHDEP)

#define	__SAVE_REGS				\
	sub	sp, sp, #REG_FRAME;		\
	stp	x0, x1, [sp, #REGOFF_X0];	\
	stp	x2, x3, [sp, #REGOFF_X2];	\
	stp	x4, x5, [sp, #REGOFF_X4];	\
	stp	x6, x7, [sp, #REGOFF_X6];	\
	stp	x8, x9, [sp, #REGOFF_X8];	\
	stp	x10, x11, [sp, #REGOFF_X10];	\
	stp	x12, x13, [sp, #REGOFF_X12];	\
	stp	x14, x15, [sp, #REGOFF_X14];	\
	stp	x16, x17, [sp, #REGOFF_X16];	\
	stp	x18, x19, [sp, #REGOFF_X18];	\
	stp	x20, x21, [sp, #REGOFF_X20];	\
	stp	x22, x23, [sp, #REGOFF_X22];	\
	stp	x24, x25, [sp, #REGOFF_X24];	\
	stp	x26, x27, [sp, #REGOFF_X26];	\
	stp	x28, x29, [sp, #REGOFF_X28];	\
	mrs	x16, sp_el0;			\
	stp	x30, x16, [sp, #REGOFF_X30];	\
	mrs	x17, elr_el1;			\
	mrs	x18, spsr_el1;			\
	stp	x17, x18, [sp, #REGOFF_PC]

#define	__RESTORE_REGS			\
	ldp	x17, x18, [sp, #REGOFF_PC];	\
	msr	elr_el1, x17;			\
	msr	spsr_el1, x18;			\
	ldp	x30, x16, [sp, #REGOFF_X30];	\
	msr	sp_el0, x16;			\
	ldp	x0, x1, [sp, #REGOFF_X0];	\
	ldp	x2, x3, [sp, #REGOFF_X2];	\
	ldp	x4, x5, [sp, #REGOFF_X4];	\
	ldp	x6, x7, [sp, #REGOFF_X6];	\
	ldp	x8, x9, [sp, #REGOFF_X8];	\
	ldp	x10, x11, [sp, #REGOFF_X10];	\
	ldp	x12, x13, [sp, #REGOFF_X12];	\
	ldp	x14, x15, [sp, #REGOFF_X14];	\
	ldp	x16, x17, [sp, #REGOFF_X16];	\
	ldp	x18, x19, [sp, #REGOFF_X18];	\
	ldp	x20, x21, [sp, #REGOFF_X20];	\
	ldp	x22, x23, [sp, #REGOFF_X22];	\
	ldp	x24, x25, [sp, #REGOFF_X24];	\
	ldp	x26, x27, [sp, #REGOFF_X26];	\
	ldp	x28, x29, [sp, #REGOFF_X28];	\
	add	sp, sp, #REG_FRAME

#define	__SAVE_SVC_REGS				\
	sub	sp, sp, #REG_FRAME;		\
	stp	x0, x1, [sp, #REGOFF_X0];	\
	stp	x2, x3, [sp, #REGOFF_X2];	\
	stp	x4, x5, [sp, #REGOFF_X4];	\
	stp	x6, x7, [sp, #REGOFF_X6];	\
	stp	x20, x21, [sp, #REGOFF_X20];	\
	mrs	x0, sp_el0;			\
	stp	x30, x0, [sp, #REGOFF_X30];	\
	mrs	x1, elr_el1;			\
	mrs	x2, spsr_el1;			\
	stp	x1, x2, [sp, #REGOFF_PC]

#define	__SAVE_EXC_REGS			\
	stp	x8, x9, [sp, #REGOFF_X8];	\
	stp	x10, x11, [sp, #REGOFF_X10];	\
	stp	x12, x13, [sp, #REGOFF_X12];	\
	stp	x14, x15, [sp, #REGOFF_X14];	\
	stp	x16, x17, [sp, #REGOFF_X16];	\
	stp	x18, x19, [sp, #REGOFF_X18];	\
	stp	x22, x23, [sp, #REGOFF_X22];	\
	stp	x24, x25, [sp, #REGOFF_X24];	\
	stp	x26, x27, [sp, #REGOFF_X26];	\
	stp	x28, x29, [sp, #REGOFF_X28]

#endif	/* _MACHDEP */

/*
 * Used to set rflags to known values at the head of an
 * interrupt gate handler, i.e. interrupts are -already- disabled.
 */
#define	INTGATE_INIT_KERNEL_FLAGS

#endif	/* !_ASM */

#include <sys/controlregs.h>

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_PRIVREGS_H */
