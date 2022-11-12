/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2017 Joyent, Inc.
 */

/*
 * C3.2.4 System
 */

/*
 * For full testing this macro can be used to generate all possible combations
 * of SYS/SYSL instructions, but the resulting output file is 2MB so is not
 * enabled by default.
 */
.macro sysops_all
	.irp op1,0,1,2,3,4,5,6,7
	.irp crn,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	.irp crm,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	.irp op2,0,1,2,3,4,5,6,7
	sys	#\op1, C\crn, C\crm, #\op2, x21
	sys	#\op1, C\crn, C\crm, #\op2, xzr
	sysl	x21, #\op1, C\crn, C\crm, #\op2
	.endr
	.endr
	.endr
	.endr
.endm

.macro regop op1, crn, crm, op2
	/*
	 * XXX: gas won't let us use .irp here to iterate s0..s3 which is
	 * completely ridiculous (the variable does not get expanded), so
	 * we just have to do it the old fashioned way.
	 */
	msr	s2_\op1\()_c\crn\()_c\crm\()_\op2\(), x21
	mrs	xzr, s2_\op1\()_c\crn\()_c\crm\()_\op2\()
	msr	s3_\op1\()_c\crn\()_c\crm\()_\op2\(), x21
	mrs	xzr, s3_\op1\()_c\crn\()_c\crm\()_\op2\()
.endm

/*
 * For full testing this macro can be used to generate all possible combations
 * of SYS instructions, but the resulting output file is 2MB so is not enabled
 * by default.
 */
.macro regops_all
	.irp op1,0,1,2,3,4,5,6,7
	.irp crn,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	.irp crm,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	.irp op2,0,1,2,3,4,5,6,7
	regop \op1, \crn, \crm, \op2
	.endr
	.endr
	.endr
	.endr
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	/*
	 * Enable these for full testing.
	 */
	.ifdef SYSTEM_TEST_ALL
	sysops_all
	regops_all
	.endif
	/*
	 * C5.6.130 MSR (immediate)
	 */
	msr	spsel, #0
	msr	daifset, #7
	msr	daifclr, #15
	/*
	 * C5.6.68 HINT and its aliases.
	 */
	nop
	yield
	wfe
	wfi
	sev
	sevl
	hint	#6
	hint	#127
	/*
	 * C5.6.38 CLREX
	 */
	clrex	#0
	clrex	#15
	/*
	 * C5.6.62 DSB
	 * C5.6.60 DMB
	 * C5.6.72 ISB
	 */
	.irp imm,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	dsb	#\imm
	dmb	#\imm
	isb	#\imm
	.endr
	/*
	 * C5.6.204 SYS and its aliases.  Test the first and last valid
	 * operration for each.
	 */
	at	s1e1r,     x21
	at	s12e0w,    xzr
	dc	zva,       x21
	dc	cisw,      xzr
	ic	ialluis
	ic	ivau,      x21
	tlbi	ipas2e1is, x21
	tlbi	vaale1,    xzr
	/* SYS instructions which do not map to an alias. */
	sys	#0, C0, C0, #0, x21
	sys	#7, C15, C15, #7, xzr
	/*
	 * C5.6.131 MSR (register)
	 * C5.6.129 MRS
	 */
	regop	 0,  0,  0, 0	// midr_el1
	regop	 0,  0,  0, 1	// impl defn
	regop	 3, 14, 15, 7	// pmccfiltr_el0
	regop	 7, 15, 15, 7	// impl defn (last)
	/*
	 * C5.6.205 SYSL
	 */
	sysl	x21, #0, C0, C0, #0
.size libdis_test, [.-libdis_test]
