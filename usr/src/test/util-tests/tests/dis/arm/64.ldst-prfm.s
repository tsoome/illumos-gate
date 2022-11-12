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
 * C3.3.5  Load register (literal)
 * C3.3.10 Load/store register (register offset)
 * C3.3.12 Load/store register (unscaled immediate)
 * C3.3.13 Load/store register (unsigned immediate)
 *
 * Test just the PRFM/PRFUM instructions from these groups, with minimum
 * and maximum values for prfop, registers, immediates and shifts.
 */
.macro prf_lit op, from=0, to=31
1:
	.ifge \from-16
	\op	\from, 2f
	.else
	\op	\from, 1b
	.endif
	.if \to-\from
	prf_lit \op "(\from+1)" \to
	.endif
2:
.endm

.macro prf_reg op, from=0, to=31
	\op	\from, [x0, x0]
	\op	\from, [x0, w0,  uxtw]
	\op	\from, [sp, wzr, uxtw #3]
	\op	\from, [x0, x0,  lsl #0]
	\op	\from, [sp, xzr, lsl #3]
	\op	\from, [x0, w0,  sxtw #0]
	\op	\from, [sp, wzr, sxtw #3]
	\op	\from, [x0, x0,  sxtx]
	\op	\from, [sp, xzr, sxtx #3]
	.if \to-\from
	prf_reg \op "(\from+1)" \to
	.endif
.endm

.macro prf_imm op, min, max, step, from=0, to=31
	\op	\from, [x0]
	\op	\from, [sp,  #\min]
	\op	\from, [x30, #\max]
	\op	\from, [x1,  #(1*\step)]
	.iflt \min
	\op	\from, [x1,  #(-1*\step)]
	.endif
	.if \to-\from
	prf_imm \op, \min, \max, \step, "(\from+1)", \to
	.endif
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	prf_lit prfm
	prf_reg prfm
	prf_imm prfum, -256, 255, 1
	prf_imm prfm, 0, 32760, 8
.size libdis_test, [.-libdis_test]
