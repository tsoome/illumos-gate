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
 * C3.5.9 Data-processing (3 source)
 */
.macro dproc_1 op
	\op	w0,  w10, w20, w30
	\op	w0,  w10, w20, wzr
	\op	x0,  x10, x20, x30
	\op	x0,  x10, x20, xzr
.endm

.macro dproc_2 op
	\op	x0, w0, w30, x30
	\op	x0, w0, w30, xzr
.endm

.macro dproc_3 op
	\op	x0, x15, x30
	\op	x0, x15, xzr
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	/*
	 * C5.6.119 MADD <Rd>, <Rn>, <Rm>, <Ra>
	 * C5.6.133 MUL  <Rd>, <Rn>, <Rm>
	 */
	dproc_1 madd
	dproc_1 msub
	dproc_2 smaddl
	dproc_2 smsubl
	dproc_2 umaddl
	dproc_2 umsubl
	dproc_3 smulh
	dproc_3 umulh
.size libdis_test, [.-libdis_test]
