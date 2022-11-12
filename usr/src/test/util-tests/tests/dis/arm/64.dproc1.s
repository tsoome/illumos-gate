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
 * C3.5.7 Data-processing (1 source)
 */
.macro dproc op wreg=1
	/* Test 32-bit (except for rev32), 64-bit, and ZR */
.if \wreg
	\op	w0, w1
	\op	w30, wzr
.endif
	\op	x0, x1
	\op	x30, xzr
.endm
.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	/*
	 * C5.6.147 RBIT
	 */
	dproc rbit
	/*
	 * C5.6.150 REV16
	 */
	dproc rev16
	/*
	 * C5.6.149 REV
	 */
	dproc rev
	/*
	 * C5.6.151 REV32
	 */
	dproc rev32 0
	/*
	 * C5.6.40 CLZ
	 */
	dproc clz
	/*
	 * C5.6.39 CLS
	 */
	dproc cls
.size libdis_test, [.-libdis_test]
