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
 * C3.6.3 AdvSIMD ZIP/UZP/TRN
 */
.macro simd_trn
	.irp op,uzp1,trn1,zip1,uzp2,trn2,zip2
	.irp arr,8b,16b,4h,8h,2s,4s,2d
	\op	v0.\arr, v15.\arr, v31.\arr
	.endr
	.endr
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	simd_trn
.size libdis_test, [.-libdis_test]
