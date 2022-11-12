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
 * C3.6.2 AdvSIMD TBL/TBX
 */
.macro simd_tbl op
	\op	v0.8b, {v1.16b}, v2.8b
	\op	v3.16b, {v4.16b, v5.16b}, v6.16b
	\op	v7.8b, {v8.16b, v9.16b, v10.16b}, v11.8b
	\op	v12.16b, {v28.16b-v31.16b}, v13.16b
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	simd_tbl tbl
	simd_tbl tbx
.size libdis_test, [.-libdis_test]
