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
 * C3.6.1 AdvSIMD EXT
 */
.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	ext	v0.8b, v1.8b, v2.8b, #0
	ext	v0.8b, v1.8b, v2.8b, #7
	ext	v29.16b, v30.16b, v31.16b, #0
	ext	v29.16b, v30.16b, v31.16b, #7
	ext	v29.16b, v30.16b, v31.16b, #8
	ext	v29.16b, v30.16b, v31.16b, #15
.size libdis_test, [.-libdis_test]
