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
 * C3.2.3 Exception generation
 */
.macro exception op, immopt=0
	.if \immopt
	\op
	.else
	\op #0
	.endif
	\op #65535
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	exception svc
	exception hvc
	exception smc
	exception brk
	exception hlt
	exception dcps1 1
	exception dcps2 1
	exception dcps3 1
.size libdis_test, [.-libdis_test]
