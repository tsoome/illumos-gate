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
 * C3.2 Branches
 */
.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
1:
	cbz	w0, 1b
	cbz	xzr, 2f
	cbnz	wzr, 1b
	cbnz	x30, 3f
2:
	b.eq	2b
	b.ne	3f
	b.cs	2b
	b.cc	3f
	b.mi	2b
	b.pl	3f
	b.vs	2b
	b.vc	3f
	b.hi	1b
	b.ls	4f
	b.ge	1b
	b.lt	4f
	b.gt	1b
	b.le	4f
	b.al	1b
3:
	tbz	w0, #0, 2b
	tbz	xzr, #63, 3b
	tbnz	wzr, #0, 1b
	tbnz	x30, #63, 4f
4:
	b	3b
	bl	4b
5:
	br	x0
	blr	x30
	ret
	ret	x0
	eret
	drps
.size libdis_test, [.-libdis_test]
