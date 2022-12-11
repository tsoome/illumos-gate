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
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 */

/*
 * The assembled file must be linked in order to resolve the relocations for
 * a proper test. The following token enables that.
 * %DIS_TEST_LINK
 */

/*
 * C3.4.6 PC-rel. addressing
 */

.text

// Add some padding so that the instructions are not in page 0.
.pad:
	.space 0xc000

.globl libdis_test
.type libdis_test, @function
libdis_test:
	adr	x0, .lword
	adr	x1, .ldata
	adr	x2, .ldata + 0xffe

	adrp	x3, .lword
	add	x3, x3, :lo12:.lword

	adrp	x4, .ldata
	add	x4, x4, :lo12:.ldata

	adrp	x5, .ldata + 0xffe
	add	x5, x5, :lo12:.ldata + 0xffe

	adrp	x6, .sym
	add	x6, x6, :lo12:.sym

	adrp	x7, :got:.sym
	ldr	x7, [x7, :got_lo12:.sym]

.size libdis_test, [.-libdis_test]

// padding so that the data is not in the same page.
.space 0x17f6

.lword:	.word	0xdeadbeef
.ldata:	.xword	0x1122334455667788
	.space	0x1ffb

.global .sym
.sym:

