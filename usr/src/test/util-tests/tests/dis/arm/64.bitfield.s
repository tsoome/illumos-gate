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
 * C3.4.2 Bitfield
 */
.macro bitfield op
	/* Test for SBFM -> ASR/UBFM -> LSR (imms == 31/63) */
	\op	w0, wzr, #30, #31
	\op	x0, xzr, #31, #63
	/* Test for SBFM -> SBFIZ/BFM -> BFI (imms < immr) */
	\op	w0, wzr, #31, #0
	\op	x0, xzr, #63, #0
	/* Test for SBFM -> SXTB/UBFM -> UXTB (immr == 0 && imms == 7) */
	\op	w0, wzr, #0, #7
	\op	x0, xzr, #0, #7
	/* Test for SBFM -> SXTH/UBFM -> UXTH (immr == 0 && imms == 15) */
	\op	w0, wzr, #0, #15
	\op	x0, xzr, #0, #15
	/* Test for SBFM -> SXTW (immr == 0 && imms == 31) */
	\op	w0, wzr, #0, #31
	\op	x0, xzr, #0, #31
	/* Test for UBFM -> LSL (imms != 31/63 && immr == imms+1) */
	\op	w0, wzr, #31, #30
	\op	x0, xzr, #63, #62
	/* Test for SBFM -> SBFIZ (any operation not already matched above) */
	\op	w0, wzr, #30, #30
	\op	x0, xzr, #62, #62
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	/*
	 * C5.6.158 SBFM
	 * C5.6.16 ASR (immediate) (alias)
	 * C5.6.157 SBFIZ (alias)
	 * C5.6.159 SBFX (alias)
	 * C5.6.201 SXTB (alias)
	 * C5.6.202 SXTH (alias)
	 * C5.6.203 SXTW (alias)
	 */
	bitfield sbfm
	/*
	 * C5.6.22 BFM
	 * C5.6.21 BFI (alias)
	 * C5.6.23 BFXIL (alias)
	 */
	bitfield bfm
	/*
	 * C5.6.212 UBFM
	 * C5.6.114 LSL (immediate) (alias)
	 * C5.6.117 LSR (immediate) (alias)
	 * C5.6.211 UBFIZ (alias)
	 * C5.6.213 UBFX (alias)
	 * C5.6.220 UXTB (alias)
	 * C5.6.221 UXTH (alias)
	 */
	bitfield ubfm
.size libdis_test, [.-libdis_test]
