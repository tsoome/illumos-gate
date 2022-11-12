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
 * C3.5.8 Data-processing (2 source)
 */
.macro dproc op
	\op	w0,  w15, w30
	\op	x0,  x15, x30
	\op	wzr, wzr, wzr
	\op	xzr, xzr, xzr
.endm
.macro dproc_crc op xreg=0
.if \xreg
	\op	w0,  w15, x30
	\op	wzr, wzr, xzr
.else
	\op	w0,  w15, w30
	\op	wzr, wzr, wzr
.endif
.endm

.text
.arch armv8-a+crc
.globl libdis_test
.type libdis_test, @function
libdis_test:
	/*
	 * C5.6.214 UDIV
	 */
	dproc udiv
	/*
	 * C5.6.160 SDIV
	 */
	dproc sdiv
	/*
	 * C5.6.115 LSLV
	 * C5.6.113 LSL (register) (alias)
	 */
	dproc lslv
	/*
	 * C5.6.118 LSRV
	 * C5.6.116 LSR (register) (alias)
	 */
	dproc lsrv
	/*
	 * C5.6.17 ASRV
	 * C5.6.15 ASR (register) (alias)
	 */
	dproc asrv
	/*
	 * C5.6.154 RORV
	 * C5.6.153 ROR (register) (alias)
	 */
	dproc rorv
	/*
	 * C5.6.48 CRC32B, CRC32H, CRC32W, CRC32X
	 */
	dproc_crc crc32b
	dproc_crc crc32h
	dproc_crc crc32w
	dproc_crc crc32x 1
	/*
	 * C5.6.49 CRC32CB, CRC32CH, CRC32CW, CRC32CX
	 */
	dproc_crc crc32cb
	dproc_crc crc32ch
	dproc_crc crc32cw
	dproc_crc crc32cx 1
.size libdis_test, [.-libdis_test]
