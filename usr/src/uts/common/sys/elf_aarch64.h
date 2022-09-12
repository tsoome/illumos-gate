/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 *	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
 *	  All Rights Reserved
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2017 Hayashi Naoyuki
 */

#pragma once

#ifdef	__cplusplus
extern "C" {
#endif

#define	ELF_AARCH64_MAXPGSZ	0x100000	/* maximum page size */

/* XXXARM: All the rest of the relocations */
#define R_AARCH64_NUM	1036

#define	R_AARCH64_NONE		0
#define	R_AARCH64_ABS64		257
#define	R_AARCH64_ABS32		258
#define	R_AARCH64_ABS16		259
#define	R_AARCH64_JUMP26	282
#define	R_AARCH64_CALL26	283
#define	R_AARCH64_COPY		1024
#define	R_AARCH64_GLOB_DAT	1025
#define	R_AARCH64_JUMP_SLOT	1026
#define	R_AARCH64_RELATIVE 	1027
#define	R_AARCH64_REGSTER	-1

/*
 * Processor specific section types
 */
#define	SHF_ORDERED		0x40000000
#define	SHF_EXCLUDE		0x80000000
#define	SHN_BEFORE		0xff00
#define	SHN_AFTER		0xff01

/*
 * There are consumers of this file that want to include elf defines for
 * all architectures.  This is a problem for the defines below, because
 * while they are architecture specific they have common names.  Hence to
 * prevent attempts to redefine these variables we'll check if any of
 * the other elf architecture header files have been included.  If
 * they have then we'll just stick with the existing definitions.
 */
#if !defined(_SYS_ELF_MACH_COMMON)
#define	_SYS_ELF_MACH_COMMON

/*
 * Plt and Got information; the first few .got and .plt entries are reserved
 *	PLT[0]	jump to dynamic linker
 *	GOT[0]	address of _DYNAMIC
 */
#define	M_PLT_INSSIZE		4	/* single plt instruction size */
#define	M_GOT_XDYNAMIC		0	/* got index for _DYNAMIC */
#define	M_GOT_XNumber		3	/* reserved no. of got entries */

/*
 * ELF64 bit PLT constants
 */
/* XXXARM: Why do these have the wrong names? */
#define	M64_WORD_ALIGN		8
#define	M64_PLT_ENTSIZE		16	/* plt entry size in bytes */
#define	M64_PLT_ALIGN		16	/* alignment of .plt section */
#define	M64_GOT_ENTSIZE		8	/* got entry size in bytes */
#define	M64_PLT_RESERVSZ	32

/*
 * Make common alias for the 64 bit specific defines based on _ELF64
 */
/* architecture common defines */
#define	M_WORD_ALIGN		M64_WORD_ALIGN
#define	M_PLT_ENTSIZE		M64_PLT_ENTSIZE
#define	M_PLT_ALIGN		M64_PLT_ALIGN
#define	M_PLT_RESERVSZ		M64_PLT_RESERVSZ
#define	M_GOT_ENTSIZE		M64_GOT_ENTSIZE

#endif /* !_SYS_ELF_MACH_COMMON */

#ifdef	__cplusplus
}
#endif
