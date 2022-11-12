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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_BOOTINFO_H
#define	_SYS_BOOTINFO_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAX_BOOT_MODULES	99

/*
 * The kernel needs to know how to find its modules.
 */
struct boot_modules {
	uint64_t	bm_addr;
	uint64_t	bm_size;
};

/*
 *
 */
struct xboot_info {
	uint64_t	bi_fdt;
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_BOOTINFO_H */
