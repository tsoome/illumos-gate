/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2017 Hayashi Naoyuki
 */

#ifndef _SYS_PLATFORM_H
#define _SYS_PLATFORM_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/machparam.h>

#define	UART_PHYS	0x09000000

#define	BOOT_TMP_MAP_BASE	0x20000000
#define	BOOT_TMP_MAP_SIZE	0x20000000

#define	DCACHE_LINE	64
#define	ICACHE_LINE	64

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PLATFORM_H */
