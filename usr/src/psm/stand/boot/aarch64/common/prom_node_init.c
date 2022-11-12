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
#include <libfdt.h>

#include <sys/salib.h>
#include <sys/promif.h>
#include <sys/promimpl.h>
#include <sys/systm.h>
#include <sys/bootvfs.h>
#include "boot_plat.h"
#include <sys/platnames.h>

void
prom_node_init(void)
{
	int err;
	extern char _dtb_start[];

	err = fdt_check_header(_dtb_start);
	if (err) {
		prom_printf("fdt_check_header ng\n");
		return;
	}

	size_t total_size = fdt_totalsize(_dtb_start);
	size_t size = ((total_size + MMU_PAGESIZE - 1) & ~(MMU_PAGESIZE - 1));
	size += MMU_PAGESIZE;
	void *fdtp = (void *)memlist_get(size, MMU_PAGESIZE, &pfreelistp);
	memcpy(fdtp, _dtb_start, total_size);
	fdt_open_into(fdtp, fdtp, size);
	set_fdtp(fdtp);
}
