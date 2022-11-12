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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/archsystm.h>
#include <sys/cmn_err.h>
#include <sys/cpupart.h>
#include <sys/cpuvar.h>
#include <sys/lgrp.h>
#include <sys/machsystm.h>
#include <sys/memlist.h>
#include <sys/memnode.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/promif.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/types.h>

#define	MAX_NODES		1
#define	NLGRP			(MAX_NODES * (MAX_NODES - 1) + 1)

static lgrp_t	lgrp_space[NLGRP];
static int	nlgrps_alloc;
struct lgrp_stats lgrp_stats[NLGRP];

void
lgrp_plat_init(lgrp_init_stages_t stage)
{
	max_mem_nodes = 1;
}

void
lgrp_plat_probe(void)
{
}


void
lgrp_plat_main_init(void)
{
}

lgrp_t *
lgrp_plat_alloc(lgrp_id_t lgrpid)
{
	if (lgrpid >= NLGRP || nlgrps_alloc >= NLGRP)
		return (NULL);

	return &lgrp_space[nlgrps_alloc++];
}

void
lgrp_plat_config(lgrp_config_flag_t flag, uintptr_t arg)
{
}

lgrp_handle_t
lgrp_plat_cpu_to_hand(processorid_t id)
{
	return LGRP_DEFAULT_HANDLE;
}

lgrp_handle_t
lgrp_plat_pfn_to_hand(pfn_t pfn)
{
	return LGRP_DEFAULT_HANDLE;
}

int
lgrp_plat_max_lgrps()
{
	return 1;
}

pgcnt_t
lgrp_plat_mem_size(lgrp_handle_t plathand, lgrp_mem_query_t query)
{
	struct memlist *mlist;
	pgcnt_t npgs = (pgcnt_t)0;
	extern struct memlist *phys_avail;
	extern struct memlist *phys_install;

	if (plathand == LGRP_DEFAULT_HANDLE) {
		switch (query) {
		case LGRP_MEM_SIZE_FREE:
			npgs = (pgcnt_t)freemem;
			break;

		case LGRP_MEM_SIZE_AVAIL:
			memlist_read_lock();
			for (mlist = phys_avail; mlist; mlist = mlist->ml_next) {
				npgs += btop(mlist->ml_size);
			}
			memlist_read_unlock();
			break;

		case LGRP_MEM_SIZE_INSTALL:
			memlist_read_lock();
			for (mlist = phys_install; mlist;
			     mlist = mlist->ml_next) {
				npgs += btop(mlist->ml_size);
			}
			memlist_read_unlock();
			break;

		default:
			break;
		}
	}

	return npgs;
}

int
lgrp_plat_latency(lgrp_handle_t from, lgrp_handle_t to)
{
	return 0;
}

lgrp_handle_t
lgrp_plat_root_hand(void)
{
	return (LGRP_DEFAULT_HANDLE);
}
