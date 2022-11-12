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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/atomic.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/cpuvar.h>
#include <sys/machcpuvar.h>
#include <sys/archsystm.h>
#include <sys/cpc_pcbe.h>
#include <sys/cpc_impl.h>
#include <sys/x_call.h>
#include <sys/cmn_err.h>
#include <sys/cmt.h>
#include <sys/spl.h>

int
kcpc_hw_load_pcbe(void)
{
	return -1;
}

void
kcpc_hw_init(cpu_t *cp)
{
}

void
kcpc_hw_fini(cpu_t *cp)
{
}

int
kcpc_hw_cpu_hook(processorid_t cpuid, ulong_t *kcpc_cpumap)
{
	return (0);
}

int
kcpc_hw_lwp_hook(void)
{
	return (0);
}
