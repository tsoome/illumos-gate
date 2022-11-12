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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Kernel/Debugger Interface (KDI) routines.  Called during debugger under
 * various system states (boot, while running, while the debugger has control).
 * Functions intended for use while the debugger has control may not grab any
 * locks or perform any functions that assume the availability of other system
 * services.
 */

#include <sys/systm.h>
#include <sys/kdi_impl.h>
#include <sys/smp_impldefs.h>
#include <sys/archsystm.h>
#include <sys/controlregs.h>
#include <sys/trap.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>

extern void flush_data_cache_all(void);
void
kdi_flush_caches(void)
{
	flush_data_cache_all();
	dsb(ish);
	invalidate_instruction_cache_all();
	dsb(ish);
	isb();
}

