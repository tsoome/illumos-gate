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
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved  	*/

#include <sys/param.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/lockstat.h>

#include <sys/clock.h>
#include <sys/debug.h>
#include <sys/smp_impldefs.h>
#include <sys/rtc.h>

/*
 * This file contains all generic part of clock and timer handling.
 * Specifics are now in separate files and may be overridden by TOD
 * modules.
 */
tod_ops_t tod_ops;
char *tod_module_name;		/* Settable in /etc/system */

extern void tod_set_prev(timestruc_t);

void
tod_set(timestruc_t ts)
{
	ASSERT(MUTEX_HELD(&tod_lock));

	if (tod_ops.tod_set) {
		tod_set_prev(ts);		/* for tod_validate() */
		TODOP_SET(tod_ops, ts);
		tod_status_set(TOD_SET_DONE);	/* TOD was modified */
	}
}

timestruc_t
tod_get(void)
{
	timestruc_t ts;

	ASSERT(MUTEX_HELD(&tod_lock));

	if (tod_ops.tod_get) {
		ts = TODOP_GET(tod_ops);
	} else {
		gethrestime(&ts);
	}
	ts.tv_sec = tod_validate(ts.tv_sec);
	return (ts);
}

int
hr_clock_lock(void)
{
	ushort_t s;

	CLOCK_LOCK(&s);
	return (s);
}

void
hr_clock_unlock(int s)
{
	CLOCK_UNLOCK(s);
}

/*
 * Support routines for horrid GMT lag handling
 */

static time_t gmt_lag;		/* offset in seconds of gmt to local time */

void
sgmtl(time_t arg)
{
	gmt_lag = arg;
}

time_t
ggmtl(void)
{
	return (gmt_lag);
}
