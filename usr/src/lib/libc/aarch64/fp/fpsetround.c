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
 */

#include <ieeefp.h>
#include "fp.h"

#pragma weak _fpsetround = fpsetround

fp_rnd
fpsetround(fp_rnd newrnd)
{
	uint32_t fpcr = read_fpcr();
	uint32_t old = ((fpcr & FPCR_RM_MASK) >> FPCR_RM_SHIFT);
	old &= ~FPCR_RM_MASK;
	old |= ((newrnd << FPCR_RM_SHIFT) & FPCR_RM_MASK);
	write_fpcr(fpcr);

	return (fp_rnd)old;
}
