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
 *
 * Copyright 2022 Richard Lowe
 */

/*
 * Libkvm Kernel Target AArch64 component
 *
 * This file provides the AArch64-dependent portion of the libkvm kernel target.
 * For more details on the implementation refer to mdb_kvm.c.
 *
 * Technically, we have no need to separate ARM and AArch64 dependent pieces
 * but do it for similarity to the Intel platform.
 */

#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_errno.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_kvm.h>
#include <mdb/mdb_ks.h>
#include <mdb/mdb.h>
#include <mdb/kvm_isadep.h>
#include <mdb/mdb_kreg.h>
#include <mdb/mdb_kreg_impl.h>

#include <sys/cpuvar.h>
#include <sys/privregs.h>

int
kt_getareg(mdb_tgt_t *t, mdb_tgt_tid_t tid,
    const char *rname, mdb_tgt_reg_t *rp)
{
	const mdb_tgt_regdesc_t *rdp;
	kt_data_t *kt = t->t_data;

	if (tid != kt->k_tid)
		return (set_errno(EMDB_NOREGS));

	for (rdp = kt->k_rds; rdp->rd_name != NULL; rdp++) {
		if (strcmp(rname, rdp->rd_name) == 0) {
			*rp = kt->k_regs->kregs[rdp->rd_num];
			if (rdp->rd_flags & MDB_TGT_R_32)
				*rp &= 0xffffffffULL;
			return (0);
		}
	}

	return (set_errno(EMDB_BADREG));
}
