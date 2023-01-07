/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/* Copyright 2022 Richard Lowe */

#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_kreg_impl.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_aarch64util.h>

#include <sys/errno.h>

#define	BOP_MASK	0xfc000000
#define	BOP(op)		((op) & BOP_MASK)

/* Note that this mask has gaps, to account for authenticated BLR with PAC */
#define	BROP_MASK	0xfefff000
#define	BROP(op)	((op) & BROP_MASK)

enum aarch64_branch {
	BL_INSTR =  0x94000000,
	BLR_INSTR = 0xd63f0000
};

static boolean_t
mdb_aarch64_call_instr(mdb_instr_t instr)
{
	return ((BOP(instr) == BL_INSTR) || (BROP(instr) == BLR_INSTR));
}

/*
 * Put the address of the next instruction after pc in p if a call, or return -1
 * and set errno to EAGAIN if the target should just single-step.
 */
int
mdb_aarch64_next(mdb_tgt_t *t, uintptr_t *p, kreg_t pc, mdb_instr_t curinstr)
{
	if (mdb_aarch64_call_instr(curinstr)) {
		*p = (pc + 4);
		return (0);
	} else {
		return (set_errno(EAGAIN));
	}
}
