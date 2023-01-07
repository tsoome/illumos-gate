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

#include <sys/debug.h>
#include <sys/reg.h>

#include <libelf.h>

#include <rtld_db.h>
#include "_rtld_db.h"
#include "msg.h"

#define	ADRP_IMMHI_SHIFT	5
#define	ADRP_IMMHI_MASK		(0x7ffff << ADRP_IMMHI_SHIFT)
#define	ADRP_IMMHI(insn)	((insn & ADRP_IMMHI_MASK) >> ADRP_IMMHI_SHIFT)

#define	ADRP_IMMLO_SHIFT	29
#define	ADRP_IMMLO_MASK		(0x3 << ADRP_IMMLO_SHIFT)
#define	ADRP_IMMLO(insn)	((insn & ADRP_IMMLO_MASK) >> ADRP_IMMLO_SHIFT)

#define	ADD_IMM_SHIFT	10
#define	ADD_IMM_MASK	(0xfff << ADD_IMM_SHIFT)
#define	ADD_IMM(insn)	((insn & ADD_IMM_MASK) >> ADD_IMM_SHIFT)

/*
 * Given a pointer to the start of a PLT entry, return the address of the
 * entry in .got.plt.
 *
 * We could do this by the equivalence of their index by looking up the right
 * object's .got.plt in a manner similar how we do this on ia32, but we
 * instead disassemble to get the pointer directly.
 *
 * XXXARM: This, and many other things, will need work for BTI and PAC.
 */
static uintptr_t
got_plt_addr(psaddr_t pc, uint32_t *insn)
{
	uintptr_t addr, immhi, immlo;

	VERIFY((*insn & 0x9f000000) == 0x90000000); /* an adrp */

	/* Extract the immediate from the adrp  */
	immhi = ADRP_IMMHI(*insn);
	immlo = ADRP_IMMLO(*insn);
	addr = (pc + ((immhi << 14) | (immlo << 12))) & ~0xfff;

	insn += 2;		/* Skip to the add */
	VERIFY((*insn & 0x7f800000) == 0x11000000); /* an immediate add */

	return (addr + ADD_IMM(*insn));
}

/*
 * On AArch64 a PLT entry looks like this:
 *
 *   .plt+0x20:                 d0 00 00 90  adrp x16, 0x41a000
 *   .plt+0x24:                 11 36 40 f9  ldr x17, [x16, #104] ; GOT.PLT[N]
 *   .plt+0x28:                 10 a2 01 91  add x16, x16, #0x68  ; GOT.PLT[N]
 *   .plt+0x2c:                 20 02 1f d6  br x17
 *
 *  The first time around GOT.PLT[N] contains address of PLT[0]; this forces
 *	the first call to go thru elf_rtbndr.
 *  Other times around the GOT.PLT[N] actually contains the resolved
 *	address of the symbol(name), so the branch is direct
 */
rd_err_e
plt64_resolution(rd_agent_t *rap, psaddr_t pc, lwpid_t lwpid,
    psaddr_t pltbase, rd_plt_info_t *rpi)
{
	instr_t		instr[3]; /* XXXARM: This is too small for BTI/PAC */
	psaddr_t	pltoff, pltaddr, gotaddr, targetaddr;

	if (rtld_db_version >= RD_VERSION3) {
		rpi->pi_flags = 0;
		rpi->pi_baddr = 0;
	}

	pltoff = pc - pltbase;
	pltaddr = pltbase + ((pltoff / M_PLT_ENTSIZE) * M_PLT_ENTSIZE);

	/*
	 * This is the target of the branch instruction
	 */
	if (ps_pread(rap->rd_psp, pltaddr, (char *)instr,
	    sizeof (instr)) != PS_OK) {
		LOG(ps_plog(MSG_ORIG(MSG_DB_READFAIL_2), EC_ADDR(pltaddr)));
		return (RD_ERR);
	}

	gotaddr = got_plt_addr(pltaddr, instr);

	if (ps_pread(rap->rd_psp, gotaddr, &targetaddr,
	    sizeof (targetaddr)) != PS_OK) {
		LOG(ps_plog(MSG_ORIG(MSG_DB_READFAIL_2), EC_ADDR(gotaddr)));
		return (RD_ERR);
	}

	if (targetaddr == pltbase) {
		rd_err_e	rerr;

		/*
		 * If GOT[ind] points to PLT[0] then this is the first
		 * time through this PLT entry.
		 */
		if ((rerr = rd_binder_exit_addr(rap, MSG_ORIG(MSG_SYM_RTBIND),
		    &(rpi->pi_target))) != RD_OK) {
			return (rerr);
		}
		rpi->pi_skip_method = RD_RESOLVE_TARGET_STEP;
		rpi->pi_nstep = 1;
	} else {
		/*
		 * This is the n'th time through and GOT[ind] points
		 * to the final destination.
		 */
		rpi->pi_skip_method = RD_RESOLVE_STEP;
		rpi->pi_nstep = 1;
		rpi->pi_target = 0;
		if (rtld_db_version >= RD_VERSION3) {
			rpi->pi_flags |= RD_FLG_PI_PLTBOUND;
			rpi->pi_baddr = targetaddr;
		}
	}

	return (RD_OK);
}
