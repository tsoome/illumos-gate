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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2017 Hayashi Naoyuki
 */

#include "thr_uberdata.h"
#include <procfs.h>
#include <ucontext.h>
#include <setjmp.h>

extern int getlwpstatus(thread_t, lwpstatus_t *);
extern int putlwpregs(thread_t, prgregset_t);

/* ARGSUSED2 */
void *
setup_top_frame(void *stk, size_t stksize, ulwp_t *ulwp)
{
	uint64_t *stack;

	/*
	 * Top-of-stack must be rounded down to STACK_ALIGN
	 */
	stack = (uint64_t *)(((uintptr_t)stk + stksize) & ~(STACK_ALIGN-1));

	return (stack);
}

int
setup_context(ucontext_t *ucp, void *(*func)(ulwp_t *),
	ulwp_t *ulwp, caddr_t stk, size_t stksize)
{
	uint64_t *stack;

	/* clear the context */
	(void) memset(ucp, 0, sizeof (*ucp));

	/*
	 * Setup the top stack frame.
	 * If this fails, pass the problem up to the application.
	 */
	if ((stack = setup_top_frame(stk, stksize, ulwp)) == NULL)
		return (ENOMEM);

	/* fill in registers of interest */
	ucp->uc_flags |= UC_CPU;
	ucp->uc_mcontext.gregs[REG_PC] = (greg_t)func;
	ucp->uc_mcontext.gregs[REG_SP] = (greg_t)stack;
	ucp->uc_mcontext.gregs[REG_X30] = (greg_t)_lwp_start;
	ucp->uc_mcontext.gregs[REG_X0] = (greg_t)ulwp;
	ucp->uc_mcontext.gregs[REG_TP] = (greg_t)ulwp;

	return (0);
}

/*
 * Machine-dependent startup code for a newly-created thread.
 */
void *
_thrp_setup(ulwp_t *self)
{
	self->ul_ustack.ss_sp = (void *)(self->ul_stktop - self->ul_stksiz);
	self->ul_ustack.ss_size = self->ul_stksiz;
	self->ul_ustack.ss_flags = 0;
	(void) setustack(&self->ul_ustack);

	update_sched(self);
	tls_setup();

	/* signals have been deferred until now */
	sigon(self);

	if (self->ul_cancel_pending == 2 && !self->ul_cancel_disabled)
		return (NULL);	/* cancelled by pthread_create() */
	return (self->ul_startpc(self->ul_startarg));
}

extern void _getfcr(uint64_t *);
void
_fpinherit(ulwp_t *ulwp)
{
	register uint64_t fpcr;
	register uint64_t fpsr;

	__asm__ volatile ("mrs %0, fpcr":"=r"(fpcr)::"memory");
	__asm__ volatile ("mrs %0, fpsr":"=r"(fpsr)::"memory");

	ulwp->ul_fpuenv.fctrl = fpcr;
	ulwp->ul_fpuenv.fstat = fpsr;
}

void
getgregs(ulwp_t *ulwp, gregset_t rs)
{
	lwpstatus_t status;

	if (getlwpstatus(ulwp->ul_lwpid, &status) == 0) {
		rs[REG_X19] = status.pr_reg[REG_X19];
		rs[REG_X20] = status.pr_reg[REG_X20];
		rs[REG_X21] = status.pr_reg[REG_X21];
		rs[REG_X22] = status.pr_reg[REG_X22];
		rs[REG_X23] = status.pr_reg[REG_X23];
		rs[REG_X24] = status.pr_reg[REG_X24];
		rs[REG_X25] = status.pr_reg[REG_X25];
		rs[REG_X26] = status.pr_reg[REG_X26];
		rs[REG_X27] = status.pr_reg[REG_X27];
		rs[REG_X28] = status.pr_reg[REG_X28];
		rs[REG_X29] = status.pr_reg[REG_X29];
		rs[REG_X30] = status.pr_reg[REG_X30];
		rs[REG_SP] = status.pr_reg[REG_SP];
		rs[REG_PC] = status.pr_reg[REG_PC];
	} else {
		rs[REG_X19] = 0;
		rs[REG_X20] = 0;
		rs[REG_X21] = 0;
		rs[REG_X22] = 0;
		rs[REG_X23] = 0;
		rs[REG_X24] = 0;
		rs[REG_X25] = 0;
		rs[REG_X26] = 0;
		rs[REG_X27] = 0;
		rs[REG_X28] = 0;
		rs[REG_X29] = 0;
		rs[REG_X30] = 0;
		rs[REG_SP] = 0;
		rs[REG_PC] = 0;
	}
}

void
setgregs(ulwp_t *ulwp, gregset_t rs)
{
	lwpstatus_t status;

	if (getlwpstatus(ulwp->ul_lwpid, &status) == 0) {
		status.pr_reg[REG_X19] = rs[REG_X19];
		status.pr_reg[REG_X20] = rs[REG_X20];
		status.pr_reg[REG_X21] = rs[REG_X21];
		status.pr_reg[REG_X22] = rs[REG_X22];
		status.pr_reg[REG_X23] = rs[REG_X23];
		status.pr_reg[REG_X24] = rs[REG_X24];
		status.pr_reg[REG_X25] = rs[REG_X25];
		status.pr_reg[REG_X26] = rs[REG_X26];
		status.pr_reg[REG_X27] = rs[REG_X27];
		status.pr_reg[REG_X28] = rs[REG_X28];
		status.pr_reg[REG_X29] = rs[REG_X29];
		status.pr_reg[REG_X30] = rs[REG_X30];
		status.pr_reg[REG_SP] = rs[REG_SP];
		status.pr_reg[REG_PC] = rs[REG_PC];
		putlwpregs(ulwp->ul_lwpid, status.pr_reg);
	}
}


/*
 * regs
 * 	x19 - x30, sp
 */
int
__csigsetjmp(sigjmp_buf env, int savemask, greg_t *regs)
{
	ucontext_t *ucp = (ucontext_t *)env;
	ulwp_t *self = curthread;
	getcontext(ucp);

	ucp->uc_link = self->ul_siglink;
	if (self->ul_ustack.ss_flags & SS_ONSTACK)
		ucp->uc_stack = self->ul_ustack;
	else {
		ucp->uc_stack.ss_sp =
		    (void *)(self->ul_stktop - self->ul_stksiz);
		ucp->uc_stack.ss_size = self->ul_stksiz;
		ucp->uc_stack.ss_flags = 0;
	}
	ucp->uc_flags = UC_STACK | UC_MCONTEXT;
	if (savemask) {
		ucp->uc_flags |= UC_SIGMASK;
		enter_critical(self);
		ucp->uc_sigmask = self->ul_sigmask;
		exit_critical(self);
	}
	ucp->uc_mcontext.gregs[REG_X19] = regs[0];
	ucp->uc_mcontext.gregs[REG_X20] = regs[1];
	ucp->uc_mcontext.gregs[REG_X21] = regs[2];
	ucp->uc_mcontext.gregs[REG_X22] = regs[3];
	ucp->uc_mcontext.gregs[REG_X23] = regs[4];
	ucp->uc_mcontext.gregs[REG_X24] = regs[5];
	ucp->uc_mcontext.gregs[REG_X25] = regs[6];
	ucp->uc_mcontext.gregs[REG_X26] = regs[7];
	ucp->uc_mcontext.gregs[REG_X27] = regs[8];
	ucp->uc_mcontext.gregs[REG_X28] = regs[9];
	ucp->uc_mcontext.gregs[REG_X29] = regs[10];
	ucp->uc_mcontext.gregs[REG_X30] = regs[11];
	ucp->uc_mcontext.gregs[REG_SP] = regs[12];
	ucp->uc_mcontext.gregs[REG_PC] = regs[11];
	return (0);
}

void
smt_pause(void)
{
}
