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
 * Copyright (c) 1992, 2011, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2017 Hayashi Naoyuki
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc. */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T   */
/*		All Rights Reserved				*/

/*	Copyright (c) 1987, 1988 Microsoft Corporation		*/
/*		All Rights Reserved				*/

/*
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/signal.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/psw.h>
#include <sys/trap.h>
#include <sys/fault.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/pcb.h>
#include <sys/lwp.h>
#include <sys/cpuvar.h>
#include <sys/thread.h>
#include <sys/disp.h>
#include <sys/siginfo.h>
#include <sys/archsystm.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/fp.h>

static struct ctxop *fp_ctxop_allocate(fpu_ctx_t *);

static void
fpu_enable(void)
{
	write_cpacr_el1(((read_cpacr_el1() & ~CPACR_FPEN_MASK)) | CPACR_FPEN_EN);
	isb();
}

static void
fpu_disable(void)
{
	isb();
	write_cpacr_el1(((read_cpacr_el1() & ~CPACR_FPEN_MASK)));
}

static void
fpsave_ctxt(void *ctx)
{
	fp_save((fpu_ctx_t *)ctx);
	fpu_disable();
}

static void
fprestore_ctxt(void *ctx)
{
	fpu_enable();
	fp_restore((fpu_ctx_t *)ctx);
}

void
fp_free(fpu_ctx_t *fp)
{
	kpreempt_disable();

	if (curthread->t_lwp && fp == &curthread->t_lwp->lwp_pcb.pcb_fpu) {
		fpu_disable();
	}
	kpreempt_enable();
}

static void
fpfree_ctxt(void *arg, int isexec __unused)
{
	fp_free((fpu_ctx_t *)arg);
}

static void
fp_new_lwp(void *parent, void *child)
{
	kthread_id_t t = parent, ct = child;
	pcb_t *pcb = &ttolwp(t)->lwp_pcb;
	pcb_t *cpcb = &ttolwp(ct)->lwp_pcb;
	fpu_ctx_t *fp = &pcb->pcb_fpu;
	fpu_ctx_t *cfp = &cpcb->pcb_fpu;

	if (t == curthread) {
		fp_save(fp);
	}
	bcopy(fp, cfp, sizeof (*cfp));
	ctxop_attach(ct, fp_ctxop_allocate(cfp));
}

int
fp_fenflt(void)
{
	int ret = 1;
	kpreempt_disable();
	struct ctxop *ctx = curthread->t_ctx;
	while (ctx != NULL) {
		if (ctx->save_op == (void(*)(void *))fpsave_ctxt) {
			break;
		}
		ctx = ctx->next;
	}
	kpreempt_enable();
	if (ctx == NULL) {
		fp_init();
		ret = 0;
	}
	return ret;
}

static struct ctxop *
fp_ctxop_allocate(fpu_ctx_t *fp)
{
	const struct ctxop_template tpl = {
		.ct_rev		= CTXOP_TPL_REV,
		.ct_save	= fpsave_ctxt,
		.ct_restore	= fprestore_ctxt,
		.ct_fork	= fp_new_lwp,
		.ct_lwp_create	= fp_new_lwp,
		.ct_free	= fpfree_ctxt
	};
	return (ctxop_allocate(&tpl, fp));
}


void
fp_init(void)
{
	pcb_t *pcb = &ttolwp(curthread)->lwp_pcb;
	fpu_ctx_t *fp = &pcb->pcb_fpu;
	struct ctxop *ctx = fp_ctxop_allocate(fp);

	kpreempt_disable();
	ctxop_attach(curthread, ctx);

	bzero(&fp->fpu_regs, sizeof(fp->fpu_regs));
	fp->fpu_regs.kfpu_cr = FPCR_INIT;
	fp->fpu_regs.kfpu_sr = 0;
	fprestore_ctxt(fp);

	kpreempt_enable();
}
