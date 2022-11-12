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
 * Copyright (c) 1992, 2011, Oracle and/or its affiliates. All rights reserved.
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

static struct ctxop *fp_ctxop_allocate(pcb_t *);

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
fpu_save(void *pcb)
{
	fp_save((struct pcb *)pcb);
	fpu_disable();
}

static void
fpu_restore(void *pcb)
{
	fpu_enable();
	fp_restore((struct pcb *)pcb);
}


static void
fp_new_lwp(void *parent, void *child)
{
	kthread_id_t t = parent, ct = child;
	pcb_t *pcb = &ttolwp(t)->lwp_pcb;
	pcb_t *cpcb = &ttolwp(ct)->lwp_pcb;
	struct fpu_ctx *fp = &pcb->pcb_fpu;
	struct fpu_ctx *cfp = &cpcb->pcb_fpu;

	ctxop_attach(ct, fp_ctxop_allocate(pcb));
}

int
fp_fenflt(void)
{
	int ret = 1;
	kpreempt_disable();
	struct ctxop *ctx = curthread->t_ctx;
	while (ctx != NULL) {
		if (ctx->save_op == (void(*)(void *))fpu_save) {
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
fp_ctxop_allocate(pcb_t *pcb)
{
	const struct ctxop_template tpl = {
		.ct_rev		= CTXOP_TPL_REV,
		.ct_save	= fpu_save,
		.ct_restore	= fpu_restore,
		.ct_fork	= fp_new_lwp,
		.ct_lwp_create	= fp_new_lwp,
		.ct_free	= NULL,
	};
	return (ctxop_allocate(&tpl, pcb));
}

void fp_init(void)
{
	struct ctxop *ctx;

	kpreempt_disable();
	pcb_t *pcb = &ttolwp(curthread)->lwp_pcb;
	bzero(&pcb->pcb_fpu.fpu_regs, sizeof(pcb->pcb_fpu.fpu_regs));
	pcb->pcb_fpu.fpu_regs.kfpu_cr = FPCR_INIT;
	pcb->pcb_fpu.fpu_regs.kfpu_sr = 0;
	fpu_restore(pcb);

	ctx = fp_ctxop_allocate(pcb);
	ctxop_attach(curthread, ctx);

	kpreempt_enable();
}
