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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, Joyent, Inc.  All rights reserverd.
 */

#include <sys/cpuvar.h>
#include <sys/cpu_event.h>
#include <sys/regset.h>
#include <sys/psw.h>
#include <sys/types.h>
#include <sys/thread.h>
#include <sys/systm.h>
#include <sys/pcb.h>
#include <sys/trap.h>
#include <sys/ftrace.h>
#include <sys/clock.h>
#include <sys/panic.h>
#include <sys/disp.h>
#include <vm/seg_kp.h>
#include <sys/stack.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/kstat.h>
#include <sys/smp_impldefs.h>
#include <sys/pool_pset.h>
#include <sys/zone.h>
#include <sys/bitmap.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/ontrap.h>
#include <sys/promif.h>
#include <sys/fault.h>
#include <sys/procfs.h>
#include <sys/fp.h>
#include <sys/contract/process_impl.h>
#include <sys/aio_impl.h>
#include <sys/prsystm.h>
#include <vm/hat_aarch64.h>
#include <sys/frame.h>
#include <sys/dtrace.h>

extern void print_msg_hwerr(ctid_t ct_id, proc_t *p);
extern int dtrace_invop(uintptr_t addr, uintptr_t *stack, uintptr_t eax);


void
panic_showtrap(struct panic_trap_info *tip)
{
}

void
panic_savetrap(panic_data_t *pdp, struct panic_trap_info *tip)
{
}

void
dump_trap(uint32_t ec, uint32_t iss, caddr_t addr, struct regs *rp)
{
	static volatile int exclusion;

	uint64_t daif = read_daif();
	set_daif(DAIF_SETCLEAR_IRQ);
	while (__sync_lock_test_and_set(&exclusion, 1)) {}

	prom_printf("%s(): ec=0x%08x iss=0x%08x addr=%p rp=%lx mpidr=%lx\n", __FUNCTION__, ec, iss, addr, rp, read_mpidr());
	prom_printf("      x0=%016lx\n", rp->r_x0);
	prom_printf("      x1=%016lx\n", rp->r_x1);
	prom_printf("      x2=%016lx\n", rp->r_x2);
	prom_printf("      x3=%016lx\n", rp->r_x3);
	prom_printf("      x4=%016lx\n", rp->r_x4);
	prom_printf("      x5=%016lx\n", rp->r_x5);
	prom_printf("      x6=%016lx\n", rp->r_x6);
	prom_printf("      x7=%016lx\n", rp->r_x7);
	prom_printf("      x8=%016lx\n", rp->r_x8);
	prom_printf("      x9=%016lx\n", rp->r_x9);
	prom_printf("      x10=%016lx\n", rp->r_x10);
	prom_printf("      x11=%016lx\n", rp->r_x11);
	prom_printf("      x12=%016lx\n", rp->r_x12);
	prom_printf("      x13=%016lx\n", rp->r_x13);
	prom_printf("      x14=%016lx\n", rp->r_x14);
	prom_printf("      x15=%016lx\n", rp->r_x15);
	prom_printf("      x16=%016lx\n", rp->r_x16);
	prom_printf("      x17=%016lx\n", rp->r_x17);
	prom_printf("      x18=%016lx\n", rp->r_x18);
	prom_printf("      x19=%016lx\n", rp->r_x19);
	prom_printf("      x20=%016lx\n", rp->r_x20);
	prom_printf("      x21=%016lx\n", rp->r_x21);
	prom_printf("      x22=%016lx\n", rp->r_x22);
	prom_printf("      x23=%016lx\n", rp->r_x23);
	prom_printf("      x24=%016lx\n", rp->r_x24);
	prom_printf("      x25=%016lx\n", rp->r_x25);
	prom_printf("      x26=%016lx\n", rp->r_x26);
	prom_printf("      x27=%016lx\n", rp->r_x27);
	prom_printf("      x28=%016lx\n", rp->r_x28);
	prom_printf("      x29=%016lx\n", rp->r_x29);
	prom_printf("      x30=%016lx\n", rp->r_x30);
	prom_printf("      SP=%016lx\n", rp->r_sp);
	prom_printf("      PC=%016lx\n", rp->r_pc);
	prom_printf("      SPSR=%016lx\n", rp->r_spsr);


	struct frame *fp = (struct frame *)rp->r_x29;
	prom_printf("Call Stack\n");
	for (;;) {
		write_s1e1r((uint64_t)fp);
		isb();
		uint64_t par = read_par_el1();
		if (par & 1)
			break;
		prom_printf("    %p\n", fp->fr_savpc);
		fp = (struct frame *)fp->fr_savfp;
	}
	prom_printf("Call Stack End\n");
	__sync_lock_release(&exclusion);
	write_daif(daif);
}
static void
die(uint32_t ec, uint32_t iss, caddr_t addr, struct regs *rp)
{
	dump_trap(ec, iss, addr, rp);
	prom_panic("");
}

int
trap(uint32_t ec, uint32_t iss, caddr_t addr, struct regs *rp)
{
	kthread_t *ct = curthread;
	enum seg_rw rw;
	proc_t *p = ttoproc(ct);
	klwp_t *lwp = ttolwp(ct);
	uintptr_t lofault;
	label_t *onfault;
	faultcode_t pagefault(), res, errcode;
	enum fault_type fault_type;
	k_siginfo_t siginfo;
	uint_t fault = 0;
	int mstate;
	int sicode = 0;
	int watchcode;
	int watchpage;
	caddr_t vaddr;
	int singlestep_twiddle;
	size_t sz;
	int ta;

	/*
	 * XXXARM: Why are these DTrace bits handled here?
	 */
	ASSERT((read_daif() & DAIF_IRQ) != 0);

	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_NOFAULT)) {
		ASSERT(!USERMODE(rp->r_spsr));
		switch (ec) {
		case T_DABT:
		case T_DABT_EL1:
			DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
			cpu_core[CPU->cpu_id].cpuc_dtrace_illval = (uintptr_t)addr;
			break;
		default:
			DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
			break;
		}
		rp->r_pc += 4;
		return 0;
	}
	if (!USERMODE(rp->r_spsr)) {
		if (ec == T_BRK && iss == 0x11) {
			int r = dtrace_invop(rp->r_pc, (uintptr_t *)rp, rp->r_x0);
			if (r == DTRACE_INVOP_RET) {
				rp->r_pc = rp->r_x30;
				return 0;
			}
			if (r == DTRACE_INVOP_NOP) {
				rp->r_pc += 4;
				return 0;
			}
		}
	}

	clear_daif(DAIF_SETCLEAR_IRQ);

	ASSERT_STACK_ALIGNED();

	CPU_STATS_ADDQ(CPU, sys, trap, 1);
	ASSERT(ct->t_schedflag & TS_DONT_SWAP);

	switch (ec) {
	case T_IABT:
	case T_IABT_EL1:
	case T_DABT:
	case T_DABT_EL1:
		{
			if (ec == T_IABT || ec == T_IABT_EL1) {
				mstate = LMS_TFAULT;
				rw = S_EXEC;
			} else {
				mstate = LMS_DFAULT;
				if (iss & (1u << 6)) {
					rw = S_WRITE;
				} else {
					rw = S_READ;
				}
			}

			if ((iss & (1u << 10)) != 0) {
				// addr is invalid
				addr = ((caddr_t)-1);
			}
			uint32_t fsc = (iss & 0x3F);
			if ((0x9 <= fsc && fsc <= 0xc) && ((iss & (1u << 10)) == 0) &&
			    (((ec == T_IABT_EL1 || ec == T_DABT_EL1)) || (addr < (caddr_t)kernelbase)) &&
			    hat_page_fault(addr < (caddr_t)kernelbase ?  curproc->p_as->a_hat: kas.a_hat, addr) == 0) {
					return 1;
			} else if (0xd <= fsc && fsc <= 0xF) {
				// Access flag fault or Permission fault
				fault_type = F_PROT;
			} else {
				fault_type = F_INVAL;
			}
		}
		break;
	default:
		mstate = LMS_TRAP;
		break;
	}

	if (USERMODE(rp->r_spsr)) {
		if (ct->t_cred != p->p_cred) {
			cred_t *oldcred = ct->t_cred;
			ct->t_cred = crgetcred();
			crfree(oldcred);
		}
		ASSERT(lwp != NULL);
		ASSERT(lwptoregs(lwp) == rp);
		lwp->lwp_state = LWP_SYS;

		mstate = new_mstate(ct, mstate);

		bzero(&siginfo, sizeof (siginfo));

		switch (ec) {
		default:
			{
				siginfo.si_signo = SIGILL;
				siginfo.si_code  = ILL_ILLTRP;
				siginfo.si_addr  = (caddr_t)rp->r_pc;
				siginfo.si_trapno = ec;
				fault = FLTILL;
			}
			break;
		case T_IABT:
		case T_DABT:
			{
				ASSERT(!(curthread->t_flag & T_WATCHPT));
				res = pagefault(addr, fault_type, rw, 0);

				if (res == 0 ||
				    (res == FC_NOMAP && addr < p->p_usrstack && grow(addr))) {
					lwp->lwp_lastfault = FLTPAGE;
					lwp->lwp_lastfaddr = addr;
					if (prismember(&p->p_fltmask, FLTPAGE)) {
						siginfo.si_addr = addr;
						(void) stop_on_fault(FLTPAGE, &siginfo);
					}
					goto out;
				} else if (res == FC_PROT && addr < p->p_usrstack && rw == S_EXEC) {
					report_stack_exec(p, addr);
				}

				siginfo.si_addr = addr;
				switch (FC_CODE(res)) {
				case FC_HWERR:
				case FC_NOSUPPORT:
					siginfo.si_signo = SIGBUS;
					siginfo.si_code = BUS_ADRERR;
					fault = FLTACCESS;
					break;
				case FC_ALIGN:
					siginfo.si_signo = SIGBUS;
					siginfo.si_code = BUS_ADRALN;
					fault = FLTACCESS;
					break;
				case FC_OBJERR:
					if ((siginfo.si_errno = FC_ERRNO(res)) != EINTR) {
						siginfo.si_signo = SIGBUS;
						siginfo.si_code = BUS_OBJERR;
						fault = FLTACCESS;
					}
					break;
				default:
					siginfo.si_signo = SIGSEGV;
					siginfo.si_code = ((res == FC_NOMAP)? SEGV_MAPERR : SEGV_ACCERR);
					fault = FLTBOUNDS;
					break;
				}
			}
			break;
		case T_FPU:
			{
				siginfo.si_signo = SIGFPE;
				siginfo.si_code  = FPE_INTDIV;
				siginfo.si_addr  = (caddr_t)rp->r_pc;
				fault = FLTIZDIV;
			}
			break;
		case T_FPEN:
			{
				if (fp_fenflt()) {
					siginfo.si_signo = SIGILL;
					siginfo.si_code  = ILL_ILLOPC;
					siginfo.si_addr  = (caddr_t)rp->r_pc;
					fault = FLTILL;
				} else {
					goto out;
				}
			}
			break;
		case T_PC_ALIGN:
		case T_SP_ALIGN:
			{
				siginfo.si_signo = SIGBUS;
				siginfo.si_code = BUS_ADRALN;
				siginfo.si_addr = (caddr_t)rp->r_pc;
				fault = FLTACCESS;
			}
			break;
		case T_SERR:
			{
				siginfo.si_addr = ((caddr_t)-1);
				siginfo.si_signo = SIGBUS;
				siginfo.si_code = BUS_ADRERR;
				fault = FLTACCESS;
			}
			break;
		case T_ILEXC:
			{
				siginfo.si_signo = SIGILL;
				siginfo.si_code  = ILL_ILLOPC;
				siginfo.si_addr  = (caddr_t)rp->r_pc;
				fault = FLTILL;
			}
			break;
		case T_AST:
			{
				if (lwp->lwp_pcb.pcb_flags & ASYNC_HWERR) {
					proc_t *p = ttoproc(curthread);
					extern void print_msg_hwerr(ctid_t ct_id, proc_t *p);

					lwp->lwp_pcb.pcb_flags &= ~ASYNC_HWERR;
					print_msg_hwerr(p->p_ct_process->conp_contract.ct_id, p);
					contract_process_hwerr(p->p_ct_process, p);
					siginfo.si_signo = SIGKILL;
					siginfo.si_code = SI_NOINFO;
				} else if (lwp->lwp_pcb.pcb_flags & CPC_OVERFLOW) {
					lwp->lwp_pcb.pcb_flags &= ~CPC_OVERFLOW;
					if (kcpc_overflow_ast()) {
						siginfo.si_signo = SIGEMT;
						siginfo.si_code = EMT_CPCOVF;
						siginfo.si_addr = (caddr_t)rp->r_pc;
						fault = FLTCPCOVF;
					}
				}
			}
			break;
		case T_SOFTWARE_STEP:
			{
				pcb_t *pcb = &lwp->lwp_pcb;
				rp->r_spsr &= ~PSR_SS;
				write_mdscr_el1(read_mdscr_el1() & ~(MDSCR_SS));

				if ((fault = undo_watch_step(&siginfo)) == 0 &&
				    ((pcb->pcb_flags & NORMAL_STEP) ||
				     !(pcb->pcb_flags & WATCH_STEP))) {
					siginfo.si_signo = SIGTRAP;
					siginfo.si_code = TRAP_TRACE;
					siginfo.si_addr = (caddr_t)rp->r_pc;
					fault = FLTTRACE;
				}
				pcb->pcb_flags &= ~(NORMAL_STEP|WATCH_STEP);
			}
			break;
		case T_BRK:
			{
				siginfo.si_signo = SIGTRAP;
				siginfo.si_code  = TRAP_BRKPT;
				siginfo.si_addr  = (caddr_t)rp->r_pc;
				fault = FLTBPT;
			}
			break;
		}

		if (fault) {
			// dump_trap(ec, iss, addr, rp);
			lwp->lwp_pcb.pcb_flags &= ~(NORMAL_STEP|WATCH_STEP);
			lwp->lwp_lastfault = fault;
			lwp->lwp_lastfaddr = siginfo.si_addr;

			if (siginfo.si_signo != SIGKILL &&
			    prismember(&p->p_fltmask, fault) &&
			    stop_on_fault(fault, &siginfo) == 0)
				siginfo.si_signo = 0;
		}

		if (siginfo.si_signo)
			trapsig(&siginfo, (fault != FLTFPE && fault != FLTCPCOVF));

		if (lwp->lwp_oweupc)
			profil_tick(rp->r_pc);

		if (ct->t_astflag | ct->t_sig_check) {
			astoff(ct);

			if (lwp->lwp_pcb.pcb_flags & DEBUG_PENDING)
				deferred_singlestep_trap((caddr_t)rp->r_pc);

			ct->t_sig_check = 0;

			if (curthread->t_proc_flag & TP_CHANGEBIND) {
				mutex_enter(&p->p_lock);
				if (curthread->t_proc_flag & TP_CHANGEBIND) {
					timer_lwpbind();
					curthread->t_proc_flag &= ~TP_CHANGEBIND;
				}
				mutex_exit(&p->p_lock);
			}

			if (p->p_aio)
				aio_cleanup(0);

			if (ISHOLD(p))
				holdlwp();

			if (ISSIG_PENDING(ct, lwp, p)) {
				if (issig(FORREAL))
					psig();
				ct->t_sig_check = 1;
			}

			if (ct->t_rprof != NULL) {
				realsigprof(0, 0, 0);
				ct->t_sig_check = 1;
			}

			if (lwp->lwp_pcb.pcb_flags & REQUEST_STEP) {
				lwp->lwp_pcb.pcb_flags &= ~REQUEST_STEP;
				rp->r_spsr |= PSR_SS;
				write_mdscr_el1(read_mdscr_el1() | (MDSCR_MDE | MDSCR_SS));
			}
			if (lwp->lwp_pcb.pcb_flags & REQUEST_NOSTEP) {
				lwp->lwp_pcb.pcb_flags &= ~REQUEST_NOSTEP;
				rp->r_spsr &= ~PSR_SS;
				write_mdscr_el1(read_mdscr_el1() & ~(MDSCR_SS));
			}
		}
out:
		if (ISHOLD(p))
			holdlwp();

		lwp->lwp_state = LWP_USER;

		if (ct->t_trapret) {
			ct->t_trapret = 0;
			thread_lock(ct);
			CL_TRAPRET(ct);
			thread_unlock(ct);
		}
		if (CPU->cpu_runrun || curthread->t_schedflag & TS_ANYWAITQ)
			preempt();
		prunstop();
		new_mstate(ct, mstate);
	} else {
		switch (ec) {
		case T_FPU:
		case T_PC_ALIGN:
		case T_SP_ALIGN:
		case T_SERR:
		case T_ILEXC:
		default:
			die(ec, iss, addr, rp);
			break;
		case T_FPEN:
			{
				if (fp_fenflt())
					die(ec, iss, addr, rp);
			}
			break;
		case T_IABT_EL1:
		case T_DABT_EL1:
			{
				if ((ct->t_ontrap != NULL) &&
				    (ct->t_ontrap->ot_prot & OT_DATA_ACCESS)) {
					ct->t_ontrap->ot_trap |= OT_DATA_ACCESS;
					rp->r_pc = ct->t_ontrap->ot_trampoline;
					goto cleanup;
				}
				lofault = ct->t_lofault;
				ct->t_lofault = 0;

				mstate = new_mstate(ct, LMS_KFAULT);

				if (addr < (caddr_t)kernelbase) {
					res = pagefault(addr, fault_type, rw, 0);
					if (res == FC_NOMAP && addr < p->p_usrstack && grow(addr))
						res = 0;
				} else {
					res = pagefault(addr, fault_type, rw, 1);
				}
				new_mstate(ct, mstate);

				ct->t_lofault = lofault;
				if (res == 0)
					goto cleanup;

				if (lofault == 0) {
					die(ec, iss, addr, rp);
				}

				if (FC_CODE(res) == FC_OBJERR)
					res = FC_ERRNO(res);
				else
					res = EFAULT;
				rp->r_x0 = res;
				rp->r_pc = ct->t_lofault;
				goto cleanup;
			}
			break;
		case T_AST:
			goto cleanup;
			break;
		}
	}
cleanup:
	return 1;
}

/*
 * Patch non-zero to disable preemption of threads in the kernel.
 */
int IGNORE_KERNEL_PREEMPTION = 0;	/* XXX - delete this someday */

struct kpreempt_cnts {		/* kernel preemption statistics */
	int	kpc_idle;	/* executing idle thread */
	int	kpc_intr;	/* executing interrupt thread */
	int	kpc_clock;	/* executing clock thread */
	int	kpc_blocked;	/* thread has blocked preemption (t_preempt) */
	int	kpc_notonproc;	/* thread is surrendering processor */
	int	kpc_inswtch;	/* thread has ratified scheduling decision */
	int	kpc_prilevel;	/* processor interrupt level is too high */
	int	kpc_apreempt;	/* asynchronous preemption */
	int	kpc_spreempt;	/* synchronous preemption */
} kpreempt_cnts;

/*
 * kernel preemption: forced rescheduling, preempt the running kernel thread.
 *	the argument is old PIL for an interrupt,
 *	or the distingished value KPREEMPT_SYNC.
 */
void
kpreempt(int asyncspl)
{
	kthread_t *ct = curthread;

	if (IGNORE_KERNEL_PREEMPTION) {
		aston(CPU->cpu_dispthread);
		return;
	}

	/*
	 * Check that conditions are right for kernel preemption
	 */
	do {
		if (ct->t_preempt) {
			/*
			 * either a privileged thread (idle, panic, interrupt)
			 * or will check when t_preempt is lowered
			 * We need to specifically handle the case where
			 * the thread is in the middle of swtch (resume has
			 * been called) and has its t_preempt set
			 * [idle thread and a thread which is in kpreempt
			 * already] and then a high priority thread is
			 * available in the local dispatch queue.
			 * In this case the resumed thread needs to take a
			 * trap so that it can call kpreempt. We achieve
			 * this by using siron().
			 * How do we detect this condition:
			 * idle thread is running and is in the midst of
			 * resume: curthread->t_pri == -1 && CPU->dispthread
			 * != CPU->thread
			 * Need to ensure that this happens only at high pil
			 * resume is called at high pil
			 * Only in resume_from_idle is the pil changed.
			 */
			if (ct->t_pri < 0) {
				kpreempt_cnts.kpc_idle++;
				if (CPU->cpu_dispthread != CPU->cpu_thread)
					siron();
			} else if (ct->t_flag & T_INTR_THREAD) {
				kpreempt_cnts.kpc_intr++;
				if (ct->t_pil == CLOCK_LEVEL)
					kpreempt_cnts.kpc_clock++;
			} else {
				kpreempt_cnts.kpc_blocked++;
				if (CPU->cpu_dispthread != CPU->cpu_thread)
					siron();
			}
			aston(CPU->cpu_dispthread);
			return;
		}
		if (ct->t_state != TS_ONPROC ||
		    ct->t_disp_queue != CPU->cpu_disp) {
			/* this thread will be calling swtch() shortly */
			kpreempt_cnts.kpc_notonproc++;
			if (CPU->cpu_thread != CPU->cpu_dispthread) {
				/* already in swtch(), force another */
				kpreempt_cnts.kpc_inswtch++;
				siron();
			}
			return;
		}
		if (getpil() >= DISP_LEVEL) {
			/*
			 * We can't preempt this thread if it is at
			 * a PIL >= DISP_LEVEL since it may be holding
			 * a spin lock (like sched_lock).
			 */
			siron();	/* check back later */
			kpreempt_cnts.kpc_prilevel++;
			return;
		}
		if (!interrupts_enabled()) {
			/*
			 * Can't preempt while running with ints disabled
			 */
			kpreempt_cnts.kpc_prilevel++;
			return;
		}
		if (asyncspl != KPREEMPT_SYNC)
			kpreempt_cnts.kpc_apreempt++;
		else
			kpreempt_cnts.kpc_spreempt++;

		ct->t_preempt++;
		preempt();
		ct->t_preempt--;
	} while (CPU->cpu_kprunrun);
}


static uint64_t fasttrap_null(void)
{
	return (uint64_t)-1;
}

static uint64_t fasttrap_gethrtime(void)
{
	return (uint64_t)gethrtime();
}

static uint64_t fasttrap_gethrvtime(void)
{
	hrtime_t hrt = gethrtime_unscaled();
	kthread_t *ct = curthread;
	klwp_t *lwp = ttolwp(ct);
	hrt -= lwp->lwp_mstate.ms_state_start;
	hrt += lwp->lwp_mstate.ms_acct[LWP_USER];
	scalehrtime(&hrt);
	return (uint64_t)hrt;
}

extern uint64_t fasttrap_gethrestime(void);
extern uint64_t getlgrp(void);

uint64_t (*fasttrap_table[])() = {
	fasttrap_null,
	fasttrap_gethrtime,
	fasttrap_gethrvtime,
	fasttrap_gethrestime,
	getlgrp,
};
