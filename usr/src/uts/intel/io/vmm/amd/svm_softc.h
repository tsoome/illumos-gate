/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2013 Anish Gupta (akgupt3@gmail.com)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef	_SVM_SOFTC_H_
#define	_SVM_SOFTC_H_

#define	SVM_IO_BITMAP_SIZE	(3 * PAGE_SIZE)
#define	SVM_MSR_BITMAP_SIZE	(2 * PAGE_SIZE)

#include <sys/hma.h>

#include "vmcb.h"
#include "svm_pmu.h"

/* This must match HOST_MSR_NUM in svm_msr.c (where it is CTASSERTed) */
#define	SVM_HOST_MSR_NUM	4

/*
 * XXX separate out 'struct vmcb' from 'svm_vcpu' to avoid wasting space
 * due to VMCB alignment requirements.
 */
struct svm_vcpu {
	struct vmcb	vmcb;	 /* hardware saved vcpu context */
	struct svm_regctx swctx; /* software saved vcpu context */
	uint64_t	vmcb_pa; /* VMCB physical address */
	uint64_t	nextrip; /* next instruction to be executed by guest */
	int		lastcpu; /* host cpu that the vcpu last ran on */
	uint32_t	dirty;	 /* state cache bits that must be cleared */
	uint64_t	nptgen;	 /* page table gen when the vcpu last ran */
	hma_svm_asid_t	hma_asid;
	boolean_t	loaded;
	struct svm_pmu_vcpu pmu;
} __aligned(PAGE_SIZE);

/*
 * SVM softc, one per virtual machine.
 */
struct svm_softc {
	uint8_t apic_page[VM_MAXCPU][PAGE_SIZE];
	struct svm_vcpu vcpu[VM_MAXCPU];
	uint64_t	nptp;		/* nested page table (host PA) */
	uint8_t		*iopm_bitmap;	/* shared by all vcpus */
	uint8_t		*msr_bitmap;	/* shared by all vcpus */
	struct vm	*vm;
	uint64_t	host_msrs[VM_MAXCPU][SVM_HOST_MSR_NUM];
	svm_pmu_flavor_t pmu_flavor;
};

/*
 * Since the VMCB must be page-aligned, and is the first member of svm_vcpu,
 * which is slated to be page-aligned, this is a belt-and-suspenders check to
 * see that such alignment instructions are being heeded.
 */
CTASSERT((offsetof(struct svm_softc, nptp) & PAGE_MASK) == 0);

static __inline struct svm_vcpu *
svm_get_vcpu(struct svm_softc *sc, int vcpu)
{
	return (&(sc->vcpu[vcpu]));
}

static __inline struct vmcb *
svm_get_vmcb(struct svm_softc *sc, int vcpu)
{
	return (&(sc->vcpu[vcpu].vmcb));
}

static __inline struct vmcb_state *
svm_get_vmcb_state(struct svm_softc *sc, int vcpu)
{
	return (&(sc->vcpu[vcpu].vmcb.state));
}

static __inline struct vmcb_ctrl *
svm_get_vmcb_ctrl(struct svm_softc *sc, int vcpu)
{
	return (&(sc->vcpu[vcpu].vmcb.ctrl));
}

static __inline struct svm_regctx *
svm_get_guest_regctx(struct svm_softc *sc, int vcpu)
{
	return (&(sc->vcpu[vcpu].swctx));
}

static __inline struct svm_pmu_vcpu *
svm_get_pmu(struct svm_softc *sc, int vcpu)
{
	return (&(sc->vcpu[vcpu].pmu));
}

static __inline void
svm_set_dirty(struct svm_softc *sc, int vcpu, uint32_t dirtybits)
{
	struct svm_vcpu *vcpustate = svm_get_vcpu(sc, vcpu);

	vcpustate->dirty |= dirtybits;
}

static __inline void
svm_apply_dirty(struct svm_softc *sc, int vcpu)
{
	struct svm_vcpu *vcpustate = svm_get_vcpu(sc, vcpu);
	struct vmcb_ctrl *ctrl = svm_get_vmcb_ctrl(sc, vcpu);

	ctrl->vmcb_clean = ~vcpustate->dirty;
	vcpustate->dirty = 0;
}

int svm_get_intercept(struct svm_softc *, int, int, uint32_t);
void svm_set_intercept(struct svm_softc *, int, int, uint32_t, int);

static __inline void
svm_disable_intercept(struct svm_softc *sc, int vcpu, int off, uint32_t bitmask)
{
	svm_set_intercept(sc, vcpu, off, bitmask, 0);
}

static __inline void
svm_enable_intercept(struct svm_softc *sc, int vcpu, int off, uint32_t bitmask)
{
	svm_set_intercept(sc, vcpu, off, bitmask, 1);
}

#endif /* _SVM_SOFTC_H_ */
