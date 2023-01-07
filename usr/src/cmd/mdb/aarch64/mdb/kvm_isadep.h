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

#ifndef	_KVM_ISADEP_H
#define	_KVM_ISADEP_H

#include <mdb/mdb_modapi.h>

#include <sys/privregs.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern int kt_cpustack(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int kt_cpuregs(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int kt_regs(uintptr_t, uint_t, int, const mdb_arg_t *);

extern int kt_kvmregs(mdb_tgt_t *, uint_t, mdb_tgt_gregset_t *);
extern void kt_regs_to_kregs(struct regs *, mdb_tgt_gregset_t *);

extern int kt_putareg(mdb_tgt_t *, mdb_tgt_tid_t, const char *, mdb_tgt_reg_t);
extern int kt_getareg(mdb_tgt_t *, mdb_tgt_tid_t,
    const char *, mdb_tgt_reg_t *);

extern int kt_stack(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int kt_stackv(uintptr_t, uint_t, int, const mdb_arg_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _KVM_ISADEP_H */
