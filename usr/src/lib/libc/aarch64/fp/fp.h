/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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

#ifndef _FP_FP_H
#define	_FP_FP_H

#include <sys/controlregs.h>
#include <sys/fp.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	FPCR_TRAP_SHIFT	8
#define	FPCR_TRAP_MASK	(FPCR_IDE | FPCR_IXE | FPCR_UFE | FPCR_OFE | \
    FPCR_DZE | FPCR_IOE)
#define	FPCR_MASK	(FPCR_TRAP_MASK | FPCR_RM_MASK)

#define	FPSR_TRAP_MASK	(FPSR_IDC | FPSR_IXC | FPSR_UFC | FPSR_OFC |	\
    FPSR_DZC | FPSR_IOC)
#define	FPSR_MASK	(FPSR_TRAP_MASK | FPSR_QC | FPSR_N | FPSR_Z |	\
    FPSR_C | FPSR_V)


#ifdef __cplusplus
}
#endif

#endif /* _FP_FP_H */
