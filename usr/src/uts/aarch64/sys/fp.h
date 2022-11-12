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
 */

#ifndef _SYS_FP_H
#define _SYS_FP_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL
#define FPCR_AHP	(1u<<26)	// Alternative half-precision
					// 0: IEEE half-precision format
					// 1: Alternative half-precision format

#define FPCR_DN		(1u<<25)	// Default NaN mode
					// 0: disable
					// 1: enable. Default NaN

#define FPCR_FZ		(1u<<24)	// Flush-to-zero mode.
					// 0: disable. fully compliant with the IEEE 754 standard
					// 1: enable

#define FPCR_RM_MASK	(3u<<22)
#define FPCR_RM_RN	(0u<<22)	// Round to Nearest
#define FPCR_RM_RP	(1u<<22)	// Round towards Plus Infinity
#define FPCR_RM_RM	(2u<<22)	// Round towards Minus Infinity
#define FPCR_RM_RZ	(3u<<22)	// Round towards Zero

#define FPCR_IDE	(1u<<15)	// Input Denormal exception trap enable
#define FPCR_IXE	(1u<<12)	// Inexact exception trap enable
#define FPCR_UFE	(1u<<11)	// Underflow exception trap enable
#define FPCR_OFE	(1u<<10)	// Overflow exception trap enable
#define FPCR_DZE	(1u<<9)		// Division by Zero exception trap enable
#define FPCR_IOE	(1u<<8)		// Invalid Operation exception trap enable

#define FPSR_N		(1u<<31)
#define FPSR_Z		(1u<<30)
#define FPSR_C		(1u<<29)
#define FPSR_V		(1u<<28)
#define FPSR_QC		(1u<<27)
#define FPSR_IDC	(1u<<7)		// Input Denormal exception cumulative
#define FPSR_IXC	(1u<<4)		// Inexact exception cumulative
#define FPSR_UFC	(1u<<3)		// Underflow exception cumulative
#define FPSR_OFC	(1u<<2)		// Overflow exception cumulative
#define FPSR_DZC	(1u<<1)		// Division by Zero exception cumulative
#define FPSR_IOC	(1u<<0)		// Invalid Operation exception cumulative

#define FPCR_INIT (FPCR_RM_RN)

extern void fp_save(pcb_t *pcb);
extern void fp_restore(pcb_t *pcb);
extern void fp_init(void);
extern void fp_free(pcb_t *pcb, int isexec);
extern int fp_fenflt(void);

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_FP_H */
