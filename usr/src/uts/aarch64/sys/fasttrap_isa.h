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

#ifndef	_FASTTRAP_ISA_H
#define	_FASTTRAP_ISA_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* svc #(T_DTRACE_PID) */
#define	FASTTRAP_INSTR			0xd4180001
/* svc #(T_DTRACE_RET) */
#define	FASTTRAP_RET_INSTR		0xd4180021

/* two instructions + sizeof(tcb_t) , though not used right now */
#define	FASTTRAP_SUNWDTRACE_SIZE	(sizeof (uint32_t) * 2) +	\
	sizeof (uintptr_t) * 2

typedef uint32_t	fasttrap_instr_t;

typedef struct fasttrap_machtp {
	uint32_t	ftmt_instr;	/* orig. instr. */
	uint8_t		ftmt_type;	/* emulation type */
} fasttrap_machtp_t;

#define	ftt_instr	ftt_mtp.ftmt_instr
#define	ftt_type	ftt_mtp.ftmt_type

#define	FASTTRAP_RETURN_AFRAMES		4
#define	FASTTRAP_ENTRY_AFRAMES		3
#define	FASTTRAP_OFFSET_AFRAMES		3


enum {
	FASTTRAP_T_COMMON,
	FASTTRAP_T_RET,
	FASTTRAP_T_BR,
	FASTTRAP_T_BLR,
	FASTTRAP_T_B,
	FASTTRAP_T_BL,
	FASTTRAP_T_B_COND,
	FASTTRAP_T_TBZ,
	FASTTRAP_T_CBZ,
	FASTTRAP_T_LDR_LITERAL,
	FASTTRAP_T_ADR,
};

#ifdef	__cplusplus
}
#endif

#endif	/* _FASTTRAP_ISA_H */
