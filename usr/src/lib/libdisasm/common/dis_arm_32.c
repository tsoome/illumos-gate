/*
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */
/*
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 * Copyright (c) 2015 Josef 'Jeff' Sipek <jeffpc@josefsipek.net>
 */

/*
 * This provides basic support for disassembling arm instructions. This is
 * derived from the arm reference manual (generic), chapter A3 (ARM DDI 0100l).
 * All instructions come in as uint32_t's.
 */

#include <libdisasm.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/byteorder.h>

#include "libdisasm_impl.h"

extern size_t strlen(const char *);
extern size_t strlcat(char *, const char *, size_t);

/*
 * Condition code mask and shift, aka bits 28-31.
 */
#define	ARM_CC_MASK	0xf0000000
#define	ARM_CC_SHIFT	28

/*
 * First level of decoding, aka bits 25-27.
 */
#define	ARM_L1_DEC_MASK	0x0e000000
#define	ARM_L1_DEC_SHIFT	25

/*
 * Masks and values for the 0b000 l1 group
 */
#define	ARM_L1_0_B4_MASK	0x00000010
#define	ARM_L1_0_B7_MASK	0x00000080
#define	ARM_L1_0_OPMASK	0x01800000
#define	ARM_L1_0_SPECOP	0x01000000
#define	ARM_L1_0_SMASK	0x00100000
#define	ARM_L1_0_ELS_MASK	0x00000060

/*
 * Masks and values for the 0b001 l1 group.
 */
#define	ARM_L1_1_OPMASK	0x01800000
#define	ARM_L1_1_SPECOP	0x01000000
#define	ARM_L1_1_SMASK	0x00100000
#define	ARM_L1_1_UNDEF_MASK	0x00200000

/*
 * Masks and values for the 0b011 l1 group
 */
#define	ARM_L1_3_B4_MASK	0x00000010
#define	ARM_L1_3_ARCHUN_MASK	0x01f000f0

/*
 * Masks for the 0b111 l1 group
 */
#define	ARM_L1_7_COPROCMASK	0x00000010
#define	ARM_L1_7_SWINTMASK	0x01000000

/*
 * Masks for the data processing instructions (dpi)
 */
#define	ARM_DPI_OPCODE_MASK	0x01e00000
#define	ARM_DPI_OPCODE_SHIFT	21
#define	ARM_DPI_IBIT_MASK	0x02000000
#define	ARM_DPI_SBIT_MASK	0x00100000
#define	ARM_DPI_RN_MASK		0x000f0000
#define	ARM_DPI_RN_SHIFT	16
#define	ARM_DPI_RD_MASK		0x0000f000
#define	ARM_DPI_RD_SHIFT	12
#define	ARM_DPI_BIT4_MASK	0x00000010

#define	ARM_DPI_IMM_ROT_MASK	0x00000f00
#define	ARM_DPI_IMM_ROT_SHIFT	8
#define	ARM_DPI_IMM_VAL_MASK	0x000000ff

#define	ARM_DPI_IMS_SHIMM_MASK	0x00000f80
#define	ARM_DPI_IMS_SHIMM_SHIFT	7
#define	ARM_DPI_IMS_SHIFT_MASK	0x00000060
#define	ARM_DPI_IMS_SHIFT_SHIFT	5
#define	ARM_DPI_IMS_RM_MASK	0x0000000f

#define	ARM_DPI_REGS_RS_MASK	0x00000f00
#define	ARM_DPI_REGS_RS_SHIFT	8
#define	ARM_DPI_REGS_SHIFT_MASK	0x00000060
#define	ARM_DPI_REGS_SHIFT_SHIFT	5
#define	ARM_DPI_REGS_RM_MASK	0x0000000f

/*
 * Definitions for the word and byte LDR and STR instructions
 */
#define	ARM_LS_IBIT_MASK	0x02000000
#define	ARM_LS_PBIT_MASK	0x01000000
#define	ARM_LS_UBIT_MASK	0x00800000
#define	ARM_LS_BBIT_MASK	0x00400000
#define	ARM_LS_WBIT_MASK	0x00200000
#define	ARM_LS_LBIT_MASK	0x00100000
#define	ARM_LS_RN_MASK		0x000f0000
#define	ARM_LS_RN_SHIFT		16
#define	ARM_LS_RD_MASK		0x0000f000
#define	ARM_LS_RD_SHIFT		12

#define	ARM_LS_IMM_MASK		0x00000fff

#define	ARM_LS_REG_RM_MASK	0x0000000f
#define	ARM_LS_REG_NRM_MASK	0x00000ff0

#define	ARM_LS_SCR_SIMM_MASK	0x00000f80
#define	ARM_LS_SCR_SIMM_SHIFT	7
#define	ARM_LS_SCR_SCODE_MASK	0x00000060
#define	ARM_LS_SCR_SCODE_SHIFT	5
#define	ARM_LS_SCR_RM_MASK	0x0000000f

/*
 * Masks for the Load and Store multiple instructions.
 */
#define	ARM_LSM_PBIT_MASK	0x01000000
#define	ARM_LSM_UBIT_MASK	0x00800000
#define	ARM_LSM_SBIT_MASK	0x00400000
#define	ARM_LSM_WBIT_MASK	0x00200000
#define	ARM_LSM_LBIT_MASK	0x00100000
#define	ARM_LSM_RN_MASK		0x000f0000
#define	ARM_LSM_RN_SHIFT	16
#define	ARM_LSM_RLIST_MASK	0x0000ffff
#define	ARM_LSM_ADDR_MASK	0x01800000
#define	ARM_LSM_ADDR_SHIFT	23

/*
 * Masks for the Extended and Misc. Loads and stores. This is the extension
 * space from figure A3-5. Most of them are handled by arm_dis_els() with the
 * exception or swap / swap byte and load/store register exclusive which due to
 * its nature is handled elsewhere.
 */
#define	ARM_ELS_SWAP_MASK	0x01b00000
#define	ARM_ELS_SWAP_BYTE_MASK	0x00400000
#define	ARM_ELS_IS_SWAP		0x01000000
#define	ARM_ELS_EXCL_MASK	0x01800000
#define	ARM_ELS_PBIT_MASK	0x01000000
#define	ARM_ELS_UBIT_MASK	0x00800000
#define	ARM_ELS_IBIT_MASK	0x00400000
#define	ARM_ELS_WBIT_MASK	0x00200000
#define	ARM_ELS_LBIT_MASK	0x00100000
#define	ARM_ELS_SBIT_MASK	0x00000040
#define	ARM_ELS_HBIT_MASK	0x00000020
#define	ARM_ELS_RN_MASK		0x000f0000
#define	ARM_ELS_RN_SHIFT	16
#define	ARM_ELS_RD_MASK		0x0000f000
#define	ARM_ELS_RD_SHIFT	12
#define	ARM_ELS_UP_AM_MASK	0x00000f00
#define	ARM_ELS_UP_AM_SHIFT	8
#define	ARM_ELS_LOW_AM_MASK	0x0000000f

/*
 * Multiply instruction extensino space masks and values
 */
#define	ARM_EMULT_UNBIT_MASK	0x00400000
#define	ARM_EMULT_ABIT_MASK	0x00200000
#define	ARM_EMULT_SBIT_MASK	0x00100000
#define	ARM_EMULT_RD_MASK	0x000f0000
#define	ARM_EMULT_RD_SHIFT	16
#define	ARM_EMULT_RN_MASK	0x0000f000
#define	ARM_EMULT_RN_SHIFT	12
#define	ARM_EMULT_RS_MASK	0x00000f00
#define	ARM_EMULT_RS_SHIFT	8
#define	ARM_EMULT_RM_MASK	0x0000000f
#define	ARM_EMULT_MA_MASK	0x0fc00000
#define	ARM_EMULT_UMA_MASK	0x0ff00000
#define	ARM_EMULT_UMA_TARG	0x00400000
#define	ARM_EMULT_MAL_MASK	0x0f800000
#define	ARM_EMULT_MAL_TARG	0x00800000

/*
 * Here we have the masks and target values to indicate instructions from the
 * Control and DSP extension space. There are a bunch of not quite related
 * instructions, but that's okay. That's how this thing always rolls.
 *
 * The ARM_CDSP_STATUS_MASK and TARG do not catch the move immediate to status
 * register. That's okay because they get handled and separated out in arm_dis.
 */
#define	ARM_CDSP_STATUS_MASK	0x0f9000f0
#define	ARM_CDSP_STATUS_TARG	0x01000000
#define	ARM_CDSP_BEX_UP_MASK	0x0ff00000	/* Branch/exchg/link instrs */
#define	ARM_CDSP_BEX_UP_TARG	0x01200000
#define	ARM_CDSP_BEX_LOW_MASK	0x000000f0
#define	ARM_CDSP_BEX_NLOW_TARG	0x00000000	/* Here the target is inverse */
#define	ARM_CDSP_CLZ_MASK	0x0ff000f0	/* Count leading zeros */
#define	ARM_CDSP_CLZ_TARG	0x01200030
#define	ARM_CDSP_SAT_MASK	0x0f9000f0	/* Saturating add/subtract */
#define	ARM_CDSP_SAT_TARG	0x01000050
#define	ARM_CDSP_BKPT_MASK	0x0ff000f0	/* Software breakpoint */
#define	ARM_CDSP_BKPT_TARG	0x01200070
#define	ARM_CDSP_SMUL_MASK	0x0f900090	/* Signed multiplies (type 2) */
#define	ARM_CDSP_SMUL_TARG	0x01000080

#define	ARM_CDSP_RN_MASK	0x000f0000
#define	ARM_CDSP_RN_SHIFT	16
#define	ARM_CDSP_RD_MASK	0x0000f000
#define	ARM_CDSP_RD_SHIFT	12
#define	ARM_CDSP_RS_MASK	0x00000f00
#define	ARM_CDSP_RS_SHIFT	8
#define	ARM_CDSP_RM_MASK	0x0000000f

#define	ARM_CDSP_STATUS_RBIT	0x00400000
#define	ARM_CDSP_MRS_MASK	0x00300000	/* Ditinguish MRS and MSR */
#define	ARM_CDSP_MRS_TARG	0x00000000
#define	ARM_CDSP_MSR_F_MASK	0x000f0000
#define	ARM_CDSP_MSR_F_SHIFT	16
#define	ARM_CDSP_MSR_RI_MASK	0x00000f00
#define	ARM_CDSP_MSR_RI_SHIFT	8
#define	ARM_CDSP_MSR_IMM_MASK	0x000000ff
#define	ARM_CDSP_MSR_ISIMM_MASK	0x02000000

#define	ARM_CDSP_BEX_TYPE_MASK	0x000000f0
#define	ARM_CDSP_BEX_TYPE_SHIFT	4
#define	ARM_CDSP_BEX_TYPE_X	1
#define	ARM_CDSP_BEX_TYPE_J	2
#define	ARM_CDSP_BEX_TYPE_L	3

#define	ARM_CDSP_SAT_OP_MASK	0x00600000
#define	ARM_CDSP_SAT_OP_SHIFT	21

#define	ARM_CDSP_BKPT_UIMM_MASK	0x000fff00
#define	ARM_CDSP_BKPT_UIMM_SHIFT	8
#define	ARM_CDSP_BKPT_LIMM_MASK	0x0000000f

#define	ARM_CDSP_SMUL_OP_MASK	0x00600000
#define	ARM_CDSP_SMUL_OP_SHIFT	21
#define	ARM_CDSP_SMUL_X_MASK	0x00000020
#define	ARM_CDSP_SMUL_Y_MASK	0x00000040

/*
 * Interrupt
 */
#define	ARM_SWI_IMM_MASK	0x00ffffff

/*
 * Branch and Link pieces.
 */
#define	ARM_BRANCH_LBIT_MASK	0x01000000
#define	ARM_BRANCH_IMM_MASK	0x00ffffff
#define	ARM_BRANCH_SIGN_MASK	0x00800000
#define	ARM_BRANCH_POS_SIGN	0x00ffffff
#define	ARM_BRANCH_NEG_SIGN	0xff000000
#define	ARM_BRANCH_SHIFT	2

/*
 * Unconditional instructions
 */
#define	ARM_UNI_CPS_MASK	0x0ff10020	/* Change processor state */
#define	ARM_UNI_CPS_TARG	0x01000000
#define	ARM_UNI_SE_MASK		0x0fff0078	/* Set endianess */
#define	ARM_UNI_SE_TARG		0x01010000
#define	ARM_UNI_PLD_MASK	0x0d70f000	/* Cach preload */
#define	ARM_UNI_PLD_TARG	0x0550f000
#define	ARM_UNI_SRS_MASK	0x0e5f0f00	/* Save return state */
#define	ARM_UNI_SRS_TARG	0x084d0500
#define	ARM_UNI_RFE_MASK	0x0e500f00	/* Return from exception */
#define	ARM_UNI_RFE_TARG	0x08100a00
#define	ARM_UNI_BLX_MASK	0x0e000000	/* Branch with Link / Thumb */
#define	ARM_UNI_BLX_TARG	0x0a000000
#define	ARM_UNI_CODRT_MASK	0x0fe00000	/* double reg to coproc */
#define	ARM_UNI_CODRT_TARG	0x0c400000
#define	ARM_UNI_CORT_MASK	0x0f000010	/* single reg to coproc */
#define	ARM_UNI_CORT_TARG	0x0e000010
#define	ARM_UNI_CODP_MASK	0x0f000010	/* coproc data processing */
#define	ARM_UNI_CODP_TARG	0x0e000000
#define	ARM_UNI_CLREX_MASK	0x057ff0ff	/* Clear exclusive */
#define	ARM_UNI_CLREX_TARG	0x057ff01f
#define	ARM_UNI_DSB_MASK	0x057ff0f0	/* Data sync barrier */
#define	ARM_UNI_DSB_TARG	0x057ff040
#define	ARM_UNI_DMB_MASK	0x057ff0f0	/* Data memory barrier */
#define	ARM_UNI_DMB_TARG	0x057ff050
#define	ARM_UNI_ISB_MASK	0x057ff0f0	/* Instruction sync barrier */
#define	ARM_UNI_ISB_TARG	0x057ff060

#define	ARM_UNI_CPS_IMOD_MASK	0x000c0000
#define	ARM_UNI_CPS_IMOD_SHIFT	18
#define	ARM_UNI_CPS_MMOD_MASK	0x00020000
#define	ARM_UNI_CPS_A_MASK	0x00000100
#define	ARM_UNI_CPS_I_MASK	0x00000080
#define	ARM_UNI_CPS_F_MASK	0x00000040
#define	ARM_UNI_CPS_MODE_MASK	0x0000001f

#define	ARM_UNI_SE_BE_MASK	0x00000200

#define	ARM_UNI_SRS_WBIT_MASK	0x00200000
#define	ARM_UNI_SRS_MODE_MASK	0x0000000f

#define	ARM_UNI_RFE_WBIT_MASK	0x00200000

#define	ARM_UNI_BLX_IMM_MASK	0x00ffffff

#define	ARM_UNI_DXB_OPT_MASK	0x0000000f

/*
 * Definitions of the ARM Media instruction extension space.
 */
#define	ARM_MEDIA_L1_MASK	0x01800000	/* First level breakdown */
#define	ARM_MEDIA_L1_SHIFT	23

#define	ARM_MEDIA_OP1_MASK	0x00700000
#define	ARM_MEDIA_OP1_SHIFT	20
#define	ARM_MEDIA_OP2_MASK	0x000000e0
#define	ARM_MEDIA_OP2_SHIFT	5

#define	ARM_MEDIA_RN_MASK	0x000f0000
#define	ARM_MEDIA_RN_SHIFT	16
#define	ARM_MEDIA_RD_MASK	0x0000f000
#define	ARM_MEDIA_RD_SHIFT	12
#define	ARM_MEDIA_RS_MASK	0x00000f00
#define	ARM_MEDIA_RS_SHIFT	8
#define	ARM_MEDIA_RM_MASK	0x0000000f

#define	ARM_MEDIA_MULT_X_MASK	0x00000020

#define	ARM_MEDIA_HPACK_MASK	0x00700020	/* Halfword pack */
#define	ARM_MEDIA_HPACK_TARG	0x00000000
#define	ARM_MEDIA_WSAT_MASK	0x00200020	/* Word saturate */
#define	ARM_MEDIA_WSAT_TARG	0x00200000
#define	ARM_MEDIA_PHSAT_MASK	0x003000e0	/* Parallel halfword saturate */
#define	ARM_MEDIA_PHSAT_TARG	0x00200020
#define	ARM_MEDIA_REV_MASK	0x007000e0	/* Byte rev. word */
#define	ARM_MEDIA_REV_TARG	0x00300020
#define	ARM_MEDIA_BRPH_MASK	0x007000e0	/* Byte rev. packed halfword */
#define	ARM_MEDIA_BRPH_TARG	0x003000a0
#define	ARM_MEDIA_BRSH_MASK	0x007000e0	/* Byte rev. signed halfword */
#define	ARM_MEDIA_BRSH_TARG	0x007000a0
#define	ARM_MEDIA_SEL_MASK	0x008000e0	/* Select bytes */
#define	ARM_MEDIA_SEL_TARG	0x000000a0
#define	ARM_MEDIA_SZE_MASK	0x000000e0	/* Sign/zero extend */
#define	ARM_MEDIA_SZE_TARG	0x00000030

#define	ARM_MEDIA_HPACK_OP_MASK	0x00000040
#define	ARM_MEDIA_HPACK_SHIFT_MASK	0x00000f80
#define	ARM_MEDIA_HPACK_SHIFT_IMM	7

#define	ARM_MEDIA_SAT_U_MASK	0x00400000
#define	ARM_MEDIA_SAT_IMM_MASK	0x001f0000
#define	ARM_MEDIA_SAT_IMM_SHIFT	16
#define	ARM_MEDIA_SAT_SHI_MASK	0x00000f80
#define	ARM_MEDIA_SAT_SHI_SHIFT	7
#define	ARM_MEDIA_SAT_STYPE_MASK	0x00000040

#define	ARM_MEDIA_SZE_S_MASK	0x00400000
#define	ARM_MEDIA_SZE_OP_MASK	0x00300000
#define	ARM_MEDIA_SZE_OP_SHIFT	20
#define	ARM_MEDIA_SZE_ROT_MASK	0x00000c00
#define	ARM_MEDIA_SZE_ROT_SHIFT	10

/*
 * Definitions for coprocessor instructions
 */
#define	ARM_COPROC_RN_MASK	0x000f0000
#define	ARM_COPROC_RN_SHIFT	16
#define	ARM_COPROC_RD_MASK	0x0000f000
#define	ARM_COPROC_RD_SHIFT	12
#define	ARM_COPROC_RM_MASK	0x0000000f
#define	ARM_COPROC_NUM_MASK	0x00000f00
#define	ARM_COPROC_NUM_SHIFT	8

#define	ARM_COPROC_CDP_OP1_MASK	0x00f00000
#define	ARM_COPROC_CDP_OP1_SHIFT	20
#define	ARM_COPROC_CDP_OP2_MASK	0x000000e0
#define	ARM_COPROC_CDP_OP2_SHIFT	5

#define	ARM_COPROC_CRT_OP1_MASK	0x00e00000
#define	ARM_COPROC_CRT_OP1_SHIFT	21
#define	ARM_COPROC_CRT_OP2_MASK	0x000000e0
#define	ARM_COPROC_CRT_OP2_SHIFT	5
#define	ARM_COPROC_CRT_DIR_MASK	0x00100000	/* MCR or MRC */

#define	ARM_COPROC_DRT_MASK	0x01e00000
#define	ARM_COPROC_DRT_TARG	0x00400000
#define	ARM_COPROC_DRT_OP_MASK	0x000000f0
#define	ARM_COPROC_DRT_OP_SHIFT	4
#define	ARM_COPROC_DRT_DIR_MASK	0x00100000	/* MCRR or MRRC */

#define	ARM_COPROC_LS_P_MASK	0x01000000
#define	ARM_COPROC_LS_U_MASK	0x00800000
#define	ARM_COPROC_LS_N_MASK	0x00400000
#define	ARM_COPROC_LS_W_MASK	0x00200000
#define	ARM_COPROC_LS_L_MASK	0x00100000
#define	ARM_COPROC_LS_IMM_MASK	0x000000ff

/*
 * This is the table of condition codes that instructions might have. Every
 * instruction starts with a four bit code. The last two codes are special.
 * 0b1110 is the always condition. Therefore we leave off its mneomic extension
 * and treat it as the empty string. The condition code 0b1111 takes us to a
 * separate series of encoded instructions and therefore we go elsewhere with
 * them.
 */
static const char *arm_cond_names[] = {
	"eq",		/* Equal */
	"ne",		/* Not Equal */
	"cs/hs",	/* Carry set/unsigned higher or same */
	"cc/lo",	/* Carry clear/unsigned lower */
	"mi",		/* Minus/negative */
	"pl",		/* Plus/positive or zero */
	"vs",		/* Overflow */
	"vc",		/* No overflow */
	"hi",		/* Unsigned higher */
	"ls",		/* Unsigned lower or same */
	"ge",		/* Signed greater than or equal */
	"lt",		/* Signed less than */
	"gt",		/* Signed greater than */
	"le",		/* Signed less than or equal */
	"",		/* AL - Always (unconditional) */
	NULL		/* Not a condition code */
};

typedef enum arm_cond_code {
	ARM_COND_EQ,	/* Equal */
	ARM_COND_NE,	/* Not Equal */
	ARM_COND_CSHS,	/* Carry set/unsigned higher or same */
	ARM_COND_CCLO,	/* Carry clear/unsigned lower */
	ARM_COND_MI,	/* Minus/negative */
	ARM_COND_PL,	/* Plus/positive or zero */
	ARM_COND_VS,	/* Overflow */
	ARM_COND_VC,	/* No overflow */
	ARM_COND_HI,	/* Unsigned higher */
	ARM_COND_LS,	/* Unsigned lower or same */
	ARM_COND_GE,	/* Signed greater than or equal */
	ARM_COND_LT,	/* Signed less than */
	ARM_COND_GT,	/* Signed greater than */
	ARM_COND_LE,	/* Signed less than or equal */
	ARM_COND_AL,	/* AL - Always (unconditional) */
	ARM_COND_NACC	/* Not a condition code */
} arm_cond_code_t;

/*
 * Registers are encoded surprisingly sanely. It's a 4-bit value that indicates
 * which register in question we're working with.
 */
static const char *arm_reg_names[] = {
	"r0",
	"r1",
	"r2",
	"r3",
	"r4",
	"r5",
	"r6",
	"r7",
	"r8",
	"fp",	/* Alt for r9 */
	"r10",
	"r11",
	"ip",	/* Alt for r12 */
	"sp",	/* Alt for r13 */
	"lr",	/* Alt for r14 */
	"pc"	/* Alt for r15 */
};

typedef enum arm_reg {
	ARM_REG_R0,
	ARM_REG_R1,
	ARM_REG_R2,
	ARM_REG_R3,
	ARM_REG_R4,
	ARM_REG_R5,
	ARM_REG_R6,
	ARM_REG_R7,
	ARM_REG_R8,
	ARM_REG_R9,
	ARM_REG_R10,
	ARM_REG_R11,
	ARM_REG_R12,
	ARM_REG_R13,
	ARM_REG_R14,
	ARM_REG_R15
} arm_reg_t;

/*
 * Default coprocessor names
 */
static const char *arm_coproc_names[] = {
	"p0",
	"p1",
	"p2",
	"p3",
	"p4",
	"p5",
	"p6",
	"p7",
	"p8",
	"p9",
	"p10",
	"p11",
	"p12",
	"p13",
	"p14",
	"p15"
};

/*
 * These are the opcodes for the instructions which are considered data
 * processing instructions.
 */
static const char *arm_dpi_opnames[] = {
	"and",	/* Logical AND */
	"eor",	/* Logical Exclusive OR */
	"sub",	/* Subtract */
	"rsb",	/* Reverse Subtract */
	"add",	/* Add */
	"adc",	/* Add with Carry */
	"sbc",	/* Subtract with Carry */
	"rsc",	/* Reverse Subtract with Carry */
	"tst",	/* Test */
	"teq",	/* Test Equivalence */
	"cmp",	/* Compare */
	"cmn",	/* Compare negated */
	"orr",	/* Logical (inclusive) OR */
	"mov",	/* Move */
	"bic",	/* Bit clear */
	"mvn"	/* Move not */
};

typedef enum arm_dpi_opcode {
	DPI_OP_AND,	/* Logical AND */
	DPI_OP_EOR,	/* Logical Exclusive OR */
	DPI_OP_SUB,	/* Subtract */
	DPI_OP_RSB,	/* Reverse Subtract */
	DPI_OP_ADD,	/* Add */
	DPI_OP_ADC,	/* Add with Carry */
	DPI_OP_SBC,	/* Subtract with Carry */
	DPI_OP_RSC,	/* Reverse Subtract with Carry */
	DPI_OP_TST,	/* Test */
	DPI_OP_TEQ,	/* Test Equivalence */
	DPI_OP_CMP,	/* Compare */
	DPI_OP_CMN,	/* Compare negated */
	DPI_OP_ORR,	/* Logical (inclusive) OR */
	DPI_OP_MOV,	/* Move */
	DPI_OP_BIC,	/* Bit clear */
	DPI_OP_MVN	/* Move not */
} arm_dpi_opcode_t;

const char *arm_dpi_shifts[] = {
	"lsl",	/* Logical shift left */
	"lsr",	/* Logical shift right */
	"asr",	/* Arithmetic shift right */
	"ror",	/* Rotate right */
	"rrx"	/* Rotate right with extend. This is a special case of ror */
};

typedef enum arm_dpi_shift_code {
	DPI_S_LSL,	/* Logical shift left */
	DPI_S_LSR,	/* Logical shift right */
	DPI_S_ASR,	/* Arithmetic shift right */
	DPI_S_ROR,	/* Rotate right */
	DPI_S_RRX,	/* Rotate right with extend. Special case of ror */
	DPI_S_NONE	/* No shift code */
} arm_dpi_shift_code_t;

#define	ARM_DPI_SHIFTER_IMM32	0x00
#define	ARM_DPI_SHIFTER_SIMM	0x01
#define	ARM_DPI_SHIFTER_SREG	0x02

typedef struct arm_dpi_shifter_imm {
	uint8_t dpisi_rot;			/* Rotation amount */
	uint8_t dpisi_imm;			/* Immediate value */
} arm_dpi_shifter_imm_t;

typedef struct arm_dpi_shifter_simm {
	uint8_t dpiss_imm;			/* Shift value */
	arm_dpi_shift_code_t dpiss_code;	/* Shift type */
	arm_reg_t dpiss_targ;			/* Target register */
} arm_dpi_shifter_simm_t;

typedef struct arm_dpi_shifter_sreg {
	arm_reg_t dpisr_val;			/* reg with shift value */
	arm_dpi_shift_code_t dpisr_code;	/* Shift type */
	arm_reg_t dpisr_targ;			/* Target register */
} arm_dpi_shifter_sreg_t;

typedef struct arm_dpi_inst {
	arm_dpi_opcode_t dpii_op;		/* dpi opcode */
	arm_cond_code_t dpii_cond;		/* condition code */
	int dpii_sbit;				/* value of S bit */
	arm_reg_t dpii_rn;			/* first operand */
	arm_reg_t dpii_rd;			/* destination operand */
	int dpii_stype;				/* type of shifter */
	union {					/* shifter values */
		arm_dpi_shifter_imm_t dpii_im;
		arm_dpi_shifter_simm_t dpii_si;
		arm_dpi_shifter_sreg_t dpii_ri;
	} dpii_un;
} arm_dpi_inst_t;

/*
 * Option limitations on DMB and DSB instructions.  SY (b1111) is the default
 * and so is ommitted from output.  According to the manual any unsupported or
 * reserved options must also be executed as SY, so we fill in the blanks too.
 */
static const char *arm_uni_dxb_options[] = {
	"",
	"",
	"oshst",	/* 0010 */
	"osh",		/* 0011 */
	"",
	"",
	"nshst",	/* 0110 */
	"nsh",		/* 0111 */
	"",
	"",
	"ishst",	/* 1010 */
	"ish",		/* 1011 */
	"",
	"",
	"st",		/* 1110 */
	"",		/* 1111 (SY) */
};

/*
 * This table contains the names of the load store multiple addressing modes.
 * The P and U bits are supposed to be combined to index into this. You should
 * do this by doing P << 1 | U.
 */
static const char *arm_lsm_mode_names[] = {
	"da",
	"ia",
	"db",
	"ib"
};

/*
 * The MSR field has a four bit field mask. Each bit correspons to a letter.
 * From high to low, f, s, x, c. At least one must be specified, hence 0 is
 * NULL. The preferred manual ordering of these is csxf.
 */
static const char *arm_cdsp_msr_field_names[] = {
	NULL,
	"c",	/* 0001 */
	"x",	/* 0010 */
	"cx",	/* 0011 */
	"s",	/* 0100 */
	"cs",	/* 0101 */
	"sx",	/* 0110 */
	"csx",	/* 0111 */
	"f",	/* 1000 */
	"cf",	/* 1001 */
	"xf",	/* 1010 */
	"cxf",	/* 1011 */
	"sf",	/* 1100 */
	"csf",	/* 1101 */
	"sxf",	/* 1110 */
	"csxf"	/* 1111 */
};

/*
 * Names for specific saturating add and subtraction instructions from the
 * extended control and dsp instructino section.
 */
static const char *arm_cdsp_sat_opnames[] = {
	"add",
	"sub",
	"dadd",
	"dsub"
};

static const char *arm_padd_p_names[] = {
	NULL,	/* 000 */
	"s",	/* 001 */
	"q",	/* 010 */
	"sh",	/* 011 */
	NULL,	/* 100 */
	"u",	/* 101 */
	"uq",	/* 110 */
	"uh",	/* 111 */
};

static const char *arm_padd_i_names[] = {
	"add16",	/* 000 */
	"addsubx",	/* 001 */
	"subaddx",	/* 010 */
	"sub16",	/* 011 */
	"add8",		/* 100 */
	NULL,		/* 101 */
	NULL,		/* 110 */
	"sub8",		/* 111 */
};

static const char *arm_extend_rot_names[] = {
	"",		/* 0b00, ROR #0 */
	", ror #8",	/* 0b01 */
	", ror #16",	/* 0b10 */
	", ror #24"	/* 0b11 */
};

/*
 * There are sixteen data processing instructions (dpi). They come in a few
 * different forms which are based on whether immediate values are used and
 * whether or not some special purpose shifting is done. We use this one entry
 * point to cover all the different types.
 *
 * From the ARM arch manual:
 *
 * <opcode1>{<cond>}{S} <Rd>,<shifter>
 * <opcode1> := MOV | MVN
 * <opcode2>{<cond>} <Rn>,<shifter>
 * <opcode2> := CMP, CMN, TST, TEQ
 * <opcode3>{<cond>{S} <Rd>,<Rn>, <shifter>
 * <opcode3> := ADD | SUB | RSB | ADC | SBC | RSC | AND | BIC | EOR | ORR
 *
 * 31 - 28|27 26 |25 | 24-21  |20 | 19-16 | 15-12 | 11 - 0
 * [ cond | 0  0 | I | opcode | S | Rn    | Rd    | shifter ]
 *
 * I bit: Determines whether shifter_operand is immediate or register based
 * S bit: Determines whether or not the insn updates condition codes
 * Rn:    First source operand register
 * Rd:    Destination register
 * shifter: Specifies the second operand
 *
 * There are three primary encodings:
 *
 * 32-bit immediate
 * 31 - 28|27 26|25 |24-21 |20|19-16| 15-12|11 - 8    |7 - 0
 * [ cond | 0  0| 1 |opcode| S|Rn   | Rd   |rotate_imm|immed_8 ]
 *
 * Immediate shifts
 * 31 - 28|27 26|25 |24-21 |20|19-16|15-12|11 - 7   |6 5  |4|3-0
 * [ cond | 0  0| 0 |opcode| S|Rn   |Rd   |shift_imm|shift|0|Rm ]
 *
 * Register shifts
 * 31 - 28|27 26|25 |24-21 |20|19-16|15-12|11 - 8|7|6 5  |4|3-0
 * [ cond | 0  0| 0 |opcode| S|Rn   |Rd   |Rs    |0|shift|1|Rm ]
 *
 * There are four different kinds of shifts that work with both immediate and
 * register shifts:
 *   o Logical shift left  0b00 (LSL)
 *   o Logical shift right 0b01 (LSR)
 *   o Arithmetic shift right 0b10 (ASR)
 *   o Rotate right 0b11 (ROR)
 * There is one special shift which only works with immediate shift format:
 *   o If shift_imm = 0 and shift = 0b11, then it is a rotate right with extend
 *   (RRX)
 *
 * Finally there is one special indication for no shift. An immediate shift
 * whose shift_imm = shift = 0. This is a shortcut to a direct value from the
 * register.
 *
 * While processing this, we first build up all the information into the
 * arm_dpi_inst_t and then from there we go and print out the format based on
 * the opcode and shifter. As per the rough grammar above we have to print
 * different sets of instructions in different ways.
 */
static int
arm_dis_dpi(uint32_t in, arm_cond_code_t cond, char *buf, size_t buflen)
{
	arm_dpi_inst_t dpi_inst;
	int ibit, bit4;
	size_t len;

	dpi_inst.dpii_op = (in & ARM_DPI_OPCODE_MASK) >> ARM_DPI_OPCODE_SHIFT;
	dpi_inst.dpii_cond = cond;
	dpi_inst.dpii_rn = (in & ARM_DPI_RN_MASK) >> ARM_DPI_RN_SHIFT;
	dpi_inst.dpii_rd = (in & ARM_DPI_RD_MASK) >> ARM_DPI_RD_SHIFT;
	dpi_inst.dpii_sbit = in & ARM_DPI_SBIT_MASK;

	ibit = in & ARM_DPI_IBIT_MASK;
	bit4 = in & ARM_DPI_BIT4_MASK;

	if (ibit) {
		/* 32-bit immediate */
		dpi_inst.dpii_stype = ARM_DPI_SHIFTER_IMM32;
		dpi_inst.dpii_un.dpii_im.dpisi_rot = (in &
		    ARM_DPI_IMM_ROT_MASK) >> ARM_DPI_IMM_ROT_SHIFT;
		dpi_inst.dpii_un.dpii_im.dpisi_imm = in & ARM_DPI_IMM_VAL_MASK;
	} else if (bit4) {
		/* Register shift */
		dpi_inst.dpii_stype = ARM_DPI_SHIFTER_SREG;
		dpi_inst.dpii_un.dpii_ri.dpisr_val = (in &
		    ARM_DPI_REGS_RS_MASK) >> ARM_DPI_REGS_RS_SHIFT;
		dpi_inst.dpii_un.dpii_ri.dpisr_targ = in &
		    ARM_DPI_REGS_RM_MASK;
		dpi_inst.dpii_un.dpii_ri.dpisr_code = in &
		    ARM_DPI_REGS_SHIFT_MASK >> ARM_DPI_REGS_SHIFT_SHIFT;
	} else {
		/* Immediate shift */
		dpi_inst.dpii_stype = ARM_DPI_SHIFTER_SIMM;
		dpi_inst.dpii_un.dpii_si.dpiss_imm = (in &
		    ARM_DPI_IMS_SHIMM_MASK) >> ARM_DPI_IMS_SHIMM_SHIFT;
		dpi_inst.dpii_un.dpii_si.dpiss_code = (in &
		    ARM_DPI_IMS_SHIFT_MASK) >> ARM_DPI_IMS_SHIFT_SHIFT;
		dpi_inst.dpii_un.dpii_si.dpiss_targ = in & ARM_DPI_IMS_RM_MASK;
		if (dpi_inst.dpii_un.dpii_si.dpiss_code == DPI_S_ROR &&
		    dpi_inst.dpii_un.dpii_si.dpiss_imm == 0)
			dpi_inst.dpii_un.dpii_si.dpiss_code = DPI_S_RRX;

		if (dpi_inst.dpii_un.dpii_si.dpiss_code == DPI_S_LSL &&
		    dpi_inst.dpii_un.dpii_si.dpiss_imm == 0)
			dpi_inst.dpii_un.dpii_si.dpiss_code = DPI_S_NONE;
	}

	/*
	 * Print everything before the shifter based on the instruction
	 */
	switch (dpi_inst.dpii_op) {
	case DPI_OP_MOV:
	case DPI_OP_MVN:
		len = dis_snprintf(buf, buflen, "%s%s%s %s",
		    arm_dpi_opnames[dpi_inst.dpii_op],
		    arm_cond_names[dpi_inst.dpii_cond],
		    dpi_inst.dpii_sbit != 0 ? "s" : "",
		    arm_reg_names[dpi_inst.dpii_rd]);
		break;
	case DPI_OP_CMP:
	case DPI_OP_CMN:
	case DPI_OP_TST:
	case DPI_OP_TEQ:
		len = dis_snprintf(buf, buflen, "%s%s %s",
		    arm_dpi_opnames[dpi_inst.dpii_op],
		    arm_cond_names[dpi_inst.dpii_cond],
		    arm_reg_names[dpi_inst.dpii_rn]);
		break;
	default:
		len = dis_snprintf(buf, buflen,
		    "%s%s%s %s, %s", arm_dpi_opnames[dpi_inst.dpii_op],
		    arm_cond_names[dpi_inst.dpii_cond],
		    dpi_inst.dpii_sbit != 0 ? "s" : "",
		    arm_reg_names[dpi_inst.dpii_rd],
		    arm_reg_names[dpi_inst.dpii_rn]);
		break;
	}

	if (len >= buflen)
		return (-1);
	buflen -= len;
	buf += len;

	/*
	 * Print the shifter as appropriate
	 */
	switch (dpi_inst.dpii_stype) {
	case ARM_DPI_SHIFTER_IMM32: {
		uint32_t rawimm, imm;
		int rawrot, rot;

		rawimm = dpi_inst.dpii_un.dpii_im.dpisi_imm;
		rawrot = dpi_inst.dpii_un.dpii_im.dpisi_rot;

		rot = rawrot * 2;
		imm = (rawimm << (32 - rot)) | (rawimm >> rot);

		len = dis_snprintf(buf, buflen, ", #%u, %d ; 0x%08x", rawimm,
		    rawrot, imm);
		break;
	}
	case ARM_DPI_SHIFTER_SIMM:
		if (dpi_inst.dpii_un.dpii_si.dpiss_code == DPI_S_NONE) {
			len = dis_snprintf(buf, buflen, ", %s",
			    arm_reg_names[dpi_inst.dpii_un.dpii_si.dpiss_targ]);
			break;
		}
		if (dpi_inst.dpii_un.dpii_si.dpiss_code == DPI_S_RRX) {
			len = dis_snprintf(buf, buflen, ", %s rrx",
			    arm_reg_names[dpi_inst.dpii_un.dpii_si.dpiss_targ]);
			break;
		}
		len = dis_snprintf(buf, buflen, ", %s, %s #%d",
		    arm_reg_names[dpi_inst.dpii_un.dpii_si.dpiss_targ],
		    arm_dpi_shifts[dpi_inst.dpii_un.dpii_si.dpiss_code],
		    dpi_inst.dpii_un.dpii_si.dpiss_imm);
		break;
	case ARM_DPI_SHIFTER_SREG:
		len = dis_snprintf(buf, buflen, ", %s, %s %s",
		    arm_reg_names[dpi_inst.dpii_un.dpii_ri.dpisr_targ],
		    arm_dpi_shifts[dpi_inst.dpii_un.dpii_ri.dpisr_code],
		    arm_reg_names[dpi_inst.dpii_un.dpii_ri.dpisr_val]);
		break;
	}

	return (len < buflen ? 0 : -1);
}

/*
 * This handles the byte and word size loads and stores. It does not handle the
 * multi-register loads or the 'extra' ones. The instruction has the generic
 * form off:
 *
 * 31 - 28|27 26 |25|24|23|22|21|20|19-16|15-12|11 - 0
 * [ cond | 0  0 |I |P |U |B |W |L | Rn | Rd   |mode_specific]
 *
 * Here the bits mean the following:
 *
 * Rn: The base register used by the addressing mode
 * Rd: The register to load to or store from
 * L bit: If L==1 then a load, else store
 * B bit: If B==1 then work on a byte, else a 32-bit word
 *
 * The remaining pieces determine the mode we are operating in:
 * I bit: If 0 use immediate offsets, otherwise if 1 used register based offsets
 * P bit: If 0 use post-indexed addressing. If 1, indexing mode is either offset
 *        addessing or pre-indexed addressing based on the W bit.
 * U bit: If 1, offset is added to base, if 0 offset is subtracted from base
 * W bit: This bits interpretation varies based on the P bit. If P is zero then
 *        W indicates whether a normal memory access is performed or if a read
 *        from user memory is performed (W = 1).
 *        If P is 1 then then when W = 0 the base register is not updated and
 *        when W = 1 the calculated address is written back to the base
 *        register.
 *
 * Based on these combinations there are a total of nine different operating
 * modes, though not every LDR and STR variant can reach them all.
 */
static int
arm_dis_ldstr(uint32_t in, char *buf, size_t buflen)
{
	arm_cond_code_t cc;
	arm_reg_t rd, rn, rm;
	int ibit, pbit, ubit, bbit, wbit, lbit;
	arm_dpi_shift_code_t sc;
	uint8_t simm;
	size_t len;

	cc = (in & ARM_CC_MASK) >> ARM_CC_SHIFT;
	ibit = in & ARM_LS_IBIT_MASK;
	pbit = in & ARM_LS_PBIT_MASK;
	ubit = in & ARM_LS_UBIT_MASK;
	bbit = in & ARM_LS_BBIT_MASK;
	wbit = in & ARM_LS_WBIT_MASK;
	lbit = in & ARM_LS_LBIT_MASK;
	rd = (in & ARM_LS_RD_MASK) >> ARM_LS_RD_SHIFT;
	rn = (in & ARM_LS_RN_MASK) >> ARM_LS_RN_SHIFT;

	len = dis_snprintf(buf, buflen, "%s%s%s%s %s, ", lbit != 0 ? "ldr" : "str",
	    arm_cond_names[cc], bbit != 0 ? "b" : "",
	    (pbit == 0 && wbit != 0) ? "t" : "",
	    arm_reg_names[rd]);
	if (len >= buflen)
		return (-1);

	/* Figure out the specifics of the encoding for the rest */
	if (ibit == 0 && pbit != 0) {
		/*
		 * This is the immediate offset mode (A5.2.2). That means that
		 * we have something of the form [ <Rn>, #+/-<offset_12> ]. All
		 * of the mode specific bits contribute to offset_12. We also
		 * handle the pre-indexed version (A5.2.5) which depends on the
		 * wbit being set.
		 */
		len += dis_snprintf(buf + len, buflen - len, "[%s, #%s%d]%s",
		    arm_reg_names[rn], ubit != 0 ? "" : "-",
		    in & ARM_LS_IMM_MASK, wbit != 0 ? "!" : "");
	} else if (ibit != 0 && pbit != 0) {
		/*
		 * This handles A5.2.2, A5.2.3, A5.2.6, and A5.2.7. We can have
		 * one of two options. If the non-rm bits (11-4) are all zeros
		 * then we have a special case of a register offset is just
		 * being added. Otherwise we have a scaled register offset where
		 * the shift code matters.
		 */
		rm = in & ARM_LS_REG_RM_MASK;
		len += dis_snprintf(buf + len, buflen - len, "[%s, %s%s",
		    arm_reg_names[rn], ubit != 0 ? "" : "-",
		    arm_reg_names[rm]);
		if (len >= buflen)
			return (-1);
		if ((in & ARM_LS_REG_NRM_MASK) != 0) {
			simm = (in & ARM_LS_SCR_SIMM_MASK) >>
			    ARM_LS_SCR_SIMM_SHIFT;
			sc = (in & ARM_LS_SCR_SCODE_MASK) >>
			    ARM_LS_SCR_SCODE_SHIFT;

			if (simm == 0 && sc == DPI_S_ROR)
				sc = DPI_S_RRX;

			len += dis_snprintf(buf + len, buflen - len, "%s",
			    arm_dpi_shifts[sc]);
			if (len >= buflen)
				return (-1);
			if (sc != DPI_S_RRX) {
				len += dis_snprintf(buf + len, buflen - len, " #%d",
				    simm);
				if (len >= buflen)
					return (-1);
			}
		}
		len += dis_snprintf(buf + len, buflen - len, "]%s",
		    wbit != 0 ? "!" : "");
	} else if (ibit == 0 && pbit == 0 && wbit == 0) {
		/* A5.2.8 immediate post-indexed */
		len += dis_snprintf(buf + len, buflen - len, "[%s], #%s%d",
		    arm_reg_names[rn], ubit != 0 ? "" : "-",
		    in & ARM_LS_IMM_MASK);
	} else if (ibit != 0 && pbit == 0 && wbit == 0) {
		/* A5.2.9 and A5.2.10 */
		rm = in & ARM_LS_REG_RM_MASK;
		len += dis_snprintf(buf + len, buflen - len, "[%s], %s%s",
		    arm_reg_names[rn], ubit != 0 ? "" : "-",
		    arm_reg_names[rm]);
		if ((in & ARM_LS_REG_NRM_MASK) != 0) {
			simm = (in & ARM_LS_SCR_SIMM_MASK) >>
			    ARM_LS_SCR_SIMM_SHIFT;
			sc = (in & ARM_LS_SCR_SCODE_MASK) >>
			    ARM_LS_SCR_SCODE_SHIFT;

			if (simm == 0 && sc == DPI_S_ROR)
				sc = DPI_S_RRX;

			len += dis_snprintf(buf + len, buflen - len, "%s",
			    arm_dpi_shifts[sc]);
			if (len >= buflen)
				return (-1);
			if (sc != DPI_S_RRX)
				len += dis_snprintf(buf + len, buflen - len,
				    " #%d", simm);
		}
	}

	return (len < buflen ? 0 : -1);
}

static void
print_range(char **bufp, size_t *buflenp, uint16_t regs, uint16_t precede)
{
	char *buf = *bufp;
	size_t buflen = *buflenp;
	boolean_t cont = B_FALSE;
	int minreg = -1;
	int i;

	*buf = '\0';

	if (precede && regs)
		strlcat(buf, ", ", buflen);

	for (i = 0; i < 16; i++) {
		boolean_t present = (regs & (1 << i)) != 0;
		boolean_t lastreg = (regs & (2 << i)) == 0;

		if (!present)
			continue;

		if (minreg == -1) {
			if (cont)
				strlcat(buf, ", ", buflen);

			strlcat(buf, arm_reg_names[i], buflen);

			if (!lastreg)
				minreg = i;
		} else {
			if (lastreg) {
				strlcat(buf, "-", buflen);
				strlcat(buf, arm_reg_names[i], buflen);
				minreg = -1;
			}
		}

		cont = B_TRUE;
	}

	*bufp += strlen(buf);
	*buflenp -= strlen(buf);
}

static size_t
print_reg_list(char *buf, size_t buflen, uint16_t regs)
{
	char *save = buf;

	print_range(&buf, &buflen, regs & 0x01ff, 0);
	print_range(&buf, &buflen, regs & 0x0200, regs & 0x01ff); /* fp */
	print_range(&buf, &buflen, regs & 0x0c00, regs & 0x03ff);
	print_range(&buf, &buflen, regs & 0x1000, regs & 0x0fff); /* ip */
	print_range(&buf, &buflen, regs & 0x2000, regs & 0x1fff); /* sp */
	print_range(&buf, &buflen, regs & 0x4000, regs & 0x3fff); /* lr */
	print_range(&buf, &buflen, regs & 0x8000, regs & 0x7fff); /* pc */

	return (strlen(save));
}

/*
 * This handles load and store multiple instructions. The general format is as
 * follows:
 *
 * 31 - 28|27 26 25|24|23|22|21|20|19-16|15-0
 * [ cond | 1  0 0 |P |U |S |W |L | Rn | register set
 *
 * The register set has one bit per register. If a bit is set it indicates that
 * register and if it is not set then it indicates that the register is not
 * included in this.
 *
 * S bit: If the instruction is a LDM and we load the PC, the S == 1 tells us to
 * load the CPSR from SPSR after the other regs are loaded. If the instruction
 * is a STM or LDM without touching the PC it indicates that if we are
 * privileged we should send the banked registers.
 *
 * L bit: Where this is a load or store. Load is active high.
 *
 * P bit: If P == 0 then Rn is included in the memory region transfers and its
 * location is dependent on the U bit. It is at the top (U == 0) or bottom (U ==
 * 1). If P == 1 then it is excluded and lies one word beyond the top (U == 0)
 * or bottom based on the U bit.
 *
 * U bit: If U == 1 then the transfer is made upwards and if U == 0 then the
 * transfer is made downwards.
 *
 * W bit: If set then we incremet the base register after the transfer. It is
 * modified by 4 times the number of registers in the list. If the U bit is
 * positive then that value is added to Rn otherwise it is subtracted.
 *
 * The overal layout for this is
 * (LDM|STM){<cond>}<addressing mode> Rn{!}, <registers>{^}. Here the ! is based
 * on having the W bit set. The ^ bit depends on whether S is set or not.
 *
 * There are four normal addressing modes: IA, IB, DA, DB. There are also
 * corresponding stack addressing modes that exist. However we have no way of
 * knowing which are the ones being used, therefore we are going to default to
 * the non-stack versions which are listed as the primary.
 *
 * Finally the last useful bit is how the registers list is specified. It is a
 * comma separated list inside of { }. However, a user may separate a contiguous
 * range by the use of a -, eg. R0 - R4. However, it is impossible for us to map
 * back directly to what the user did. So for now, we punt on second down and
 * instead just list each indidvidual register rather than attempt a joining
 * routine.
 */
static int
arm_dis_ldstr_multi(uint32_t in, char *buf, size_t buflen)
{
	int sbit, wbit, lbit;
	uint16_t regs, addr_mode;
	arm_reg_t rn;
	arm_cond_code_t cc;
	size_t len;

	cc = (in & ARM_CC_MASK) >> ARM_CC_SHIFT;
	sbit = in & ARM_LSM_SBIT_MASK;
	wbit = in & ARM_LSM_WBIT_MASK;
	lbit = in & ARM_LSM_LBIT_MASK;
	rn = (in & ARM_LSM_RN_MASK) >> ARM_LSM_RN_SHIFT;
	regs = in & ARM_LSM_RLIST_MASK;
	addr_mode = (in & ARM_LSM_ADDR_MASK) >> ARM_LSM_ADDR_SHIFT;

	if ((lbit == 0 && addr_mode == 2 && rn == ARM_REG_R13 && wbit != 0) ||
	    (lbit != 0 && addr_mode == 1 && rn == ARM_REG_R13 && wbit != 0))
		len = dis_snprintf(buf, buflen, "%s%s { ",
		    lbit != 0 ? "pop" : "push",
		    arm_cond_names[cc]);
	else
		len = dis_snprintf(buf, buflen, "%s%s%s %s%s, { ",
		    lbit != 0 ? "ldm" : "stm",
		    arm_cond_names[cc],
		    arm_lsm_mode_names[addr_mode],
		    arm_reg_names[rn],
		    wbit != 0 ? "!" : "");

	len += print_reg_list(buf + len, buflen - len, regs);

	len += dis_snprintf(buf + len, buflen - len, " }%s", sbit != 0 ? "^" : "");
	return (len >= buflen ? -1 : 0);
}

/*
 * Here we need to handle miscellaneous loads and stores. This is used to load
 * and store signed and unsigned half words. To load a signed byte. And to load
 * and store double words. There is no specific store routines for signed bytes
 * and halfwords as they are supposed to use the SRB and STRH. There are two
 * primary encodings this time. The general case looks like:
 *
 * 31 - 28|27 - 25|24|23|22|21|20|19-16|15-12|11-8 |7|6|5|4|3-0
 * [ cond |   0   |P |U |I |W |L | Rn | Rd   |amode|1|S|H|1|amode ]
 *
 * The I, P, U, and W bits specify the addressing mode.
 * The L, S, and H bits describe the type and size.
 * Rn: The base register used by the addressing mode
 * Rd: The register to load to or store from
 *
 * The other bits specifically mean:
 * I bit: If set to one the address specific pieces are immediate. Otherwise
 * they aren't.
 * P bit: If P is 0 used post-indexed addressing. If P is 1 its behavior is
 * based on the value of W.
 * U bit: If U is one the offset is added to the base otherwise subtracted
 * W bit: When P is one a value of W == 1 says that the resulting memory address
 * should be written back to the base register. The base register isn't touched
 * when W is zero.
 *
 * The L, S, and H bits combine in the following table:
 *
 *  L | S | H | Meaning
 *  -------------------
 *  0 | 0 | 1 | store halfword
 *  0 | 1 | 0 | load doubleword
 *  0 | 1 | 1 | store doubleword
 *  1 | 0 | 1 | load unsigned half word
 *  1 | 1 | 0 | load signed byte
 *  1 | 1 | 1 | load signed halfword
 *
 * The final format of this is:
 * LDR|STR{<cond>}H|SH|SB|D <rd>, address_mode
 */
static int
arm_dis_els(uint32_t in, char *buf, size_t buflen)
{
	arm_cond_code_t cc;
	arm_reg_t rn, rd;
	const char *iname, *suffix;
	int lbit, sbit, hbit, pbit, ubit, ibit, wbit;
	uint8_t imm;
	size_t len;

	lbit = in & ARM_ELS_LBIT_MASK;
	sbit = in & ARM_ELS_SBIT_MASK;
	hbit = in & ARM_ELS_SBIT_MASK;

	if (lbit || (sbit && hbit == 0))
		iname = "ldr";
	else
		iname = "str";

	if (sbit == 0 && hbit)
		suffix = "h";
	else if (lbit == 0)
		suffix = "d";
	else if (sbit && hbit == 0)
		suffix = "sb";
	else if (sbit && hbit)
		suffix = "sh";

	cc = (in & ARM_CC_MASK) >> ARM_CC_SHIFT;
	rn = (in & ARM_ELS_RN_MASK) >> ARM_ELS_RN_SHIFT;
	rd = (in & ARM_ELS_RD_MASK) >> ARM_ELS_RD_SHIFT;

	len = dis_snprintf(buf, buflen, "%s%s%s %s, ", iname, arm_cond_names[cc],
	    suffix, arm_reg_names[rd]);
	if (len >= buflen)
		return (-1);

	pbit = in & ARM_ELS_PBIT_MASK;
	ubit = in & ARM_ELS_UBIT_MASK;
	ibit = in & ARM_ELS_IBIT_MASK;
	wbit = in & ARM_ELS_WBIT_MASK;

	if (pbit && ibit) {
		/* Handle A5.3.2 and A5.3.4 immediate offset and pre-indexed */
		/* Bits 11-8 form the upper 4 bits of imm */
		imm = (in & ARM_ELS_UP_AM_MASK) >> (ARM_ELS_UP_AM_SHIFT - 4);
		imm |= in & ARM_ELS_LOW_AM_MASK;
		len += dis_snprintf(buf + len, buflen - len, "[%s, #%s%d]%s",
		    arm_reg_names[rn],
		    ubit != 0 ? "" : "-", imm,
		    wbit != 0 ? "!" : "");
	} else if (pbit && ibit == 0) {
		/* Handle A5.3.3 and A5.3.5 register offset and pre-indexed */
		len += dis_snprintf(buf + len, buflen - len, "[%s %s%s]%s",
		    arm_reg_names[rn],
		    ubit != 0 ? "" : "-",
		    arm_reg_names[in & ARM_ELS_LOW_AM_MASK],
		    wbit != 0 ? "!" : "");
	} else if (pbit == 0 && ibit) {
		/* A5.3.6 Immediate post-indexed */
		/* Bits 11-8 form the upper 4 bits of imm */
		imm = (in & ARM_ELS_UP_AM_MASK) >> (ARM_ELS_UP_AM_SHIFT - 4);
		imm |= in & ARM_ELS_LOW_AM_MASK;
		len += dis_snprintf(buf + len, buflen - len, "[%s], #%s%d",
		    arm_reg_names[rn], ubit != 0 ? "" : "-", imm);
	} else if (pbit == 0 && ibit == 0) {
		/* Handle A 5.3.7 Register post-indexed */
		len += dis_snprintf(buf + len, buflen - len, "[%s], %s%s",
		    arm_reg_names[rn], ubit != 0 ? "" : "-",
		    arm_reg_names[in & ARM_ELS_LOW_AM_MASK]);
	}

	return (len >= buflen ? -1 : 0);
}

/*
 * Handle SWP and SWPB out of the extra loads/stores extensions.
 */
static int
arm_dis_swap(uint32_t in, char *buf, size_t buflen)
{
	arm_cond_code_t cc;
	arm_reg_t rn, rd, rm;

	cc = (in & ARM_CC_MASK) >> ARM_CC_SHIFT;
	rn = (in & ARM_ELS_RN_MASK) >> ARM_ELS_RN_SHIFT;
	rd = (in & ARM_ELS_RD_MASK) >> ARM_ELS_RD_SHIFT;
	rm = in & ARM_ELS_RN_MASK;

	if (dis_snprintf(buf, buflen, "swp%s%s %s, %s, [%s]",
	    arm_cond_names[cc],
	    (in & ARM_ELS_SWAP_BYTE_MASK) ? "b" : "",
	    arm_reg_names[rd], arm_reg_names[rm], arm_reg_names[rn]) >=
	    buflen)
		return (-1);

	return (0);
}

/*
 * Handle LDREX and STREX out of the extra loads/stores extensions.
 */
static int
arm_dis_lsexcl(uint32_t in, char *buf, size_t buflen)
{
	arm_cond_code_t cc;
	arm_reg_t rx, ry, rz;
	int lbit;
	size_t len;

	/*
	 * To make things confusing enough, the names of bitfields between
	 * ldrex and strex are not totally consistent.  Specifically,
	 *    STREX rd, rt, [rn]
	 *       rn = 19:16
	 *       rd = 15:12
	 *       rt = 3:0
	 *
	 *    LDREX rt, [rn]
	 *       rn = 19:16
	 *       rt = 15:12
	 *
	 * To avoid having to do too many mental gymnastics, let's just
	 * think of the bitfields as:
	 *
	 *       rx = 19:16
	 *       ry = 15:12
	 *       rz = 3:0
	 *
	 * And so we print the instructions as:
	 *    STREX ry, rz, [rx]
	 *    LDREX ry, [rx]
	 */

	cc = (in & ARM_CC_MASK) >> ARM_CC_SHIFT;
	rx = (in & ARM_ELS_RN_MASK) >> ARM_ELS_RN_SHIFT;
	ry = (in & ARM_ELS_RD_MASK) >> ARM_ELS_RD_SHIFT;
	rz = (in & ARM_ELS_LOW_AM_MASK);
	lbit = in & ARM_ELS_LBIT_MASK;

	len = dis_snprintf(buf, buflen, "%s%sex %s, ",
	    lbit != 0 ? "ldr" : "str",
	    arm_cond_names[cc], arm_reg_names[ry]);
	if (len >= buflen)
		return (-1);

	if (lbit)
		len += dis_snprintf(buf + len, buflen - len, "[%s]",
		    arm_reg_names[rx]);
	else
		len += dis_snprintf(buf + len, buflen - len, "%s, [%s]",
		    arm_reg_names[rz], arm_reg_names[rx]);
	return (len >= buflen ? -1 : 0);
}

/*
 * This is designed to handle the multiplication instruction extension space.
 * Note that this doesn't actually cover all of the multiplication instructions
 * available in ARM, but all of the ones that are in this space. This includes
 * the following instructions:
 *
 *
 * There are three basic encoding formats:
 *
 * Multipy (acc):
 * 31 - 28|27 - 24|23|22|21|20|19-16|15-12|11-8 |7|6|5|4|3-0
 * [ cond |   0   |0 |0 | A |S |Rn  | Rd   |Rs   |1|0|0|1|Rm ]
 *
 * Unsigned multipy acc acc long
 * 31 - 28|27 - 24|23|22|21|20|19-16|15-12|11-8 |7|6|5|4|3-0
 * [ cond |   0   |0 |1 |0 |0 |RdHi |RdLo  |Rs   |1|0|0|1|Rm ]
 *
 * Multiply (acc) long:
 * 31 - 28|27 - 24|23|22|21|20|19-16|15-12|11-8 |7|6|5|4|3-0
 * [ cond |   0   |1 |Un|A |S |RdHi| RdLo |Rs   |1|0|0|1|Rm ]
 *
 * A bit: Accumulate
 * Un bit: Unsigned is active low, signed is active high
 * S bit: Indicates whethere the status register should be updated.
 *
 * MLA(S) and MUL(S) make up the first type of instructions.
 * UMAAL makes up the second group.
 * (U|S)MULL(S), (U|S)MLAL(S), Make up the third.
 */
static int
arm_dis_extmul(uint32_t in, char *buf, size_t buflen)
{
	arm_cond_code_t cc;
	arm_reg_t rd, rn, rs, rm;
	size_t len;

	/*
	 * RdHi is equal to rd here. RdLo is equal to Rn here.
	 */
	rd = (in & ARM_EMULT_RD_MASK) >> ARM_EMULT_RD_SHIFT;
	rn = (in & ARM_EMULT_RN_MASK) >> ARM_EMULT_RN_SHIFT;
	rs = (in & ARM_EMULT_RS_MASK) >> ARM_EMULT_RS_SHIFT;
	rm = in & ARM_EMULT_RM_MASK;

	cc = (in & ARM_CC_MASK) >> ARM_CC_SHIFT;

	if ((in & ARM_EMULT_MA_MASK) == 0) {
		if (in & ARM_EMULT_ABIT_MASK) {
			len = dis_snprintf(buf, buflen, "mla%s%s %s, %s, %s, %s",
			    arm_cond_names[cc],
			    (in & ARM_EMULT_SBIT_MASK) ? "s" : "",
			    arm_reg_names[rd], arm_reg_names[rm],
			    arm_reg_names[rs], arm_reg_names[rs]);
		} else {
			len = dis_snprintf(buf, buflen, "mul%s%s %s, %s, %s",
			    arm_cond_names[cc],
			    (in & ARM_EMULT_SBIT_MASK) ? "s" : "",
			    arm_reg_names[rd], arm_reg_names[rm],
			    arm_reg_names[rs]);

		}
	} else if ((in & ARM_EMULT_UMA_MASK) == ARM_EMULT_UMA_TARG) {
		len = dis_snprintf(buf, buflen, "umaal%s %s, %s, %s, %s",
		    arm_cond_names[cc], arm_reg_names[rn], arm_reg_names[rd],
		    arm_reg_names[rm], arm_reg_names[rs]);
	} else if ((in & ARM_EMULT_MAL_MASK) == ARM_EMULT_MAL_TARG) {
		len = dis_snprintf(buf, buflen, "%s%s%s%s %s, %s, %s, %s",
		    (in & ARM_EMULT_UNBIT_MASK) ? "s" : "u",
		    (in & ARM_EMULT_ABIT_MASK) ? "mlal" : "mull",
		    arm_cond_names[cc],
		    (in & ARM_EMULT_SBIT_MASK) ? "s" : "",
		    arm_reg_names[rn], arm_reg_names[rd], arm_reg_names[rm],
		    arm_reg_names[rs]);
	} else {
		/* Not a supported instruction in this space */
		return (-1);
	}
	return (len >= buflen ? -1 : 0);
}

/*
 * Here we handle the three different cases of moving to and from the various
 * status registers in both register mode and in immediate mode.
 */
static int
arm_dis_status_regs(uint32_t in, char *buf, size_t buflen)
{
	arm_cond_code_t cc;
	arm_reg_t rd, rm;
	uint8_t field;
	int imm;
	size_t len;

	cc = (in & ARM_CC_MASK) >> ARM_CC_SHIFT;

	if ((in & ARM_CDSP_MRS_MASK) == ARM_CDSP_MRS_TARG) {
		rd = (in & ARM_CDSP_RD_MASK) >> ARM_CDSP_RD_SHIFT;
		if (dis_snprintf(buf, buflen, "mrs%s %s, %s", arm_cond_names[cc],
		    arm_reg_names[rd],
		    (in & ARM_CDSP_STATUS_RBIT) != 0 ? "spsr" : "cpsr") >=
		    buflen)
			return (-1);
		return (0);
	}

	field = (in & ARM_CDSP_MSR_F_MASK) >> ARM_CDSP_MSR_F_SHIFT;
	len = dis_snprintf(buf, buflen, "msr%s %s_%s, ", arm_cond_names[cc],
	    (in & ARM_CDSP_STATUS_RBIT) != 0 ? "spsr" : "cpsr",
	    arm_cdsp_msr_field_names[field]);
	if (len >= buflen)
		return (-1);

	if (in & ARM_CDSP_MSR_ISIMM_MASK) {
		imm = in & ARM_CDSP_MSR_IMM_MASK;
		imm <<= (in & ARM_CDSP_MSR_RI_MASK) >> ARM_CDSP_MSR_RI_SHIFT;
		len += dis_snprintf(buf + len, buflen - len, "#%d", imm);
	} else {
		rm = in & ARM_CDSP_RM_MASK;
		len += dis_snprintf(buf + len, buflen - len, "%s",
		    arm_reg_names[rm]);
	}

	return (len >= buflen ? -1 : 0);
}

/*
 * Here we need to handle the Control And DSP instruction extension space. This
 * consists of several different instructions. Unlike other extension spaces
 * there isn't as much that is similar here as there is stuff that is different.
 * Oh well, that's a part of life. Instead we do a little bit of additional
 * parsing here.
 *
 * The first group that we separate out are the instructions that interact with
 * the status registers. Those are handled in their own function.
 */
static int
arm_dis_cdsp_ext(uint32_t in, char *buf, size_t buflen)
{
	uint16_t imm, op;
	arm_cond_code_t cc;
	arm_reg_t rd, rm, rn, rs;
	size_t len;

	if ((in & ARM_CDSP_STATUS_MASK) == ARM_CDSP_STATUS_TARG)
		return (arm_dis_status_regs(in, buf, buflen));

	cc = (in & ARM_CC_MASK) >> ARM_CC_SHIFT;

	/*
	 * This gets the Branch/exchange as well as the Branch and link/exchange
	 * pieces. These generally also transform the instruction set into
	 * something we can't actually disassemble. Here the lower mask and
	 * target is the opposite. eg. the target bits are not what we want.
	 */
	if ((in & ARM_CDSP_BEX_UP_MASK) == ARM_CDSP_BEX_UP_TARG &&
	    (in & ARM_CDSP_BEX_LOW_MASK) != ARM_CDSP_BEX_NLOW_TARG) {
		rm = in & ARM_CDSP_RM_MASK;
		imm = (in & ARM_CDSP_BEX_TYPE_MASK) >> ARM_CDSP_BEX_TYPE_SHIFT;
		if (dis_snprintf(buf, buflen, "b%s%s %s",
		    imm == ARM_CDSP_BEX_TYPE_X ? "x" :
		    imm == ARM_CDSP_BEX_TYPE_J ? "xj" : "lx",
		    arm_cond_names[cc], arm_reg_names[rm]) >= buflen)
			return (-1);
		return (0);
	}

	/* Count leading zeros */
	if ((in & ARM_CDSP_CLZ_MASK) == ARM_CDSP_CLZ_TARG) {
		rd = (in & ARM_CDSP_RD_MASK) >> ARM_CDSP_RD_SHIFT;
		rm = in & ARM_CDSP_RM_MASK;
		if (dis_snprintf(buf, buflen, "clz%s %s, %s", arm_cond_names[cc],
		    arm_reg_names[rd], arm_reg_names[rm]) >= buflen)
			return (-1);
		return (0);
	}

	if ((in & ARM_CDSP_SAT_MASK) == ARM_CDSP_SAT_TARG) {
		rd = (in & ARM_CDSP_RD_MASK) >> ARM_CDSP_RD_SHIFT;
		rn = (in & ARM_CDSP_RN_MASK) >> ARM_CDSP_RN_SHIFT;
		rm = in & ARM_CDSP_RM_MASK;
		imm = (in & ARM_CDSP_SAT_OP_MASK) >> ARM_CDSP_SAT_OP_SHIFT;
		if (dis_snprintf(buf, buflen, "q%s%s %s, %s, %s",
		    arm_cdsp_sat_opnames[imm], arm_cond_names[cc],
		    arm_reg_names[rd], arm_reg_names[rm],
		    arm_reg_names[rn]) >= buflen)
			return (-1);
		return (0);
	}

	/*
	 * Breakpoint instructions are a bit different. While they are in the
	 * conditional instruction namespace, they actually aren't defined to
	 * take a condition. That's just how it rolls. The breakpoint is a
	 * 16-bit value. The upper 12 bits are stored together and the lower
	 * four together.
	 */
	if ((in & ARM_CDSP_BKPT_MASK) == ARM_CDSP_BKPT_TARG) {
		if (cc != ARM_COND_NACC)
			return (-1);
		imm = (in & ARM_CDSP_BKPT_UIMM_MASK) >>
		    ARM_CDSP_BKPT_UIMM_SHIFT;
		imm <<= 4;
		imm |= (in & ARM_CDSP_BKPT_LIMM_MASK);
		if (dis_snprintf(buf, buflen, "bkpt %d", imm) >= buflen)
			return (1);
		return (0);
	}

	/*
	 * Here we need to handle another set of multiplies. Specifically the
	 * Signed multiplies. This is SMLA<x><y>, SMLAW<y>, SMULW<y>,
	 * SMLAL<x><y>, SMUL<x><y>. These instructions all follow the form:
	 *
	 * 31 - 28|27-25|24|23|22-21|20|19-16|15-12|11 - 8|7|6|5|4|3-0
	 * [ cond |  0  | 1| 0| op. | 0|Rn   |Rd   |Rs    |1|y|x|0|Rm ]
	 *
	 * If x is one a T is used for that part of the name. Otherwise a B is.
	 * The same holds true for y.
	 *
	 * These instructions map to the following opcodes:
	 * SMLA<x><y>: 00,
	 * SMLAW<y>: 01 and x is zero,
	 * SMULW<y>: 01 and x is one ,
	 * SMLAL<x><y>: 10,
	 * SMUL<xy><y>: 11
	 */
	if ((in & ARM_CDSP_SMUL_MASK) == ARM_CDSP_SMUL_TARG) {
		rd = (in & ARM_CDSP_RD_MASK) >> ARM_CDSP_RD_SHIFT;
		rn = (in & ARM_CDSP_RN_MASK) >> ARM_CDSP_RN_SHIFT;
		rs = (in & ARM_CDSP_RS_MASK) >> ARM_CDSP_RS_SHIFT;
		rm = in & ARM_CDSP_RM_MASK;
		op = (in & ARM_CDSP_SMUL_OP_MASK) >> ARM_CDSP_SMUL_OP_SHIFT;

		switch (op) {
		case 0:
			len = dis_snprintf(buf, buflen, "smla%s%s%s %s, %s, %s, %s",
			    (in & ARM_CDSP_SMUL_X_MASK) != 0 ? "t" : "b",
			    (in & ARM_CDSP_SMUL_Y_MASK) != 0 ? "t" : "b",
			    arm_cond_names[cc], arm_reg_names[rd],
			    arm_reg_names[rm], arm_reg_names[rs],
			    arm_reg_names[rn]);
			break;
		case 1:
			if (in & ARM_CDSP_SMUL_X_MASK) {
				len = dis_snprintf(buf, buflen,
				    "smulw%s%s %s, %s, %s",
				    (in & ARM_CDSP_SMUL_Y_MASK) != 0 ? "t" :
				    "b", arm_cond_names[cc], arm_reg_names[rd],
				    arm_reg_names[rm], arm_reg_names[rs]);
			} else {
				len = dis_snprintf(buf, buflen,
				    "smlaw%s%s %s, %s, %s %s",
				    (in & ARM_CDSP_SMUL_Y_MASK) != 0 ? "t" :
				    "b", arm_cond_names[cc], arm_reg_names[rd],
				    arm_reg_names[rm], arm_reg_names[rs],
				    arm_reg_names[rn]);
			}
			break;
		case 2:
			len = dis_snprintf(buf, buflen,
			    "smlal%s%s%s %s, %s, %s, %s",
			    (in & ARM_CDSP_SMUL_X_MASK) != 0 ? "t" : "b",
			    (in & ARM_CDSP_SMUL_Y_MASK) != 0 ? "t" : "b",
			    arm_cond_names[cc], arm_reg_names[rd],
			    arm_reg_names[rn], arm_reg_names[rm],
			    arm_reg_names[rs]);
			break;
		case 3:
			len = dis_snprintf(buf, buflen, "smul%s%s%s %s, %s, %s",
			    (in & ARM_CDSP_SMUL_X_MASK) != 0 ? "t" : "b",
			    (in & ARM_CDSP_SMUL_Y_MASK) != 0 ? "t" : "b",
			    arm_cond_names[cc], arm_reg_names[rd],
			    arm_reg_names[rm], arm_reg_names[rs]);
			break;
		default:
			return (-1);
		}
		return (len >= buflen ? -1 : 0);
	}

	/*
	 * If we got here then this is some other instruction we don't know
	 * about in the instruction extension space.
	 */
	return (-1);
}

/*
 * Coprocessor double register transfers
 *
 * MCRR:
 * 31 - 28|27-25|24|23|22|21|20|19-16|15-12|11-8|7-4|3-0
 * [ cond |1 1 0| 0| 0| 1| 0| 0| Rn  |  Rd |cp #|op |CRm
 *
 * MRRC:
 * 31 - 28|27-25|24|23|22|21|20|19-16|15-12|11-8|7-4|3-0
 * [ cond |1 1 0| 0| 0| 1| 0| 1| Rn  |  Rd |cp #|op |CRm
 *
 */
static int
arm_dis_coproc_drt(uint32_t in, char *buf, size_t buflen)
{
	arm_cond_code_t cc;
	arm_reg_t rd, rn, rm;
	uint8_t coproc, op;
	const char *ccn;
	size_t len;

	cc = (in & ARM_CC_MASK) >> ARM_CC_SHIFT;
	coproc = (in & ARM_COPROC_NUM_MASK) >> ARM_COPROC_NUM_SHIFT;
	rn = (in & ARM_COPROC_RN_MASK) >> ARM_COPROC_RN_SHIFT;
	rd = (in & ARM_COPROC_RD_MASK) >> ARM_COPROC_RD_SHIFT;
	rm = in & ARM_COPROC_RM_MASK;
	op = (in & ARM_COPROC_DRT_OP_MASK) >> ARM_COPROC_DRT_OP_SHIFT;

	if (cc == ARM_COND_NACC)
		ccn = "2";
	else
		ccn = arm_cond_names[cc];

	len = dis_snprintf(buf, buflen, "%s%s %s, #%d, %s, %s, c%s",
	    (in & ARM_COPROC_DRT_DIR_MASK) != 0 ? "mrrc" : "mcrr",
	    ccn, arm_coproc_names[coproc], op, arm_reg_names[rd],
	    arm_reg_names[rn], arm_reg_names[rm]);
	return (len >= buflen ? -1 : 0);
}

/*
 * This serves as both the entry point for the normal load and stores as well as
 * the double register transfers (MCRR and MRCC). If it is a register transfer
 * then we quickly send it off.
 * LDC:
 * 31 - 28|27-25|24|23|22|21|20|19-16|15-12|11 - 8|7 - 0
 * [ cond |1 1 0| P| U| N| W| L| Rn  | CRd | cp # | off ]
 *
 * STC:
 * 31 - 28|27-25|24|23|22|21|20|19-16|15-12|11 - 8|7 - 0
 * [ cond |1 1 0| P| U| N| W| L| Rn  | CRd | cp # | off ]
 *
 * Here the bits mean:
 *
 * P bit: If P is zero, it is post-indexed or unindexed based on W. If P is 1
 * then it is offset-addressing or pre-indexed based on W again.
 *
 * U bit: If U is positive then the offset if added, subtracted otherwise.. Note
 * that if P is zero and W is zero, U must be one.
 *
 * N bit: If set that means that we have a Long size, this bit is set by the L
 * suffix, not to be confused with the L bit.
 *
 * W bit: If W is one then the memory address is written back to the base
 * register. Further W = 0 and P = 0 is unindexed addressing. W = 1, P = 0 is
 * post-indexed. W = 0, P = 1 is offset addressing and W = 1, P = 1 is
 * pre-indexed.
 */
static int
arm_dis_coproc_lsdrt(uint32_t in, char *buf, size_t buflen)
{
	arm_cond_code_t cc;
	arm_reg_t rn, rd;
	uint8_t coproc;
	uint32_t imm;
	int pbit, ubit, nbit, wbit, lbit;
	const char *ccn;
	size_t len;

	if ((in & ARM_COPROC_DRT_MASK) == ARM_COPROC_DRT_TARG)
		return (arm_dis_coproc_drt(in, buf, buflen));

	cc = (in & ARM_CC_MASK) >> ARM_CC_SHIFT;
	coproc = (in & ARM_COPROC_NUM_MASK) >> ARM_COPROC_NUM_SHIFT;
	rn = (in & ARM_COPROC_RN_MASK) >> ARM_COPROC_RN_SHIFT;
	rd = (in & ARM_COPROC_RD_MASK) >> ARM_COPROC_RD_SHIFT;
	imm = in & ARM_COPROC_LS_IMM_MASK;

	pbit = in & ARM_COPROC_LS_P_MASK;
	ubit = in & ARM_COPROC_LS_U_MASK;
	nbit = in & ARM_COPROC_LS_N_MASK;
	wbit = in & ARM_COPROC_LS_W_MASK;
	lbit = in & ARM_COPROC_LS_L_MASK;

	if (cc == ARM_COND_NACC)
		ccn = "2";
	else
		ccn = arm_cond_names[cc];

	len = dis_snprintf(buf, buflen, "%s%s%s %s, c%s, ",
	    lbit != 0 ? "ldc" : "stc", ccn, nbit != 0 ? "l" : "",
	    arm_coproc_names[coproc], arm_reg_names[rd]);
	if (len >= buflen)
		return (-1);

	if (pbit != 0) {
		imm *= 4;
		len += dis_snprintf(buf + len, buflen - len, "[%s, #%s%d]%s",
		    arm_reg_names[rn],
		    ubit != 0 ? "" : "-", imm,
		    wbit != 0 ? "!" : "");
	} else if (wbit != 0) {
		imm *= 4;
		len += dis_snprintf(buf + len, buflen - len, "[%s], #%s%d",
		    arm_reg_names[rn], ubit != 0 ? "" : "-", imm);
	} else {
		len += dis_snprintf(buf + len, buflen - len, "[%s], { %d }",
		    arm_reg_names[rn], imm);
	}
	return (len >= buflen ? -1 : 0);
}

/*
 * Here we tell a coprocessor to do data processing
 *
 * CDP:
 * 31 - 28|27 - 24|23-20|19-16|15-12|11 - 8|7 - 5|4|3-0
 * [ cond |1 1 1 0| op_1| CRn | CRd | cp # | op_2|0|CRm ]
 */
static int
arm_dis_coproc_dp(uint32_t in, char *buf, size_t buflen)
{
	arm_cond_code_t cc;
	arm_reg_t rn, rd, rm;
	uint8_t op1, op2, coproc;
	const char *ccn;

	cc = (in & ARM_CC_MASK) >> ARM_CC_SHIFT;
	coproc = (in & ARM_COPROC_NUM_MASK) >> ARM_COPROC_NUM_SHIFT;
	rn = (in & ARM_COPROC_RN_MASK) >> ARM_COPROC_RN_SHIFT;
	rd = (in & ARM_COPROC_RD_MASK) >> ARM_COPROC_RD_SHIFT;
	rm = in & ARM_COPROC_RM_MASK;
	op1 = (in & ARM_COPROC_CDP_OP1_MASK) >> ARM_COPROC_CDP_OP1_SHIFT;
	op2 = (in & ARM_COPROC_CDP_OP2_MASK) >> ARM_COPROC_CDP_OP2_SHIFT;

	/*
	 * This instruction is valid with the undefined condition code. When it
	 * does that, the instruction is intead CDP2 as opposed to CDP.
	 */
	if (cc == ARM_COND_NACC)
		ccn = "2";
	else
		ccn = arm_cond_names[cc];

	if (dis_snprintf(buf, buflen, "cdp%s %s, #%d, c%s, c%s, c%s, #%d", ccn,
	    arm_coproc_names[coproc], op1, arm_reg_names[rd],
	    arm_reg_names[rn], arm_reg_names[rm], op2) >= buflen)
		return (-1);

	return (0);
}

/*
 * Here we handle coprocesser single register transfers.
 *
 * MCR:
 * 31 - 28|27 - 24|23-21|20|19-16|15-12|11 - 8|7 - 5|4|3-0
 * [ cond |1 1 1 0| op_1| 0| CRn |  Rd | cp # | op_2|1|CRm ]
 *
 * MRC:
 * 31 - 28|27 - 24|23-21|20|19-16|15-12|11 - 8|7 - 5|4|3-0
 * [ cond |1 1 1 0| op_1| 1| CRn |  Rd | cp # | op_2|1|CRm ]
 */
static int
arm_dis_coproc_rt(uint32_t in, char *buf, size_t buflen)
{
	arm_cond_code_t cc;
	arm_reg_t rn, rd, rm;
	uint8_t op1, op2, coproc;
	const char *ccn;
	size_t len;

	cc = (in & ARM_CC_MASK) >> ARM_CC_SHIFT;
	coproc = (in & ARM_COPROC_NUM_MASK) >> ARM_COPROC_NUM_SHIFT;
	rn = (in & ARM_COPROC_RN_MASK) >> ARM_COPROC_RN_SHIFT;
	rd = (in & ARM_COPROC_RD_MASK) >> ARM_COPROC_RD_SHIFT;
	rm = in & ARM_COPROC_RM_MASK;
	op1 = (in & ARM_COPROC_CRT_OP1_MASK) >> ARM_COPROC_CRT_OP1_SHIFT;
	op2 = (in & ARM_COPROC_CRT_OP2_MASK) >> ARM_COPROC_CRT_OP2_SHIFT;

	if (cc == ARM_COND_NACC)
		ccn = "2";
	else
		ccn = arm_cond_names[cc];

	len = dis_snprintf(buf, buflen, "%s%s %s, #%d, %s, c%s, c%s",
	    (in & ARM_COPROC_CRT_DIR_MASK) != 0 ? "mrc" : "mcr", ccn,
	    arm_coproc_names[coproc], op1, arm_reg_names[rd],
	    arm_reg_names[rn], arm_reg_names[rm]);
	if (len >= buflen)
		return (-1);

	if (op2 != 0)
		if (dis_snprintf(buf + len, buflen - len, ", #%d", op2) >=
		    buflen - len)
			return (-1);
	return (0);
}

/*
 * Here we handle the set of unconditional instructions.
 */
static int
arm_dis_uncond_insn(uint32_t in, char *buf, size_t buflen)
{
	int imm, opt, sc;
	arm_reg_t rn, rm;
	size_t len;

	/*
	 * The CPS instruction is a bit complicated. It has the following big
	 * pattern which maps to a few different ways to use it:
	 *
	 *
	 * 31-28|27-25|24|23-20|19-18|17 |16|15-9|8|7|6|5|4-0
	 *    1 |  0  | 1| 0   |imod|mmod| 0|SBZ |A|I|F|0|mode
	 *
	 * CPS<effect> <iflags> {, #<mode> }
	 * CPS #<mode>
	 *
	 * effect: determines what to do with the A, I, F interrupt bits in the
	 * CPSR. effect is encoded in the imod field. It is either enable
	 * interrupts 0b10 or disable interrupts 0b11. Recall that interrupts
	 * are active low in the CPSR. If effect is not specified then this is
	 * strictly a mode change which is required.
	 *
	 * A, I, F: If effect is specified then the bits which are high are
	 * modified by the instruction.
	 *
	 * mode: Specifies a mode to change to. mmod will be 1 if mode is set.
	 *
	 */
	if ((in & ARM_UNI_CPS_MASK) == ARM_UNI_CPS_TARG) {
		imm = (in & ARM_UNI_CPS_IMOD_MASK) > ARM_UNI_CPS_IMOD_SHIFT;

		/* Ob01 is not a valid value for the imod */
		if (imm == 1)
			return (-1);

		if (imm != 0)
			len = dis_snprintf(buf, buflen, "cps%s %s%s%s%s",
			    imm == 2 ? "ie" : "id",
			    (in & ARM_UNI_CPS_A_MASK) ? "a" : "",
			    (in & ARM_UNI_CPS_I_MASK) ? "i" : "",
			    (in & ARM_UNI_CPS_F_MASK) ? "f" : "",
			    (in & ARM_UNI_CPS_MMOD_MASK) ? " ," : "");
		else
			len = dis_snprintf(buf, buflen, "cps ");
		if (len >= buflen)
			return (-1);

		if (in & ARM_UNI_CPS_MMOD_MASK)
			if ((dis_snprintf(buf + len, buflen - len, "#%d",
			    in & ARM_UNI_CPS_MODE_MASK)) >= buflen - len)
				return (-1);
		return (0);
	}

	if ((in & ARM_UNI_SE_MASK) == ARM_UNI_SE_TARG) {
		if (dis_snprintf(buf, buflen, "SETEND %s",
		    (in & ARM_UNI_SE_BE_MASK) ? "be" : "le") >= buflen)
			return (-1);
		return (0);
	}

	/*
	 * The cache preload is like a load, but it has a much simpler set of
	 * constraints. The only valid bits that you can transform are the I and
	 * the U bits. We have to use pre-indexed addressing. This means that we
	 * only have the U bit and the I bit. See arm_dis_ldstr for a full
	 * explanation of what's happening here.
	 */
	if ((in & ARM_UNI_PLD_MASK) == ARM_UNI_PLD_TARG) {
		rn = (in & ARM_LS_RN_MASK) >> ARM_LS_RN_SHIFT;
		if ((in & ARM_LS_IBIT_MASK) == 0) {
			if (dis_snprintf(buf, buflen, "pld [%s, #%s%d",
			    arm_reg_names[rn],
			    (in & ARM_LS_UBIT_MASK) != 0 ? "" : "-",
			    in & ARM_LS_IMM_MASK) >= buflen)
				return (-1);
			return (0);
		}

		rm = in & ARM_LS_REG_RM_MASK;
		len = dis_snprintf(buf, buflen, "pld [%s, %s%s", arm_reg_names[rn],
		    (in & ARM_LS_UBIT_MASK) != 0 ? "" : "-",
		    arm_reg_names[rm]);
		if (len >= buflen)
			return (-1);

		if ((in & ARM_LS_REG_NRM_MASK) != 0) {
			imm = (in & ARM_LS_SCR_SIMM_MASK) >>
			    ARM_LS_SCR_SIMM_SHIFT;
			sc = (in & ARM_LS_SCR_SCODE_MASK) >>
			    ARM_LS_SCR_SCODE_SHIFT;

			if (imm == 0 && sc == DPI_S_ROR)
				sc = DPI_S_RRX;

			len += dis_snprintf(buf + len, buflen - len, "%s",
			    arm_dpi_shifts[sc]);
			if (len >= buflen)
				return (-1);
			if (sc != DPI_S_RRX) {
				len += dis_snprintf(buf + len, buflen - len,
				    " #%d", imm);
				if (len >= buflen)
					return (-1);
			}
		}
		if (dis_snprintf(buf + len, buflen - len, "]") >= buflen - len)
			return (-1);
		return (0);
	}

	/*
	 * This is a special case of STM, but it works across chip modes.
	 */
	if ((in & ARM_UNI_SRS_MASK) == ARM_UNI_SRS_TARG) {
		imm = (in & ARM_LSM_ADDR_MASK) >> ARM_LSM_ADDR_SHIFT;
		if (dis_snprintf(buf, buflen, "srs%s #%d%s",
		    arm_lsm_mode_names[imm],
		    in & ARM_UNI_SRS_MODE_MASK,
		    (in & ARM_UNI_SRS_WBIT_MASK) != 0 ? "!" : "") >= buflen)
			return (-1);
		return (0);
	}

	/*
	 * RFE is a return from exception instruction that is similar to the LDM
	 * and STM, but a bit different.
	 */
	if ((in & ARM_UNI_RFE_MASK) == ARM_UNI_RFE_TARG) {
		imm = (in & ARM_LSM_ADDR_MASK) >> ARM_LSM_ADDR_SHIFT;
		rn = (in & ARM_LS_RN_MASK) >> ARM_LS_RN_SHIFT;
		if (dis_snprintf(buf, buflen, "rfe%s %s%s", arm_lsm_mode_names[imm],
		    arm_reg_names[rn],
		    (in & ARM_UNI_RFE_WBIT_MASK) != 0 ? "!" : "") >= buflen)
			return (-1);
		return (0);
	}

	if ((in & ARM_UNI_BLX_MASK) == ARM_UNI_BLX_TARG) {
		if (dis_snprintf(buf, buflen, "blx %d",
		    in & ARM_UNI_BLX_IMM_MASK) >= buflen)
			return (-1);
		return (0);
	}

	if ((in & ARM_UNI_CLREX_MASK) == ARM_UNI_CLREX_TARG) {
		if ((dis_snprintf(buf, buflen, "clrex")) >= buflen)
			return (-1);
		return (0);
	}

	if ((in & ARM_UNI_CODRT_MASK) == ARM_UNI_CODRT_TARG) {
		return (arm_dis_coproc_lsdrt(in, buf, buflen));
	}

	if ((in & ARM_UNI_CORT_MASK) == ARM_UNI_CORT_TARG) {
		return (arm_dis_coproc_rt(in, buf, buflen));
	}

	if ((in & ARM_UNI_CODP_MASK) == ARM_UNI_CORT_TARG) {
		return (arm_dis_coproc_dp(in, buf, buflen));
	}

	if ((in & ARM_UNI_DMB_MASK) == ARM_UNI_DMB_TARG) {
		opt = (in & ARM_UNI_DXB_OPT_MASK);
		if ((dis_snprintf(buf, buflen, "dmb %s",
		    arm_uni_dxb_options[opt])) >= buflen)
			return (-1);
		return (0);
	}

	if ((in & ARM_UNI_DSB_MASK) == ARM_UNI_DSB_TARG) {
		opt = (in & ARM_UNI_DXB_OPT_MASK);
		if ((dis_snprintf(buf, buflen, "dsb %s",
		    arm_uni_dxb_options[opt])) >= buflen)
			return (-1);
		return (0);
	}

	if ((in & ARM_UNI_ISB_MASK) == ARM_UNI_ISB_TARG) {
		if ((dis_snprintf(buf, buflen, "isb")) >= buflen)
			return (-1);
		return (0);
	}

	/*
	 * An undefined or illegal instruction
	 */
	return (-1);
}

/*
 * Disassemble B and BL instructions. The instruction is given a 24-bit two's
 * complement value as an offset address. This value gets sign extended to 30
 * bits and then shifted over two bits. This is then added to the PC + 8. So,
 * instead of dispalying an absolute address, we're going to display the delta
 * that the instruction has instead.
 */
static int
arm_dis_branch(dis_handle_t *dhp, uint32_t in, char *buf, size_t buflen)
{
	uint32_t addr;
	arm_cond_code_t cc;
	size_t len;

	cc = (in & ARM_CC_MASK) >> ARM_CC_SHIFT;
	addr = in & ARM_BRANCH_IMM_MASK;
	if (in & ARM_BRANCH_SIGN_MASK)
		addr |= ARM_BRANCH_NEG_SIGN;
	else
		addr &= ARM_BRANCH_POS_SIGN;
	addr <<= 2;
	if ((len = dis_snprintf(buf, buflen, "b%s%s %d",
	    (in & ARM_BRANCH_LBIT_MASK) != 0 ? "l" : "",
	    arm_cond_names[cc], (int)addr)) >= buflen)
		return (-1);

	/* Per the ARM manuals, we have to account for the extra 8 bytes here */
	if (dhp->dh_lookup(dhp->dh_data, dhp->dh_addr + (int)addr + 8, NULL, 0,
	    NULL, NULL) == 0) {
		len += dis_snprintf(buf + len, buflen - len, "\t<");
		if (len >= buflen)
			return (-1);
		dhp->dh_lookup(dhp->dh_data, dhp->dh_addr + (int)addr + 8,
		    buf + len, buflen - len, NULL, NULL);
		strlcat(buf, ">", buflen);
	}

	return (0);
}

/*
 * There are six instructions that are covered here: ADD16, ADDSUBX, SUBADDX,
 * SUB16, ADD8, and SUB8. They can hae the following variations: S, Q, SH, U,
 * UQ, and UH. It has two differnt sets of bits to determine the opcode: 22-20
 * and then 7-5.
 *
 * These instructions have the general form of:
 *
 * 31 - 28|27-25|24|23|22-20|19-16|15-12|11 - 8|7-5|4|3-0
 * [ cond |0 1 1| 0| 0| opP |Rn   |Rd   |SBO   |opI|1|Rm ]
 *
 * Here we use opP to refer to the prefix of the instruction, eg. S, Q, etc.
 * Where as opI refers to which instruction it is, eg. ADD16, ADD8, etc. We use
 * string tables for both of these in arm_padd_p_names and arm_padd_i_names. If
 * there is an empty entry that means that the instruction in question doesn't
 * exist.
 */
static int
arm_dis_padd(uint32_t in, char *buf, size_t buflen)
{
	arm_reg_t rn, rd, rm;
	arm_cond_code_t cc;
	uint8_t opp, opi;
	const char *pstr, *istr;

	opp = (in & ARM_MEDIA_OP1_MASK) >> ARM_MEDIA_OP1_SHIFT;
	opi = (in & ARM_MEDIA_OP2_MASK) >> ARM_MEDIA_OP2_SHIFT;

	pstr = arm_padd_p_names[opp];
	istr = arm_padd_i_names[opi];

	if (pstr == NULL || istr == NULL)
		return (-1);

	cc = (in & ARM_CC_MASK) >> ARM_CC_SHIFT;
	rn = (in & ARM_MEDIA_RN_MASK) >> ARM_MEDIA_RN_SHIFT;
	rd = (in & ARM_MEDIA_RD_MASK) >> ARM_MEDIA_RD_SHIFT;
	rm = in & ARM_MEDIA_RM_MASK;

	if (dis_snprintf(buf, buflen, "%s%%s %s, %s, %s", pstr, istr,
	    arm_cond_names[cc], arm_reg_names[rd], arm_reg_names[rn],
	    arm_reg_names[rm]) >= buflen)
		return (-1);
	return (0);
}

/*
 * Disassemble the extend instructions from ARMv6. There are six instructions:
 *
 * XTAB16, XTAB, XTAH, XTB16, XTB, XTFH. These can exist with one of the
 * following prefixes: S, U. The opcode exists in bits 22-20. We have the
 * following rules from there:
 *
 * If bit 22 is one then we are using the U prefix, otherwise the S prefix. Then
 * we have the following opcode maps in the lower two bits:
 * XTAB16	00 iff Rn != 0xf
 * XTAB		10 iff Rn != 0xf
 * XTAH		11 iff Rn != 0xf
 * XTB16	00 iff Rn = 0xf
 * XTB		10 iff Rn = 0xf
 * XTH		11 iff Rn = 0xf
 */
static int
arm_dis_extend(uint32_t in, char *buf, size_t buflen)
{
	uint8_t op, rot;
	int sbit;
	arm_cond_code_t cc;
	arm_reg_t rn, rm, rd;
	const char *opn;
	size_t len;


	rn = (in & ARM_MEDIA_RN_MASK) >> ARM_MEDIA_RN_SHIFT;
	rd = (in & ARM_MEDIA_RD_MASK) >> ARM_MEDIA_RD_SHIFT;
	rm = in & ARM_MEDIA_RM_MASK;
	op = (in & ARM_MEDIA_SZE_OP_MASK) >> ARM_MEDIA_SZE_OP_SHIFT;
	rot = (in & ARM_MEDIA_SZE_ROT_MASK) >> ARM_MEDIA_SZE_ROT_SHIFT;
	sbit = in & ARM_MEDIA_SZE_S_MASK;
	cc = (in & ARM_CC_MASK) >> ARM_CC_SHIFT;

	switch (op) {
	case 0x0:
		opn = rn == ARM_REG_R15 ? "xtab16" : "xtb16";
		break;
	case 0x2:
		opn = rn == ARM_REG_R15 ? "xtab" : "xtb";
		break;
	case 0x3:
		opn = rn == ARM_REG_R15 ? "xtah" : "xth";
		break;
	default:
		return (-1);
		break;
	}

	if (rn == ARM_REG_R15) {
		len = dis_snprintf(buf, buflen, "%s%s%s %s, %s",
		    sbit != 0 ? "u" : "s",
		    opn, arm_cond_names[cc], arm_reg_names[rd],
		    arm_reg_names[rn]);
	} else {
		len = dis_snprintf(buf, buflen, "%s%s%s %s, %s, %s",
		    sbit != 0 ? "u" : "s",
		    opn, arm_cond_names[cc], arm_reg_names[rd],
		    arm_reg_names[rn], arm_reg_names[rm]);
	}

	if (len >= buflen)
		return (-1);

	if (dis_snprintf(buf + len, buflen - len, "%s",
	    arm_extend_rot_names[rot]) >= buflen - len)
		return (-1);
	return (0);
}

/*
 * The media instructions and extensions can be divided into different groups of
 * instructions. We first use bits 23 and 24 to figure out where to send it. We
 * call this group of bits the l1 mask.
 */
static int
arm_dis_media(uint32_t in, char *buf, size_t buflen)
{
	uint8_t l1, op1, op2;
	arm_cond_code_t cc;
	arm_reg_t rd, rn, rs, rm;
	int xbit;
	size_t len;

	cc = (in & ARM_CC_MASK) >> ARM_CC_SHIFT;
	l1 = (in & ARM_MEDIA_L1_MASK) >> ARM_MEDIA_L1_SHIFT;
	switch (l1) {
	case 0x0:
		return (arm_dis_padd(in, buf, buflen));
		break;
	case 0x1:
		if ((in & ARM_MEDIA_HPACK_MASK) == ARM_MEDIA_HPACK_TARG) {
			rn = (in & ARM_MEDIA_RN_MASK) >> ARM_MEDIA_RN_SHIFT;
			rd = (in & ARM_MEDIA_RD_MASK) >> ARM_MEDIA_RD_SHIFT;
			rm = in & ARM_MEDIA_RM_MASK;
			op1 = (in & ARM_MEDIA_HPACK_SHIFT_MASK) >>
			    ARM_MEDIA_HPACK_SHIFT_IMM;
			len = dis_snprintf(buf, buflen, "%s%s %s, %s, %s",
			    (in & ARM_MEDIA_HPACK_OP_MASK) != 0 ?
			    "pkhtb" : "pkhbt", arm_cond_names[cc],
			    arm_reg_names[rd], arm_reg_names[rn],
			    arm_reg_names[rd]);
			if (len >= buflen)
				return (-1);

			if (op1 != 0) {
				if (in & ARM_MEDIA_HPACK_OP_MASK)
					len += dis_snprintf(buf + len, buflen - len,
					    ", asr %d", op1);
				else
					len += dis_snprintf(buf + len, buflen - len,
					    ", lsl %d", op1);
			}
			return (len >= buflen ? -1 : 0);
		}

		if ((in & ARM_MEDIA_WSAT_MASK) == ARM_MEDIA_WSAT_TARG) {
			rd = (in & ARM_MEDIA_RD_MASK) >> ARM_MEDIA_RD_SHIFT;
			rm = in & ARM_MEDIA_RM_MASK;
			op1 = (in & ARM_MEDIA_SAT_IMM_MASK) >>
			    ARM_MEDIA_SAT_IMM_SHIFT;
			op2 = (in & ARM_MEDIA_SAT_SHI_MASK) >>
			    ARM_MEDIA_SAT_SHI_SHIFT;
			len = dis_snprintf(buf, buflen, "%s%s %s, #%d, %s",
			    (in & ARM_MEDIA_SAT_U_MASK) != 0 ? "usat" : "ssat",
			    arm_cond_names[cc], arm_reg_names[rd], op1,
			    arm_reg_names[rm]);

			if (len >= buflen)
				return (-1);

			/*
			 * The shift is optional in the assembler and encoded as
			 * LSL 0. However if we get ASR 0, that means ASR #32.
			 * An ARM_MEDIA_SAT_STYPE_MASK of 0 is LSL, 1 is ASR.
			 */
			if (op2 != 0 || (in & ARM_MEDIA_SAT_STYPE_MASK) != 0) {
				if (op2 == 0)
					op2 = 32;
				if (dis_snprintf(buf + len, buflen - len,
				    ", %s #%d",
				    (in & ARM_MEDIA_SAT_STYPE_MASK) != 0 ?
				    "asr" : "lsl", op2) >= buflen - len)
					return (-1);
			}
			return (0);
		}

		if ((in & ARM_MEDIA_PHSAT_MASK) == ARM_MEDIA_PHSAT_TARG) {
			rd = (in & ARM_MEDIA_RD_MASK) >> ARM_MEDIA_RD_SHIFT;
			rm = in & ARM_MEDIA_RM_MASK;
			op1 = (in & ARM_MEDIA_RN_MASK) >> ARM_MEDIA_RN_SHIFT;
			if (dis_snprintf(buf, buflen, "%s%s %s, #%d, %s",
			    (in & ARM_MEDIA_SAT_U_MASK) != 0 ?
			    "usat16" : "ssat16",
			    arm_cond_names[cc], arm_reg_names[rd], op1,
			    arm_reg_names[rm]) >= buflen)
				return (-1);
			return (0);
		}

		if ((in & ARM_MEDIA_REV_MASK) == ARM_MEDIA_REV_TARG) {
			rd = (in & ARM_MEDIA_RD_MASK) >> ARM_MEDIA_RD_SHIFT;
			rm = in & ARM_MEDIA_RM_MASK;
			if (dis_snprintf(buf, buflen, "rev%s %s, %s",
			    arm_cond_names[cc], arm_reg_names[rd],
			    arm_reg_names[rd]) >= buflen)
				return (-1);
			return (0);
		}

		if ((in & ARM_MEDIA_BRPH_MASK) == ARM_MEDIA_BRPH_TARG) {
			rd = (in & ARM_MEDIA_RD_MASK) >> ARM_MEDIA_RD_SHIFT;
			rm = in & ARM_MEDIA_RM_MASK;
			if (dis_snprintf(buf, buflen, "rev16%s %s, %s",
			    arm_cond_names[cc], arm_reg_names[rd],
			    arm_reg_names[rd]) >= buflen)
				return (-1);
			return (0);
		}

		if ((in & ARM_MEDIA_BRSH_MASK) == ARM_MEDIA_BRSH_TARG) {
			rd = (in & ARM_MEDIA_RD_MASK) >> ARM_MEDIA_RD_SHIFT;
			rm = in & ARM_MEDIA_RM_MASK;
			if (dis_snprintf(buf, buflen, "revsh%s %s, %s",
			    arm_cond_names[cc], arm_reg_names[rd],
			    arm_reg_names[rd]) >= buflen)
				return (-1);
			return (0);
		}

		if ((in & ARM_MEDIA_SEL_MASK) == ARM_MEDIA_SEL_TARG) {
			rn = (in & ARM_MEDIA_RN_MASK) >> ARM_MEDIA_RN_SHIFT;
			rd = (in & ARM_MEDIA_RD_MASK) >> ARM_MEDIA_RD_SHIFT;
			rm = in & ARM_MEDIA_RM_MASK;
			if (dis_snprintf(buf, buflen, "sel%s %s, %s, %s",
			    arm_cond_names[cc], arm_reg_names[rd],
			    arm_reg_names[rn], arm_reg_names[rm]) >= buflen)
				return (-1);
			return (0);
		}

		if ((in & ARM_MEDIA_SZE_MASK) != 0)
			return (arm_dis_extend(in, buf, buflen));
		/* Unknown instruction */
		return (-1);
		break;
	case 0x2:
		/*
		 * This consists of the following multiply instructions:
		 * SMLAD, SMLSD, SMLALD, SMUAD, and SMUSD.
		 *
		 * SMLAD and SMUAD encoding are the same, switch on Rn == R15
		 * 22-20 are 000 7-6 are 00
		 * SMLSD and SMUSD encoding are the same, switch on Rn == R15
		 * 22-20 are 000 7-6 are 01
		 * SMLALD: 22-20 are 100 7-6 are 00
		 */
		rn = (in & ARM_MEDIA_RN_MASK) >> ARM_MEDIA_RN_SHIFT;
		rd = (in & ARM_MEDIA_RD_MASK) >> ARM_MEDIA_RD_SHIFT;
		rs = (in & ARM_MEDIA_RS_MASK) >> ARM_MEDIA_RS_SHIFT;
		rm = in & ARM_MEDIA_RM_MASK;
		op1 = (in & ARM_MEDIA_OP1_MASK) >> ARM_MEDIA_OP1_SHIFT;
		op2 = (in & ARM_MEDIA_OP2_MASK) >> ARM_MEDIA_OP2_SHIFT;
		xbit = in & ARM_MEDIA_MULT_X_MASK;

		if (op1 == 0x0) {
			if (op2 != 0x0 && op2 != 0x1)
				return (-1);
			if (rn == ARM_REG_R15) {
				len = dis_snprintf(buf, buflen, "%s%s%s %s, %s, %s",
				    op2 != 0 ? "smusd" : "smuad",
				    xbit != 0 ? "x" : "x",
				    arm_cond_names[cc], arm_reg_names[rd],
				    arm_reg_names[rm], arm_reg_names[rs]);
			} else {
				len = dis_snprintf(buf, buflen,
				    "%s%s%s %s, %s, %s, %s",
				    op2 != 0 ? "smlsd" : "smlad",
				    xbit != 0 ? "x" : "",
				    arm_cond_names[cc], arm_reg_names[rd],
				    arm_reg_names[rm], arm_reg_names[rs],
				    arm_reg_names[rn]);

			}
		} else if (op1 == 0x8) {
			if (op2 != 0x0)
				return (-1);
			len = dis_snprintf(buf, buflen, "smlald%s%s %s, %s, %s, %s",
			    xbit != 0 ? "x" : "",
			    arm_cond_names[cc], arm_reg_names[rn],
			    arm_reg_names[rd], arm_reg_names[rm],
			    arm_reg_names[rs]);
		} else
			return (-1);

		return (len >= buflen ? -1 : 0);
		break;
	case 0x3:
		/*
		 * Here we handle USAD8 and USADA8. The main difference is the
		 * presence of RN. USAD8 is defined as having a value of rn that
		 * is not r15. If it is r15, then instead it is USADA8.
		 */
		if ((in & ARM_MEDIA_OP1_MASK) != 0)
			return (-1);
		if ((in & ARM_MEDIA_OP2_MASK) != 0)
			return (-1);

		cc = (in & ARM_CC_MASK) >> ARM_CC_SHIFT;
		rn = (in & ARM_MEDIA_RN_MASK) >> ARM_MEDIA_RN_SHIFT;
		rd = (in & ARM_MEDIA_RD_MASK) >> ARM_MEDIA_RD_SHIFT;
		rs = (in & ARM_MEDIA_RS_MASK) >> ARM_MEDIA_RS_SHIFT;
		rm = in & ARM_MEDIA_RM_MASK;

		if (rn != ARM_REG_R15)
			len = dis_snprintf(buf, buflen, "usada8%s %s, %s, %s, %s",
			    arm_cond_names[cc], arm_reg_names[rd],
			    arm_reg_names[rm], arm_reg_names[rs],
			    arm_reg_names[rn]);
		else
			len = dis_snprintf(buf, buflen, "usad8%s %s, %s, %s",
			    arm_cond_names[cc], arm_reg_names[rd],
			    arm_reg_names[rm], arm_reg_names[rs]);
		return (len >= buflen ? -1 : 0);
		break;
	default:
		return (-1);
	}
}

/*
 * Each instruction in the ARM instruction set is a uint32_t and in our case is
 * LE. The upper four bits determine the condition code. If the condition code
 * is undefined then we know to immediately jump there. Otherwise we go use the
 * next three bits to determine where we should go next and how to further
 * process the instruction in question. The ARM instruction manual doesn't
 * define this field so we're going to call it the L1_DEC or level 1 decoding
 * from which it will have to be further subdivided into the specific
 * instruction groupings that we care about.
 */
static int
arm_dis(dis_handle_t *dhp, uint32_t in, char *buf, size_t buflen)
{
	uint8_t l1;
	arm_cond_code_t cc;

	cc = (in & ARM_CC_MASK) >> ARM_CC_SHIFT;

	if (cc == ARM_COND_NACC)
		return (arm_dis_uncond_insn(in, buf, buflen));

	l1 = (in & ARM_L1_DEC_MASK) >> ARM_L1_DEC_SHIFT;

	switch (l1) {
	case 0x0:
		/*
		 * The l0 group is a bit complicated. We have several different
		 * groups of instructions to consider. The first question is
		 * whether bit 4 is zero or not. If it is, then we have a data
		 * processing immediate shift unless the opcode and + S bits
		 * (24-20) is of the form 0b10xx0.
		 *
		 * When bit 4 is 1, we have to then also look at bit 7. If bit
		 * 7 is one then we know that this is the class of multiplies /
		 * extra load/stores. If bit 7 is zero then we have the same
		 * opcode games as we did above.
		 */
		if (in & ARM_L1_0_B4_MASK) {
			if (in & ARM_L1_0_B7_MASK) {
				/*
				 * Both the multiplication extensions and the
				 * load and store extensions live in this
				 * region. The load and store extensions can be
				 * identified by having at least one of bits 5
				 * and 6 set. The exceptions to this are the
				 * SWP and SWPB instructions and the exclusive
				 * load and store instructions which, unlike the
				 * multiplication instructions. These have
				 * specific values for the bits in the range of
				 * 20-24.
				 */
				if ((in & ARM_L1_0_ELS_MASK) != 0)
					/* Extra loads/stores */
					return (arm_dis_els(in, buf, buflen));
				if ((in & ARM_ELS_SWAP_MASK) == ARM_ELS_IS_SWAP)
					return (arm_dis_swap(in, buf, buflen));
				if ((in & ARM_ELS_EXCL_MASK) ==
				    ARM_ELS_EXCL_MASK)
					return (arm_dis_lsexcl(in, buf,
					    buflen));
				/* Multiplication instruction extension A3-3. */
				return (arm_dis_extmul(in, buf, buflen));
			}
			if ((in & ARM_L1_0_OPMASK) == ARM_L1_0_SPECOP &&
			    !(in & ARM_L1_0_SMASK)) {
				/* Misc. Instructions A3-4 */
				return (arm_dis_cdsp_ext(in, buf, buflen));
			} else {
				/* data processing register shift */
				return (arm_dis_dpi(in, cc, buf, buflen));
			}
		} else {
			if ((in & ARM_L1_0_OPMASK) == ARM_L1_0_SPECOP &&
			    !(in & ARM_L1_0_SMASK))
				/* Misc. Instructions A3-4 */
				return (arm_dis_cdsp_ext(in, buf, buflen));
			else {
				/* Data processing immediate shift */
				return (arm_dis_dpi(in, cc, buf, buflen));
			}
		}
		break;
	case 0x1:
		/*
		 * In l1 group 0b001 there are a few ways to tell things apart.
		 * We are directed to first look at bits 20-24. Data processing
		 * immediate has a 4 bit opcode 24-21 followed by an S bit. We
		 * know it is not a data processing immediate if we have
		 * something of the form 0b10xx0.
		 */
		if ((in & ARM_L1_1_OPMASK) == ARM_L1_1_SPECOP &&
		    !(in & ARM_L1_1_SMASK)) {
			if (in & ARM_L1_1_UNDEF_MASK) {
				/* Undefined instructions */
				return (-1);
			} else {
				/* Move immediate to status register */
				return (arm_dis_status_regs(in, buf, buflen));
			}
		} else {
			/* Data processing immedaite */
			return (arm_dis_dpi(in, cc, buf, buflen));
		}
		break;
	case 0x2:
		/* Load/store Immediate offset */
		return (arm_dis_ldstr(in, buf, buflen));
		break;
	case 0x3:
		/*
		 * Like other sets we use the 4th bit to make an intial
		 * determination. If it is zero then this is a load/store
		 * register offset class instruction. Following that we have a
		 * specical mask of 0x01f000f0 to determine whether this is an
		 * architecturally undefined instruction type or not.
		 *
		 * The architecturally undefined are parts of the current name
		 * space that just aren't used, but could be used at some point
		 * in the future. For now though, it's an invalid op code.
		 */
		if (in & ARM_L1_3_B4_MASK) {
			if ((in & ARM_L1_3_ARCHUN_MASK) ==
			    ARM_L1_3_ARCHUN_MASK) {
				/* Architecturally undefined */
				return (-1);
			} else {
				/* Media instructions */
				return (arm_dis_media(in, buf, buflen));
			}
		} else {
			/* Load/store register offset */
			return (arm_dis_ldstr(in, buf, buflen));
		}
		break;
	case 0x4:
		/* Load/store multiple */
		return (arm_dis_ldstr_multi(in, buf, buflen));
		break;
	case 0x5:
		/* Branch and Branch with link */
		return (arm_dis_branch(dhp, in, buf, buflen));
		break;
	case 0x6:
		/* coprocessor load/store && double register transfers */
		return (arm_dis_coproc_lsdrt(in, buf, buflen));
		break;
	case 0x7:
		/*
		 * In l1 group 0b111 you can determine the three groups using
		 * the following logic. If the next bit after the l1 group (bit
		 * 24) is one than you know that it is a software interrupt.
		 * Otherwise it is one of the coprocessor instructions.
		 * Furthermore you can tell apart the data processing from the
		 * register transfers based on bit 4. If it is zero then it is
		 * a data processing instruction, otherwise it is a register
		 * transfer.
		 */
		if (in & ARM_L1_7_SWINTMASK) {
			/*
			 * The software interrupt is pretty straightforward. The
			 * lower 24 bits are the interrupt number. It's also
			 * valid for it to run with a condition code.
			 */
			if (dis_snprintf(buf, buflen, "swi%s %d",
			    arm_cond_names[cc],
			    in & ARM_SWI_IMM_MASK) >= buflen)
				return (-1);
			return (0);
		} else if (in & ARM_L1_7_COPROCMASK) {
			/* coprocessor register transfers */
			return (arm_dis_coproc_rt(in, buf, buflen));
		} else {
			/* coprocessor data processing */
			return (arm_dis_coproc_dp(in, buf, buflen));
		}
		break;
	}

	return (-1);
}

static int
dis_arm_supports_flags(int flags)
{
	int archflags = flags & DIS_ARCH_MASK;

	return (archflags == DIS_ARM_32);
}

/*ARGSUSED*/
static int
dis_arm_handle_attach(dis_handle_t *dhp)
{
	return (0);
}

/*ARGSUSED*/
static void
dis_arm_handle_detach(dis_handle_t *dhp)
{
}

static int
dis_arm_disassemble(dis_handle_t *dhp, uint64_t addr, char *buf, size_t buflen)
{
	uint32_t in;

	buf[0] = '\0';
	dhp->dh_addr = addr;
	if (dhp->dh_read(dhp->dh_data, addr, &in, sizeof (in)) !=
	    sizeof (in))
		return (-1);

	/* Translate in case we're on sparc? */
	in = LE_32(in);

	return (arm_dis(dhp, in, buf, buflen));
}

/*
 * This is simple in a non Thumb world. If and when we do enter a world where we
 * support thumb instructions, then this becomes far less than simple.
 */
/*ARGSUSED*/
static uint64_t
dis_arm_previnstr(dis_handle_t *dhp, uint64_t pc, int n)
{
	if (n <= 0)
		return (pc);

	return (pc - n*4);
}

/*
 * If and when we support thumb, then this value should probably become two.
 * However, it varies based on whether or not a given instruction is in thumb
 * mode.
 */
/*ARGSUSED*/
static int
dis_arm_min_instrlen(dis_handle_t *dhp)
{
	return (4);
}

/*
 * Regardless of thumb, this value does not change.
 */
/*ARGSUSED*/
static int
dis_arm_max_instrlen(dis_handle_t *dhp)
{
	return (4);
}

/* ARGSUSED */
static int
dis_arm_instrlen(dis_handle_t *dhp, uint64_t pc)
{
	return (4);
}

dis_arch_t dis_arch_arm_32 = {
	dis_arm_supports_flags,
	dis_arm_handle_attach,
	dis_arm_handle_detach,
	dis_arm_disassemble,
	dis_arm_previnstr,
	dis_arm_min_instrlen,
	dis_arm_max_instrlen,
	dis_arm_instrlen
};
