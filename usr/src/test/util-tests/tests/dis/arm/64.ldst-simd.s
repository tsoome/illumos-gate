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

/*
 * Copyright 2017 Joyent, Inc.
 */

/*
 * C3.3.1 AdvSIMD load/store multiple structures
 * C3.3.2 AdvSIMD load/store multiple structures (post-indexed)
 */
.macro ldst_simd_mult op
	/* No offset / register offset ST1 */
	.irp arr,8b,16b,4h,8h,2s,4s,1d,2d
	\op\()1	{v0.\arr\()}, [x0]
	\op\()1	{v1.\arr\()-v3.\arr\()}, [sp]
	\op\()1	{v28.\arr\()-v31.\arr\()}, [x21], x21
	.endr
	/* No offset / register offset ST2-4 (with wraparound) */
	.irp arr,8b,16b,4h,8h,2s,4s,2d
	\op\()2	{v0.\arr\(), v1.\arr\()}, [x2]
	\op\()2	{v2.\arr\(), v3.\arr\()}, [sp], x30
	\op\()3	{v20.\arr\()-v22.\arr\()}, [x3]
	\op\()3	{v20.\arr\()-v22.\arr\()}, [sp], x30
	\op\()4	{v28.\arr\()-v31.\arr\()}, [x30]
	\op\()4	{v30.\arr\(), v31.\arr\(), v0.\arr\(), v1.\arr\()}, [x21], x21
	.endr
	/* Immediate offset */
	.irp arr,8b,4h,2s
	\op\()1	{v0.\arr\()}, [x21], #8
	\op\()2	{v10.\arr\(), v11.\arr\()}, [x1], #16
	\op\()3	{v20.\arr\()-v22.\arr\()}, [sp], #24
	\op\()4	{v28.\arr\()-v31.\arr\()}, [x10], #32
	.endr
	.irp arr,16b,8h,4s,2d
	\op\()1	{v0.\arr\()}, [x21], #16
	\op\()2	{v10.\arr\(), v11.\arr\()}, [x1], #32
	\op\()3	{v20.\arr\()-v22.\arr\()}, [sp], #48
	\op\()4	{v28.\arr\()-v31.\arr\()}, [x10], #64
	.endr
.endm

/*
 * C3.3.3 AdvSIMD load/store single structure
 * C3.3.4 AdvSIMD load/store single structure (post-indexed)
 */
.macro ldst_simd_single_no_offset op arr idx
	\op\()1 {v0.\arr\()}[\idx], [x0]
	\op\()2 {v31.\arr\(), v0.\arr\()}[\idx], [x7]
	\op\()3 {v10.\arr\()-v12.\arr\()}[\idx], [x21]
	\op\()4 {v28.\arr\()-v31.\arr\()}[\idx], [sp]
.endm
.macro ldst_simd_single_imm_offset op arr idx imm
	\op\()1	{v0.\arr\()}[\idx], [x0], #\imm
	\op\()2 {v31.\arr\(), v0.\arr\()}[\idx], [x7], #(\imm*2)
	\op\()3 {v10.\arr\()-v12.\arr\()}[\idx], [x21], #(\imm*3)
	\op\()4 {v28.\arr\()-v31.\arr\()}[\idx], [sp], #(\imm*4)
.endm
.macro ldst_simd_single_reg_offset op arr idx imm
	\op\()1	{v0.\arr\()}[\idx], [x0], x0
	\op\()2 {v31.\arr\(), v0.\arr\()}[\idx], [x7], x7
	\op\()3 {v10.\arr\()-v12.\arr\()}[\idx], [x21], x21
	\op\()4 {v28.\arr\()-v31.\arr\()}[\idx], [sp], x30
.endm
.macro ldst_simd_single op
	/* No offset */
	ldst_simd_single_no_offset \op, b, 15
	ldst_simd_single_no_offset \op, h, 7
	ldst_simd_single_no_offset \op, s, 3
	ldst_simd_single_no_offset \op, d, 1
	/* Post-index immediate */
	ldst_simd_single_imm_offset \op, b, 0, 1
	ldst_simd_single_imm_offset \op, h, 0, 2
	ldst_simd_single_imm_offset \op, s, 0, 4
	ldst_simd_single_imm_offset \op, d, 0, 8
	/* Post-index register */
	ldst_simd_single_reg_offset \op, b, 8
	ldst_simd_single_reg_offset \op, h, 4
	ldst_simd_single_reg_offset \op, s, 2
	ldst_simd_single_reg_offset \op, d, 1
.endm

/*
 * LDnR instructions handled separately.
 */
.macro ldst_simd_ldr_imm arr imm
	ld1r	{v0.\arr\()}, [x0], #\imm
	ld2r	{v31.\arr\(), v0.\arr\()}, [x7], #(\imm*2)
	ld3r	{v10.\arr\()-v12.\arr\()}, [x21], #(\imm*3)
	ld4r	{v28.\arr\()-v31.\arr\()}, [sp], #(\imm*4)
.endm
.macro ldst_simd_ldr
	.irp arr,8b,16b,4h,8h,2s,4s,1d,2d
	ld1r	{v0.\arr\()}, [x0]
	ld2r	{v31.\arr\(), v0.\arr\()}, [x7]
	ld3r	{v10.\arr\()-v12.\arr\()}, [x21]
	ld4r	{v28.\arr\()-v31.\arr\()}, [sp]
	ld1r	{v0.\arr\()}, [x0], x0
	ld2r	{v31.\arr\(), v0.\arr\()}, [x7], x7
	ld3r	{v10.\arr\()-v12.\arr\()}, [x21], x21
	ld4r	{v28.\arr\()-v31.\arr\()}, [sp], x30
	.endr
	/* There's probably a clever macro way to simplify this */
	ldst_simd_ldr_imm 8b 1
	ldst_simd_ldr_imm 16b 1
	ldst_simd_ldr_imm 4h 2
	ldst_simd_ldr_imm 8h 2
	ldst_simd_ldr_imm 2s 4
	ldst_simd_ldr_imm 4s 4
	ldst_simd_ldr_imm 1d 8
	ldst_simd_ldr_imm 2d 8
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	ldst_simd_mult st
	ldst_simd_mult ld
	ldst_simd_single st
	ldst_simd_single ld
	ldst_simd_ldr
.size libdis_test, [.-libdis_test]
