/*
 * Copyright (c) 2003  Peter Wemm <peter@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Quick and dirty trampoline to get into 64 bit (long) mode and running
 * with paging enabled so that we enter the kernel at its linked address.
 *
 * Trampoline is entered through __exec(), which is a BTX system call:
 * BTX drops us to ring 0 with flat, zero based segments and
 * calls us with the trampoline address itself already consumed, so our
 * arguments start at 4(%esp).  Ring 0 is what lets us touch %cr0, %cr3,
 * %cr4 and the EFER MSR at all, and the flat segments mean we are running
 * with linear == physical addresses.  Anything still living in the BTX
 * client is therefore only reachable through VTOP().
 */

#include <sys/controlregs.h>
#include <sys/segments.h>

/* GRRR. Deal with BTX that links us for a non-zero location */
#define VPBASE	0xa000
#define VTOP(x)	((x) + VPBASE)

	.text
	.code32

	.globl	amd64_tramp
	.globl	amd64_tramp_end

/*
 * void amd64_tramp(uint64_t bi, uint64_t stack, uint64_t pagetable,
 *     uint64_t entry)
 *
 * Enter the illumos kernel staged by dboot_exec().  Called through
 * __exec(), so the arguments land as:
 *
 *      4(%esp)  bi            physical address of struct xboot_info
 *     12(%esp)  stack         physical address of the kernel boot stack
 *     20(%esp)  pagetable     physical address of the top level page table
 *     28(%esp)  entry         kernel entry point, a 64 bit virtual address
 *
 * The kernel entry point expects the machine state dboot_grub.S sets up
 * (see uts/i86pc/dboot/dboot_grub.S), so we have to establish it here.
 */
amd64_tramp:
	/* Be sure that interrupts are disabled */
	cli

	/*
	 * Collect the arguments now.  Once paging is on we only get to touch
	 * memory dboot_exec() mapped 1:1 for us.  These are 32 bit writes in
	 * legacy mode, where the upper halves of the 64 bit registers are
	 * inaccessible and their contents undefined, so each value is zero
	 * extended again in long mode below before it is used.
	 */
	movl	4(%esp), %ebx		/* bi */
	movl	12(%esp), %ebp		/* stack */
	movl	28(%esp), %esi		/* entry, low half */
	movl	32(%esp), %edi		/* entry, high half */

	/* Switch to the GDT dboot_exec() built for us. */
	lgdt	VTOP(gdt_info)

	/*
	 * PAE is mandatory for long mode, so it goes on unconditionally.
	 * PGE and large pages are only turned on if the processor has them,
	 * matching what dboot does for us.
	 */
	movl	%cr4, %eax
	orl	$CR4_PAE, %eax
	testb	$1, VTOP(pge_support)
	jz	1f
	orl	$CR4_PGE, %eax
1:
	testb	$1, VTOP(largepage_support)
	jz	2f
	orl	$CR4_PSE, %eax
2:
	movl	%eax, %cr4

	/* Switch to the page tables built by build_page_tables(). */
	movl	20(%esp), %eax
	movl	%eax, %cr3

	/*
	 * Enable long mode, and NX if the processor supports it.  NXE must be
	 * enabled before the kernel builds any PTE with the NX bit set
	 * (bi_use_nx is set from NX_support), otherwise bit 63 is a reserved
	 * bit and any access through such a PTE will #PF.
	 */
	movl	$MSR_AMD_EFER, %ecx
	rdmsr				/* clobbers %eax and %edx */
	orl	$AMD_EFER_LME, %eax
	testb	$1, VTOP(NX_support)
	jz	3f
	orl	$AMD_EFER_NXE, %eax
3:
	wrmsr

	/*
	 * Enable paging, write protection and alignment masking, but disable
	 * the cache disable and write through only bits.  Turning on paging
	 * implicitly sets EFER.LMA and puts us in compatibility mode; we keep
	 * executing because dboot_exec() maps this trampoline 1:1.
	 */
	 movl	%cr0, %eax
	 orl	$(CR0_PG | CR0_WP | CR0_AM), %eax
	 andl	$~(CR0_NW | CR0_CD), %eax
	 movl	%eax, %cr0

	/*
	 * Set %cs for long mode.  The BTX stack we are still on lives below
	 * 640k, which dboot_exec() maps 1:1 along with the low megabyte.
	 */
	pushl	$B64CODE_SEL
	pushl	$VTOP(longmode)
	lret

	.code64
longmode:
	/* Reassemble the 64 bit kernel entry point. */
	movl	%edi, %eax
	salq	$32, %rax
	movl	%esi, %esi
	orq	%rsi, %rax

	movl	%ebp, %esp		/* Switch to the kernel boot stack. */
	pushq	$0x0
	pushq	$0x0
	movq	%rsp, %rbp

	movl	%ebx, %edi		/* xboot_info is the kernel argument. */
	pushq	%rax
	ret				/* Return to the kernel entry point. */
amd64_tramp_end:
