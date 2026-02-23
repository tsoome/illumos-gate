/*
 * Copyright (c) 2013 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed by Benno Rice under sponsorship from
 * the FreeBSD Foundation.
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
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <machine/asmacros.h>
#include <sys/segments.h>
#include <sys/controlregs.h>

	.text
	.globl	amd64_tramp
	.globl	amd64_tramp_end

/*
 * void amd64_tramp(uint64_t bi, uint64_t stack, uint64_t pagetable,
 *	uint64_t entry)
 */
amd64_tramp:
	cli			/* Make sure we don't get interrupted. */
	movq	%rsi,%rsp	/* Switch to our temporary stack. */
	pushq	$0x0
	pushq	$0x0
	movq	%rsp,%rbp

	lea	gdt_info(%rip), %rax
	lgdt	(%rax)

	pushq	$B64CODE_SEL
	leaq	sel(%rip), %rax
	pushq	%rax
	lretq
sel:
	pushq	%rcx		/* Push the entry address. */
	movq	%rdx,%r8	/* Save page table. */
	/*
	 * The kernel entry point we are about to call expects the machine
	 * state set up by dboot_grub.S (see uts/i86pc/dboot/dboot_grub.S).
	 * Since we hand off directly to the 64-bit kernel, we must establish
	 * it here. CR0, CR4.PAE and EFER.LME are already set up as we are
	 * running in long mode, so we only need PGE, PSE and NXE.
	 *
	 * NXE must be enabled before the kernel builds any PTE with the NX
	 * bit set (bi_use_nx is set from NX_support), otherwise bit 63 is a
	 * reserved bit and any access through such a PTE will #PF.
	 */
	movq	%cr4,%rax
	testb	$1,pge_support(%rip)
	jz	1f
	orq	$CR4_PGE,%rax
1:
	testb	$1,largepage_support(%rip)
	jz	2f
	orq	$CR4_PSE,%rax
2:
	movq	%rax,%cr4

	testb	$1,NX_support(%rip)
	jz	3f
	movl	$MSR_AMD_EFER,%ecx
	rdmsr			/* clobbers %eax and %edx */
	orl	$AMD_EFER_NXE,%eax
	wrmsr
3:
	movq	%r8,%cr3	/* Switch page tables. */
	ret			/* "Return" to kernel entry. */
amd64_tramp_end:
