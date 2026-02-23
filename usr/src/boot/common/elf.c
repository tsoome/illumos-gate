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
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * Process ELF kernel data.
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/elf.h>
#include <sys/stdint.h>

/*
 * Default limit for allocations. illumos dboot component is
 * running in 32-bit protexted mode and can not access memory
 * above 4GB. If the trampoline to start kernel is taking path
 * to use dboot, we must provide data in usable space.
 */
uint64_t load_limit = UINT32_MAX;

/*
 * start of kernel text, physical address and virtual.
 */
vm_offset_t ktext_phys;
uint64_t target_kernel_text;
size_t kernel_load_size;

vm_offset_t
elf_kernel_address(caddr_t buf)
{
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)buf;
	vm_offset_t allphdrs;

	allphdrs = (vm_offset_t)ehdr + ehdr->e_phoff;
	for (Elf64_Half i = 0; i < ehdr->e_phnum; i++) {
		Elf64_Phdr *phdr;

		phdr = (Elf64_Phdr *)(allphdrs + ehdr->e_phentsize * i);
		/* Check PT_LOAD only. */
		if (phdr->p_type != PT_LOAD)
			continue;

		if (phdr->p_memsz == 0)
			continue;

		/* load address 1:1 is dboot, ignore */
		if (phdr->p_paddr == phdr->p_vaddr)
			continue;

		if (phdr->p_flags == (PF_X | PF_R)) {
			/* Side effect - record virtual address */
			target_kernel_text = phdr->p_vaddr;
			return (phdr->p_paddr);
		}
	}
	return (0);
}

/*
 * elf_load_size() does calculate space needed for unix ELF sections,
 * and stores this value in kernel_load_size.
 *
 * However, the return value for memory allocation is fixed 8MB, the
 * space reserved for our nucleus. We need to use this value to make
 * sure there will be no other allocations from nucleus space.
 */
size_t
elf_load_size(caddr_t buf)
{
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)buf;
	vm_offset_t start, end;
	vm_offset_t allphdrs;

	allphdrs = (vm_offset_t)ehdr + ehdr->e_phoff;
	start = end = 0;
	for (Elf64_Half i = 0; i < ehdr->e_phnum; i++) {
		Elf64_Phdr *phdr;

		phdr = (Elf64_Phdr *)(allphdrs + ehdr->e_phentsize * i);

		if (phdr->p_type == PT_INTERP)
			continue;

		if (phdr->p_type != PT_LOAD)
			continue;

		if (phdr->p_flags == (PF_R | PF_W) && phdr->p_vaddr == 0)
			continue;

		if (phdr->p_memsz == 0)
			continue;

		/* load address 1:1 is dboot, ignore */
		if (phdr->p_paddr == phdr->p_vaddr)
			continue;

		if (start == 0) {
			/* Record first segment. */
			start = phdr->p_paddr;
			end = start + phdr->p_memsz;
			continue;
		}

		end = MAX(end, phdr->p_paddr + phdr->p_memsz);
	}

	/* Side effect - store kernel_load_size */
	kernel_load_size = round_page(end - start);
	return (MAX(kernel_load_size, 8 << 20));	/* nucleus is 8Meg */
}
