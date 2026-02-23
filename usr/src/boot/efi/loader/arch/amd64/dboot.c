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
 * Copyright 2026 Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * Transitional interface to implement illumos x86 kernel dboot
 * functionality to load and start illumos kernel as 64-bit elf.
 *
 * dboot module in illumos x86 kernel is 32-bit protected mode
 * code designed to interpret multiboot protocol to prepare
 * xboot_info data structure, relocate the kernel text, data and bss
 * sections, switch machine to 64-bit mode and start the kernel.
 *
 * The problem with 32-bit dboot is added complexity - from 64-bit UEFI
 * bootloader we need to switch to 32-bit protected mode and 32-bit
 * address space lmits. We have already seen those limits blocking
 * the use of memory mapped framebuffer and also trouble with large
 * modules.
 *
 * dboot component in loader still depends on creating multiboot2
 * data structures because this information is expected to be present
 * in xboot_info data structure.
 */

#include <stand.h>
#include <sys/param.h>
#include <efi.h>
#include <efilib.h>
#include <machine/elf.h>

#include "bootstrap.h"

#define	STACK_SIZE	0x8000

static int dboot_loadfile(char *, uint64_t, struct preloaded_file **);
static int dboot_exec(struct preloaded_file *);

struct file_format dboot = { dboot_loadfile, dboot_exec };

EFI_PHYSICAL_ADDRESS
elf_kernel_address(Elf64_Ehdr *ehdr)
{
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

		if (phdr->p_flags == (PF_X | PF_R))
			return (phdr->p_paddr);
	}
	return (0);
}

size_t
elf_load_size(Elf64_Ehdr *ehdr)
{
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

		if (start == 0 || start < phdr->p_paddr) {
			start = phdr->p_paddr;
		}

		if (end < phdr->p_paddr)
			end = phdr->p_paddr;

		/* Take account memory size */
		end += phdr->p_memsz;
	}

	/*
	 * XXX reserve space for stack, xboot_info and page table?
	 */
	return (end - start);
}

static int
dboot_loadfile(char *filename, uint64_t dest, struct preloaded_file **result)
{
	int fd, error;
	size_t size;
	ssize_t rsize;
	struct preloaded_file *fp;
	Elf64_Ehdr *ehdr;
	vm_offset_t addr = 0;
	void *page;

	/* This allows to check other file formats from file_formats array. */
	error = EFTYPE;
	if (filename == NULL)
		return (error);

	/* is kernel already loaded? */
	fp = file_findfile(NULL, NULL);
	if (fp != NULL)
		return (error);

	fd = open(filename, O_RDONLY);
	if (fd == -1)
		return (errno);

	page = malloc(PAGE_SIZE);
	if (page == NULL) {
		close(fd);
		return (errno);
	}

	fp = file_alloc();
	if (fp == NULL) {
		printf("%s: %s\n", __func__, strerror(errno));
		error = errno;
		goto error;
	}

	rsize = read(fd, page, PAGE_SIZE);
	if (rsize < 0 || rsize < (ssize_t)PAGE_SIZE)
		goto error;

	ehdr = page;
	/* Is it ELF? */
	if (!IS_ELF(*ehdr))
		goto error;

	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
	    ehdr->e_ident[EI_OSABI] != ELFOSABI_SOLARIS ||
	    ehdr->e_machine != EM_AMD64 ||
	    ehdr->e_type != ET_EXEC ||
	    ehdr->e_phnum == 0 || ehdr->e_phoff == 0)
		goto error;

	dest = elf_kernel_address(ehdr);
	if (archsw.arch_loadaddr != NULL)
		addr = archsw.arch_loadaddr(LOAD_ELF, ehdr, dest);
	if (addr == 0) {
		printf("%s: failed to allocate staging area for kernel\n",
		    __func__);
		goto error;
	}

	vm_offset_t start, dst;
	vm_offset_t allphdrs;

	allphdrs = (vm_offset_t)ehdr + ehdr->e_phoff;
	start = 0;
	dst = 0;

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

		if (start == 0)
			start = phdr->p_paddr;
		dst = addr + (phdr->p_paddr - start);

		size = 0;

		/*
		 * Is our data within first page we did read?
		 * If so, copy bytes from page, then read in
		 * remaining bytes.
		 */
		if (phdr->p_offset < PAGE_SIZE) {
			void *src = page + phdr->p_offset;
			size = PAGE_SIZE - phdr->p_offset;
			rsize = archsw.arch_copyin(src, dst, size);
			if (rsize < 0 || rsize != (ssize_t)size) {
				error = errno;
				goto error;
			}
			dst += size;
		}

		if (phdr->p_filesz > size) {
			printf("%s: buffer read -> %#jx %zu bytes\n",
			    __func__, dst, phdr->p_filesz - size);
			rsize = kern_pread(fd, dst, phdr->p_filesz - size,
			    phdr->p_offset + size);
			if (rsize == -1) {
				error = errno;
				goto error;
			}
			dst += (phdr->p_filesz - size);
		}
		/* clear space from oversized segments, bss */
		if (phdr->p_filesz < phdr->p_memsz) {
			size = phdr->p_memsz - phdr->p_filesz;
			printf("%s: zeroing %#jx %zu bytes\n",
			    __func__, dst, size);
			kern_bzero(dst, size);
			dst += size;
		}
	}

	fp->f_name = strdup(filename);
	fp->f_type = strdup("elf multiboot2 kernel");
	fp->f_addr = start;
	fp->f_size = dst - start;
	*result = fp;
	error = 0;
error:
	if (error != 0)
		file_discard(fp);
	free(page);
	close(fd);
	return (error);
}

static int
dboot_exec(struct preloaded_file *fp)
{
	return (0);
}
