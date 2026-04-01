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
#include <stdbool.h>
#include <sys/param.h>
#include <efi.h>
#include <efilib.h>
#include <machine/elf.h>
#include <sys/bootinfo.h>
#include <sys/framebuffer.h>
#include "platform/acfreebsd.h"
#include "acconfig.h"
#define ACPI_SYSTEM_XFACE
#include "actypes.h"
#include "actbl.h"
#include <zalloc_defs.h>
#include "bootstrap.h"
#include "gfx_fb.h"

typedef uint64_t maddr_t;
typedef uint64_t paddr_t;

#include <sys/machparam.h>
#undef __unused
#include <sys/mach_mmu.h>

extern ACPI_TABLE_RSDP *rsdp;

#define	STACK_SIZE	0x8000

static int dboot_loadfile(char *, uint64_t, struct preloaded_file **);
static int dboot_exec(struct preloaded_file *);

struct file_format dboot = { dboot_loadfile, dboot_exec };

/*
 * Our memory allocations and layout starts from kernel, the first hint is
 * from ELF program header p_paddr for text segment (0x400000).
 * text segment is followed by data and bss, current 32-bit dboot
 * is using the value 8MB for size of the nucleus.
 *
 * The first early allocations are done from the end of the nucleus.
 * However, there is a BUT.
 *
 * dboot is set to be loaded at physical addresss 0xc00000, and is expected
 * to be loaded as raw file - if the kernel is started via trampoline to dboot,
 * it means we have unix elf file loaded at 0xc00000 - size of elf header,
 * and is followed by multiboot info and modules.
 *
 * To use memory from dboot, the allocator is using variable 'next_avail_addr'
 * for a starting point for unused memory, and its set to point to past
 * currently known used memory - that is, at the end of the loaded modules.
 *
 * To put illumos nucleus in place, dboot does allocate nucleus pages and
 * will copy kernel text, data and bss pages to allocated area.
 * dboot does not use addresses from ELF program headers as we can observe
 * from debug log:
 *
 *	Allocating nucleus pages.
 *	load_addr is 0xbffea8
 *	Skipping PT_LOAD segment for paddr = 0xc00000
 *	copying 1527600 bytes from ELF offset 0x1b000 to physaddr 0x1b000000
 *	(va=0xfb800000)
 *	copying 151144 bytes from ELF offset 0x190000 to physaddr 0x1b400000
 *	(va=0xfbc00000)
 *	zeroing BSS 570208 bytes from physaddr 0x1b424e68 (end=0x1b4b01c8)
 *
 * For dboot implementation in loader, it means that we can actually
 * verify memory map for nucleus location and avoid possible conflicts.
 *
 * It also means, it may be possible for us to avoid relocations of
 * loaded components.
 */

/*
 * start of kernel text, physical address and virtual.
 */
extern vm_offset_t ktext_phys;
extern vm_offset_t target_kernel_text;
extern size_t kernel_load_size;
extern EFI_PHYSICAL_ADDRESS elf_kernel_address(Elf64_Ehdr *);

extern EFI_PHYSICAL_ADDRESS load_limit;

/* set in cpuid.c */
extern bool largepage_support;
extern bool pge_support;
extern bool pae_support;
extern bool PAT_support;
extern bool NX_support;

static bool map_debug = false;

/*
 * elf_load_size() does calculate space needed for unix ELF sections.
 */
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

		if (start == 0 && start < phdr->p_paddr) {
			start = phdr->p_paddr;
			continue;
		}

		if (end < phdr->p_paddr)
			end = phdr->p_paddr;

		/* Take account memory size */
		end += phdr->p_memsz;
	}

	kernel_load_size = round_page(end - start);
	return (kernel_load_size);
}

static int
dboot_loadfile(char *filename, uint64_t dest, struct preloaded_file **result)
{
	int fd, error;
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

	page = malloc(EFI_PAGE_SIZE);
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

	rsize = read(fd, page, EFI_PAGE_SIZE);
	if (rsize < 0 || rsize < (ssize_t)EFI_PAGE_SIZE)
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

	/*
	 * We are done checking. Set the limit to lift 4GB barrier.
	 */
	load_limit = UINT64_MAX;
	addr = archsw.arch_loadaddr(LOAD_ELF, ehdr, elf_kernel_address(ehdr));
	if (addr == 0) {
		printf("%s: failed to allocate staging area for kernel\n",
		    __func__);
		goto error;
	}

	fp->f_name = strdup(filename);
	fp->f_type = strdup("elf multiboot2 kernel");
	fp->f_addr = addr;
	fp->f_size = kernel_load_size;

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

		size_t size = 0;
		/*
		 * Is our data within first page we did read?
		 * If so, copy bytes from page, then read in
		 * remaining bytes.
		 */
		if (phdr->p_offset < EFI_PAGE_SIZE) {
			void *src = page + phdr->p_offset;
			size = EFI_PAGE_SIZE - phdr->p_offset;
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

	*result = fp;
	error = 0;
error:
	if (error != 0)
		file_discard(fp);
	free(page);
	close(fd);
	return (error);
}

/*
 * Build page tables to map all of memory used so far as well as the kernel.
 */

x86pte_t ptp_bits = PT_VALID | PT_REF | PT_WRITABLE | PT_USER;
x86pte_t pte_bits = PT_VALID | PT_REF | PT_WRITABLE | PT_MOD | PT_NOCONSIST;

x86pte_t
get_pteval(paddr_t table, uint_t index)
{
	return (((x86pte_t *)(uintptr_t)table)[index]);
}

void
set_pteval(paddr_t table, uint_t index, uint_t level, x86pte_t pteval)
{
	uintptr_t tab_addr = (uintptr_t)table;

	((x86pte_t *)tab_addr)[index] = pteval;
	if (level == top_level && level == 2)
		reload_cr3();
}

paddr_t
make_ptable(x86pte_t *pteval, uint_t level)
{
	paddr_t new_table = (paddr_t)(uintptr_t)calloc(1, MMU_PAGESIZE);

	if (level == top_level && level == 2)
		*pteval = pa_to_ma((uintptr_t)new_table) | PT_VALID;
	else
		*pteval = pa_to_ma((uintptr_t)new_table) | ptp_bits;

	if (map_debug)
		printf("new page table lvl=%u paddr=0x%lx ptp=0x%lx\n",
		    level, (ulong_t)new_table, *pteval);
	return (new_table);
}

x86pte_t *
map_pte(paddr_t table, uint_t index)
{
	return ((x86pte_t *)(uintptr_t)(table + index * pte_size));
}

/*
 * Add a mapping for the machine page at the given virtual address.
 */
static void
map_ma_at_va(maddr_t ma, native_ptr_t va, uint_t level)
{
	x86pte_t *ptep;
	x86pte_t pteval;

	pteval = ma | pte_bits;
	if (level > 0)
		pteval |= PT_PAGESIZE;
	if (va >= target_kernel_text && pge_support)
		pteval |= PT_GLOBAL;

	if (map_debug && ma != va)
		printf("mapping ma=0x%jx va=0x%jx pte=0x%jx l=%d\n",
		    (uintmax_t)ma, (uintmax_t)va, pteval, level);

	/*
	 * Find the pte that will map this address. This creates any
	 * missing intermediate level page tables
	 */
	ptep = find_pte(va, NULL, level, 0);

	if (va < 1024 * 1024)
		pteval |= PT_NOCACHE;           /* for video RAM */
	*ptep = pteval;
}

/*
 * Add a mapping for the physical page at the given virtual address.
 */
static void
map_pa_at_va(paddr_t pa, native_ptr_t va, uint_t level)
{
	map_ma_at_va(pa_to_ma(pa), va, level);
}

static void
build_page_tables(struct xboot_info *bp)
{
	uint32_t ksize, psize;
	uint32_t level;
	uint32_t off;
	uint64_t start;
	// uint32_t i;
	// uint64_t end;

	psize = 2 << 20;	/* 2MB */
	ksize = 8 << 20;	/* kernel nucleus is 8Meg */
	ptes_per_table = 512;
	pte_size = 8;
	top_level = 3;
	level = 1;

	for (off = 0; off < ksize; off += psize)
		map_pa_at_va(ktext_phys + off, target_kernel_text + off, level);
	bp->bi_pte_to_pt_window =
	    (uintptr_t)find_pte(bp->bi_pt_window, NULL, 0, 0);
	if (map_debug)
		printf("1:1 map pa=0..1Meg\n");
	for (start = 0; start < 1024 * 1024; start += EFI_PAGE_SIZE) {
		map_pa_at_va(start, start, 0);
	}
}

static int
dboot_exec(struct preloaded_file *fp)
{
	extern MemPool LoaderPool;
	struct devdesc *rootdev;
	struct xboot_info *bp;
	boot_framebuffer_t *fb;
	char *buf;
	int rv;

	if (getenv("map_debug") != NULL)
		map_debug = true;

	shift_amt = shift_amt_pae;

	efi_getdev((void **)(&rootdev), NULL, NULL);
	if (rootdev == NULL) {
		printf("can't determine root device\n");
		rv = EINVAL;
		goto error;
	}

	bp = znalloc_align(&LoaderPool, sizeof (*bp), EFI_PAGE_SIZE);
	if (bp == NULL)
		return (ENOMEM);
	bzero(bp, sizeof (*bp));
	if (map_debug)
		printf("%s: bp: %p\n", __func__, bp);

	// XXX
	vm_offset_t free_offset = 0;
	top_page_table = fp->f_addr + free_offset;
	bzero((void *)top_page_table, 2 * EFI_PAGE_SIZE);
	bp->bi_top_page_table = ktext_phys + free_offset;
	free_offset += EFI_PAGE_SIZE;
	bp->bi_pt_window = ktext_phys + free_offset;
	free_offset += EFI_PAGE_SIZE;
	free_offset += sizeof (*bp);
	fb = (boot_framebuffer_t *)
	    roundup2(fp->f_addr + free_offset, 0x10);
	bp->bi_framebuffer = (native_ptr_t)
	    roundup2(ktext_phys + free_offset, 0x10);
	free_offset = ((uintptr_t)fb - (uintptr_t)fp->f_addr) + sizeof (*fb);

	bp->bi_uefi_arch = XBI_UEFI_ARCH_64;
	bp->bi_uefi_systab = (native_ptr_t)ST;
	bp->bi_acpi_rsdp = (native_ptr_t)rsdp;
	bp->bi_acpi_rsdp_copy = 0;

	bp->bi_smbios = 0;
	buf = getenv("smbios-address");
	if (buf != NULL) {
		errno = 0;
		bp->bi_smbios = strtoull(buf, NULL, 0);
		if (errno != 0)
			bp->bi_smbios = 0;
	}

	bp->bi_use_largepage = largepage_support;
	bp->bi_use_pge = pge_support;
	bp->bi_use_pae = pae_support;
	bp->bi_use_nx = NX_support;

	build_page_tables(bp);
#if 0
        uint64_t        bi_next_paddr;  /* next physical address not used */
        native_ptr_t    bi_next_vaddr;  /* next virtual address not used */
        native_ptr_t    bi_cmdline;
        native_ptr_t    bi_phys_install;
        native_ptr_t    bi_rsvdmem;
        native_ptr_t    bi_pcimem;
        native_ptr_t    bi_modules;
        uint32_t        bi_module_cnt;
        native_ptr_t    bi_pte_to_pt_window;
        native_ptr_t    bi_kseg_size;   /* size used for kernel nucleus pages */
        native_ptr_t    bi_mb_info;             /* multiboot 1 or 2 info */

PAT_support;
#endif
        bp->bi_mb_version = 2;

	/* Fill framebuffer data */
	fb->framebuffer = (native_ptr_t)&gfx_fb;
	errno = 0;
	buf = getenv("tem.cursor.origin.x");
	fb->cursor.origin.x = strtoul(buf, NULL, 0);
	buf = getenv("tem.cursor.origin.y");
	fb->cursor.origin.y = strtoul(buf, NULL, 0);
	buf = getenv("tem.cursor.col");
	fb->cursor.pos.x = strtoul(buf, NULL, 0);
	buf = getenv("tem.cursor.row");
	fb->cursor.pos.y = strtoul(buf, NULL, 0);
	if (getenv("tem.cursor.visible") != NULL)
		fb->cursor.visible = B_TRUE;
	else
		fb->cursor.visible = B_FALSE;

	rv = 0;
error:
	return (rv);
}
