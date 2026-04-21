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
#include <sys/segments.h>
#include <machine/elf.h>
#include <sys/bootinfo.h>
#include <sys/framebuffer.h>
#include "platform/acfreebsd.h"
#include "acconfig.h"
#define ACPI_SYSTEM_XFACE
#include "actypes.h"
#include "actbl.h"
#include <zalloc_loader.h>
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
extern int mb_kernel_cmdline(struct preloaded_file *,
    struct devdesc *, char **);

extern EFI_PHYSICAL_ADDRESS load_limit;

/* set in cpuid.c */
extern bool largepage_support;
extern bool pge_support;
extern bool pae_support;
extern bool PAT_support;
extern bool NX_support;

static uint64_t next_avail_addr;
static uint64_t page_index;
static uint64_t page_count;

static bool map_debug = false;
static bool prom_debug = false;

#define	DBG_MSG(s)	do { if (prom_debug)	\
	printf(s);				\
	} while (0)

#define	DBG(x)		do { if (prom_debug) {		\
	printf("%s is 0x%jx\n", #x, (uint64_t)(x));	\
	} } while (0)

desctbr_t gdt_info;

static user_desc_t gdt_template[] = {
	[GDT_NULL] = { 0 },
	[GDT_B32DATA] = {
		.usd_lolimit = 0xffff,
		.usd_lobase = 0x0,
		.usd_midbase = 0x0,
		.usd_type = 0x13,
		.usd_dpl = 0x0,
		.usd_p = 0x1,
		.usd_hilimit = 0xf,
		.usd_avl = 0x0,
		.usd_long = 0x0,
		.usd_def32 = 0x1,
		.usd_gran = 0x1,
		.usd_hibase = 0x0 },
	[GDT_B32CODE] = {
		.usd_lolimit = 0xffff,
		.usd_lobase = 0x0,
		.usd_midbase = 0x0,
		.usd_type = 0x1b,
		.usd_dpl = 0x0,
		.usd_p = 0x1,
		.usd_hilimit = 0xf,
		.usd_avl = 0x0,
		.usd_long = 0x0,
		.usd_def32 = 0x1,
		.usd_gran = 0x1,
		.usd_hibase = 0x0 },
	[GDT_B16CODE] = {
		.usd_lolimit = 0xffff,
		.usd_lobase = 0x0,
		.usd_midbase = 0x0,
		.usd_type = 0x1b,
		.usd_dpl = 0x0,
		.usd_p = 0x1,
		.usd_hilimit = 0xf,
		.usd_avl = 0x0,
		.usd_long = 0x0,
		.usd_def32 = 0x0,
		.usd_gran = 0x0,
		.usd_hibase = 0x0 },
	[GDT_B16DATA] = {
		.usd_lolimit = 0xffff,
		.usd_lobase = 0x0,
		.usd_midbase = 0x0,
		.usd_type = 0x13,
		.usd_dpl = 0x0,
		.usd_p = 0x1,
		.usd_hilimit = 0xf,
		.usd_avl = 0x0,
		.usd_long = 0x0,
		.usd_def32 = 0x1,
		.usd_gran = 0x0,
		.usd_hibase = 0x0 },
	[GDT_B64CODE] = {
		.usd_lolimit = 0xffff,
		.usd_lobase = 0x0,
		.usd_midbase = 0x0,
		.usd_type = 0x1b,
		.usd_dpl = 0x0,
		.usd_p = 0x1,
		.usd_hilimit = 0xf,
		.usd_avl = 0x0,
		.usd_long = 0x1,
		.usd_def32 = 0x0,
		.usd_gran = 0x1,
		.usd_hibase = 0x0 },
	[GDT_KCODE] = {
		.usd_lolimit = 0x0,
		.usd_lobase = 0x0,
		.usd_midbase = 0x0,
		.usd_type = 0x1b,
		.usd_dpl = 0x0,
		.usd_p = 0x1,
		.usd_hilimit = 0x0,
		.usd_avl = 0x0,
		.usd_long = 0x1,
		.usd_def32 = 0x0,
		.usd_gran = 0x1,
		.usd_hibase = 0x0 },
	[GDT_BGSTMP] = {
		.usd_lolimit = 0x1,
		.usd_lobase = 0x0,
		.usd_midbase = 0x0,
		.usd_type = 0x1b,
		.usd_dpl = 0x0,
		.usd_p = 0x1,
		.usd_hilimit = 0x0,
		.usd_avl = 0x0,
		.usd_long = 0x0,
		.usd_def32 = 0x1,
		.usd_gran = 0x1,
		.usd_hibase = 0x0 },
};

static int
init_gdt(void)
{
	user_desc_t *gdt;

	gdt = loader_alloc_align(sizeof (gdt_template), EFI_PAGE_SIZE);
	if (gdt == NULL)
		return (ENOMEM);

	memcpy(gdt, gdt_template, sizeof (gdt_template));
	gdt_info.dtr_limit = sizeof (gdt_template) - 1;
	gdt_info.dtr_base = vtop((caddr_t)gdt);
	return (0);
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
			if (prom_debug) {
				printf("%s: buffer read -> %#jx %zu bytes\n",
				    __func__, dst, phdr->p_filesz - size);
			}
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
			if (prom_debug) {
				printf("%s: zeroing %#jx %zu bytes\n",
				    __func__, dst, size);
			}
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
	paddr_t new_table;

	if (page_index == page_count)
		panic("not enough memory for page tables\n");

	new_table = (paddr_t)(uintptr_t)
	    (top_page_table + page_index * EFI_PAGE_SIZE);
	page_index++;

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
 * dump out the contents of page tables...
 */
static void
dump_tables(void)
{
	uint_t save_index[4];   /* for recursion */
	char *save_table[4];    /* for recursion */
	uint_t l;
	uint64_t va;
	uint64_t pgsize;
	int index;
	int i;
	x86pte_t pteval;
	char *table;
	static char *tablist = "\t\t\t";
	char *tabs = tablist + 3 - top_level;
	uint_t pa, pa1;

	printf("Finished pagetables:\n");
	table = (char *)(uintptr_t)top_page_table;
	l = top_level;
	va = 0;
	for (index = 0; index < ptes_per_table; ++index) {
		pgsize = 1ull << shift_amt[l];
		if (pae_support)
			pteval = ((x86pte_t *)table)[index];
		else
			pteval = ((x86pte32_t *)table)[index];
		if (pteval == 0)
			goto next_entry;

		printf("%s %p[0x%x] = %jx, va=%jx",
		    tabs + l, (void *)table, index, (uint64_t)pteval, va);
		pa = ma_to_pa(pteval & MMU_PAGEMASK);
		printf(" physaddr=%x\n", pa);

		/*
		 * Don't try to walk hypervisor private pagetables
		 */
		if ((l > 1 || (l == 1 && (pteval & PT_PAGESIZE) == 0))) {
			save_table[l] = table;
			save_index[l] = index;
			--l;
			index = -1;
			table = (char *)(uintptr_t)
			    ma_to_pa(pteval & MMU_PAGEMASK);
			goto recursion;
		}
		/*
		 * shorten dump for consecutive mappings
		 */
		for (i = 1; index + i < ptes_per_table; ++i) {
			if (pae_support)
				pteval = ((x86pte_t *)table)[index + i];
			else
				pteval = ((x86pte32_t *)table)[index + i];
			if (pteval == 0)
				break;
			pa1 = ma_to_pa(pteval & MMU_PAGEMASK);
			if (pa1 != pa + i * pgsize)
				break;
		}
		if (i > 2) {
			printf("%s...\n", tabs + l);
			va += pgsize * (i - 2);
			index += i - 2;
		}
next_entry:
		va += pgsize;
		if (l == 3 && index == 255)	/* VA hole */
			va = 0xffff800000000000ull;
recursion:
		;
	}
	if (l < top_level) {
		++l;
		index = save_index[l];
		table = save_table[l];
		goto recursion;
	}
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

/*
 * Count the number of page-table pages (each MMU_PAGESIZE) that find_pte()
 * would allocate via make_ptable() to map the contiguous VA range
 * [va_start, va_end) with the given leaf mapping level.
 *
 * For each intermediate level l in [leaf_level .. top_level-1], a distinct
 * level-l table is needed per aligned (1 << shift_amt[l+1])-byte block.
 * The top-level page table is pre-allocated once and is NOT counted here.
 */
static uint64_t
count_pgtable_pages_for_range(uint64_t va_start, uint64_t va_end,
    uint_t leaf_level)
{
	uint_t l;
	uint64_t count = 0;

	if (va_start >= va_end)
		return (0);

	for (l = leaf_level; l < top_level; l++) {
		uint64_t block = 1ULL << shift_amt[l + 1];
		count += (va_end - 1) / block - va_start / block + 1;
	}

	return (count);
}

static uint64_t
count_page_tables_needed(uint32_t ksize)
{
	uint64_t count;
	uint_t leaf_level;

	/* One page for the top-level table (PML4 / PDPE / PD) */
	count = 1;

	/* Leaf level depends on large-page support */
	leaf_level = largepage_support ? 1 : 0;

	/* Kernel text mapped at target_kernel_text */
	count += count_pgtable_pages_for_range(target_kernel_text,
	    target_kernel_text + ksize, leaf_level);

	/*
	 * 1:1 physical memory [0, next_avail_addr) at 4KB pages.
	 * This is a superset of the explicit [0, 1MB) low-memory mapping,
	 * so counting it once covers both.  The pt_window page allocated
	 * inside build_page_tables() lands within this range too.
	 */
	if (next_avail_addr > 0)
		count += count_pgtable_pages_for_range(0, next_avail_addr, 0);

	/* Framebuffer device memory, 1:1 mapped at level 0 */
	uint64_t fb_start =
	    gfx_fb.framebuffer_common.framebuffer_addr;
	uint64_t fb_end = fb_start +
	    gfx_fb.framebuffer_common.framebuffer_height *
	    gfx_fb.framebuffer_common.framebuffer_pitch;
	/*
	 * Only count pages for the portion of the framebuffer that
	 * lies outside [0, next_avail_addr); tables for the overlap
	 * were already counted in the 1:1 range above.
	 */
	if (fb_end > next_avail_addr) {
		uint64_t fb_uncovered =
		    MAX(fb_start, next_avail_addr);
		count += count_pgtable_pages_for_range(
		    fb_uncovered, fb_end, 0);
	}
	return (count);
}

static void
build_page_tables(struct xboot_info *bi)
{
	struct boot_memlist *ml;
	uint32_t ksize, psize;
	uint32_t level;
	uint32_t off;
	uint64_t start;
	uint64_t end;
	void *tptable;

	psize = 2 << 20;	/* 2MB */
	ksize = 8 << 20;	/* kernel nucleus is 8Meg */
	ptes_per_table = 512;
	pte_size = 8;
	top_level = 3;
	level = 1;

	DBG(top_level);
	DBG(pte_size);
	DBG(ptes_per_table);

	next_avail_addr = vtop(loader_alloc_next_avail());
	if (next_avail_addr == 0)
		panic("no next_avail_addr\n");

	page_index = 0;
	page_count = count_page_tables_needed(ksize) + 1;
	DBG(page_count);
	/*
	 * Allocate pages for whole map.
	 */
	tptable = loader_alloc_align(EFI_PAGE_SIZE * page_count, EFI_PAGE_SIZE);
	if (tptable == NULL)
		panic("Failed to allocate page tables\n");

	next_avail_addr = vtop(loader_alloc_next_avail());
	if (next_avail_addr == 0)
		panic("no next_avail_addr\n");

	bzero(tptable, EFI_PAGE_SIZE * page_count);
	page_index++;
	top_page_table = (uintptr_t)(vtop(tptable));
	bi->bi_top_page_table = (uintptr_t)top_page_table;
	DBG(bi->bi_top_page_table);
	bi->bi_pt_window = (native_ptr_t)(top_page_table + EFI_PAGE_SIZE);
	page_index++;

	DBG_MSG("Mapping kernel\n");
	DBG(ktext_phys);
        DBG(target_kernel_text);
        DBG(ksize);
        DBG(psize);
	for (off = 0; off < ksize; off += psize)
		map_pa_at_va(ktext_phys + off, target_kernel_text + off, level);

	DBG(bi->bi_pt_window);
	bi->bi_pte_to_pt_window = (native_ptr_t)(uintptr_t)
	    find_pte(bi->bi_pt_window, NULL, 0, 0);
	DBG(bi->bi_pte_to_pt_window);

	if (map_debug)
		printf("1:1 map pa=0..1Meg\n");
	for (start = 0; start < 1024 * 1024; start += EFI_PAGE_SIZE) {
		map_pa_at_va(start, start, 0);
	}

	for (ml = (struct boot_memlist *)ptov(bi->bi_phys_install);
	    ml != NULL; ml = (struct boot_memlist *)ptov(ml->next)) {
		start = ml->addr;
                end = start + ml->size;
		if (map_debug)
			printf("1:1 map pa=%jx..%jx\n", start, end);
		while (start < end && start < next_avail_addr) {
			map_pa_at_va(start, start, 0);
			start += EFI_PAGE_SIZE;
		}
		if (start >= next_avail_addr)
			break;
	}

	/*
	 * Map framebuffer memory as PT_NOCACHE as this is memory from a
	 * device and therefore must not be cached.
	 */
	start = gfx_fb.framebuffer_common.framebuffer_addr;
	end = start + gfx_fb.framebuffer_common.framebuffer_height *
	    gfx_fb.framebuffer_common.framebuffer_pitch;

	if (map_debug)
		printf("FB 1:1 map pa=%jx..%jx\n", start, end);
	pte_bits |= PT_NOCACHE;
	if (PAT_support != 0)
		pte_bits |= PT_PAT_4K;

	while (start < end) {
		map_pa_at_va(start, start, 0);
		start += MMU_PAGESIZE;
	}
	pte_bits &= ~PT_NOCACHE;
	if (PAT_support != 0)
		pte_bits &= ~PT_PAT_4K;

	bi->bi_top_page_table = (native_ptr_t)vtop((caddr_t)top_page_table);
	bi->bi_pt_window = bi->bi_top_page_table + EFI_PAGE_SIZE;

	DBG_MSG("\nPage tables constructed\n");
	bi->bi_next_paddr = next_avail_addr;
	DBG(bi->bi_next_paddr);
	bi->bi_next_vaddr = next_avail_addr;
	DBG(bi->bi_next_vaddr);

	if (map_debug)
		dump_tables();
}

static int
dboot_add_modules(struct xboot_info *bi, struct preloaded_file *fp)
{
	int i;
	struct preloaded_file *mfp;

	DBG_MSG("\nFinding Modules\n");
	/* Count the modules */
	for (mfp = fp->f_next; mfp != NULL; mfp = mfp->f_next)
		bi->bi_module_cnt++;

	if (bi->bi_module_cnt == 0)
		return (0);

	struct boot_modules *bm;
	bm = loader_alloc_align(bi->bi_module_cnt * sizeof (*bm), 16);
	if (bm == NULL)
		return (ENOMEM);

	/* Populate modules array */
	i = 0;
	for (mfp = fp->f_next; mfp != NULL; mfp = mfp->f_next) {
		bm[i].bm_addr = mfp->f_addr;

		bm[i].bm_name = 0;
		if (mfp->f_name != NULL) {
			char *name;
			name = loader_alloc_align(strlen(mfp->f_name) + 1, 1);
			if (name != NULL)
				strcpy(name, mfp->f_name);
			bm[i].bm_name = (native_ptr_t)vtop(name);
		}
		bm[i].bm_hash = 0;
		if (mfp->f_args != NULL) {
			char *begin, *end, *hash;

			begin = strstr(mfp->f_args, "hash=");
			if (begin != NULL) {
				char *ptr = strdup(begin + 5);

				if (ptr == NULL)
					return (ENOMEM);
				/* arguments are separated by space */
				end = strchr(ptr, ' ');
				if (end != NULL)
					*end = '\0';
				hash = loader_alloc_align(strlen(ptr) + 1, 1);
				if (hash != NULL)
					strcpy(hash, ptr);
				bm[i].bm_hash = (native_ptr_t)vtop(hash);
				free(ptr);
			}
		}

		bm[i].bm_size = mfp->f_size;
		bm[i].bm_type = BMT_FILE;
		if (mfp->f_type != NULL) {
			if (strcmp(mfp->f_type, "rootfs") == 0)
				bm[i].bm_type = BMT_ROOTFS;
			if (strcmp(mfp->f_type, "console-font") == 0)
				bm[i].bm_type = BMT_FONT;
			else if (strcmp(mfp->f_type, "environment") == 0)
				bm[i].bm_type = BMT_ENV;
		}
		i++;
	}
        bi->bi_modules = (native_ptr_t)vtop((caddr_t)bm);
	DBG(bi->bi_modules);
	DBG(bi->bi_module_cnt);
	return (0);
}

/*
 * Fill framebuffer data. UEFI does not need to provide
 * colormap, we can copy gfx_fb verbatim.
 */
static int
dboot_add_framebuffer(struct xboot_info *bi)
{
	boot_framebuffer_t *fb;
	multiboot_tag_framebuffer_t *gfx;
	char *buf;

	fb = loader_alloc_align(sizeof (*fb), 16);
	if (fb == NULL)
		return (ENOMEM);
	bzero(fb, sizeof (*fb));

	gfx = loader_alloc_align(sizeof (*gfx), 16);
	if (gfx == NULL)
		return (ENOMEM);

	memcpy(gfx, &gfx_fb, sizeof (*gfx));
	fb->framebuffer = vtop((caddr_t)gfx);

	errno = 0;
	buf = getenv("tem.cursor.origin.x");
	if (buf != NULL)
		fb->cursor.origin.x = strtoul(buf, NULL, 0);
	buf = getenv("tem.cursor.origin.y");
	if (buf != NULL)
		fb->cursor.origin.y = strtoul(buf, NULL, 0);
	buf = getenv("tem.cursor.col");
	if (buf != NULL)
		fb->cursor.pos.x = strtoul(buf, NULL, 0);
	buf = getenv("tem.cursor.row");
	if (buf != NULL)
		fb->cursor.pos.y = strtoul(buf, NULL, 0);
	if (getenv("tem.cursor.visible") != NULL)
		fb->cursor.visible = B_TRUE;
	else
		fb->cursor.visible = B_FALSE;
	bi->bi_framebuffer = (native_ptr_t)vtop((caddr_t)fb);
	return (0);
}

/*
 * Build xboot_info memlists from UEFI memory map.
 */
#define	MAX_MEMLIST	50
#define	PCI_LO_LIMIT	0x00100000ul
#define	PCI_HI_LIMIT	0xfff00000ul

static void
exclude_from_pci(struct boot_memlist *pcimemlists, uint_t *usedp,
    uint64_t start, uint64_t end)
{
	uint_t i, j;
	struct boot_memlist *ml;
	uint_t pcimemlists_used = *usedp;

	for (i = 0; i < pcimemlists_used; ++i) {
		ml = &pcimemlists[i];

		/* delete the entire range? */
		if (start <= ml->addr && ml->addr + ml->size <= end) {
			--pcimemlists_used;
			for (j = i; j < pcimemlists_used; ++j)
				pcimemlists[j] = pcimemlists[j + 1];
			--i;    /* to revisit the new one at this index */
		} else if (ml->addr < start && end < ml->addr + ml->size) {
			/* split a range? */

			++pcimemlists_used;
			if (pcimemlists_used > MAX_MEMLIST)
				panic("too many pcimemlists");

			for (j = pcimemlists_used - 1; j > i; --j)
				pcimemlists[j] = pcimemlists[j - 1];
			ml->size = start - ml->addr;

			++ml;
			ml->size = (ml->addr + ml->size) - end;
			ml->addr = end;
			++i;    /* skip on to next one */
		} else if (ml->addr < end && end < ml->addr + ml->size) {
			/* cut memory off the start? */
			ml->size -= end - ml->addr;
			ml->addr = end;
		} else if (ml->addr <= start && start < ml->addr + ml->size) {
			/* cut memory off the end? */
			ml->size = start - ml->addr;
		}
	}
	*usedp = pcimemlists_used;
}

static int
build_pcimemlists(struct xboot_info *bi, EFI_MEMORY_DESCRIPTOR *map,
    uint_t ndesc, UINTN dsz)
{
	struct boot_memlist *pcimemlists, *ml;
	uint64_t page_offset = MMU_PAGEOFFSET;  /* needs to be 64 bits */
	uint64_t start;
	uint64_t end;
	uint_t pcimemlists_used, max_memlist;
	uint_t i;

	DBG_MSG("building pcimemlists:\n");
	/*
	 * initialize
	 */
	max_memlist = MAX_MEMLIST;
	pcimemlists = calloc(max_memlist, sizeof (*pcimemlists));
	if (pcimemlists == NULL) {
		return (ENOMEM);
	}
	pcimemlists[0].addr = PCI_LO_LIMIT;
	pcimemlists[0].size = PCI_HI_LIMIT - PCI_LO_LIMIT;
	pcimemlists_used = 1;

	/*
	 * Fill in PCI memlists.
	 */
	for (i = 0; i < ndesc; ++i, map = NextMemoryDescriptor(map, dsz)) {
		start = map->PhysicalStart;
		end = start + (map->NumberOfPages << EFI_PAGE_SHIFT);

		if (prom_debug)
			printf("\ttype: %s %jx..%jx\n",
			    efi_memory_type(map->Type),
			    start, end);

		/*
		 * page align start and end
		 */
		start = (start + page_offset) & ~page_offset;
		end &= ~page_offset;
		if (end <= start)
			continue;

		exclude_from_pci(pcimemlists, &pcimemlists_used, start, end);
	}

	/*
	 * Finish off the pcimemlist.
	 */
	ml = loader_alloc_align(pcimemlists_used * sizeof (*ml), 16);
	if (ml == NULL)
		panic("no memory for pcimemlists\n");
	memcpy(ml, pcimemlists, pcimemlists_used * sizeof (*ml));
	free(pcimemlists);

	if (prom_debug) {
		for (i = 0; i < pcimemlists_used; ++i) {
			printf("pcimemlist entry 0x%jx..0x%jx\n",
			    ml[i].addr,
			    ml[i].addr + ml[i].size);
		}
	}
	ml[0].next = 0;
	ml[0].prev = 0;
	for (i = 1; i < pcimemlists_used; ++i) {
		ml[i].prev =
		    (native_ptr_t)vtop((caddr_t)(ml + i - 1));
		ml[i].next = 0;
		ml[i - 1].next =
		    (native_ptr_t)vtop((caddr_t)(ml + i));
	}

	bi->bi_pcimem = (native_ptr_t)vtop((caddr_t)ml);
	DBG(bi->bi_pcimem);

	return (0);
}

/*
 * sort/merge/link memlist for final use.
 */
static void
sort_physinstall(struct xboot_info *bi, struct boot_memlist *memlists,
    uint_t memlists_used)
{
	struct boot_memlist *ml;

	/*
	 * Now sort the memlists, in case they weren't in order.
	 * Yeah, this is a bubble sort; small, simple and easy to get right.
	 */
	DBG_MSG("Sorting phys-installed list\n");
	for (uint_t j = memlists_used - 1; j > 0; --j) {
		for (uint_t i = 0; i < j; ++i) {
			if (memlists[i].addr < memlists[i + 1].addr)
				continue;

			struct boot_memlist tmp;
			tmp = memlists[i];
			memlists[i] = memlists[i + 1];
			memlists[i + 1] = tmp;
		}
	}

	ml = loader_alloc_align(memlists_used * sizeof (*ml), 16);
	if (ml == NULL)
		panic("no memory for memlists\n");
	memcpy(ml, memlists, memlists_used * sizeof (*ml));
	free(memlists);

	if (prom_debug) {
		printf("\nFinal memlists:\n");
		for (uint_t i = 0; i < memlists_used; ++i) {
			printf("\t%d: addr=%jx size=%jx\n",
			    i, ml[i].addr, ml[i].size);
		}
	}

	/*
	* link together the memlists with native size pointers
	*/
	ml[0].next = 0;
	ml[0].prev = 0;
	for (uint_t i = 1; i < memlists_used; ++i) {
		ml[i].prev = (native_ptr_t)vtop((caddr_t)(ml + i - 1));
		ml[i].next = 0;
		ml[i - 1].next = (native_ptr_t)vtop((caddr_t)(ml + i));
	}
	bi->bi_phys_install = (native_ptr_t)vtop((caddr_t)ml);
	DBG(bi->bi_phys_install);
}

/*
 * build bios reserved memlists
 */
static void
build_rsvdmemlists(struct xboot_info *bi, struct boot_memlist *rsvdmemlists,
    uint_t rsvdmemlists_used)
{
	struct boot_memlist *ml;

	ml = loader_alloc_align(rsvdmemlists_used * sizeof (*ml), 16);
	if (ml == NULL)
		panic("no memory for rsvdmemlists\n");
	memcpy(ml, rsvdmemlists, rsvdmemlists_used * sizeof (*ml));
	free(rsvdmemlists);

	ml[0].next = 0;
	ml[0].prev = 0;
	for (uint_t i = 1; i < rsvdmemlists_used; ++i) {
		ml[i].prev =
		    (native_ptr_t)vtop((caddr_t)(ml + i - 1));
		ml[i].next = 0;
		ml[i - 1].next =
		    (native_ptr_t)vtop((caddr_t)(ml + i));
	}
	bi->bi_rsvdmem = (native_ptr_t)vtop((caddr_t)ml);
	DBG(bi->bi_rsvdmem);
}

static int
dboot_add_mmap(struct xboot_info *bi)
{
	EFI_STATUS status;
	EFI_MEMORY_DESCRIPTOR *map, *md;
	UINTN map_key, map_size, desc_size;
	UINT32 desc_ver;
	uint_t i, ndesc, *indexp;
	uint_t memlists_used, rsvdmemlists_used, max_memlist;
	struct boot_memlist *mlist, *memlists, *rsvdmemlists;

	status = efi_get_memory_map(&map_size, &map, &map_key,
	    &desc_size, &desc_ver);
	if (status != EFI_SUCCESS)
		return (efi_status_to_errno(status));

	max_memlist = MAX_MEMLIST;
	memlists = calloc(max_memlist, sizeof (*memlists));
	if (memlists == NULL)
		return (ENOMEM);
	rsvdmemlists = calloc(max_memlist, sizeof (*rsvdmemlists));
	if (rsvdmemlists == NULL) {
		free (memlists);
		return (ENOMEM);
	}

	memlists_used = 0;
	rsvdmemlists_used = 0;
	md = map;
	ndesc = map_size / desc_size;

	DBG_MSG("\nFinding Memory Map\n");

	for (i = 0; i < ndesc; i++, md = NextMemoryDescriptor(md, desc_size)) {
		uint64_t start;
		uint64_t end;

		start = md->PhysicalStart;
		end = start + (md->NumberOfPages << EFI_PAGE_SHIFT);

		if (prom_debug)
			printf("\ttype: %s %jx..%jx\n",
			    efi_memory_type(md->Type), start, end);

		switch (md->Type) {
		case EfiACPIMemoryNVS:
		case EfiACPIReclaimMemory:
			/* Treat page 0 as normal memory */
			if (start != 0)
				continue;
		case EfiLoaderCode:
		case EfiLoaderData:
		case EfiBootServicesCode:
		case EfiBootServicesData:
		case EfiConventionalMemory:
			mlist = memlists;
			indexp = &memlists_used;
			break;

		case EfiReservedMemoryType:
		case EfiRuntimeServicesCode:
		case EfiRuntimeServicesData:
		case EfiMemoryMappedIO:
		case EfiMemoryMappedIOPortSpace:
		case EfiPalCode:
		case EfiUnusableMemory:
		default:
			mlist = rsvdmemlists;
			indexp = &rsvdmemlists_used;
			break;
		}

		if (*indexp > max_memlist)
			panic("need to grow memlist!\n");

		if (mlist[*indexp].size != 0 &&
		    (mlist[*indexp].addr + mlist[*indexp].size) == start) {
			/* Grow this entry. */
			mlist[*indexp].size =
			    end - mlist[*indexp].addr;
			continue;
		}

		/* do we need new entry? */
		if (mlist[*indexp].size != 0) {
			*indexp = *indexp + 1;
			if (*indexp > max_memlist)
				panic("need to grow memlist!\n");
		}
		if (mlist[*indexp].size == 0) {
			mlist[*indexp].addr = start;
			mlist[*indexp].size = end - start;
		}
	}

	if (memlists[memlists_used].size != 0) {
		memlists_used++;
	}
	if (rsvdmemlists[rsvdmemlists_used].size != 0) {
		rsvdmemlists_used++;
	}

	if (prom_debug) {
		for (i = 0; i < memlists_used; i++) {
			printf("memlists[%u] %jx..%jx\n", i,
			    memlists[i].addr, memlists[i].size);
		}
		for (i = 0; i < rsvdmemlists_used; i++) {
			printf("rsvdmemlists[%u] %jx..%jx\n", i,
			    rsvdmemlists[i].addr, rsvdmemlists[i].size);
		}
	}

	build_pcimemlists(bi, map, ndesc, desc_size);

	/*
	 * finish processing the physinstall list
	 */
	sort_physinstall(bi, memlists, memlists_used);

	/*
	 * build bios reserved mem lists
	 */
	build_rsvdmemlists(bi, rsvdmemlists, rsvdmemlists_used);

	return (0);
}

/*
 * loader_alloc_ family functions do return virtual addresses.
 *
 * XXX - we need to pass bootp-response via MBI.
 */
static int
dboot_exec(struct preloaded_file *fp)
{
	char *cmdline, *stackp;
	vm_offset_t stack;
	struct devdesc *rootdev;
	struct xboot_info *bi;
	char *buf;
	int rv;
	extern void amd64_tramp(uint64_t, uint64_t, uint64_t, uint64_t);

	if (getenv("prom_debug") != NULL)
		prom_debug = true;

	if (getenv("map_debug") != NULL)
		map_debug = true;

	shift_amt = shift_amt_pae;

	rv = init_gdt();
	if (rv != 0)
		return (rv);

	efi_getdev((void **)(&rootdev), NULL, NULL);
	if (rootdev == NULL) {
		printf("can't determine root device\n");
		return (EINVAL);
	}

	rv = mb_kernel_cmdline(fp, rootdev, &cmdline);
	if (rv != 0)
		return (ENOMEM);

	/* mb_kernel_cmdline() updates the environment. */
	build_environment_module();

	/* Pass the loaded console font for kernel. */
	build_font_module();

	/* Allocate xboot_info */
	bi = loader_alloc_align(sizeof (*bi), 16);
	if (bi == NULL) {
		free(cmdline);
		return (ENOMEM);
	}
	bzero(bi, sizeof (*bi));
	DBG(bi);

	/* Build kernel command line */
	buf = loader_alloc_align(strlen(cmdline) + 1, 1);
	if (buf != NULL) {
		(void) strcpy(buf, cmdline);
		bi->bi_cmdline = (native_ptr_t)vtop(buf);
	}
	free(cmdline);

	rv = dboot_add_modules(bi, fp);
	if (rv != 0)
		return (rv);

	rv = dboot_add_framebuffer(bi);
	if (rv != 0)
		return (rv);

	rv = dboot_add_mmap(bi);
	if (rv != 0)
		return (rv);

	DBG(PAT_support);
	DBG(pge_support);
	DBG(NX_support);
	DBG(largepage_support);

	bi->bi_uefi_arch = XBI_UEFI_ARCH_64;
	bi->bi_uefi_systab = (native_ptr_t)ST;
	bi->bi_acpi_rsdp = (native_ptr_t)rsdp;
	bi->bi_acpi_rsdp_copy = 0;

	bi->bi_smbios = 0;
	buf = getenv("smbios-address");
	if (buf != NULL) {
		errno = 0;
		bi->bi_smbios = strtoull(buf, NULL, 0);
		if (errno != 0)
			bi->bi_smbios = 0;
	}

	bi->bi_use_largepage = largepage_support;
	bi->bi_use_pge = pge_support;
	bi->bi_use_pae = pae_support;
	bi->bi_use_nx = NX_support;
	bi->bi_kseg_size = FOUR_MEG;
        bi->bi_mb_version = 2;
	bi->bi_mb_info = 0;	/* XXX */

	stackp = loader_alloc_align(STACK_SIZE, EFI_PAGE_SIZE);
	if (stackp == NULL)
		return (ENOMEM);
	stack = vtop(stackp) + STACK_SIZE - 8;
	DBG(stack);

	build_page_tables(bi);

	/* Attempts to ExitBootServices() */
	for (int i = 0; i < 2; i++) {
		EFI_STATUS status;
		EFI_MEMORY_DESCRIPTOR *map;
		UINTN map_key, map_size, desc_size;
		UINT32 desc_ver;

		status = efi_get_memory_map(&map_size, &map, &map_key,
		    &desc_size, &desc_ver);
		if (status == EFI_SUCCESS)
			status = BS->ExitBootServices(IH, map_key);
		if (status == EFI_SUCCESS) {
			has_boot_services = false;
			break;
		}
		if (prom_debug)
			printf("Retry to call ExitBootServices()\n");
	}

	if (!has_boot_services) {
		amd64_tramp(vtop((caddr_t)bi), stack, top_page_table,
		    target_kernel_text);
	}
	return (0);
}
