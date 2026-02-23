/*
 * Copyright (c) 1998 Michael Smith <msmith@freebsd.org>
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

#include <sys/cdefs.h>

/*
 * MD primitives supporting placement of module data
 */
#include <stand.h>
#include <sys/param.h>
#include <sys/elf.h>
#include <sys/multiboot2.h>
#include <sys/consplat.h>
#include <machine/metadata.h>
#include <machine/pc/bios.h>
#include "libi386.h"
#include "btxv86.h"
#include "bootstrap.h"
#include <zalloc_loader.h>

extern uint64_t load_limit;
extern vm_offset_t ktext_phys;

extern multiboot_tag_framebuffer_t gfx_fb;

static struct bios_smap *
get_memory_descriptor(struct MemPool *mp, vm_offset_t paddr, uintptr_t size)
{
	struct bios_smap *smap;
	uint_t smaplen;

	smap = bios_smap_info(&smaplen);
	if (smap == NULL)
		return (smap);

	if (size == 0)
		return (smap);

	for (uint_t i = 0; i < smaplen; i++) {
		if (smap[i].type != SMAP_TYPE_MEMORY)
			continue;

		/* Pick next segment after current segment in pool. */
		if (mp->mp_Base != NULL &&
		    smap[i].base <= vtop(mp->mp_Base))
			continue;

		/*
		 * Skip descriptors for memory before ktext_phys.
		 */
		if (smap[i].base <= paddr &&
		    smap[i].base + smap[i].length <= paddr)
			continue;

		/*
		 * Now, we only do need to check the size.
		 */
		if (smap[i].base + smap[i].length -
		    MAX(paddr, smap[i].base) >= size)
			return (&smap[i]);
	}
	return (NULL);
}

/*
 * Allocate memory for loader pool.
 * Find chunks of unused memory from SMAP.
 */
static void *
i386_loader_alloc(struct MemPool *mp, uintptr_t addr, size_t *sizep)
{
	vm_offset_t paddr = 0;
	intptr_t size = *sizep;
	struct bios_smap *smap;

	/*
	 * With addr == 0, we must have pool set up with at least one
	 * segment allocated for kernel and we want next segment to
	 * be allocated.
	 */
	if (addr == 0) {
		/* Get last segment */
		while (mp->mp_next != NULL)
			mp = mp->mp_next;
	} else {
		/*
		 * If our pool is empty, we need to allocate space for
		 * kernel, based on addr.
		 */
		paddr = vtop((caddr_t)addr);
	}
	if (paddr > load_limit || paddr + size > load_limit)
		return ((void *)-1);

	smap = get_memory_descriptor(mp, paddr, size);
	if (smap == NULL)
		return ((void *)-1);

	if (smap->base > load_limit || smap->base + size > load_limit)
		return ((void *)-1);

	/*
	 * If we are adding new segment or if kernel can not be
	 * stored on given address, use segment start.
	 */
	if (mp->mp_Base == NULL) {
		if (paddr < smap->base)
			paddr = smap->base;
	} else {
		paddr = smap->base;
	}

	*sizep =
	    roundup2(
	    MIN(smap->length - (paddr - smap->base), load_limit - paddr),
	    MALLOCALIGN);

	return (ptov(paddr));
}

/*
 * Find usable address for loading. Note, we do return physical
 * address here.
 */
vm_offset_t
i386_loadaddr(uint_t type, void *data, vm_offset_t addr)
{
	vm_offset_t vaddr;
	struct stat st;
	size_t size, alignment;

	/*
	 * Every other allocation happens after ELF, therefore,
	 * addr must non-zero value.
	 */
	if (addr == 0)
		return (addr);	/* nothing to do */

	switch (type) {
	case LOAD_ELF:
		load_limit = memtop;
		ktext_phys = addr;
		size = elf_load_size(data);
		break;

	case LOAD_MEM:
		size = *(size_t *)data;
		break;

	case LOAD_KERN:
		load_limit = memtop;
		/* FALLTHROUGH */
	case LOAD_RAW:
	default:
		stat(data, &st);
		size = st.st_size;
	}

	/* We do not support allocating 0 pages. */
	if (size == 0)
		return (0);

	if (type == LOAD_ELF || type == LOAD_KERN) {
		size_t diff;

		/* Make sure we have memory pool set up. */
		loader_alloc_init(i386_loader_alloc, NULL);

		/* loader_xalloc needs aligned address */
		diff = addr & PAGE_MASK;
		addr -= diff;
		size += diff;

		/* make sure we will not exceed the limit. */
		if (addr + diff > load_limit ||
		    addr + size > load_limit)
			return (0);

		vaddr = (vm_offset_t)loader_xalloc(addr, addr + size, size);
		if (vaddr != 0) {
			return (VTOP(vaddr + diff));
		}
		/*
		 * We failed to allocate at address. This is 32-bit
		 * loader and we have no fallback available.
		 */
		return (0);
	}

	alignment = PAGE_SIZE;

	vaddr = (vm_offset_t)loader_alloc_align(size, alignment);
	if (VTOP(vaddr) > load_limit || VTOP(vaddr) + size > load_limit) {
		loader_free((void *)(uintptr_t)vaddr);
		vaddr = 0;
	}

	if (vaddr == 0) {
		printf("failed to allocate %zu bytes for %p\n",
		    size, (void *)(uintptr_t)addr);
		return (0);
	}

	return (VTOP(vaddr));
}

ssize_t
i386_copyin(const void *src, vm_offset_t dest, const size_t len)
{
	if (dest + len >= load_limit) {
		errno = EFBIG;
		return (-1);
	}

	bcopy(src, PTOV(dest), len);
	return (len);
}

ssize_t
i386_copyout(const vm_offset_t src, void *dest, const size_t len)
{
	if (src + len >= load_limit) {
		errno = EFBIG;
		return (-1);
	}

	bcopy(PTOV(src), dest, len);
	return (len);
}


ssize_t
i386_readin(const int fd, vm_offset_t dest, const size_t len)
{
	if (dest + len >= load_limit) {
		errno = EFBIG;
		return (-1);
	}

	return (read(fd, PTOV(dest), len));
}
