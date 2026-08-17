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
 * Use zalloc facilities to implement memory management support for
 * loading kernel and data.
 *
 * The allocations must consult memory map to make sure we are allocating
 * from usable memory.
 *
 * The kernel and boot archive (module) can be large chunk of memory,
 * especially the boot archive (when used on installer or as root fs).
 *
 * The implementation is using concept of memory pool, where we allocate
 * large chunk for pool by using allocation function provided during
 * pool setup and the chunk should be sufficiently large to store at least
 * one allocatin request. The allocation function is using system memory
 * map to find usable memory.
 *
 * To undo allocations, we will release the memory from pool by using
 * function callback provided during pool setup.
 * When cleanup is done, we have empty pool.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <zalloc_defs.h>

/*
 * Memory pool for loader.
 */
static MemPool LoaderPool;

/*
 * Return first address above all allocated memory from loader pool.
 * We do check for case nothing is yet allocated, but this function
 * is supposed to be used after at least kernel is loaded.
 */
vm_offset_t
loader_alloc_next_avail(void)
{
	uintptr_t ptr = (uintptr_t)zalloc_last_addr(&LoaderPool);

	if (ptr == 0)
		return (0);
	return (roundup2(ptr, PAGE_SIZE));
}

void
loader_alloc_stats(void)
{
#ifdef ZALLOCDEBUG
	zallocstats(&LoaderPool);
#endif
}

void
loader_alloc_init(zalloc_alloc_t *allocf, zalloc_free_t *freef)
{
	if (LoaderPool.mp_Base == NULL)
		zalloc_init(&LoaderPool, 0, allocf, freef);
}

void
loader_alloc_fini(void)
{
	zalloc_fini(&LoaderPool);
}

void *
loader_alloc_align(size_t size, size_t alignment)
{
	void *ptr;

	ptr = znalloc_align(&LoaderPool, size, alignment);
	if (ptr == (void *)-1)
		ptr = NULL;
	return (ptr);
}

/*
 * Allocate memory segment [addr1 .. addr2].
 * addr1 and addr2 are physical addresses from kernel ELF file.
 * We do need to translate them to virtual addresses for BIOS loader.
 */
void *
loader_xalloc(vm_offset_t addr1, vm_offset_t addr2, size_t size)
{
	return (znxalloc(&LoaderPool, ptov(addr1), ptov(addr2), size));
}

void
loader_free(void *ptr)
{
	znalloc_free(&LoaderPool, ptr);
}
