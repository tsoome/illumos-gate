/*
 * This module derived from code donated to the FreeBSD Project by
 * Matthew Dillon <dillon@backplane.com>
 *
 * Copyright (c) 1998 The FreeBSD Project
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
#include <sys/param.h>

/*
 * LIB/MEMORY/ZALLOC.C	- self contained low-overhead memory pool/allocation
 *			  subsystem
 *
 *	This subsystem implements memory pools and memory allocation
 *	routines.
 *
 *	Pools are managed via a linked list of 'free' areas.  Allocating
 *	memory creates holes in the freelist, freeing memory fills them.
 *	Since the freelist consists only of free memory areas, it is possible
 *	to allocate the entire pool without incuring any structural overhead.
 *
 *	The system works best when allocating similarly-sized chunks of
 *	memory.  Care must be taken to avoid fragmentation when
 *	allocating/deallocating dissimilar chunks.
 *
 *	When a memory pool is first allocated, the entire pool is marked as
 *	allocated.  This is done mainly because we do not want to modify any
 *	portion of a pool's data area until we are given permission.  The
 *	caller must explicitly deallocate portions of the pool to make them
 *	available.
 *
 *	znxalloc() works like znalloc() but the allocation is made from
 *	within the specified address range.  If the segment could not be
 *	allocated, NULL is returned.  WARNING!  The address range will be
 *	aligned to an 8 or 16 byte boundry depending on the cpu so if you
 *	give an unaligned address range, unexpected results may occur.
 *
 *	Allocation and frees of 0 bytes are valid operations.
 */

#include "zalloc_defs.h"

/*
 * Objects in the pool must be aligned to at least the size of struct MemNode.
 * They must also be aligned to MALLOCALIGN, which should normally be larger
 * than the struct, so assert that to be so at compile time.
 */
_Static_assert(sizeof (struct MemNode) <= MALLOCALIGN,
	"struct MemNode must be aligned to MALLOCALIGN");

#define	MEMNODE_SIZE_MASK	MALLOCALIGN_MASK

void
zalloc_init(MemPool *mp, intptr_t blksz, zalloc_alloc_t *allocf,
    zalloc_free_t *freef)
{
	mp->mp_alloc = allocf;
	mp->mp_free = freef;
	mp->mp_blksz = blksz;
}

/*
 * Free memory segment and mp.
 */
static void
zalloc_fini_impl(MemPool *mp)
{
	if (mp == NULL)
		return;

	zalloc_fini_impl(mp->mp_next);
	if (mp->mp_free != NULL)
		mp->mp_free(mp);
	free(mp);
}

/*
 * Free memory segments and zero mp.
 */
void
zalloc_fini(MemPool *mp)
{
	zalloc_fini_impl(mp->mp_next);
	if (mp->mp_free != NULL)
		mp->mp_free(mp);
	bzero(mp, sizeof (*mp));
}

/*
 * Wrapper around znalloc(). We need this because znalloc_impl
 * is assuming it can use MALLOCALIGN, and if we want to use znalloc()
 * outside with custom mempool, we would need to implement MALLOCALIGN
 * setup too.
 */
void *
znalloc_align(MemPool *mp, size_t bytes, size_t alignment)
{
	Guard *res;

#ifdef USEENDGUARD
	bytes += MALLOCALIGN + 1;
#else
	bytes += MALLOCALIGN;
#endif

	res = znalloc(mp, bytes, alignment);
	if (res == NULL)
		return (NULL);

#ifdef USEGUARD
	res->ga_Magic = GAMAGIC;
#endif
	res->ga_Bytes = bytes;
#ifdef USEENDGUARD
	*((signed char *)res + bytes - 1) = -2;
#endif

	return ((char *)res + MALLOCALIGN);
}

/*
 * Wrapper to pair znalloc_align() with free() function (see above).
 */
void
znalloc_free(MemPool *mp, void *ptr)
{
	size_t bytes;

	if (ptr != NULL) {
		Guard *res = (void *)((char *)ptr - MALLOCALIGN);

#ifdef USEGUARD
		if (res->ga_Magic == GAFREE) {
			printf("free: duplicate free @ %p\n", ptr);
			return;
		}
		if (res->ga_Magic != GAMAGIC)
			panic("free: guard1 fail @ %p", ptr);
		res->ga_Magic = GAFREE;
#endif
#ifdef USEENDGUARD
		if (*((signed char *)res + res->ga_Bytes - 1) == -1) {
			printf("free: duplicate2 free @ %p\n", ptr);
			return;
		}
		if (*((signed char *)res + res->ga_Bytes - 1) != -2)
			panic("free: guard2 fail @ %p + %zu",
			    ptr, res->ga_Bytes - MALLOCALIGN);
		*((signed char *)res + res->ga_Bytes - 1) = -1;
#endif

		bytes = res->ga_Bytes;
		zfree(mp, res, bytes);
	}
}

/*
 * znalloc() -	allocate memory (without zeroing) from pool.
 *		Return NULL if unable to allocate memory.
 */

static void *
znalloc_impl(MemPool *mp, uintptr_t bytes, size_t align)
{
	MemNode **pmn;
	MemNode *mn;

	/*
	 * align according to pool object size (can be 0).  This is
	 * inclusive of the MEMNODE_SIZE_MASK minimum alignment.
	 *
	 */
	bytes = (bytes + MEMNODE_SIZE_MASK) & ~MEMNODE_SIZE_MASK;

	if (bytes == 0)
		return ((void *)-1);

	/*
	 * locate freelist entry big enough to hold the object.  If all objects
	 * are the same size, this is a constant-time function.
	 */

	while (mp != NULL) {
		if (bytes > mp->mp_Size - mp->mp_Used)
			mp = mp->mp_next;
		else
			break;
	}

	if (mp == NULL)
		return (NULL);

	for (pmn = &mp->mp_First; (mn = *pmn) != NULL; pmn = &mn->mr_Next) {
		char *ptr = (char *)mn;
		uintptr_t dptr;
		char *aligned;
		size_t extra;

		dptr = (uintptr_t)(ptr + MALLOCALIGN);	/* pointer to data */
		aligned = (char *)(roundup2(dptr, align) - MALLOCALIGN);
		extra = aligned - ptr;

		if (bytes + extra > mn->mr_Bytes)
			continue;

		/*
		 * Cut extra from head and create new memory node from
		 * remainder.
		 */

		if (extra != 0) {
			MemNode *new;

			new = (MemNode *)aligned;
			new->mr_Next = mn->mr_Next;
			new->mr_Bytes = mn->mr_Bytes - extra;

			/* And update current memory node */
			mn->mr_Bytes = extra;
			mn->mr_Next = new;
			/* In next iteration, we will get our aligned address */
			continue;
		}

		/*
		 *  Cut a chunk of memory out of the beginning of this
		 *  block and fixup the link appropriately.
		 */

		if (mn->mr_Bytes == bytes) {
			*pmn = mn->mr_Next;
		} else {
			mn = (MemNode *)((char *)mn + bytes);
			mn->mr_Next  = ((MemNode *)ptr)->mr_Next;
			mn->mr_Bytes = ((MemNode *)ptr)->mr_Bytes - bytes;
			*pmn = mn;
		}
		mp->mp_Used += bytes;
		return (ptr);
	}

	/*
	 * Memory pool is full, return NULL.
	 */

	return (NULL);
}


void *
znalloc(MemPool *mp, uintptr_t bytes, size_t align)
{
	void *res;

	if (bytes == 0)
		return ((void *)-1);

	while ((res = znalloc_impl(mp, bytes, align)) == NULL) {
		intptr_t incr;

		if (mp->mp_blksz == 0)
			incr = bytes;
		else
			incr = (bytes + (mp->mp_blksz - 1)) &
			    ~(mp->mp_blksz - 1);

		res = mp->mp_alloc(mp, 0, &incr);
		if (res == (void *)-1)
			return (NULL);
		zextendPool(mp, res, incr);
		zfree(mp, res, incr);
	}
	return (res);
}

/*
 * znxalloc() -  allocate memory from within a specific address region.
 *		If allocating AT a specific address, then addr2 must be
 *		set to addr1 + bytes (and this only works if addr1 is
 *		already aligned).  addr1 and addr2 are aligned by
 *		MEMNODE_SIZE_MASK + 1 (i.e. they wlill be 8 or 16 byte
 *		aligned depending on the machine core).
 */

static void *
znxalloc_impl(MemPool *mp, void *addr1, void *addr2, uintptr_t bytes)
{
	/*
	 * align according to pool object size (can be 0).  This is
	 * inclusive of the MEMNODE_SIZE_MASK minimum alignment.
	 */
	bytes = (bytes + MEMNODE_SIZE_MASK) & ~MEMNODE_SIZE_MASK;
	addr1= (void *)
	    (((uintptr_t)addr1 + MEMNODE_SIZE_MASK) & ~MEMNODE_SIZE_MASK);
	addr2= (void *)
	    (((uintptr_t)addr2 + MEMNODE_SIZE_MASK) & ~MEMNODE_SIZE_MASK);

	if (bytes == 0)
		return (addr1);

	while (mp != NULL) {
		if ((char *)addr1 < (char *)mp->mp_Base ||
		    (char *)addr2 > (char *)mp->mp_End)
			mp = mp->mp_next;
		else
			break;
	}

	if (mp == NULL)
		return (NULL);

	/*
	 * Locate freelist entry big enough to hold the object that is within
	 * the allowed address range.
	 */

	if (bytes <= mp->mp_Size - mp->mp_Used) {
		MemNode **pmn;
		MemNode *mn;

		for (pmn = &mp->mp_First; (mn = *pmn) != NULL;
		    pmn = &mn->mr_Next) {
			int mrbytes = mn->mr_Bytes;
			int offset = 0;

			/*
			 * offset from base of mn to satisfy addr1.
			 * 0 or positive.
			 */

			if ((char *)mn < (char *)addr1)
				offset = (char *)addr1 - (char *)mn;

			/*
			 * truncate mrbytes to satisfy addr2.
			 * mrbytes may go negative if the mn is beyond
			 * the last acceptable address.
			 */

			if ((char *)mn + mrbytes > (char *)addr2)
				mrbytes =
				    (intptr_t)addr2 - (intptr_t)mn; /* signed */

			/*
			 * beyond last acceptable address.
			 *
			 * before first acceptable address
			 * (if offset > mrbytes, the second conditional will
			 * always succeed).
			 *
			 * area overlapping acceptable address range is not
			 * big enough.
			 */

			if (mrbytes < 0)
				break;

			if (mrbytes - offset < bytes)
				continue;

			/*
			 * Cut a chunk of memory out of the block and fixup
			 * the link appropriately.
			 *
			 * If offset != 0, we have to cut a chunk out from
			 * the middle of the block.
			 */

			if (offset != 0) {
				MemNode *mnew =
				    (MemNode *)((char *)mn + offset);

				mnew->mr_Bytes = mn->mr_Bytes - offset;
				mnew->mr_Next = mn->mr_Next;
				mn->mr_Bytes = offset;
				mn->mr_Next = mnew;
				pmn = &mn->mr_Next;
				mn = mnew;
			}

			char *ptr = (char *)mn;
			if (mn->mr_Bytes == bytes) {
				*pmn = mn->mr_Next;
			} else {
				mn = (MemNode *)((char *)mn + bytes);
				mn->mr_Next  = ((MemNode *)ptr)->mr_Next;
				mn->mr_Bytes =
				    ((MemNode *)ptr)->mr_Bytes - bytes;
				*pmn = mn;
			}
			mp->mp_Used += bytes;
			return (ptr);
		}
	}

	return (NULL);
}

void *
znxalloc(MemPool *mp, void *addr1, void *addr2, uintptr_t bytes)
{
	void *res;

	if (bytes == 0)
		return ((void *)-1);

	while ((res = znxalloc_impl(mp, addr1, addr2, bytes)) == NULL) {
		intptr_t incr;

		/*
		 * If our pool segment base address is larger than addr1,
		 * then allocating next segment will not get us smaller
		 * base address.
		 * This is because we do not allocate segments for heap
		 * and load pool addresses will only grow.
		 */
		for (MemPool *p = mp; p != NULL; p = p->mp_next) {
			if (addr1 < mp->mp_Base)
				return (res);
		}

		if (mp->mp_blksz == 0)
			incr = bytes;
		else
			incr = (bytes + (mp->mp_blksz - 1)) &
			    ~(mp->mp_blksz - 1);

		res = mp->mp_alloc(mp, (uintptr_t)addr1, &incr);
		printf("%s: res: %p\n", __func__, res);
		if (res == (void *)-1)
			return (NULL);
		zextendPool(mp, res, incr);
		zfree(mp, res, incr);
	}
	return (res);
}

/*
 * zfree() - free previously allocated memory
 */

void
zfree(MemPool *mp, void *ptr, uintptr_t bytes)
{
	MemNode **pmn;
	MemNode *mn;

	/*
	 * align according to pool object size (can be 0).  This is
	 * inclusive of the MEMNODE_SIZE_MASK minimum alignment.
	 */
	bytes = (bytes + MEMNODE_SIZE_MASK) & ~MEMNODE_SIZE_MASK;

	if (bytes == 0)
		return;

	while (mp != NULL) {
		if ((char *)ptr < (char *)mp->mp_Base ||
		    (char *)ptr + bytes > (char *)mp->mp_End)
			mp = mp->mp_next;
		else
			break;
	}

	/*
	 * panic if illegal pointer
	 */
	if (mp == NULL ||
	    ((uintptr_t)ptr & MEMNODE_SIZE_MASK) != 0)
		panic("zfree(%p,%ju): wild pointer", ptr, (uintmax_t)bytes);

	/*
	 * free the segment
	 */
	mp->mp_Used -= bytes;

	for (pmn = &mp->mp_First; (mn = *pmn) != NULL; pmn = &mn->mr_Next) {
		/*
		 * If area between last node and current node
		 *  - check range
		 *  - check merge with next area
		 *  - check merge with previous area
		 */
		if ((char *)ptr <= (char *)mn) {
			/*
			 * range check
			 */
			if ((char *)ptr + bytes > (char *)mn) {
				panic("zfree(%p,%ju): corrupt memlist1", ptr,
				    (uintmax_t)bytes);
			}

			/*
			 * merge against next area or create independant area
			 */

			if ((char *)ptr + bytes == (char *)mn) {
				((MemNode *)ptr)->mr_Next = mn->mr_Next;
				((MemNode *)ptr)->mr_Bytes =
				    bytes + mn->mr_Bytes;
			} else {
				((MemNode *)ptr)->mr_Next = mn;
				((MemNode *)ptr)->mr_Bytes = bytes;
			}
			*pmn = mn = (MemNode *)ptr;

			/*
			 * merge against previous area (if there is a previous
			 * area).
			 */

			if (pmn != &mp->mp_First) {
				if ((char *)pmn + ((MemNode*)pmn)->mr_Bytes ==
				    (char *)ptr) {
					((MemNode *)pmn)->mr_Next = mn->mr_Next;
					((MemNode *)pmn)->mr_Bytes +=
					    mn->mr_Bytes;
					mn = (MemNode *)pmn;
				}
			}
			return;
		}
		if ((char *)ptr < (char *)mn + mn->mr_Bytes) {
			panic("zfree(%p,%ju): corrupt memlist2", ptr,
			    (uintmax_t)bytes);
		}
	}
	/*
	 * We are beyond the last MemNode, append new MemNode.  Merge against
	 * previous area if possible.
	 */
	if (pmn == &mp->mp_First ||
	    (char *)pmn + ((MemNode *)pmn)->mr_Bytes != (char *)ptr) {
		((MemNode *)ptr)->mr_Next = NULL;
		((MemNode *)ptr)->mr_Bytes = bytes;
		*pmn = (MemNode *)ptr;
		mn = (MemNode *)ptr;
	} else {
		((MemNode *)pmn)->mr_Bytes += bytes;
		mn = (MemNode *)pmn;
	}
}

/*
 * zextendPool() - extend memory pool to cover additional space.
 *
 * Note: the added memory starts out as allocated, you
 * must free it to make it available to the memory subsystem.
 *
 * if non-contiguous segment is added to pool, we will create
 * new mempool segment via mp_next pointer.
 */

void
zextendPool(MemPool *mp, void *base, uintptr_t bytes)
{
	MemPool *pool;

	if (mp->mp_Size == 0) {
		mp->mp_Base = base;
		mp->mp_Used = bytes;
		mp->mp_End = (char *)base + bytes;
		mp->mp_Size = bytes;
		return;
	}

	if (base < mp->mp_Base &&
	    base + bytes == mp->mp_Base) {
		mp->mp_Size += bytes;
		mp->mp_Used += bytes;
		mp->mp_Base = base;
		return;
	}

	if (base == mp->mp_End) {
		mp->mp_Size += bytes;
		mp->mp_Used += bytes;
		mp->mp_End += bytes;
		return;
	}

	pool = calloc(1, sizeof (*pool));
	if (pool == NULL)
		panic("%s: out of memory", __func__);

	pool->mp_alloc = mp->mp_alloc;
	pool->mp_free = mp->mp_free;
	pool->mp_blksz = mp->mp_blksz;
	pool->mp_Base = base;
	pool->mp_Used = bytes;
	pool->mp_End = (char *)base + bytes;
	pool->mp_Size = bytes;
	while (mp->mp_next != NULL)
		mp = mp->mp_next;
	mp->mp_next = pool;
}

#ifdef ZALLOCDEBUG

void
zallocstats(MemPool *mp)
{
	uint64_t abytes = 0;
	uint64_t hbytes = 0;
	uint64_t fcount = 0;
	uint64_t reserved = 0;
	unsigned pool = 0;
	MemNode *mn;

	while (mp != NULL) {
		reserved += mp->mp_Size;

		mn = mp->mp_First;

		if ((void *)mn != (void *)mp->mp_Base) {
			if (mn != NULL)
				abytes += (char *)mn - (char *)mp->mp_Base;
		}

		while (mn != NULL) {
			if ((char *)mn + mn->mr_Bytes != mp->mp_End) {
				hbytes += mn->mr_Bytes;
				++fcount;
			}
			if (mn->mr_Next != NULL) {
				abytes += (char *)mn->mr_Next -
				    ((char *)mn + mn->mr_Bytes);
			}
			mn = mn->mr_Next;
		}
		mp = mp->mp_next;
		printf("\nMemory pool segment %u:\n", pool);
		printf("%ju bytes reserved %ju bytes allocated\n",
		    reserved, abytes);
		printf("%ju fragments (%ju bytes fragmented)\n",
		    fcount, hbytes);
		reserved = abytes = fcount = hbytes = 0;
		pool++;
	}
}

#endif
