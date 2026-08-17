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
 * Copyright 2026 <contributor>
 */

#ifndef _ZALLOC_LOADER_H
#define	_ZALLOC_LOADER_H

/*
 * Functions to support memory allocation for loaded
 * kernel and other data structures needed to complete the load.
 */

#include <zalloc_defs.h>

#ifdef __cplusplus
extern "C" {
#endif

extern vm_offset_t loader_alloc_next_avail(void);
extern void loader_alloc_stats(void);
extern void loader_alloc_init(zalloc_alloc_t *, zalloc_free_t *);
extern void loader_alloc_fini(void);

extern void *loader_alloc_align(size_t, size_t);
extern void *loader_xalloc(vm_offset_t, vm_offset_t, size_t);
extern void loader_free(void *);

#ifdef __cplusplus
}
#endif

#endif /* _ZALLOC_LOADER_H */
