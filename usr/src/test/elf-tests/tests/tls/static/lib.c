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

/* Copyright 2023 Richard Lowe */

/*
 * Shared object definitions of our thread-locals.
 *
 * These must match precisely those in bin.c, except without the model
 * specified.
 */
#include <stdio.h>
#include <sys/types.h>

__thread uint32_t foo = 0x8675309;
__thread char bar[BUFSIZ] = {0};
