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

/* Copyright 2022 Richard Lowe */

#ifndef _SVCCFG_ENGINE_H
#define	_SVCCFG_ENGINE_H

#ifdef __cplusplus
extern "C" {
#endif

extern int engine_restore(const char *);
extern int engine_apply(const char *, int);
extern int engine_set(uu_list_t *);

#ifdef __cplusplus
}
#endif

#endif /* _SVCCFG_ENGINE_H */
