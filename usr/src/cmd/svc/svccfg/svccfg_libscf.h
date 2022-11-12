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

#ifndef _SVCCFG_LIBSCF_H
#define	_SVCCFG_LIBSCF_H

#ifdef __cplusplus
extern "C" {
#endif

extern int lscf_archive(const char *, int);
extern void lscf_validate(const char *);
extern void lscf_validate_fmri(const char *);
extern int lscf_service_export(char *, const char *, int);
extern int lscf_profile_extract(const char *);
extern int lscf_setprop(const char *, const char *, const char *,
    const uu_list_t *);
extern int lscf_editprop();
extern int lscf_addpropvalue(const char *, const char *, const char *);
extern int lscf_delpropvalue(const char *, const char *, int);
extern int lscf_setenv(uu_list_t *, int);
extern void lscf_set_repository(const char *, int);

#ifdef __cplusplus
}
#endif

#endif /* _SVCCFG_LIBSCF_H */
