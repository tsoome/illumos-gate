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

#ifndef _MDB_KREG_IMPL_H
#define	_MDB_KREG_IMPL_H

#include <mdb/mdb_kreg.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The mdb_tgt_gregset type is opaque to callers of the target interface
 * and to our own target common code.  We now can define it explicitly.
 */
struct mdb_tgt_gregset {
	kreg_t kregs[KREG_NGREG];
};

#ifdef __cplusplus
}
#endif

#endif /* _MDB_KREG_IMPL_H */
