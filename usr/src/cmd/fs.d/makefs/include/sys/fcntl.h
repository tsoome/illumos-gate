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
 * Copyright 2025 Edgecast Cloud LLC
 */

#ifndef _SYS_FCNTL_H
#define	_SYS_FCNTL_H

/*
 * Set up illumos values in BSD compilation environment.
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Flag values accessible to open(2) and fcntl(2)
 * The first five can only be set (exclusively) by open(2).
 */
#define	O_RDONLY	0
#define	O_WRONLY	1
#define	O_RDWR		2
#define	O_SEARCH	0x200000
#define	O_EXEC		0x400000

/*
 * Flag values accessible only to open(2).
 */
#define	O_CREAT		0x100	/* open with file create (uses third arg) */
#define	O_TRUNC		0x200	/* open with truncation */
#define	O_EXCL		0x400	/* exclusive open */
#define	O_NOCTTY	0x800	/* don't allocate controlling tty (POSIX) */
#define	O_XATTR		0x4000	/* extended attribute */
#define	O_NOFOLLOW	0x20000	/* don't follow symlinks */
#define	O_NOLINKS	0x40000	/* don't allow multiple hard links */
#define	O_CLOEXEC	0x800000	/* set the close-on-exec flag */
#define	O_DIRECTORY	0x1000000	/* fail if not a directory */

#define	AT_FDCWD	0xffd19553

extern int open(const char *, int, ...);
extern int openat(int, const char *, int, ...);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_FCNTL_H */
