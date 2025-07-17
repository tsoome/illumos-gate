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

/* Provide illumos definition of dirent in BSD compilation environment. */

#ifndef _DIRENT_H
#define	_DIRENT_H

#include <sys/types.h>
#include <sys/dirent.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	int	d_fd;		/* file descriptor */
	int	d_loc;		/* offset in block */
	int	d_size;		/* amount of valid data */
	char	*d_buf;		/* directory block */
} DIR;

extern DIR *opendir(const char *);
extern struct dirent *readdir(DIR *);
extern int closedir(DIR *);

#ifdef __cplusplus
}
#endif

#endif /* _DIRENT_H */
