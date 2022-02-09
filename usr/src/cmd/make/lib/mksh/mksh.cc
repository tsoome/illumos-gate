/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2004 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */


/*
 *	mksh.cc
 *
 *	Execute the command(s) of one Make or DMake rule
 */

/*
 * Included files
 */
#include <mksh/dosys.h>		/* redirect_io() */
#include <mksh/misc.h>		/* retmem() */
#include <mksh/mksh.h>
#include <errno.h>
#include <signal.h>


/*
 * Workaround for NFS bug. Sometimes, when running 'chdir' on a remote
 * dmake server, it fails with "Stale NFS file handle" error.
 * The second attempt seems to work.
 */
int
my_chdir(char * dir) {
	int res = chdir(dir);
	if (res != 0 && (errno == ESTALE || errno == EAGAIN)) {
		/* Stale NFS file handle. Try again */
		res = chdir(dir);
	}
	return res;
}
