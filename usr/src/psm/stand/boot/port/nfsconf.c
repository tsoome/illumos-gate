/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/obpdefs.h>
#include <sys/boothsfs.h>
#include <sys/bootufs.h>
#include <sys/bootvfs.h>
#include <sys/salib.h>
#include "boot_plat.h"

/*
 * filesystem switch table, NFS
 */
extern struct boot_fs_ops boot_nfs_ops;
extern struct boot_fs_ops boot_zfs_ops;
struct boot_fs_ops *boot_fsw[] = {
	&boot_zfs_ops,
	&boot_nfs_ops,
	&boot_hsfs_ops,
	&boot_ufs_ops,
};

int boot_nfsw = sizeof (boot_fsw) / sizeof (boot_fsw[0]);
int nfs_readsize = 0;
char *systype;

static char *nfsname = "nfs";
static char *ufsname = "ufs";
static char *hsfsname = "hsfs";
static char *zfsname = "zfs";

int
determine_fstype_and_mountroot(char *path)
{
	clr_default_fs();

	if (is_netdev(path)) {
		set_default_fs(nfsname);
		if (mountroot(path) == VFS_SUCCESS) {
			systype = nfsname;
			return (VFS_SUCCESS);
		}
	} else {
		set_default_fs(zfsname);
		if (mountroot(path) == VFS_SUCCESS) {
			systype = zfsname;
			return (VFS_SUCCESS);
		}

		set_default_fs(hsfsname);
		if (mountroot(path) == VFS_SUCCESS) {
			systype = hsfsname;
			return (VFS_SUCCESS);
		}

		set_default_fs(ufsname);
		if (mountroot(path) == VFS_SUCCESS) {
			systype = ufsname;
			return (VFS_SUCCESS);
		}
	}
	clr_default_fs();

	return (VFS_FAILURE);
}
