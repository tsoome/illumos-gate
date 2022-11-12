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
 * Copyright 2017 Hayashi Naoyuki
 */

#include <sys/types.h>
#include <sys/promif.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/salib.h>
#include "ramdisk.h"
#include "prom_dev.h"

static ihandle_t ramdisk_open(const char *ramdisk_name);
static ssize_t ramdisk_read(ihandle_t fd, caddr_t buf, size_t len, uint_t startblk);

#define MAX_ID 1
static ihandle_t next_id = 0;
struct ramdisk_attr {
	char rd_name[OBP_MAXPATHLEN];
	caddr_t rd_base;
	size_t rd_size;
	int count;
	ihandle_t id;
} ramdisk_attr[MAX_ID] = {0};

static int
ramdisk_match(const char *name)
{
	return !strncmp(name, RD_ROOTFS, strlen(RD_ROOTFS));
}

static struct prom_dev ramdisk_dev =
{
	.open = ramdisk_open,
	.read = ramdisk_read,
	.match = ramdisk_match
};

void init_ramdisk()
{
	prom_register(&ramdisk_dev);
}

static struct ramdisk_attr *
ramdisk_lookup(const char *ramdisk_name)
{
	return &ramdisk_attr[0];
}

caddr_t
create_ramdisk(char *ramdisk_name, size_t size, char **devpath)
{
	struct ramdisk_attr *rdp;
	extern char _RamdiskStart[];
	extern char _RamdiskEnd[];

	if ((_RamdiskEnd - _RamdiskStart) < size)
		return NULL;

	/*
	 * lookup ramdisk name.
	 */
	rdp = ramdisk_lookup(ramdisk_name);
	if (rdp->count) {
		rdp->count++;
		return rdp->rd_base;
	}
	rdp->rd_base = _RamdiskStart;
	rdp->rd_size = _RamdiskEnd - _RamdiskStart;
	rdp->id = next_id;
	rdp->count = 1;
	next_id++;

	if (devpath != NULL) {
		*devpath = 0;
	}

	return (_RamdiskStart);
}

void
destroy_ramdisk(char *ramdisk_name)
{
	struct ramdisk_attr *rdp;

	/*
	 * lookup ramdisk name.
	 */
	if ((rdp = ramdisk_lookup(ramdisk_name)) == NULL)
		prom_panic("invalid ramdisk name");

	if (--rdp->count == 0) {
		rdp->rd_base = 0;
		rdp->rd_size = 0;
	}
}

static ihandle_t ramdisk_open(const char *ramdisk_name)
{
	struct ramdisk_attr *rdp = ramdisk_lookup(ramdisk_name);
	return rdp? rdp->id: -1;
}

static ssize_t ramdisk_read(ihandle_t fd, caddr_t buf, size_t len, uint_t startblk)
{
	struct ramdisk_attr *rdp = &ramdisk_attr[0];
	caddr_t diskloc = rdp->rd_base + (uintptr_t)startblk * DEV_BSIZE;
	if (startblk * DEV_BSIZE + len > rdp->rd_size) {
		prom_printf("diskread: reading beyond end of ramdisk\n");
		prom_printf("\tstart = 0x%p, size = 0x%lx\n", (void *)diskloc, len);
		return -1;
	}
	memcpy(buf, diskloc, len);

	return len;
}

