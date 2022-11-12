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

#include <sys/promif.h>
#include <sys/promimpl.h>
#include <sys/systm.h>
#include <sys/dklabel.h>
#include <sys/vtoc.h>
#include <sys/efi_partition.h>
#include "boot_plat.h"
#include "prom_dev.h"
#include "ramdisk.h"
#ifndef PATH_MAX
#define	PATH_MAX	1024
#endif

#include <sys/dktp/fdisk.h>


extern unsigned long unix_startblk;
extern size_t unix_numblks;

#define	PROMIF_CLNTNAMELEN	16
char	promif_clntname[PROMIF_CLNTNAMELEN];

#define PROM_MAXDEVS 8

struct prom_ctrlblk {
	int opened;
	int fd;
	const struct prom_dev *dev;
};

static struct prom_ctrlblk prom_cb[PROM_MAXDEVS];
static const struct prom_dev *prom_devs[PROM_MAXDEVS];

int prom_register(const struct prom_dev *dev)
{
	for (int i = 0; i < sizeof(prom_devs) / sizeof(prom_devs[0]); i++) {
		if (prom_devs[i] == NULL) {
			prom_devs[i] = dev;
			return 0;
		}
	}
	return -1;
}

static ihandle_t stdin_handle = -1;
static ihandle_t stdout_handle = -1;
void
prom_init(char *pgmname, void *cookie)
{
	strncpy(promif_clntname, pgmname, PROMIF_CLNTNAMELEN - 1);
	promif_clntname[PROMIF_CLNTNAMELEN - 1] = '\0';

	stdin_handle = prom_open("stdin");
	stdout_handle = prom_open("stdout");
}

ihandle_t prom_stdin_ihandle(void) { return stdin_handle; }
ihandle_t prom_stdout_ihandle(void) { return stdout_handle; }

int prom_open(char *path)
{
	int index;
	int fd;
	int i;

	for (index = 0; index < sizeof(prom_cb) / sizeof(prom_cb[0]); index++) {
		if (prom_cb[index].opened == 0)
			break;
	}
	if (index == sizeof(prom_cb) / sizeof(prom_cb[0]))
	    return 0;

	for (i = 0; i < sizeof(prom_devs) / sizeof(prom_devs[0]); i++) {
		if (prom_devs[i] && prom_devs[i]->match(path))
			break;
	}
	if (i == sizeof(prom_devs) / sizeof(prom_devs[0]))
		return 0;

	prom_cb[index].dev = prom_devs[i];
	prom_cb[index].fd = 0;
	if (prom_cb[index].dev->open) {
		prom_cb[index].fd = prom_cb[index].dev->open(path);
	}
	if (prom_cb[index].fd < 0)
		return 0;

	prom_cb[index].opened = 1;
	fd = index + 1;

	unix_startblk = 0;
	unix_numblks = 0;
	if (strcmp(path, "stdin") && strcmp(path, "stdout")) {
		if (!is_netdev(path) && strcmp(prom_bootpath(), path) == 0) {
			struct mboot bootblk;
			if (prom_read(fd, (caddr_t)&bootblk, 0x200, 0, 0) == 0x200 && bootblk.signature == MBB_MAGIC) {
				struct ipart *iparts = (struct ipart *)(uintptr_t)&bootblk.parts[0];
				for (i = 0; i < FD_NUMPART; i++) {
					if (iparts[i].systid == SUNIXOS2) {
						uint64_t slice_start = iparts[i].relsect;
						struct dk_label dkl;
						if (prom_read(fd, (caddr_t)&dkl, 0x200, slice_start + DK_LABEL_LOC, 0) == 0x200) {
							for (int j = 0; j < NDKMAP; j++) {
								if (dkl.dkl_vtoc.v_part[j].p_tag == V_ROOT) {
									unix_startblk = slice_start + dkl.dkl_vtoc.v_part[j].p_start;
									unix_numblks = dkl.dkl_vtoc.v_part[j].p_size;
									break;
								}
							}
							if (unix_startblk == 0) {
								for (int j = 0; j < NDKMAP; j++) {
									if (dkl.dkl_vtoc.v_part[j].p_size != 0 &&
									    dkl.dkl_vtoc.v_part[j].p_tag != V_ROOT &&
									    dkl.dkl_vtoc.v_part[j].p_tag != V_BOOT) {
										unix_startblk = slice_start + dkl.dkl_vtoc.v_part[j].p_start;
										unix_numblks = dkl.dkl_vtoc.v_part[j].p_size;
										break;
									}
								}
							}
						}
						break;
					}
					if (iparts[i].systid == EFI_PMBR) {
						efi_gpt_t gpt;
						if (prom_read(fd, (caddr_t)&gpt, sizeof(gpt), iparts[i].relsect, 0) == sizeof(gpt)) {
							if (gpt.efi_gpt_Signature == EFI_SIGNATURE && gpt.efi_gpt_SizeOfPartitionEntry == sizeof(efi_gpe_t)) {
								efi_gpe_t gpeb[(0x200 / sizeof(efi_gpe_t))];
								for (uint_t i = 0; i < gpt.efi_gpt_NumberOfPartitionEntries; i++) {
									const efi_gpe_t *gpe = &gpeb[i % (0x200 / sizeof(efi_gpe_t))];
									if ((i % (0x200 / sizeof(efi_gpe_t))) == 0) {
										memset(gpeb, 0, sizeof(gpeb));
										if (prom_read(fd, (caddr_t)gpeb, sizeof(gpeb), gpt.efi_gpt_PartitionEntryLBA + (i / (0x200 / sizeof(efi_gpe_t))), 0) != sizeof(gpeb)) {
											break;
										}
									}
									static const struct uuid efi_root = EFI_ROOT;
									if (memcmp((void *)&gpe->efi_gpe_PartitionTypeGUID, &efi_root, sizeof(efi_root)) == 0) {
										unix_startblk = gpe->efi_gpe_StartingLBA;
										unix_numblks = (gpe->efi_gpe_EndingLBA - gpe->efi_gpe_StartingLBA + 1);
										boot_partition = i;
										break;
									}
								}
							}
						}
						break;
					}
				}
			}
		}
	}

	return fd;
}

int prom_close(int fd)
{
	if (fd <= 0)
		return -1;
	int index = fd - 1;
	if (prom_cb[index].opened == 0)
		return -1;

	if (prom_cb[index].dev->close) {
		prom_cb[index].dev->close(prom_cb[index].fd);
	}
	prom_cb[index].opened = 0;

	return 0;
}

ssize_t prom_read(ihandle_t fd, caddr_t buf, size_t len, uint_t startblk, char devtype)
{
	if (fd <= 0)
		return -1;
	int index = fd - 1;
	if (prom_cb[index].opened == 0 || prom_cb[index].dev->read == 0)
		return -1;
	return prom_cb[index].dev->read(prom_cb[index].fd, buf, len, startblk);
}

ssize_t prom_write(ihandle_t fd, caddr_t buf, size_t len, uint_t startblk, char devtype)
{
	if (fd <= 0)
		return -1;
	int index = fd - 1;
	if (prom_cb[index].opened == 0 || prom_cb[index].dev->write == 0)
		return -1;
	return prom_cb[index].dev->write(prom_cb[index].fd, buf, len, startblk);
}

int prom_seek(int fd, unsigned long long offset)
{
	return offset;
}

int
prom_getmacaddr(ihandle_t fd, caddr_t ea)
{
	if (fd <= 0)
		return -1;
	int index = fd - 1;
	if (prom_cb[index].opened == 0 || prom_cb[index].dev->getmacaddr == 0)
		return -1;
	return prom_cb[index].dev->getmacaddr(prom_cb[index].fd, ea);
}

boolean_t
prom_is_netdev(char *devpath)
{
	pnode_t node = prom_finddevice(devpath);
	if (node > 0) {
		int len = prom_getproplen(node, "model");
		if (len > 0) {
			char *buf = __builtin_alloca(len);
			prom_getprop(node, "model", buf);
			if (strcmp(buf, "Ethernet controller") == 0) {
				return B_TRUE;
			}
		}
	}

	int i;
	for (i = 0; i < sizeof(prom_devs) / sizeof(prom_devs[0]); i++) {
		if (prom_devs[i] && prom_devs[i]->match(devpath))
			break;
	}
	if (i == sizeof(prom_devs) / sizeof(prom_devs[0]))
		return B_FALSE;
	if (prom_devs[i]->getmacaddr)
		return B_TRUE;
	return B_FALSE;
}
