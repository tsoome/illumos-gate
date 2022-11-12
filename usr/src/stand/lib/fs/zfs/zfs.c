/*-
 * Copyright (c) 2007 Doug Rabson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$FreeBSD$
 */

/*
 *	Stand-alone bsd_file reading package.
 */

#include <stddef.h>
#include <sys/salib.h>
#include <sys/sysmacros.h>
#include <sys/queue.h>
#include <sys/bootvfs.h>
#include <sys/byteorder.h>
#include <sys/dirent.h>
#include <sys/promif.h>
#include <zlib.h>
#include <endian.h>

#define	min(a, b)		((a) > (b) ? (b) : (a))
#define	roundup(x, y)	((((x)+((y)-1))/(y))*(y))
#define panic prom_panic
#define	DIRENT_RECLEN(namelen)	\
	((offsetof(dirent_t, d_name[0]) + 1 + (namelen) + (sizeof(off_t) - 1)) & ~ (sizeof(off_t) - 1))

int pager_output(const char *s)
{
	prom_printf("%s",s);
	return 0;
}

#define nitems ARRAY_SIZE

#include "libzfs.h"

#include "zfsimpl.c"
#include "gzip.c"
#include "edonr.c"
#include "skein.c"
#include "skein_iv.c"
#include "skein_block.c"
#include "list.c"
#include "nvlist.c"

static int	boot_zfs_mountroot(char *str);
static int	boot_zfs_unmountroot(void);
static int	boot_zfs_open(char *filename, int flags);
static int	boot_zfs_close(int fd);
static ssize_t	boot_zfs_read(int fd, caddr_t buf, size_t size);
static off_t	boot_zfs_lseek(int, off_t, int);
static int	boot_zfs_fstat(int fd, struct bootstat *stp);
static void	boot_zfs_closeall(int flag);
static int	boot_zfs_getdents(int fd, struct dirent *dep, unsigned size);

struct boot_fs_ops boot_zfs_ops = {
	"zfs",
	boot_zfs_mountroot,
	boot_zfs_unmountroot,
	boot_zfs_open,
	boot_zfs_close,
	boot_zfs_read,
	boot_zfs_lseek,
	boot_zfs_fstat,
	boot_zfs_closeall,
	boot_zfs_getdents
};


extern unsigned long unix_startblk;
static struct zfsmount zfsmount;
static fileid_t *head;

static int
vdev_read(vdev_t *vdev, void *priv, off_t offset, void *buf, size_t size)
{
	int fd = (int)(intptr_t)vdev->v_priv;
	uint64_t sec_buffer[DEV_BSIZE/sizeof(uint64_t)];
	char *sec_buf = (char *)sec_buffer;

	while (size != 0) {
		uint64_t sector = offset / DEV_BSIZE;
		uint64_t sector_offset = offset % DEV_BSIZE;
		size_t sz = min(DEV_BSIZE - sector_offset, size);
		if (sz < DEV_BSIZE) {
			if (prom_read(fd, sec_buf, DEV_BSIZE, sector + unix_startblk, 0) != DEV_BSIZE)
				return EIO;
			memcpy(buf, sec_buf + sector_offset, sz);
		} else {
			sz = (size / DEV_BSIZE) * DEV_BSIZE;
			if (prom_read(fd, buf, sz, sector + unix_startblk, 0) != sz)
				return EIO;
		}
		buf = (char *)buf + sz;
		size -= sz;
		offset += sz;
	}
	return 0;
}

static int
vdev_write(vdev_t *vdev, off_t offset, void *buf, size_t size)
{
	int fd = (int)(intptr_t)vdev->v_priv;
	uint64_t sec_buffer[DEV_BSIZE/sizeof(uint64_t)];
	char *sec_buf = (char *)sec_buffer;

	while (size != 0) {
		uint64_t sector = offset / DEV_BSIZE;
		uint64_t sector_offset = offset % DEV_BSIZE;
		size_t sz = min(DEV_BSIZE - sector_offset, size);
		if (sz < DEV_BSIZE) {
			memcpy(sec_buf, buf, sz);
			if (prom_write(fd, sec_buf, DEV_BSIZE, sector + unix_startblk, 0) != DEV_BSIZE)
				return EIO;
		} else {
			sz = (size / DEV_BSIZE) * DEV_BSIZE;
			if (prom_write(fd, buf, sz, sector + unix_startblk, 0) != sz)
				return EIO;
		}
		buf = (char *)buf + sz;
		size -= sz;
		offset += sz;
	}
	return 0;
}

static int boot_zfs_mountroot(char *devname)
{

	zfs_init();

	int fd = prom_open(devname);
	if (fd == 0) {
		prom_printf("prom_open error %s\n", devname);
		return -1;
	}

	if (vdev_probe(vdev_read, vdev_write, (void *)(uintptr_t)fd, NULL) != 0) {
		prom_printf("vdev_probe error\n");
		prom_close(fd);
		return -1;
	}

	spa_t *spa = STAILQ_FIRST(&zfs_pools);
	if (zfs_spa_init(spa) != 0) {
		prom_printf("zfs_spa_init error\n");
		prom_close(fd);
		return -1;
	}

	if (zfs_mount(spa, 0, &zfsmount) != 0) {
		prom_printf("zfs_mount error\n");
		prom_close(fd);
		return -1;
	}

	return 0;
}


static int boot_zfs_open(char *filename, int flags)
{
	fileid_t	*filep;
	static int	filedes = 1;

	/* build and link a new file descriptor */
	filep = (fileid_t *)bkmem_alloc(sizeof (fileid_t));

	filep->fi_filedes = filedes++;
	filep->fi_taken = 1;
	filep->fi_path = (char *)bkmem_alloc(strlen(filename) + 1);
	(void) strcpy(filep->fi_path, filename);
	filep->fi_devp = (devid_t *)bkmem_alloc(sizeof(dnode_phys_t));
	filep->fi_inode = NULL;

	if (zfs_lookup(&zfsmount, filename, (dnode_phys_t *)filep->fi_devp) != 0) {
		prom_printf("zfs_lookup error %s\n", filename);
		bkmem_free(filep->fi_path, strlen(filep->fi_path)+1);
		bkmem_free(filep->fi_devp, sizeof(dnode_phys_t));
		bkmem_free((char *)filep, sizeof (fileid_t));
		return -1;
	}

	filep->fi_back = NULL;
	filep->fi_forw = head;
	if (head) {
		head->fi_back = filep;
	}
	head = filep;

	filep->fi_offset = filep->fi_count = 0;

	return (filep->fi_filedes);
}

static fileid_t *
find_fp(int fd)
{
	fileid_t *filep = head;

	if (fd >= 0) {
		while (filep) {
			if (fd == filep->fi_filedes)
				return (filep->fi_taken ? filep : 0);
			filep = filep->fi_forw;
		}
	}

	return NULL;
}
static int boot_zfs_close(int fd)
{
	fileid_t *filep;

	if (!(filep = find_fp(fd)))
		return (-1);

	if (filep->fi_taken == 0)
		return (-1);

	/* Clear the ranks */
	bkmem_free(filep->fi_path, strlen(filep->fi_path)+1);
	bkmem_free(filep->fi_devp, sizeof(dnode_phys_t));
	filep->fi_blocknum = filep->fi_count = filep->fi_offset = 0;
	filep->fi_memp = (caddr_t)0;
	filep->fi_devp = 0;
	filep->fi_taken = 0;

	/* unlink and deallocate node */
	if (filep->fi_forw) {
		filep->fi_forw->fi_back = filep->fi_back;
	}
	if (filep->fi_back) {
		filep->fi_back->fi_forw = filep->fi_forw;
	}
	if (filep == head) {
		head = filep->fi_forw;
	}

	bkmem_free((char *)filep, sizeof (fileid_t));

	return (0);
}

static ssize_t
zfs_read(const spa_t *spa, dnode_phys_t *dnode, off_t *offp, void *start, size_t size)
{
	size_t n;
	int rc;
	struct stat sb;

	if (zfs_dnode_stat(spa, dnode, &sb) != 0)
		return (-1);

	n = size;
	if (*offp + n > sb.st_size)
		n = sb.st_size - *offp;

	rc = dnode_read(spa, dnode, *offp, start, n);
	if (rc)
		return (-1);
	*offp += n;

	return (n);
}

static ssize_t boot_zfs_read(int fd, caddr_t buf, size_t size)
{
	fileid_t *filep;

	if (!(filep = find_fp(fd)))
		return (-1);
	dnode_phys_t *dnp = (dnode_phys_t *)filep->fi_devp;
	return zfs_read(zfsmount.spa, dnp, &filep->fi_offset, buf, size);
}

static off_t boot_zfs_lseek(int fd, off_t addr, int whence)
{
	fileid_t *filep;

	/* Make sure user knows what file he is talking to */
	if (!(filep = find_fp(fd)))
		return (-1);

	switch (whence) {
	case SEEK_CUR:
		filep->fi_offset += addr;
		break;
	case SEEK_SET:
		filep->fi_offset = addr;
		break;
	default:
	case SEEK_END:
		printf("boot_zfs_lseek(): invalid whence value %d\n", whence);
		break;
	}

	return (0);
}

static void boot_zfs_closeall(int flag)
{
	while (head != NULL) {
		int fd = head->fi_filedes;
		boot_zfs_close(fd);
	}
}
static int boot_zfs_unmountroot(void)
{
	boot_zfs_closeall(0);
	return 0;
}

static int boot_zfs_fstat(int fd, struct bootstat *stp)
{
	fileid_t	*filep;
	struct stat sb;

	if (!(filep = find_fp(fd)))
		return (-1);

	if (zfs_dnode_stat(zfsmount.spa, (dnode_phys_t *)filep->fi_devp, &sb) != 0)
		return -1;
	memset(stp, 0, sizeof(struct bootstat));
	stp->st_mode = sb.st_mode;
	stp->st_size = sb.st_size;

	return (0);
}

static int boot_zfs_getdents(int fd, struct dirent *dep, unsigned size)
{
	prom_printf("%s: not supported\n",__func__);
	return -1;
}

void get_boot_zpool(char *buf)
{
	strcpy(buf, zfsmount.spa->spa_name);
	buf += strlen(buf);
	strcpy(buf, "/");
	buf += strlen(buf);
	zfs_rlookup(zfsmount.spa, zfsmount.rootobj, buf);
}

void
get_boot_zpool_guid(char *buf)
{
	snprintf(buf, ZFS_MAXNAMELEN * 2, "%" PRIu64, zfsmount.spa->spa_guid);
}

void
get_boot_vdev_guid(char *buf)
{
	snprintf(buf, ZFS_MAXNAMELEN * 2, "%" PRIu64, zfsmount.spa->spa_boot_vdev->v_guid);
}

voidpf zcalloc (voidpf opaque, unsigned items, unsigned size)
{
	return calloc(items, size);
}

void zcfree (voidpf opaque, voidpf ptr)
{
	free(ptr);
}

void
zmemcpy(void *dest, const void *source, uint_t len)
{
	memcpy(dest, source, len);
}

int
zmemcmp(const void *s1, const void *s2, uint_t len)
{
	return (memcmp(s1, s2, len));
}

void
zmemzero(void *dest, uint_t len)
{
	memset(dest, 0, len);
}

extern size_t unix_numblks;

uint64_t
ldi_get_size(void *priv)
{
	return unix_numblks * 0x200ul;
}

int asprintf(char **buf, const char *fmt, ...)
{
	va_list aargs;
	size_t len = 256;
	char *ptr;
	int ret;

	for (;;) {
		va_start(aargs, fmt);
		ptr = malloc(len);
		if (ptr != NULL) {
			ret = vsnprintf(ptr, len, fmt, aargs);
		}
		va_end(aargs);
		if (ptr == NULL)
			break;
		if (ret < len)
			break;
		free(ptr);
		len *= 2;
	}
	*buf = ptr;
	if (ptr == NULL)
		return -1;
	return ret;
}
