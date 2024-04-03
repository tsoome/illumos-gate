/*
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
 */

#include <sys/cdefs.h>

/*
 *	Stand-alone file reading package.
 */

#include <stand.h>
#include <sys/disk.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <disk.h>
#include <part.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <bootstrap.h>
#include <inttypes.h>

#include "libzfs.h"

#include "zfsimpl.c"

/* Define the range of indexes to be populated with ZFS Boot Environments */
#define		ZFS_BE_FIRST	4
#define		ZFS_BE_LAST	8

static int	zfs_open(const char *, struct open_file *);
static int	zfs_close(struct open_file *);
static int	zfs_read(struct open_file *, void *, size_t, size_t *);
static off_t	zfs_seek(struct open_file *, off_t, int);
static int	zfs_stat(struct open_file *, struct stat *);
static int	zfs_readdir(struct open_file *, struct dirent *);

struct devsw zfs_dev;

struct fs_ops zfs_fsops = {
	"zfs",
	zfs_open,
	zfs_close,
	zfs_read,
	null_write,
	zfs_seek,
	zfs_stat,
	zfs_readdir
};

/*
 * In-core open file.
 */
struct file {
	off_t		f_seekp;	/* seek pointer */
	dnode_phys_t	f_dnode;
	uint64_t	f_zap_type;	/* zap type for readdir */
	uint64_t	f_num_leafs;	/* number of fzap leaf blocks */
	zap_leaf_phys_t	*f_zap_leaf;	/* zap leaf buffer */
};

SLIST_HEAD(zfs_be_list, zfs_be_entry) zfs_be_head =
    SLIST_HEAD_INITIALIZER(zfs_be_head);
struct zfs_be_list *zfs_be_headp;
struct zfs_be_entry {
	const char *name;
	SLIST_ENTRY(zfs_be_entry) entries;
} *zfs_be, *zfs_be_tmp;

/*
 * Open a file.
 */
static int
zfs_open(const char *upath, struct open_file *f)
{
	struct zfsmount *mount = (struct zfsmount *)f->f_devdata;
	struct file *fp;
	int rc;

	if (f->f_dev != &zfs_dev)
		return (EINVAL);

	/* allocate file system specific data structure */
	fp = calloc(1, sizeof (struct file));
	if (fp == NULL)
		return (ENOMEM);
	f->f_fsdata = fp;

	rc = zfs_lookup(mount, upath, &fp->f_dnode);
	fp->f_seekp = 0;
	if (rc) {
		f->f_fsdata = NULL;
		free(fp);
	}
	return (rc);
}

static int
zfs_close(struct open_file *f)
{
	struct file *fp = (struct file *)f->f_fsdata;

	dnode_cache_obj = NULL;
	f->f_fsdata = NULL;

	free(fp);
	return (0);
}

/*
 * Copy a portion of a file into kernel memory.
 * Cross block boundaries when necessary.
 */
static int
zfs_read(struct open_file *f, void *start, size_t size, size_t *resid)
{
	const spa_t *spa = ((struct zfsmount *)f->f_devdata)->spa;
	struct file *fp = (struct file *)f->f_fsdata;
	struct stat sb;
	size_t n;
	int rc;

	rc = zfs_stat(f, &sb);
	if (rc)
		return (rc);
	n = size;
	if (fp->f_seekp + n > sb.st_size)
		n = sb.st_size - fp->f_seekp;

	rc = dnode_read(spa, &fp->f_dnode, fp->f_seekp, start, n);
	if (rc)
		return (rc);

	fp->f_seekp += n;
	if (resid)
		*resid = size - n;

	return (0);
}

static off_t
zfs_seek(struct open_file *f, off_t offset, int where)
{
	struct file *fp = (struct file *)f->f_fsdata;
	struct stat sb;
	int error;

	switch (where) {
	case SEEK_SET:
		fp->f_seekp = offset;
		break;
	case SEEK_CUR:
		fp->f_seekp += offset;
		break;
	case SEEK_END:
		error = zfs_stat(f, &sb);
		if (error != 0) {
			errno = error;
			return (-1);
		}
		fp->f_seekp = sb.st_size - offset;
		break;
	default:
		errno = EINVAL;
		return (-1);
	}
	return (fp->f_seekp);
}

static int
zfs_stat(struct open_file *f, struct stat *sb)
{
	const spa_t *spa = ((struct zfsmount *)f->f_devdata)->spa;
	struct file *fp = (struct file *)f->f_fsdata;

	return (zfs_dnode_stat(spa, &fp->f_dnode, sb));
}

static int
zfs_readdir(struct open_file *f, struct dirent *d)
{
	const spa_t *spa = ((struct zfsmount *)f->f_devdata)->spa;
	struct file *fp = (struct file *)f->f_fsdata;
	mzap_ent_phys_t mze;
	struct stat sb;
	size_t bsize = fp->f_dnode.dn_datablkszsec << SPA_MINBLOCKSHIFT;
	int rc;

	rc = zfs_stat(f, &sb);
	if (rc)
		return (rc);
	if (!S_ISDIR(sb.st_mode))
		return (ENOTDIR);

	/*
	 * If this is the first read, get the zap type.
	 */
	if (fp->f_seekp == 0) {
		rc = dnode_read(spa, &fp->f_dnode, 0, &fp->f_zap_type,
		    sizeof (fp->f_zap_type));
		if (rc)
			return (rc);

		if (fp->f_zap_type == ZBT_MICRO) {
			fp->f_seekp = offsetof(mzap_phys_t, mz_chunk);
		} else {
			rc = dnode_read(spa, &fp->f_dnode,
			    offsetof(zap_phys_t, zap_num_leafs),
			    &fp->f_num_leafs, sizeof (fp->f_num_leafs));
			if (rc)
				return (rc);

			fp->f_seekp = bsize;
			fp->f_zap_leaf = malloc(bsize);
			if (fp->f_zap_leaf == NULL)
				return (ENOMEM);
			rc = dnode_read(spa, &fp->f_dnode, fp->f_seekp,
			    fp->f_zap_leaf, bsize);
			if (rc)
				return (rc);
		}
	}

	if (fp->f_zap_type == ZBT_MICRO) {
	mzap_next:
		if (fp->f_seekp >= bsize)
			return (ENOENT);

		rc = dnode_read(spa, &fp->f_dnode, fp->f_seekp, &mze,
		    sizeof (mze));
		if (rc)
			return (rc);
		fp->f_seekp += sizeof (mze);

		if (!mze.mze_name[0])
			goto mzap_next;

		d->d_fileno = ZFS_DIRENT_OBJ(mze.mze_value);
		d->d_type = ZFS_DIRENT_TYPE(mze.mze_value);
		strcpy(d->d_name, mze.mze_name);
		d->d_namlen = strlen(d->d_name);
		return (0);
	} else {
		zap_leaf_t zl;
		zap_leaf_chunk_t *zc, *nc;
		int chunk;
		size_t namelen;
		char *p;
		uint64_t value;

		/*
		 * Initialise this so we can use the ZAP size
		 * calculating macros.
		 */
		zl.l_bs = ilog2(bsize);
		zl.l_phys = fp->f_zap_leaf;

		/*
		 * Figure out which chunk we are currently looking at
		 * and consider seeking to the next leaf. We use the
		 * low bits of f_seekp as a simple chunk index.
		 */
	fzap_next:
		chunk = fp->f_seekp & (bsize - 1);
		if (chunk == ZAP_LEAF_NUMCHUNKS(&zl)) {
			fp->f_seekp = (fp->f_seekp & ~(bsize - 1)) + bsize;
			chunk = 0;

			/*
			 * Check for EOF and read the new leaf.
			 */
			if (fp->f_seekp >= bsize * fp->f_num_leafs)
				return (ENOENT);

			rc = dnode_read(spa, &fp->f_dnode, fp->f_seekp,
			    fp->f_zap_leaf, bsize);
			if (rc)
				return (rc);
		}

		zc = &ZAP_LEAF_CHUNK(&zl, chunk);
		fp->f_seekp++;
		if (zc->l_entry.le_type != ZAP_CHUNK_ENTRY)
			goto fzap_next;

		namelen = zc->l_entry.le_name_numints;
		if (namelen > sizeof (d->d_name))
			namelen = sizeof (d->d_name);

		/*
		 * Paste the name back together.
		 */
		nc = &ZAP_LEAF_CHUNK(&zl, zc->l_entry.le_name_chunk);
		p = d->d_name;
		while (namelen > 0) {
			int len;
			len = namelen;
			if (len > ZAP_LEAF_ARRAY_BYTES)
				len = ZAP_LEAF_ARRAY_BYTES;
			memcpy(p, nc->l_array.la_array, len);
			p += len;
			namelen -= len;
			nc = &ZAP_LEAF_CHUNK(&zl, nc->l_array.la_next);
		}
		d->d_name[sizeof (d->d_name) - 1] = 0;

		/*
		 * Assume the first eight bytes of the value are
		 * a uint64_t.
		 */
		value = fzap_leaf_value(&zl, zc);

		d->d_fileno = ZFS_DIRENT_OBJ(value);
		d->d_type = ZFS_DIRENT_TYPE(value);
		d->d_namlen = strlen(d->d_name);

		return (0);
	}
}

static int
vdev_read(vdev_t *vdev __unused, void *priv, off_t offset, void *buf,
    size_t bytes)
{
	int fd, ret;
	size_t res, head, tail, total_size, full_sec_size;
	unsigned secsz, do_tail_read;
	off_t start_sec;
	char *outbuf, *bouncebuf;

	fd = (uintptr_t)priv;
	outbuf = (char *)buf;
	bouncebuf = NULL;

	ret = ioctl(fd, DIOCGSECTORSIZE, &secsz);
	if (ret != 0)
		return (ret);

	/* BEGIN CSTYLED */
	/*
	 * Handling reads of arbitrary offset and size - multi-sector case
	 * and single-sector case.
	 *
	 *                        Multi-sector Case
	 *                (do_tail_read = true if tail > 0)
	 *
	 *   |<----------------------total_size--------------------->|
	 *   |                                                       |
	 *   |<--head-->|<--------------bytes------------>|<--tail-->|
	 *   |          |                                 |          |
	 *   |          |       |<~full_sec_size~>|       |          |
	 *   +------------------+                 +------------------+
	 *   |          |0101010|     .  .  .     |0101011|          |
	 *   +------------------+                 +------------------+
	 *         start_sec                         start_sec + n
	 *
	 *
	 *                      Single-sector Case
	 *                    (do_tail_read = false)
	 *
	 *              |<------total_size = secsz----->|
	 *              |                               |
	 *              |<-head->|<---bytes--->|<-tail->|
	 *              +-------------------------------+
	 *              |        |0101010101010|        |
	 *              +-------------------------------+
	 *                          start_sec
	 */
	/* END CSTYLED */
	start_sec = offset / secsz;
	head = offset % secsz;
	total_size = roundup2(head + bytes, secsz);
	tail = total_size - (head + bytes);
	do_tail_read = ((tail > 0) && (head + bytes > secsz));
	full_sec_size = total_size;
	if (head > 0)
		full_sec_size -= secsz;
	if (do_tail_read)
		full_sec_size -= secsz;

	/* Return of partial sector data requires a bounce buffer. */
	if ((head > 0) || do_tail_read || bytes < secsz) {
		bouncebuf = malloc(secsz);
		if (bouncebuf == NULL) {
			printf("vdev_read: out of memory\n");
			return (ENOMEM);
		}
	}

	if (lseek(fd, start_sec * secsz, SEEK_SET) == -1) {
		ret = errno;
		goto error;
	}

	/* Partial data return from first sector */
	if (head > 0) {
		res = read(fd, bouncebuf, secsz);
		if (res != secsz) {
			ret = EIO;
			goto error;
		}
		memcpy(outbuf, bouncebuf + head, min(secsz - head, bytes));
		outbuf += min(secsz - head, bytes);
	}

	/* Full data return from read sectors */
	if (full_sec_size > 0) {
		if (bytes < full_sec_size) {
			res = read(fd, bouncebuf, secsz);
			if (res != secsz) {
				ret = EIO;
				goto error;
			}
			memcpy(outbuf, bouncebuf, bytes);
		} else {
			res = read(fd, outbuf, full_sec_size);
			if (res != full_sec_size) {
				ret = EIO;
				goto error;
			}
			outbuf += full_sec_size;
		}
	}

	/* Partial data return from last sector */
	if (do_tail_read) {
		res = read(fd, bouncebuf, secsz);
		if (res != secsz) {
			ret = EIO;
			goto error;
		}
		memcpy(outbuf, bouncebuf, secsz - tail);
	}

	ret = 0;
error:
	free(bouncebuf);
	return (ret);
}

static int
vdev_write(vdev_t *vdev, off_t offset, void *buf, size_t bytes)
{
	int fd, ret;
	size_t head, tail, total_size, full_sec_size;
	unsigned secsz, do_tail_write;
	off_t start_sec;
	ssize_t res;
	char *outbuf, *bouncebuf;

	fd = (uintptr_t)vdev->v_priv;
	outbuf = (char *)buf;
	bouncebuf = NULL;

	ret = ioctl(fd, DIOCGSECTORSIZE, &secsz);
	if (ret != 0)
		return (ret);

	start_sec = offset / secsz;
	head = offset % secsz;
	total_size = roundup2(head + bytes, secsz);
	tail = total_size - (head + bytes);
	do_tail_write = ((tail > 0) && (head + bytes > secsz));
	full_sec_size = total_size;
	if (head > 0)
		full_sec_size -= secsz;
	if (do_tail_write)
		full_sec_size -= secsz;

	/* Partial sector write requires a bounce buffer. */
	if ((head > 0) || do_tail_write || bytes < secsz) {
		bouncebuf = malloc(secsz);
		if (bouncebuf == NULL) {
			printf("vdev_write: out of memory\n");
			return (ENOMEM);
		}
	}

	if (lseek(fd, start_sec * secsz, SEEK_SET) == -1) {
		ret = errno;
		goto error;
	}

	/* Partial data for first sector */
	if (head > 0) {
		res = read(fd, bouncebuf, secsz);
		if ((unsigned)res != secsz) {
			ret = EIO;
			goto error;
		}
		memcpy(bouncebuf + head, outbuf, min(secsz - head, bytes));
		(void) lseek(fd, -secsz, SEEK_CUR);
		res = write(fd, bouncebuf, secsz);
		if ((unsigned)res != secsz) {
			ret = EIO;
			goto error;
		}
		outbuf += min(secsz - head, bytes);
	}

	/*
	 * Full data write to sectors.
	 * Note, there is still corner case where we write
	 * to sector boundary, but less than sector size, e.g. write 512B
	 * to 4k sector.
	 */
	if (full_sec_size > 0) {
		if (bytes < full_sec_size) {
			res = read(fd, bouncebuf, secsz);
			if ((unsigned)res != secsz) {
				ret = EIO;
				goto error;
			}
			memcpy(bouncebuf, outbuf, bytes);
			(void) lseek(fd, -secsz, SEEK_CUR);
			res = write(fd, bouncebuf, secsz);
			if ((unsigned)res != secsz) {
				ret = EIO;
				goto error;
			}
		} else {
			res = write(fd, outbuf, full_sec_size);
			if ((unsigned)res != full_sec_size) {
				ret = EIO;
				goto error;
			}
			outbuf += full_sec_size;
		}
	}

	/* Partial data write to last sector */
	if (do_tail_write) {
		res = read(fd, bouncebuf, secsz);
		if ((unsigned)res != secsz) {
			ret = EIO;
			goto error;
		}
		memcpy(bouncebuf, outbuf, secsz - tail);
		(void) lseek(fd, -secsz, SEEK_CUR);
		res = write(fd, bouncebuf, secsz);
		if ((unsigned)res != secsz) {
			ret = EIO;
			goto error;
		}
	}

	ret = 0;
error:
	free(bouncebuf);
	return (ret);
}

static int
zfs_dev_init(void)
{
	spa_t *spa;
	spa_t *next;
	spa_t *prev;

	zfs_init();
	if (archsw.arch_zfs_probe == NULL)
		return (ENXIO);
	archsw.arch_zfs_probe();

	prev = NULL;
	spa = STAILQ_FIRST(&zfs_pools);
	while (spa != NULL) {
		next = STAILQ_NEXT(spa, spa_link);
		if (zfs_spa_init(spa)) {
			if (prev == NULL)
				STAILQ_REMOVE_HEAD(&zfs_pools, spa_link);
			else
				STAILQ_REMOVE_AFTER(&zfs_pools, prev, spa_link);
		} else
			prev = spa;
		spa = next;
	}
	return (0);
}

struct zfs_probe_args {
	int		fd;
	const char	*devname;
	uint64_t	*pool_guid;
	unsigned	secsz;
};

static int
zfs_diskread(void *arg, void *buf, size_t blocks, uint64_t offset)
{
	struct zfs_probe_args *ppa;

	ppa = (struct zfs_probe_args *)arg;
	return (vdev_read(NULL, (void *)(uintptr_t)ppa->fd,
	    offset * ppa->secsz, buf, blocks * ppa->secsz));
}

static int
zfs_probe(int fd, uint64_t *pool_guid)
{
	spa_t *spa;
	int ret;

	spa = NULL;
	ret = vdev_probe(vdev_read, vdev_write, (void *)(uintptr_t)fd, &spa);
	if (ret == 0 && pool_guid != NULL)
		*pool_guid = spa->spa_guid;
	return (ret);
}

static int
zfs_probe_partition(void *arg, const char *partname,
    const struct ptable_entry *part)
{
	struct zfs_probe_args *ppa, pa;
	struct ptable *table;
	char devname[32];
	int ret = 0;

	/* filter out partitions *not* used by zfs */
	switch (part->type) {
	case PART_EFI:		/* efi system partition */
	case PART_RESERVED:	/* efi reserverd */
	case PART_VTOC_BOOT:	/* vtoc boot area */
	case PART_VTOC_SWAP:
		return (ret);
	default:
		break;
	}
	ppa = (struct zfs_probe_args *)arg;
	strncpy(devname, ppa->devname, strlen(ppa->devname) - 1);
	devname[strlen(ppa->devname) - 1] = '\0';
	snprintf(devname, sizeof (devname), "%s%s:", devname, partname);
	pa.fd = open(devname, O_RDWR);
	if (pa.fd == -1)
		return (ret);
	ret = zfs_probe(pa.fd, ppa->pool_guid);
	if (ret == 0)
		return (ret);
	if (part->type == PART_SOLARIS2) {
		pa.devname = devname;
		pa.pool_guid = ppa->pool_guid;
		pa.secsz = ppa->secsz;
		table = ptable_open(&pa, part->end - part->start + 1,
		    ppa->secsz, zfs_diskread);
		if (table != NULL) {
			enum ptable_type pt = ptable_gettype(table);

			if (pt == PTABLE_VTOC8 || pt == PTABLE_VTOC)
				ptable_iterate(table, &pa, zfs_probe_partition);
			ptable_close(table);
		}
	}
	close(pa.fd);
	return (0);
}

/*
 * Return bootenv nvlist from pool label.
 */
int
zfs_get_bootenv(void *vdev, nvlist_t **benvp)
{
	struct zfs_devdesc *dev = (struct zfs_devdesc *)vdev;
	nvlist_t *benv = NULL;
	vdev_t *vd;
	spa_t *spa;

	if (dev->dd.d_dev->dv_type != DEVT_ZFS)
		return (ENOTSUP);

	if ((spa = spa_find_by_dev(dev)) == NULL)
		return (ENXIO);

	if (spa->spa_bootenv == NULL) {
		STAILQ_FOREACH(vd, &spa->spa_root_vdev->v_children,
		    v_childlink) {
			benv = vdev_read_bootenv(vd);

			if (benv != NULL)
				break;
		}
		spa->spa_bootenv = benv;
	} else {
		benv = spa->spa_bootenv;
	}

	if (benv == NULL)
		return (ENOENT);

	*benvp = benv;
	return (0);
}

/*
 * Store nvlist to pool label bootenv area. Also updates cached pointer in spa.
 */
int
zfs_set_bootenv(void *vdev, nvlist_t *benv)
{
	struct zfs_devdesc *dev = (struct zfs_devdesc *)vdev;
	spa_t *spa;
	vdev_t *vd;

	if (dev->dd.d_dev->dv_type != DEVT_ZFS)
		return (ENOTSUP);

	if ((spa = spa_find_by_dev(dev)) == NULL)
		return (ENXIO);

	STAILQ_FOREACH(vd, &spa->spa_root_vdev->v_children, v_childlink) {
		vdev_write_bootenv(vd, benv);
	}

	spa->spa_bootenv = benv;
	return (0);
}

/*
 * Get bootonce value by key. The bootonce <key, value> pair is removed
 * from the bootenv nvlist and the remaining nvlist is committed back to disk.
 */
int
zfs_get_bootonce(void *vdev, const char *key, char *buf, size_t size)
{
	nvlist_t *benv;
	char *result = NULL;
	int rv;

	if ((rv = zfs_get_bootenv(vdev, &benv)) != 0)
		return (rv);

	if ((rv = nvlist_lookup_string(benv, key, &result)) == 0) {
		if (result[0] == '\0') {
			/* ignore empty string */
			rv = ENOENT;
		} else {
			size = MIN(strlen(result) + 1, size);
			strlcpy(buf, result, size);
		}
		rv = nvlist_remove(benv, key, DATA_TYPE_STRING);
		if (rv == 0)
			rv = zfs_set_bootenv(vdev, benv);
	}

	return (rv);
}

/*
 * nvstore backend.
 */

static int zfs_nvstore_setter(void *, int, const char *,
    const void *, size_t);
static int zfs_nvstore_setter_str(void *, const char *, const char *,
    const char *);
static int zfs_nvstore_unset_impl(void *, const char *, bool);
static int zfs_nvstore_setenv(void *, void *);

/*
 * nvstore is only present for current rootfs pool.
 */
static int
zfs_nvstore_sethook(struct env_var *ev, int flags __unused, const void *value)
{
	struct zfs_devdesc *dev;
	int rv;

	archsw.arch_getdev((void **)&dev, NULL, NULL);
	if (dev == NULL)
		return (ENXIO);

	rv = zfs_nvstore_setter_str(dev, NULL, ev->ev_name, value);

	free(dev);
	return (rv);
}

/*
 * nvstore is only present for current rootfs pool.
 */
static int
zfs_nvstore_unsethook(struct env_var *ev)
{
	struct zfs_devdesc *dev;
	int rv;

	archsw.arch_getdev((void **)&dev, NULL, NULL);
	if (dev == NULL)
		return (ENXIO);

	rv = zfs_nvstore_unset_impl(dev, ev->ev_name, false);

	free(dev);
	return (rv);
}

static int
zfs_nvstore_getter(void *vdev, const char *name, void **data)
{
	struct zfs_devdesc *dev = (struct zfs_devdesc *)vdev;
	spa_t *spa;
	nvlist_t *nv;
	char *str, **ptr;
	int rv;

	if (dev->dd.d_dev->dv_type != DEVT_ZFS)
		return (ENOTSUP);

	if ((spa = spa_find_by_dev(dev)) == NULL)
		return (ENXIO);

	if (spa->spa_bootenv == NULL)
		return (ENXIO);

	rv = nvlist_lookup_nvlist(spa->spa_bootenv, OS_NVSTORE, &nv);
	if (rv != 0)
		return (rv);

	rv = nvlist_lookup_string(nv, name, &str);
	if (rv == 0) {
		ptr = (char **)data;
		asprintf(ptr, "%s", str);
		if (*data == NULL)
			rv = ENOMEM;
	}
	return (rv);
}

static int
zfs_nvstore_setter(void *vdev, int type, const char *name,
    const void *data, size_t size)
{
	struct zfs_devdesc *dev = (struct zfs_devdesc *)vdev;
	spa_t *spa;
	nvlist_t *nv;
	int rv;
	bool env_set = true;

	if (dev->dd.d_dev->dv_type != DEVT_ZFS)
		return (ENOTSUP);

	if ((spa = spa_find_by_dev(dev)) == NULL)
		return (ENXIO);

	if (spa->spa_bootenv == NULL)
		return (ENXIO);

	if (nvlist_lookup_nvlist(spa->spa_bootenv, OS_NVSTORE, &nv) != 0) {
		rv = nvlist_alloc(&nv, NV_UNIQUE_NAME, 0);
		if (rv != 0)
			return (rv);
	} else {
		nvlist_t *tmp;
		rv = nvlist_dup(nv, &tmp, 0);
		if (rv != 0)
			return (rv);
		nv = tmp;
	}

	rv = 0;
	switch (type) {
	case DATA_TYPE_INT8:
		if (size != sizeof (int8_t)) {
			rv = EINVAL;
			break;
		}
		rv = nvlist_add_int8(nv, name, *(int8_t *)data);
		break;

	case DATA_TYPE_INT16:
		if (size != sizeof (int16_t)) {
			rv = EINVAL;
			break;
		}
		rv = nvlist_add_int16(nv, name, *(int16_t *)data);
		break;

	case DATA_TYPE_INT32:
		if (size != sizeof (int32_t)) {
			rv = EINVAL;
			break;
		}
		rv = nvlist_add_int32(nv, name, *(int32_t *)data);
		break;

	case DATA_TYPE_INT64:
		if (size != sizeof (int64_t)) {
			rv = EINVAL;
			break;
		}
		rv = nvlist_add_int64(nv, name, *(int64_t *)data);
		break;

	case DATA_TYPE_BYTE:
		if (size != sizeof (uint8_t)) {
			rv = EINVAL;
			break;
		}
		rv = nvlist_add_byte(nv, name, *(int8_t *)data);
		break;

	case DATA_TYPE_UINT8:
		if (size != sizeof (uint8_t)) {
			rv = EINVAL;
			break;
		}
		rv = nvlist_add_uint8(nv, name, *(int8_t *)data);
		break;
	case DATA_TYPE_UINT16:
		if (size != sizeof (uint16_t)) {
			rv = EINVAL;
			break;
		}
		rv = nvlist_add_uint16(nv, name, *(uint16_t *)data);
		break;

	case DATA_TYPE_UINT32:
		if (size != sizeof (uint32_t)) {
			rv = EINVAL;
			break;
		}
		rv = nvlist_add_uint32(nv, name, *(uint32_t *)data);
		break;

	case DATA_TYPE_UINT64:
		if (size != sizeof (uint64_t)) {
			rv = EINVAL;
			break;
		}
		rv = nvlist_add_uint64(nv, name, *(uint64_t *)data);
		break;

	case DATA_TYPE_STRING:
		rv = nvlist_add_string(nv, name, data);
		break;

	case DATA_TYPE_BOOLEAN_VALUE:
		if (size != sizeof (boolean_t)) {
			rv = EINVAL;
			break;
		}
		rv = nvlist_add_boolean_value(nv, name, *(boolean_t *)data);
		break;

	default:
		rv = EINVAL;
		break;
	}

	if (rv == 0) {
		rv = nvlist_add_nvlist(spa->spa_bootenv, OS_NVSTORE, nv);
		if (rv == 0) {
			rv = zfs_set_bootenv(vdev, spa->spa_bootenv);
		}
		if (rv == 0) {
			if (env_set) {
				nvpair_t *nvp;

				rv = nvlist_lookup_nvpair(nv, name, &nvp);
				if (rv == 0) {
					rv = zfs_nvstore_setenv(vdev, nvp);
				}
			}
		}
	}

	nvlist_free(nv);
	return (rv);
}

static const char *typenames[] = {
	"DATA_TYPE_UNKNOWN",
	"DATA_TYPE_BOOLEAN",
	"DATA_TYPE_BYTE",
	"DATA_TYPE_INT16",
	"DATA_TYPE_UINT16",
	"DATA_TYPE_INT32",
	"DATA_TYPE_UINT32",
	"DATA_TYPE_INT64",
	"DATA_TYPE_UINT64",
	"DATA_TYPE_STRING",
	"DATA_TYPE_BYTE_ARRAY",
	"DATA_TYPE_INT16_ARRAY",
	"DATA_TYPE_UINT16_ARRAY",
	"DATA_TYPE_INT32_ARRAY",
	"DATA_TYPE_UINT32_ARRAY",
	"DATA_TYPE_INT64_ARRAY",
	"DATA_TYPE_UINT64_ARRAY",
	"DATA_TYPE_STRING_ARRAY",
	"DATA_TYPE_HRTIME",
	"DATA_TYPE_NVLIST",
	"DATA_TYPE_NVLIST_ARRAY",
	"DATA_TYPE_BOOLEAN_VALUE",
	"DATA_TYPE_INT8",
	"DATA_TYPE_UINT8",
	"DATA_TYPE_BOOLEAN_ARRAY",
	"DATA_TYPE_INT8_ARRAY",
	"DATA_TYPE_UINT8_ARRAY"
};

static int
nvpair_type_from_name(const char *name)
{
	unsigned i;

	for (i = 0; i < nitems(typenames); i++) {
		if (strcmp(name, typenames[i]) == 0)
			return (i);
	}
	return (0);
}

static int
get_int64(const char *data, int64_t *ip)
{
	char *end;
	int64_t val;

	errno = 0;
	val = strtoll(data, &end, 0);
	if (errno != 0 || *data == '\0' || *end != '\0')
		return (EINVAL);

	*ip = val;
	return (0);
}

static int
get_uint64(const char *data, uint64_t *ip)
{
	char *end;
	uint64_t val;

	errno = 0;
	val = strtoull(data, &end, 0);
	if (errno != 0 || *data == '\0' || *end != '\0')
		return (EINVAL);

	*ip = val;
	return (0);
}

/*
 * Translate textual data to data type. If type is not set, and we are
 * creating new pair, use DATA_TYPE_STRING.
 */
static int
zfs_nvstore_setter_str(void *vdev, const char *type, const char *name,
    const char *data)
{
	struct zfs_devdesc *dev = (struct zfs_devdesc *)vdev;
	spa_t *spa;
	nvlist_t *nv;
	int rv;
	data_type_t dt;
	int64_t val;
	uint64_t uval;

	if (dev->dd.d_dev->dv_type != DEVT_ZFS)
		return (ENOTSUP);

	if ((spa = spa_find_by_dev(dev)) == NULL)
		return (ENXIO);

	if (spa->spa_bootenv == NULL)
		return (ENXIO);

	rv = nvlist_lookup_nvlist(spa->spa_bootenv, OS_NVSTORE, &nv);
	if (rv != 0) {
		return (rv);
	}

	if (type == NULL) {
		nvpair_t *nvp;

		/*
		 * if there is no existing pair, default to string.
		 * Otherwise, use type from existing pair.
		 */
		rv = nvlist_lookup_nvpair(nv, name, &nvp);
		if (rv != 0) {
			dt = DATA_TYPE_STRING;
		} else {
			dt = nvpair_type(nvp);
		}
	} else {
		dt = nvpair_type_from_name(type);
	}

	rv = 0;
	switch (dt) {
	case DATA_TYPE_INT8:
		rv = get_int64(data, &val);
		if (rv == 0) {
			int8_t v = val;

			rv = zfs_nvstore_setter(vdev, dt, name, &v, sizeof (v));
		}
		break;
	case DATA_TYPE_INT16:
		rv = get_int64(data, &val);
		if (rv == 0) {
			int16_t v = val;

			rv = zfs_nvstore_setter(vdev, dt, name, &v, sizeof (v));
		}
		break;
	case DATA_TYPE_INT32:
		rv = get_int64(data, &val);
		if (rv == 0) {
			int32_t v = val;

			rv = zfs_nvstore_setter(vdev, dt, name, &v, sizeof (v));
		}
		break;
	case DATA_TYPE_INT64:
		rv = get_int64(data, &val);
		if (rv == 0) {
			rv = zfs_nvstore_setter(vdev, dt, name, &val,
			    sizeof (val));
		}
		break;

	case DATA_TYPE_BYTE:
		rv = get_uint64(data, &uval);
		if (rv == 0) {
			uint8_t v = uval;

			rv = zfs_nvstore_setter(vdev, dt, name, &v, sizeof (v));
		}
		break;

	case DATA_TYPE_UINT8:
		rv = get_uint64(data, &uval);
		if (rv == 0) {
			uint8_t v = uval;

			rv = zfs_nvstore_setter(vdev, dt, name, &v, sizeof (v));
		}
		break;

	case DATA_TYPE_UINT16:
		rv = get_uint64(data, &uval);
		if (rv == 0) {
			uint16_t v = uval;

			rv = zfs_nvstore_setter(vdev, dt, name, &v, sizeof (v));
		}
		break;

	case DATA_TYPE_UINT32:
		rv = get_uint64(data, &uval);
		if (rv == 0) {
			uint32_t v = uval;

			rv = zfs_nvstore_setter(vdev, dt, name, &v, sizeof (v));
		}
		break;

	case DATA_TYPE_UINT64:
		rv = get_uint64(data, &uval);
		if (rv == 0) {
			rv = zfs_nvstore_setter(vdev, dt, name, &uval,
			    sizeof (uval));
		}
		break;

	case DATA_TYPE_STRING:
		rv = zfs_nvstore_setter(vdev, dt, name, data, strlen(data) + 1);
		break;

	case DATA_TYPE_BOOLEAN_VALUE:
		rv = get_int64(data, &val);
		if (rv == 0) {
			boolean_t v = val;

			rv = zfs_nvstore_setter(vdev, dt, name, &v, sizeof (v));
		}
		break;

	default:
		rv = EINVAL;
	}
	return (rv);
}

static int
zfs_nvstore_unset_impl(void *vdev, const char *name, bool unset_env)
{
	struct zfs_devdesc *dev = (struct zfs_devdesc *)vdev;
	spa_t *spa;
	nvlist_t *nv;
	int rv;

	if (dev->dd.d_dev->dv_type != DEVT_ZFS)
		return (ENOTSUP);

	if ((spa = spa_find_by_dev(dev)) == NULL)
		return (ENXIO);

	if (spa->spa_bootenv == NULL)
		return (ENXIO);

	rv = nvlist_lookup_nvlist(spa->spa_bootenv, OS_NVSTORE, &nv);
	if (rv != 0)
		return (ENOENT);

	rv = nvlist_remove_all(nv, name);
	if (rv == 0) {
		rv = nvlist_add_nvlist(spa->spa_bootenv, OS_NVSTORE, nv);
		if (rv == 0)
			rv = zfs_set_bootenv(vdev, spa->spa_bootenv);
	}

	if (unset_env) {
		struct env_var *ev = env_getenv(name);

		if (ev != NULL)
			env_discard(ev);
	}
	return (rv);
}

static int
zfs_nvstore_unset(void *vdev, const char *name)
{
	return (zfs_nvstore_unset_impl(vdev, name, true));
}

static uint_t
nvpair_nelem(nvpair_t *nvp)
{
	uint_t nelem;
	data_type_t type;
	void *val, **valp;

	type = nvpair_type(nvp);
	switch (type) {
	case DATA_TYPE_BOOLEAN:
	case DATA_TYPE_BOOLEAN_VALUE:
	case DATA_TYPE_BYTE:
	case DATA_TYPE_INT8:
	case DATA_TYPE_UINT8:
	case DATA_TYPE_INT16:
	case DATA_TYPE_UINT16:
	case DATA_TYPE_INT32:
	case DATA_TYPE_UINT32:
	case DATA_TYPE_INT64:
	case DATA_TYPE_UINT64:
	case DATA_TYPE_STRING:
	case DATA_TYPE_NVLIST:
	default:
		nelem = 1;
		break;

	case DATA_TYPE_BOOLEAN_ARRAY:
		(void) nvpair_value_boolean_array(nvp,
		    (boolean_t **)&val, &nelem);
		break;
	case DATA_TYPE_BYTE_ARRAY:
		(void) nvpair_value_byte_array(nvp, (uchar_t **)&val, &nelem);
		break;
	case DATA_TYPE_INT8_ARRAY:
		(void) nvpair_value_int8_array(nvp, (int8_t **)&val, &nelem);
		break;
	case DATA_TYPE_UINT8_ARRAY:
		(void) nvpair_value_uint8_array(nvp, (uint8_t **)&val, &nelem);
		break;
	case DATA_TYPE_INT16_ARRAY:
		(void) nvpair_value_int16_array(nvp, (int16_t **)&val, &nelem);
		break;
	case DATA_TYPE_UINT16_ARRAY:
		(void) nvpair_value_uint16_array(nvp,
		    (uint16_t **)&val, &nelem);
		break;
	case DATA_TYPE_INT32_ARRAY:
		(void) nvpair_value_int32_array(nvp, (int32_t **)&val, &nelem);
		break;
	case DATA_TYPE_UINT32_ARRAY:
		(void) nvpair_value_uint32_array(nvp,
		    (uint32_t **)&val, &nelem);
		break;
	case DATA_TYPE_INT64_ARRAY:
		(void) nvpair_value_int64_array(nvp, (int64_t **)&val, &nelem);
		break;
	case DATA_TYPE_UINT64_ARRAY:
		(void) nvpair_value_uint64_array(nvp,
		    (uint64_t **)&val, &nelem);
		break;
	case DATA_TYPE_STRING_ARRAY:
		(void) nvpair_value_string_array(nvp, (char ***)&valp, &nelem);
		break;
	case DATA_TYPE_NVLIST_ARRAY:
		(void) nvpair_value_nvlist_array(nvp,
		    (nvlist_t ***)&valp, &nelem);
		break;
	}
	return (nelem);
}

static void nvlist_print(nvlist_t *, uint_t);

static void
nvpair_print(nvpair_t *nvp, uint_t indent)
{
	uint_t i, nelem;
	data_type_t type;

	for (i = 0; i < indent; i++)
		printf(" ");

	type = nvpair_type(nvp);
	nelem = nvpair_nelem(nvp);
	printf("%s [%d] %s = ", typenames[nvpair_type(nvp)],
	    nelem, nvpair_name(nvp));

	switch (type) {
	case DATA_TYPE_BOOLEAN:
		printf("TRUE");
		break;
	case DATA_TYPE_BOOLEAN_VALUE: {
		boolean_t val;
		if (nvpair_value_boolean_value(nvp, &val) == 0)
			printf("%s", val? "B_TRUE" : "B_FALSE");
		break;
	}
	case DATA_TYPE_BYTE: {
		uchar_t val;
		if (nvpair_value_byte(nvp, &val) == 0)
			printf("0x%x", val);
		break;
	}
	case DATA_TYPE_INT8: {
		int8_t val;
		if (nvpair_value_int8(nvp, &val) == 0)
			printf("0x%x", val);
		break;
	}
	case DATA_TYPE_UINT8: {
		uint8_t val;
		if (nvpair_value_uint8(nvp, &val) == 0)
			printf("0x%x", val);
		break;
	}
	case DATA_TYPE_INT16: {
		int16_t val;
		if (nvpair_value_int16(nvp, &val) == 0)
			printf("0x%hx", val);
		break;
	}
	case DATA_TYPE_UINT16: {
		uint16_t val;
		if (nvpair_value_uint16(nvp, &val) == 0)
			printf("0x%hx", val);
		break;
	}
	case DATA_TYPE_INT32: {
		int32_t val;
		if (nvpair_value_int32(nvp, &val) == 0)
			printf("0x%x", val);
		break;
	}
	case DATA_TYPE_UINT32: {
		uint32_t val;
		if (nvpair_value_uint32(nvp, &val) == 0)
			printf("0x%x", val);
		break;
	}
	case DATA_TYPE_INT64: {
		int64_t val;
		if (nvpair_value_int64(nvp, &val) == 0)
			printf("0x%jx", (intmax_t)val);
		break;
	}
	case DATA_TYPE_UINT64: {
		uint64_t val;
		if (nvpair_value_uint64(nvp, &val) == 0)
			printf("0x%jx", (uintmax_t)val);
		break;
	}
	case DATA_TYPE_STRING: {
		char *val;
		if (nvpair_value_string(nvp, &val) == 0)
			printf("\"%s\"", val);
		break;
	}
	case DATA_TYPE_NVLIST: {
		nvlist_t *val;
		if (nvpair_value_nvlist(nvp, &val) == 0) {
			printf("\n");
			nvlist_print(val, indent + 2);
		}
		break;
	}
	case DATA_TYPE_BOOLEAN_ARRAY: {
		boolean_t *val;
		if (nvpair_value_boolean_array(nvp, &val, &nelem) == 0) {
			for (i = 0; i < nelem; i++) {
				printf(" [%u] = %s", i,
				    val[i]? "B_TRUE" : "B_FALSE");
			}
		}
		break;
	}
	case DATA_TYPE_BYTE_ARRAY: {
		uchar_t *val;
		if (nvpair_value_byte_array(nvp, &val, &nelem) == 0) {
			for (i = 0; i < nelem; i++) {
				printf(" [%u] = 0x%x", i, val[i]);
			}
		}
		break;
	}
	case DATA_TYPE_INT8_ARRAY: {
		int8_t *val;
		if (nvpair_value_int8_array(nvp, &val, &nelem) == 0) {
			for (i = 0; i < nelem; i++) {
				printf(" [%u] = 0x%x", i, val[i]);
			}
		}
		break;
	}
	case DATA_TYPE_UINT8_ARRAY: {
		uint8_t *val;
		if (nvpair_value_uint8_array(nvp, &val, &nelem) == 0) {
			for (i = 0; i < nelem; i++) {
				printf(" [%u] = 0x%x", i, val[i]);
			}
		}
		break;
	}
	case DATA_TYPE_INT16_ARRAY: {
		int16_t *val;
		if (nvpair_value_int16_array(nvp, &val, &nelem) == 0) {
			for (i = 0; i < nelem; i++) {
				printf(" [%u] = 0x%hx", i, val[i]);
			}
		}
		break;
	}
	case DATA_TYPE_UINT16_ARRAY: {
		uint16_t *val;
		if (nvpair_value_uint16_array(nvp, &val, &nelem) == 0) {
			for (i = 0; i < nelem; i++) {
				printf(" [%u] = 0x%hx", i, val[i]);
			}
		}
		break;
	}
	case DATA_TYPE_INT32_ARRAY: {
		int32_t *val;
		if (nvpair_value_int32_array(nvp, &val, &nelem) == 0) {
			for (i = 0; i < nelem; i++) {
				printf(" [%u] = 0x%x", i, val[i]);
			}
		}
		break;
	}
	case DATA_TYPE_UINT32_ARRAY: {
		uint32_t *val;
		if (nvpair_value_uint32_array(nvp, &val, &nelem) == 0) {
			for (i = 0; i < nelem; i++) {
				printf(" [%u] = 0x%x", i, val[i]);
			}
		}
		break;
	}
	case DATA_TYPE_INT64_ARRAY: {
		int64_t *val;
		if (nvpair_value_int64_array(nvp, &val, &nelem) == 0) {
			for (i = 0; i < nelem; i++) {
				printf(" [%u] = 0x%jx", i, (intmax_t)val[i]);
			}
		}
		break;
	}
	case DATA_TYPE_UINT64_ARRAY: {
		uint64_t *val;
		if (nvpair_value_uint64_array(nvp, &val, &nelem) == 0) {
			for (i = 0; i < nelem; i++) {
				printf(" [%u] = 0x%jx", i, (uintmax_t)val[i]);
			}
		}
		break;
	}
	case DATA_TYPE_STRING_ARRAY: {
		char **val;
		if (nvpair_value_string_array(nvp, &val, &nelem) == 0) {
			for (i = 0; i < nelem; i++) {
				printf(" [%u] = \"%s\"", i, val[i]);
			}
		}
		break;
	}
	case DATA_TYPE_NVLIST_ARRAY: {
		nvlist_t **val;
		if (nvpair_value_nvlist_array(nvp, &val, &nelem) == 0) {
			for (i = 0; i < nelem; i++) {
				nvlist_print(val[i], indent + 2);
			}
		}
		break;
	}
	default:
		printf("unknown type");
	}
	printf("\n");
}

static void
nvlist_print(nvlist_t *nvl, unsigned int indent)
{
	nvpair_t *nvp;

	for (nvp = nvlist_next_nvpair(nvl, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(nvl, nvp)) {
		nvpair_print(nvp, indent);
	}

	printf("%*s\n", indent + 13, "End of nvlist");
}

static int
zfs_nvstore_print(void *vdev __unused, void *ptr)
{

	nvpair_print(ptr, 0);
	return (0);
}

/*
 * Create environment variable from nvpair.
 * set hook will update nvstore with new value, unset hook will remove
 * variable from nvstore.
 */
static int
zfs_nvstore_setenv(void *vdev __unused, void *ptr)
{
	nvpair_t *nvp = ptr;
	char *name, *value;
	int rv = 0;

	if (nvp == NULL)
		return (ENOENT);

	name = nvpair_name(nvp);

	value = NULL;
	switch (nvpair_type(nvp)) {
	case DATA_TYPE_BYTE: {
		uchar_t val;
		rv = nvpair_value_byte(nvp, &val);
		if (rv == 0) {
			(void) asprintf(&value, "%uc", val);
			if (value == NULL)
				rv = ENOMEM;
		}
		break;
	}

	case DATA_TYPE_INT8: {
		int8_t val;
		rv = nvpair_value_int8(nvp, &val);
		if (rv == 0) {
			(void) asprintf(&value, "%c", val);
			if (value == NULL)
				rv = ENOMEM;
		}
		break;
	}

	case DATA_TYPE_UINT8: {
		uint8_t val;
		rv = nvpair_value_uint8(nvp, &val);
		if (rv == 0) {
			(void) asprintf(&value, "%uc", val);
			if (value == NULL)
				rv = ENOMEM;
		}
		break;
	}

	case DATA_TYPE_INT16: {
		int16_t val;
		rv = nvpair_value_int16(nvp, &val);
		if (rv == 0) {
			(void) asprintf(&value, "%hd", val);
			if (value == NULL)
				rv = ENOMEM;
		}
		break;
	}

	case DATA_TYPE_UINT16: {
		uint16_t val;
		rv = nvpair_value_uint16(nvp, &val);
		if (rv == 0) {
			(void) asprintf(&value, "%hu", val);
			if (value == NULL)
				rv = ENOMEM;
		}
		break;
	}

	case DATA_TYPE_BOOLEAN_VALUE: {
		boolean_t val;
		rv = nvpair_value_boolean_value(nvp, &val);
		if (rv == 0) {
			(void) asprintf(&value, "%d", val);
			if (value == NULL)
				rv = ENOMEM;
		}
		break;
	}

	case DATA_TYPE_INT32: {
		int32_t val;
		rv = nvpair_value_int32(nvp, &val);
		if (rv == 0) {
			(void) asprintf(&value, "%d", val);
			if (value == NULL)
				rv = ENOMEM;
		}
		break;
	}

	case DATA_TYPE_UINT32: {
		uint32_t val;
		rv = nvpair_value_uint32(nvp, &val);
		if (rv == 0) {
			(void) asprintf(&value, "%u", val);
			if (value == NULL)
				rv = ENOMEM;
		}
		break;
	}

	case DATA_TYPE_INT64: {
		int64_t val;
		rv = nvpair_value_int64(nvp, &val);
		if (rv == 0) {
			(void) asprintf(&value, "%jd", (intmax_t)val);
			if (value == NULL)
				rv = ENOMEM;
		}
		break;
	}

	case DATA_TYPE_UINT64: {
		uint64_t val;
		rv = nvpair_value_uint64(nvp, &val);
		if (rv == 0) {
			(void) asprintf(&value, "%ju", (uintmax_t)val);
			if (value == NULL)
				rv = ENOMEM;
		}
		break;
	}

	case DATA_TYPE_STRING: {
		char *val;
		rv = nvpair_value_string(nvp, &val);
		if (rv == 0) {
			value = strdup(val);
			if (value == NULL)
				rv = ENOMEM;
			break;
		}
		break;
	}

	default:
		rv = EINVAL;
		break;
	}

	if (value != NULL) {
		rv = env_setenv(name, EV_NOHOOK, value,
		    zfs_nvstore_sethook, zfs_nvstore_unsethook);
	}
	return (rv);
}

static int
zfs_nvstore_iterate(void *vdev, int (*cb)(void *, void *))
{
	struct zfs_devdesc *dev = (struct zfs_devdesc *)vdev;
	spa_t *spa;
	nvlist_t *nv;
	nvpair_t *nvp;
	int rv;

	if (dev->dd.d_dev->dv_type != DEVT_ZFS)
		return (ENOTSUP);

	if ((spa = spa_find_by_dev(dev)) == NULL)
		return (ENXIO);

	if (spa->spa_bootenv == NULL)
		return (ENXIO);

	rv = nvlist_lookup_nvlist(spa->spa_bootenv, OS_NVSTORE, &nv);
	if (rv != 0)
		return (rv);

	nvp = NULL;
	while ((nvp = nvlist_next_nvpair(nv, nvp)) != NULL) {
		rv = cb(vdev, nvp);
		if (rv != 0)
			break;
	}
	return (rv);
}

nvs_callbacks_t nvstore_zfs_cb = {
	.nvs_getter = zfs_nvstore_getter,
	.nvs_setter = zfs_nvstore_setter,
	.nvs_setter_str = zfs_nvstore_setter_str,
	.nvs_unset = zfs_nvstore_unset,
	.nvs_print = zfs_nvstore_print,
	.nvs_iterate = zfs_nvstore_iterate
};

int
zfs_attach_nvstore(void *vdev)
{
	struct zfs_devdesc *dev = vdev;
	spa_t *spa;
	uint64_t version;
	int rv;

	if (dev->dd.d_dev->dv_type != DEVT_ZFS)
		return (ENOTSUP);

	if ((spa = spa_find_by_dev(dev)) == NULL)
		return (ENXIO);

	rv = nvlist_lookup_uint64(spa->spa_bootenv, BOOTENV_VERSION, &version);
	if (rv != 0 || version != VB_NVLIST) {
		return (ENXIO);
	}

	dev = malloc(sizeof (*dev));
	if (dev == NULL)
		return (ENOMEM);
	memcpy(dev, vdev, sizeof (*dev));

	rv = nvstore_init(spa->spa_name, &nvstore_zfs_cb, dev);
	if (rv != 0)
		free(dev);
	else
		rv = zfs_nvstore_iterate(dev, zfs_nvstore_setenv);
	return (rv);
}

int
zfs_probe_dev(const char *devname, uint64_t *pool_guid)
{
	struct disk_devdesc *dev;
	struct ptable *table;
	struct zfs_probe_args pa;
	uint64_t mediasz;
	int ret;

	if (pool_guid)
		*pool_guid = 0;
	pa.fd = open(devname, O_RDWR);
	if (pa.fd == -1)
		return (ENXIO);
	/*
	 * We will not probe the whole disk, we can not boot from such
	 * disks and some systems will misreport the disk sizes and will
	 * hang while accessing the disk.
	 */
	if (archsw.arch_getdev((void **)&dev, devname, NULL) == 0) {
		int partition = dev->d_partition;
		int slice = dev->d_slice;

		free(dev);
		if (partition != D_PARTNONE && slice != D_SLICENONE) {
			ret = zfs_probe(pa.fd, pool_guid);
			if (ret == 0)
				return (0);
		}
	}

	/* Probe each partition */
	ret = ioctl(pa.fd, DIOCGMEDIASIZE, &mediasz);
	if (ret == 0)
		ret = ioctl(pa.fd, DIOCGSECTORSIZE, &pa.secsz);
	if (ret == 0) {
		pa.devname = devname;
		pa.pool_guid = pool_guid;
		table = ptable_open(&pa, mediasz / pa.secsz, pa.secsz,
		    zfs_diskread);
		if (table != NULL) {
			ptable_iterate(table, &pa, zfs_probe_partition);
			ptable_close(table);
		}
	}
	close(pa.fd);
	if (pool_guid && *pool_guid == 0)
		ret = ENXIO;
	return (ret);
}

/*
 * Print information about ZFS pools
 */
static int
zfs_dev_print(int verbose)
{
	spa_t *spa;
	char line[80];
	int ret = 0;

	if (STAILQ_EMPTY(&zfs_pools))
		return (0);

	printf("%s devices:", zfs_dev.dv_name);
	if ((ret = pager_output("\n")) != 0)
		return (ret);

	if (verbose) {
		return (spa_all_status());
	}
	STAILQ_FOREACH(spa, &zfs_pools, spa_link) {
		snprintf(line, sizeof (line), "    zfs:%s\n", spa->spa_name);
		ret = pager_output(line);
		if (ret != 0)
			break;
	}
	return (ret);
}

/*
 * Attempt to open the pool described by (dev) for use by (f).
 */
static int
zfs_dev_open(struct open_file *f, ...)
{
	va_list		args;
	struct zfs_devdesc	*dev;
	struct zfsmount	*mount;
	spa_t		*spa;
	int		rv;

	va_start(args, f);
	dev = va_arg(args, struct zfs_devdesc *);
	va_end(args);

	if ((spa = spa_find_by_dev(dev)) == NULL)
		return (ENXIO);

	mount = malloc(sizeof (*mount));
	if (mount == NULL)
		rv = ENOMEM;
	else
		rv = zfs_mount(spa, dev->root_guid, mount);
	if (rv != 0) {
		free(mount);
		return (rv);
	}
	if (mount->objset.os_type != DMU_OST_ZFS) {
		printf("Unexpected object set type %ju\n",
		    (uintmax_t)mount->objset.os_type);
		free(mount);
		return (EIO);
	}
	f->f_devdata = mount;
	free(dev);
	return (0);
}

static int
zfs_dev_close(struct open_file *f)
{

	free(f->f_devdata);
	f->f_devdata = NULL;
	return (0);
}

static int
zfs_dev_strategy(void *devdata __unused, int rw __unused,
    daddr_t dblk __unused, size_t size __unused,
    char *buf __unused, size_t *rsize __unused)
{

	return (ENOSYS);
}

struct devsw zfs_dev = {
	.dv_name = "zfs",
	.dv_type = DEVT_ZFS,
	.dv_init = zfs_dev_init,
	.dv_strategy = zfs_dev_strategy,
	.dv_open = zfs_dev_open,
	.dv_close = zfs_dev_close,
	.dv_ioctl = noioctl,
	.dv_print = zfs_dev_print,
	.dv_cleanup = NULL
};

int
zfs_parsedev(struct zfs_devdesc *dev, const char *devspec, const char **path)
{
	static char	rootname[ZFS_MAXNAMELEN];
	static char	poolname[ZFS_MAXNAMELEN];
	spa_t		*spa;
	const char	*end;
	const char	*np;
	const char	*sep;
	int		rv;

	np = devspec;
	if (*np != ':')
		return (EINVAL);
	np++;
	end = strrchr(np, ':');
	if (end == NULL)
		return (EINVAL);
	sep = strchr(np, '/');
	if (sep == NULL || sep >= end)
		sep = end;
	memcpy(poolname, np, sep - np);
	poolname[sep - np] = '\0';
	if (sep < end) {
		sep++;
		memcpy(rootname, sep, end - sep);
		rootname[end - sep] = '\0';
	}
	else
		rootname[0] = '\0';

	spa = spa_find_by_name(poolname);
	if (!spa)
		return (ENXIO);
	dev->pool_guid = spa->spa_guid;
	rv = zfs_lookup_dataset(spa, rootname, &dev->root_guid);
	if (rv != 0)
		return (rv);
	if (path != NULL)
		*path = (*end == '\0') ? end : end + 1;
	dev->dd.d_dev = &zfs_dev;
	return (0);
}

char *
zfs_bootfs(void *zdev)
{
	static char		rootname[ZFS_MAXNAMELEN];
	static char		buf[2 * ZFS_MAXNAMELEN];
	struct zfs_devdesc	*dev = (struct zfs_devdesc *)zdev;
	uint64_t		objnum;
	spa_t			*spa;
	int			n;

	buf[0] = '\0';
	if (dev->dd.d_dev->dv_type != DEVT_ZFS)
		return (buf);

	spa = spa_find_by_guid(dev->pool_guid);
	if (spa == NULL) {
		printf("ZFS: can't find pool by guid\n");
		return (buf);
	}
	if (zfs_rlookup(spa, dev->root_guid, rootname)) {
		printf("ZFS: can't find filesystem by guid\n");
		return (buf);
	}
	if (zfs_lookup_dataset(spa, rootname, &objnum)) {
		printf("ZFS: can't find filesystem by name\n");
		return (buf);
	}

	/* Set the environment. */
	snprintf(buf, sizeof (buf), "%" PRIu64, dev->pool_guid);
	setenv("zfs-bootpool", buf, 1);
	snprintf(buf, sizeof (buf), "%" PRIu64, spa->spa_boot_vdev->v_guid);
	setenv("zfs-bootvdev", buf, 1);
	snprintf(buf, sizeof (buf), "%s/%" PRIu64, spa->spa_name, objnum);
	setenv("zfs-bootfs", buf, 1);
	if (spa->spa_boot_vdev->v_phys_path != NULL)
		setenv("bootpath", spa->spa_boot_vdev->v_phys_path, 1);
	if (spa->spa_boot_vdev->v_devid != NULL)
		setenv("diskdevid", spa->spa_boot_vdev->v_devid, 1);

	/*
	 * Build the command line string. Once our kernel will read
	 * the environment and we can stop caring about old kernels,
	 * we can remove this part.
	 */
	snprintf(buf, sizeof (buf), "zfs-bootfs=%s/%" PRIu64, spa->spa_name,
	    objnum);
	n = strlen(buf);
	if (spa->spa_boot_vdev->v_phys_path != NULL) {
		snprintf(buf+n, sizeof (buf) - n, ",bootpath=\"%s\"",
		    spa->spa_boot_vdev->v_phys_path);
		n = strlen(buf);
	}
	if (spa->spa_boot_vdev->v_devid != NULL) {
		snprintf(buf+n, sizeof (buf) - n, ",diskdevid=\"%s\"",
		    spa->spa_boot_vdev->v_devid);
	}
	return (buf);
}

char *
zfs_fmtdev(void *vdev)
{
	static char		rootname[ZFS_MAXNAMELEN];
	static char		buf[2 * ZFS_MAXNAMELEN + 8];
	struct zfs_devdesc	*dev = (struct zfs_devdesc *)vdev;
	spa_t			*spa;

	buf[0] = '\0';
	if (dev->dd.d_dev->dv_type != DEVT_ZFS)
		return (buf);

	/* Do we have any pools? */
	spa = STAILQ_FIRST(&zfs_pools);
	if (spa == NULL)
		return (buf);

	if (dev->pool_guid == 0)
		dev->pool_guid = spa->spa_guid;
	else
		spa = spa_find_by_guid(dev->pool_guid);

	if (spa == NULL) {
		printf("ZFS: can't find pool by guid\n");
		return (buf);
	}
	if (dev->root_guid == 0 && zfs_get_root(spa, &dev->root_guid)) {
		printf("ZFS: can't find root filesystem\n");
		return (buf);
	}
	if (zfs_rlookup(spa, dev->root_guid, rootname)) {
		printf("ZFS: can't find filesystem by guid\n");
		return (buf);
	}

	if (rootname[0] == '\0')
		snprintf(buf, sizeof (buf), "%s:%s:", dev->dd.d_dev->dv_name,
		    spa->spa_name);
	else
		snprintf(buf, sizeof (buf), "%s:%s/%s:", dev->dd.d_dev->dv_name,
		    spa->spa_name, rootname);
	return (buf);
}

int
zfs_list(const char *name)
{
	static char	poolname[ZFS_MAXNAMELEN];
	uint64_t	objid;
	spa_t		*spa;
	const char	*dsname;
	int		len;
	int		rv;

	len = strlen(name);
	dsname = strchr(name, '/');
	if (dsname != NULL) {
		len = dsname - name;
		dsname++;
	} else
		dsname = "";
	memcpy(poolname, name, len);
	poolname[len] = '\0';

	spa = spa_find_by_name(poolname);
	if (!spa)
		return (ENXIO);
	rv = zfs_lookup_dataset(spa, dsname, &objid);
	if (rv != 0)
		return (rv);

	return (zfs_list_dataset(spa, objid));
}
