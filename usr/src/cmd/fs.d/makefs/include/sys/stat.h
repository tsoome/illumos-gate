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

#include <sys/types.h>
#include <sys/timespec.h>

#ifndef _SYS_STAT_H
#define	_SYS_STAT_H

#ifdef __cplusplus
extern "C" {
#endif

#define	_ST_FSTYPSZ 16		/* array size for file system type name */

typedef struct	timespec timestruc_t;

struct stat {
	dev_t		st_dev;
	ino_t		st_ino;
	uint_t		st_mode;
	uint_t		st_nlink;
	uid_t		st_uid;
	gid_t		st_gid;
	dev_t		st_rdev;
	off_t		st_size;
	timestruc_t	st_atim;
	timestruc_t	st_mtim;
	timestruc_t	st_ctim;
	blksize_t	st_blksize;
	blkcnt_t	st_blocks;
	char		st_fstype[_ST_FSTYPSZ];
};

#define	st_atime	st_atim.tv_sec
#define	st_mtime	st_mtim.tv_sec
#define	st_ctime	st_ctim.tv_sec

/* MODE MASKS */

/* de facto standard definitions */

#define	S_IFMT		0xF000	/* type of file */
#define	S_IAMB		0x1FF	/* access mode bits */
#define	S_IFIFO		0x1000	/* fifo */
#define	S_IFCHR		0x2000	/* character special */
#define	S_IFDIR		0x4000	/* directory */
/* XENIX definitions are not relevant to Solaris */
#define	S_IFNAM		0x5000  /* XENIX special named file */
#define	S_INSEM		0x1	/* XENIX semaphore subtype of IFNAM */
#define	S_INSHD		0x2	/* XENIX shared data subtype of IFNAM */
#define	S_IFBLK		0x6000	/* block special */
#define	S_IFREG		0x8000	/* regular */
#define	S_IFLNK		0xA000	/* symbolic link */
#define	S_IFSOCK	0xC000	/* socket */
#define	S_IFDOOR	0xD000	/* door */
#define	S_IFPORT	0xE000	/* event port */
#define	S_ISUID		0x800	/* set user id on execution */
#define	S_ISGID		0x400	/* set group id on execution */
#define	S_ISVTX		0x200	/* save swapped text even after use */
#define	S_IREAD		00400	/* read permission, owner */
#define	S_IWRITE	00200	/* write permission, owner */
#define	S_IEXEC		00100	/* execute/search permission, owner */
#define	S_ENFMT		S_ISGID	/* record locking enforcement flag */

/* the following macros are for POSIX conformance */

#define	S_IRWXU		00700	/* read, write, execute: owner */
#define	S_IRUSR		00400	/* read permission: owner */
#define	S_IWUSR		00200	/* write permission: owner */
#define	S_IXUSR		00100	/* execute permission: owner */
#define	S_IRWXG		00070	/* read, write, execute: group */
#define	S_IRGRP		00040	/* read permission: group */
#define	S_IWGRP		00020	/* write permission: group */
#define	S_IXGRP		00010	/* execute permission: group */
#define	S_IRWXO		00007	/* read, write, execute: other */
#define	S_IROTH		00004	/* read permission: other */
#define	S_IWOTH		00002	/* write permission: other */
#define	S_IXOTH		00001	/* execute permission: other */


#define	S_ISFIFO(mode)	(((mode)&0xF000) == 0x1000)
#define	S_ISCHR(mode)	(((mode)&0xF000) == 0x2000)
#define	S_ISDIR(mode)	(((mode)&0xF000) == 0x4000)
#define	S_ISBLK(mode)	(((mode)&0xF000) == 0x6000)
#define	S_ISREG(mode)	(((mode)&0xF000) == 0x8000)
#define	S_ISLNK(mode)	(((mode)&0xF000) == 0xa000)
#define	S_ISSOCK(mode)	(((mode)&0xF000) == 0xc000)
#define	S_ISDOOR(mode)	(((mode)&0xF000) == 0xd000)
#define	S_ISPORT(mode)	(((mode)&0xF000) == 0xe000)

int     stat(const char * __restrict, struct stat * __restrict);
int     lstat(const char * __restrict, struct stat * __restrict);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_STAT_H */
