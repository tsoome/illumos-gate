#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2021 Toomas Soome <tsoome@me.com>
#

ZFS_OBJ =	abd.o
ZFS_OBJ +=	blkptr.o
ZFS_OBJ +=	dmu.o
ZFS_OBJ +=	edonr_zfs.o
ZFS_OBJ +=	skein_zfs.o
ZFS_OBJ +=	sha256.o
ZFS_OBJ +=	zfs_fletcher.o
ZFS_OBJ +=	zfs_fletcher_superscalar4.o
ZFS_OBJ +=	gzip.o
ZFS_OBJ +=	lzjb.o
ZFS_OBJ +=	lz4_zfs.o
ZFS_OBJ +=	zle.o
ZFS_OBJ +=	list.o
ZFS_OBJ +=	nvlist.o
ZFS_OBJ +=	nvlist_print.o
ZFS_OBJ +=	spa_misc.o
ZFS_OBJ +=	uberblock.o
ZFS_OBJ +=	vdev.o
ZFS_OBJ +=	vdev_disk.o
ZFS_OBJ +=	vdev_label.o
ZFS_OBJ +=	vdev_missing.o
ZFS_OBJ +=	vdev_indirect.o
ZFS_OBJ +=	vdev_raidz.o
ZFS_OBJ +=	vdev_raidz_math_scalar.o
ZFS_OBJ +=	zio.o
ZFS_OBJ +=	zio_checksum.o
ZFS_OBJ +=	zio_compress.o
ZFS_OBJ +=	zfs.o

OBJECTS +=	$(ZFS_OBJ)
OBJS = $(ZFS_OBJ:%.o=objs/%.o) $(ZFS_OBJ:%.o=pics/%.o)

$(OBJS) := CPPFLAGS += -I$(ZFSSRC) -I$(BOOTSRC)/common
$(OBJS) := CPPFLAGS += -I$(SRC)/uts/common -I$(SRC)/uts/common/fs/zfs

objs/lz4_zfs.o pics/lz4_zfs.o := CPPFLAGS += -I$(LZ4)

objs/zfs.o pics/zfs.o := CPPFLAGS += -I$(LZ4)
objs/zfs.o pics/zfs.o := CPPFLAGS += -I$(CRYPTOSRC)

pics/%.o objs/%.o:	$(ZFSSRC)/%.c
	$(COMPILE.c) -o $@ $<

pics/%.o objs/%.o:	$(SRC)/common/list/%.c
	$(COMPILE.c) -DNDEBUG -o $@ $<

zfs.o: $(ZFSSRC)/zfsimpl.c
