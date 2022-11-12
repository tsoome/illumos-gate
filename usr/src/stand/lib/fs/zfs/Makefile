#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2017 Hayashi Naoyuki
#

LIBRARY = libzfs.a
OBJECTS = \
	  zfs.o \
	  lz4.o \
	  inflate.o \
	  crc32.o \
	  zutil.o \
	  inffast.o \
	  inftrees.o \
	  zutil.o \
	  adler32.o

include	../Makefile.com

CPPFLAGS += -I.
CPPFLAGS += -I$(SRC)/stand/lib/sa
CPPFLAGS += -I$(SRC)/contrib/zlib/
CPPFLAGS += -I$(SRC)/boot/sys/cddl/boot/zfs
CPPFLAGS += -I$(SRC)/boot/libsa/zfs/
CPPFLAGS += -I$(SRC)/common/lz4/
CPPFLAGS += -I$(SRC)/common/crypto/edonr/
CPPFLAGS += -I$(SRC)/common/crypto/skein/
CPPFLAGS += -I$(SRC)/common/list/
CPPFLAGS += -I$(ROOT)/usr/include
CPPFLAGS += -I$(SRC)/uts/common/fs/zfs
CERRWARN += -_gcc=-Wno-unused-function

include ../../Makefile.targ

objs/zfs.o := CPPFLAGS +=	-I$(SRC)/uts/common/fs/zfs

objs/%.o: $(SRC)/contrib/zlib/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

objs/%.o: $(SRC)/common/lz4/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
