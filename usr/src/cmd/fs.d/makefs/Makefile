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
# Copyright 2025 Edgecast Cloud LLC
#

PROG =	makefs

ZFSOBJS = \
	zfs/dsl.o \
	zfs/fs.o \
	zfs/objset.o \
	zfs/vdev.o \
	zfs/zap.o \
	zfs/nvlist.o \
	zfs.o

OBJS =	\
	$(ZFSOBJS) \
	libnetbsd/efun.o \
	libnetbsd/strsuftoll.o \
	makefs.o \
	walk.o \
	bsd.o

include ../../Makefile.cmd
include ../../Makefile.cmd.64
include ../../Makefile.ctf

CSTD =	$(CSTD_GNU99)

all: $(PROG)
install: all

CPPFLAGS.first += -I./include -Ilibnetbsd
CPPFLAGS.first += -I$(SRC)/boot/include -I$(SRC)/boot/sys
CPPFLAGS += -DDEFAULT_FSTYPE=\"zfs\" -Ilibutil -I.

$(ZFSOBJS) := CPPFLAGS += -Izfs -I$(SRC)/boot/libsa -I$(SRC)/boot/sys/cddl/boot

bsd.o := CPPFLAGS.first =

LDLIBS += -lc

$(OBJS):	machine x86
CLOBBERFILES += machine x86

$(PROG): $(OBJS) 
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

zfs/%.o:	zfs/%.c
	$(COMPILE.c) $< -o $@
	$(POST_PROCESS_O)

zfs/%.o:	$(SRC)/boot/libsa/zfs/%.c
	$(COMPILE.c) $< -o $@
	$(POST_PROCESS_O)

libnetbsd/%.o:	libnetbsd/%.c
	$(COMPILE.c) $< -o $@
	$(POST_PROCESS_O)

mtree/%.o:	mtree/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

machine:
	$(RM) machine
	$(SYMLINK) ../../../boot/sys/$(MACH64)/include machine

x86:
	$(RM) x86
	$(SYMLINK) ../../../boot/sys/x86/include x86

clean:
	$(RM) $(OBJS)

include ../../Makefile.targ
