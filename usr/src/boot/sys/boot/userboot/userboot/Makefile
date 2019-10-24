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
# Copyright 2019 Toomas Soome <tsoome@me.com>
#

include $(SRC)/Makefile.master
include $(SRC)/boot/Makefile.version
include $(SRC)/boot/sys/boot/Makefile.inc

LIBRARY=	userboot.a
LIBDIR=		/boot

OBJS_SHARED=	autoload.o
OBJS_SHARED +=	biossmap.o
OBJS_SHARED +=	bootinfo.o
OBJS_SHARED +=	bootinfo32.o
OBJS_SHARED +=	bootinfo64.o
OBJS_SHARED +=	conf.o
OBJS_SHARED +=	copy.o
OBJS_SHARED +=	devicename.o
OBJS_SHARED +=	elf32_freebsd.o
OBJS_SHARED +=	elf64_freebsd.o
OBJS_SHARED +=	host.o
OBJS_SHARED +=	main.o
OBJS_SHARED +=	userboot_cons.o
OBJS_SHARED +=	userboot_disk.o
OBJS_SHARED +=	userboot_gfx.o
OBJS_SHARED +=	vers.o

OBJS_COMMON=	bcache.o
OBJS_COMMON +=	boot.o
OBJS_COMMON +=	commands.o
OBJS_COMMON +=	console.o
OBJS_COMMON +=	devopen.o
OBJS_COMMON +=	disk.o
OBJS_COMMON +=	interp.o
OBJS_COMMON +=	interp_backslash.o
OBJS_COMMON +=	interp_forth.o
OBJS_COMMON +=	interp_parse.o
OBJS_COMMON +=	ls.o
OBJS_COMMON +=	misc.o
OBJS_COMMON +=	module.o
OBJS_COMMON +=	part.o
OBJS_COMMON +=	vdisk.o
OBJS_COMMON +=	zfs_cmd.o
OBJS_COMMON +=	load_elf32.o
OBJS_COMMON +=	load_elf32_obj.o
OBJS_COMMON +=	reloc_elf32.o
OBJS_COMMON +=	load_elf64.o
OBJS_COMMON +=	load_elf64_obj.o
OBJS_COMMON +=	reloc_elf64.o

OBJS_LINENOISE=	linenoise.o

OBJECTS= $(OBJS_COMMON) $(OBJS_SHARED) $(OBJS_LINENOISE)

SRCS=		$(OBJS_SHARED:%.o=%.c) \
		$(OBJS_COMMON:%.o=../../common/%.c) \
		$(OBJS_LINENOISE:%.o=../../common/linenoise/%.c)

include $(SRC)/lib/Makefile.lib

CSTD=		$(CSTD_GNU99)
C99LMODE=	-Xc99=%all

LIBS=		$(DYNLIB)
SRCDIR=		.
CFLAGS +=	$(CCVERBOSE)
CPPFLAGS=	-D_STANDALONE -DLOADER_MBR_SUPPORT -DLOADER_GPT_SUPPORT
CPPFLAGS +=	-DUSER_MALLOC
CPPFLAGS +=	-I$(SRC)/boot/include -I$(SRC)/boot/sys
CPPFLAGS +=	-I$(SRC)/boot/lib/libstand
CPPFLAGS +=	-I$(SRC)/boot/lib/libstand/zfs
CPPFLAGS +=	-I$(BOOTSRC)/libcrypto
CPPFLAGS +=	-I$(BOOTSRC)/common
CPPFLAGS +=	-DBOOT_FORTH -I$(SRC)/common/ficl -I../../libficl
CPPFLAGS +=	-I$(SRC)/common/pnglite
CPPFLAGS +=	-I..
CPPFLAGS +=	-I. -I$(SRC)/uts/common

NEWVERSWHAT=	"User boot 4th" $(MACHINE_CPUARCH)
VERSION_FILE=	version

MACHINE=	$(MACH)

CLEANFILES=	vers.c machine x86

LDLIBS +=	-L../../libficl/i386 -lficl --start-group -L../../libcrypto/i386 -lcrypto -L../libstand -lstand --end-group

BUILD.SO= $(GNU_ROOT)/bin/gld -G -Bsymbolic -o userboot.so $(PICS) $(LDLIBS)

$(LIBS):	../../libficl/i386/libficl.a ../../libcrypto/i386/libcrypto.a \
	../libstand/libstand.a

all:	$(LIBS)

$(PICS): machine x86

machine:
	$(RM) machine
	$(SYMLINK) ../../../${MACHINE}/include machine

x86:
	$(RM) x86
	$(SYMLINK) ../../../x86/include x86

pics/part.o := CPPFLAGS += -I$(ZLIB)

vers.c: ../../common/newvers.sh $(SRC)/boot/Makefile.version
	$(SH) ../../common/newvers.sh $(LOADER_VERSION) $(NEWVERSWHAT)

pics/%.o:	../../common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	../../common/linenoise/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include $(SRC)/lib/Makefile.targ
