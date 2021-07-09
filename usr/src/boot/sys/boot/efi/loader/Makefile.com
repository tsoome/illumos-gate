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
# Copyright 2016 Toomas Soome <tsoome@me.com>
#

include $(SRC)/boot/Makefile.version
include $(SRC)/boot/sys/boot/Makefile.inc

PROG=		loader.sym

# architecture-specific loader code
SRCS=	\
	acpi.c \
	autoload.c \
	bootinfo.c \
	conf.c \
	copy.c \
	efi_main.c \
	font.c \
	$(FONT).c \
	framebuffer.c \
	main.c \
	memmap.c \
	mb_header.S \
	multiboot2.c \
	nvstore.c \
	self_reloc.c \
	smbios.c \
	tem.c \
	vers.c

OBJS=	\
	acpi.o \
	autoload.o \
	bootinfo.o \
	conf.o \
	copy.o \
	efi_main.o \
	font.o \
	$(FONT).o \
	framebuffer.o \
	main.o \
	memmap.o \
	mb_header.o \
	multiboot2.o \
	nvstore.o \
	self_reloc.o \
	smbios.o \
	tem.o \
	vers.o

module.o := CPPFLAGS += -I$(CRYPTOSRC)
tem.o := CPPFLAGS += $(DEFAULT_CONSOLE_COLOR)
main.o := CPPFLAGS += -I$(SRC)/uts/common/fs/zfs

CPPFLAGS += -I../../../../../include -I../../..../
CPPFLAGS += -I../../../../../lib/libstand

include ../../Makefile.inc

include ../arch/$(MACHINE)/Makefile.inc

CPPFLAGS +=	-I. -I..
CPPFLAGS +=	-I../../include
CPPFLAGS +=	-I../../include/$(MACHINE)
CPPFLAGS +=	-I../../../..
CPPFLAGS +=	-I../../../i386/libi386
CPPFLAGS +=	-I$(ZFSSRC)
CPPFLAGS +=	-I../../../../cddl/boot/zfs
CPPFLAGS +=	-I$(SRC)/uts/intel/sys/acpi
CPPFLAGS +=	-I$(PNGLITE)
CPPFLAGS +=	-DNO_PCI -DEFI

# Export serial numbers, UUID, and asset tag from loader.
smbios.o := CPPFLAGS += -DSMBIOS_SERIAL_NUMBERS
# Use little-endian UUID format as defined in SMBIOS 2.6.
smbios.o := CPPFLAGS += -DSMBIOS_LITTLE_ENDIAN_UUID
# Use network-endian UUID format for backward compatibility.
#CPPFLAGS += -DSMBIOS_NETWORK_ENDIAN_UUID

DPLIBSTAND=	../../../libstand/$(MACHINE)/libstand_pics.a
LIBSTAND=	-L../../../libstand/$(MACHINE) -lstand_pics

BOOT_FORTH=	yes
CPPFLAGS +=	-DBOOT_FORTH
CPPFLAGS +=	-I$(SRC)/common/ficl
CPPFLAGS +=	-I../../../libficl
DPLIBFICL=	../../../libficl/$(MACHINE)/libficl_pics.a
LIBFICL=	-L../../../libficl/$(MACHINE) -lficl_pics

# Always add MI sources
#
SRCS +=	boot.c commands.c console.c devopen.c interp.c
SRCS +=	interp_backslash.c interp_parse.c ls.c misc.c
SRCS +=	module.c linenoise.c zfs_cmd.c

OBJS += boot.o commands.o console.o devopen.o interp.o \
	interp_backslash.o interp_parse.o ls.o misc.o \
	module.o linenoise.o zfs_cmd.o

SRCS +=	load_elf32.c load_elf32_obj.c reloc_elf32.c
SRCS +=	load_elf64.c load_elf64_obj.c reloc_elf64.c

OBJS += load_elf32.o load_elf32_obj.o reloc_elf32.o \
	load_elf64.o load_elf64_obj.o reloc_elf64.o

SRCS +=	disk.c part.c dev_net.c vdisk.c
OBJS += disk.o part.o dev_net.o vdisk.o
CPPFLAGS += -DLOADER_DISK_SUPPORT
CPPFLAGS += -DLOADER_GPT_SUPPORT
CPPFLAGS += -DLOADER_MBR_SUPPORT

part.o := CPPFLAGS += -I$(ZLIB)

SRCS +=  bcache.c
OBJS +=  bcache.o

# Forth interpreter
SRCS +=	interp_forth.c
OBJS +=	interp_forth.o
CPPFLAGS +=	-I../../../common

# For multiboot2.h, must be last, to avoid conflicts
CPPFLAGS +=	-I$(SRC)/uts/common

FILES=		$(EFIPROG)
FILEMODE=	0555
ROOT_BOOT=	$(ROOT)/boot
ROOTBOOTFILES=$(FILES:%=$(ROOT_BOOT)/%)

LDSCRIPT=	../arch/$(MACHINE)/ldscript.$(MACHINE)
LDFLAGS =	-nostdlib --eh-frame-hdr
LDFLAGS +=	-shared --hash-style=both --enable-new-dtags
LDFLAGS +=	-T$(LDSCRIPT) -Bsymbolic

CLEANFILES=	$(EFIPROG) loader.sym loader.bin
CLEANFILES +=	$(FONT).c vers.c

NEWVERSWHAT=	"EFI loader" $(MACHINE)

install: all $(ROOTBOOTFILES)

vers.c:	../../../common/newvers.sh $(SRC)/boot/Makefile.version
	$(SH) ../../../common/newvers.sh $(LOADER_VERSION) $(NEWVERSWHAT)

$(EFIPROG): loader.bin
	$(BTXLD) -V $(BOOT_VERSION) -o $@ loader.bin

loader.bin: loader.sym
	if [ `$(OBJDUMP) -t loader.sym | fgrep '*UND*' | wc -l` != 0 ]; then \
		$(OBJDUMP) -t loader.sym | fgrep '*UND*'; \
		exit 1; \
	fi
	$(OBJCOPY) --readonly-text -j .peheader -j .text -j .sdata -j .data \
		-j .dynamic -j .dynsym -j .rel.dyn \
		-j .rela.dyn -j .reloc -j .eh_frame -j set_Xcommand_set \
		-j set_Xficl_compile_set \
		--output-target=$(EFI_TARGET) --subsystem efi-app loader.sym $@

DPLIBEFI=	../../libefi/$(MACHINE)/libefi.a
LIBEFI=		-L../../libefi/$(MACHINE) -lefi

DPADD=		$(DPLIBFICL) $(DPLIBEFI) $(DPLIBSTAND) $(LDSCRIPT)
LDADD=		$(LIBFICL) $(LIBEFI) $(LIBSTAND)

loader.sym:	$(OBJS) $(DPADD)
	$(LD) $(LDFLAGS) -o $@ $(OBJS) $(LDADD)

machine:
	$(RM) machine
	$(SYMLINK) ../../../../$(MACHINE)/include machine

x86:
	$(RM) x86
	$(SYMLINK) ../../../../x86/include x86

clean clobber:
	$(RM) $(CLEANFILES) $(OBJS) machine x86

%.o:	../%.c
	$(COMPILE.c) $<

%.o:	../arch/$(MACHINE)/%.c
	$(COMPILE.c) $<

#
# using -W to silence gas here, as for 32bit build, it will generate warning
# for start.S because hand crafted .reloc section does not have group name
#
%.o:	../arch/$(MACHINE)/%.S
	$(COMPILE.S) -Wa,-W $<

%.o:	../../../common/%.S
	$(COMPILE.S) $<

%.o:	../../../common/%.c
	$(COMPILE.c) $<

%.o:	../../../common/linenoise/%.c
	$(COMPILE.c) $<

%.o: $(SRC)/common/font/%.c
	$(COMPILE.c) $<

$(FONT).c: $(FONT_DIR)/$(FONT_SRC)
	$(VTFONTCVT) -f compressed-source -o $@ $(FONT_DIR)/$(FONT_SRC)

$(ROOT_BOOT)/%: %
	$(INS.file)
