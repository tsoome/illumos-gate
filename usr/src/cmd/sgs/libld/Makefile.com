#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2019 Joyent, Inc.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.

LIBRARY =	libld.a
VERS =		.4

COMOBJS =	debug.o		globals.o	util.o

COMOBJS32 =	args_32.o		\
		entry_32.o		\
		exit_32.o		\
		groups_32.o		\
		ldentry_32.o		\
		ldlibs_32.o		\
		ldmachdep_32.o		\
		ldmain_32.o		\
		libs_32.o		\
		files_32.o		\
		map_32.o		\
		map_core_32.o		\
		map_support_32.o	\
		map_v2_32.o		\
		order_32.o		\
		outfile_32.o		\
		place_32.o		\
		relocate_32.o		\
		resolve_32.o		\
		sections_32.o		\
		sunwmove_32.o		\
		support_32.o		\
		syms_32.o		\
		update_32.o		\
		unwind_32.o		\
		version_32.o		\
		wrap_32.o

COMOBJS64 =	args_64.o		\
		entry_64.o		\
		exit_64.o		\
		groups_64.o		\
		ldentry_64.o		\
		ldlibs_64.o		\
		ldmachdep_64.o		\
		ldmain_64.o		\
		libs_64.o		\
		files_64.o		\
		map_64.o		\
		map_core_64.o		\
		map_support_64.o	\
		map_v2_64.o		\
		order_64.o		\
		outfile_64.o		\
		place_64.o		\
		relocate_64.o		\
		resolve_64.o		\
		sections_64.o		\
		sunwmove_64.o		\
		support_64.o		\
		syms_64.o		\
		update_64.o		\
		unwind_64.o		\
		version_64.o		\
		wrap_64.o

SGSCOMMONOBJ =	alist.o		\
		assfail.o	\
		findprime.o	\
		string_table.o	\
		strhash.o

AVLOBJ =	avl.o

# Relocation engine objects.
G_MACHOBJS32 =	doreloc_sparc_32.o doreloc_x86_32.o
G_MACHOBJS64 =	doreloc_sparc_64.o doreloc_x86_64.o doreloc_aarch64_64.o

# Target specific objects (sparc/sparcv9)
L_SPARC_MACHOBJS32 =	machrel.sparc_32.o	machsym.sparc_32.o
L_SPARC_MACHOBJS64 =	machrel.sparc_64.o	machsym.sparc_64.o

# Target specific objects (i386/amd64)
E_X86_COMMONOBJ =	leb128.o
L_X86_MACHOBJS32 =	machrel.intel_32.o
L_X86_MACHOBJS64 =	machrel.amd_64.o

# Target specific objects (aarch64)
L_AARCH64_MACHOBJS64 = machrel.aarch64_64.o

# All target specific objects rolled together
E_COMMONOBJ =	$(E_SPARC_COMMONOBJ) \
	$(E_X86_COMMONOBJ)
L_MACHOBJS32 =	$(L_SPARC_MACHOBJS32) \
	$(L_X86_MACHOBJS32)
L_MACHOBJS64 =	$(L_AARCH64_MACHOBJS64) $(L_SPARC_MACHOBJS64) \
	$(L_X86_MACHOBJS64)


BLTOBJ =	msg.o
ELFCAPOBJ =	elfcap.o

OBJECTS =	$(BLTOBJ) $(G_MACHOBJS32) $(G_MACHOBJS64) \
		$(L_MACHOBJS32) $(L_MACHOBJS64) \
		$(COMOBJS) $(COMOBJS32) $(COMOBJS64) \
		$(SGSCOMMONOBJ) $(E_COMMONOBJ) $(AVLOBJ) $(ELFCAPOBJ)

include		$(SRC)/lib/Makefile.lib
include		$(SRC)/cmd/sgs/Makefile.com

SRCDIR =	$(SGSHOME)/libld
MAPFILEDIR =	$(SRCDIR)/common

CERRWARN += -_gcc=-Wno-unused-value
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += $(CNOWARN_UNINIT)
CERRWARN += -_gcc=-Wno-switch
CERRWARN += -_gcc=-Wno-char-subscripts
CERRWARN += -_gcc=-Wno-type-limits
$(RELEASE_BUILD)CERRWARN += -_gcc=-Wno-unused

SMOFF += no_if_block

# Location of the shared relocation engines maintained under usr/src/uts.
#
KRTLD_AARCH64 = $(SRC)/uts/aarch64/krtld
KRTLD_I386 = $(SRC)/uts/intel/ia32/krtld
KRTLD_AMD64 = $(SRC)/uts/intel/amd64/krtld
KRTLD_SPARC = $(SRC)/uts/sparc/krtld


CPPFLAGS +=	-DUSE_LIBLD_MALLOC -I$(SRC)/lib/libc/inc \
		    -I$(SRC)/uts/common/krtld -I$(SRC)/uts/sparc \
		    -I $(SRC)/uts/common
LDLIBS +=	$(CONVLIBDIR) -lconv $(LDDBGLIBDIR) -llddbg \
		    $(ELFLIBDIR) -lelf $(DLLIB) -lc

DYNFLAGS +=	$(VERSREF) -Wl,-R'$$ORIGIN'

# too hairy
pics/sections_32.o :=	SMATCH=off
pics/sections_64.o :=	SMATCH=off
# confused about our strange allocation choices
pics/syms_32.o :=	SMOFF += check_kmalloc_wrong_size
pics/syms_64.o :=	SMOFF += check_kmalloc_wrong_size
pics/entry_32.o :=	SMOFF += check_kmalloc_wrong_size
pics/entry_64.o :=	SMOFF += check_kmalloc_wrong_size
pics/relocate_32.o :=	SMOFF += check_kmalloc_wrong_size
pics/relocate_64.o :=	SMOFF += check_kmalloc_wrong_size

BLTDEFS =	msg.h
BLTDATA =	msg.c
BLTMESG =	$(SGSMSGDIR)/libld

BLTFILES =	$(BLTDEFS) $(BLTDATA) $(BLTMESG)

# Due to cross linking support, every copy of libld contains every message.
# However, we keep target specific messages in their own separate files for
# organizational reasons.
#
SGSMSGCOM =	$(SRCDIR)/common/libld.msg
SGSMSGAARCH64 =	$(SRCDIR)/common/libld.aarch64.msg
SGSMSGINTEL =	$(SRCDIR)/common/libld.intel.msg
SGSMSGSPARC =	$(SRCDIR)/common/libld.sparc.msg
SGSMSGTARG =	$(SGSMSGCOM) $(SGSMSGAARCH64) $(SGSMSGINTEL) $(SGSMSGSPARC)
SGSMSGALL =	$(SGSMSGCOM) $(SGSMSGAARCH64) $(SGSMSGINTEL) $(SGSMSGSPARC)

SGSMSGFLAGS1 =	$(SGSMSGFLAGS) -m $(BLTMESG)
SGSMSGFLAGS2 =	$(SGSMSGFLAGS) -h $(BLTDEFS) -d $(BLTDATA) -n libld_msg

CHKSRCS =	$(SRC)/uts/common/krtld/reloc.h \
		$(COMOBJS32:%_32.o=$(SRCDIR)/common/%.c) \
		$(L_MACHOBJS32:%_32.o=$(SRCDIR)/common/%.c) \
		$(L_MACHOBJS64:%_64.o=$(SRCDIR)/common/%.c) \
		$(KRTLD_AARCH64)/doreloc.c \
		$(KRTLD_I386)/doreloc.c \
		$(KRTLD_AMD64)/doreloc.c \
		$(KRTLD_SPARC)/doreloc.c

LIBSRCS =	$(SGSCOMMONOBJ:%.o=$(SGSCOMMON)/%.c) \
		$(SGSCOMMONOBJ:%.o=$(SGSCOMMON)/%.c) \
		$(COMOBJS:%.o=$(SRCDIR)/common/%.c) \
		$(AVLOBJS:%.o=$(SRC)/common/avl/%.c) \
		$(BLTDATA)

CLEANFILES +=	$(BLTFILES)
CLOBBERFILES +=	$(DYNLIB) $(LIBLINKS)

ROOTFS_DYNLIB =	$(DYNLIB:%=$(ROOTFS_LIBDIR)/%)
