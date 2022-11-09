#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2011, Richard Lowe.
#
# Copyright (c) 2018, Joyent, Inc.

include ../../Makefile.ctf

LIBRARY=	libdwarf.a
VERS=		.1

OBJECTS=dwarf_abbrev.o		\
	dwarf_alloc.o		\
	dwarf_arange.o		\
	dwarf_debuglink.o	\
	dwarf_die_deliv.o	\
	dwarf_dnames.o		\
	dwarf_dsc.o		\
	dwarf_elf_access.o	\
	dwarf_elf_load_headers.o \
	dwarf_elf_rel_detector.o \
	dwarf_elfread.o		\
	dwarf_error.o		\
	dwarf_form.o		\
	dwarf_frame.o		\
	dwarf_frame2.o		\
	dwarf_funcs.o		\
	dwarf_gdbindex.o	\
	dwarf_generic_init.o	\
	dwarf_global.o		\
	dwarf_groups.o		\
	dwarf_harmless.o	\
	dwarf_init_finish.o	\
	dwarf_leb.o		\
	dwarf_line.o		\
	dwarf_loc.o		\
	dwarf_locationop_read.o \
	dwarf_loclists.o	\
	dwarf_machoread.o	\
	dwarf_macro.o		\
	dwarf_macro5.o		\
	dwarf_names.o		\
	dwarf_object_detector.o	\
	dwarf_object_read_common.o \
	dwarf_original_elf_init.o	\
	dwarf_peread.o		\
	dwarf_print_lines.o	\
	dwarf_pubtypes.o	\
	dwarf_query.o		\
	dwarf_ranges.o		\
	dwarf_rnglists.o	\
	dwarf_str_offsets.o	\
	dwarf_stringsection.o	\
	dwarf_stubs.o		\
	dwarf_tied.o		\
	dwarf_tsearchhash.o	\
	dwarf_types.o		\
	dwarf_util.o		\
	dwarf_vars.o		\
	dwarf_weaks.o		\
	dwarf_xu_index.o	\
	dwarfstring.o		\
	dwgetopt.o		\
	gennames.o		\
	malloc_check.o		\
	pro_alloc.o		\
	pro_arange.o		\
	pro_die.o		\
	pro_dnames.o		\
	pro_encode_nm.o		\
	pro_error.o		\
	pro_expr.o		\
	pro_finish.o		\
	pro_forms.o		\
	pro_frame.o		\
	pro_funcs.o		\
	pro_init.o		\
	pro_line.o		\
	pro_log_extra_flag_strings.o \
	pro_macinfo.o		\
	pro_pubnames.o		\
	pro_reloc_stream.o	\
	pro_reloc_symbolic.o	\
	pro_reloc.o		\
	pro_section.o		\
	pro_types.o		\
	pro_vars.o		\
	pro_weaks.o

include $(SRC)/lib/Makefile.lib
include $(SRC)/tools/Makefile.tools

FILEMODE =	0755
SRCDIR =	$(SRC)/lib/libdwarf/common/
SRCS =		$(PICS:%.o=$(SRCDIR)/%.c)

CPPFLAGS +=	-I$(SRCDIR) -DELF_TARGET_ALL=1
CERRWARN +=	-_gcc=-Wno-unused -_clang=-Wno-unused
CERRWARN +=	-_gcc=-Wno-implicit-function-declaration

# libdwarf not clean
SMATCH=off

DYNFLAGS += '-R$$ORIGIN/../../lib/$(MACH)'
LDLIBS = -lelf -lc -lz
NATIVE_LIBS += libelf.so libc.so libz.so

.KEEP_STATE:
.PARALLEL:

all:	$(DYNLIB)

install: all $(ROOTONBLDLIBMACH)/libdwarf.so.1 $(ROOTONBLDLIBMACH)/libdwarf.so

$(ROOTONBLDLIBMACH)/%: %
	$(INS.file)

$(ROOTONBLDLIBMACH)/$(LIBLINKS): $(ROOTONBLDLIBMACH)/$(LIBLINKS)$(VERS)
	$(INS.liblink)

FRC:

# We can't provide CTF information for libdwarf, as the CTF tools themselves
# depond upon it, and so aren't built yet.
$(DYNLIB) := CTFMERGE_POST= :
CTFCONVERT_O= :

include $(SRC)/lib/Makefile.targ
