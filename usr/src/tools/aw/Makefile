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

SUBDIRS=	aarch64 i386 sparc

install	:= TARGET = install
all	:= TARGET = all
lint	:= TARGET = lint
clobber	:= TARGET = clobber
clean	:= TARGET = clean
check	:= TARGET = check

install all clean clobber check lint: $(SUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) TARG_MACH=$@ $(TARGET)

FRC:

include ../Makefile.tools

install: $(ROOTONBLDMAN1FILES) $(ROOTONBLDBINMACH)/aw

$(ROOTONBLDBINMACH)/aw: FRC
	$(RM) $@; $(SYMLINK) aw.$(NATIVE_MACH) $@

include ../Makefile.targ
