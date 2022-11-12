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

all: $(SUBDIRS) $(MAN1ONBLDFILES)

clean clobber check lint: $(SUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) TARG_MACH=$@ $(TARGET)

FRC:

MAN1ONBLDFILES=	cw.1onbld

include ../Makefile.tools

# Assume we don't have the install.bin available yet
INS.file=	$(RM) $@; $(CP) $< $(@D); $(CHMOD) $(FILEMODE) $@

$(ROOTONBLDMAN1ONBLDFILES) := FILEMODE= 644

install: $(SUBDIRS) .WAIT $(ROOTONBLDMAN1ONBLDFILES) $(ROOTONBLDBINMACH)/cw

$(ROOTONBLDBINMACH)/cw: FRC
	$(RM) $@; $(SYMLINK) cw.$(NATIVE_MACH) $@

#
# Not run by default: bootstrap...
check:
	$(ROOTONBLDBINMACH)/mandoc -Tlint -Wwarning $(MAN1ONBLDFILES)

include ../Makefile.targ
