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
# Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
# Copyright (c) 2019, Joyent, Inc.
#

LIBMDIR		= $(SRC)/lib/libm

LIBMSRC		= $(LIBMDIR)/common

CPP_CMD		= $(CC) -E -Xs

M4FLAGS		= -D__STDC__ -DPIC

LDBLDIR_sparc	= Q
LDBLDIR_i386	= LD
LDBLDIR		= $(LDBLDIR_$(MACH))

CFLAGS		+= $(C_PICFLAGS)
CFLAGS64	+= $(C_PICFLAGS)
sparc_CFLAGS	+= -Wa,-xarch=v8plus

CPPFLAGS	+= -I$(LIBMSRC)/C \
		-I$(LIBMSRC)/$(LDBLDIR) -I$(LIBMDIR)/$(TARGET_ARCH)/src
$(RELEASE_BUILD)CPPFLAGS += -DNDEBUG

# libm depends on integer overflow characteristics
CFLAGS		+= -_gcc=-fno-strict-overflow
CFLAGS64	+= -_gcc=-fno-strict-overflow

# sparse currently has no _Complex support
CFLAGS		+= -_smatch=off
CFLAGS64	+= -_smatch=off

$(DYNLIB)	:= LDLIBS += -lc


CLEANFILES	+= pics/*.s pics/*.S

FPDEF_amd64	= -DARCH_amd64
FPDEF_sparc	= -DCG89 -DARCH_v8plus -DFPADD_TRAPS_INCOMPLETE_ON_NAN
FPDEF_sparcv9	= -DARCH_v9 -DFPADD_TRAPS_INCOMPLETE_ON_NAN
FPDEF		= $(FPDEF_$(TARGET_ARCH))

ASFLAGS		+= -D_ASM $(FPDEF)
ASFLAGS64	+= -D_ASM $(FPDEF)

XARCH_sparc	= v8plus
XARCH_sparcv9	= v9
XARCH_i386	= f80387
XARCH_amd64	= amd64
XARCH		= $(XARCH_$(TARGET_ARCH))

ASOPT_sparc	= -xarch=$(XARCH) $(AS_PICFLAGS)
ASOPT_sparcv9	= -xarch=$(XARCH) $(AS_PICFLAGS)
ASOPT_i386	=
ASOPT_amd64	= -xarch=$(XARCH) $(AS_PICFLAGS)
ASOPT		= $(ASOPT_$(TARGET_ARCH))

ASFLAGS		+= $(ASOPT)
ASFLAGS64	+= $(ASOPT)

CPPFLAGS_sparc = -DFPADD_TRAPS_INCOMPLETE_ON_NAN \
	-DFDTOS_TRAPS_INCOMPLETE_IN_FNS_MODE

CPPFLAGS	+= $(CPPFLAGS_$(MACH))
ASFLAGS		+= $(CPPFLAGS)
ASFLAGS64	+= $(CPPFLAGS)
