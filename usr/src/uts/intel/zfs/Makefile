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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#	This makefile drives the production of the zfs file system
#	kernel module.
#
# Copyright 2013 Saso Kiselkov. All rights reserved.
#
# Copyright (c) 2016 by Delphix. All rights reserved.
#
# Copyright 2019 Joyent, Inc.

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

ARCHDIR:sh = cd ..; basename `pwd`

#
#	Define the module and object file sets.
#
MODULE		= zfs
OBJECTS		= $(ZFS_OBJS:%=$(OBJS_DIR)/%) $(LUA_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
ROOTLINK	= $(ROOT_FS_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/common/fs/zfs

#
#	Include common rules.
#
include ../Makefile.$(ARCHDIR)

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(SRC_CONFILE)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOTLINK) $(ROOT_CONFFILE)

#
#	Overrides and depends_on
#
MODSTUBS_DIR	 = $(OBJS_DIR)
LDFLAGS		+= -dy -Nfs/specfs -Ncrypto/swrand -Nmisc/idmap -Nmisc/sha2 \
	-Nmisc/skein -Nmisc/edonr

INC_PATH	+= -I$(UTSBASE)/common/fs/zfs
INC_PATH	+= -I$(UTSBASE)/common/fs/zfs/lua
INC_PATH	+= -I$(SRC)/common
INC_PATH	+= -I$(COMMONBASE)/zfs
INC_PATH	+= -I$(UTSBASE)/i86pc

C99LMODE=	-Xc99=%all

CERRWARN	+= -_gcc=-Wno-type-limits
CERRWARN	+= -_gcc=-Wno-switch
CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-unused-variable
CERRWARN	+= -_gcc=-Wno-unused-function
CERRWARN	+= -_gcc=-Wno-unused-label

# lua code
$(OBJS_DIR)/lgc.o := SMOFF += all_func_returns
$(OBJS_DIR)/lparser.o := SMOFF += all_func_returns
$(OBJS_DIR)/llex.o := SMOFF += all_func_returns,index_overflow
$(OBJS_DIR)/lcode.o := SMOFF += all_func_returns
$(OBJS_DIR)/lstrlib.o := SMOFF += all_func_returns
$(OBJS_DIR)/lbaselib.o := SMOFF += all_func_returns
$(OBJS_DIR)/lbitlib.o := SMOFF += all_func_returns
$(OBJS_DIR)/ltablib.o := SMOFF += all_func_returns
$(OBJS_DIR)/lundump.o := SMOFF += all_func_returns
$(OBJS_DIR)/lfunc.o := SMOFF += all_func_returns
$(OBJS_DIR)/lstate.o := SMOFF += all_func_returns
$(OBJS_DIR)/ldebug.o := SMOFF += all_func_returns,indenting
$(OBJS_DIR)/ldo.o := SMOFF += all_func_returns
$(OBJS_DIR)/lauxlib.o := SMOFF += all_func_returns
$(OBJS_DIR)/lcorolib.o := SMOFF += all_func_returns
$(OBJS_DIR)/ltable.o := SMOFF += all_func_returns

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS)

$(ROOTLINK):	$(ROOT_FS_DIR) $(ROOTMODULE)
	-$(RM) $@; ln $(ROOTMODULE) $@

#
#	Include common targets.
#
include ../Makefile.targ
