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
# Copyright 2019 Joyent, Inc.
#

PROG=		ls
XPG4PROG=	ls
XPG6PROG=	ls
OBJS=           $(PROG).o
SRCS=           $(OBJS:%.o=../%.c)

include ../../Makefile.cmd

LDLIBS += -lsec -lnvpair -lcmdutils -lcurses
CFLAGS	+=	$(CCVERBOSE)
$(XPG4) := CFLAGS += -DXPG4

# Include all XPG4 changes in the XPG6 version
$(XPG6) := CFLAGS += -DXPG4 -DXPG6
$(XPG6) := CFLAGS64 += -DXPG4 -DXPG6

CFLAGS64 +=	$(CCVERBOSE)
CPPFLAGS += -D_FILE_OFFSET_BITS=64

# main() can be too hairy
SMATCH=off

.KEEP_STATE:

all:	$(PROG) $(XPG4) $(XPG6)

clean:
	$(RM) $(CLEANFILES)

include ../../Makefile.targ

%.xpg4: ../%.c
	$(LINK.c) $(CPPFLAGS) -o $@ $< $(LDLIBS)
	$(POST_PROCESS)

%.xpg6: ../%.c
	$(LINK.c) $(CPPFLAGS) -o $@ $< $(LDLIBS)
	$(POST_PROCESS)

%: ../%.c
	$(LINK.c) $(CPPFLAGS) -o $@ $< $(LDLIBS)
	$(POST_PROCESS)
