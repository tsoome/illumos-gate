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
# Copyright 2021 Toomas Soome <tsoome@me.com>
#

COMDIR = $(SRC)/common/crypto

SRCS +=		$(CRYPTOSRC)/digest.c
SRCS +=		$(CRYPTOSRC)/pkcs5_pbkdf2.c
SRCS +=		$(COMDIR)/sha1/sha1.c
SRCS +=		$(COMDIR)/edonr/edonr.c
SRCS +=		$(COMDIR)/skein/skein.c
SRCS +=		$(COMDIR)/skein/skein_iv.c
SRCS +=		$(COMDIR)/skein/skein_block.c
OBJECTS +=	crypto.o
OBJECTS +=	digest.o
OBJECTS +=	pkcs5_pbkdf2.o
OBJECTS +=	sha1.o
OBJECTS +=	sha2.o
OBJECTS +=	sha2_mac.o
OBJECTS +=	edonr.o
OBJECTS +=	skein.o
OBJECTS +=	skein_iv.o
OBJECTS +=	skein_block.o
OBJECTS +=	aes_impl.o
OBJECTS +=	ccm.o
OBJECTS +=	gcm.o

objs/crypto.o pics/crypto.o := CPPFLAGS +=	-I$(CRYPTOSRC)
objs/ccm.o pics/ccm.o := CPPFLAGS +=	-I$(CRYPTOSRC)
objs/gcm.o pics/gcm.o := CPPFLAGS +=	-I$(CRYPTOSRC)
objs/aes_impl.o pics/aes_impl.o := CPPFLAGS +=	-I$(CRYPTOSRC)
objs/sha2.o pics/sha2.o := CPPFLAGS +=	-I$(CRYPTOSRC)
objs/sha2_mac.o pics/sha2_mac.o := CPPFLAGS +=	-I$(CRYPTOSRC)
objs/digest.o pics/digest.o := CPPFLAGS +=	-I../../common

# Do not unroll skein loops, reduce code size
objs/skein_block.o pics/skein_block.o := CPPFLAGS +=	-DSKEIN_LOOP=111

objs/%.o pics/%.o:	$(COMDIR)/edonr/%.c
	$(COMPILE.c) -o $@ $<

objs/%.o pics/%.o:	$(COMDIR)/skein/%.c
	$(COMPILE.c) -o $@ $<

objs/%.o pics/%.o:	$(CRYPTOSRC)/%.c
	$(COMPILE.c) -o $@ $<

objs/%.o pics/%.o:	$(COMDIR)/sha1/%.c
	$(COMPILE.c) -o $@ $<

sha1-x86_64.S: $(COMDIR)/sha1/amd64/sha1-x86_64.pl
	$(PERL) $? $@

pics/sha1-x86_64.o: sha1-x86_64.S
	$(COMPILE.s) -o $@ ${@F:.o=.S}
