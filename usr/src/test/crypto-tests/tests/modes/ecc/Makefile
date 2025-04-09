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
# Copyright 2025 MNX Cloud, Inc.
#

BASEPROG = modtest
CRYPTO = ecc
TESTROOT = $(ROOT)/opt/crypto-tests/tests

ECC_COBJECTS = \
	ec_naf.o ec2_163.o ec2_193.o ec2_233.o ec2_aff.o ec2_mont.o \
	ecl_curve.o ecl_gf.o ecl_mult.o ecl.o ecp_192.o ecp_224.o ecp_256.o \
	ecp_521.o ecp_aff.o ecp_jac.o ecp_jm.o ecp_mont.o

MPI_COBJECTS = \
	mp_gf2m.o mpi.o mplogic.o mpmontg.o

COMMON_OBJS = $(ECC_COBJECTS) $(MPI_COBJECTS)
CRYPTO_pkcs =  $(POUND_SIGN)
CRYPTO_kcf =  $(POUND_SIGN)
CRYPTO_testfuncs =  $(POUND_SIGN)
CRYPTO_ecc=

ECCDIR = $(SRC)/common/crypto/ecc
MPIDIR = $(SRC)/common/mpi

include $(SRC)/test/crypto-tests/tests/Makefile.crypto

CPPFLAGS += -I$(ECCDIR) -I$(MPIDIR) \
	-DMP_API_COMPATIBLE -DNSS_ECC_MORE_THAN_SUITE_B

CERRWARN += -_gcc=-Wno-type-limits
CERRWARN += -_gcc=-Wno-unused-variable

SMATCH=off

%.32.o:    $(ECCDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.64.o:    $(ECCDIR)/%.c
	$(COMPILE64.c) -o $@ $<
	$(POST_PROCESS_O)

%.32.o:    $(MPIDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.64.o:    $(MPIDIR)/%.c
	$(COMPILE64.c) -o $@ $<
	$(POST_PROCESS_O)
