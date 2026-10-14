# SPDX-License-Identifier: GPL-2.0

TEST_GEN_PROGS := zkl_test

include ../../lib.mk

$(OUTPUT)/zkl_test: zkl_test.c kle.h
	$(CC) -static -O2 -march=rv64gcv -o $@ $(CFLAGS) $(LDFLAGS) $< -lpthread
