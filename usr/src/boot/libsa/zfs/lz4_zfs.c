/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2026 Toomas Soome <tsoome@me.com>
 */

#include <lz4.h>
#include <sys/abd.h>

int
zfs_lz4_decompress(abd_t *src, abd_t *dst, size_t s_len, size_t d_len, int n)
{
	void *s_buf = abd_borrow_buf_copy(src, s_len);
	void *d_buf = abd_borrow_buf(dst, d_len);
	int err = lz4_decompress(s_buf, d_buf, s_len, d_len, n);

	abd_return_buf(src, s_buf, s_len);
	abd_return_buf_copy(dst, d_buf, d_len);

	return (err);
}
