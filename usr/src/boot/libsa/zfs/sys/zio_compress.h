/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or https://opensource.org/licenses/CDDL-1.0.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Copyright (c) 2019, Allan Jude
 * Copyright (c) 2019, 2024, Klara, Inc.
 * Use is subject to license terms.
 * Copyright (c) 2015, 2016 by Delphix. All rights reserved.
 * Copyright (c) 2021, 2024 by George Melikov. All rights reserved.
 */

#ifndef _SYS_ZIO_COMPRESS_H
#define	_SYS_ZIO_COMPRESS_H

#include <sys/abd.h>

#ifdef  __cplusplus
extern "C" {
#endif

enum zio_compress {
	ZIO_COMPRESS_INHERIT = 0,
	ZIO_COMPRESS_ON,
	ZIO_COMPRESS_OFF,
	ZIO_COMPRESS_LZJB,
	ZIO_COMPRESS_EMPTY,
	ZIO_COMPRESS_GZIP_1,
	ZIO_COMPRESS_GZIP_2,
	ZIO_COMPRESS_GZIP_3,
	ZIO_COMPRESS_GZIP_4,
	ZIO_COMPRESS_GZIP_5,
	ZIO_COMPRESS_GZIP_6,
	ZIO_COMPRESS_GZIP_7,
	ZIO_COMPRESS_GZIP_8,
	ZIO_COMPRESS_GZIP_9,
	ZIO_COMPRESS_ZLE,
	ZIO_COMPRESS_LZ4,
	ZIO_COMPRESS_FUNCTIONS
};

#define	ZIO_COMPRESS_ON_VALUE	ZIO_COMPRESS_LZJB
#define	ZIO_COMPRESS_DEFAULT	ZIO_COMPRESS_OFF

/* Common signature for all zio decompress functions. */
typedef int zio_decompress_func_t(abd_t *src, abd_t *dst,
    size_t s_len, size_t d_len, int);

/*
 * Information about each compression function.
 */
typedef struct zio_compress_info {
	zio_decompress_func_t	*ci_decompress;	/* decompression function */
	int			ci_level;	/* level parameter */
	const char		*ci_name;	/* algorithm name */
} zio_compress_info_t;

/*
 * Compression routines.
 */
extern int zfs_lzjb_decompress(abd_t *src, abd_t *dst, size_t s_len,
    size_t d_len, int level);
extern int zfs_gzip_decompress(abd_t *src, abd_t *dst, size_t s_len,
    size_t d_len, int level);
extern int zfs_zle_decompress(abd_t *src, abd_t *dst, size_t s_len,
    size_t d_len, int level);
extern int zfs_lz4_decompress(abd_t *src, abd_t *dst, size_t s_len,
    size_t d_len, int level);

/*
 * Compress and decompress data if necessary.
 */
extern int zio_decompress_data(enum zio_compress c, abd_t *src, abd_t *abd,
    size_t s_len, size_t d_len);

#define ZFS_DECOMPRESS_WRAP_DECL(name)					\
int									\
name(abd_t *src, abd_t *dst, size_t s_len, size_t d_len, int n)		\
{									\
        void *s_buf = abd_borrow_buf_copy(src, s_len);			\
        void *d_buf = abd_borrow_buf(dst, d_len);			\
        int err = name##_buf(s_buf, d_buf, s_len, d_len, n);		\
        abd_return_buf(src, s_buf, s_len);				\
        abd_return_buf_copy(dst, d_buf, d_len);				\
        return (err);							\
}

#ifdef  __cplusplus
}
#endif

#endif  /* _SYS_ZIO_COMPRESS_H */
