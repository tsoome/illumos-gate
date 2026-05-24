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
 * Use is subject to license terms.
 * Copyright (c) 2013 by Saso Kiselkov. All rights reserved.
 * Copyright (c) 2013, 2018 by Delphix. All rights reserved.
 * Copyright (c) 2019, 2024, Klara, Inc.
 * Copyright (c) 2019, Allan Jude
 * Copyright (c) 2021, 2024 by George Melikov. All rights reserved.
 */

#include <stand.h>
#include <sys/zio_compress.h>
#include <sys/zfsimpl.h>

/*
 * Compression vectors.
 */
static zio_compress_info_t zio_compress_table[ZIO_COMPRESS_FUNCTIONS] = {
	{ NULL,			0,	"inherit" },
	{ NULL,			0,	"on" },
	{ NULL,			0,	"uncompressed" },
	{ zfs_lzjb_decompress,	0,	"lzjb" },
	{ NULL,			0,	"empty" },
	{ zfs_gzip_decompress,	1,	"gzip-1" },
	{ zfs_gzip_decompress,	2,	"gzip-2" },
	{ zfs_gzip_decompress,	3,	"gzip-3" },
	{ zfs_gzip_decompress,	4,	"gzip-4" },
	{ zfs_gzip_decompress,	5,	"gzip-5" },
	{ zfs_gzip_decompress,	6,	"gzip-6" },
	{ zfs_gzip_decompress,	7,	"gzip-7" },
	{ zfs_gzip_decompress,	8,	"gzip-8" },
	{ zfs_gzip_decompress,	9,	"gzip-9" },
	{ zfs_zle_decompress,	64,	"zle" },
	{ zfs_lz4_decompress,	0,	"lz4" },
};

int
zio_decompress_data(enum zio_compress c, abd_t *src, abd_t *dst,
    size_t s_len, size_t d_len)
{
	int err = EINVAL;

	if ((uint_t)c >= ZIO_COMPRESS_FUNCTIONS) {
		printf("ZFS: unsupported compression algorithm %u\n", c);
		return (err);
	}

	zio_compress_info_t *ci = &zio_compress_table[c];

	if (ci->ci_decompress == NULL)
		printf("ZFS: unsupported compression algorithm %s\n",
		    ci->ci_name);
	else
		err = ci->ci_decompress(src, dst, s_len, d_len, ci->ci_level);

	return (err);
}
