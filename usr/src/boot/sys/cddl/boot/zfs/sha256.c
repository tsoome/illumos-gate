/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2013 Saso Kiselkov.  All rights reserved.
 * Copyright 2024 Toomas Soome <tsoome@me.com>
 */

#include <sys/sha2.h>

static void
zio_checksum_SHA256(const void *buf, uint64_t size,
    const void *ctx_template __unused, zio_cksum_t *zcp)
{
	SHA2_CTX ctx;
	zio_cksum_t tmp;

	SHA2Init(SHA256, &ctx);
	SHA2Update(&ctx, buf, size);
	SHA2Final(&tmp, &ctx);

	zcp->zc_word[0] = BE_64(tmp.zc_word[0]);
	zcp->zc_word[1] = BE_64(tmp.zc_word[1]);
	zcp->zc_word[2] = BE_64(tmp.zc_word[2]);
	zcp->zc_word[3] = BE_64(tmp.zc_word[3]);
}

static void
zio_checksum_SHA512_native(const void *buf, uint64_t size,
    const void *ctx_template __unused, zio_cksum_t *zcp)
{
	SHA2_CTX ctx;

	SHA2Init(SHA512_256, &ctx);
	SHA2Update(&ctx, buf, size);
	SHA2Final(zcp, &ctx);
}

static void
zio_checksum_SHA512_byteswap(const void *buf, uint64_t size,
    const void *ctx_template, zio_cksum_t *zcp)
{
	zio_cksum_t	tmp;

	zio_checksum_SHA512_native(buf, size, ctx_template, &tmp);
	zcp->zc_word[0] = BSWAP_64(tmp.zc_word[0]);
	zcp->zc_word[1] = BSWAP_64(tmp.zc_word[1]);
	zcp->zc_word[2] = BSWAP_64(tmp.zc_word[2]);
	zcp->zc_word[3] = BSWAP_64(tmp.zc_word[3]);
}
