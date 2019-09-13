/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2023 Toomas Soome <tsoome@me.com>
 */

#include <stand.h>
#include <sys/param.h>
#include <sys/sha2.h>
#include <libcrypto.h>

typedef enum {
	SHA1_TYPE,
	SHA256_TYPE,
	SHA384_TYPE,
	SHA512_TYPE
} sha2_mech_t;

typedef struct sha2_hmac_ctx {
	sha2_mech_type_t	hc_mech_type;	/* type of context */
	uint32_t		hc_digest_len;	/* digest len in bytes */
	SHA2_CTX		hc_icontext;	/* inner SHA2 context */
	SHA2_CTX		hc_ocontext;	/* outer SHA2 context */
} sha2_hmac_ctx_t;

#define	PROV_SHA2_DIGEST_KEY(mech, ctx, key, len, digest) {	\
	SHA2Init(mech, ctx);				\
	SHA2Update(ctx, key, len);			\
	SHA2Final(digest, ctx);				\
}

#define	PROV_SHA2_CTX(ctx)	((sha2_ctx_t *)(ctx)->cc_provider_private)
#define	PROV_SHA2_HMAC_CTX(ctx)	((sha2_hmac_ctx_t *)(ctx)->cc_provider_private)

/*
 * Initialize a SHA2-HMAC context.
 */
static void
sha2_mac_init_ctx(sha2_hmac_ctx_t *ctx, void *keyval, uint_t length_in_bytes)
{
	uint64_t ipad[SHA512_HMAC_BLOCK_SIZE / sizeof (uint64_t)];
	uint64_t opad[SHA512_HMAC_BLOCK_SIZE / sizeof (uint64_t)];
	int i, block_size, blocks_per_int64;

	/* Determine the block size */
	if (ctx->hc_mech_type <= SHA256_HMAC_GEN_MECH_INFO_TYPE) {
		block_size = SHA256_HMAC_BLOCK_SIZE;
		blocks_per_int64 = SHA256_HMAC_BLOCK_SIZE / sizeof (uint64_t);
	} else {
		block_size = SHA512_HMAC_BLOCK_SIZE;
		blocks_per_int64 = SHA512_HMAC_BLOCK_SIZE / sizeof (uint64_t);
	}

	(void) bzero(ipad, block_size);
	(void) bzero(opad, block_size);
	(void) bcopy(keyval, ipad, length_in_bytes);
	(void) bcopy(keyval, opad, length_in_bytes);

	/* XOR key with ipad (0x36) and opad (0x5c) */
	for (i = 0; i < blocks_per_int64; i ++) {
		ipad[i] ^= 0x3636363636363636;
		opad[i] ^= 0x5c5c5c5c5c5c5c5c;
	}

	/* perform SHA2 on ipad */
	SHA2Init(ctx->hc_mech_type, &ctx->hc_icontext);
	SHA2Update(&ctx->hc_icontext, (uint8_t *)ipad, block_size);

	/* perform SHA2 on opad */
	SHA2Init(ctx->hc_mech_type, &ctx->hc_ocontext);
	SHA2Update(&ctx->hc_ocontext, (uint8_t *)opad, block_size);
}

#define	SHA2_MAC_UPDATE(data, ctx, ret) {				\
	switch (data->cd_format) {					\
	case CRYPTO_DATA_RAW:						\
		SHA2Update(&(ctx).hc_icontext,				\
		    (uint8_t *)data->cd_raw.iov_base +			\
		    data->cd_offset, data->cd_length);			\
		break;							\
	case CRYPTO_DATA_UIO:						\
		ret = sha2_digest_update_uio(&(ctx).hc_icontext, data);	\
		break;							\
	default:							\
		ret = EINVAL;						\
	}								\
}

/*
 * Helper SHA2 digest update function for uio data.
 */
static int
sha2_digest_update_uio(SHA2_CTX *sha2_ctx, crypto_data_t *data)
{
	off_t offset = data->cd_offset;
	size_t length = data->cd_length;
	uint_t vec_idx;
	size_t cur_len;

	if (data->cd_uio->uio_segflg != UIO_SYSSPACE)
		return (EINVAL);

	/*
	 * Jump to the first iovec containing data to be
	 * digested.
	 */
	for (vec_idx = 0; vec_idx < data->cd_uio->uio_iovcnt &&
	    offset >= data->cd_uio->uio_iov[vec_idx].iov_len;
	    offset -= data->cd_uio->uio_iov[vec_idx++].iov_len)
		;
	if (vec_idx == data->cd_uio->uio_iovcnt) {
		/*
		 * The caller specified an offset that is larger than the
		 * total size of the buffers it provided.
		 */
		return (ERANGE);
	}

	/*
	 * Now do the digesting on the iovecs.
	 */
	while (vec_idx < data->cd_uio->uio_iovcnt && length > 0) {
		cur_len = MIN(data->cd_uio->uio_iov[vec_idx].iov_len -
		    offset, length);

		SHA2Update(sha2_ctx, (uint8_t *)data->cd_uio->
		    uio_iov[vec_idx].iov_base + offset, cur_len);
		length -= cur_len;
		vec_idx++;
		offset = 0;
	}

	if (vec_idx == data->cd_uio->uio_iovcnt && length > 0) {
		/*
		 * The end of the specified iovec's was reached but
		 * the length requested could not be processed, i.e.
		 * The caller requested to digest more data than it provided.
		 */
		return (ERANGE);
	}

	return (0);
}

/*
 * Helper SHA2 digest final function for uio data.
 * digest_len is the length of the desired digest. If digest_len
 * is smaller than the default SHA2 digest length, the caller
 * must pass a scratch buffer, digest_scratch, which must
 * be at least the algorithm's digest length bytes.
 */
static int
sha2_digest_final_uio(SHA2_CTX *sha2_ctx, crypto_data_t *digest,
    ulong_t digest_len, uchar_t *digest_scratch)
{
	off_t offset = digest->cd_offset;
	uint_t vec_idx;

	if (digest->cd_uio->uio_segflg != UIO_SYSSPACE)
		return (EINVAL);

	/*
	 * Jump to the first iovec containing ptr to the digest to
	 * be returned.
	 */
	for (vec_idx = 0; offset >= digest->cd_uio->uio_iov[vec_idx].iov_len &&
	    vec_idx < digest->cd_uio->uio_iovcnt;
	    offset -= digest->cd_uio->uio_iov[vec_idx++].iov_len)
		;
	if (vec_idx == digest->cd_uio->uio_iovcnt) {
		/*
		 * The caller specified an offset that is
		 * larger than the total size of the buffers
		 * it provided.
		 */
		return (ERANGE);
	}

	if (offset + digest_len <=
	   digest->cd_uio->uio_iov[vec_idx].iov_len) {
		/*
		 * The computed SHA2 digest will fit in the current
		 * iovec.
		 */
		if (((sha2_ctx->algotype <= SHA256_HMAC_GEN_MECH_INFO_TYPE) &&
		    (digest_len != SHA256_DIGEST_LENGTH)) ||
		    ((sha2_ctx->algotype > SHA256_HMAC_GEN_MECH_INFO_TYPE) &&
		    (digest_len != SHA512_DIGEST_LENGTH))) {
			/*
			 * The caller requested a short digest. Digest
			 * into a scratch buffer and return to
			 * the user only what was requested.
			 */
			SHA2Final(digest_scratch, sha2_ctx);

			bcopy(digest_scratch, (uchar_t *)digest->
			    cd_uio->uio_iov[vec_idx].iov_base + offset,
			    digest_len);
		} else {
			SHA2Final((uchar_t *)digest->
			    cd_uio->uio_iov[vec_idx].iov_base + offset,
			    sha2_ctx);

		}
	} else {
		/*
		 * The computed digest will be crossing one or more iovec's.
		 * This is bad performance-wise but we need to support it.
		 * Allocate a small scratch buffer on the stack and
		 * copy it piece meal to the specified digest iovec's.
		 */
		uchar_t digest_tmp[SHA512_DIGEST_LENGTH];
		off_t scratch_offset = 0;
		size_t length = digest_len;
		size_t cur_len;

		SHA2Final(digest_tmp, sha2_ctx);

		while (vec_idx < digest->cd_uio->uio_iovcnt && length > 0) {
			cur_len =
			    MIN(digest->cd_uio->uio_iov[vec_idx].iov_len -
			    offset, length);
			bcopy(digest_tmp + scratch_offset,
			    digest->cd_uio->uio_iov[vec_idx].iov_base + offset,
			    cur_len);

			length -= cur_len;
			vec_idx++;
			scratch_offset += cur_len;
			offset = 0;
		}

		if (vec_idx == digest->cd_uio->uio_iovcnt && length > 0) {
			/*
			 * The end of the specified iovec's was reached but
			 * the length requested could not be processed, i.e.
			 * The caller requested to digest more data than it
			 * provided.
			 */
			return (ERANGE);
		}
	}

	return (0);
}

int
sha2_mac(crypto_mechanism_t *mechanism, crypto_key_t *key, crypto_data_t *data,
    crypto_data_t *mac)
{
	int ret = 0;
	uchar_t digest[SHA512_DIGEST_LENGTH];
	sha2_hmac_ctx_t sha2_hmac_ctx;
	uint32_t sha_digest_len, digest_len, sha_hmac_block_size;
	uint_t keylen_in_bytes = CRYPTO_BITS2BYTES(key->ck_length);

	switch (mechanism->cm_type) {
	case SHA512_HMAC_MECH_INFO_TYPE:
		sha_digest_len = digest_len = SHA512_DIGEST_LENGTH;
		sha_hmac_block_size = SHA512_HMAC_BLOCK_SIZE;
		break;
	default:
		return (EINVAL);
	}

	if (key->ck_format != CRYPTO_KEY_RAW)
		return (EINVAL);

	sha2_hmac_ctx.hc_mech_type = mechanism->cm_type;
	/* no context template, initialize context */
	if (keylen_in_bytes > sha_hmac_block_size) {
		/*
		 * Hash the passed-in key to get a smaller key.
		 * The inner context is used since it hasn't been
		 * initialized yet.
		 */
		PROV_SHA2_DIGEST_KEY(mechanism->cm_type / 3,
		    &sha2_hmac_ctx.hc_icontext,
		    key->ck_data, keylen_in_bytes, digest);
		sha2_mac_init_ctx(&sha2_hmac_ctx, digest,
		    sha_digest_len);
	} else {
		sha2_mac_init_ctx(&sha2_hmac_ctx, key->ck_data,
		    keylen_in_bytes);
	}

	/* do a SHA2 update of the inner context using the specified data */
	SHA2_MAC_UPDATE(data, sha2_hmac_ctx, ret);
	if (ret != 0)
		/* the update failed, free context and bail */
		goto bail;

	/*
	 * Do a SHA2 final on the inner context.
	 */
	SHA2Final(digest, &sha2_hmac_ctx.hc_icontext);

	/*
	 * Do an SHA2 update on the outer context, feeding the inner
	 * digest as data.
	 */
	SHA2Update(&sha2_hmac_ctx.hc_ocontext, digest, sha_digest_len);

	/*
	 * Do a SHA2 final on the outer context, storing the computed
	 * digest in the users buffer.
	 */
	switch (mac->cd_format) {
	case CRYPTO_DATA_RAW:
		if (digest_len != sha_digest_len) {
			/*
			 * The caller requested a short digest. Digest
			 * into a scratch buffer and return to
			 * the user only what was requested.
			 */
			SHA2Final(digest, &sha2_hmac_ctx.hc_ocontext);
			bcopy(digest, (unsigned char *)mac->cd_raw.iov_base +
			    mac->cd_offset, digest_len);
		} else {
			SHA2Final((unsigned char *)mac->cd_raw.iov_base +
			    mac->cd_offset, &sha2_hmac_ctx.hc_ocontext);
		}
		break;
	case CRYPTO_DATA_UIO:
		ret = sha2_digest_final_uio(&sha2_hmac_ctx.hc_ocontext, mac,
		    digest_len, digest);
		break;
	default:
		ret = EINVAL;
	}

	if (ret == 0) {
		mac->cd_length = digest_len;
		return (ret);
	}
bail:
	bzero(&sha2_hmac_ctx, sizeof (sha2_hmac_ctx_t));
	mac->cd_length = 0;
	return (ret);
}

typedef struct crypto_ctx {
	void			*cc_provider_private;	/* owned by provider */
	void			*cc_framework_private;	/* owned by framework */
	uint32_t		cc_flags;		/* flags */
	void			*cc_opstate;		/* state */
} crypto_ctx_t;

int
sha2_mac_init(crypto_mechanism_t *mechanism, crypto_key_t *key,
    crypto_context_t *ctxp)
{
	crypto_ctx_t *ctx;
	int ret = 0;
	uint_t keylen_in_bytes = CRYPTO_BITS2BYTES(key->ck_length);
	uint_t sha_digest_len, sha_hmac_block_size;

	/*
	 * Set the digest length and block size to values appropriate to the
	 * mechanism
	 */
	switch (mechanism->cm_type) {
	case SHA512_HMAC_MECH_INFO_TYPE:
		sha_digest_len = SHA512_DIGEST_LENGTH;
		sha_hmac_block_size = SHA512_HMAC_BLOCK_SIZE;
		break;
	default:
		return (EINVAL);
	}

	if (key->ck_format != CRYPTO_KEY_RAW)
		return (EINVAL);

	ctx = calloc(1, sizeof (crypto_ctx_t));
	if (ctx == NULL)
		return (ENOMEM);

	ctx->cc_provider_private = malloc(sizeof (sha2_hmac_ctx_t));
	if (ctx->cc_provider_private == NULL) {
		free(ctx);
		return (ENOMEM);
	}

	PROV_SHA2_HMAC_CTX(ctx)->hc_mech_type = mechanism->cm_type;
	/* no context template, compute context */
	if (keylen_in_bytes > sha_hmac_block_size) {
		uchar_t digested_key[SHA512_DIGEST_LENGTH];
		sha2_hmac_ctx_t *hmac_ctx = ctx->cc_provider_private;

		/*
		 * Hash the passed-in key to get a smaller key.
		 * The inner context is used since it hasn't been
		 * initialized yet.
		 */
		PROV_SHA2_DIGEST_KEY(mechanism->cm_type / 3,
		    &hmac_ctx->hc_icontext,
		    key->ck_data, keylen_in_bytes, digested_key);
		sha2_mac_init_ctx(PROV_SHA2_HMAC_CTX(ctx),
		    digested_key, sha_digest_len);
	} else {
		sha2_mac_init_ctx(PROV_SHA2_HMAC_CTX(ctx),
		    key->ck_data, keylen_in_bytes);
	}

	*ctxp = ctx;
	return (ret);
}

int
sha2_mac_update(crypto_context_t context, crypto_data_t *data)
{
	int ret = 0;
	crypto_ctx_t *ctx = context;

	switch (data->cd_format) {
	case CRYPTO_DATA_RAW:
		SHA2Update(&PROV_SHA2_HMAC_CTX(ctx)->hc_icontext,
		    (uint8_t *)data->cd_raw.iov_base + data->cd_offset,
		    data->cd_length);
		break;
	case CRYPTO_DATA_UIO:
		ret = sha2_digest_update_uio(
		    &PROV_SHA2_HMAC_CTX(ctx)->hc_icontext, data);
		break;
	default:
		ret = EINVAL;
	}

	return (ret);
}

int
sha2_mac_final(crypto_context_t context, crypto_data_t *mac)
{
	crypto_ctx_t *ctx = context;
	int ret = 0;
	uchar_t digest[SHA512_DIGEST_LENGTH];
	uint32_t digest_len, sha_digest_len;

	/* Set the digest lengths to values appropriate to the mechanism */
	switch (PROV_SHA2_HMAC_CTX(ctx)->hc_mech_type) {
	case SHA512_HMAC_MECH_INFO_TYPE:
		sha_digest_len = digest_len = SHA512_DIGEST_LENGTH;
		break;
	default:
		return (EINVAL);
	}

	/*
	 * We need to just return the length needed to store the output.
	 * We should not destroy the context for the following cases.
	 */
	if ((mac->cd_length == 0) || (mac->cd_length < digest_len)) {
		mac->cd_length = digest_len;
		return (ENOSPC);
	}

	/*
	 * Do a SHA2 final on the inner context.
	 */
	SHA2Final(digest, &PROV_SHA2_HMAC_CTX(ctx)->hc_icontext);

	/*
	 * Do a SHA2 update on the outer context, feeding the inner
	 * digest as data.
	 */
	SHA2Update(&PROV_SHA2_HMAC_CTX(ctx)->hc_ocontext, digest,
	    sha_digest_len);

	/*
	 * Do a SHA2 final on the outer context, storing the computing
	 * digest in the users buffer.
	 */
	switch (mac->cd_format) {
	case CRYPTO_DATA_RAW:
		if (digest_len != sha_digest_len) {
			/*
			 * The caller requested a short digest. Digest
			 * into a scratch buffer and return to
			 * the user only what was requested.
			 */
			SHA2Final(digest,
			    &PROV_SHA2_HMAC_CTX(ctx)->hc_ocontext);
			bcopy(digest, (unsigned char *)mac->cd_raw.iov_base +
			    mac->cd_offset, digest_len);
		} else {
			SHA2Final((unsigned char *)mac->cd_raw.iov_base +
			    mac->cd_offset,
			    &PROV_SHA2_HMAC_CTX(ctx)->hc_ocontext);
		}
		break;
	case CRYPTO_DATA_UIO:
		ret = sha2_digest_final_uio(
		    &PROV_SHA2_HMAC_CTX(ctx)->hc_ocontext, mac,
		    digest_len, digest);
		break;
	default:
		ret = EINVAL;
	}

	if (ret == 0)
		mac->cd_length = digest_len;
	else
		mac->cd_length = 0;

	bzero(ctx->cc_provider_private, sizeof (sha2_hmac_ctx_t));
	free(ctx->cc_provider_private);
	ctx->cc_provider_private = NULL;
	free(ctx);

	return (ret);
}
