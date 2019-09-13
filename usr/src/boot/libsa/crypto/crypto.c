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
 * Copyright 2023 Toomas Soome <tsoome@me.com>
 */

#include <stand.h>
#include <sys/param.h>
#include <libcrypto.h>
#include "aes_impl.h"

/* Copy a 16-byte AES block from "in" to "out" */
static void
aes_copy_block(uint8_t *in, uint8_t *out)
{
	if (IS_P2ALIGNED2(in, out, sizeof (uint32_t))) {
		*(uint32_t *)&out[0] = *(uint32_t *)&in[0];
		*(uint32_t *)&out[4] = *(uint32_t *)&in[4];
		*(uint32_t *)&out[8] = *(uint32_t *)&in[8];
		*(uint32_t *)&out[12] = *(uint32_t *)&in[12];
	} else {
		AES_COPY_BLOCK(in, out);
	}
}

/* XOR a 16-byte AES block of data into dst */
void
aes_xor_block(uint8_t *data, uint8_t *dst)
{
	if (IS_P2ALIGNED2(dst, data, sizeof (uint32_t))) {
		*(uint32_t *)&dst[0] ^= *(uint32_t *)&data[0];
		*(uint32_t *)&dst[4] ^= *(uint32_t *)&data[4];
		*(uint32_t *)&dst[8] ^= *(uint32_t *)&data[8];
		*(uint32_t *)&dst[12] ^= *(uint32_t *)&data[12];
	} else {
		AES_XOR_BLOCK(data, dst);
	}
}

static int
aes_common_init_ctx(aes_ctx_t *aes_ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key)
{
	aes_key_t *keysched;
	int rv = 0;

	keysched = malloc(sizeof (*keysched));
	if (keysched == NULL)
		return (ENOMEM);

	aes_init_keysched(key, keysched);
	aes_ctx->ac_keysched = keysched;
	aes_ctx->ac_keysched_len = sizeof (*keysched);

	switch (mechanism->cm_type) {
	case AES_CCM_MECH_INFO_TYPE:
		if (mechanism->cm_param == NULL ||
		    mechanism->cm_param_len != sizeof (CK_AES_CCM_PARAMS)) {
			return (EINVAL);
		}
		rv = ccm_init_ctx(&aes_ctx->acu.acu_ccm, mechanism->cm_param,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_xor_block);
		break;

	case AES_GCM_MECH_INFO_TYPE:
		if (mechanism->cm_param == NULL ||
		    mechanism->cm_param_len != sizeof (CK_AES_GCM_PARAMS)) {
			return (EINVAL);
		}
		rv = gcm_init_ctx(&aes_ctx->acu.acu_gcm, mechanism->cm_param,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);
		break;

	default:
		rv = ENOTSUP;
	}

	if (rv != 0) {
		bzero(keysched, aes_ctx->ac_keysched_len);
		free(keysched);
	}
	return (rv);
}

int
crypto_mac(crypto_mechanism_t *mech, crypto_data_t *data,
    crypto_key_t *key, crypto_data_t *mac)
{
	switch (mech->cm_type) {
	case SHA512_HMAC_MECH_INFO_TYPE:
		return (sha2_mac(mech, key, data, mac));

	default:
		return (ENOTSUP);
	}
}

int
crypto_mac_init(crypto_mechanism_t *mech, crypto_key_t *key,
    crypto_context_t *ctxp)
{
	switch (mech->cm_type) {
	case SHA512_HMAC_MECH_INFO_TYPE:
		return (sha2_mac_init(mech, key, ctxp));

	default:
		return (ENOTSUP);
	}
}

int
crypto_mac_update(crypto_context_t context, crypto_data_t *data)
{
	return (sha2_mac_update(context, data));
}

int
crypto_mac_final(crypto_context_t context, crypto_data_t *mac)
{
	return (sha2_mac_final(context, mac));
}

static int
crypto_update_uio(void *ctx, crypto_data_t *input, crypto_data_t *output,
    int (*cipher)(void *, caddr_t, size_t, crypto_data_t *))
{
	uio_t *uiop = input->cd_uio;
	off_t offset = input->cd_offset;
	size_t length = input->cd_length;
	uint_t vec_idx;
	size_t cur_len;

	if (input->cd_uio->uio_segflg != UIO_SYSSPACE) {
		return (EINVAL);
	}

	/*
	 * Jump to the first iovec containing data to be
	 * processed.
	 */
	for (vec_idx = 0; vec_idx < uiop->uio_iovcnt &&
	    offset >= uiop->uio_iov[vec_idx].iov_len;
	    offset -= uiop->uio_iov[vec_idx++].iov_len)
		;

	if (vec_idx == uiop->uio_iovcnt && length > 0) {
		/*
		 * The caller specified an offset that is larger than the
		 * total size of the buffers it provided.
		 */
		return (ERANGE);
	}

	/*
	 * Now process the iovecs.
	 */
	while (vec_idx < uiop->uio_iovcnt && length > 0) {
		cur_len = MIN(uiop->uio_iov[vec_idx].iov_len -
		    offset, length);

		int rv = (cipher)(ctx, uiop->uio_iov[vec_idx].iov_base + offset,
		    cur_len, output);

		if (rv != 0) {
			return (rv);
		}

		length -= cur_len;
		vec_idx++;
		offset = 0;
	}

	if (vec_idx == uiop->uio_iovcnt && length > 0) {
		/*
		 * The end of the specified iovec's was reached but
		 * the length requested could not be processed, i.e.
		 * The caller requested to digest more data than it provided.
		 */

		return (ERANGE);
	}

	return (0);
}

static int
crypto_uio_copy_to_data(crypto_data_t *data, uchar_t *buf, int len)
{
	uio_t *uiop = data->cd_uio;
	off_t offset = data->cd_offset;
	size_t length = len;
	uint_t vec_idx;
	size_t cur_len;
	uchar_t *datap;

	if (uiop->uio_segflg != UIO_SYSSPACE) {
		return (EINVAL);
	}

	/*
	 * Jump to the first iovec containing data to be
	 * processed.
	 */
	for (vec_idx = 0; vec_idx < uiop->uio_iovcnt &&
	    offset >= uiop->uio_iov[vec_idx].iov_len;
	    offset -= uiop->uio_iov[vec_idx++].iov_len)
		;

	if (vec_idx == uiop->uio_iovcnt && length > 0) {
		/*
		 * The caller specified an offset that is larger than
		 * the total size of the buffers it provided.
		 */
		return (ERANGE);
	}

	while (vec_idx < uiop->uio_iovcnt && length > 0) {
		cur_len = MIN(uiop->uio_iov[vec_idx].iov_len -
		    offset, length);

		datap = (uchar_t *)(uiop->uio_iov[vec_idx].iov_base +
		    offset);
		bcopy(buf, datap, cur_len);
		buf += cur_len;

		length -= cur_len;
		vec_idx++;
		offset = 0;
	}

	if (vec_idx == uiop->uio_iovcnt && length > 0) {
		/*
		 * The end of the specified iovec's was reached but
		 * the length requested could not be processed.
		 */
		data->cd_length = len;
		return (ENOSPC);
	}

	return (0);
}

int
crypto_put_output_data(uchar_t *buf, crypto_data_t *output, int len)
{
	return (crypto_uio_copy_to_data(output, buf, len));
}

static int
aes_decrypt_contiguous_blocks(void *ctx, char *data, size_t length,
    crypto_data_t *out)
{
	aes_ctx_t *aes_ctx = ctx;
	int rv = ENOTSUP;

	if (aes_ctx->ac_flags & CCM_MODE) {
		rv = ccm_mode_decrypt_contiguous_blocks(ctx, data, length,
		    out, AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);
	} else if (aes_ctx->ac_flags & GCM_MODE) {
		rv = gcm_mode_decrypt_contiguous_blocks(ctx, data, length,
		    out, AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);
	}
	return (rv);
}

int crypto_decrypt(crypto_mechanism_t *mechanism, crypto_data_t *ciphertext,
    crypto_key_t *key, crypto_data_t *plaintext)
{
	aes_ctx_t aes_ctx;
	off_t saved_offset;
	size_t saved_length;
	size_t length_needed;
	int rv;

	bzero(&aes_ctx, sizeof (aes_ctx_t));

	rv = aes_common_init_ctx(&aes_ctx, mechanism, key);
	if (rv != 0)
		return (rv);

	switch (mechanism->cm_type) {
	case AES_CCM_MECH_INFO_TYPE:
		length_needed = aes_ctx.ac_data_len;
		break;
	case AES_GCM_MECH_INFO_TYPE:
		length_needed = ciphertext->cd_length - aes_ctx.ac_tag_len;
		break;
	default:
		rv = ENOTSUP;
		goto out;
	}

	/* return size of buffer needed to store output */
	if (plaintext->cd_length < length_needed) {
		plaintext->cd_length = length_needed;
		rv = ENOSPC;
		goto out;
	}

	saved_offset = plaintext->cd_offset;
	saved_length = plaintext->cd_length;

	rv = crypto_update_uio(&aes_ctx, ciphertext, plaintext,
	    aes_decrypt_contiguous_blocks);

	if (rv == 0) {
		switch (mechanism->cm_type) {
		case AES_CCM_MECH_INFO_TYPE:
			rv = ccm_decrypt_final((ccm_ctx_t *)&aes_ctx,
			    plaintext, AES_BLOCK_LEN, aes_encrypt_block,
			    aes_copy_block, aes_xor_block);
			if (rv == 0 && ciphertext != plaintext) {
				plaintext->cd_length =
				    plaintext->cd_offset - saved_offset;
			} else {
				plaintext->cd_length = saved_length;
			}
			break;
		case AES_GCM_MECH_INFO_TYPE:
			rv = gcm_decrypt_final((gcm_ctx_t *)&aes_ctx,
			    plaintext, AES_BLOCK_LEN, aes_encrypt_block,
			    aes_xor_block);
			if (rv == 0 && ciphertext != plaintext) {
				plaintext->cd_length =
				    plaintext->cd_offset - saved_offset;
			} else {
				plaintext->cd_length = saved_length;
			}
			break;
		}
	} else {
		plaintext->cd_length = saved_length;
	}
	plaintext->cd_offset = saved_offset;
out:
	bzero(aes_ctx.ac_keysched, aes_ctx.ac_keysched_len);
	free(aes_ctx.ac_keysched);

	if (aes_ctx.ac_flags & CCM_MODE) {
		if (aes_ctx.ac_pt_buf != NULL) {
			free(aes_ctx.ac_pt_buf);
		}
	}
	if (aes_ctx.ac_flags & GCM_MODE) {
		if (((gcm_ctx_t *)&aes_ctx)->gcm_pt_buf != NULL) {
			free(((gcm_ctx_t *)&aes_ctx)->gcm_pt_buf);
		}
	}

	return (rv);
}
