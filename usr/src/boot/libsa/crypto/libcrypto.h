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
 * Copyright 2019 Toomas Soome <tsoome@me.com>
 */

#ifndef _LIBCRYPTO_H
#define	_LIBCRYPTO_H

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/sysmacros.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct uio uio_t;
typedef struct iovec iovec_t;
typedef void *crypto_context_t;

#define	SHA512_DIGEST_LENGTH	64

typedef enum sha2_mech_type {
	SHA256_MECH_INFO_TYPE,		/* SUN_CKM_SHA256 */
	SHA256_HMAC_MECH_INFO_TYPE,	/* SUN_CKM_SHA256_HMAC */
	SHA256_HMAC_GEN_MECH_INFO_TYPE,	/* SUN_CKM_SHA256_HMAC_GENERAL */
	SHA384_MECH_INFO_TYPE,		/* SUN_CKM_SHA384 */
	SHA384_HMAC_MECH_INFO_TYPE,	/* SUN_CKM_SHA384_HMAC */
	SHA384_HMAC_GEN_MECH_INFO_TYPE,	/* SUN_CKM_SHA384_HMAC_GENERAL */
	SHA512_MECH_INFO_TYPE,		/* SUN_CKM_SHA512 */
	SHA512_HMAC_MECH_INFO_TYPE,	/* SUN_CKM_SHA512_HMAC */
	SHA512_HMAC_GEN_MECH_INFO_TYPE,	/* SUN_CKM_SHA512_HMAC_GENERAL */
	SHA512_224_MECH_INFO_TYPE,	/* SUN_CKM_SHA512_224 */
	SHA512_256_MECH_INFO_TYPE	/* SUN_CKM_SHA512_256 */
} sha2_mech_type_t;

/*
 * Raw key lengths are expressed in number of bits.
 * The following macro returns the minimum number of
 * bytes that can contain the specified number of bits.
 * Round up without overflowing the integer type.
 */
#define	CRYPTO_BITS2BYTES(n)	((n) == 0 ? 0 : (((n) - 1) >> 3) + 1)
#define	CRYPTO_BYTES2BITS(n)	((n) << 3)

typedef struct crypto_mechanism {
	int		cm_type;
	char		*cm_param;
	size_t		cm_param_len;
} crypto_mechanism_t;

typedef enum crypto_data_format {
	CRYPTO_DATA_RAW = 1,
	CRYPTO_DATA_UIO,
	CRYPTO_DATA_MBLK
} crypto_data_format_t;

typedef struct crypto_data {
	crypto_data_format_t cd_format;
	off_t		cd_offset;
	size_t		cd_length;
	char		*cd_miscdata;
	union {
		/* Raw format */
		iovec_t cdu_raw;	/* Pointer and length */

		/* uio scatter-gather format */
		uio_t	*cdu_uio;
	} cdu;	/* Crypto Data Union */
} crypto_data_t;

#define	cd_raw		cdu.cdu_raw
#define	cd_uio		cdu.cdu_uio
#define	cd_mp		cdu.cdu_mp

typedef enum {
	CRYPTO_KEY_RAW = 1,	/* ck_data is a cleartext key */
	CRYPTO_KEY_REFERENCE,	/* ck_obj_id is an opaque reference */
	CRYPTO_KEY_ATTR_LIST	/* ck_attrs is a list of object attributes */
} crypto_key_format_t;

typedef struct crypto_key {
	crypto_key_format_t	ck_format;	/* format identifier */
	void	*ck_data;
	size_t	ck_length;
} crypto_key_t;

/* CK_AES_CCM_PARAMS provides parameters to the CKM_AES_CCM mechanism */
typedef struct CK_AES_CCM_PARAMS {
	ulong_t ulMACSize;
	ulong_t ulNonceSize;
	ulong_t ulAuthDataSize;
	ulong_t ulDataSize; /* used for plaintext or ciphertext */
	uchar_t *nonce;
	uchar_t *authData;
} CK_AES_CCM_PARAMS;

/* CK_AES_GCM_PARAMS provides parameters to the CKM_AES_GCM mechanism */
typedef struct CK_AES_GCM_PARAMS {
	uchar_t *pIv;
	ulong_t ulIvLen;
	ulong_t ulIvBits;
	uchar_t *pAAD;
	ulong_t ulAADLen;
	ulong_t ulTagBits;
} CK_AES_GCM_PARAMS;

/* CK_AES_GMAC_PARAMS provides parameters to the CKM_AES_GMAC mechanism */
typedef struct CK_AES_GMAC_PARAMS {
	uchar_t *pIv;
	uchar_t *pAAD;
	ulong_t ulAADLen;
} CK_AES_GMAC_PARAMS;

#define	ECB_MODE	0x00000002
#define	CBC_MODE	0x00000004
#define	CTR_MODE	0x00000008
#define	CCM_MODE	0x00000010
#define	GCM_MODE	0x00000020
#define	GMAC_MODE	0x00000040
#define	CMAC_MODE	0x00000080

typedef enum aes_mech_type {
	AES_CCM_MECH_INFO_TYPE = 1,	/* SUN_CKM_AES_CCM */
	AES_GCM_MECH_INFO_TYPE		/* SUN_CKM_AES_GCM */
} aes_mech_type_t;

typedef struct common_ctx {
	void *cc_keysched;
	size_t cc_keysched_len;
	uint64_t cc_iv[2];
	uint64_t cc_remainder[2];
	size_t cc_remainder_len;
	uint8_t *cc_lastp;
	uint8_t *cc_copy_to;
	uint32_t cc_flags;
} common_ctx_t;

typedef struct ccm_ctx {
	common_ctx_t ccm_common;
	uint32_t ccm_tmp[4];
	size_t ccm_mac_len;
	uint64_t ccm_mac_buf[2];
	size_t ccm_data_len;
	size_t ccm_processed_data_len;
	size_t ccm_processed_mac_len;
	uint8_t *ccm_pt_buf;
	uint64_t ccm_mac_input_buf[2];
	uint64_t ccm_counter_mask;
} ccm_ctx_t;

#define	ccm_keysched		ccm_common.cc_keysched
#define	ccm_keysched_len	ccm_common.cc_keysched_len
#define	ccm_cb			ccm_common.cc_iv
#define	ccm_remainder		ccm_common.cc_remainder
#define	ccm_remainder_len	ccm_common.cc_remainder_len
#define	ccm_lastp		ccm_common.cc_lastp
#define	ccm_copy_to		ccm_common.cc_copy_to
#define	ccm_flags		ccm_common.cc_flags

typedef struct gcm_ctx {
	common_ctx_t gcm_common;
	size_t gcm_tag_len;
	size_t gcm_processed_data_len;
	size_t gcm_pt_buf_len;
	uint32_t gcm_tmp[4];
	uint64_t gcm_ghash[2];
	uint64_t gcm_H[2];
	uint64_t gcm_J0[2];
	uint64_t gcm_len_a_len_c[2];
	uint8_t *gcm_pt_buf;
} gcm_ctx_t;

#define	gcm_keysched		gcm_common.cc_keysched
#define	gcm_keysched_len	gcm_common.cc_keysched_len
#define	gcm_cb			gcm_common.cc_iv
#define	gcm_remainder		gcm_common.cc_remainder
#define	gcm_remainder_len	gcm_common.cc_remainder_len
#define	gcm_lastp		gcm_common.cc_lastp
#define	gcm_copy_to		gcm_common.cc_copy_to
#define	gcm_flags		gcm_common.cc_flags

#define	AES_GMAC_IV_LEN		12
#define	AES_GMAC_TAG_BITS	128

typedef struct aes_ctx {
	union {
		common_ctx_t acu_common;
		ccm_ctx_t acu_ccm;
		gcm_ctx_t acu_gcm;
	} acu;
} aes_ctx_t;

#define	ac_flags		acu.acu_common.cc_flags
#define	ac_remainder_len	acu.acu_common.cc_remainder_len
#define	ac_remainder		acu.acu_common.cc_remainder
#define	ac_keysched		acu.acu_common.cc_keysched
#define	ac_keysched_len		acu.acu_common.cc_keysched_len
#define	ac_iv			acu.acu_common.cc_iv
#define	ac_lastp		acu.acu_common.cc_lastp
#define	ac_pt_buf		acu.acu_ccm.ccm_pt_buf
#define	ac_mac_len		acu.acu_ccm.ccm_mac_len
#define	ac_data_len		acu.acu_ccm.ccm_data_len
#define	ac_processed_mac_len	acu.acu_ccm.ccm_processed_mac_len
#define	ac_processed_data_len	acu.acu_ccm.ccm_processed_data_len
#define	ac_tag_len		acu.acu_gcm.gcm_tag_len

static inline uint64_t
htonll(uint64_t value)
{
	return (htonl(value >> 32) | ((uint64_t)htonl(value) << 32));
}

static inline uint64_t
ntohll(uint64_t in)
{
	return ((uint64_t)ntohl((in >> 32) & 0xffffffff) |
	    ((uint64_t)ntohl(in & 0xffffffff) << 32));
}

extern int crypto_put_output_data(uchar_t *, crypto_data_t *, int);
extern int crypto_decrypt(crypto_mechanism_t *, crypto_data_t *,
    crypto_key_t *, crypto_data_t *);

extern int ccm_mode_decrypt_contiguous_blocks(ccm_ctx_t *, char *, size_t,
    crypto_data_t *, size_t,
    int (*)(const void *, const uint8_t *, uint8_t *),
    void (*)(uint8_t *, uint8_t *),
    void (*)(uint8_t *, uint8_t *));
extern int ccm_decrypt_final(ccm_ctx_t *, crypto_data_t *, size_t,
    int (*)(const void *, const uint8_t *, uint8_t *),
    void (*)(uint8_t *, uint8_t *),
    void (*)(uint8_t *, uint8_t *));
extern int ccm_init_ctx(ccm_ctx_t *, char *, size_t,
    int (*)(const void *, const uint8_t *, uint8_t *),
    void (*)(uint8_t *, uint8_t *));

extern int gcm_mode_decrypt_contiguous_blocks(gcm_ctx_t *, char *, size_t,
    crypto_data_t *, size_t,
    int (*)(const void *, const uint8_t *, uint8_t *),
    void (*)(uint8_t *, uint8_t *),
    void (*)(uint8_t *, uint8_t *));
extern int gcm_decrypt_final(gcm_ctx_t *, crypto_data_t *, size_t,
    int (*)(const void *, const uint8_t *, uint8_t *),
    void (*)(uint8_t *, uint8_t *));
extern int gcm_init_ctx(gcm_ctx_t *, char *, size_t,
    int (*)(const void *, const uint8_t *, uint8_t *),
    void (*)(uint8_t *, uint8_t *),
    void (*)(uint8_t *, uint8_t *));

extern int crypto_mac(crypto_mechanism_t *, crypto_data_t *,
    crypto_key_t *, crypto_data_t *);
extern int crypto_mac_init(crypto_mechanism_t *, crypto_key_t *,
    crypto_context_t *);
extern int crypto_mac_update(crypto_context_t, crypto_data_t *);
extern int crypto_mac_final(crypto_context_t, crypto_data_t *);

extern void sha1(void *, size_t, uint8_t *);
extern int sha2_mac(crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *);
extern int sha2_mac_init(crypto_mechanism_t *, crypto_key_t *,
    crypto_context_t *);
extern int sha2_mac_update(crypto_context_t, crypto_data_t *);
extern int sha2_mac_final(crypto_context_t, crypto_data_t *);
extern int pkcs5_pbkdf2(const uint8_t *, size_t, const uint8_t *,
    size_t, uint8_t *, size_t, unsigned int);

#ifdef __cplusplus
}
#endif

#endif /* _LIBCRYPTO_H */
