/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 *  lws_genec provides an EC abstraction api in lws that works the
 *  same whether you are using openssl or OpenHiTLS crypto functions underneath.
 */
#include "private-lib-core.h"
#include "private.h"
#include "crypt_eal_rand.h"

/* OpenHiTLS combined ECDSA+SHA512 algorithm for P-521 support */
#ifndef CRYPT_PKEY_ECDSAWITHSHA512
#define CRYPT_PKEY_ECDSAWITHSHA512 BSL_CID_ECDSAWITHSHA512
#endif

/* Random number generator initialization state */
static int rand_initialized = 0;

/*
 * Convert ECDSA signature from JWS format (raw concatenated r || s) to DER format.
 * JWS format: r (keybytes) + s (keybytes)
 * DER format: SEQUENCE { INTEGER r, INTEGER s }
 *
 * Returns the length of DER signature, or -1 on error.
 */
static int
lws_ecdsa_sig_jws_to_der(const uint8_t *jws_sig, int keybytes, uint8_t *der_sig, int der_len)
{
	/* Use stack buffers large enough for P-521 (66 bytes + 1 for leading zero + padding) */
	uint8_t r[128], s[128];
	int r_len, s_len, offset = 0;
	const uint8_t *jws_r = jws_sig;
	const uint8_t *jws_s = jws_sig + keybytes;

	/* In JWS format, r and s are always exactly keybytes long (no leading zeros)
	 * We need to convert to DER format which may require leading zeros */

	/* Process r: if MSB is set, add leading zero */
	if (jws_r[0] & 0x80) {
		r[0] = 0;
		memcpy(r + 1, jws_r, (size_t)keybytes);
		r_len = keybytes + 1;
	} else {
		/* Skip leading zeros to minimize encoding */
		int skip = 0;
		while (skip < keybytes - 1 && jws_r[skip] == 0) {
			skip++;
		}
		/* Check if we need leading zero after skipping */
		if (jws_r[skip] & 0x80) {
			r[0] = 0;
			memcpy(r + 1, jws_r + skip, (size_t)(keybytes - skip));
			r_len = keybytes - skip + 1;
		} else {
			memcpy(r, jws_r + skip, (size_t)(keybytes - skip));
			r_len = keybytes - skip;
		}
	}

	/* Process s: if MSB is set, add leading zero */
	if (jws_s[0] & 0x80) {
		s[0] = 0;
		memcpy(s + 1, jws_s, (size_t)keybytes);
		s_len = keybytes + 1;
	} else {
		/* Skip leading zeros to minimize encoding */
		int skip = 0;
		while (skip < keybytes - 1 && jws_s[skip] == 0) {
			skip++;
		}
		/* Check if we need leading zero after skipping */
		if (jws_s[skip] & 0x80) {
			s[0] = 0;
			memcpy(s + 1, jws_s + skip, (size_t)(keybytes - skip));
			s_len = keybytes - skip + 1;
		} else {
			memcpy(s, jws_s + skip, (size_t)(keybytes - skip));
			s_len = keybytes - skip;
		}
	}

	/* DER encode: SEQUENCE { INTEGER r, INTEGER s } */
	if (offset < der_len)
		der_sig[offset++] = 0x30; /* SEQUENCE tag */

	/* Calculate total length: r_len + s_len + tag bytes + length bytes */
	int int_r_len_len = (r_len >= 128) ? 2 : 1; /* INTEGER length bytes for r */
	int int_s_len_len = (s_len >= 128) ? 2 : 1; /* INTEGER length bytes for s */
	int total_len = r_len + s_len + 2 + int_r_len_len + int_s_len_len; /* +2 for INTEGER tags */
	/* Handle long form length if needed */
	if (total_len >= 128) {
		if (offset < der_len)
			der_sig[offset++] = 0x81;
		if (offset < der_len)
			der_sig[offset++] = (uint8_t)total_len;
	} else {
		if (offset < der_len)
			der_sig[offset++] = (uint8_t)total_len;
	}

	/* Encode r */
	if (offset < der_len)
		der_sig[offset++] = 0x02; /* INTEGER tag */
	/* Handle long form length for r if needed */
	if (r_len >= 128) {
		if (offset < der_len)
			der_sig[offset++] = 0x81;
		if (offset < der_len)
			der_sig[offset++] = (uint8_t)r_len;
	} else {
		if (offset < der_len)
			der_sig[offset++] = (uint8_t)r_len;
	}
	if (offset + r_len <= der_len)
		memcpy(der_sig + offset, r, (size_t)r_len);
	offset += r_len;

	/* Encode s */
	if (offset < der_len)
		der_sig[offset++] = 0x02; /* INTEGER tag */
	/* Handle long form length for s if needed */
	if (s_len >= 128) {
		if (offset < der_len)
			der_sig[offset++] = 0x81;
		if (offset < der_len)
			der_sig[offset++] = (uint8_t)s_len;
	} else {
		if (offset < der_len)
			der_sig[offset++] = (uint8_t)s_len;
	}
	if (offset + s_len <= der_len)
		memcpy(der_sig + offset, s, (size_t)s_len);
	offset += s_len;

	return offset;
}

/* Initialize OpenHiTLS random number generator if not already done
 * This is exported for use by lws-genrsa.c as well */
int lws_hitls_init_rand(void)
{
	if (rand_initialized)
		return 0;

	/*
	 * Prefer OpenHiTLS CTR-DRBG path and tolerate repeat init from
	 * other callsites.
	 */
	int32_t ret = CRYPT_EAL_RandInit(CRYPT_RAND_AES256_CTR, NULL, NULL,
					 NULL, 0);
	if (ret == CRYPT_SUCCESS || ret == CRYPT_EAL_ERR_DRBG_REPEAT_INIT) {
		rand_initialized = 1;
		return 0;
	}

	lwsl_err("%s: CRYPT_EAL_RandInit failed: %d\n", __func__, ret);
	return -1;
}

const struct lws_ec_curves lws_ec_curves[4] = {
	{ "P-256", CRYPT_ECC_NISTP256, 32 },
	{ "P-384", CRYPT_ECC_NISTP384,  48 },
	{ "P-521", CRYPT_ECC_NISTP521,  66 },
	{ NULL, 0, 0 }
};

int
lws_genecdh_create(struct lws_genec_ctx *ctx, struct lws_context *context,
		   const struct lws_ec_curves *curve_table)
{
	ctx->context = context;
	ctx->ctx[0] = NULL;
	ctx->ctx[1] = NULL;
	/* Use OpenHiTLS curve table if NULL is passed */
	ctx->curve_table = curve_table ? curve_table : lws_ec_curves;
	ctx->genec_alg = LEGENEC_ECDH;

	return 0;
}

int
lws_genecdsa_create(struct lws_genec_ctx *ctx, struct lws_context *context,
		    const struct lws_ec_curves *curve_table)
{
	ctx->context = context;
	ctx->ctx[0] = NULL;
	ctx->ctx[1] = NULL;
	/* Use OpenHiTLS curve table if NULL is passed */
	ctx->curve_table = curve_table ? curve_table : lws_ec_curves;
	ctx->genec_alg = LEGENEC_ECDSA;

	return 0;
}

static int
lws_genec_keypair_import(struct lws_genec_ctx *ctx,
		         const struct lws_ec_curves *curve_table,
		         CRYPT_EAL_PkeyCtx **pctx,
		         const struct lws_gencrypto_keyelem *el)
{
	const struct lws_ec_curves *curve;
	CRYPT_PKEY_ParaId curveId;
	CRYPT_PKEY_AlgId pkeyAlg;
	CRYPT_EAL_PkeyPub pubKey = {0};
	CRYPT_EAL_PkeyPrv prvKey = {0};
	CRYPT_EccPrv *eccPrv = &prvKey.key.eccPrv;
	uint8_t *pubKeyBuf = NULL;
	int ret;
	int have_private_key = !!el[LWS_GENCRYPTO_EC_KEYEL_D].len;

	/* Validate curve name */
	if (el[LWS_GENCRYPTO_EC_KEYEL_CRV].len < 4)
		return -2;

	curve = lws_genec_curve(curve_table,
				(char *)el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf);
	if (!curve)
		return -3;

	/* Validate key element lengths */
	if ((el[LWS_GENCRYPTO_EC_KEYEL_D].len &&
	     el[LWS_GENCRYPTO_EC_KEYEL_D].len != curve->key_bytes) ||
	    el[LWS_GENCRYPTO_EC_KEYEL_X].len != curve->key_bytes ||
	    el[LWS_GENCRYPTO_EC_KEYEL_Y].len != curve->key_bytes) {
		lwsl_notice("%s: key length mismatch: curve=%s key_bytes=%d, D.len=%d, X.len=%d, Y.len=%d\n",
			    __func__, curve->name, curve->key_bytes,
			    (int)el[LWS_GENCRYPTO_EC_KEYEL_D].len,
			    (int)el[LWS_GENCRYPTO_EC_KEYEL_X].len,
			    (int)el[LWS_GENCRYPTO_EC_KEYEL_Y].len);
		return -4;
	}

	ctx->has_private = (char)have_private_key;

	/* Determine algorithm based on context */
	pkeyAlg = (ctx->genec_alg == LEGENEC_ECDSA) ?
		  CRYPT_PKEY_ECDSA : CRYPT_PKEY_ECDH;

	/* For P-521, use combined ECDSA+SHA512 algorithm if available */
	if (ctx->genec_alg == LEGENEC_ECDSA &&
	    (int)curve->tls_lib_nid == CRYPT_ECC_NISTP521) {
		lwsl_notice("%s: P-521 detected, trying CRYPT_PKEY_ECDSAWITHSHA512\n", __func__);
		pkeyAlg = (CRYPT_PKEY_AlgId)CRYPT_PKEY_ECDSAWITHSHA512;
	}

	*pctx = CRYPT_EAL_PkeyNewCtx(pkeyAlg);
	if (!*pctx) {
		lwsl_err("%s: CRYPT_EAL_PkeyNewCtx failed for alg %d\n", __func__, (int)pkeyAlg);
		/* Try falling back to regular ECDSA */
		if ((int)pkeyAlg == CRYPT_PKEY_ECDSAWITHSHA512) {
			lwsl_notice("%s: Falling back to CRYPT_PKEY_ECDSA\n", __func__);
			pkeyAlg = CRYPT_PKEY_ECDSA;
			*pctx = CRYPT_EAL_PkeyNewCtx(pkeyAlg);
			if (!*pctx) {
				lwsl_err("%s: CRYPT_EAL_PkeyNewCtx (fallback) failed\n", __func__);
				return -5;
			}
		} else {
			return -5;
		}
	}

	/* Set the curve */
	curveId = (CRYPT_PKEY_ParaId)curve->tls_lib_nid;
	ret = CRYPT_EAL_PkeySetParaById(*pctx, curveId);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeySetParaById failed: %d\n", __func__, ret);
		goto bail;
	}

	/* Build uncompressed public key point: 0x04 || X || Y */
	pubKeyBuf = lws_malloc((uint32_t)curve->key_bytes * 2 + 1, "ec-pub-import");
	if (!pubKeyBuf) {
		lwsl_err("%s: OOM allocating public key buffer\n", __func__);
		goto bail;
	}
	pubKeyBuf[0] = 0x04; /* Uncompressed point indicator */
	memcpy(pubKeyBuf + 1, el[LWS_GENCRYPTO_EC_KEYEL_X].buf, (size_t)curve->key_bytes);
	memcpy(pubKeyBuf + 1 + curve->key_bytes, el[LWS_GENCRYPTO_EC_KEYEL_Y].buf, (size_t)curve->key_bytes);

	/* Set public key */
	pubKey.id = pkeyAlg;
	pubKey.key.eccPub.data = pubKeyBuf;
	pubKey.key.eccPub.len = (uint32_t)curve->key_bytes * 2 + 1;

	ret = CRYPT_EAL_PkeySetPub(*pctx, &pubKey);
	lws_free(pubKeyBuf);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeySetPub failed: %d\n", __func__, ret);
		goto bail;
	}

	/* Set private key if present and needed for signing
	 * For verification, we only need the public key */
	if (have_private_key) {
		prvKey.id = pkeyAlg;
		eccPrv->data = (uint8_t *)el[LWS_GENCRYPTO_EC_KEYEL_D].buf;
		eccPrv->len = (uint32_t)el[LWS_GENCRYPTO_EC_KEYEL_D].len;

		ret = CRYPT_EAL_PkeySetPrv(*pctx, &prvKey);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CRYPT_EAL_PkeySetPrv failed: %d\n", __func__, ret);
			goto bail;
		}
	}

	return 0;

bail:
	CRYPT_EAL_PkeyFreeCtx(*pctx);
	*pctx = NULL;
	return -9;
}

int
lws_genecdh_set_key(struct lws_genec_ctx *ctx, const struct lws_gencrypto_keyelem *el,
		    enum enum_lws_dh_side side)
{
	if (ctx->genec_alg != LEGENEC_ECDH)
		return -1;

	return lws_genec_keypair_import(ctx, ctx->curve_table, &ctx->ctx[side], el);
}

int
lws_genecdsa_set_key(struct lws_genec_ctx *ctx,
		     const struct lws_gencrypto_keyelem *el)
{
	if (ctx->genec_alg != LEGENEC_ECDSA)
		return -1;

	return lws_genec_keypair_import(ctx, ctx->curve_table, &ctx->ctx[0], el);
}

void
lws_genec_destroy(struct lws_genec_ctx *ctx)
{
	if (ctx->ctx[0])
		CRYPT_EAL_PkeyFreeCtx(ctx->ctx[0]);
	if (ctx->ctx[1])
		CRYPT_EAL_PkeyFreeCtx(ctx->ctx[1]);
	ctx->ctx[0] = NULL;
	ctx->ctx[1] = NULL;
}

int
lws_genecdh_new_keypair(struct lws_genec_ctx *ctx, enum enum_lws_dh_side side,
			const char *curve_name,
			struct lws_gencrypto_keyelem *el)
{
	const struct lws_ec_curves *curve;
	CRYPT_PKEY_ParaId curveId;
	CRYPT_PKEY_AlgId pkeyAlg;
	CRYPT_EAL_PkeyPub pubKey = {0};
	CRYPT_EAL_PkeyPrv prvKey = {0};
	CRYPT_EccPrv *eccPrv = &prvKey.key.eccPrv;
	int ret;
	int n;

	if (ctx->genec_alg != LEGENEC_ECDH && ctx->genec_alg != LEGENEC_ECDSA)
		return -1;

	/* Initialize random number generator if needed */
	if (lws_hitls_init_rand() < 0)
		return -1;

	curve = lws_genec_curve(ctx->curve_table, curve_name);
	if (!curve) {
		lwsl_err("%s: curve '%s' not supported\n",
			 __func__, curve_name);
		return -22;
	}

	/* Create appropriate pkey context based on algorithm type */
	pkeyAlg = (ctx->genec_alg == LEGENEC_ECDSA) ?
		  CRYPT_PKEY_ECDSA : CRYPT_PKEY_ECDH;
	ctx->ctx[side] = CRYPT_EAL_PkeyNewCtx(pkeyAlg);
	if (!ctx->ctx[side]) {
		lwsl_err("%s: CRYPT_EAL_PkeyNewCtx failed\n", __func__);
		return -23;
	}

	/* Set the curve using the simpler API */
	curveId = (CRYPT_PKEY_ParaId)curve->tls_lib_nid;
	ret = CRYPT_EAL_PkeySetParaById(ctx->ctx[side], curveId);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeySetParaById failed: %d\n", __func__, ret);
		goto bail;
	}

	/* Generate the key */
	ret = CRYPT_EAL_PkeyGen(ctx->ctx[side]);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyGen failed: %d\n", __func__, ret);
		goto bail;
	}

	/* Extract the key elements
	 * Need to allocate buffers for the output */
	pubKey.id = pkeyAlg;
	prvKey.id = pkeyAlg;

	/* Allocate buffer for public key (uncompressed point is 65 bytes for P-256) */
	uint32_t pubKeyLen = (uint32_t)curve->key_bytes * 2 + 1; /* Uncompressed format: 0x04 + X + Y */
	uint8_t *pubKeyBuf = lws_malloc(pubKeyLen, "ec-pub");
	if (!pubKeyBuf) {
		lwsl_err("%s: OOM allocating public key buffer\n", __func__);
		goto bail;
	}
	pubKey.key.eccPub.data = pubKeyBuf;
	pubKey.key.eccPub.len = pubKeyLen;

	/* Allocate buffer for private key */
	uint8_t *prvKeyBuf = lws_malloc((uint32_t)curve->key_bytes, "ec-prv");
	if (!prvKeyBuf) {
		lwsl_err("%s: OOM allocating private key buffer\n", __func__);
		lws_free(pubKeyBuf);
		goto bail;
	}
	eccPrv->data = prvKeyBuf;
	eccPrv->len = (uint32_t)curve->key_bytes;

	ret = CRYPT_EAL_PkeyGetPub(ctx->ctx[side], &pubKey);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyGetPub failed: %d\n", __func__, ret);
		lws_free(pubKeyBuf);
		lws_free(prvKeyBuf);
		goto bail;
	}

	ret = CRYPT_EAL_PkeyGetPrv(ctx->ctx[side], &prvKey);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyGetPrv failed: %d\n", __func__, ret);
		lws_free(pubKeyBuf);
		lws_free(prvKeyBuf);
		goto bail;
	}

	/* Copy curve name */
	el[LWS_GENCRYPTO_EC_KEYEL_CRV].len = (uint32_t)strlen(curve_name) + 1;
	el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf = lws_malloc(el[LWS_GENCRYPTO_EC_KEYEL_CRV].len, "ec");
	if (!el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf) {
		lwsl_err("%s: OOM\n", __func__);
		lws_free(pubKeyBuf);
		lws_free(prvKeyBuf);
		goto bail;
	}
	strcpy((char *)el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf, curve_name);

	/* Private key - the buffer was already filled by CRYPT_EAL_PkeyGetPrv */
	el[LWS_GENCRYPTO_EC_KEYEL_D].len = eccPrv->len;
	el[LWS_GENCRYPTO_EC_KEYEL_D].buf = prvKeyBuf;  /* Take ownership */

	/* Public key is in serialized format (uncompressed point: 0x04 || X || Y)
	 * Parse out X and Y coordinates */
	if (pubKey.key.eccPub.len > 1 && pubKey.key.eccPub.data[0] == 0x04) {
		/* Uncompressed format */
		uint32_t coordLen = (pubKey.key.eccPub.len - 1) / 2;
		uint8_t *x = lws_malloc(coordLen, "ec-x");
		uint8_t *y = lws_malloc(coordLen, "ec-y");
		if (x && y) {
			memcpy(x, pubKey.key.eccPub.data + 1, coordLen);
			memcpy(y, pubKey.key.eccPub.data + 1 + coordLen, coordLen);
			el[LWS_GENCRYPTO_EC_KEYEL_X].len = coordLen;
			el[LWS_GENCRYPTO_EC_KEYEL_X].buf = x;
			el[LWS_GENCRYPTO_EC_KEYEL_Y].len = coordLen;
			el[LWS_GENCRYPTO_EC_KEYEL_Y].buf = y;
		} else {
			lws_free(x);
			lws_free(y);
			lws_free(pubKeyBuf);
			el[LWS_GENCRYPTO_EC_KEYEL_X].len = 0;
			el[LWS_GENCRYPTO_EC_KEYEL_X].buf = NULL;
			el[LWS_GENCRYPTO_EC_KEYEL_Y].len = 0;
			el[LWS_GENCRYPTO_EC_KEYEL_Y].buf = NULL;
		}
	} else {
		/* Compressed or unknown format - store as-is for now */
		el[LWS_GENCRYPTO_EC_KEYEL_X].len = 0;
		el[LWS_GENCRYPTO_EC_KEYEL_X].buf = NULL;
		el[LWS_GENCRYPTO_EC_KEYEL_Y].len = 0;
		el[LWS_GENCRYPTO_EC_KEYEL_Y].buf = NULL;
	}
	lws_free(pubKeyBuf);  /* Free the temp public key buffer */

	ctx->has_private = 1;

	return 0;

bail:
	for (n = LWS_GENCRYPTO_EC_KEYEL_CRV; n < LWS_GENCRYPTO_EC_KEYEL_COUNT; n++)
		if (el[n].buf)
			lws_free_set_NULL(el[n].buf);

	CRYPT_EAL_PkeyFreeCtx(ctx->ctx[side]);
	ctx->ctx[side] = NULL;

	return -1;
}

int
lws_genecdsa_new_keypair(struct lws_genec_ctx *ctx, const char *curve_name,
			 struct lws_gencrypto_keyelem *el)
{
	if (ctx->genec_alg != LEGENEC_ECDSA)
		return -1;

	return lws_genecdh_new_keypair(ctx, LDHS_OURS, curve_name, el);
}

int
lws_genecdsa_hash_sign_jws(struct lws_genec_ctx *ctx, const uint8_t *in,
			   enum lws_genhash_types hash_type, int keybits,
			   uint8_t *sig, size_t sig_len)
{
	uint32_t outLen;
	int ret;
	int keybytes = lws_gencrypto_bits_to_bytes(keybits);
	uint8_t der_buf[256]; /* Buffer for DER-encoded signature - increased for P-521 */
	uint8_t *der_p = der_buf;
	const uint8_t *r_val, *s_val;

	if (ctx->genec_alg != LEGENEC_ECDSA) {
		lwsl_notice("%s: ctx alg %d\n", __func__, ctx->genec_alg);
		return -1;
	}

	if (!ctx->has_private)
		return -1;

	/* Initialize random number generator for ECDSA signing */
	if (lws_hitls_init_rand() < 0) {
		lwsl_err("%s: failed to init random number generator\n", __func__);
		return -1;
	}

	if ((int)sig_len != keybytes * 2) {
		lwsl_notice("%s: sig buff %d < expected\n", __func__, (int)sig_len);
		return -1;
	}

	/* Sign into temporary buffer - OpenHiTLS returns DER-encoded signature */
	outLen = sizeof(der_buf);

	/* OpenHiTLS native ECDSA sign */
	ret = CRYPT_EAL_PkeySignData(ctx->ctx[0], in,
				     (uint32_t)lws_genhash_size(hash_type),
				     der_buf, &outLen);

	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: ECDSA signing failed (error %d)\n", __func__, ret);
		return -1;
	}

	/* Parse DER signature: SEQUENCE { INTEGER r, INTEGER s }
	 * and convert to JWS format (raw r || s concatenation) */

	/* Skip SEQUENCE tag and length */
	if (outLen < 2 || der_buf[0] != 0x30) {
		lwsl_err("%s: invalid DER signature format\n", __func__);
		return -1;
	}

	der_p++; /* Skip SEQUENCE tag */
	unsigned int len_byte = *der_p;
	der_p++;
	if (len_byte >= 0x80) {
		/* Long form length encoding */
		int num_len_bytes = len_byte & 0x7F;
		if (num_len_bytes > 2 || num_len_bytes < 1) {
			lwsl_err("%s: invalid DER length encoding\n", __func__);
			return -1;
		}
		/* Read the length value */
		if (num_len_bytes == 1) {
			len_byte = *der_p;
			der_p++;
		} else { /* num_len_bytes == 2 */
			len_byte = ((unsigned int)der_p[0] << 8) |
				   (unsigned int)der_p[1];
			der_p += 2;
		}
	}

	/* Parse INTEGER r */
	if ((size_t)(der_p - der_buf) >= outLen || *der_p != 0x02) {
		lwsl_err("%s: expected INTEGER tag for r\n", __func__);
		return -1;
	}
	der_p++; /* Skip INTEGER tag */
	uint8_t r_len_byte = *der_p;
	der_p++; /* Skip length byte */
	int r_len = r_len_byte;
	if (r_len_byte >= 0x80) {
		/* Long form length for INTEGER r */
		int num_len_bytes = r_len_byte & 0x7F;
		if (num_len_bytes > 1) {
			lwsl_err("%s: r length too large\n", __func__);
			return -1;
		}
		r_len = *der_p;
		der_p++;
	}
	/* Bounds check */
	if (der_p + r_len > der_buf + outLen) {
		lwsl_err("%s: r value exceeds DER buffer\n", __func__);
		return -1;
	}
	r_val = der_p;
	/* Skip leading zero if present */
	if (r_len > 0 && r_val[0] == 0) {
		r_val++;
		r_len--;
	}
	der_p += (r_val - der_p) + r_len;

	/* Parse INTEGER s */
	if ((size_t)(der_p - der_buf) >= outLen || *der_p != 0x02) {
		lwsl_err("%s: expected INTEGER tag for s\n", __func__);
		return -1;
	}
	der_p++; /* Skip INTEGER tag */
	uint8_t s_len_byte = *der_p;
	der_p++; /* Skip length byte */
	int s_len = s_len_byte;
	if (s_len_byte >= 0x80) {
		/* Long form length for INTEGER s */
		int num_len_bytes = s_len_byte & 0x7F;
		if (num_len_bytes > 1) {
			lwsl_err("%s: s length too large\n", __func__);
			return -1;
		}
		s_len = *der_p;
		der_p++;
	}
	/* Bounds check */
	if (der_p + s_len > der_buf + outLen) {
		lwsl_err("%s: s value exceeds DER buffer\n", __func__);
		return -1;
	}
	s_val = der_p;
	/* Skip leading zero if present */
	if (s_len > 0 && s_val[0] == 0) {
		s_val++;
		s_len--;
	}

	/* Verify lengths match expected keybytes */
	if (r_len > keybytes || s_len > keybytes) {
		lwsl_err("%s: r or s length exceeds keybytes\n", __func__);
		return -1;
	}

	/* Copy r and s to output buffer with proper padding */
	memset(sig, 0, sig_len);
	memcpy(sig + (keybytes - r_len), r_val, (size_t)r_len);
	memcpy(sig + keybytes + (keybytes - s_len), s_val, (size_t)s_len);

	return 0;
}

int
lws_genecdsa_hash_sig_verify_jws(struct lws_genec_ctx *ctx, const uint8_t *in,
				 enum lws_genhash_types hash_type, int keybits,
				 const uint8_t *sig, size_t sig_len)
{
	int ret;
	int keybytes = lws_gencrypto_bits_to_bytes(keybits);

	if (ctx->genec_alg != LEGENEC_ECDSA)
		return -1;

	if ((int)sig_len != keybytes * 2) {
		lwsl_err("%s: sig buf size %d vs expected\n", __func__,
			 (int)sig_len);
		return -1;
	}

	/* OpenHiTLS native ECDSA verify */
	uint8_t der_sig[256];
	int der_len = lws_ecdsa_sig_jws_to_der(sig, keybytes, der_sig, sizeof(der_sig));
	if (der_len < 0) {
		lwsl_err("%s: failed to convert signature to DER format\n", __func__);
		return -1;
	}

	ret = CRYPT_EAL_PkeyVerifyData(ctx->ctx[0], in,
				       (uint32_t)lws_genhash_size(hash_type),
				       der_sig, (uint32_t)der_len);

	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyVerifyData fail: %d\n", __func__, ret);
		return -1;
	}

	return 0;
}

int
lws_genecdh_compute_shared_secret(struct lws_genec_ctx *ctx, uint8_t *ss,
				  int *ss_len)
{
	int32_t ret;
	uint32_t shareLen = (uint32_t)*ss_len;

	if (!ctx->ctx[LDHS_OURS] || !ctx->ctx[LDHS_THEIRS]) {
		lwsl_err("%s: both sides must be set up\n", __func__);
		return -1;
	}

	ret = CRYPT_EAL_PkeyComputeShareKey(ctx->ctx[LDHS_OURS],
					    ctx->ctx[LDHS_THEIRS],
					    ss, &shareLen);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyComputeShareKey failed: %d\n",
			 __func__, ret);
		return -1;
	}

	*ss_len = (int)shareLen;

	return 0;
}
