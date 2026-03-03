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
 *  lws_genrsa provides an RSA abstraction api in lws that works the
 *  same whether you are using openssl or OpenHiTLS crypto functions underneath.
 */
#include "private-lib-core.h"
#include "private.h"
/* Random number generator initialization state (shared with EC) */
extern int lws_hitls_init_rand(void);

static int
lws_genrsa_set_crypt_padding(struct lws_genrsa_ctx *ctx)
{
	CRYPT_RsaPadType pad;
	CRYPT_MD_AlgId mdId;
	int32_t ret;

	if (ctx->mode == LGRSAM_PKCS1_1_5)
		pad = CRYPT_RSAES_PKCSV15;
	else
		pad = CRYPT_RSAES_OAEP;

	ret = CRYPT_EAL_PkeyCtrl(ctx->ctx, CRYPT_CTRL_SET_RSA_PADDING,
				 &pad, (uint32_t)sizeof(pad));
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyCtrl(SET_RSA_PADDING) failed: %d\n",
			 __func__, ret);
		return -1;
	}
	if (ctx->mode == LGRSAM_PKCS1_OAEP_PSS) {
		BSL_Param oaep_param[3] = { {0} };

		mdId = lws_genhash_type_to_hitls_md_id(ctx->oaep_hashid);
		if (mdId == CRYPT_MD_MAX) {
			lwsl_err("%s: unsupported OAEP hash %d\n", __func__,
				 (int)ctx->oaep_hashid);
			return -1;
		}

		oaep_param[0].key = CRYPT_PARAM_RSA_MD_ID;
		oaep_param[0].value = &mdId;
		oaep_param[0].valueLen = sizeof(mdId);
		oaep_param[0].valueType = BSL_PARAM_TYPE_INT32;
		oaep_param[1].key = CRYPT_PARAM_RSA_MGF1_ID;
		oaep_param[1].value = &mdId;
		oaep_param[1].valueLen = sizeof(mdId);
		oaep_param[1].valueType = BSL_PARAM_TYPE_INT32;
		oaep_param[2].key = 0;
		oaep_param[2].valueType = 0;
		oaep_param[2].value = NULL;
		oaep_param[2].valueLen = 0;
		oaep_param[2].useLen = 0;

		ret = CRYPT_EAL_PkeyCtrl(ctx->ctx, CRYPT_CTRL_SET_RSA_RSAES_OAEP,
					 oaep_param, 0);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CRYPT_EAL_PkeyCtrl(SET_RSA_RSAES_OAEP) failed: %d\n",
				 __func__, ret);
			return -1;
		}

		ret = CRYPT_EAL_PkeyCtrl(ctx->ctx, CRYPT_CTRL_SET_RSA_OAEP_LABEL,
					 NULL, 0);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CRYPT_EAL_PkeyCtrl(SET_RSA_OAEP_LABEL) failed: %d\n",
				 __func__, ret);
			return -1;
		}
	}

	return 0;
}

static int
lws_genrsa_set_sign_padding(struct lws_genrsa_ctx *ctx, CRYPT_MD_AlgId mdId)
{
	int32_t ret;

	if (ctx->mode == LGRSAM_PKCS1_1_5) {
		CRYPT_RsaPadType pad = CRYPT_EMSA_PKCSV15;
		int32_t pkcs15 = (int32_t)mdId;

		ret = CRYPT_EAL_PkeyCtrl(ctx->ctx, CRYPT_CTRL_SET_RSA_PADDING,
					 &pad, (uint32_t)sizeof(pad));
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CRYPT_EAL_PkeyCtrl(SET_RSA_PADDING) failed: %d\n",
				 __func__, ret);
			return -1;
		}
		ret = CRYPT_EAL_PkeyCtrl(ctx->ctx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15,
					 &pkcs15, (uint32_t)sizeof(pkcs15));
	} else {
		CRYPT_RSA_PssPara pss;

		pss.saltLen = CRYPT_RSA_SALTLEN_TYPE_HASHLEN;
		pss.mdId = mdId;
		pss.mgfId = mdId;
		ret = CRYPT_EAL_PkeyCtrl(ctx->ctx, CRYPT_CTRL_SET_RSA_EMSA_PSS,
					 &pss, 0);
	}

	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyCtrl(SET_RSA_EMSA_*) failed: %d\n",
			 __func__, ret);
		return -1;
	}

	return 0;
}

void
lws_genrsa_destroy_elements(struct lws_gencrypto_keyelem *el)
{
	lws_gencrypto_destroy_elements(el, LWS_GENCRYPTO_RSA_KEYEL_COUNT);
}

int
lws_genrsa_create(struct lws_genrsa_ctx *ctx,
		  const struct lws_gencrypto_keyelem *el,
		  struct lws_context *context, enum enum_genrsa_mode mode,
		  enum lws_genhash_types oaep_hashid)
{
	CRYPT_EAL_PkeyPub pubKey = {0};
	CRYPT_EAL_PkeyPrv prvKey = {0};
	CRYPT_RsaPub *rsaPub;
	CRYPT_RsaPrv *rsaPrv;
	int ret;

	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->mode = mode;
	ctx->oaep_hashid = oaep_hashid;

	/* Initialize random number generator if needed */
	if (lws_hitls_init_rand() < 0)
		return -1;

	ctx->ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
	if (!ctx->ctx) {
		lwsl_err("%s: CRYPT_EAL_PkeyNewCtx failed\n", __func__);
		return 1;
	}

	pubKey.id = CRYPT_PKEY_RSA;
	prvKey.id = CRYPT_PKEY_RSA;
	rsaPub = &pubKey.key.rsaPub;
	rsaPrv = &prvKey.key.rsaPrv;

	/* Set public key elements (n and e) */
	rsaPub->n = el[LWS_GENCRYPTO_RSA_KEYEL_N].buf;
	rsaPub->nLen = (uint32_t)el[LWS_GENCRYPTO_RSA_KEYEL_N].len;
	rsaPub->e = el[LWS_GENCRYPTO_RSA_KEYEL_E].buf;
	rsaPub->eLen = (uint32_t)el[LWS_GENCRYPTO_RSA_KEYEL_E].len;

	ret = CRYPT_EAL_PkeySetPub(ctx->ctx, &pubKey);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeySetPub failed: %d\n", __func__, ret);
		goto bail;
	}

	/* Set private key elements if present */
	if (el[LWS_GENCRYPTO_RSA_KEYEL_D].len > 0) {
		rsaPrv->d = el[LWS_GENCRYPTO_RSA_KEYEL_D].buf;
		rsaPrv->dLen = (uint32_t)el[LWS_GENCRYPTO_RSA_KEYEL_D].len;
		rsaPrv->n = el[LWS_GENCRYPTO_RSA_KEYEL_N].buf;
		rsaPrv->nLen = (uint32_t)el[LWS_GENCRYPTO_RSA_KEYEL_N].len;
		rsaPrv->e = el[LWS_GENCRYPTO_RSA_KEYEL_E].buf;
		rsaPrv->eLen = (uint32_t)el[LWS_GENCRYPTO_RSA_KEYEL_E].len;

		if (el[LWS_GENCRYPTO_RSA_KEYEL_P].len > 0) {
			rsaPrv->p = el[LWS_GENCRYPTO_RSA_KEYEL_P].buf;
			rsaPrv->pLen = (uint32_t)el[LWS_GENCRYPTO_RSA_KEYEL_P].len;
		}
		if (el[LWS_GENCRYPTO_RSA_KEYEL_Q].len > 0) {
			rsaPrv->q = el[LWS_GENCRYPTO_RSA_KEYEL_Q].buf;
			rsaPrv->qLen = (uint32_t)el[LWS_GENCRYPTO_RSA_KEYEL_Q].len;
		}
		if (el[LWS_GENCRYPTO_RSA_KEYEL_DP].len > 0) {
			rsaPrv->dP = el[LWS_GENCRYPTO_RSA_KEYEL_DP].buf;
			rsaPrv->dPLen = (uint32_t)el[LWS_GENCRYPTO_RSA_KEYEL_DP].len;
		}
		if (el[LWS_GENCRYPTO_RSA_KEYEL_DQ].len > 0) {
			rsaPrv->dQ = el[LWS_GENCRYPTO_RSA_KEYEL_DQ].buf;
			rsaPrv->dQLen = (uint32_t)el[LWS_GENCRYPTO_RSA_KEYEL_DQ].len;
		}
		if (el[LWS_GENCRYPTO_RSA_KEYEL_QI].len > 0) {
			rsaPrv->qInv = el[LWS_GENCRYPTO_RSA_KEYEL_QI].buf;
			rsaPrv->qInvLen = (uint32_t)el[LWS_GENCRYPTO_RSA_KEYEL_QI].len;
		}

		ret = CRYPT_EAL_PkeySetPrv(ctx->ctx, &prvKey);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CRYPT_EAL_PkeySetPrv failed: %d\n", __func__, ret);
			goto bail;
		}
	}

	return 0;

bail:
	CRYPT_EAL_PkeyFreeCtx(ctx->ctx);
	ctx->ctx = NULL;
	return 1;
}

int
lws_genrsa_new_keypair(struct lws_context *context, struct lws_genrsa_ctx *ctx,
		       enum enum_genrsa_mode mode, struct lws_gencrypto_keyelem *el,
		       int bits)
{
	CRYPT_EAL_PkeyPara para = {0};
	CRYPT_RsaPara *rsaPara = &para.para.rsaPara;
	CRYPT_EAL_PkeyPub pubKey = {0};
	CRYPT_EAL_PkeyPrv prvKey = {0};
	CRYPT_RsaPub *rsaPub;
	CRYPT_RsaPrv *rsaPrv;
	int ret;
	int n;

	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->mode = mode;
	ctx->oaep_hashid = LWS_GENHASH_TYPE_SHA1;

	/* Initialize random number generator if needed */
	if (lws_hitls_init_rand() < 0)
		return -1;

	ctx->ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
	if (!ctx->ctx) {
		lwsl_err("%s: CRYPT_EAL_PkeyNewCtx failed\n", __func__);
		return -1;
	}

	/* Set RSA parameters for key generation
	 * Use the standard public exponent 65537 (0x010001) */
	static const uint8_t default_pub_exp[] = {0x01, 0x00, 0x01};
	para.id = CRYPT_PKEY_RSA;
	rsaPara->e = (uint8_t *)default_pub_exp;
	rsaPara->eLen = sizeof(default_pub_exp);
	rsaPara->bits = (uint32_t)bits;

	ret = CRYPT_EAL_PkeySetPara(ctx->ctx, &para);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeySetPara failed: %d\n", __func__, ret);
		goto bail;
	}

	/* Generate the key */
	ret = CRYPT_EAL_PkeyGen(ctx->ctx);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyGen failed: %d\n", __func__, ret);
		goto bail;
	}

	/* Extract the key elements
	 * Need to allocate buffers for the output first */
	pubKey.id = CRYPT_PKEY_RSA;
	prvKey.id = CRYPT_PKEY_RSA;
	rsaPub = &pubKey.key.rsaPub;
	rsaPrv = &prvKey.key.rsaPrv;

	/* Allocate buffers for public key */
	uint32_t bytes = (uint32_t)bits / 8;
	uint8_t *nBuf = lws_malloc(bytes, "rsa-n");
	uint8_t *eBuf = lws_malloc(3, "rsa-e");  /* Public exponent is typically 3 bytes */
	if (!nBuf || !eBuf) {
		lws_free(nBuf);
		lws_free(eBuf);
		goto bail;
	}
	rsaPub->n = nBuf;
	rsaPub->nLen = bytes;
	rsaPub->e = eBuf;
	rsaPub->eLen = 3;

	ret = CRYPT_EAL_PkeyGetPub(ctx->ctx, &pubKey);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyGetPub failed: %d\n", __func__, ret);
		lws_free(nBuf);
		lws_free(eBuf);
		goto bail;
	}

	/* Allocate buffers for private key
	 * Note: RSA private key includes many optional fields */
	uint8_t *dBuf = lws_malloc(bytes, "rsa-d");
	uint8_t *pBuf = lws_malloc(bytes / 2, "rsa-p");
	uint8_t *qBuf = lws_malloc(bytes / 2, "rsa-q");
	if (!dBuf || !pBuf || !qBuf) {
		lws_free(dBuf);
		lws_free(pBuf);
		lws_free(qBuf);
		lws_free(nBuf);
		lws_free(eBuf);
		goto bail;
	}
	rsaPrv->n = nBuf;  /* Include n in private key */
	rsaPrv->nLen = bytes;
	rsaPrv->d = dBuf;
	rsaPrv->dLen = bytes;
	rsaPrv->p = pBuf;
	rsaPrv->pLen = (uint32_t)bytes / 2;
	rsaPrv->q = qBuf;
	rsaPrv->qLen = (uint32_t)bytes / 2;
	rsaPrv->e = NULL;  /* e is not needed in private key */
	rsaPrv->eLen = 0;

	ret = CRYPT_EAL_PkeyGetPrv(ctx->ctx, &prvKey);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyGetPrv failed: %d\n", __func__, ret);
		lws_free(nBuf);
		lws_free(eBuf);
		lws_free(dBuf);
		lws_free(pBuf);
		lws_free(qBuf);
		goto bail;
	}

	/* Now copy the data to the output elements
	 * Take ownership of the allocated buffers */
	el[LWS_GENCRYPTO_RSA_KEYEL_N].len = rsaPub->nLen;
	el[LWS_GENCRYPTO_RSA_KEYEL_N].buf = nBuf;  /* Transfer ownership */

	el[LWS_GENCRYPTO_RSA_KEYEL_E].len = rsaPub->eLen;
	el[LWS_GENCRYPTO_RSA_KEYEL_E].buf = eBuf;  /* Transfer ownership */

	el[LWS_GENCRYPTO_RSA_KEYEL_D].len = rsaPrv->dLen;
	el[LWS_GENCRYPTO_RSA_KEYEL_D].buf = dBuf;  /* Transfer ownership */

	el[LWS_GENCRYPTO_RSA_KEYEL_P].len = rsaPrv->pLen;
	el[LWS_GENCRYPTO_RSA_KEYEL_P].buf = pBuf;  /* Transfer ownership */

	el[LWS_GENCRYPTO_RSA_KEYEL_Q].len = rsaPrv->qLen;
	el[LWS_GENCRYPTO_RSA_KEYEL_Q].buf = qBuf;  /* Transfer ownership */

	/* Note: Padding mode is set separately during encrypt/decrypt operations,
	 * not during key generation */

	return 0;

bail:
	for (n = 0; n < LWS_GENCRYPTO_RSA_KEYEL_COUNT; n++)
		if (el[n].buf)
			lws_free_set_NULL(el[n].buf);

	CRYPT_EAL_PkeyFreeCtx(ctx->ctx);
	ctx->ctx = NULL;

	return -1;
}

int
lws_genrsa_public_encrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			  size_t in_len, uint8_t *out)
{
	uint32_t outLen = 512; /* Max RSA 4096 */
	int32_t ret;

	if (lws_genrsa_set_crypt_padding(ctx))
		return -1;

	ret = CRYPT_EAL_PkeyEncrypt(ctx->ctx, in, (uint32_t)in_len, out, &outLen);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyEncrypt failed: %d\n", __func__, ret);
		return -1;
	}

	return (int)outLen;
}

int
lws_genrsa_private_encrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			   size_t in_len, uint8_t *out)
{
	uint32_t outLen = 512; /* Max RSA 4096 */
	int32_t ret;

	if (lws_genrsa_set_crypt_padding(ctx))
		return -1;

	ret = CRYPT_EAL_PkeySignData(ctx->ctx, in, (uint32_t)in_len, out, &outLen);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeySignData failed: %d\n", __func__, ret);
		return -1;
	}

	return (int)outLen;
}

int
lws_genrsa_public_decrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			  size_t in_len, uint8_t *out, size_t out_max)
{
	int32_t ret;

	if (lws_genrsa_set_crypt_padding(ctx))
		return -1;

	ret = CRYPT_EAL_PkeyVerifyData(ctx->ctx, in, (uint32_t)in_len, out, (uint32_t)out_max);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyVerifyData failed: %d\n", __func__, ret);
		return -1;
	}

	return (int)out_max;
}

int
lws_genrsa_private_decrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			   size_t in_len, uint8_t *out, size_t out_max)
{
	uint32_t outLen = (uint32_t)out_max;
	int32_t ret;

	if (lws_genrsa_set_crypt_padding(ctx))
		return -1;

	ret = CRYPT_EAL_PkeyDecrypt(ctx->ctx, in, (uint32_t)in_len, out, &outLen);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyDecrypt failed: %d\n", __func__, ret);
		return -1;
	}

	return (int)outLen;
}

int
lws_genrsa_hash_sig_verify(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			 enum lws_genhash_types hash_type, const uint8_t *sig,
			 size_t sig_len)
{
	CRYPT_MD_AlgId mdId;
	uint32_t hash_len;
	int32_t ret;

	mdId = lws_genhash_type_to_hitls_md_id(hash_type);
	if (mdId == CRYPT_MD_MAX)
		return -1;
	hash_len = (uint32_t)lws_genhash_size(hash_type);

	if (lws_genrsa_set_sign_padding(ctx, mdId))
		return -1;

	ret = CRYPT_EAL_PkeyVerifyData(ctx->ctx, in, hash_len,
				       sig, (uint32_t)sig_len);
	if (ret != CRYPT_SUCCESS) {
		lwsl_notice("%s: CRYPT_EAL_PkeyVerifyData failed: %d\n", __func__, ret);
		return -1;
	}

	return 0;
}

int
lws_genrsa_hash_sign(struct lws_genrsa_ctx *ctx, const uint8_t *in,
		       enum lws_genhash_types hash_type, uint8_t *sig,
		       size_t sig_len)
{
	CRYPT_MD_AlgId mdId;
	uint32_t hash_len;
	uint32_t used = (uint32_t)sig_len;
	int32_t ret;

	mdId = lws_genhash_type_to_hitls_md_id(hash_type);
	if (mdId == CRYPT_MD_MAX)
		return -1;
	hash_len = (uint32_t)lws_genhash_size(hash_type);

	if (lws_genrsa_set_sign_padding(ctx, mdId))
		return -1;

	ret = CRYPT_EAL_PkeySignData(ctx->ctx, in, hash_len, sig, &used);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeySignData failed: %d\n", __func__, ret);
		return -1;
	}

	return (int)used;
}

void
lws_genrsa_destroy(struct lws_genrsa_ctx *ctx)
{
	if (!ctx->ctx)
		return;

	CRYPT_EAL_PkeyFreeCtx(ctx->ctx);
	ctx->ctx = NULL;
}
