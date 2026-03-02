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
 *  lws_genaes provides an AES abstraction api in lws that works the
 *  same whether you are using openssl or OpenHiTLS cipher functions underneath.
 */
#include "private-lib-core.h"
#include "private.h"
#if defined(LWS_WITH_JOSE)
#include "private-lib-jose.h"
#endif

static int
lws_openhitls_kw_wrap_alg(size_t kek_len, CRYPT_CIPHER_AlgId *alg)
{
	if (!alg)
		return -1;

	switch (kek_len) {
	case 16:
		*alg = CRYPT_CIPHER_AES128_WRAP_NOPAD;
		return 0;
	case 24:
		*alg = CRYPT_CIPHER_AES192_WRAP_NOPAD;
		return 0;
	case 32:
		*alg = CRYPT_CIPHER_AES256_WRAP_NOPAD;
		return 0;
	default:
		break;
	}

	return -1;
}

int
lws_genaes_create(struct lws_genaes_ctx *ctx, enum enum_aes_operation op,
		  enum enum_aes_modes mode, struct lws_gencrypto_keyelem *el,
		  enum enum_aes_padding padding, void *engine)
{
	CRYPT_CIPHER_AlgId cipherId;

	ctx->mode = mode;
	ctx->k = el;
	ctx->op = op;
	ctx->padding = padding;
	ctx->underway = 0;

	/* engine parameter is not used for OpenHiTLS */
	(void)engine;

	if (mode == LWS_GAESM_KW) {
		if (lws_openhitls_kw_wrap_alg(el->len, &cipherId)) {
			lwsl_err("%s: unsupported AES-KW key size %d bits\n",
				 __func__, (int)el->len * 8);
			return -1;
		}

		ctx->ctx = CRYPT_EAL_CipherNewCtx(cipherId);
		if (!ctx->ctx) {
			lwsl_err("%s: CRYPT_EAL_CipherNewCtx failed for AES-KW\n",
				 __func__);
			return -1;
		}

		return 0;
	}

	/* Map mode and key length to OpenHiTLS cipher ID */
	cipherId = lws_genaes_mode_to_hitls_cipher_id(mode, el->len);
	if (cipherId == CRYPT_CIPHER_MAX) {
		lwsl_err("%s: unsupported AES mode %d or key size %d bits\n",
			 __func__, mode, (int)el->len * 8);
		return -1;
	}

	ctx->ctx = CRYPT_EAL_CipherNewCtx(cipherId);
	if (!ctx->ctx) {
		lwsl_err("%s: CRYPT_EAL_CipherNewCtx failed\n", __func__);
		return -1;
	}

	return 0;
}

int
lws_genaes_destroy(struct lws_genaes_ctx *ctx, unsigned char *tag, size_t tlen)
{
	int ret = 0;

	if (!ctx->ctx)
		return 0;

	/* For GCM mode, get the tag */
	if (ctx->mode == LWS_GAESM_GCM && tag && ctx->op == LWS_GAESO_ENC) {
		ret = CRYPT_EAL_CipherCtrl(ctx->ctx, CRYPT_CTRL_GET_TAG,
					   tag, (uint32_t)tlen);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: GET_TAG ctrl failed: %d\n", __func__, ret);
			ret = 1;
		}
	}

	CRYPT_EAL_CipherFreeCtx(ctx->ctx);
	ctx->ctx = NULL;
	ctx->underway = 0;

	return ret;
}

int
lws_genaes_crypt(struct lws_genaes_ctx *ctx,
		 const uint8_t *in, size_t len, uint8_t *out,
		 uint8_t *iv_or_nonce_ctr_or_data_unit_16,
		 uint8_t *stream_block_16, size_t *nc_or_iv_off, int taglen)
{
	int32_t ret;
	uint32_t outl;
	uint32_t outcap;
	bool enc = (ctx->op == LWS_GAESO_ENC);
	uint8_t iv[16];
	uint8_t *update_out = out;
	uint8_t *tmp_out = NULL;
	size_t tmp_len = len;

	(void)stream_block_16;  /* unused for OpenHiTLS */
	(void)nc_or_iv_off;     /* unused for OpenHiTLS */

	/* For GCM mode with AAD (out == NULL), set tag length and init with IV */
	if (ctx->mode == LWS_GAESM_GCM && !out) {
		uint32_t ivLen = 12; /* GCM uses 12-byte IV (nonce) */

		/* Note: SET_TAGLEN is optional, openHiTLS will use default tag length */

		/* Initialize cipher with IV */
		ret = CRYPT_EAL_CipherInit(ctx->ctx, ctx->k->buf,
					   (uint32_t)ctx->k->len,
					   iv_or_nonce_ctr_or_data_unit_16,
					   ivLen,
					   enc);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CRYPT_EAL_CipherInit failed: %d (mode=%d, ivLen=%u)\n",
				 __func__, ret, ctx->mode, ivLen);
			return -1;
		}

		/* Set AAD */
		if (!len)
			return 0;

		ret = CRYPT_EAL_CipherCtrl(ctx->ctx, CRYPT_CTRL_SET_AAD,
					   (void *)in, (uint32_t)len);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: SET_AAD failed: %d\n", __func__, ret);
			return -1;
		}

		return 0;
	}

	if (!ctx->ctx) {
		if (ctx->mode == LWS_GAESM_KW)
			goto do_update;
		return -1;
	}

	if (ctx->mode == LWS_GAESM_KW)
		goto do_update;

	/* Non-GCM or actual data encryption/decryption */
	if (ctx->mode != LWS_GAESM_GCM || out) {
		uint32_t ivLen = 0;

		if (ctx->mode == LWS_GAESM_GCM) {
			/* GCM encryption after AAD - IV already set, skip init */
			goto do_update;
		} else if (ctx->mode == LWS_GAESM_CTR) {
			/* CTR uses 16-byte counter */
			ivLen = 16;
		} else if (iv_or_nonce_ctr_or_data_unit_16 && ctx->mode != LWS_GAESM_ECB) {
			ivLen = 16;
		}

		if (ctx->mode == LWS_GAESM_CBC && iv_or_nonce_ctr_or_data_unit_16) {
			memcpy(iv, iv_or_nonce_ctr_or_data_unit_16, sizeof(iv));
			iv_or_nonce_ctr_or_data_unit_16 = iv;
		}

		ret = CRYPT_EAL_CipherInit(ctx->ctx, ctx->k->buf,
					   (uint32_t)ctx->k->len,
					   ctx->mode == LWS_GAESM_ECB ? NULL : iv_or_nonce_ctr_or_data_unit_16,
					   ivLen,
					   enc);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CRYPT_EAL_CipherInit failed: %d (mode=%d, ivLen=%u)\n",
				 __func__, ret, ctx->mode, ivLen);
			return -1;
		}
		if (ctx->mode == LWS_GAESM_CBC) {
			CRYPT_PaddingType pt = ctx->padding == LWS_GAESP_WITH_PADDING ?
					       CRYPT_PADDING_PKCS7 :
					       CRYPT_PADDING_NONE;

			ret = CRYPT_EAL_CipherSetPadding(ctx->ctx, pt);
			if (ret != CRYPT_SUCCESS) {
				lwsl_err("%s: CRYPT_EAL_CipherSetPadding failed: %d\n",
					 __func__, ret);
				return -1;
			}
		}
		ctx->underway = 1;
	}

do_update:
	if (ctx->mode == LWS_GAESM_KW) {
		uint32_t final_outl = 0;

		if (len & 7)
			return -1;
		if (ctx->op == LWS_GAESO_ENC) {
			if (len < 16)
				return -1;
		} else {
			if (len < 24)
				return -1;
		}

		ret = CRYPT_EAL_CipherInit(ctx->ctx, ctx->k->buf,
					   (uint32_t)ctx->k->len, NULL, 0, enc);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: AES-KW CRYPT_EAL_CipherInit failed: %d\n",
				 __func__, ret);
			return -1;
		}
		outl = (uint32_t)(ctx->op == LWS_GAESO_ENC ?
				 (len + 8) : (len - 8));
		ret = CRYPT_EAL_CipherUpdate(ctx->ctx, in, (uint32_t)len,
					     out, &outl);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: AES-KW CRYPT_EAL_CipherUpdate failed: %d\n",
				 __func__, ret);
			return -1;
		}
		ret = CRYPT_EAL_CipherFinal(ctx->ctx, out + outl, &final_outl);
		if (ret != CRYPT_SUCCESS || final_outl != 0) {
			lwsl_err("%s: AES-KW CRYPT_EAL_CipherFinal failed: %d, final_outl=%u\n",
				 __func__, ret, (unsigned int)final_outl);
			return -1;
		}

		return 0;
	}

	if (ctx->mode == LWS_GAESM_CBC &&
	    ctx->padding == LWS_GAESP_WITH_PADDING)
		tmp_len += LWS_AES_CBC_BLOCKLEN;

	outcap = (uint32_t)tmp_len;
	outl = outcap;
	if (ctx->mode == LWS_GAESM_CBC &&
	    (in == out || ctx->padding == LWS_GAESP_WITH_PADDING)) {
		tmp_out = lws_malloc(tmp_len, "openhitls-aes-cbc-inplace");
		if (!tmp_out)
			return -1;
		update_out = tmp_out;
	}

	ret = CRYPT_EAL_CipherUpdate(ctx->ctx, in, (uint32_t)len, update_out, &outl);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_CipherUpdate failed: %d\n", __func__, ret);
		if (tmp_out)
			lws_free(tmp_out);
		return -1;
	}
	if (ctx->mode == LWS_GAESM_CBC && ctx->padding == LWS_GAESP_WITH_PADDING &&
	    ctx->op == LWS_GAESO_ENC) {
		uint32_t final_outl = outcap > outl ? outcap - outl :
					       LWS_AES_CBC_BLOCKLEN;

		ret = CRYPT_EAL_CipherFinal(ctx->ctx, update_out + outl,
					    &final_outl);
		if (ret != CRYPT_SUCCESS) {
			if (tmp_out)
				lws_free(tmp_out);
			lwsl_err("%s: CBC(with-padding) CRYPT_EAL_CipherFinal failed: %d\n",
				 __func__, ret);
			return -1;
		}
		outl += final_outl;
		ctx->underway = 0;
	}
	if (tmp_out) {
		memcpy(out, tmp_out, outl);
		lws_free(tmp_out);
	}
	if (ctx->mode == LWS_GAESM_CBC && ctx->padding == LWS_GAESP_NO_PADDING) {
		uint32_t final_outl = LWS_AES_CBC_BLOCKLEN;

		ret = CRYPT_EAL_CipherFinal(ctx->ctx, out + outl, &final_outl);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CBC(no-padding) CRYPT_EAL_CipherFinal failed: %d\n",
				 __func__, ret);
			return -1;
		}
		ctx->underway = 0;
	}

	return 0;
}
