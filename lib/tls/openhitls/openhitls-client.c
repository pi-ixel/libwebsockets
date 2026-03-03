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
 * OpenHiTLS TLS client implementation
 */

#include "private-lib-core.h"
#include "private-lib-tls.h"
#include "private.h"

#include <hitls_pki_errno.h>
#include <hitls_pki_x509.h>

typedef int32_t (*lws_openhitls_cfg_buf_loader_t)(HITLS_Config *config,
						   const uint8_t *buf,
						   uint32_t bufLen,
						   HITLS_ParseFormat format);
typedef int32_t (*lws_openhitls_ctx_buf_loader_t)(HITLS_Ctx *ctx,
						   const uint8_t *buf,
						   uint32_t bufLen,
						   HITLS_ParseFormat format);

#if defined(LWS_WITH_TLS_JIT_TRUST)
static void
lws_openhitls_kid_from_bsl(const BSL_Buffer *b, lws_tls_kid_t *kid)
{
	size_t n;

	if (!kid)
		return;

	memset(kid, 0, sizeof(*kid));
	if (!b || !b->data || !b->dataLen)
		return;

	n = b->dataLen;
	if (n > sizeof(kid->kid))
		n = sizeof(kid->kid);

	memcpy(kid->kid, b->data, n);
	kid->kid_len = (uint8_t)n;
}

static void
lws_openhitls_collect_peer_kids(struct lws *wsi)
{
	HITLS_CERT_Chain *chain;
	BslList *list;
	BslListNode *node;

	if (!wsi || !wsi->tls.ssl)
		return;

	chain = HITLS_GetPeerCertChain((const HITLS_Ctx *)wsi->tls.ssl);
	list = (BslList *)chain;
	if (!list)
		return;

	memset(&wsi->tls.kid_chain, 0, sizeof(wsi->tls.kid_chain));

	for (node = list->first; node &&
	     wsi->tls.kid_chain.count < LWS_ARRAY_SIZE(wsi->tls.kid_chain.akid);
	     node = node->next) {
		HITLS_X509_ExtSki ski;
		HITLS_X509_ExtAki aki;
		HITLS_X509_Cert *cert = (HITLS_X509_Cert *)node->data;
		uint8_t idx = wsi->tls.kid_chain.count;

		if (!cert)
			continue;

		memset(&ski, 0, sizeof(ski));
		memset(&aki, 0, sizeof(aki));

		if (HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_SKI, &ski,
					sizeof(ski)) == HITLS_SUCCESS)
			lws_openhitls_kid_from_bsl(&ski.kid,
						   &wsi->tls.kid_chain.skid[idx]);

		if (HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_AKI, &aki,
					sizeof(aki)) == HITLS_SUCCESS)
			lws_openhitls_kid_from_bsl(&aki.kid,
						   &wsi->tls.kid_chain.akid[idx]);

		if (wsi->tls.kid_chain.skid[idx].kid_len ||
		    wsi->tls.kid_chain.akid[idx].kid_len)
			wsi->tls.kid_chain.count++;
	}
}
#endif

static int
lws_openhitls_mem_is_pem(const uint8_t *buf, size_t len)
{
	if (!buf || len < 11)
		return 0;

	return !memcmp(buf, "-----BEGIN ", 11);
}

static int
lws_openhitls_cfg_try_load_buffer(HITLS_Config *config, const void *buf,
				  size_t len, HITLS_ParseFormat format,
				  lws_openhitls_cfg_buf_loader_t loader)
{
	const uint8_t *in = (const uint8_t *)buf;
	const uint8_t *use = in;
	uint8_t *tmp = NULL;
	uint32_t use_len;
	int ret;

	if (!config || !buf || !len || !loader || len > 0xffffffffu)
		return -1;

	if (format == TLS_PARSE_FORMAT_PEM && in[len - 1] != '\0') {
		tmp = lws_malloc(len + 1, "openhitls pem");
		if (!tmp)
			return -1;
		memcpy(tmp, in, len);
		tmp[len] = '\0';
		use = tmp;
	}

	use_len = (uint32_t)len; /* PEM length excludes optional trailing '\0' */
	ret = loader(config, use, use_len, format);

	if (tmp)
		lws_free(tmp);

	return ret;
}

static int
lws_openhitls_cfg_load_buffer_autofmt(HITLS_Config *config, const void *buf,
				      size_t len,
				      lws_openhitls_cfg_buf_loader_t loader)
{
	HITLS_ParseFormat first, second;
	int ret;

	if (lws_openhitls_mem_is_pem((const uint8_t *)buf, len)) {
		first = TLS_PARSE_FORMAT_PEM;
		second = TLS_PARSE_FORMAT_ASN1;
	} else {
		first = TLS_PARSE_FORMAT_ASN1;
		second = TLS_PARSE_FORMAT_PEM;
	}

	ret = lws_openhitls_cfg_try_load_buffer(config, buf, len, first, loader);
	if (ret == HITLS_SUCCESS)
		return ret;

	return lws_openhitls_cfg_try_load_buffer(config, buf, len, second,
						 loader);
}

static int
lws_openhitls_cfg_load_verify_location(HITLS_Config *config, const char *path)
{
	int ret;

	if (!config || !path || !*path)
		return -1;

	ret = HITLS_CFG_LoadVerifyFile(config, path);
	if (ret == HITLS_SUCCESS)
		return ret;

	return HITLS_CFG_LoadVerifyDir(config, path);
}

static int
lws_openhitls_ctx_try_load_buffer(HITLS_Ctx *ctx, const void *buf, size_t len,
				  HITLS_ParseFormat format,
				  lws_openhitls_ctx_buf_loader_t loader)
{
	const uint8_t *in = (const uint8_t *)buf;
	const uint8_t *use = in;
	uint8_t *tmp = NULL;
	uint32_t use_len;
	int ret;

	if (!ctx || !buf || !len || !loader || len > 0xffffffffu)
		return -1;

	if (format == TLS_PARSE_FORMAT_PEM && in[len - 1] != '\0') {
		tmp = lws_malloc(len + 1, "openhitls pem");
		if (!tmp)
			return -1;
		memcpy(tmp, in, len);
		tmp[len] = '\0';
		use = tmp;
	}

	use_len = (uint32_t)len;
	ret = loader(ctx, use, use_len, format);

	if (tmp)
		lws_free(tmp);

	return ret;
}

static int
lws_openhitls_ctx_load_buffer_autofmt(HITLS_Ctx *ctx, const void *buf,
				      size_t len,
				      lws_openhitls_ctx_buf_loader_t loader)
{
	HITLS_ParseFormat first, second;
	int ret;

	if (lws_openhitls_mem_is_pem((const uint8_t *)buf, len)) {
		first = TLS_PARSE_FORMAT_PEM;
		second = TLS_PARSE_FORMAT_ASN1;
	} else {
		first = TLS_PARSE_FORMAT_ASN1;
		second = TLS_PARSE_FORMAT_PEM;
	}

	ret = lws_openhitls_ctx_try_load_buffer(ctx, buf, len, first, loader);
	if (ret == HITLS_SUCCESS)
		return ret;

	return lws_openhitls_ctx_try_load_buffer(ctx, buf, len, second, loader);
}

static int32_t
lws_openhitls_store_ctx_get_error(HITLS_CERT_StoreCtx *store_ctx, int *vr)
{
	int32_t e = 0;

	if (!store_ctx || !vr)
		return -1;

	if (HITLS_X509_StoreCtxCtrl((HITLS_X509_StoreCtx *)store_ctx,
				    HITLS_X509_STORECTX_GET_ERROR, &e,
				    (uint32_t)sizeof(e)) == HITLS_PKI_SUCCESS) {
		*vr = (int)e;
		return 0;
	}

	return -1;
}

static void
lws_openhitls_store_ctx_set_ok(HITLS_CERT_StoreCtx *store_ctx)
{
	int32_t e = (int32_t)HITLS_X509_V_OK;

	if (!store_ctx)
		return;

	(void)HITLS_X509_StoreCtxCtrl((HITLS_X509_StoreCtx *)store_ctx,
				      HITLS_X509_STORECTX_SET_ERROR, &e,
				      (uint32_t)sizeof(e));
}

static int32_t
lws_openhitls_client_verify_cb(int32_t verify_code,
			       HITLS_CERT_StoreCtx *store_ctx)
{
	lws_tls_conn *ssl = lws_openhitls_verify_get_ssl();
	struct lws *wsi = ssl ? (struct lws *)HITLS_GetUserData(ssl) : NULL;
	const struct lws_protocols *lp;
	HITLS_ERROR verify_result = HITLS_X509_V_OK;
	const char *type = "tls=verify";
	unsigned int avoid = 0;
	int internal_allow = verify_code == HITLS_X509_V_OK;
	int n;
	int selfsigned = 0;
	int vr = verify_code;

	if (!wsi || !ssl)
		return verify_code;

	if (!internal_allow) {
		if (lws_openhitls_store_ctx_get_error(store_ctx, &vr))
			if (HITLS_GetVerifyResult((const HITLS_Ctx *)ssl,
						  &verify_result) == HITLS_SUCCESS)
				vr = (int)verify_result;

		lws_openhitls_verify_result_to_policy(vr, &type, &avoid);
		if ((vr == HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND ||
		     vr == HITLS_X509_ERR_ROOT_CERT_NOT_FOUND) &&
		    HITLS_GetPeerCertificate(ssl)) {
			bool is_self_signed = false;

			if (HITLS_X509_CertCtrl(
				    (HITLS_X509_Cert *)HITLS_GetPeerCertificate(
					    ssl),
				    HITLS_X509_IS_SELF_SIGNED, &is_self_signed,
				    (uint32_t)sizeof(is_self_signed)) ==
				    HITLS_SUCCESS &&
			    is_self_signed)
				selfsigned = 1;
		}
		if (vr == HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND ||
		    vr == HITLS_X509_ERR_ROOT_CERT_NOT_FOUND)
			avoid = LCCSCF_ALLOW_INSECURE |
				LCCSCF_ALLOW_SELFSIGNED;
		if (selfsigned)
			avoid = LCCSCF_ALLOW_SELFSIGNED;
		if (avoid && (wsi->tls.use_ssl & avoid))
			internal_allow = 1;
	}

	if (internal_allow && verify_code != HITLS_X509_V_OK) {
		lws_openhitls_store_ctx_set_ok(store_ctx);
		(void)HITLS_SetVerifyResult((HITLS_Ctx *)ssl, HITLS_X509_V_OK);
	}

	lp = &(lws_get_context_protocol(wsi->a.context, 0));
	if (wsi->a.protocol)
		lp = wsi->a.protocol;

	n = lp->callback(wsi,
			 LWS_CALLBACK_OPENSSL_PERFORM_SERVER_CERT_VERIFICATION,
			 store_ctx, ssl, (unsigned int)internal_allow);
	if (n)
		return vr ? vr : HITLS_ERR_TLS;

	/*
	 * Callback precedence: if callback explicitly fixed verify state, honor it.
	 */
	if (!internal_allow &&
	    HITLS_GetVerifyResult((const HITLS_Ctx *)ssl, &verify_result) ==
		    HITLS_SUCCESS &&
	    verify_result == HITLS_X509_V_OK)
		internal_allow = 1;

	if (!internal_allow)
		lwsl_info("%s: cert verify denied (%s, verify=0x%x)\n", __func__,
			  type, (unsigned int)vr);

	return internal_allow ? HITLS_X509_V_OK :
				(vr ? vr : HITLS_ERR_TLS);
}

int
lws_tls_client_create_vhost_context(struct lws_vhost *vh,
				    const struct lws_context_creation_info *info,
				    const char *cipher_list,
				    const char *ca_filepath,
				    const void *ca_mem,
				    unsigned int ca_mem_len,
				    const char *cert_filepath,
				    const void *cert_mem,
				    unsigned int cert_mem_len,
				    const char *private_key_filepath,
				    const void *key_mem,
				    unsigned int key_mem_len)
{
	lws_tls_ctx *ctx;
	HITLS_Config *config;
	uint16_t suites[64];
	size_t suites_count = 0;
	int cert_set = 0, key_set = 0;
	int ret;

	ctx = lws_zalloc(sizeof(*ctx), __func__);
	if (!ctx)
		return -1;

	/* Create full TLS config so options_set/clear version mapping can apply */
	config = HITLS_CFG_NewTLSConfig();
	if (!config) {
		lwsl_err("%s: HITLS_CFG_NewTLSConfig failed\n", __func__);
		goto bail;
	}

	ctx->client_config = config;
	lws_ssl_bind_passphrase(ctx, 1, info);

	if (vh->context->keylog_file[0]) {
		ret = HITLS_CFG_SetKeyLogCb(config, lws_openhitls_klog_dump);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_CFG_SetKeyLogCb failed: 0x%x\n",
				 __func__, ret);
			goto bail_cfg;
		}
	}

	if (lws_openhitls_apply_ssl_options(config, info->ssl_client_options_set,
					    info->ssl_client_options_clear,
					    "client")) {
		lwsl_err("%s: failed to apply ssl_client_options_set/clear\n",
			 __func__);
		goto bail_cfg;
	}

	if (HITLS_CFG_SetVerifyCb(config, lws_openhitls_client_verify_cb) !=
	    HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_SetVerifyCb failed\n", __func__);
		goto bail_cfg;
	}

	if (cipher_list && cipher_list[0]) {
		ret = lws_openhitls_collect_cipher_list(cipher_list, suites,
							LWS_ARRAY_SIZE(suites),
							&suites_count, __func__);
		if (ret < 0) {
			lwsl_err("%s: no valid cipher mapped from '%s'\n",
				 __func__, cipher_list);
			goto bail_cfg;
		}
	}

	if (info->client_tls_1_3_plus_cipher_list &&
	    info->client_tls_1_3_plus_cipher_list[0]) {
		ret = lws_openhitls_collect_cipher_list(
				info->client_tls_1_3_plus_cipher_list, suites,
				LWS_ARRAY_SIZE(suites), &suites_count, __func__);
		if (ret < 0) {
			lwsl_err("%s: no valid cipher mapped from client_tls_1_3_plus_cipher_list '%s'\n",
				 __func__, info->client_tls_1_3_plus_cipher_list);
			goto bail_cfg;
		}
	}

	if (suites_count &&
	    HITLS_CFG_SetCipherSuites(config, suites,
				      (uint32_t)suites_count) != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_SetCipherSuites failed\n", __func__);
		goto bail_cfg;
	}

#ifdef LWS_SSL_CLIENT_USE_OS_CA_CERTS
	if (!lws_check_opt(vh->options, LWS_SERVER_OPTION_DISABLE_OS_CA_CERTS)) {
		ret = HITLS_CFG_LoadDefaultCAPath(config);
		if (ret != HITLS_SUCCESS)
			lwsl_warn("%s: unable to load system default CA path: 0x%x\n",
				  __func__, ret);
	}
#endif

	/* Load CA certificates for verification (OpenSSL-equivalent flow). */
	if (!ca_filepath && (!ca_mem || !ca_mem_len)) {
		ret = lws_openhitls_cfg_load_verify_location(config,
						LWS_OPENSSL_CLIENT_CERTS);
		if (ret != HITLS_SUCCESS)
			lwsl_err("Unable to load SSL Client certs from %s "
				 "(set by LWS_OPENSSL_CLIENT_CERTS) -- "
				 "client ssl isn't going to work\n",
				 LWS_OPENSSL_CLIENT_CERTS);
	} else if (ca_filepath) {
		lwsl_notice("%s: loading CA from %s\n", __func__, ca_filepath);
		ret = HITLS_CFG_LoadVerifyFile(config, ca_filepath);
		if (ret != HITLS_SUCCESS)
			lwsl_err("Unable to load SSL Client certs file from %s "
				 "-- client ssl isn't going to work\n",
				 ca_filepath);
		else
			lwsl_info("loaded ssl_ca_filepath\n");
	} else {
		lwsl_notice("%s: loading CA from memory (%u bytes)\n", __func__,
			    ca_mem_len);
		ret = lws_openhitls_cfg_load_buffer_autofmt(config, ca_mem,
				ca_mem_len, HITLS_CFG_LoadVerifyBuffer);
		if (ret != HITLS_SUCCESS)
			lwsl_err("Unable to load SSL Client certs from "
				 "ssl_ca_mem -- client ssl isn't going to work\n");
		else
			lwsl_info("loaded ssl_ca_mem\n");
	}

	/* Load client certificate if provided (OpenSSL order: filepath first). */
	if (cert_filepath) {
		if (lws_tls_use_any_upgrade_check_extant(cert_filepath) !=
				LWS_TLS_EXTANT_YES &&
		    (info->options & LWS_SERVER_OPTION_IGNORE_MISSING_CERT)) {
			lwsl_notice("%s: ignoring missing client cert %s\n",
				    __func__, cert_filepath);
			goto client_cert_done;
		}

		lwsl_notice("%s: loading client cert from %s\n", __func__,
			    cert_filepath);
		ret = HITLS_CFG_UseCertificateChainFile(config, cert_filepath);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_CFG_UseCertificateChainFile failed: 0x%x\n",
				 __func__, ret);
			goto bail_cfg;
		}
		cert_set = 1;
	} else if (cert_mem && cert_mem_len) {
		lwsl_notice("%s: loading client cert from memory (%u bytes)\n",
			    __func__, cert_mem_len);
		ret = lws_openhitls_cfg_load_buffer_autofmt(config, cert_mem,
				cert_mem_len, HITLS_CFG_LoadCertBuffer);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_CFG_LoadCertBuffer failed: 0x%x\n",
				 __func__, ret);
			goto bail_cfg;
		}
		cert_set = 1;
	}

	/* Load client private key if provided (OpenSSL order: filepath first). */
	if (private_key_filepath) {
		lwsl_notice("%s: loading client key from %s\n", __func__,
			    private_key_filepath);
		ret = HITLS_CFG_LoadKeyFile(config, private_key_filepath,
					    TLS_PARSE_FORMAT_PEM);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_CFG_LoadKeyFile failed: 0x%x\n",
				 __func__, ret);
			goto bail_cfg;
		}
		key_set = 1;
	} else if (key_mem && key_mem_len) {
		lwsl_notice("%s: loading client key from memory (%u bytes)\n",
			    __func__, key_mem_len);
		ret = lws_openhitls_cfg_load_buffer_autofmt(config, key_mem,
				key_mem_len, HITLS_CFG_LoadKeyBuffer);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_CFG_LoadKeyBuffer failed: 0x%x\n",
				 __func__, ret);
			goto bail_cfg;
		}
		key_set = 1;
	}

	if (cert_set && key_set) {
		ret = HITLS_CFG_CheckPrivateKey(config);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_CFG_CheckPrivateKey failed: 0x%x\n",
				 __func__, ret);
			goto bail_cfg;
		}
	}

client_cert_done:

	/*
	 * ALPN is set per-connection in lws_ssl_client_bio_create()
	 * based on wsi->a.vhost->tls.alpn. The config here is just
	 * a placeholder for protocol preferences.
	 */

	vh->tls.ssl_client_ctx = ctx;
	lws_tls_session_cache(vh, info->tls_session_timeout);

	return 0;

bail_cfg:
	HITLS_CFG_FreeConfig(config);
bail:
	lws_free(ctx);
	return -1;
}

int
lws_ssl_client_bio_create(struct lws *wsi)
{
	lws_tls_ctx *ctx;
	HITLS_Ctx *ssl;
	lws_system_blob_t *b;
	BSL_UIO *uio;
	const uint8_t *data;
	char alpn_buf[128];
	const char *alpn_comma = wsi->a.context->tls.alpn_default;
	uint8_t hitls_alpn[sizeof(wsi->a.vhost->tls.alpn_ctx.data)];
	size_t size;
	int ret;
	int n;

	if (!wsi->a.vhost || !wsi->a.vhost->tls.ssl_client_ctx) {
		lwsl_err("%s: no client context\n", __func__);
		return -1;
	}

	ctx = (lws_tls_ctx *)wsi->a.vhost->tls.ssl_client_ctx;
	if (!ctx->client_config) {
		lwsl_err("%s: no client config\n", __func__);
		return -1;
	}

	/* Create new SSL connection */
	ssl = HITLS_New(ctx->client_config);
	if (!ssl) {
		lwsl_err("%s: HITLS_New failed\n", __func__);
		return -1;
	}

	ret = HITLS_SetUserData(ssl, wsi);
	if (ret != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_SetUserData failed: 0x%x\n", __func__, ret);
		HITLS_Free(ssl);
		return -1;
	}

	if (wsi->a.vhost->tls.ssl_info_event_mask) {
		ret = HITLS_SetInfoCb(ssl, lws_ssl_info_callback);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_SetInfoCb failed: 0x%x\n",
				 __func__, ret);
			HITLS_Free(ssl);
			return -1;
		}
	}

	ret = HITLS_SetVerifyCb(ssl, lws_openhitls_client_verify_cb);
	if (ret != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_SetVerifyCb failed: 0x%x\n", __func__, ret);
		HITLS_Free(ssl);
		return -1;
	}

	/*
	 * For relaxed verification policies, disable handshake-time verify hard
	 * fail so policy handling can proceed in lws callback path.
	 */
	if (wsi->tls.use_ssl &
	    (LCCSCF_ALLOW_INSECURE | LCCSCF_ALLOW_SELFSIGNED)) {
		ret = HITLS_SetVerifyNoneSupport(ssl, true);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_SetVerifyNoneSupport failed: 0x%x\n",
				 __func__, ret);
			HITLS_Free(ssl);
			return -1;
		}
	}

	/* Create and attach BSL_UIO (TCP socket) */
	uio = BSL_UIO_New(BSL_UIO_TcpMethod());
	if (!uio) {
		lwsl_err("%s: BSL_UIO_New failed\n", __func__);
		HITLS_Free(ssl);
		return -1;
	}

	/* BSL_UIO_SetFD returns void */
	BSL_UIO_SetFD(uio, (int)wsi->desc.sockfd);

	/* Set non-blocking mode */
	BSL_UIO_Ctrl(uio, BSL_UIO_SET_NOBLOCK, 1, NULL);

	ret = HITLS_SetUio(ssl, uio);
	if (ret != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_SetUio failed: 0x%x\n", __func__, ret);
		BSL_UIO_Free(uio);
		HITLS_Free(ssl);
		return -1;
	}

	/* Set SNI if hostname is available */
	if (wsi->cli_hostname_copy) {
		ret = HITLS_SetServerName(ssl, (uint8_t *)wsi->cli_hostname_copy,
					  (uint32_t)strlen(wsi->cli_hostname_copy));
		if (ret != HITLS_SUCCESS) {
			lwsl_debug("%s: HITLS_SetServerName failed: 0x%x\n",
				   __func__, ret);
			/* Non-fatal: continue without SNI */
		}
	}

	/*
	 * Match the OpenSSL client-side ALPN precedence:
	 * context default -> vhost default -> stash override -> request header.
	 */
	if (wsi->a.vhost->tls.alpn)
		alpn_comma = wsi->a.vhost->tls.alpn;
	if (wsi->stash) {
		alpn_comma = wsi->stash->cis[CIS_ALPN];
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	} else {
		if (lws_hdr_copy(wsi, alpn_buf, sizeof(alpn_buf),
				 _WSI_TOKEN_CLIENT_ALPN) > 0)
			alpn_comma = alpn_buf;
#endif
	}

	if (alpn_comma && alpn_comma[0]) {
		n = lws_alpn_comma_to_openssl(alpn_comma, hitls_alpn,
					      (int)sizeof(hitls_alpn));
		if (n < 0) {
			lwsl_warn("%s: unable to encode ALPN '%s'\n",
				  __func__, alpn_comma);
		} else {
			lwsl_info("%s client conn using alpn list '%s'\n",
				  wsi->role_ops->name, alpn_comma);
			ret = HITLS_SetAlpnProtos(ssl, hitls_alpn, (uint32_t)n);
		}
	} else
		ret = HITLS_SUCCESS;

	if (ret != HITLS_SUCCESS && alpn_comma && alpn_comma[0]) {
		lwsl_warn("%s: HITLS_SetAlpnProtos failed: 0x%x\n",
			  __func__, ret);
		/* Non-fatal: continue without ALPN */
	} else if (alpn_comma && alpn_comma[0]) {
		lwsl_info("%s: ALPN set successfully\n", __func__);
	}

	wsi->tls.ssl = ssl;

	if (wsi->sys_tls_client_cert) {
		b = lws_system_get_blob(wsi->a.context,
					LWS_SYSBLOB_TYPE_CLIENT_CERT_DER,
					wsi->sys_tls_client_cert - 1);
		if (!b)
			goto no_client_cert;

		size = lws_system_blob_get_size(b);
		if (!size || lws_system_blob_get_single_ptr(b, &data))
			goto no_client_cert;

		ret = lws_openhitls_ctx_load_buffer_autofmt(ssl, data, size,
							    HITLS_LoadCertBuffer);
		if (ret != HITLS_SUCCESS)
			goto no_client_cert;

		b = lws_system_get_blob(wsi->a.context,
					LWS_SYSBLOB_TYPE_CLIENT_KEY_DER,
					wsi->sys_tls_client_cert - 1);
		if (!b)
			goto no_client_cert;

		size = lws_system_blob_get_size(b);
		if (!size || lws_system_blob_get_single_ptr(b, &data))
			goto no_client_cert;

		ret = lws_openhitls_ctx_load_buffer_autofmt(ssl, data, size,
							    HITLS_LoadKeyBuffer);
		if (ret != HITLS_SUCCESS)
			goto no_client_cert;

		if (HITLS_CheckPrivateKey(ssl) != HITLS_SUCCESS)
			goto no_client_cert;

		lwsl_notice("%s: set system client cert %u\n", __func__,
			    wsi->sys_tls_client_cert - 1);
	}

	/*
	 * Reuse any cached client session before the handshake starts so
	 * session resumption works like the OpenSSL backend.
	 */
	lws_tls_reuse_session(wsi);

	return 0;

no_client_cert:
	lwsl_err("%s: unable to set up system client cert %d\n", __func__,
		 wsi->sys_tls_client_cert - 1);
	uio = HITLS_GetUio(ssl);
	if (uio)
		BSL_UIO_Free(uio);
	HITLS_Free(ssl);
	wsi->tls.ssl = NULL;

	return -1;
}

int
lws_tls_client_confirm_peer_cert(struct lws *wsi, char *ebuf, size_t ebuf_len)
{
	HITLS_ERROR verify_result = HITLS_X509_V_OK;
	const char *type = "";
	unsigned int avoid = 0;
	int vr;
	int ret;

	if (!wsi->tls.ssl) {
		if (ebuf)
			lws_snprintf(ebuf, ebuf_len, "no SSL context");
		return -1;
	}

	ret = HITLS_GetVerifyResult((const HITLS_Ctx *)wsi->tls.ssl,
				    &verify_result);
	if (ret != HITLS_SUCCESS) {
		if (ebuf)
			lws_snprintf(ebuf, ebuf_len,
				     "unable to get verify result: 0x%x", ret);
		return -1;
	}

	if ((verify_result == HITLS_WANT_CONNECT ||
	     verify_result == HITLS_WANT_ACCEPT ||
	     verify_result == HITLS_WANT_READ ||
	     verify_result == HITLS_WANT_WRITE) &&
	    (wsi->tls.use_ssl &
	     (LCCSCF_ALLOW_INSECURE | LCCSCF_ALLOW_SELFSIGNED))) {
		lwsl_info("%s: treating transient verify result 0x%x as allowed "
			  "for relaxed policy (use_ssl=0x%x)\n",
			  __func__, verify_result, (unsigned int)wsi->tls.use_ssl);
		return 0;
	}

	if (verify_result == HITLS_X509_V_OK)
		goto maybe_hostname_check;

	goto use_verify_result;

maybe_hostname_check:
	if (!(wsi->tls.use_ssl & LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK) &&
	    wsi->cli_hostname_copy && wsi->cli_hostname_copy[0]) {
		HITLS_CERT_X509 *tls_cert = HITLS_GetPeerCertificate(wsi->tls.ssl);

		if (!tls_cert ||
		    HITLS_X509_VerifyHostname((HITLS_X509_Cert *)tls_cert, 0,
					      wsi->cli_hostname_copy,
					      (uint32_t)strlen(wsi->cli_hostname_copy))
				!= HITLS_PKI_SUCCESS) {
			verify_result = (HITLS_ERROR)HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
		}
	}

	if (verify_result == HITLS_X509_V_OK)
		return 0;

use_verify_result:

	vr = (int)verify_result;

#if defined(LWS_WITH_TLS_JIT_TRUST)
	if ((vr == HITLS_X509_ERR_VFY_INVALID_CA ||
	     vr == HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND ||
	     vr == HITLS_X509_ERR_ROOT_CERT_NOT_FOUND) &&
	    !wsi->tls.kid_chain.count) {
		lws_openhitls_collect_peer_kids(wsi);
		if (wsi->tls.kid_chain.count)
			(void)lws_tls_jit_trust_sort_kids(wsi,
							  &wsi->tls.kid_chain);
	}
#endif

	lws_openhitls_verify_result_to_policy(vr, &type, &avoid);
	if (vr == HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND ||
	    vr == HITLS_X509_ERR_ROOT_CERT_NOT_FOUND)
		avoid = LCCSCF_ALLOW_INSECURE | LCCSCF_ALLOW_SELFSIGNED;
	if ((vr == HITLS_X509_ERR_VFY_INVALID_CA ||
	     vr == HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND ||
	     vr == HITLS_X509_ERR_ROOT_CERT_NOT_FOUND) &&
	    HITLS_GetPeerCertificate(wsi->tls.ssl)) {
		bool is_self_signed = false;

		if (HITLS_X509_CertCtrl((HITLS_X509_Cert *)
					    HITLS_GetPeerCertificate(
						    wsi->tls.ssl),
					HITLS_X509_IS_SELF_SIGNED,
					&is_self_signed,
					(uint32_t)sizeof(is_self_signed)) ==
			    HITLS_SUCCESS &&
		    is_self_signed)
			avoid = LCCSCF_ALLOW_SELFSIGNED;
	}

	lwsl_info("%s: cert problem: %s (0x%x)\n",
		  __func__, type, verify_result);

	if (avoid && (wsi->tls.use_ssl & avoid)) {
		lwsl_info("%s: allowing verify error 0x%x due to policy\n",
			  __func__, verify_result);
		return 0;
	}

	if (ebuf)
		lws_snprintf(ebuf, ebuf_len,
			     "server cert didn't look good, %s (use_ssl 0x%x) verify = 0x%x",
			     type, (unsigned int)wsi->tls.use_ssl, verify_result);
	lwsl_info("%s: server cert verify failed: 0x%x\n",
		  __func__, verify_result);

	return -1;
}

int
lws_tls_client_vhost_extra_cert_mem(struct lws_vhost *vh, const uint8_t *der,
				    size_t len)
{
	lws_tls_ctx *ctx;
	int ret;

	if (!vh || !vh->tls.ssl_client_ctx || !der || !len)
		return 1;

	ctx = (lws_tls_ctx *)vh->tls.ssl_client_ctx;
	if (!ctx->client_config)
		return 1;

	ret = lws_openhitls_cfg_load_buffer_autofmt(ctx->client_config,
			der, len, HITLS_CFG_LoadVerifyBuffer);
	if (ret != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_LoadVerifyBuffer failed: 0x%x\n",
			 __func__, ret);
		return 1;
	}

	return 0;
}
