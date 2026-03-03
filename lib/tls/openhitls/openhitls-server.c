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
 * OpenHiTLS TLS server implementation
 */

#include "private-lib-core.h"
#include "private-lib-tls.h"
#include "private.h"
#include <hitls_cert.h>
#include <hitls_pki_cert.h>
#include <hitls_pki_csr.h>
#include <hitls_pki_utils.h>
#include <crypt_eal_codecs.h>
#include <crypt_params_key.h>
#include <bsl_sal.h>

typedef int32_t (*lws_openhitls_cfg_buf_loader_t)(HITLS_Config *config,
						   const uint8_t *buf,
						   uint32_t bufLen,
						   HITLS_ParseFormat format);

struct lws_tls_ss_pieces {
	int temp_cert_active;
	HITLS_Config *orig_certkey_snapshot;
};

static void
lws_openhitls_tls_ss_free(struct lws_vhost *vhost)
{
	if (!vhost || !vhost->tls.ss)
		return;

	if (vhost->tls.ss->orig_certkey_snapshot)
		HITLS_CFG_FreeConfig(vhost->tls.ss->orig_certkey_snapshot);

	lws_free_set_NULL(vhost->tls.ss);
}

static int32_t
lws_ssl_server_name_cb(HITLS_Ctx *ssl, int *alert, void *arg)
{
	struct lws_context *context = (struct lws_context *)arg;
	const HITLS_Config *current;
	struct lws_vhost *vhost, *vh;
	lws_tls_ctx *target_ctx;
	const char *servername;

	(void)alert;

	if (!ssl || !context)
		return HITLS_ACCEPT_SNI_ERR_NOACK;

	current = HITLS_GetConfig(ssl);
	if (!current)
		return HITLS_ACCEPT_SNI_ERR_NOACK;

	vh = context->vhost_list;
	while (vh) {
		lws_tls_ctx *ctx = (lws_tls_ctx *)vh->tls.ssl_ctx;

		if (!vh->being_destroyed && ctx && ctx->config == current)
			break;
		vh = vh->vhost_next;
	}

	if (!vh)
		return HITLS_ACCEPT_SNI_ERR_OK;

	servername = HITLS_GetServerName(ssl, HITLS_SNI_HOSTNAME_TYPE);
	if (!servername) {
		lwsl_info("SNI: Unknown ServerName\n");
		return HITLS_ACCEPT_SNI_ERR_OK;
	}

	vhost = lws_select_vhost(context, vh->listen_port, servername);
	if (!vhost) {
		lwsl_info("SNI: none: %s:%d\n", servername, vh->listen_port);
		return HITLS_ACCEPT_SNI_ERR_OK;
	}

	target_ctx = (lws_tls_ctx *)vhost->tls.ssl_ctx;
	if (!target_ctx || !target_ctx->config)
		return HITLS_ACCEPT_SNI_ERR_OK;

	if (HITLS_SetNewConfig(ssl, target_ctx->config) != HITLS_SUCCESS)
		return HITLS_ACCEPT_SNI_ERR_ALERT_FATAL;

	lwsl_info("SNI: Found: %s:%d\n", servername, vh->listen_port);

	return HITLS_ACCEPT_SNI_ERR_OK;
}

static int
OpenHiTLS_verify_callback(int32_t is_preverify_ok,
			       HITLS_CERT_StoreCtx *store_ctx)
{
	lws_tls_conn *ssl = lws_openhitls_verify_get_ssl();
	struct lws *wsi = ssl ? (struct lws *)HITLS_GetUserData(ssl) : NULL;
	const struct lws_protocols *lp;
	HITLS_ERROR verify_result = HITLS_X509_V_OK;
	int internal_allow = is_preverify_ok ? 1 : 0;
	int n;

	if (!wsi || !wsi->a.vhost || !wsi->a.vhost->protocols)
		return is_preverify_ok ? 1 : 0;

	lp = &wsi->a.vhost->protocols[0];
	n = lp->callback(wsi,
			 LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION,
			 store_ctx, ssl, (unsigned int)is_preverify_ok);
	if (n)
		return 0;

	if (!internal_allow &&
	    HITLS_GetVerifyResult((const HITLS_Ctx *)ssl, &verify_result) ==
		    HITLS_SUCCESS &&
	    verify_result == HITLS_X509_V_OK)
		internal_allow = 1;

	return internal_allow ? 1 : 0;
}

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
lws_openhitls_cfg_load_certkey_pair(HITLS_Config *config, const char *cert,
				    const char *private_key,
				    const char *mem_cert,
				    size_t len_mem_cert,
				    const char *mem_privkey,
				    size_t mem_privkey_len)
{
	int ret;

	if (!config)
		return -1;

	if ((mem_cert && len_mem_cert) != (mem_privkey && mem_privkey_len)) {
		lwsl_err("%s: memory cert/key must be provided as a pair\n",
			 __func__);
		return -1;
	}

	if (!!cert != !!private_key) {
		lwsl_err("%s: file cert/key must be provided as a pair\n",
			 __func__);
		return -1;
	}

	if (mem_cert && len_mem_cert) {
		ret = lws_openhitls_cfg_load_buffer_autofmt(config, mem_cert,
				len_mem_cert, HITLS_CFG_LoadCertBuffer);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_CFG_LoadCertBuffer failed: 0x%x\n",
				 __func__, ret);
			return -1;
		}

		ret = lws_openhitls_cfg_load_buffer_autofmt(config, mem_privkey,
				mem_privkey_len, HITLS_CFG_LoadKeyBuffer);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_CFG_LoadKeyBuffer failed: 0x%x\n",
				 __func__, ret);
			return -1;
		}
	} else if (cert && private_key) {
		ret = HITLS_CFG_LoadCertFile(config, cert, TLS_PARSE_FORMAT_PEM);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_CFG_LoadCertFile failed: 0x%x\n",
				 __func__, ret);
			return -1;
		}

		ret = HITLS_CFG_LoadKeyFile(config, private_key,
					    TLS_PARSE_FORMAT_PEM);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_CFG_LoadKeyFile failed: 0x%x\n",
				 __func__, ret);
			return -1;
		}
	} else
		return 0;

	ret = HITLS_CFG_CheckPrivateKey(config);
	if (ret != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_CheckPrivateKey failed: 0x%x\n",
			 __func__, ret);
		return -1;
	}

	return 0;
}

int
lws_tls_server_vhost_backend_init(const struct lws_context_creation_info *info,
				  struct lws_vhost *vhost, struct lws *wsi)
{
	lws_tls_ctx *ctx;
	HITLS_Config *config;
	uint16_t suites[64];
	size_t suites_count = 0;
	int cert_mode;
	int ret;

	(void)wsi;

	if (!vhost->tls.use_ssl ||
	    (!info->ssl_cert_filepath && !info->server_ssl_cert_mem))
		return 0;

	ctx = lws_zalloc(sizeof(*ctx), __func__);
	if (!ctx)
		return 1;

	/* Create full TLS config so options_set/clear version mapping can apply */
	config = HITLS_CFG_NewTLSConfig();
	if (!config) {
		lwsl_err("%s: HITLS_CFG_NewTLSConfig failed\n", __func__);
		goto bail;
	}

	/* Mirror OpenSSL server preference behavior where supported */
	ret = HITLS_CFG_SetCipherServerPreference(config, true);
	if (ret != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_SetCipherServerPreference failed: 0x%x\n",
			 __func__, ret);
		goto bail_cfg;
	}

	ctx->config = config;
	lws_ssl_bind_passphrase(ctx, 0, info);

	if (vhost->context->keylog_file[0]) {
		ret = HITLS_CFG_SetKeyLogCb(config, lws_openhitls_klog_dump);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_CFG_SetKeyLogCb failed: 0x%x\n",
				 __func__, ret);
			goto bail_cfg;
		}
	}

	if (HITLS_CFG_SetServerNameCb(config, lws_ssl_server_name_cb)
			!= HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_SetServerNameCb failed\n", __func__);
		goto bail_cfg;
	}

	if (HITLS_CFG_SetServerNameArg(config, vhost->context) != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_SetServerNameArg failed\n", __func__);
		goto bail_cfg;
	}

	if (info->ssl_cipher_list && info->ssl_cipher_list[0]) {
		ret = lws_openhitls_collect_cipher_list(info->ssl_cipher_list,
							suites,
							LWS_ARRAY_SIZE(suites),
							&suites_count, __func__);
		if (ret < 0) {
			lwsl_err("%s: no valid cipher mapped from ssl_cipher_list '%s'\n",
				 __func__, info->ssl_cipher_list);
			goto bail_cfg;
		}
	}
	if (info->tls1_3_plus_cipher_list && info->tls1_3_plus_cipher_list[0]) {
		ret = lws_openhitls_collect_cipher_list(info->tls1_3_plus_cipher_list,
							suites,
							LWS_ARRAY_SIZE(suites),
							&suites_count, __func__);
		if (ret < 0) {
			lwsl_err("%s: no valid cipher mapped from tls1_3_plus_cipher_list '%s'\n",
				 __func__, info->tls1_3_plus_cipher_list);
			goto bail_cfg;
		}
	}
	if (suites_count &&
	    HITLS_CFG_SetCipherSuites(config, suites,
				      (uint32_t)suites_count) != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_SetCipherSuites failed\n", __func__);
		goto bail_cfg;
	}

	/* Load verify CA for client cert verification if provided */
	if (info->ssl_ca_filepath) {
		ret = HITLS_CFG_LoadVerifyFile(config, info->ssl_ca_filepath);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_CFG_LoadVerifyFile failed: 0x%x\n",
				 __func__, ret);
			goto bail_cfg;
		}
	} else if (info->server_ssl_ca_mem && info->server_ssl_ca_mem_len) {
		ret = lws_openhitls_cfg_load_buffer_autofmt(config,
				info->server_ssl_ca_mem,
				info->server_ssl_ca_mem_len,
				HITLS_CFG_LoadVerifyBuffer);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_CFG_LoadVerifyBuffer failed: 0x%x\n",
				 __func__, ret);
			goto bail_cfg;
		}
	}

	cert_mode = (int)lws_tls_generic_cert_checks(vhost,
					info->ssl_cert_filepath,
					info->ssl_private_key_filepath);
	if (!info->ssl_cert_filepath && !info->ssl_private_key_filepath)
		cert_mode = LWS_TLS_EXTANT_ALTERNATIVE;

	if (cert_mode == LWS_TLS_EXTANT_NO &&
	    (!info->server_ssl_cert_mem || !info->server_ssl_private_key_mem))
		goto done_ctx;
	if (cert_mode == LWS_TLS_EXTANT_NO)
		cert_mode = LWS_TLS_EXTANT_ALTERNATIVE;

	if (cert_mode == LWS_TLS_EXTANT_ALTERNATIVE &&
	    (!info->server_ssl_cert_mem || !info->server_ssl_private_key_mem)) {
		lwsl_err("%s: incomplete alternative cert/key at init\n",
			 __func__);
		goto bail_cfg;
	}

	if ((!!info->ssl_cert_filepath != !!info->ssl_private_key_filepath) ||
	    (!!info->server_ssl_cert_mem != !!info->server_ssl_private_key_mem)) {
		lwsl_err("%s: server cert/key must be configured as a pair\n",
			 __func__);
		goto bail_cfg;
	}

	if (cert_mode == LWS_TLS_EXTANT_ALTERNATIVE) {
		lwsl_notice("%s: loading cert/key from memory\n", __func__);
		if (lws_openhitls_cfg_load_certkey_pair(config, NULL, NULL,
				info->server_ssl_cert_mem,
				info->server_ssl_cert_mem_len,
				info->server_ssl_private_key_mem,
				info->server_ssl_private_key_mem_len))
			goto bail_cfg;
	} else if (cert_mode == LWS_TLS_EXTANT_YES) {
		lwsl_notice("%s: loading cert from %s\n", __func__,
			    info->ssl_cert_filepath);
		lwsl_notice("%s: loading key from %s\n", __func__,
			    info->ssl_private_key_filepath);
		if (lws_openhitls_cfg_load_certkey_pair(config,
				info->ssl_cert_filepath,
				info->ssl_private_key_filepath,
				NULL, 0, NULL, 0))
			goto bail_cfg;
	}

done_ctx:
	vhost->tls.ssl_ctx = ctx;

	return 0;

bail_cfg:
	HITLS_CFG_FreeConfig(config);
bail:
	lws_free(ctx);
	return 1;
}

int
lws_tls_server_new_nonblocking(struct lws *wsi, lws_sockfd_type accept_fd)
{
	lws_tls_ctx *vhost_ctx;
	HITLS_Ctx *ssl;
	BSL_UIO *uio;

	(void)accept_fd;

	if (!wsi->a.vhost || !wsi->a.vhost->tls.ssl_ctx)
		return 1;

	vhost_ctx = (lws_tls_ctx *)wsi->a.vhost->tls.ssl_ctx;
	if (!vhost_ctx->config)
		return 1;

	/* Create new SSL connection from vhost's config */
	ssl = HITLS_New(vhost_ctx->config);
	if (!ssl) {
		lwsl_err("%s: HITLS_New failed\n", __func__);
		return 1;
	}

	if (HITLS_SetUserData(ssl, wsi) != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_SetUserData failed\n", __func__);
		HITLS_Free(ssl);
		return 1;
	}

	if (wsi->a.vhost->tls.ssl_info_event_mask &&
	    HITLS_SetInfoCb(ssl, lws_ssl_info_callback) != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_SetInfoCb failed\n", __func__);
		HITLS_Free(ssl);
		return 1;
	}

	/* Create and attach BSL_UIO for I/O (TCP socket) */
	uio = BSL_UIO_New(BSL_UIO_TcpMethod());
	if (!uio) {
		lwsl_err("%s: BSL_UIO_New failed\n", __func__);
		HITLS_Free(ssl);
		return 1;
	}

	BSL_UIO_SetFD(uio, (int)wsi->desc.sockfd);

	/* Set non-blocking mode */
	BSL_UIO_Ctrl(uio, BSL_UIO_SET_NOBLOCK, 1, NULL);

	if (HITLS_SetUio(ssl, uio) != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_SetUio failed\n", __func__);
		BSL_UIO_Free(uio);
		HITLS_Free(ssl);
		return 1;
	}

	wsi->tls.ssl = ssl;
	return 0;
}

int
lws_tls_server_certs_load(struct lws_vhost *vhost, struct lws *wsi,
			  const char *cert, const char *private_key,
			  const char *mem_cert, size_t len_mem_cert,
			  const char *mem_privkey, size_t mem_privkey_len)
{
	lws_tls_ctx *ctx;
	HITLS_Config *verify_cfg;
	int n;

	(void)wsi;

	if (!vhost->tls.ssl_ctx)
		return 1;

	ctx = (lws_tls_ctx *)vhost->tls.ssl_ctx;
	if (!ctx->config)
		return 1;

	n = (int)lws_tls_generic_cert_checks(vhost, cert, private_key);
	if (!cert && !private_key)
		n = LWS_TLS_EXTANT_ALTERNATIVE;

	if (n == LWS_TLS_EXTANT_NO && (!mem_cert || !mem_privkey))
		return 0;
	if (n == LWS_TLS_EXTANT_NO)
		n = LWS_TLS_EXTANT_ALTERNATIVE;

	if (n == LWS_TLS_EXTANT_ALTERNATIVE && (!mem_cert || !mem_privkey)) {
		lwsl_err("%s: incomplete alternative cert/key update\n",
			 __func__);
		return 1;
	}

	if ((!!cert != !!private_key) ||
	    (!!mem_cert != !!mem_privkey) ||
	    (!!len_mem_cert != !!mem_privkey_len)) {
		lwsl_err("%s: cert/key updates must be provided as a pair\n",
			 __func__);
		return 1;
	}

	verify_cfg = HITLS_CFG_NewTLSConfig();
	if (!verify_cfg) {
		lwsl_err("%s: unable to allocate verification config\n",
			 __func__);
		return 1;
	}

	if (lws_openhitls_cfg_load_certkey_pair(verify_cfg,
			n == LWS_TLS_EXTANT_YES ? cert : NULL,
			n == LWS_TLS_EXTANT_YES ? private_key : NULL,
			n == LWS_TLS_EXTANT_ALTERNATIVE ? mem_cert : NULL,
			n == LWS_TLS_EXTANT_ALTERNATIVE ? len_mem_cert : 0,
			n == LWS_TLS_EXTANT_ALTERNATIVE ? mem_privkey : NULL,
			n == LWS_TLS_EXTANT_ALTERNATIVE ? mem_privkey_len : 0)) {
		HITLS_CFG_FreeConfig(verify_cfg);
		return 1;
	}

	HITLS_CFG_FreeConfig(verify_cfg);

	if (lws_openhitls_cfg_load_certkey_pair(ctx->config,
			n == LWS_TLS_EXTANT_YES ? cert : NULL,
			n == LWS_TLS_EXTANT_YES ? private_key : NULL,
			n == LWS_TLS_EXTANT_ALTERNATIVE ? mem_cert : NULL,
			n == LWS_TLS_EXTANT_ALTERNATIVE ? len_mem_cert : 0,
			n == LWS_TLS_EXTANT_ALTERNATIVE ? mem_privkey : NULL,
			n == LWS_TLS_EXTANT_ALTERNATIVE ? mem_privkey_len : 0))
		return 1;

	return 0;
}

int
lws_tls_server_client_cert_verify_config(struct lws_vhost *vh)
{
	lws_tls_ctx *ctx;

	if (!vh || !vh->tls.ssl_ctx)
		return -1;

	ctx = (lws_tls_ctx *)vh->tls.ssl_ctx;
	if (!ctx->config)
		return -1;

	if (!lws_check_opt(vh->options,
			   LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT))
		return 0;

	if (HITLS_CFG_SetClientVerifySupport(ctx->config, true) != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_SetClientVerifySupport failed\n",
			 __func__);
		return -1;
	}

	if (HITLS_CFG_SetNoClientCertSupport(ctx->config,
			lws_check_opt(vh->options,
				      LWS_SERVER_OPTION_PEER_CERT_NOT_REQUIRED))
			!= HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_SetNoClientCertSupport failed\n",
			 __func__);
		return -1;
	}

	if (HITLS_CFG_SetVerifyCb(ctx->config, OpenHiTLS_verify_callback)
			!= HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_SetVerifyCb failed\n", __func__);
		return -1;
	}

	if (!HITLS_CFG_GetVerifyStore(ctx->config))
		lwsl_warn("%s: client cert verify requested without explicit CA\n",
			  __func__);

	return 0;
}

static int
lws_openhitls_cert_info(HITLS_CERT_X509 *tls_cert, enum lws_tls_cert_info type,
			union lws_tls_cert_info_results *buf, size_t len)
{
	HITLS_X509_Cert *cert = (HITLS_X509_Cert *)tls_cert;
	char *str_val;
	uint32_t str_len;
	BSL_Buffer encode_buf;
	BSL_TIME bsl_time;
	struct tm t;
	int ret;

	if (!cert)
		return -1;

	buf->ns.len = 0;

	if (!len)
		len = sizeof(buf->ns.name);

	switch (type) {
	case LWS_TLS_CERT_INFO_COMMON_NAME:
		ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SUBJECT_CN_STR,
					  &str_val, 0);
		if (ret != HITLS_SUCCESS || !str_val)
			return -1;
		str_len = (uint32_t)strlen(str_val);
		if (str_len >= len) {
			BSL_SAL_Free(str_val);
			return -1;
		}
		memcpy(buf->ns.name, str_val, str_len);
		buf->ns.name[str_len] = '\0';
		buf->ns.len = (int)str_len;
		BSL_SAL_Free(str_val);
		break;

	case LWS_TLS_CERT_INFO_ISSUER_NAME:
		ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ISSUER_DN_STR,
					  &str_val, 0);
		if (ret != HITLS_SUCCESS || !str_val)
			return -1;
		str_len = (uint32_t)strlen(str_val);
		if (str_len >= len) {
			BSL_SAL_Free(str_val);
			return -1;
		}
		memcpy(buf->ns.name, str_val, str_len);
		buf->ns.name[str_len] = '\0';
		buf->ns.len = (int)str_len;
		BSL_SAL_Free(str_val);
		break;

	case LWS_TLS_CERT_INFO_VALIDITY_FROM:
		ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_BEFORE_TIME,
					  &bsl_time, sizeof(BSL_TIME));
		if (ret != HITLS_SUCCESS)
			return -1;
		memset(&t, 0, sizeof(t));
		t.tm_year = bsl_time.year - 1900;
		t.tm_mon = bsl_time.month - 1;
		t.tm_mday = bsl_time.day;
		t.tm_hour = bsl_time.hour;
		t.tm_min = bsl_time.minute;
		t.tm_sec = bsl_time.second;
		t.tm_isdst = 0;
		buf->time = mktime(&t);
		if (buf->time == (time_t)-1)
			return -1;
		break;

	case LWS_TLS_CERT_INFO_VALIDITY_TO:
		ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_AFTER_TIME,
					  &bsl_time, sizeof(BSL_TIME));
		if (ret != HITLS_SUCCESS)
			return -1;
		memset(&t, 0, sizeof(t));
		t.tm_year = bsl_time.year - 1900;
		t.tm_mon = bsl_time.month - 1;
		t.tm_mday = bsl_time.day;
		t.tm_hour = bsl_time.hour;
		t.tm_min = bsl_time.minute;
		t.tm_sec = bsl_time.second;
		t.tm_isdst = 0;
		buf->time = mktime(&t);
		if (buf->time == (time_t)-1)
			return -1;
		break;

	case LWS_TLS_CERT_INFO_USAGE:
		ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_KUSAGE,
					  &buf->usage, sizeof(buf->usage));
		if (ret != HITLS_SUCCESS)
			return -1;
		break;

	case LWS_TLS_CERT_INFO_OPAQUE_PUBLIC_KEY:
		encode_buf.data = (uint8_t *)buf->ns.name;
		encode_buf.dataLen = (uint32_t)len;
		ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_PUBKEY,
					  &encode_buf, sizeof(encode_buf));
		if (ret != HITLS_SUCCESS)
			return -1;
		buf->ns.len = (int)encode_buf.dataLen;
		break;

	case LWS_TLS_CERT_INFO_DER_RAW:
		encode_buf.data = (uint8_t *)buf->ns.name;
		encode_buf.dataLen = (uint32_t)len;
		ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ENCODE,
					  &encode_buf, sizeof(encode_buf));
		if (ret != HITLS_SUCCESS)
			return -1;
		buf->ns.len = (int)encode_buf.dataLen;
		break;

	default:
		return -1;
	}

	return 0;
}

int
lws_tls_peer_cert_info(struct lws *wsi, enum lws_tls_cert_info type,
		       union lws_tls_cert_info_results *buf, size_t len)
{
	HITLS_CERT_X509 *cert;
	HITLS_Ctx *ssl;
	int ret;

	if (!wsi || !wsi->tls.ssl)
		return -1;

	ssl = (HITLS_Ctx *)wsi->tls.ssl;

	cert = HITLS_GetPeerCertificate(ssl);
	if (!cert) {
		lwsl_debug("%s: no peer certificate\n", __func__);
		return -1;
	}

	if (type == LWS_TLS_CERT_INFO_VERIFIED) {
		HITLS_ERROR verify_result = HITLS_X509_V_OK;

		ret = HITLS_GetVerifyResult((const HITLS_Ctx *)ssl,
					    &verify_result);
		if (ret != HITLS_SUCCESS)
			return -1;

		buf->verified = verify_result == HITLS_X509_V_OK;

		return 0;
	}

	ret = lws_openhitls_cert_info(cert, type, buf, len);

	return ret;
}

int
lws_tls_vhost_cert_info(struct lws_vhost *vhost, enum lws_tls_cert_info type,
			       union lws_tls_cert_info_results *buf, size_t len)
{
	lws_tls_ctx *ctx;
	HITLS_CERT_X509 *cert;
	int ret;

	if (!vhost || !vhost->tls.ssl_ctx)
		return -1;

	ctx = (lws_tls_ctx *)vhost->tls.ssl_ctx;
	if (!ctx->config)
		return -1;

	cert = HITLS_CFG_GetCertificate(ctx->config);
	if (!cert) {
		lwsl_debug("%s: no vhost certificate configured\n", __func__);
		return -1;
	}

	/* Extract requested field using PKI module */
	ret = lws_openhitls_cert_info(cert, type, buf, len);

	return ret;
}

int
lws_tls_acme_sni_cert_create(struct lws_vhost *vhost, const char *san_a,
			     const char *san_b)
{
	HITLS_X509_Cert *xcrt = NULL;
	CRYPT_EAL_PkeyCtx *pkey = NULL;
	CRYPT_EAL_PkeyPara para;
	BSL_Buffer crt_der = { 0 }, key_der = { 0 };
	BslList *dn_subj = NULL;
	BslList *dn_issuer = NULL;
	BslList *san_names = NULL;
	HITLS_X509_ExtSan san;
	HITLS_X509_GeneralName gn;
	BSL_TIME before, after;
	int64_t utc;
	uint8_t exp_65537[] = { 0x01, 0x00, 0x01 };
	uint8_t serial_one[] = { 0x01 };
	BSL_Buffer serial = { serial_one, (uint32_t)sizeof(serial_one) };
	int32_t ver = HITLS_X509_VERSION_3;
	lws_tls_ctx *ctx;
	const char *cn = "temp.acme.invalid";
	const char *org = "somecompany";
	const char *c = "GB";
	int ret = 1, ss_new = 0, snapshot_new = 0;

	if (!vhost || !vhost->tls.ssl_ctx || !san_a || !san_a[0])
		return 1;

	ctx = (lws_tls_ctx *)vhost->tls.ssl_ctx;
	if (!ctx->config)
		return 1;

	if (!vhost->tls.ss) {
		vhost->tls.ss = lws_zalloc(sizeof(*vhost->tls.ss), __func__);
		if (!vhost->tls.ss)
			return 1;
		ss_new = 1;
	}
	vhost->tls.ss->temp_cert_active = 0;
	if (!vhost->tls.ss->orig_certkey_snapshot) {
		HITLS_CERT_X509 *cur_cert;
		HITLS_CERT_Key *cur_key;

		vhost->tls.ss->orig_certkey_snapshot = HITLS_CFG_NewTLSConfig();
		if (!vhost->tls.ss->orig_certkey_snapshot) {
			lwsl_err("%s: unable to allocate snapshot config\n",
				 __func__);
			goto cleanup;
		}
		snapshot_new = 1;

		cur_cert = HITLS_CFG_GetCertificate(ctx->config);
		cur_key = HITLS_CFG_GetPrivateKey(ctx->config);
		if (!cur_cert || !cur_key) {
			lwsl_warn("%s: no complete original cert/key to snapshot\n",
				  __func__);
		} else if (HITLS_CFG_SetCertificate(
				   vhost->tls.ss->orig_certkey_snapshot,
				   cur_cert, true) != HITLS_SUCCESS ||
			   HITLS_CFG_SetPrivateKey(
				   vhost->tls.ss->orig_certkey_snapshot,
				   cur_key, true) != HITLS_SUCCESS ||
			   HITLS_CFG_CheckPrivateKey(
				   vhost->tls.ss->orig_certkey_snapshot)
				   != HITLS_SUCCESS) {
			lwsl_err("%s: original cert/key snapshot failed\n",
				 __func__);
			goto cleanup;
		}
	}

	pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
	if (!pkey)
		goto cleanup;

	memset(&para, 0, sizeof(para));
	para.id = CRYPT_PKEY_RSA;
	para.para.rsaPara.e = exp_65537;
	para.para.rsaPara.eLen = (uint32_t)sizeof(exp_65537);
	para.para.rsaPara.bits = (uint32_t)lws_plat_recommended_rsa_bits();

	if (CRYPT_EAL_PkeySetPara(pkey, &para) != CRYPT_SUCCESS ||
	    CRYPT_EAL_PkeyGen(pkey) != CRYPT_SUCCESS) {
		lwsl_err("%s: RSA key generation failed\n", __func__);
		goto cleanup;
	}

	xcrt = HITLS_X509_CertNew();
	if (!xcrt)
		goto cleanup;

	if (HITLS_X509_CertCtrl(xcrt, HITLS_X509_SET_VERSION, &ver,
				sizeof(ver)) != HITLS_SUCCESS ||
	    HITLS_X509_CertCtrl(xcrt, HITLS_X509_SET_SERIALNUM, &serial,
				sizeof(serial)) != HITLS_SUCCESS) {
		lwsl_err("%s: set version/serial failed\n", __func__);
		goto cleanup;
	}

	if (BSL_SAL_SysTimeGet(&before) != BSL_SUCCESS ||
	    BSL_SAL_DateToUtcTimeConvert(&before, &utc) != BSL_SUCCESS ||
	    BSL_SAL_UtcTimeToDateConvert(utc + 3600, &after) != BSL_SUCCESS) {
		lwsl_err("%s: get cert validity time failed\n", __func__);
		goto cleanup;
	}

	if (HITLS_X509_CertCtrl(xcrt, HITLS_X509_SET_BEFORE_TIME, &before,
				sizeof(before)) != HITLS_SUCCESS ||
	    HITLS_X509_CertCtrl(xcrt, HITLS_X509_SET_AFTER_TIME, &after,
				sizeof(after)) != HITLS_SUCCESS) {
		lwsl_err("%s: set cert validity failed\n", __func__);
		goto cleanup;
	}

	dn_subj = HITLS_X509_DnListNew();
	dn_issuer = HITLS_X509_DnListNew();
	if (!dn_subj || !dn_issuer)
		goto cleanup;

	{
		HITLS_X509_DN dn[3];

		memset(dn, 0, sizeof(dn));
		dn[0].cid = BSL_CID_AT_COUNTRYNAME;
		dn[0].data = (uint8_t *)(uintptr_t)c;
		dn[0].dataLen = (uint32_t)strlen(c);
		dn[1].cid = BSL_CID_AT_ORGANIZATIONNAME;
		dn[1].data = (uint8_t *)(uintptr_t)org;
		dn[1].dataLen = (uint32_t)strlen(org);
		dn[2].cid = BSL_CID_AT_COMMONNAME;
		dn[2].data = (uint8_t *)(uintptr_t)cn;
		dn[2].dataLen = (uint32_t)strlen(cn);

		if (HITLS_X509_AddDnName(dn_subj, dn, 3) != HITLS_SUCCESS ||
		    HITLS_X509_AddDnName(dn_issuer, dn, 3) != HITLS_SUCCESS) {
			lwsl_err("%s: add subject/issuer DN failed\n", __func__);
			goto cleanup;
		}
	}

	if (HITLS_X509_CertCtrl(xcrt, HITLS_X509_SET_SUBJECT_DN, dn_subj, 0) !=
	    HITLS_SUCCESS ||
	    HITLS_X509_CertCtrl(xcrt, HITLS_X509_SET_ISSUER_DN, dn_issuer, 0) !=
	    HITLS_SUCCESS ||
	    HITLS_X509_CertCtrl(xcrt, HITLS_X509_SET_PUBKEY, pkey, 0) !=
	    HITLS_SUCCESS) {
		lwsl_err("%s: set cert DN/pubkey failed\n", __func__);
		goto cleanup;
	}

	san_names = BSL_LIST_New(sizeof(HITLS_X509_GeneralName));
	if (!san_names)
		goto cleanup;

	memset(&gn, 0, sizeof(gn));
	gn.type = HITLS_X509_GN_DNS;
	gn.value.data = (uint8_t *)(uintptr_t)san_a;
	gn.value.dataLen = (uint32_t)strlen(san_a);
	if (BSL_LIST_AddElement(san_names, &gn, BSL_LIST_POS_END) != BSL_SUCCESS)
		goto cleanup;

	if (san_b && san_b[0]) {
		memset(&gn, 0, sizeof(gn));
		gn.type = HITLS_X509_GN_DNS;
		gn.value.data = (uint8_t *)(uintptr_t)san_b;
		gn.value.dataLen = (uint32_t)strlen(san_b);
		if (BSL_LIST_AddElement(san_names, &gn, BSL_LIST_POS_END) !=
		    BSL_SUCCESS)
			goto cleanup;
	}

	memset(&san, 0, sizeof(san));
	san.critical = false;
	san.names = san_names;
	if (HITLS_X509_CertCtrl(xcrt, HITLS_X509_EXT_SET_SAN, &san,
				sizeof(san)) != HITLS_SUCCESS) {
		lwsl_err("%s: set SAN extension failed\n", __func__);
		goto cleanup;
	}

	if (HITLS_X509_CertSign(CRYPT_MD_SHA256, pkey, NULL, xcrt) !=
	    HITLS_SUCCESS ||
	    HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, xcrt, &crt_der) !=
	    HITLS_SUCCESS ||
	    !crt_der.data || !crt_der.dataLen) {
		lwsl_err("%s: cert sign/export failed\n", __func__);
		goto cleanup;
	}

	if (CRYPT_EAL_EncodeBuffKey(pkey, NULL, BSL_FORMAT_ASN1,
				    CRYPT_PRIKEY_PKCS8_UNENCRYPT, &key_der) !=
	    CRYPT_SUCCESS || !key_der.data || !key_der.dataLen) {
		lwsl_err("%s: private key export failed\n", __func__);
		goto cleanup;
	}

	if (HITLS_CFG_LoadCertBuffer(ctx->config, crt_der.data, crt_der.dataLen,
				     TLS_PARSE_FORMAT_ASN1) != HITLS_SUCCESS ||
	    HITLS_CFG_LoadKeyBuffer(ctx->config, key_der.data, key_der.dataLen,
				    TLS_PARSE_FORMAT_ASN1) != HITLS_SUCCESS ||
	    HITLS_CFG_CheckPrivateKey(ctx->config) != HITLS_SUCCESS) {
		lwsl_err("%s: loading generated cert/key into vhost failed\n",
			 __func__);
		goto cleanup;
	}

	vhost->tls.ss->temp_cert_active = 1;

	ret = 0;

cleanup:
	if (crt_der.data)
		BSL_SAL_Free(crt_der.data);
	if (key_der.data)
		BSL_SAL_Free(key_der.data);
	if (san_names)
		BSL_LIST_FREE(san_names, NULL);
	if (dn_subj)
		HITLS_X509_DnListFree(dn_subj);
	if (dn_issuer)
		HITLS_X509_DnListFree(dn_issuer);
	if (xcrt)
		HITLS_X509_CertFree(xcrt);
	if (pkey)
		CRYPT_EAL_PkeyFreeCtx(pkey);
	if (ret && snapshot_new && vhost->tls.ss &&
	    vhost->tls.ss->orig_certkey_snapshot) {
		HITLS_CFG_FreeConfig(vhost->tls.ss->orig_certkey_snapshot);
		vhost->tls.ss->orig_certkey_snapshot = NULL;
	}
	if (ret && ss_new)
		lws_openhitls_tls_ss_free(vhost);

	return ret;
}

void
lws_tls_acme_sni_cert_destroy(struct lws_vhost *vhost)
{
	lws_tls_ctx *ctx;
	HITLS_CERT_X509 *cert = NULL;
	HITLS_CERT_Key *key = NULL;
	struct lws wsi;
	int restored = 0, snapshot_attempted = 0, path_attempted = 0;
	int cleared_cert = 0, cleared_key = 0;
	int snapshot_available = 0, path_available = 0;

	if (!vhost || !vhost->tls.ss)
		return;

	ctx = (lws_tls_ctx *)vhost->tls.ssl_ctx;
	snapshot_available = !!(ctx && ctx->config &&
				 vhost->tls.ss->orig_certkey_snapshot);
	path_available = !!(vhost->tls.alloc_cert_path && vhost->tls.key_path);

	if (vhost->tls.ss->temp_cert_active) {
		if (snapshot_available) {
			snapshot_attempted = 1;
			cert = HITLS_CFG_GetCertificate(
					vhost->tls.ss->orig_certkey_snapshot);
			key = HITLS_CFG_GetPrivateKey(
					vhost->tls.ss->orig_certkey_snapshot);
			if (cert && key &&
			    HITLS_CFG_SetCertificate(ctx->config, cert, true) ==
				    HITLS_SUCCESS &&
			    HITLS_CFG_SetPrivateKey(ctx->config, key, true) ==
				    HITLS_SUCCESS &&
			    HITLS_CFG_CheckPrivateKey(ctx->config) ==
				    HITLS_SUCCESS) {
				lwsl_vhost_notice(vhost,
					"%s: restored original cert/key from snapshot",
					__func__);
				restored = 1;
			}
		}

		if (path_available) {
			path_attempted = 1;
			memset(&wsi, 0, sizeof(wsi));
			wsi.a.context = vhost->context;
			wsi.a.vhost = vhost;

			if (!restored &&
			    !lws_tls_server_certs_load(vhost, &wsi,
					vhost->tls.alloc_cert_path,
					vhost->tls.key_path,
					NULL, 0, NULL, 0)) {
				lwsl_vhost_notice(vhost,
					"%s: restored original cert/key from paths",
					__func__);
				restored = 1;
			}
		}

		if (!restored)
			lwsl_vhost_warn(vhost,
				"%s: failed to restore original cert/key after temp cert",
				__func__);

		if (!restored && ctx && ctx->config) {
			HITLS_CERT_X509 *cur_cert = HITLS_CFG_GetCertificate(
								ctx->config);
			HITLS_CERT_Key *cur_key = HITLS_CFG_GetPrivateKey(
								ctx->config);

			if (cur_cert &&
			    HITLS_CFG_FreeCert(ctx->config, cur_cert) ==
				    HITLS_SUCCESS) {
				lwsl_vhost_notice(vhost,
					"%s: cleared temporary certificate from config",
					__func__);
				cleared_cert = 1;
			}
			if (cur_key &&
			    HITLS_CFG_FreeKey(ctx->config, cur_key) ==
				    HITLS_SUCCESS) {
				lwsl_vhost_notice(vhost,
					"%s: cleared temporary private key from config",
					__func__);
				cleared_key = 1;
			}

			if (!cleared_cert && !cleared_key)
				lwsl_vhost_warn(vhost,
					"%s: failed to clear temporary cert/key from config",
					__func__);
		}

		if (!restored)
			lwsl_vhost_notice(vhost,
				"%s: recovery summary snapshot(avail=%d,try=%d) path(avail=%d,try=%d) clear(cert=%d,key=%d)",
				__func__, snapshot_available, snapshot_attempted,
				path_available, path_attempted,
				cleared_cert, cleared_key);

		vhost->tls.ss->temp_cert_active = 0;
	}

	lws_openhitls_tls_ss_free(vhost);
}

int
lws_tls_acme_sni_csr_create(struct lws_context *context, const char *elements[],
			    uint8_t *csr, size_t csr_len, char **privkey_pem,
			    size_t *privkey_len)
{
#if defined(LWS_WITH_JOSE)
	static const BslCid dn_cid[LWS_TLS_REQ_ELEMENT_COUNT] = {
		BSL_CID_AT_COUNTRYNAME,
		BSL_CID_AT_STATEORPROVINCENAME,
		BSL_CID_AT_LOCALITYNAME,
		BSL_CID_AT_ORGANIZATIONNAME,
		BSL_CID_AT_COMMONNAME,
		0, /* subjectAltName is extension, not DN */
		BSL_CID_EMAILADDRESS,
	};
	HITLS_X509_Csr *xcsr = NULL;
	HITLS_X509_Attrs *attrs = NULL;
	HITLS_X509_Ext *ext = NULL;
	CRYPT_EAL_PkeyCtx *pkey = NULL;
	BSL_Buffer csr_der = { 0 }, key_pem = { 0 };
	CRYPT_EAL_PkeyPara para;
	BslList *dn_list = NULL;
	BslList *san_names = NULL;
	uint8_t exp_65537[] = { 0x01, 0x00, 0x01 };
	size_t klen;
	int n, ret = 1;

	(void)context;

	if (!elements || !csr || !csr_len || !privkey_pem || !privkey_len)
		return 1;

	*privkey_pem = NULL;
	*privkey_len = 0;

	pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
	if (!pkey)
		goto cleanup;

	memset(&para, 0, sizeof(para));
	para.id = CRYPT_PKEY_RSA;
	para.para.rsaPara.e = exp_65537;
	para.para.rsaPara.eLen = (uint32_t)sizeof(exp_65537);
	para.para.rsaPara.bits = (uint32_t)lws_plat_recommended_rsa_bits();

	if (CRYPT_EAL_PkeySetPara(pkey, &para) != CRYPT_SUCCESS ||
	    CRYPT_EAL_PkeyGen(pkey) != CRYPT_SUCCESS) {
		lwsl_err("%s: RSA key generation failed\n", __func__);
		goto cleanup;
	}

	xcsr = HITLS_X509_CsrNew();
	if (!xcsr)
		goto cleanup;

	if (HITLS_X509_CsrCtrl(xcsr, HITLS_X509_SET_PUBKEY, pkey, 0) !=
	    HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_X509_SET_PUBKEY failed\n", __func__);
		goto cleanup;
	}

	dn_list = HITLS_X509_DnListNew();
	if (!dn_list)
		goto cleanup;

	for (n = 0; n < LWS_TLS_REQ_ELEMENT_COUNT; n++) {
		HITLS_X509_DN dn;
		const char *v = elements[n];

		if (n == LWS_TLS_REQ_ELEMENT_SUBJECT_ALT_NAME)
			continue;
		if (!dn_cid[n])
			continue;
		if (!v || !v[0])
			v = "none";

		memset(&dn, 0, sizeof(dn));
		dn.cid = dn_cid[n];
		dn.data = (uint8_t *)(uintptr_t)v;
		dn.dataLen = (uint32_t)strlen(v);
		if (HITLS_X509_AddDnName(dn_list, &dn, 1) != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_X509_AddDnName failed at %d\n",
				 __func__, n);
			goto cleanup;
		}
	}

	if (HITLS_X509_CsrCtrl(xcsr, HITLS_X509_SET_SUBJECT_DN, dn_list, 0) !=
	    HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_X509_SET_SUBJECT_DN failed\n", __func__);
		goto cleanup;
	}

	if (elements[LWS_TLS_REQ_ELEMENT_SUBJECT_ALT_NAME] &&
	    elements[LWS_TLS_REQ_ELEMENT_SUBJECT_ALT_NAME][0]) {
		HITLS_X509_ExtSan san;
		HITLS_X509_GeneralName gn;
		const char *cn = elements[LWS_TLS_REQ_ELEMENT_COMMON_NAME];
		const char *san_alt = elements[LWS_TLS_REQ_ELEMENT_SUBJECT_ALT_NAME];

		san_names = BSL_LIST_New(sizeof(HITLS_X509_GeneralName));
		if (!san_names)
			goto cleanup;

		memset(&gn, 0, sizeof(gn));
		gn.type = HITLS_X509_GN_DNS;
		if (cn && cn[0]) {
			gn.value.data = (uint8_t *)(uintptr_t)cn;
			gn.value.dataLen = (uint32_t)strlen(cn);
			if (BSL_LIST_AddElement(san_names, &gn,
						BSL_LIST_POS_END) != BSL_SUCCESS) {
				lwsl_err("%s: BSL_LIST_AddElement CN SAN failed\n",
					 __func__);
				goto cleanup;
			}
		}

		memset(&gn, 0, sizeof(gn));
		gn.type = HITLS_X509_GN_DNS;
		gn.value.data = (uint8_t *)(uintptr_t)san_alt;
		gn.value.dataLen = (uint32_t)strlen(san_alt);
		if (BSL_LIST_AddElement(san_names, &gn, BSL_LIST_POS_END) !=
		    BSL_SUCCESS) {
			lwsl_err("%s: BSL_LIST_AddElement alt SAN failed\n",
				 __func__);
			goto cleanup;
		}

		ext = HITLS_X509_ExtNew(HITLS_X509_EXT_TYPE_CSR);
		if (!ext)
			goto cleanup;

		memset(&san, 0, sizeof(san));
		san.critical = false;
		san.names = san_names;
		if (HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_SAN, &san,
				       sizeof(san)) != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_X509_EXT_SET_SAN failed\n", __func__);
			goto cleanup;
		}

		if (HITLS_X509_CsrCtrl(xcsr, HITLS_X509_CSR_GET_ATTRIBUTES, &attrs,
				       sizeof(attrs)) != HITLS_SUCCESS || !attrs) {
			lwsl_err("%s: HITLS_X509_CSR_GET_ATTRIBUTES failed\n",
				 __func__);
			goto cleanup;
		}

		if (HITLS_X509_AttrCtrl(attrs,
					HITLS_X509_ATTR_SET_REQUESTED_EXTENSIONS,
					ext, 0) != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_X509_ATTR_SET_REQUESTED_EXTENSIONS failed\n",
				 __func__);
			goto cleanup;
		}
	}

	if (HITLS_X509_CsrSign(CRYPT_MD_SHA256, pkey, NULL, xcsr) !=
	    HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_X509_CsrSign failed\n", __func__);
		goto cleanup;
	}

	if (HITLS_X509_CsrGenBuff(BSL_FORMAT_ASN1, xcsr, &csr_der) !=
	    HITLS_SUCCESS || !csr_der.data || !csr_der.dataLen) {
		lwsl_err("%s: HITLS_X509_CsrGenBuff failed\n", __func__);
		goto cleanup;
	}

	n = lws_jws_base64_enc((char *)csr_der.data, csr_der.dataLen,
			       (char *)csr, csr_len);
	if (n < 0) {
		lwsl_err("%s: lws_jws_base64_enc failed\n", __func__);
		goto cleanup;
	}

	if (CRYPT_EAL_EncodeBuffKey(pkey, NULL, BSL_FORMAT_PEM,
				    CRYPT_PRIKEY_PKCS8_UNENCRYPT,
				    &key_pem) != CRYPT_SUCCESS ||
	    !key_pem.data || !key_pem.dataLen) {
		lwsl_err("%s: CRYPT_EAL_EncodeBuffKey failed\n", __func__);
		goto cleanup;
	}

	klen = key_pem.dataLen;
	if (klen && key_pem.data[klen - 1] == '\0')
		klen--;

	*privkey_pem = malloc(klen + 1);
	if (!*privkey_pem)
		goto cleanup;
	memcpy(*privkey_pem, key_pem.data, klen);
	(*privkey_pem)[klen] = '\0';
	*privkey_len = klen;
	ret = 0;

cleanup:
	if (ret) {
		if (*privkey_pem) {
			free(*privkey_pem);
			*privkey_pem = NULL;
		}
		*privkey_len = 0;
	}
	if (key_pem.data)
		BSL_SAL_Free(key_pem.data);
	if (csr_der.data)
		BSL_SAL_Free(csr_der.data);
	if (ext)
		HITLS_X509_ExtFree(ext);
	if (san_names)
		BSL_LIST_FREE(san_names, NULL);
	if (dn_list)
		HITLS_X509_DnListFree(dn_list);
	if (xcsr)
		HITLS_X509_CsrFree(xcsr);
	if (pkey)
		CRYPT_EAL_PkeyFreeCtx(pkey);

	return ret;
#else
	(void)context;
	(void)elements;
	(void)csr;
	(void)csr_len;
	(void)privkey_pem;
	(void)privkey_len;

	lwsl_notice("%s: ACME CSR/key generation requires LWS_WITH_JOSE\n",
		    __func__);

	return 1;
#endif
}

enum lws_ssl_capable_status
lws_tls_server_abort_connection(struct lws *wsi)
{
	if (wsi->tls.use_ssl)
		__lws_tls_shutdown(wsi);

	return LWS_SSL_CAPABLE_DONE;
}

enum lws_ssl_capable_status
lws_tls_server_accept(struct lws *wsi)
{
	int ret, m;

	if (!wsi->tls.ssl)
		return LWS_SSL_CAPABLE_ERROR;

	lws_openhitls_verify_bind(wsi->tls.ssl);
	ret = HITLS_Accept(wsi->tls.ssl);
	lws_openhitls_verify_unbind();

	wsi->skip_fallback = 1;

	if (ret == HITLS_SUCCESS) {

#if !defined(LWS_WITH_NO_LOGS)
		/* OpenHiTLS does not have equivalent cipher description API */
#endif

		if (lws_openhitls_pending_bytes(wsi) &&
		    lws_dll2_is_detached(&wsi->tls.dll_pending_tls))
			lws_dll2_add_head(&wsi->tls.dll_pending_tls,
					  &wsi->a.context->pt[(int)wsi->tsi].
					  tls.dll_pending_tls_owner);

		return LWS_SSL_CAPABLE_DONE;
	}

	lwsl_debug("%s: HITLS_Accept returned 0x%x\n", __func__, ret);
	m = lws_ssl_get_error(wsi, ret);

	if (m == LWS_SSL_CAPABLE_ERROR)
		return LWS_SSL_CAPABLE_ERROR;

	if (m == LWS_SSL_CAPABLE_MORE_SERVICE_READ) {
		if (lws_change_pollfd(wsi, 0, LWS_POLLIN)) {
			lwsl_info("%s: WANT_READ change_pollfd failed\n",
				  __func__);
			return LWS_SSL_CAPABLE_ERROR;
		}

		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
	}
	if (m == LWS_SSL_CAPABLE_MORE_SERVICE_WRITE) {
		lwsl_debug("%s: WANT_WRITE\n", __func__);

		if (lws_change_pollfd(wsi, 0, LWS_POLLOUT)) {
			lwsl_info("%s: WANT_WRITE change_pollfd failed\n",
				  __func__);
			return LWS_SSL_CAPABLE_ERROR;
		}
		return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
	}

	return LWS_SSL_CAPABLE_ERROR;
}
