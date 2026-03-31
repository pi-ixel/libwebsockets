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

static void
lws_openhitls_log_error_string(const char *prefix, const char *subject,
			       int32_t ret)
{
	const char *file = NULL;
	const char *s;
	uint32_t line = 0;
	int32_t err;

	err = BSL_ERR_PeekErrorFileLine(&file, &line);
	if (!err) {
		err = ret;
	}

	s = BSL_ERR_GetString(err);
	lwsl_err("%s '%s' 0x%x: %s\n", prefix, subject ? subject : "?",
		 (unsigned int)err, (s && *s) ? s : "unknown");
}

static int
OpenHiTLS_verify_callback(int32_t is_preverify_ok,
			       HITLS_CERT_StoreCtx *store_ctx)
{
	void *userdata = NULL;
	struct lws *wsi;
	lws_tls_conn *ssl;
	const struct lws_protocols *lp;
	HITLS_X509_Cert *topcert = NULL;
	union lws_tls_cert_info_results ir;
	int n;

	HITLS_X509_StoreCtxCtrl((HITLS_X509_StoreCtx *)store_ctx,
					HITLS_X509_STORECTX_GET_USR_DATA,
					&userdata,
					(uint32_t)sizeof(userdata));

	ssl = (lws_tls_conn *)userdata;
	wsi = ssl ? (struct lws *)HITLS_GetUserData((HITLS_Ctx *)ssl) : NULL;
	ssl = wsi ? wsi->tls.ssl : NULL;

	if (!wsi || !wsi->a.vhost || !wsi->a.vhost->protocols) {
		return 1;
	}

	if (!HITLS_X509_StoreCtxCtrl((HITLS_X509_StoreCtx *)store_ctx,
				     HITLS_X509_STORECTX_GET_CUR_CERT,
				     &topcert, sizeof(topcert)) &&
	    topcert &&
	    !lws_tls_openhitls_cert_info(topcert, LWS_TLS_CERT_INFO_COMMON_NAME,
					 &ir, sizeof(ir.ns.name))) {
		lwsl_info("%s: client cert CN '%s'\n", __func__, ir.ns.name);
	}
	else
		lwsl_info("%s: couldn't get client cert CN\n", __func__);

	lp = &wsi->a.vhost->protocols[0];
	n = lp->callback(wsi,
			 LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION,
			 store_ctx, ssl, (unsigned int)is_preverify_ok);

	return n;
}

int
lws_tls_server_client_cert_verify_config(struct lws_vhost *vh)
{
	lws_tls_ctx *ctx;

	if (!vh || !vh->tls.ssl_ctx) {
		return -1;
	}

	ctx = (lws_tls_ctx *)vh->tls.ssl_ctx;
	if (!ctx) {
		return -1;
	}

	if (!lws_check_opt(vh->options,
			   LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT)) {
		return 0;
	}

	if (HITLS_CFG_SetClientVerifySupport(ctx, true) != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_SetClientVerifySupport failed\n",
			 __func__);
		return -1;
	}

	if (HITLS_CFG_SetNoClientCertSupport(ctx,
			lws_check_opt(vh->options,
				      LWS_SERVER_OPTION_PEER_CERT_NOT_REQUIRED))
			!= HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_SetNoClientCertSupport failed\n",
			 __func__);
		return -1;
	}

	if (HITLS_CFG_SetSessionIdCtx(ctx,
				      (const uint8_t *)vh->context,
				      sizeof(void *)) != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_SetSessionIdCtx failed\n", __func__);
		return -1;
	}

	if (HITLS_CFG_SetVerifyCb(ctx, OpenHiTLS_verify_callback)
			!= HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_SetVerifyCb failed\n", __func__);
		return -1;
	}

	return 0;
}

static int32_t
lws_ssl_server_name_cb(HITLS_Ctx *ssl, int *alert, void *arg)
{
	struct lws_context *context = (struct lws_context *)arg;
	struct lws_vhost *vhost, *vh;
	lws_tls_ctx *target_ctx;
	const char *servername;

	(void)alert;

	if (!ssl || !context) {
		return HITLS_ACCEPT_SNI_ERR_NOACK;
	}

	vh = context->vhost_list;
	while (vh) {
		lws_tls_ctx *ctx = (lws_tls_ctx *)vh->tls.ssl_ctx;

		if (!vh->being_destroyed && ctx && ctx == HITLS_GetGlobalConfig(ssl)) {
			break;
		}
		vh = vh->vhost_next;
	}

	if (!vh) {
		return HITLS_ACCEPT_SNI_ERR_OK;
	}

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
	if (!target_ctx) {
		return HITLS_ACCEPT_SNI_ERR_OK;
	}

	if (!HITLS_SetNewConfig(ssl, target_ctx)) {
		return HITLS_ACCEPT_SNI_ERR_ALERT_FATAL;
	}

	lwsl_info("SNI: Found: %s:%d\n", servername, vh->listen_port);

	return HITLS_ACCEPT_SNI_ERR_OK;
}

/*
 * this may now get called after the vhost creation, when certs become
 * available.
 */
int
lws_tls_server_certs_load(struct lws_vhost *vhost, struct lws *wsi,
			  const char *cert, const char *private_key,
			  const char *mem_cert, size_t mem_cert_len,
			  const char *mem_privkey, size_t mem_privkey_len)
{
	lws_tls_ctx *ctx;
	HITLS_Config *config;
	lws_filepos_t flen;
	uint8_t *der_buf = NULL;
	int n, ret;

	(void)wsi;

	n = (int)lws_tls_generic_cert_checks(vhost, cert, private_key);

	if (!cert && !private_key) {
		n = LWS_TLS_EXTANT_ALTERNATIVE;
	}

	if (n == LWS_TLS_EXTANT_NO && (!mem_cert || !mem_privkey)) {
		return 0;
	}
	if (n == LWS_TLS_EXTANT_NO) {
		n = LWS_TLS_EXTANT_ALTERNATIVE;
	}

	if (n == LWS_TLS_EXTANT_ALTERNATIVE && (!mem_cert || !mem_privkey)) {
		return 1;
	} /* no alternative */

	if (n == LWS_TLS_EXTANT_ALTERNATIVE) {
		/*
		 * Although we have prepared update certs, we no longer have
		 * the rights to read our own cert + key we saved.
		 *
		 * If we were passed copies in memory buffers, use those
		 * in favour of the filepaths we normally want.
		 */
		cert = NULL;
		private_key = NULL;
	}

	/*
	 * use the multi-cert interface for backwards compatibility in the
	 * both simple files case
	 */

	if (n != LWS_TLS_EXTANT_ALTERNATIVE && cert) {
		int m;

		if (!vhost->tls.ssl_ctx) {
			return 1;
		}

		ctx = (lws_tls_ctx *)vhost->tls.ssl_ctx;
		config = ctx;
		if (!config) {
			return 1;
		}

		/* Prefer chain-file semantics to match the OpenSSL server path. */
		m = HITLS_CFG_UseCertificateChainFile(config, cert);
		if (m != HITLS_SUCCESS) {
			lws_openhitls_log_error_string("problem getting cert",
						       cert, m);

			return 1;
		}

		if (!private_key) {
			lwsl_err("ssl private key not set\n");
			return 1;
		} else {
			/* set the private key from KeyFile */
			ret = HITLS_CFG_LoadKeyFile(config, private_key,
						    TLS_PARSE_FORMAT_PEM);
			if (ret != HITLS_SUCCESS) {
				lws_openhitls_log_error_string("ssl problem getting key",
						       private_key, ret);
				return 1;
			}
		}

		return 0;
	}

	/* Match the client path: normalize memory PEM/DER into DER, then load ASN.1. */

	if (!vhost->tls.ssl_ctx) {
		return 1;
	}

	ctx = (lws_tls_ctx *)vhost->tls.ssl_ctx;
	config = ctx;
	if (!config) {
		return 1;
	}

	if (lws_tls_alloc_pem_to_der_file(vhost->context, NULL, mem_cert,
					  (lws_filepos_t)mem_cert_len, &der_buf,
					  &flen)) {
		lwsl_err("%s: couldn't read cert file\n", __func__);

		return 1;
	}
	ret = HITLS_CFG_LoadCertBuffer(config, der_buf, (uint32_t)flen,
				       TLS_PARSE_FORMAT_ASN1);
	if (ret != HITLS_SUCCESS) {
		lws_free_set_NULL(der_buf);
		lws_openhitls_log_error_string("couldn't read cert file",
					       "memory", ret);
		lws_tls_err_describe_clear();

		return 1;
	}
	lws_free_set_NULL(der_buf);

	if (lws_tls_alloc_pem_to_der_file(vhost->context, NULL, mem_privkey,
					  (lws_filepos_t)mem_privkey_len,
					  &der_buf, &flen)) {
		lwsl_notice("unable to convert memory privkey\n");

		return 1;
	}
	ret = HITLS_CFG_LoadKeyBuffer(config, der_buf, (uint32_t)flen,
				      TLS_PARSE_FORMAT_ASN1);
	if (ret != HITLS_SUCCESS) {
		lws_free_set_NULL(der_buf);
		lws_openhitls_log_error_string("unable to convert memory privkey",
					       "memory", ret);

		return 1;
	}
	lws_free_set_NULL(der_buf);

	/* verify private key */
	ret = HITLS_CFG_CheckPrivateKey(config);
	if (ret != HITLS_SUCCESS) {
		lws_openhitls_log_error_string("Private SSL key doesn't match cert",
					       "memory", ret);

		return 1;
	}

	vhost->tls.skipped_certs = 0;

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
	int ret;

	(void)wsi;

	/* Create full TLS config so options_set/clear version mapping can apply */
	config = HITLS_CFG_NewTLSConfig();
	if (!config) {
		lwsl_err("%s: HITLS_CFG_NewTLSConfig failed\n", __func__);
		return 1;
	}

	ctx = config;
	/* Assign ctx to vhost immediately, so vhost destruction handles cleanup */
	vhost->tls.ssl_ctx = ctx;

#if defined(LWS_WITH_TLS) && (!defined(LWS_WITHOUT_CLIENT) || !defined(LWS_WITHOUT_SERVER))
	if (vhost->context->keylog_file[0]) {
		ret = HITLS_CFG_SetKeyLogCb(config, lws_openhitls_klog_dump);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_CFG_SetKeyLogCb failed: 0x%x\n",
				 __func__, ret);
			return 1;
		}
	}
#endif

	ret = HITLS_CFG_SetConfigUserData(config, vhost->context);
	if (ret != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_SetConfigUserData failed: 0x%x\n",
			 __func__, ret);
		return 1;
	}

	if (lws_check_opt(info->options,
			  LWS_SERVER_OPTION_OPENSSL_AUTO_DH_PARAMETERS) &&
	    HITLS_CFG_SetDhAutoSupport(config, true) != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_SetDhAutoSupport failed\n", __func__);
		return 1;
	}

	HITLS_CFG_SetCipherServerPreference(config, true);

	HITLS_CFG_SetModeSupport(config,
				       HITLS_MODE_ACCEPT_MOVING_WRITE_BUFFER |
				       HITLS_MODE_RELEASE_BUFFERS);

	if (info->tls1_3_plus_cipher_list && info->tls1_3_plus_cipher_list[0]) {
		lws_openhitls_collect_cipher_list(info->tls1_3_plus_cipher_list,
							suites,
							LWS_ARRAY_SIZE(suites),
							&suites_count, __func__);
	}

	if (info->ssl_cipher_list && info->ssl_cipher_list[0]) {
		lws_openhitls_collect_cipher_list(info->ssl_cipher_list,
							suites,
							LWS_ARRAY_SIZE(suites),
							&suites_count, __func__);
	}

	if (suites_count &&
	    HITLS_CFG_SetCipherSuites(config, suites,
				      (uint32_t)suites_count) != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_SetCipherSuites failed\n", __func__);
		return 1;
	}

	if (HITLS_CFG_SetServerNameCb(config, lws_ssl_server_name_cb)
			!= HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_SetServerNameCb failed\n", __func__);
		return 1;
	}

	if (HITLS_CFG_SetServerNameArg(config, vhost->context) != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_SetServerNameArg failed\n", __func__);
		return 1;
	}

	if (info->ssl_ca_filepath &&
	    HITLS_CFG_LoadVerifyFile(config, info->ssl_ca_filepath) !=
			    HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_LoadVerifyFile unhappy\n",
			 __func__);
	}

	if (!vhost->tls.use_ssl ||
	    (!info->ssl_cert_filepath && !info->server_ssl_cert_mem)) {
		return 0;
	}

	lws_ssl_bind_passphrase(ctx, 0, info);

	return lws_tls_server_certs_load(vhost, wsi, info->ssl_cert_filepath,
					 info->ssl_private_key_filepath,
					 info->server_ssl_cert_mem,
					 info->server_ssl_cert_mem_len,
					 info->server_ssl_private_key_mem,
					 info->server_ssl_private_key_mem_len);
}

int
lws_tls_server_new_nonblocking(struct lws *wsi, lws_sockfd_type accept_fd)
{
	lws_tls_ctx *vhost_ctx;
	HITLS_Ctx *ssl;
	BSL_UIO *uio;

	if (!wsi->a.vhost || !wsi->a.vhost->tls.ssl_ctx) {
		lwsl_err("%s: no vhost or ssl_ctx\n", __func__);
		return 1;
	}

	vhost_ctx = (lws_tls_ctx *)wsi->a.vhost->tls.ssl_ctx;
	if (!vhost_ctx) {
		lwsl_err("%s: no config in vhost ctx\n", __func__);
		return 1;
	}

	/* Create new SSL connection from vhost's config */
	ssl = HITLS_New(vhost_ctx);
	if (!ssl) {
		lwsl_err("%s: HITLS_New failed\n", __func__);
		return 1;
	}

	if (HITLS_SetUserData(ssl, wsi) != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_SetUserData failed\n", __func__);
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

	if (HITLS_SetModeSupport(ssl,
				 HITLS_MODE_ACCEPT_MOVING_WRITE_BUFFER |
				 HITLS_MODE_RELEASE_BUFFERS) != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_SetModeSupport failed\n", __func__);
		HITLS_Free(ssl);
		return 1;
	}

	wsi->tls.ssl = ssl;
	if (wsi->a.vhost->tls.ssl_info_event_mask &&
	    HITLS_SetInfoCb(ssl, lws_ssl_info_callback) != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_SetInfoCb failed\n", __func__);
		HITLS_Free(ssl);
		return 1;
	}
	return 0;
}

enum lws_ssl_capable_status
lws_tls_server_abort_connection(struct lws *wsi)
{
	BSL_UIO *uio = NULL;

	if (!wsi->tls.ssl) {
		return LWS_SSL_CAPABLE_DONE;
	}

	/*
	 * HITLS_Close() (called from __lws_tls_shutdown) has been observed to
	 * corrupt heap metadata.  Skip it; HITLS_Free() handles full cleanup.
	 */
	uio = HITLS_GetUio(wsi->tls.ssl);
	if (uio) {
		BSL_UIO_SetFD(uio, -1);
	}
	HITLS_Free(wsi->tls.ssl);
	wsi->tls.ssl = NULL;

	return LWS_SSL_CAPABLE_DONE;
}

enum lws_ssl_capable_status
lws_tls_server_accept(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	union lws_tls_cert_info_results ir;
	int ret;

	if (!wsi->tls.ssl) {
		return LWS_SSL_CAPABLE_ERROR;
	}

	ret = HITLS_Accept(wsi->tls.ssl);

	wsi->skip_fallback = 1;

	if (ret == HITLS_SUCCESS) {

		if (!lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_COMMON_NAME, &ir,
						   sizeof(ir.ns.name))) {
			lwsl_notice("%s: client cert CN '%s'\n", __func__,
							    ir.ns.name);
		}
		else
			lwsl_info("%s: no client cert CN\n", __func__);

		lws_openhitls_describe_cipher(wsi);

		if (HITLS_GetReadPendingBytes(wsi->tls.ssl) &&
		    lws_dll2_is_detached(&wsi->tls.dll_pending_tls)) {
			lws_dll2_add_head(&wsi->tls.dll_pending_tls,
								  &pt->tls.dll_pending_tls_owner);
		}

		return LWS_SSL_CAPABLE_DONE;
	}

	lwsl_debug("%s: HITLS_Accept returned 0x%x\n", __func__, ret);
	ret = lws_ssl_get_error(wsi, ret);

	if (ret == HITLS_ERR_TLS || ret == HITLS_ERR_SYSCALL) {
		return LWS_SSL_CAPABLE_ERROR;
	}

	if (ret == HITLS_WANT_READ) {
		if (lws_change_pollfd(wsi, 0, LWS_POLLIN)) {
			lwsl_info("%s: WANT_READ change_pollfd failed\n",
				  __func__);
			return LWS_SSL_CAPABLE_ERROR;
		}

		lwsl_info("SSL_ERROR_WANT_READ: ret %d\n", ret);
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
	}
	if (ret == HITLS_WANT_WRITE) {
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

int
lws_tls_acme_sni_cert_create(struct lws_vhost *vhost, const char *san_a,
			     const char *san_b)
{
	(void)vhost;
	(void)san_a;
	(void)san_b;

	return 1;
}

void
lws_tls_acme_sni_cert_destroy(struct lws_vhost *vhost)
{
	(void)vhost;
}

int
lws_tls_acme_sni_csr_create(struct lws_context *context, const char *elements[],
			    uint8_t *csr, size_t csr_len, char **privkey_pem,
			    size_t *privkey_len)
{
	(void)context;
	(void)elements;
	(void)csr;
	(void)csr_len;
	(void)privkey_pem;
	(void)privkey_len;

	return 1;
}
