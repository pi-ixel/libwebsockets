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

struct lws_tls_ss_pieces {
	HITLS_X509_Cert *x509;
	CRYPT_EAL_PkeyCtx *pkey;
};

static void
lws_openhitls_tls_ss_free(struct lws_vhost *vhost)
{
	if (!vhost || !vhost->tls.ss) {
		return;
	}

	if (vhost->tls.ss->x509) {
		HITLS_X509_CertFree(vhost->tls.ss->x509);
	}
	if (vhost->tls.ss->pkey) {
		CRYPT_EAL_PkeyFreeCtx(vhost->tls.ss->pkey);
	}

	lws_free_set_NULL(vhost->tls.ss);
}

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
	int ret = 1, ss_new = 0;

	if (!vhost || !vhost->tls.ssl_ctx || !san_a || !san_a[0]) {
		return 1;
	}

	ctx = (lws_tls_ctx *)vhost->tls.ssl_ctx;
	if (!ctx) {
		return 1;
	}

	if (!vhost->tls.ss) {
		vhost->tls.ss = lws_zalloc(sizeof(*vhost->tls.ss), __func__);
		if (!vhost->tls.ss) {
			return 1;
		}
		ss_new = 1;
	}

	pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
	if (!pkey) {
		goto cleanup;
	}

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
	if (!xcrt) {
		goto cleanup;
	}

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
	if (!dn_subj || !dn_issuer) {
		goto cleanup;
	}

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
	if (!san_names) {
		goto cleanup;
	}

	memset(&gn, 0, sizeof(gn));
	gn.type = HITLS_X509_GN_DNS;
	gn.value.data = (uint8_t *)(uintptr_t)san_a;
	gn.value.dataLen = (uint32_t)strlen(san_a);
	if (BSL_LIST_AddElement(san_names, &gn, BSL_LIST_POS_END) != BSL_SUCCESS) {
		goto cleanup;
	}

	if (san_b && san_b[0]) {
		memset(&gn, 0, sizeof(gn));
		gn.type = HITLS_X509_GN_DNS;
		gn.value.data = (uint8_t *)(uintptr_t)san_a;
		gn.value.dataLen = (uint32_t)strlen(san_a);
		if (BSL_LIST_AddElement(san_names, &gn, BSL_LIST_POS_END) !=
		    BSL_SUCCESS) {
			goto cleanup;
		}
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

	if (HITLS_CFG_LoadCertBuffer(ctx, crt_der.data, crt_der.dataLen,
				     TLS_PARSE_FORMAT_ASN1) != HITLS_SUCCESS ||
	    HITLS_CFG_LoadKeyBuffer(ctx, key_der.data, key_der.dataLen,
				    TLS_PARSE_FORMAT_ASN1) != HITLS_SUCCESS ||
	    HITLS_CFG_CheckPrivateKey(ctx) != HITLS_SUCCESS) {
		lwsl_err("%s: loading generated cert/key into vhost failed\n",
			 __func__);
		goto cleanup;
	}

	ret = 0;
	vhost->tls.ss->x509 = xcrt;
	vhost->tls.ss->pkey = pkey;
	xcrt = NULL;
	pkey = NULL;

cleanup:
	if (crt_der.data) {
		BSL_SAL_Free(crt_der.data);
	}
	if (key_der.data) {
		BSL_SAL_Free(key_der.data);
	}
	if (san_names) {
		BSL_LIST_FREE(san_names, NULL);
	}
	if (dn_subj) {
		HITLS_X509_DnListFree(dn_subj);
	}
	if (dn_issuer) {
		HITLS_X509_DnListFree(dn_issuer);
	}
	if (xcrt) {
		HITLS_X509_CertFree(xcrt);
	}
	if (pkey) {
		CRYPT_EAL_PkeyFreeCtx(pkey);
	}
	if (ret && ss_new) {
		lws_openhitls_tls_ss_free(vhost);
	}

	return ret;
}

void
lws_tls_acme_sni_cert_destroy(struct lws_vhost *vhost)
{
	if (!vhost || !vhost->tls.ss) {
		return;
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
	int n, ret = -1;

	(void)context;

	if (!elements || !csr || !csr_len || !privkey_pem || !privkey_len) {
		return -1;
	}

	*privkey_pem = NULL;
	*privkey_len = 0;

	pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
	if (!pkey) {
		goto cleanup;
	}

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
	if (!xcsr) {
		goto cleanup;
	}

	if (HITLS_X509_CsrCtrl(xcsr, HITLS_X509_SET_PUBKEY, pkey, 0) !=
	    HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_X509_SET_PUBKEY failed\n", __func__);
		goto cleanup;
	}

	dn_list = HITLS_X509_DnListNew();
	if (!dn_list) {
		goto cleanup;
	}

	for (n = 0; n < LWS_TLS_REQ_ELEMENT_COUNT; n++) {
		HITLS_X509_DN dn;
		const char *v = elements[n];

		if (n == LWS_TLS_REQ_ELEMENT_SUBJECT_ALT_NAME) {
			continue;
		}
		if (!dn_cid[n]) {
			continue;
		}
		if (!v) {
			continue;
		}
		if (!v[0]) {
			v = "none";
		}

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
		if (!san_names) {
			goto cleanup;
		}

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
		if (!ext) {
			goto cleanup;
		}

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
	if (klen && key_pem.data[klen - 1] == '\0') {
		klen--;
	}

	*privkey_pem = malloc(klen + 1);
	if (!*privkey_pem) {
		goto cleanup;
	}
	memcpy(*privkey_pem, key_pem.data, klen);
	(*privkey_pem)[klen] = '\0';
	*privkey_len = klen;
	ret = n;

cleanup:
	if (ret) {
		if (*privkey_pem) {
			free(*privkey_pem);
			*privkey_pem = NULL;
		}
		*privkey_len = 0;
	}
	if (key_pem.data) {
		BSL_SAL_Free(key_pem.data);
	}
	if (csr_der.data) {
		BSL_SAL_Free(csr_der.data);
	}
	if (ext) {
		HITLS_X509_ExtFree(ext);
	}
	if (san_names) {
		BSL_LIST_FREE(san_names, NULL);
	}
	if (dn_list) {
		HITLS_X509_DnListFree(dn_list);
	}
	if (xcsr) {
		HITLS_X509_CsrFree(xcsr);
	}
	if (pkey) {
		CRYPT_EAL_PkeyFreeCtx(pkey);
	}

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

	return -1;
#endif
}
