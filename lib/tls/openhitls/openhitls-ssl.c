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
 * OpenHiTLS core SSL/TLS operations
 */

#include "private-lib-core.h"
#include "private-lib-tls.h"
#include "private.h"

int openhitls_websocket_private_data_index,
    openhitls_SSL_CTX_private_data_index;

#ifndef SSL_CB_HANDSHAKE_START
#define SSL_CB_HANDSHAKE_START	0x10
#endif
#ifndef SSL_CB_HANDSHAKE_DONE
#define SSL_CB_HANDSHAKE_DONE	0x20
#endif
#ifndef SSL_CB_ALERT
#define SSL_CB_ALERT		0x4000
#endif

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
static _Thread_local lws_tls_conn *lws_openhitls_verify_ssl_tls;
#else
static lws_tls_conn *lws_openhitls_verify_ssl_tls;
#endif

/*
 * BSL_UIO helper functions
 */

uint32_t
lws_openhitls_pending_bytes(struct lws *wsi)
{
	if (!wsi || !wsi->tls.ssl)
		return 0;

	return HITLS_GetReadPendingBytes(wsi->tls.ssl);
}

void
lws_openhitls_verify_bind(lws_tls_conn *ssl)
{
	lws_openhitls_verify_ssl_tls = ssl;
}

void
lws_openhitls_verify_unbind(void)
{
	lws_openhitls_verify_ssl_tls = NULL;
}

lws_tls_conn *
lws_openhitls_verify_get_ssl(void)
{
	return lws_openhitls_verify_ssl_tls;
}

int
lws_openhitls_describe_cipher(struct lws *wsi)
{
#if !defined(LWS_WITH_NO_LOGS)
	/* OpenHiTLS does not have equivalent cipher description API */
	lwsl_info("%s: cipher info not available\n", __func__);
#endif
	return 0;
}

int
lws_ssl_get_error(struct lws *wsi, int n)
{
	int m = lws_openhitls_error_to_lws(n);

	if (m == LWS_SSL_CAPABLE_ERROR) {
		lwsl_debug("%s: %p 0x%x -> %d (errno %d)\n", __func__,
			   wsi ? (void *)wsi->tls.ssl : NULL, n, m, LWS_ERRNO);
		lws_tls_err_describe_clear();
	}

	return m;
}

#if defined(LWS_WITH_SERVER)
static int32_t
lws_context_init_ssl_pem_passwd_cb(char *buf, int32_t bufLen, int32_t flag,
				   void *userdata)
{
	const struct lws_context_creation_info *info =
			(const struct lws_context_creation_info *)userdata;
	const char *p;

	(void)flag;

	if (!buf || bufLen < 2 || !info)
		return 0;

	p = info->ssl_private_key_password;
	if (!p)
		p = "";

	lws_strncpy(buf, p, (size_t)bufLen);

	return (int32_t)strlen(buf);
}
#endif

#if defined(LWS_WITH_CLIENT)
static int32_t
lws_context_init_ssl_pem_passwd_client_cb(char *buf, int32_t bufLen, int32_t flag,
					  void *userdata)
{
	const struct lws_context_creation_info *info =
			(const struct lws_context_creation_info *)userdata;
	const char *p;

	(void)flag;

	if (!buf || bufLen < 2 || !info)
		return 0;

	p = info->ssl_private_key_password;
	if (info->client_ssl_private_key_password)
		p = info->client_ssl_private_key_password;
	if (!p)
		p = "";

	lws_strncpy(buf, p, (size_t)bufLen);

	return (int32_t)strlen(buf);
}
#endif

void
lws_ssl_bind_passphrase(lws_tls_ctx *ssl_ctx, int is_client,
			const struct lws_context_creation_info *info)
{
	HITLS_Config *config;
	int ret;

	if (!ssl_ctx || !info)
		return;

	config = is_client ? ssl_ctx->client_config : ssl_ctx->config;
	if (!config)
		return;

	if (
#if defined(LWS_WITH_SERVER)
		!info->ssl_private_key_password
#endif
#if defined(LWS_WITH_SERVER) && defined(LWS_WITH_CLIENT)
		&&
#endif
#if defined(LWS_WITH_CLIENT)
		!info->client_ssl_private_key_password
#endif
	    )
		return;

	ret = HITLS_CFG_SetDefaultPasswordCbUserdata(config, (void *)info);
	if (ret != HITLS_SUCCESS) {
		lwsl_warn("%s: HITLS_CFG_SetDefaultPasswordCbUserdata failed: 0x%x\n",
			  __func__, ret);
		return;
	}

	ret = HITLS_CFG_SetDefaultPasswordCb(config, is_client ?
					     lws_context_init_ssl_pem_passwd_client_cb :
					     lws_context_init_ssl_pem_passwd_cb);
	if (ret != HITLS_SUCCESS)
		lwsl_warn("%s: HITLS_CFG_SetDefaultPasswordCb failed: 0x%x\n",
			  __func__, ret);
}

#if defined(LWS_WITH_CLIENT)
static void
lws_ssl_destroy_client_ctx(struct lws_vhost *vhost)
{
	if (vhost->tls.user_supplied_ssl_ctx || !vhost->tls.ssl_client_ctx)
		return;

	if (vhost->tls.tcr && --vhost->tls.tcr->refcount)
		return;

	lws_tls_ctx *ctx = (lws_tls_ctx *)vhost->tls.ssl_client_ctx;

	if (ctx->client_config) {
		HITLS_CFG_FreeConfig(ctx->client_config);
		ctx->client_config = NULL;
	}

	lws_free(ctx);
	vhost->tls.ssl_client_ctx = NULL;

	vhost->context->tls.count_client_contexts--;

	if (vhost->tls.tcr) {
		lws_dll2_remove(&vhost->tls.tcr->cc_list);
		lws_free(vhost->tls.tcr);
		vhost->tls.tcr = NULL;
	}
}
#endif

void
lws_ssl_destroy(struct lws_vhost *vhost)
{
	if (!vhost || !vhost->context)
		return;

	if (!lws_check_opt(vhost->context->options,
			   LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT))
		return;

	lws_ssl_SSL_CTX_destroy(vhost);
}

int
lws_ssl_capable_read(struct lws *wsi, unsigned char *buf, size_t len)
{
	struct lws_context *context = wsi->a.context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	uint32_t readlen = 0;
	int ret, m;

	if (!wsi->tls.ssl)
		return lws_ssl_capable_read_no_ssl(wsi, buf, len);

	ret = HITLS_Read(wsi->tls.ssl, buf, (uint32_t)len, &readlen);

	if (ret == HITLS_SUCCESS) {
#if defined(LWS_WITH_SYS_METRICS)
		if (wsi->a.vhost)
			lws_metric_event(wsi->a.vhost->mt_traffic_rx,
					 METRES_GO, (u_mt_t)readlen);
#endif
		/*
		 * If the user's buffer limited the read, schedule another
		 * service pass when OpenHiTLS still has decrypted plaintext.
		 */
		if (readlen != len || !wsi->tls.ssl)
			goto bail;

		if (lws_openhitls_pending_bytes(wsi)) {
			if (lws_dll2_is_detached(&wsi->tls.dll_pending_tls))
				lws_dll2_add_head(&wsi->tls.dll_pending_tls,
						  &pt->tls.dll_pending_tls_owner);
		} else
			__lws_ssl_remove_wsi_from_buffered_list(wsi);

		return (int)readlen;
	}

	/* Handle non-blocking and error cases */
	m = lws_ssl_get_error(wsi, ret);

	switch (m) {
	case LWS_SSL_CAPABLE_MORE_SERVICE_READ:
		lwsl_debug("%s: WANT_READ\n", __func__);
		return LWS_SSL_CAPABLE_MORE_SERVICE;

	case LWS_SSL_CAPABLE_MORE_SERVICE_WRITE:
		lwsl_info("%s: WANT_WRITE during read\n", __func__);
		wsi->tls_read_wanted_write = 1;
		lws_callback_on_writable(wsi);
		return LWS_SSL_CAPABLE_MORE_SERVICE;

	case LWS_SSL_CAPABLE_DONE:
		/* Connection closed cleanly */
		lwsl_debug("%s: connection closed\n", __func__);
		goto do_err;

	default:
		/* Error case */
		lwsl_debug("%s: read error: 0x%x (mapped %d)\n", __func__,
			   ret, m);
		goto do_err;
	}

do_err:
	wsi->socket_is_permanently_unusable = 1;
#if defined(LWS_WITH_SYS_METRICS)
	if (wsi->a.vhost)
		lws_metric_event(wsi->a.vhost->mt_traffic_rx, METRES_NOGO, 0);
#endif
	__lws_ssl_remove_wsi_from_buffered_list(wsi);
	return LWS_SSL_CAPABLE_ERROR;

bail:
	lws_ssl_remove_wsi_from_buffered_list(wsi);

	return (int)readlen;
}

int
lws_ssl_pending(struct lws *wsi)
{
	if (!wsi->tls.ssl)
		return 0;

	return (int)lws_openhitls_pending_bytes(wsi);
}

int
lws_ssl_capable_write(struct lws *wsi, unsigned char *buf, size_t len)
{
	uint32_t writelen = 0;
	int ret, m;

	if (!wsi->tls.ssl)
		return lws_ssl_capable_write_no_ssl(wsi, buf, len);

	ret = HITLS_Write(wsi->tls.ssl, buf, (uint32_t)len, &writelen);

	if (ret == HITLS_SUCCESS) {
#if defined(LWS_WITH_SYS_METRICS)
		if (wsi->a.vhost)
			lws_metric_event(wsi->a.vhost->mt_traffic_tx,
					 METRES_GO, (u_mt_t)writelen);
#endif
		return (int)writelen;
	}

	/* Handle non-blocking and error cases */
	m = lws_ssl_get_error(wsi, ret);

	switch (m) {
	case LWS_SSL_CAPABLE_MORE_SERVICE_READ:
		lwsl_notice("%s: want read during write\n", __func__);
		return LWS_SSL_CAPABLE_MORE_SERVICE;

	case LWS_SSL_CAPABLE_MORE_SERVICE_WRITE:
		lws_set_blocking_send(wsi);
		lwsl_debug("%s: want write\n", __func__);
		return LWS_SSL_CAPABLE_MORE_SERVICE;

	default:
		lwsl_debug("%s: write error: 0x%x (mapped %d)\n", __func__,
			   ret, m);
		break;
	}

	wsi->socket_is_permanently_unusable = 1;
#if defined(LWS_WITH_SYS_METRICS)
	if (wsi->a.vhost)
		lws_metric_event(wsi->a.vhost->mt_traffic_tx, METRES_NOGO, 0);
#endif
	return LWS_SSL_CAPABLE_ERROR;
}

void
lws_ssl_info_callback(const lws_tls_conn *ssl, int where, int ret)
{
	struct lws *wsi = (struct lws *)HITLS_GetUserData((HITLS_Ctx *)ssl);
	struct lws_ssl_info si;

	if (!wsi || !wsi->a.vhost || !wsi->a.protocol)
		return;

	if (!(where & wsi->a.vhost->tls.ssl_info_event_mask))
		return;

	si.where = where;
	si.ret = ret;

	if (user_callback_handle_rxflow(wsi->a.protocol->callback,
					wsi, LWS_CALLBACK_SSL_INFO,
					wsi->user_space, &si, 0))
		lws_set_timeout(wsi, PENDING_TIMEOUT_KILLED_BY_SSL_INFO, -1);
}

int
lws_ssl_close(struct lws *wsi)
{
	if (!wsi->tls.ssl)
		return 0; /* not handled */

	if (wsi->a.vhost->tls.ssl_info_event_mask)
		(void)HITLS_SetInfoCb(wsi->tls.ssl, NULL);

#if defined(LWS_TLS_SYNTHESIZE_CB)
	lws_sul_cancel(&wsi->tls.sul_cb_synth);
	lws_sess_cache_synth_cb(&wsi->tls.sul_cb_synth);
#endif

	/*
	 * Graceful shutdown - send close notify
	 * HITLS_Close sends the close_notify alert
	 */
	if (!wsi->socket_is_permanently_unusable) {
		int ret = HITLS_Close(wsi->tls.ssl);
		if (ret != HITLS_SUCCESS && ret != HITLS_WANT_WRITE) {
			lwsl_debug("%s: HITLS_Close: 0x%x\n", __func__, ret);
		}
	}

	/* Free the BSL_UIO that we attached */
	{
		BSL_UIO *uio = HITLS_GetUio(wsi->tls.ssl);
		if (uio)
			BSL_UIO_Free(uio);
	}

	(void)HITLS_SetUserData(wsi->tls.ssl, NULL);
	HITLS_Free(wsi->tls.ssl);
	wsi->tls.ssl = NULL;

	__lws_ssl_remove_wsi_from_buffered_list(wsi);
	lws_tls_restrict_return(wsi);

	return 1; /* handled */
}

void
lws_ssl_SSL_CTX_destroy(struct lws_vhost *vhost)
{
	if (vhost->tls.ssl_ctx) {
		lws_tls_ctx *ctx = (lws_tls_ctx *)vhost->tls.ssl_ctx;

		if (ctx->config) {
			HITLS_CFG_FreeConfig(ctx->config);
			ctx->config = NULL;
		}

		lws_free(ctx);
		vhost->tls.ssl_ctx = NULL;
	}

#if defined(LWS_WITH_CLIENT)
	lws_ssl_destroy_client_ctx(vhost);
#endif

#if defined(LWS_WITH_ACME)
	lws_tls_acme_sni_cert_destroy(vhost);
#endif
}

void
lws_ssl_context_destroy(struct lws_context *context)
{
	(void)context;

	/* OpenHiTLS doesn't require global cleanup */
}

lws_tls_ctx *
lws_tls_ctx_from_wsi(struct lws *wsi)
{
	if (!wsi->tls.ssl)
		return NULL;

	if (wsi->a.vhost)
		return (lws_tls_ctx *)wsi->a.vhost->tls.ssl_ctx;

	return NULL;
}

enum lws_ssl_capable_status
__lws_tls_shutdown(struct lws *wsi)
{
	int ret;

	if (!wsi->tls.ssl)
		return LWS_SSL_CAPABLE_ERROR;

	ret = HITLS_Close(wsi->tls.ssl);
	lwsl_debug("%s: HITLS_Close=%d for fd %d\n", __func__, ret,
		   wsi->desc.sockfd);

	switch (ret) {
	case HITLS_SUCCESS:
		shutdown(wsi->desc.sockfd, SHUT_WR);
		return LWS_SSL_CAPABLE_DONE;

	case HITLS_WANT_READ:
		__lws_change_pollfd(wsi, 0, LWS_POLLIN);
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;

	case HITLS_WANT_WRITE:
		__lws_change_pollfd(wsi, 0, LWS_POLLOUT);
		return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;

	default:
		return LWS_SSL_CAPABLE_ERROR;
	}
}

static int
tops_fake_POLLIN_for_buffered_openhitls(struct lws_context_per_thread *pt)
{
	return lws_tls_fake_POLLIN_for_buffered(pt);
}

const struct lws_tls_ops tls_ops_openhitls = {
	/* fake_POLLIN_for_buffered */	tops_fake_POLLIN_for_buffered_openhitls,
};
