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

static int32_t
lws_openhitls_pem_passwd_server_cb(char *buf, int32_t bufLen, int32_t flag,
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

static int32_t
lws_openhitls_pem_passwd_client_cb(char *buf, int32_t bufLen, int32_t flag,
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

/*
 * BSL_UIO helper functions
 */

static void
lws_openhitls_uio_free(BSL_UIO *uio)
{
	if (uio)
		BSL_UIO_Free(uio);
}

static void
lws_openhitls_ssl_info_emit(struct lws *wsi, int where, int ret)
{
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
lws_ssl_capable_read(struct lws *wsi, unsigned char *buf, size_t len)
{
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
		 * Keep read scheduling conservative: synthetic pending
		 * generation via HITLS_Peek can over-drive callbacks.
		 */
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

int
lws_ssl_pending(struct lws *wsi)
{
	if (!wsi->tls.ssl)
		return 0;

	/* Keep conservative semantics until a non-consuming pending API exists. */
	return 0;
}

int
lws_ssl_close(struct lws *wsi)
{
	if (!wsi->tls.ssl)
		return 0; /* not handled */

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
			lws_openhitls_uio_free(uio);
	}

	(void)HITLS_SetUserData(wsi->tls.ssl, NULL);
	HITLS_Free(wsi->tls.ssl);
	wsi->tls.ssl = NULL;

	__lws_ssl_remove_wsi_from_buffered_list(wsi);
	lws_tls_restrict_return(wsi);

	return 1; /* handled */
}

enum lws_ssl_capable_status
lws_tls_server_accept(struct lws *wsi)
{
	int ret, m;

	if (!wsi->tls.ssl)
		return LWS_SSL_CAPABLE_ERROR;

	lws_openhitls_verify_bind(wsi->tls.ssl);
	lws_openhitls_ssl_info_emit(wsi, SSL_CB_HANDSHAKE_START, 1);
	ret = HITLS_Accept(wsi->tls.ssl);
	lws_openhitls_verify_unbind();

	if (ret == HITLS_SUCCESS) {
		lws_openhitls_ssl_info_emit(wsi, SSL_CB_HANDSHAKE_DONE, ret);
		return LWS_SSL_CAPABLE_DONE;
	}

	lwsl_debug("%s: HITLS_Accept returned 0x%x\n", __func__, ret);
	m = lws_ssl_get_error(wsi, ret);

	switch (m) {
	case LWS_SSL_CAPABLE_MORE_SERVICE_READ:
		if (lws_change_pollfd(wsi, LWS_POLLOUT, LWS_POLLIN)) {
			lwsl_info("%s: WANT_READ change_pollfd failed\n",
				  __func__);
			return LWS_SSL_CAPABLE_ERROR;
		}
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;

	case LWS_SSL_CAPABLE_MORE_SERVICE_WRITE:
		if (lws_change_pollfd(wsi, LWS_POLLIN, LWS_POLLOUT)) {
			lwsl_info("%s: WANT_WRITE change_pollfd failed\n",
				  __func__);
			return LWS_SSL_CAPABLE_ERROR;
		}
		return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;

	case LWS_SSL_CAPABLE_MORE_SERVICE:
		return LWS_SSL_CAPABLE_MORE_SERVICE;

	case LWS_SSL_CAPABLE_DONE:
		return LWS_SSL_CAPABLE_DONE;

	default:
		lws_openhitls_ssl_info_emit(wsi, SSL_CB_ALERT, ret);
		return LWS_SSL_CAPABLE_ERROR;
	}
}

enum lws_ssl_capable_status
lws_tls_client_connect(struct lws *wsi, char *errbuf, size_t len)
{
	int ret, m;

	if (!wsi->tls.ssl) {
		if (errbuf)
			lws_snprintf(errbuf, len, "no SSL context");
		return LWS_SSL_CAPABLE_ERROR;
	}

	lws_openhitls_ssl_info_emit(wsi, SSL_CB_HANDSHAKE_START, 1);
	lws_openhitls_verify_bind(wsi->tls.ssl);
	ret = HITLS_Connect(wsi->tls.ssl);
	lws_openhitls_verify_unbind();

	if (ret == HITLS_SUCCESS) {
		uint8_t *proto = NULL;
		uint32_t proto_len = 0;

		/* Session save path is still being completed for OpenHiTLS. */

		if (HITLS_GetSelectedAlpnProto(wsi->tls.ssl, &proto, &proto_len)
				== HITLS_SUCCESS && proto && proto_len) {
			char a[32];

			if (proto_len >= sizeof(a))
				proto_len = sizeof(a) - 1;
			memcpy(a, proto, proto_len);
			a[proto_len] = '\0';
			lws_role_call_alpn_negotiated(wsi, a);
		}
		lws_openhitls_ssl_info_emit(wsi, SSL_CB_HANDSHAKE_DONE, ret);
		return LWS_SSL_CAPABLE_DONE;
	}

	/*
	 * In handshake stage, record-layer IO busy is a transient "retry now"
	 * condition; mapping it to strict WANT_WRITE can stall progress on some
	 * platforms where POLLOUT edge is not re-delivered.
	 */
	if (ret == HITLS_REC_NORMAL_IO_BUSY)
		return LWS_SSL_CAPABLE_MORE_SERVICE;

	lwsl_debug("%s: HITLS_Connect returned 0x%x\n", __func__, ret);
	m = lws_ssl_get_error(wsi, ret);

	switch (m) {
	case LWS_SSL_CAPABLE_MORE_SERVICE_READ:
	case LWS_SSL_CAPABLE_MORE_SERVICE_WRITE:
	case LWS_SSL_CAPABLE_MORE_SERVICE: {
		enum lws_ssl_capable_status pending = (enum lws_ssl_capable_status)m;
		int soerr = 0;
		socklen_t sl = (socklen_t)sizeof(soerr);

		if (wsi->desc.sockfd >= 0 &&
		    !getsockopt(wsi->desc.sockfd, SOL_SOCKET, SO_ERROR,
				(char *)&soerr, &sl) && soerr) {
			if (errbuf)
				lws_snprintf(errbuf, len,
					     "TLS connect pending but socket error %d",
					     soerr);
			lwsl_info("%s: pending handshake with SO_ERROR=%d\n",
				  __func__, soerr);
			lws_openhitls_ssl_info_emit(wsi, SSL_CB_ALERT, ret);
			return LWS_SSL_CAPABLE_ERROR;
		}

		return pending;
	}

	default:
		if (errbuf)
			lws_snprintf(errbuf, len, "TLS handshake failed: 0x%x", ret);
		lws_openhitls_ssl_info_emit(wsi, SSL_CB_ALERT, ret);
		return LWS_SSL_CAPABLE_ERROR;
	}
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

enum lws_ssl_capable_status
lws_tls_server_abort_connection(struct lws *wsi)
{
	__lws_tls_shutdown(wsi);

	return LWS_SSL_CAPABLE_ERROR;
}

void
lws_ssl_info_callback(const lws_tls_conn *ssl, int where, int ret)
{
	(void)ssl;
	(void)where;
	(void)ret;

	/*
	 * OpenHiTLS doesn't provide SSL_set_info_callback() style registration.
	 * Events are emitted actively by lws_openhitls_ssl_info_emit() from
	 * handshake callsites instead.
	 */
}

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
					     lws_openhitls_pem_passwd_client_cb :
					     lws_openhitls_pem_passwd_server_cb);
	if (ret != HITLS_SUCCESS)
		lwsl_warn("%s: HITLS_CFG_SetDefaultPasswordCb failed: 0x%x\n",
			  __func__, ret);
}

static int
tops_fake_POLLIN_for_buffered_openhitls(struct lws_context_per_thread *pt)
{
	return lws_tls_fake_POLLIN_for_buffered(pt);
}

const struct lws_tls_ops tls_ops_openhitls = {
	/* fake_POLLIN_for_buffered */	tops_fake_POLLIN_for_buffered_openhitls,
};
