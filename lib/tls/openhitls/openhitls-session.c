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
 * OpenHiTLS TLS session management
 */

#include "private-lib-core.h"
#include "private-lib-tls.h"
#include "private.h"

typedef struct lws_tls_session_cache_openhitls {
	lws_dll2_t list;
	HITLS_Session *session;
	lws_sorted_usec_list_t sul_ttl;
	/* hostname:port string overallocated after struct */
} lws_tls_sco_t;

static int32_t
lws_openhitls_session_new_cb(HITLS_Ctx *ssl, HITLS_Session *session);

static lws_tls_sco_t *
__lws_tls_session_lookup(struct lws_vhost *vh, const char *name);

#define tlssess_loglevel		LLL_INFO
#if (_LWS_ENABLED_LOGS & tlssess_loglevel)
#define lwsl_tlssess(...)		_lws_log(tlssess_loglevel, __VA_ARGS__)
#else
#define lwsl_tlssess(...)
#endif

static void
__lws_tls_session_destroy(lws_tls_sco_t *ts)
{
	lwsl_tlssess("%s: %s (%u)\n", __func__, (const char *)&ts[1],
		     ts->list.owner->count - 1);

	lws_sul_cancel(&ts->sul_ttl);
	if (ts->session)
		HITLS_SESS_Free(ts->session);
	lws_dll2_remove(&ts->list);

	lws_free(ts);
}

static void
lws_tls_session_expiry_cb(lws_sorted_usec_list_t *sul)
{
	lws_tls_sco_t *ts = lws_container_of(sul, lws_tls_sco_t, sul_ttl);
	struct lws_vhost *vh = lws_container_of(ts->list.owner,
						struct lws_vhost,
						tls_sessions);

	lws_context_lock(vh->context, __func__);
	lws_vhost_lock(vh);
	__lws_tls_session_destroy(ts);
	lws_vhost_unlock(vh);
	lws_context_unlock(vh->context);
}

static lws_tls_sco_t *
lws_openhitls_session_add_entry(struct lws_vhost *vh, const char *tag)
{
	lws_tls_sco_t *ts;
	size_t nl = strlen(tag);
	size_t max = vh->tls_session_cache_max ? vh->tls_session_cache_max : 10;

	if (vh->tls_sessions.count >= max) {
		ts = lws_container_of(vh->tls_sessions.head, lws_tls_sco_t, list);
		if (ts) {
			lwsl_tlssess("%s: pruning oldest session\n", __func__);
			__lws_tls_session_destroy(ts);
		}
	}

	ts = lws_malloc(sizeof(*ts) + nl + 1, __func__);
	if (!ts)
		return NULL;

	memset(ts, 0, sizeof(*ts));
	memcpy(&ts[1], tag, nl + 1);
	lws_dll2_add_tail(&ts->list, &vh->tls_sessions);

	return ts;
}

static int
lws_openhitls_session_store_locked(struct lws_vhost *vh,
				   struct lws_context *context, int tsi,
				   const char *tag, HITLS_Session *session,
				   uint64_t ttl)
{
	lws_tls_sco_t *ts;

	ts = __lws_tls_session_lookup(vh, tag);
	if (!ts) {
		ts = lws_openhitls_session_add_entry(vh, tag);
		if (!ts)
			return -1;
	} else {
		lws_sul_cancel(&ts->sul_ttl);
		if (ts->session)
			HITLS_SESS_Free(ts->session);
		lws_dll2_remove(&ts->list);
		lws_dll2_add_tail(&ts->list, &vh->tls_sessions);
	}

	ts->session = session;
	if (!ttl)
		ttl = 300;

	lws_sul_schedule(context, tsi, &ts->sul_ttl, lws_tls_session_expiry_cb,
			 (lws_usec_t)ttl * LWS_US_PER_SEC);

	return 0;
}

void
lws_tls_session_vh_destroy(struct lws_vhost *vh)
{
	if (!vh)
		return;

	lws_context_lock(vh->context, __func__);
	lws_vhost_lock(vh);

	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
				   lws_dll2_get_head(&vh->tls_sessions)) {
		lws_tls_sco_t *ts = lws_container_of(p, lws_tls_sco_t, list);
		__lws_tls_session_destroy(ts);
	} lws_end_foreach_dll_safe(p, p1);

	lws_vhost_unlock(vh);
	lws_context_unlock(vh->context);
}

static lws_tls_sco_t *
__lws_tls_session_lookup(struct lws_vhost *vh, const char *name)
{
	lws_start_foreach_dll(struct lws_dll2 *, p,
			      lws_dll2_get_head(&vh->tls_sessions)) {
		lws_tls_sco_t *ts = lws_container_of(p, lws_tls_sco_t, list);
		const char *ts_name = (const char *)&ts[1];

		if (!strcmp(name, ts_name))
			return ts;
	} lws_end_foreach_dll(p);

	return NULL;
}

int
lws_tls_session_is_reused(struct lws *wsi)
{
	HITLS_Ctx *ssl;
	bool isReused = false;
	int ret;

	if (!wsi || !wsi->tls.ssl)
		return 0;

	ssl = (HITLS_Ctx *)wsi->tls.ssl;

	ret = HITLS_IsSessionReused(ssl, &isReused);
	if (ret != HITLS_SUCCESS) {
		lwsl_tlssess("%s: HITLS_IsSessionReused failed: 0x%x\n",
			     __func__, ret);
		return 0;
	}

	lwsl_tlssess("%s: session reused = %d\n", __func__, isReused);

	return isReused ? 1 : 0;
}

int
lws_tls_session_dump_save(struct lws_vhost *vh, const char *host, uint16_t port,
			  int (*cb)(struct lws_context *,
				    struct lws_tls_session_dump *),
			  void *user)
{
	(void)vh;
	(void)host;
	(void)port;
	(void)cb;
	(void)user;

	return 1;
}

int
lws_tls_session_dump_load(struct lws_vhost *vh, const char *host, uint16_t port,
			  int (*cb)(struct lws_context *,
				    struct lws_tls_session_dump *),
			  void *user)
{
	(void)vh;
	(void)host;
	(void)port;
	(void)cb;
	(void)user;

	return 1;
}

static int32_t
lws_openhitls_session_new_cb(HITLS_Ctx *ssl, HITLS_Session *session)
{
	struct lws *wsi = (struct lws *)HITLS_GetUserData(ssl);
	struct lws_vhost *vh;
	HITLS_Session *dup;
	char tag[LWS_SESSION_TAG_LEN];
	uint64_t ttl;
	int r;

	if (!wsi || !wsi->a.vhost || !session)
		return 0;

	vh = wsi->a.vhost;
	if (vh->options & LWS_SERVER_OPTION_DISABLE_TLS_SESSION_CACHE)
		return 0;

	if (!wsi->cli_hostname_copy || !wsi->c_port)
		return 0;

	lws_snprintf(tag, sizeof(tag), "%s:%u", wsi->cli_hostname_copy,
		     (unsigned int)wsi->c_port);

	dup = HITLS_SESS_Dup(session);
	if (!dup) {
		lwsl_tlssess("%s: HITLS_SESS_Dup failed\n", __func__);
		return 0;
	}

	ttl = HITLS_SESS_GetTimeout(session);

	lws_context_lock(vh->context, __func__);
	lws_vhost_lock(vh);
	r = lws_openhitls_session_store_locked(vh, wsi->a.context, wsi->tsi,
					       tag, dup, ttl);
	lws_vhost_unlock(vh);
	lws_context_unlock(vh->context);

	if (r) {
		HITLS_SESS_Free(dup);
		return 0;
	}

	lwsl_tlssess("%s: session cached for %s, ttl=%u\n", __func__, tag,
		     (unsigned int)(ttl ? ttl : 300));

	return 1;
}

void
lws_tls_session_cache(struct lws_vhost *vh, uint32_t ttl)
{
	lws_tls_ctx *ctx;
	uint64_t timeout = ttl ? (uint64_t)ttl : 300;

	if (!vh || (vh->options & LWS_SERVER_OPTION_DISABLE_TLS_SESSION_CACHE))
		return;

	if (!vh->tls.ssl_client_ctx)
		return;

	ctx = (lws_tls_ctx *)vh->tls.ssl_client_ctx;
	if (!ctx->client_config)
		return;

	if (HITLS_CFG_SetSessionCacheMode(ctx->client_config,
					  HITLS_SESS_CACHE_CLIENT)
			!= HITLS_SUCCESS) {
		lwsl_warn("%s: HITLS_CFG_SetSessionCacheMode failed\n", __func__);
		return;
	}

	if (HITLS_CFG_SetSessionTimeout(ctx->client_config, timeout)
			!= HITLS_SUCCESS) {
		lwsl_warn("%s: HITLS_CFG_SetSessionTimeout failed\n", __func__);
		return;
	}

	if (HITLS_CFG_SetNewSessionCb(ctx->client_config,
				      lws_openhitls_session_new_cb)
			!= HITLS_SUCCESS) {
		lwsl_warn("%s: HITLS_CFG_SetNewSessionCb failed\n", __func__);
		return;
	}

	lwsl_tlssess("%s: session cache enabled, timeout=%us\n", __func__,
		     (unsigned int)timeout);
}

void
lws_tls_reuse_session(struct lws *wsi)
{
	if (!wsi || !wsi->tls.ssl || !wsi->cli_hostname_copy || !wsi->c_port)
		return;

	(void)lws_openhitls_session_set(wsi, wsi->cli_hostname_copy,
					(uint16_t)wsi->c_port);
}

int
lws_openhitls_session_set(struct lws *wsi, const char *host, uint16_t port)
{
	struct lws_vhost *vh;
	lws_tls_sco_t *ts;
	char tag[LWS_SESSION_TAG_LEN];
	int ret;

	if (!wsi || !wsi->tls.ssl || !host)
		return -1;

	vh = wsi->a.vhost;
	if (!vh)
		return -1;

	if (vh->options & LWS_SERVER_OPTION_DISABLE_TLS_SESSION_CACHE)
		return 0;

	lws_snprintf(tag, sizeof(tag), "%s:%u", host, (unsigned int)port);

	lws_context_lock(vh->context, __func__);
	lws_vhost_lock(vh);
	ts = __lws_tls_session_lookup(vh, tag);
	if (!ts || !ts->session) {
		lwsl_tlssess("%s: no session to resume for %s\n", __func__, tag);
		lws_vhost_unlock(vh);
		lws_context_unlock(vh->context);
		return -1;
	}

	ret = HITLS_SetSession((HITLS_Ctx *)wsi->tls.ssl, ts->session);
	if (ret != HITLS_SUCCESS) {
		lwsl_tlssess("%s: HITLS_SetSession failed: 0x%x\n", __func__, ret);
		lws_vhost_unlock(vh);
		lws_context_unlock(vh->context);
		return -1;
	}

	lwsl_tlssess("%s: session set for resumption: %s\n", __func__, tag);
	lws_dll2_remove(&ts->list);
	lws_dll2_add_tail(&ts->list, &vh->tls_sessions);
	lws_vhost_unlock(vh);
	lws_context_unlock(vh->context);

	return 0;
}
