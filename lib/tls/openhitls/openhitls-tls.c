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
 * OpenHiTLS TLS context, global initialization, and session management
 */

#include "private-lib-core.h"
#include "private-lib-tls.h"
#include "private.h"

/* Session cache structure for OpenHiTLS */
typedef struct lws_tls_session_cache_openhitls {
	lws_dll2_t           list;
	HITLS_Session       *session;
	lws_sorted_usec_list_t sul_ttl;
	/* hostname:port string overallocated after struct */
} lws_tls_sco_t;

static int32_t
lws_openhitls_session_new_cb(HITLS_Ctx *ssl, HITLS_Session *session);

static lws_tls_sco_t *
__lws_tls_session_lookup(struct lws_vhost *vh, const char *name);

static HITLS_Session *
lws_openhitls_session_get_cb(HITLS_Ctx *ctx, const uint8_t *data, int32_t len,
			     int32_t *copy);

static void
lws_openhitls_session_remove_cb(HITLS_Config *config, HITLS_Session *sess);


#define tlssess_loglevel		LLL_INFO
#if (_LWS_ENABLED_LOGS & tlssess_loglevel)
#define lwsl_tlssess(...)		_lws_log(tlssess_loglevel, __VA_ARGS__)
#else
#define lwsl_tlssess(...)
#endif

static int openhitls_contexts_using_global_init;

void
lws_tls_err_describe_clear(void)
{
	const char *file = NULL;
	uint32_t line = 0;
	int32_t err;
	unsigned int n = 0;

	while ((err = BSL_ERR_GetErrorFileLine(&file, &line)) != BSL_SUCCESS) {
		lwsl_info("   openhitls error: 0x%x (%s:%u)\n",
			  (unsigned int)err, file ? file : "?",
			  (unsigned int)line);
		if (++n == 32) {
			lwsl_info("   openhitls error: too many entries, clearing remainder\n");
			BSL_ERR_ClearError();
			break;
		}
	}

	if (n)
		lwsl_info("\n");
}

int
lws_context_init_ssl_library(struct lws_context *context,
			     const struct lws_context_creation_info *info)
{
	int ret;

	lwsl_cx_info(context, " Compiled with OpenHiTLS support");

	if (!lws_check_opt(info->options, LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT)) {
		lwsl_cx_info(context, " SSL disabled: no "
			     "LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT");
		return 0;
	}

	if (openhitls_contexts_using_global_init++) {
		lwsl_cx_info(context, " OpenHiTLS global init refcount=%d",
			     openhitls_contexts_using_global_init);
		return 0;
	}

	/* Initialize BSL error handling */
	ret = BSL_ERR_Init();
	if (ret != BSL_SUCCESS) {
		lwsl_cx_err(context, "BSL_ERR_Init failed: 0x%x", ret);
		openhitls_contexts_using_global_init--;
		return -1;
	}

	/* Initialize crypto library with all features */
	ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
	if (ret != CRYPT_SUCCESS) {
		lwsl_cx_err(context, "CRYPT_EAL_Init failed: 0x%x", ret);
		BSL_ERR_DeInit();
		openhitls_contexts_using_global_init--;
		return -1;
	}

	lwsl_cx_info(context, " OpenHiTLS global init done");
	return 0;
}

void
lws_context_deinit_ssl_library(struct lws_context *context)
{
	if (!lws_check_opt(context->options,
			   LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT))
		return;

	if (!openhitls_contexts_using_global_init) {
		lwsl_cx_warn(context, " OpenHiTLS deinit with zero refcount");
		return;
	}

	if (--openhitls_contexts_using_global_init) {
		lwsl_cx_info(context, " OpenHiTLS global deinit deferred, refcount=%d",
			     openhitls_contexts_using_global_init);
		return;
	}

	/* Cleanup crypto library */
	CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);

	/* Cleanup BSL error handling */
	BSL_ERR_DeInit();

	lwsl_cx_info(context, " OpenHiTLS global deinit done");
}

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

void
lws_ssl_SSL_CTX_destroy(struct lws_vhost *vhost)
{
	lws_tls_ctx *ctx;

	/* Destroy server SSL context */
	if (vhost->tls.ssl_ctx) {
		ctx = (lws_tls_ctx *)vhost->tls.ssl_ctx;

		if (ctx->config) {
			HITLS_CFG_FreeConfig(ctx->config);
			ctx->config = NULL;
		}

		lws_free(ctx);
		vhost->tls.ssl_ctx = NULL;
	}

#if defined(LWS_WITH_CLIENT)
	/* Destroy client SSL context (may be separate allocation) */
	if (vhost->tls.ssl_client_ctx) {
		if (!vhost->tls.user_supplied_ssl_ctx) {
			ctx = (lws_tls_ctx *)vhost->tls.ssl_client_ctx;

			if (ctx->client_config) {
				HITLS_CFG_FreeConfig(ctx->client_config);
				ctx->client_config = NULL;
			}

			lws_free(ctx);
		}
		vhost->tls.ssl_client_ctx = NULL;
	}
#endif

#if defined(LWS_WITH_ACME)
	lws_tls_acme_sni_cert_destroy(vhost);
#endif
}

lws_tls_ctx *
lws_tls_ctx_from_wsi(struct lws *wsi)
{
	if (!wsi->tls.ssl)
		return NULL;

	/* Return the vhost's context, not the connection */
	if (wsi->a.vhost)
		return (lws_tls_ctx *)wsi->a.vhost->tls.ssl_ctx;

	return NULL;
}

void
lws_ssl_context_destroy(struct lws_context *context)
{
	(void)context;

	/* OpenHiTLS doesn't require global cleanup */
}

/*
 * Session cache destruction - clean up all cached sessions for a vhost
 */
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

static int
lws_openhitls_session_match_id(HITLS_Session *session, const uint8_t *sid,
			       int32_t sid_len)
{
	uint8_t id[HITLS_SESSION_ID_MAX_SIZE];
	uint32_t id_len = (uint32_t)sizeof(id);

	if (!session || !sid || sid_len <= 0)
		return 0;

	if (HITLS_SESS_GetSessionId(session, id, &id_len) != HITLS_SUCCESS)
		return 0;

	if (id_len != (uint32_t)sid_len)
		return 0;

	return !memcmp(id, sid, id_len);
}

static struct lws_vhost *
lws_openhitls_session_vh_from_ctx(HITLS_Ctx *ctx)
{
	struct lws *wsi = (struct lws *)HITLS_GetUserData(ctx);
	const HITLS_Config *config;
	struct lws_vhost *vh;

	if (wsi && wsi->a.vhost)
		return wsi->a.vhost;

	config = HITLS_GetConfig(ctx);
	if (!config)
		return NULL;

	vh = (struct lws_vhost *)HITLS_CFG_GetConfigUserData(config);

	return vh;
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

/*
 * Look up a session in the cache by hostname:port
 */
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
	struct lws_tls_session_dump d;
	lws_tls_sco_t *ts;
	uint8_t sid[HITLS_SESSION_ID_MAX_SIZE];
	uint8_t sid_ctx[32];
	uint8_t *mk = NULL;
	uint32_t sid_len = (uint32_t)sizeof(sid);
	uint32_t sid_ctx_len = (uint32_t)sizeof(sid_ctx);
	uint32_t mk_len;
	uint16_t proto = 0, cipher = 0;
	uint64_t timeout = 0;
	size_t blen;
	bool extms = false;
	uint8_t *p, *b;
	int ret = 1;

	if (!vh || !host || !cb)
		return 1;
	if (vh->options & LWS_SERVER_OPTION_DISABLE_TLS_SESSION_CACHE)
		return 1;

	lws_tls_session_tag_discrete(vh->name, host, port, d.tag, sizeof(d.tag));

	lws_context_lock(vh->context, __func__);
	lws_vhost_lock(vh);

	ts = __lws_tls_session_lookup(vh, d.tag);
	if (!ts || !ts->session)
		goto bail;

	mk_len = HITLS_SESS_GetMasterKeyLen(ts->session);
	if (!mk_len || mk_len > 512)
		goto bail;
	mk = lws_malloc(mk_len, __func__);
	if (!mk)
		goto bail;

	if (HITLS_SESS_GetSessionId(ts->session, sid, &sid_len) != HITLS_SUCCESS ||
	    !sid_len ||
	    HITLS_SESS_GetMasterKey(ts->session, mk, &mk_len) != HITLS_SUCCESS ||
	    !mk_len ||
	    HITLS_SESS_GetProtocolVersion(ts->session, &proto) != HITLS_SUCCESS ||
	    HITLS_SESS_GetCipherSuite(ts->session, &cipher) != HITLS_SUCCESS ||
	    HITLS_SESS_GetHaveExtMasterSecret(ts->session, &extms) != HITLS_SUCCESS) {
		lwsl_tlssess("%s: unable to extract session components for dump\n",
			     __func__);
		goto bail;
	}

	timeout = HITLS_SESS_GetTimeout(ts->session);
	if (HITLS_SESS_GetSessionIdCtx(ts->session, sid_ctx, &sid_ctx_len) !=
	    HITLS_SUCCESS)
		sid_ctx_len = 0;
	if (sid_ctx_len > 32)
		sid_ctx_len = 32;

	blen = 4 + 1 + 1 + 2 + 2 + 8 + 1 + 1 + sid_len + mk_len + sid_ctx_len;
	b = lws_malloc(blen, __func__);
	if (!b)
		goto bail;

	p = b;
	memcpy(p, "OHSS", 4); p += 4;
	*p++ = 1; /* format version */
	*p++ = (uint8_t)sid_len;
	*p++ = (uint8_t)(mk_len >> 8);
	*p++ = (uint8_t)(mk_len & 0xff);
	*p++ = (uint8_t)(sid_ctx_len & 0xff);
	*p++ = (uint8_t)(extms ? 1 : 0);
	*p++ = (uint8_t)(proto >> 8);
	*p++ = (uint8_t)(proto & 0xff);
	*p++ = (uint8_t)(cipher >> 8);
	*p++ = (uint8_t)(cipher & 0xff);
	*p++ = (uint8_t)(timeout >> 56);
	*p++ = (uint8_t)(timeout >> 48);
	*p++ = (uint8_t)(timeout >> 40);
	*p++ = (uint8_t)(timeout >> 32);
	*p++ = (uint8_t)(timeout >> 24);
	*p++ = (uint8_t)(timeout >> 16);
	*p++ = (uint8_t)(timeout >> 8);
	*p++ = (uint8_t)(timeout);
	memcpy(p, sid, sid_len); p += sid_len;
	memcpy(p, mk, mk_len); p += mk_len;
	if (sid_ctx_len)
		memcpy(p, sid_ctx, sid_ctx_len);

	d.blob = b;
	d.blob_len = blen;
	d.opaque = user;

	if (!cb(vh->context, &d))
		ret = 0;
	else
		lwsl_notice("%s: save callback failed\n", __func__);

	lws_free(b);

bail:
	if (mk)
		lws_free(mk);
	lws_vhost_unlock(vh);
	lws_context_unlock(vh->context);

	return ret;
}

int
lws_tls_session_dump_load(struct lws_vhost *vh, const char *host, uint16_t port,
			  int (*cb)(struct lws_context *,
				    struct lws_tls_session_dump *),
			  void *user)
{
	struct lws_tls_session_dump d;
	lws_tls_sco_t *ts;
	HITLS_Session *sess = NULL;
	uint8_t sid[HITLS_SESSION_ID_MAX_SIZE], sid_ctx[32], *mk = NULL;
	const uint8_t *p;
	size_t rem;
	uint16_t proto, cipher, mk_len;
	uint64_t timeout;
	uint8_t sid_len, sid_ctx_len, extms;
	void *v = NULL;
	int ret = 1;

	if (!vh || !host || !cb)
		return 1;
	if (vh->options & LWS_SERVER_OPTION_DISABLE_TLS_SESSION_CACHE)
		return 1;

	d.opaque = user;
	lws_tls_session_tag_discrete(vh->name, host, port, d.tag, sizeof(d.tag));

	lws_context_lock(vh->context, __func__);
	lws_vhost_lock(vh);
	ts = __lws_tls_session_lookup(vh, d.tag);
	if (ts) {
		lwsl_notice("%s: session already exists for %s\n", __func__,
			    d.tag);
		goto bail1;
	}

	if (cb(vh->context, &d)) {
		lwsl_warn("%s: load callback failed\n", __func__);
		goto bail1;
	}

	v = d.blob; /* callback uses malloc() */
	p = (const uint8_t *)d.blob;
	rem = d.blob_len;
	if (!p || rem < 4 + 1 + 1 + 2 + 1 + 1 + 2 + 2 + 8)
		goto bail;

	if (memcmp(p, "OHSS", 4) || p[4] != 1) {
		lwsl_warn("%s: unsupported session blob format\n", __func__);
		goto bail;
	}
	p += 5; rem -= 5;
	sid_len = *p++;
	mk_len = (uint16_t)((uint16_t)p[0] << 8 | p[1]); p += 2;
	sid_ctx_len = *p++;
	extms = *p++;
	proto = (uint16_t)((uint16_t)p[0] << 8 | p[1]); p += 2;
	cipher = (uint16_t)((uint16_t)p[0] << 8 | p[1]); p += 2;
	timeout = ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
		  ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
		  ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
		  ((uint64_t)p[6] << 8) | (uint64_t)p[7];
	p += 8;
	rem = d.blob_len - (size_t)(p - (const uint8_t *)d.blob);

	if (!sid_len || sid_len > sizeof(sid) ||
	    !mk_len || mk_len > 512 ||
	    sid_ctx_len > sizeof(sid_ctx) ||
	    rem < (size_t)sid_len + (size_t)mk_len + (size_t)sid_ctx_len) {
		lwsl_warn("%s: malformed session blob\n", __func__);
		goto bail;
	}

	mk = lws_malloc(mk_len, __func__);
	if (!mk)
		goto bail;

	memcpy(sid, p, sid_len); p += sid_len;
	memcpy(mk, p, mk_len); p += mk_len;
	if (sid_ctx_len)
		memcpy(sid_ctx, p, sid_ctx_len);

	sess = HITLS_SESS_New();
	if (!sess)
		goto bail;

	if (HITLS_SESS_SetSessionId(sess, sid, sid_len) != HITLS_SUCCESS ||
	    HITLS_SESS_SetMasterKey(sess, mk, mk_len) != HITLS_SUCCESS ||
	    HITLS_SESS_SetProtocolVersion(sess, proto) != HITLS_SUCCESS ||
	    HITLS_SESS_SetCipherSuite(sess, cipher) != HITLS_SUCCESS ||
	    HITLS_SESS_SetHaveExtMasterSecret(sess, extms ? 1 : 0) != HITLS_SUCCESS ||
	    HITLS_SESS_SetTimeout(sess, timeout ? timeout : 300) != HITLS_SUCCESS ||
	    (sid_ctx_len && HITLS_SESS_SetSessionIdCtx(sess, sid_ctx, sid_ctx_len)
				  != HITLS_SUCCESS)) {
		lwsl_warn("%s: unable to reconstruct session from blob\n", __func__);
		goto bail;
	}

	if (lws_openhitls_session_store_locked(vh, vh->context, 0, d.tag, sess,
					       timeout ? timeout : 300)) {
		goto bail;
	}

	sess = NULL;
	ret = 0;

bail:
	free(v);
	if (mk)
		lws_free(mk);
	if (sess)
		HITLS_SESS_Free(sess);
bail1:
	lws_vhost_unlock(vh);
	lws_context_unlock(vh->context);

	return ret;
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

static HITLS_Session *
lws_openhitls_session_get_cb(HITLS_Ctx *ctx, const uint8_t *data, int32_t len,
			     int32_t *copy)
{
	struct lws_vhost *vh;
	HITLS_Session *dup = NULL;

	if (!ctx || !data || len <= 0 || !copy)
		return NULL;
	*copy = 0;

	vh = lws_openhitls_session_vh_from_ctx(ctx);
	if (!vh || (vh->options & LWS_SERVER_OPTION_DISABLE_TLS_SESSION_CACHE))
		return NULL;

	lws_context_lock(vh->context, __func__);
	lws_vhost_lock(vh);

	lws_start_foreach_dll(struct lws_dll2 *, p,
			      lws_dll2_get_head(&vh->tls_sessions)) {
		lws_tls_sco_t *ts = lws_container_of(p, lws_tls_sco_t, list);

		if (!lws_openhitls_session_match_id(ts->session, data, len))
			continue;

		dup = HITLS_SESS_Dup(ts->session);
		if (dup) {
			lws_dll2_remove(&ts->list);
			lws_dll2_add_tail(&ts->list, &vh->tls_sessions);
			*copy = 1;
			lwsl_tlssess("%s: hit sid-len=%d\n", __func__, len);
		}
		break;
	} lws_end_foreach_dll(p);

	lws_vhost_unlock(vh);
	lws_context_unlock(vh->context);

	if (!dup)
		lwsl_tlssess("%s: miss sid-len=%d\n", __func__, len);

	return dup;
}

static void
lws_openhitls_session_remove_cb(HITLS_Config *config, HITLS_Session *sess)
{
	struct lws_vhost *vh;
	uint8_t sid[HITLS_SESSION_ID_MAX_SIZE];
	uint32_t sid_len = (uint32_t)sizeof(sid);

	if (!config || !sess)
		return;

	if (HITLS_SESS_GetSessionId(sess, sid, &sid_len) != HITLS_SUCCESS ||
	    !sid_len)
		return;

	vh = (struct lws_vhost *)HITLS_CFG_GetConfigUserData(config);
	if (!vh)
		return;

	lws_context_lock(vh->context, __func__);
	lws_vhost_lock(vh);

	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
				   lws_dll2_get_head(&vh->tls_sessions)) {
		lws_tls_sco_t *ts = lws_container_of(p, lws_tls_sco_t, list);

		if (!lws_openhitls_session_match_id(ts->session, sid,
						    (int32_t)sid_len))
			continue;

		lwsl_tlssess("%s: remove sid-len=%u\n", __func__,
			     (unsigned int)sid_len);
		__lws_tls_session_destroy(ts);
		break;
	} lws_end_foreach_dll_safe(p, p1);

	lws_vhost_unlock(vh);
	lws_context_unlock(vh->context);
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

	if (HITLS_CFG_SetSessionGetCb(ctx->client_config,
				      lws_openhitls_session_get_cb)
			!= HITLS_SUCCESS) {
		lwsl_warn("%s: HITLS_CFG_SetSessionGetCb failed\n", __func__);
		return;
	}

	if (HITLS_CFG_SetSessionRemoveCb(ctx->client_config,
					 lws_openhitls_session_remove_cb)
			!= HITLS_SUCCESS) {
		lwsl_warn("%s: HITLS_CFG_SetSessionRemoveCb failed\n", __func__);
		return;
	}

	if (HITLS_CFG_SetConfigUserData(ctx->client_config, vh)
			!= HITLS_SUCCESS) {
		lwsl_warn("%s: HITLS_CFG_SetConfigUserData failed\n", __func__);
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

/*
 * Internal: Set session for a connection (called during client connection setup)
 */
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

	/* Skip if session caching disabled */
	if (vh->options & LWS_SERVER_OPTION_DISABLE_TLS_SESSION_CACHE)
		return 0;

	/* Build session tag */
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

	/* Set session for resumption */
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

int
lws_openhitls_session_save(struct lws *wsi, const char *host, uint16_t port)
{
	struct lws_vhost *vh;
	HITLS_Session *session;
	char tag[LWS_SESSION_TAG_LEN];
	uint64_t ttl;
	int r;

	if (!wsi || !wsi->tls.ssl || !host)
		return -1;

	vh = wsi->a.vhost;
	if (!vh)
		return -1;

	/* Skip if session caching disabled */
	if (vh->options & LWS_SERVER_OPTION_DISABLE_TLS_SESSION_CACHE)
		return 0;

	session = HITLS_GetDupSession((HITLS_Ctx *)wsi->tls.ssl);
	if (!session) {
		lwsl_tlssess("%s: HITLS_GetDupSession returned NULL\n", __func__);
		return -1;
	}

	lws_snprintf(tag, sizeof(tag), "%s:%u", host, (unsigned int)port);
	ttl = HITLS_SESS_GetTimeout(session);

	lws_context_lock(vh->context, __func__);
	lws_vhost_lock(vh);
	r = lws_openhitls_session_store_locked(vh, wsi->a.context, wsi->tsi,
					       tag, session, ttl);
	lws_vhost_unlock(vh);
	lws_context_unlock(vh->context);

	if (r) {
		HITLS_SESS_Free(session);
		return -1;
	}

	return 0;
}
