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
 * OpenHiTLS TLS context and global initialization
 */

#include "private-lib-core.h"
#include "private-lib-tls.h"
#include "private.h"

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

	ret = BSL_ERR_Init();
	if (ret != BSL_SUCCESS) {
		lwsl_cx_err(context, "BSL_ERR_Init failed: 0x%x", ret);
		openhitls_contexts_using_global_init--;
		return -1;
	}

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

	CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
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
