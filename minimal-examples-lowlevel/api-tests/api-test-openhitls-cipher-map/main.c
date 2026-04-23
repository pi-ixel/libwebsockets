/*
 * lws-api-test-openhitls-cipher-map
 *
 * unit tests for OpenHiTLS direct IANA cipher-suite configuration
 */

#include <libwebsockets.h>

#include "private-lib-core.h"
#include "private-lib-tls.h"
#include "private.h"

static int
expect_apply_success(const char *in)
{
	HITLS_Config *config = HITLS_CFG_NewTLSConfig();
	int ret;

	if (!config) {
		lwsl_err("%s: HITLS_CFG_NewTLSConfig failed\n", __func__);

		return 1;
	}

	ret = lws_openhitls_apply_cipher_suites(config, in, __func__);
	HITLS_CFG_FreeConfig(config);
	if (ret)
		lwsl_err("%s: apply failed for '%s'\n", __func__, in);

	return ret != 0;
}

static int
expect_apply_fail(const char *in)
{
	HITLS_Config *config = HITLS_CFG_NewTLSConfig();
	int ret;

	if (!config) {
		lwsl_err("%s: HITLS_CFG_NewTLSConfig failed\n", __func__);

		return 1;
	}

	ret = lws_openhitls_apply_cipher_suites(config, in, __func__);
	HITLS_CFG_FreeConfig(config);
	if (!ret)
		lwsl_err("%s: expected failure for '%s'\n", __func__, in);

	return ret == 0;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	const char *p;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	int e = 0;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: OpenHiTLS IANA cipher config\n");

	memset(&info, 0, sizeof(info));
#if defined(LWS_WITH_NETWORK)
	info.port = CONTEXT_PORT_NO_LISTEN;
#endif
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	e |= expect_apply_success("TLS_AES_128_GCM_SHA256");
	e |= expect_apply_success("TLS_AES_128_GCM_SHA256,"
				  "TLS_AES_256_GCM_SHA384");
	e |= expect_apply_fail("AES128-SHA");
	e |= expect_apply_fail("ECDHE-RSA-FAKE-CIPHER");
	e |= expect_apply_fail("TLS_AES_128_GCM_SHA256:ECDHE-RSA-FAKE-CIPHER");

	if (e)
		lwsl_err("%s: failed\n", __func__);
	else
		lwsl_user("%s: pass\n", __func__);

	lws_context_destroy(context);

	return e;
}
