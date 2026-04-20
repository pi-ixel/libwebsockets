/*
 * lws-api-test-openhitls-cipher-map
 *
 * unit tests for OpenHiTLS OpenSSL cipher alias lookup
 */

#include <libwebsockets.h>

#include "private-lib-core.h"
#include "private-lib-tls.h"
#include "private.h"

static int
expect_success(const char *in, const char *expected)
{
	char buf[192];

	if (lws_openhitls_cipher_to_stdname(in, buf, sizeof(buf))) {
		lwsl_err("%s: conversion failed for '%s'\n", __func__, in);

		return 1;
	}

	if (strcmp(buf, expected)) {
		lwsl_err("%s: '%s' -> '%s', expected '%s'\n",
			 __func__, in, buf, expected);

		return 1;
	}

	return 0;
}

static int
expect_fail(const char *in)
{
	char buf[192];

	if (!lws_openhitls_cipher_to_stdname(in, buf, sizeof(buf))) {
		lwsl_err("%s: expected failure for '%s', got '%s'\n",
			 __func__, in, buf);

		return 1;
	}

	return 0;
}

int
main(int argc, const char **argv)
{
	const char *p;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	int e = 0;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: OpenHiTLS cipher alias lookup\n");

	e |= expect_success("DHE-PSK-AES128-CCM8",
			    "TLS_PSK_DHE_WITH_AES_128_CCM_8");
	e |= expect_fail("ECDHE-RSA-FAKE-CIPHER");
	e |= expect_success("TLS_AES_128_GCM_SHA256",
			    "TLS_AES_128_GCM_SHA256");

	if (e)
		lwsl_err("%s: failed\n", __func__);
	else
		lwsl_user("%s: pass\n", __func__);

	return e;
}
