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
 */

#if !defined(__LWS_OPENHITLS_PRIVATE_H__)
#define __LWS_OPENHITLS_PRIVATE_H__

#include <stdio.h>

#include "cipher-mapping.h"

#include <hitls.h>
#include <hitls_config.h>
#include <hitls_alpn.h>
#include <hitls_sni.h>

#include <hitls_session.h>
#include <hitls_debug.h>

#include <hitls_cert.h>

#include <crypt_errno.h>
#include <crypt_types.h>
#include <crypt_params_key.h>
#include <crypt_eal_init.h>

#include <bsl_err.h>

#include <bsl_sal.h>

#include <hitls_pki_cert.h>
#include <hitls_pki_types.h>
#include <hitls_pki_x509.h>
#include <hitls_pki_errno.h>
#include <bsl_uio.h>

struct lws_x509_cert {
	HITLS_X509_Cert *cert;
};

typedef HITLS_Ctx lws_tls_conn;
typedef HITLS_Config lws_tls_ctx;
typedef BSL_UIO lws_tls_bio;

/*
 * Session reuse structure for client context caching
 * One per different client context; cc_owner is in lws_context.lws_context_tls
 */
struct lws_tls_client_reuse {
	lws_tls_ctx *ssl_client_ctx;
	uint8_t hash[32];
	struct lws_dll2 cc_list;
	int refcount;
	int index;
};

#define LWS_OPENHITLS_HOSTNAME_VERIFY_FLAGS 0u

int
lws_openhitls_describe_cipher(struct lws *wsi);

void
lws_openhitls_klog_dump(HITLS_Ctx *ctx, const char *line);

CRYPT_MD_AlgId
lws_genhash_type_to_hitls_md_id(enum lws_genhash_types hash_type);

CRYPT_CIPHER_AlgId
lws_genaes_mode_to_hitls_cipher_id(enum enum_aes_modes mode, size_t keylen);

int
lws_tls_openhitls_cert_info(HITLS_X509_Cert *x509,
			    enum lws_tls_cert_info type,
			    union lws_tls_cert_info_results *buf, size_t len);

#ifndef SSL_OP_NO_TLSv1_2
#define SSL_OP_NO_TLSv1_2 0x08000000L
#endif

#ifndef SSL_OP_NO_TLSv1_3
#define SSL_OP_NO_TLSv1_3 0x20000000L
#endif

int
lws_openhitls_apply_tls_version_by_ssl_options(HITLS_Config *config, long set,
					       long clear, const char *who);

static LWS_INLINE HITLS_Config *
lws_openhitls_server_config_from_ssl_ctx(void *ssl_ctx)
{
	return (HITLS_Config *)ssl_ctx;
}

static LWS_INLINE void
lws_openhitls_trim_ws(char **start, char **end)
{
	while (*start < *end && (**start == ' ' || **start == '\t'))
		(*start)++;

	while (*end > *start &&
	       ((*(*end - 1) == ' ') || (*(*end - 1) == '\t')))
		(*end)--;
}

static LWS_INLINE int
lws_openhitls_cipher_to_stdname(const char *in, char *out, size_t out_len)
{
	size_t i;
	int n;

	if (!in || !*in || !out || !out_len)
		return -1;

	if (strpbrk(in, "!+@[]")) /* OpenSSL expression operators unsupported */
		return -1;

	if (!strncmp(in, "TLS_", 4)) {
		n = lws_snprintf(out, out_len, "%s", in);
		if (n <= 0 || (size_t)n >= out_len)
			return -1;

		return 0;
	}

	for (i = 0; i < LWS_ARRAY_SIZE(lws_openhitls_cipher_map); i++)
		if (!strcmp(in, lws_openhitls_cipher_map[i].openssl_name)) {
			n = lws_snprintf(out, out_len, "%s",
					 lws_openhitls_cipher_map[i].iana_name);
			if (n <= 0 || (size_t)n >= out_len)
				return -1;

			return 0;
		}

	return -1;
}

static LWS_INLINE int
lws_openhitls_collect_cipher_list(const char *list, uint16_t *suites,
				  size_t max_suites, size_t *count,
				  const char *who)
{
	const HITLS_Cipher *c;
	char token[192], std[192];
	const char *p, *d;
	size_t before;
	uint16_t id;
	int n;

	if (!list || !*list || !suites || !count || !max_suites)
		return 0;

	before = *count;
	p = list;
	while (*p) {
		const char *d2;
		char *ts, *te;
		size_t tl;

		d = strchr(p, ':');
		d2 = strchr(p, ',');
		if (!d || (d2 && d2 < d))
			d = d2;
		if (!d)
			d = p + strlen(p);
		tl = (size_t)(d - p);
		if (tl >= sizeof(token))
			tl = sizeof(token) - 1;
		memcpy(token, p, tl);
		token[tl] = '\0';

		ts = token;
		te = token + strlen(token);
		lws_openhitls_trim_ws(&ts, &te);
		*te = '\0';

		if (*ts) {
			if (lws_openhitls_cipher_to_stdname(ts, std, sizeof(std))) {
				lwsl_warn("%s: unsupported cipher token '%s'\n",
					  who, ts);
			} else {
				c = HITLS_CFG_GetCipherSuiteByStdName((const uint8_t *)std);
				if (!c) {
					lwsl_warn("%s: unknown cipher '%s' (std '%s')\n",
						  who, ts, std);
				} else if (HITLS_CFG_GetCipherSuite(c, &id) != HITLS_SUCCESS) {
					lwsl_warn("%s: unable to get cipher id for '%s'\n",
						  who, std);
				} else if (*count < max_suites) {
					size_t i;
					int dup = 0;

					for (i = 0; i < *count; i++)
						if (suites[i] == id) {
							dup = 1;
							break;
						}
					if (!dup)
						suites[(*count)++] = id;
				}
			}
		}

		p = *d ? d + 1 : d;
	}

	if (*count == before)
		return -1;

	n = (int)(*count - before);
	return n;
}

#endif
