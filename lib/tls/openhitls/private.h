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

struct lws_tls_openhitls_ctx {
	HITLS_Config *config;
#if defined(LWS_WITH_CLIENT)
	HITLS_Config *client_config;
	uint8_t client_explicit_ca_loaded;
#endif
};

struct lws_tls_openhitls_bio {
	BSL_UIO *uio;
};

struct lws_x509_cert {
	HITLS_X509_Cert *cert;
};

typedef HITLS_Ctx lws_tls_conn;
typedef struct lws_tls_openhitls_ctx lws_tls_ctx;
typedef struct lws_tls_openhitls_bio lws_tls_bio;

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
lws_openhitls_session_set(struct lws *wsi, const char *host, uint16_t port);

void
lws_openhitls_verify_bind(lws_tls_conn *ssl);

lws_tls_conn *
lws_openhitls_verify_get_ssl(void);

void
lws_openhitls_verify_unbind(void);

uint32_t
lws_openhitls_pending_bytes(struct lws *wsi);

void
lws_openhitls_klog_dump(HITLS_Ctx *ctx, const char *line);

CRYPT_MD_AlgId
lws_genhash_type_to_hitls_md_id(enum lws_genhash_types hash_type);

CRYPT_CIPHER_AlgId
lws_genaes_mode_to_hitls_cipher_id(enum enum_aes_modes mode, size_t keylen);

int32_t
lws_genrsa_padding_to_hitls(enum enum_genrsa_mode mode);

CRYPT_PKEY_ParaId
lws_genec_curve_to_hitls_para_id(const char *curve_name);

int
lws_genec_curve_key_bytes(const char *curve_name);

static LWS_INLINE HITLS_Config *
lws_openhitls_server_config_from_ssl_ctx(void *ssl_ctx)
{
	lws_tls_ctx *ctx = (lws_tls_ctx *)ssl_ctx;

	return ctx ? ctx->config : NULL;
}

static LWS_INLINE int
lws_openhitls_peer_cert_is_self_signed(HITLS_X509_Cert *cert)
{
	bool is_self_signed = false;

	if (!cert)
		return 0;

	if (HITLS_X509_CertCtrl(cert, HITLS_X509_IS_SELF_SIGNED,
				&is_self_signed,
				(uint32_t)sizeof(is_self_signed)) !=
			HITLS_SUCCESS)
		return 0;

	return is_self_signed ? 1 : 0;
}

static LWS_INLINE void
lws_openhitls_verify_result_to_policy(int vr, HITLS_X509_Cert *peer_cert,
				      const char **type, unsigned int *avoid)
{
	const char *lt = "tls=verify";
	unsigned int la = 0;
	int self_signed = lws_openhitls_peer_cert_is_self_signed(peer_cert);

	switch (vr) {
	case HITLS_X509_ERR_VFY_HOSTNAME_FAIL:
		lt = "tls=hostname";
		la = LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
		break;
	case HITLS_X509_ERR_VFY_INVALID_CA:
		lt = "tls=invalidca";
		la = LCCSCF_ALLOW_SELFSIGNED;
		break;
	case HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND:
	case HITLS_X509_ERR_ROOT_CERT_NOT_FOUND:
		lt = "tls=invalidca";
		la = self_signed ? LCCSCF_ALLOW_SELFSIGNED :
				   (LCCSCF_ALLOW_INSECURE |
				    LCCSCF_ALLOW_SELFSIGNED);
		break;
	case HITLS_X509_ERR_VFY_NOTBEFORE_IN_FUTURE:
	case HITLS_X509_ERR_TIME_FUTURE:
		lt = "tls=notyetvalid";
		la = LCCSCF_ALLOW_EXPIRED;
		break;
	case HITLS_X509_ERR_VFY_NOTAFTER_EXPIRED:
	case HITLS_X509_ERR_TIME_EXPIRED:
		lt = "tls=expired";
		la = LCCSCF_ALLOW_EXPIRED;
		break;
	default:
		break;
	}

	if (type)
		*type = lt;
	if (avoid)
		*avoid = la;
}

static LWS_INLINE int
lws_openhitls_error_to_lws(int hitls_ret)
{
	switch (hitls_ret) {
	case HITLS_SUCCESS:
		return LWS_SSL_CAPABLE_DONE;

	case HITLS_WANT_READ:
	case HITLS_REC_NORMAL_RECV_BUF_EMPTY:
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;

	case HITLS_WANT_WRITE:
	case HITLS_REC_NORMAL_IO_BUSY:
		return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;

	case HITLS_WANT_CONNECT:
	case HITLS_WANT_ACCEPT:
		return LWS_SSL_CAPABLE_MORE_SERVICE;

	case HITLS_REC_NORMAL_IO_EOF:
		return LWS_SSL_CAPABLE_DONE;

	default:
		return LWS_SSL_CAPABLE_ERROR;
	}
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

static LWS_INLINE const char *
lws_openhitls_cipher_seg_norm(const char *seg)
{
	if (!strcmp(seg, "AES128"))
		return "AES_128";
	if (!strcmp(seg, "AES256"))
		return "AES_256";
	if (!strcmp(seg, "CCM8"))
		return "CCM_8";

	return seg;
}

static LWS_INLINE int
lws_openhitls_cipher_to_stdname(const char *in, char *out, size_t out_len)
{
	char tmp[192], *parts[16], *p, *s;
	const char *seg;
	size_t i, np = 0, from = 0;
	int n;

	if (!in || !*in || !out || !out_len)
		return -1;

	if (strpbrk(in, "!+@[]")) /* OpenSSL expression operators unsupported */
		return -1;

	if (!strncmp(in, "TLS_", 4)) {
		lws_strncpy(out, in, out_len);
		return 0;
	}

	if (strlen(in) >= sizeof(tmp))
		return -1;

	lws_strncpy(tmp, in, sizeof(tmp));
	p = tmp;
	parts[np++] = p;
	while (*p && np < LWS_ARRAY_SIZE(parts)) {
		if (*p == '-') {
			*p = '\0';
			parts[np++] = p + 1;
		}
		p++;
	}
	if (np < 2)
		return -1;

	n = 0;
	if (!strcmp(parts[0], "ECDHE") && np >= 3 &&
	    (!strcmp(parts[1], "RSA") || !strcmp(parts[1], "ECDSA") ||
	     !strcmp(parts[1], "PSK"))) {
		n = lws_snprintf(out, out_len, "TLS_ECDHE_%s_WITH_", parts[1]);
		from = 2;
	} else if (!strcmp(parts[0], "DHE") && np >= 3 &&
		   (!strcmp(parts[1], "RSA") || !strcmp(parts[1], "DSS") ||
		    !strcmp(parts[1], "PSK"))) {
		n = lws_snprintf(out, out_len, "TLS_DHE_%s_WITH_", parts[1]);
		from = 2;
	} else if (!strcmp(parts[0], "RSA")) {
		n = lws_snprintf(out, out_len, "TLS_RSA_WITH_");
		from = 1;
	} else if (!strcmp(parts[0], "PSK")) {
		n = lws_snprintf(out, out_len, "TLS_PSK_WITH_");
		from = 1;
	} else {
		return -1;
	}
	if (n <= 0 || (size_t)n >= out_len)
		return -1;

	for (i = from; i < np; i++) {
		size_t left;

		seg = lws_openhitls_cipher_seg_norm(parts[i]);
		s = out + strlen(out);
		left = out_len - strlen(out);
		if (!left)
			return -1;
		n = lws_snprintf(s, left, "%s%s",
				 i == from ? "" : "_", seg);
		if (n <= 0 || (size_t)n >= left)
			return -1;
	}

	return 0;
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
