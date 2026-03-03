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

#include <hitls.h>
#include <hitls_config.h>
#include <hitls_alpn.h>
#include <hitls_sni.h>

#include <hitls_session.h>

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
int
lws_openhitls_session_set(struct lws *wsi, const char *host, uint16_t port);

int
lws_openhitls_session_save(struct lws *wsi, const char *host, uint16_t port);

void
lws_openhitls_verify_bind(lws_tls_conn *ssl);

lws_tls_conn *
lws_openhitls_verify_get_ssl(void);

void
lws_openhitls_verify_unbind(void);

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

static LWS_INLINE void
lws_openhitls_verify_result_to_policy(int vr, const char **type,
				      unsigned int *avoid)
{
	const char *lt = "tls=verify";
	unsigned int la = 0;

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
		la = LCCSCF_ALLOW_INSECURE;
		break;
	case HITLS_X509_ERR_VFY_NOTBEFORE_IN_FUTURE:
	case HITLS_X509_ERR_VFY_NOTAFTER_EXPIRED:
	case HITLS_X509_ERR_TIME_FUTURE:
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

#ifndef SSL_OP_NO_TLSv1
#define SSL_OP_NO_TLSv1			0x04000000L
#endif
#ifndef SSL_OP_NO_TLSv1_1
#define SSL_OP_NO_TLSv1_1		0x10000000L
#endif
#ifndef SSL_OP_NO_TLSv1_2
#define SSL_OP_NO_TLSv1_2		0x08000000L
#endif
#ifndef SSL_OP_NO_TLSv1_3
#define SSL_OP_NO_TLSv1_3		0x20000000L
#endif
#ifndef SSL_OP_NO_TICKET
#define SSL_OP_NO_TICKET		0x00004000L
#endif
#ifndef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
#define SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION	0x00010000L
#endif
#ifndef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
#define SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION	0x00040000L
#endif
#ifndef SSL_OP_NO_ENCRYPT_THEN_MAC
#define SSL_OP_NO_ENCRYPT_THEN_MAC	0x00080000L
#endif
#ifndef SSL_OP_CIPHER_SERVER_PREFERENCE
#define SSL_OP_CIPHER_SERVER_PREFERENCE	0x00400000L
#endif
#ifndef SSL_OP_NO_RENEGOTIATION
#define SSL_OP_NO_RENEGOTIATION		0x40000000L
#endif
#ifndef SSL_OP_NO_EXTENDED_MASTER_SECRET
#define SSL_OP_NO_EXTENDED_MASTER_SECRET	(1ULL << 0)
#endif
#ifndef SSL_OP_CLEANSE_PLAINTEXT
#define SSL_OP_CLEANSE_PLAINTEXT		(1ULL << 1)
#endif
#ifndef SSL_OP_LEGACY_SERVER_CONNECT
#define SSL_OP_LEGACY_SERVER_CONNECT		(1ULL << 2)
#endif
#ifndef SSL_OP_ENABLE_KTLS
#define SSL_OP_ENABLE_KTLS			(1ULL << 3)
#endif
#ifndef SSL_OP_TLSEXT_PADDING
#define SSL_OP_TLSEXT_PADDING			(1ULL << 4)
#endif
#ifndef SSL_OP_SAFARI_ECDHE_ECDSA_BUG
#define SSL_OP_SAFARI_ECDHE_ECDSA_BUG		(1ULL << 6)
#endif
#ifndef SSL_OP_IGNORE_UNEXPECTED_EOF
#define SSL_OP_IGNORE_UNEXPECTED_EOF		(1ULL << 7)
#endif
#ifndef SSL_OP_ALLOW_CLIENT_RENEGOTIATION
#define SSL_OP_ALLOW_CLIENT_RENEGOTIATION	(1ULL << 8)
#endif
#ifndef SSL_OP_DISABLE_TLSEXT_CA_NAMES
#define SSL_OP_DISABLE_TLSEXT_CA_NAMES		(1ULL << 9)
#endif
#ifndef SSL_OP_ALLOW_NO_DHE_KEX
#define SSL_OP_ALLOW_NO_DHE_KEX			(1ULL << 10)
#endif
#ifndef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
#define SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS	(1ULL << 11)
#endif
#ifndef SSL_OP_NO_QUERY_MTU
#define SSL_OP_NO_QUERY_MTU			(1ULL << 12)
#endif
#ifndef SSL_OP_COOKIE_EXCHANGE
#define SSL_OP_COOKIE_EXCHANGE			(1ULL << 13)
#endif
#ifndef SSL_OP_CISCO_ANYCONNECT
#define SSL_OP_CISCO_ANYCONNECT			(1ULL << 15)
#endif
#ifndef SSL_OP_NO_COMPRESSION
#define SSL_OP_NO_COMPRESSION			(1ULL << 17)
#endif
#ifndef SSL_OP_ENABLE_MIDDLEBOX_COMPAT
#define SSL_OP_ENABLE_MIDDLEBOX_COMPAT		(1ULL << 20)
#endif
#ifndef SSL_OP_PRIORITIZE_CHACHA
#define SSL_OP_PRIORITIZE_CHACHA		(1ULL << 21)
#endif
#ifndef SSL_OP_SERVER_PREFERENCE
#define SSL_OP_SERVER_PREFERENCE		(1ULL << 22)
#endif
#ifndef SSL_OP_TLS_ROLLBACK_BUG
#define SSL_OP_TLS_ROLLBACK_BUG			(1ULL << 23)
#endif
#ifndef SSL_OP_NO_ANTI_REPLAY
#define SSL_OP_NO_ANTI_REPLAY			(1ULL << 24)
#endif
#ifndef SSL_OP_NO_SSLv3
#define SSL_OP_NO_SSLv3				(1ULL << 25)
#endif
#ifndef SSL_OP_NO_DTLSv1
#define SSL_OP_NO_DTLSv1			(1ULL << 26)
#endif
#ifndef SSL_OP_NO_DTLSv1_2
#define SSL_OP_NO_DTLSv1_2			(1ULL << 27)
#endif
#ifndef SSL_OP_NO_SSLv2
#define SSL_OP_NO_SSLv2				0
#endif
#ifndef SSL_OP_CRYPTOPRO_TLSEXT_BUG
#define SSL_OP_CRYPTOPRO_TLSEXT_BUG		(1ULL << 31)
#endif
#ifndef SSL_OP_NO_TX_CERTIFICATE_COMPRESSION
#define SSL_OP_NO_TX_CERTIFICATE_COMPRESSION	(1ULL << 32)
#endif
#ifndef SSL_OP_NO_RX_CERTIFICATE_COMPRESSION
#define SSL_OP_NO_RX_CERTIFICATE_COMPRESSION	(1ULL << 33)
#endif
#ifndef SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE
#define SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE	(1ULL << 34)
#endif
#ifndef SSL_OP_PREFER_NO_DHE_KEX
#define SSL_OP_PREFER_NO_DHE_KEX		(1ULL << 35)
#endif
#ifndef SSL_OP_LEGACY_EC_POINT_FORMATS
#define SSL_OP_LEGACY_EC_POINT_FORMATS		(1ULL << 36)
#endif

/*
 * OpenSSL ssl_options_set/clear mapping:
 * - actionable bits are mapped to OpenHiTLS config APIs
 * - compatibility-only bits are recognized and ignored (explicit no-op)
 * - unknown bits are warned
 */
static LWS_INLINE int
lws_openhitls_apply_ssl_options(HITLS_Config *config, long options_set,
				long options_clear, const char *who)
{
	const unsigned long long mapped =
		(unsigned long long)SSL_OP_NO_EXTENDED_MASTER_SECRET |
		(unsigned long long)SSL_OP_LEGACY_SERVER_CONNECT |
		(unsigned long long)SSL_OP_ALLOW_CLIENT_RENEGOTIATION |
		(unsigned long long)SSL_OP_COOKIE_EXCHANGE |
		(unsigned long long)SSL_OP_NO_TICKET |
		(unsigned long long)SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
		(unsigned long long)SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
		(unsigned long long)SSL_OP_NO_ENCRYPT_THEN_MAC |
		(unsigned long long)SSL_OP_SERVER_PREFERENCE |
		(unsigned long long)SSL_OP_CIPHER_SERVER_PREFERENCE |
		(unsigned long long)SSL_OP_NO_SSLv3 |
		(unsigned long long)SSL_OP_NO_TLSv1 |
		(unsigned long long)SSL_OP_NO_TLSv1_1 |
		(unsigned long long)SSL_OP_NO_TLSv1_2 |
		(unsigned long long)SSL_OP_NO_TLSv1_3 |
		(unsigned long long)SSL_OP_NO_RENEGOTIATION;
	const unsigned long long ignored =
		(unsigned long long)SSL_OP_CLEANSE_PLAINTEXT |
		(unsigned long long)SSL_OP_ENABLE_KTLS |
		(unsigned long long)SSL_OP_TLSEXT_PADDING |
		(unsigned long long)SSL_OP_SAFARI_ECDHE_ECDSA_BUG |
		(unsigned long long)SSL_OP_IGNORE_UNEXPECTED_EOF |
		(unsigned long long)SSL_OP_DISABLE_TLSEXT_CA_NAMES |
		(unsigned long long)SSL_OP_ALLOW_NO_DHE_KEX |
		(unsigned long long)SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS |
		(unsigned long long)SSL_OP_NO_QUERY_MTU |
		(unsigned long long)SSL_OP_CISCO_ANYCONNECT |
		(unsigned long long)SSL_OP_NO_COMPRESSION |
		(unsigned long long)SSL_OP_ENABLE_MIDDLEBOX_COMPAT |
		(unsigned long long)SSL_OP_PRIORITIZE_CHACHA |
		(unsigned long long)SSL_OP_TLS_ROLLBACK_BUG |
		(unsigned long long)SSL_OP_NO_ANTI_REPLAY |
		(unsigned long long)SSL_OP_CRYPTOPRO_TLSEXT_BUG |
		(unsigned long long)SSL_OP_NO_TX_CERTIFICATE_COMPRESSION |
		(unsigned long long)SSL_OP_NO_RX_CERTIFICATE_COMPRESSION |
		(unsigned long long)SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE |
		(unsigned long long)SSL_OP_PREFER_NO_DHE_KEX |
		(unsigned long long)SSL_OP_LEGACY_EC_POINT_FORMATS |
		(unsigned long long)SSL_OP_NO_DTLSv1 |
		(unsigned long long)SSL_OP_NO_DTLSv1_2;
	unsigned long long set64 = (unsigned long long)(unsigned long)options_set;
	unsigned long long clr64 = (unsigned long long)(unsigned long)options_clear;
	unsigned long long effective, unknown;
	int client_renego = 0, legacy_renego = 0;
	int r;
	uint16_t minv = HITLS_VERSION_TLS12, maxv = HITLS_VERSION_TLS13;

	if (!config)
		return -1;

	effective = (set64 & (mapped | ignored)) &
		    ~(clr64 & (mapped | ignored));
	unknown = (set64 | clr64) & ~(mapped | ignored);

	/*
	 * Keep current backend default at TLS1.2+.
	 * If caller explicitly clears older no-tls bits, permit lowering min.
	 */
	if (clr64 & ((unsigned long long)SSL_OP_NO_TLSv1 |
		     (unsigned long long)SSL_OP_NO_TLSv1_1))
		minv = HITLS_VERSION_TLS10;
	if (clr64 & (unsigned long long)SSL_OP_NO_SSLv3)
		lwsl_warn("%s: %s cannot enable SSLv3 (unsupported by OpenHiTLS)\n",
			  __func__, who ? who : "openhitls");

	if (effective & (unsigned long long)SSL_OP_NO_SSLv3)
		minv = minv > HITLS_VERSION_TLS10 ? minv : HITLS_VERSION_TLS10;
	if (effective & (unsigned long long)SSL_OP_NO_TLSv1)
		minv = minv > HITLS_VERSION_TLS11 ? minv : HITLS_VERSION_TLS11;
	if (effective & (unsigned long long)SSL_OP_NO_TLSv1_1)
		minv = minv > HITLS_VERSION_TLS12 ? minv : HITLS_VERSION_TLS12;
	if (effective & (unsigned long long)SSL_OP_NO_TLSv1_2)
		minv = HITLS_VERSION_TLS13;
	if (effective & (unsigned long long)SSL_OP_NO_TLSv1_3)
		maxv = HITLS_VERSION_TLS12;

	if (minv > maxv) {
		lwsl_err("%s: %s incompatible tls options (disable TLS1.2 and TLS1.3)\n",
			 __func__, who ? who : "openhitls");
		return -1;
	}

	if (HITLS_CFG_SetVersion(config, minv, maxv) != HITLS_SUCCESS) {
		lwsl_err("%s: %s HITLS_CFG_SetVersion failed (%04x..%04x)\n",
			 __func__, who ? who : "openhitls",
			 (unsigned int)minv, (unsigned int)maxv);
		return -1;
	}

	r = HITLS_CFG_SetExtendedMasterSecretSupport(config,
		(effective & (unsigned long long)SSL_OP_NO_EXTENDED_MASTER_SECRET) ?
				false : true);
	if (r != HITLS_SUCCESS) {
		lwsl_err("%s: %s HITLS_CFG_SetExtendedMasterSecretSupport failed\n",
			 __func__, who ? who : "openhitls");
		return -1;
	}

	if (HITLS_CFG_SetSessionTicketSupport(config,
			(effective & (unsigned long long)SSL_OP_NO_TICKET) ?
				false : true) !=
				HITLS_SUCCESS) {
		lwsl_err("%s: %s HITLS_CFG_SetSessionTicketSupport failed\n",
			 __func__, who ? who : "openhitls");
		return -1;
	}

	r = HITLS_CFG_SetResumptionOnRenegoSupport(config,
			(effective & (unsigned long long)
					SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION) ?
					false : true);
	if (r != HITLS_SUCCESS) {
		lwsl_err("%s: %s HITLS_CFG_SetResumptionOnRenegoSupport failed\n",
			 __func__, who ? who : "openhitls");
		return -1;
	}

	legacy_renego = !!(effective & ((unsigned long long)
			SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
			(unsigned long long)SSL_OP_LEGACY_SERVER_CONNECT));
	r = HITLS_CFG_SetLegacyRenegotiateSupport(config, legacy_renego);
	if (r != HITLS_SUCCESS) {
		lwsl_err("%s: %s HITLS_CFG_SetLegacyRenegotiateSupport failed\n",
			 __func__, who ? who : "openhitls");
		return -1;
	}

	client_renego = !!(effective &
			(unsigned long long)SSL_OP_ALLOW_CLIENT_RENEGOTIATION);
	if (effective & (unsigned long long)SSL_OP_NO_RENEGOTIATION)
		client_renego = 0;
	r = HITLS_CFG_SetClientRenegotiateSupport(config, client_renego);
	if (r != HITLS_SUCCESS) {
		lwsl_err("%s: %s HITLS_CFG_SetClientRenegotiateSupport failed\n",
			 __func__, who ? who : "openhitls");
		return -1;
	}

	r = HITLS_CFG_SetEncryptThenMac(config,
			(effective & (unsigned long long)SSL_OP_NO_ENCRYPT_THEN_MAC) ?
				false : true);
	if (r != HITLS_SUCCESS) {
		lwsl_err("%s: %s HITLS_CFG_SetEncryptThenMac failed\n",
			 __func__, who ? who : "openhitls");
		return -1;
	}

	r = HITLS_CFG_SetCipherServerPreference(config,
		(effective & ((unsigned long long)SSL_OP_SERVER_PREFERENCE |
			      (unsigned long long)SSL_OP_CIPHER_SERVER_PREFERENCE)) ?
			true : false);
	if (r != HITLS_SUCCESS) {
		lwsl_err("%s: %s HITLS_CFG_SetCipherServerPreference failed\n",
			 __func__, who ? who : "openhitls");
		return -1;
	}

	r = HITLS_CFG_SetRenegotiationSupport(config,
			(effective & (unsigned long long)SSL_OP_NO_RENEGOTIATION) ?
				false : true);
	if (r != HITLS_SUCCESS) {
		lwsl_err("%s: %s HITLS_CFG_SetRenegotiationSupport failed\n",
			 __func__, who ? who : "openhitls");
		return -1;
	}

	if ((set64 | clr64) & (unsigned long long)SSL_OP_COOKIE_EXCHANGE) {
		r = HITLS_CFG_SetDtlsCookieExchangeSupport(config,
				(effective & (unsigned long long)SSL_OP_COOKIE_EXCHANGE) ?
					true : false);
		if (r != HITLS_SUCCESS) {
			lwsl_warn("%s: %s HITLS_CFG_SetDtlsCookieExchangeSupport not applicable\n",
				  __func__, who ? who : "openhitls");
		}
	}

	if (unknown)
		lwsl_warn("%s: %s unsupported ssl_options bits: 0x%llx\n",
			  __func__, who ? who : "openhitls", unknown);

	if (minv < HITLS_VERSION_TLS12)
		lwsl_warn("%s: %s enabling legacy TLS versions (min=%04x)\n",
			  __func__, who ? who : "openhitls",
			  (unsigned int)minv);

	return 0;
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
