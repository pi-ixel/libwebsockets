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

#include "private-lib-core.h"
#include "../private-lib-tls.h"

#include <hitls_pki_cert.h>
#include <hitls_pki_x509.h>
#include <hitls_pki_types.h>
#include <hitls_pki_utils.h>
#include <crypt_eal_pkey.h>
#include <crypt_eal_codecs.h>
#include <crypt_eal_md.h>
#include <crypt_eal_rand.h>
#include <bsl_types.h>
#include <bsl_asn1.h>
#include <bsl_list.h>
#include <bsl_obj.h>
#include <bsl_sal.h>
#include <bsl_params.h>
#include <hitls_pki_errno.h>
#include <hitls_cert.h>
#include <hitls_error.h>
#include <crypt_params_key.h>
#include <crypt_errno.h>

static time_t
lws_tls_openhitls_bsltime_to_unix(BSL_TIME *bsl_time)
{
	struct tm t;
	memset(&t, 0, sizeof(t));
	t.tm_year = bsl_time->year - 1900;
	t.tm_mon = bsl_time->month - 1;
	t.tm_mday = bsl_time->day - 1;
	t.tm_hour = bsl_time->hour;
	t.tm_min = bsl_time->minute;
	t.tm_sec = bsl_time->second;
	t.tm_isdst = 0;
	return mktime(&t);
}

static int
lws_tls_openhitls_parse_ipv4(const char *ads, uint8_t out[4])
{
	char *e;
	unsigned long v;
	int n;

	if (!ads || !*ads)
		return -1;
	for (n = 0; n < 4; n++) {
		if (*ads < '0' || *ads > '9')
			return -1;
		v = strtoul(ads, &e, 10);
		if (e == ads || v > 255)
			return -1;
		out[n] = (uint8_t)v;
		if (n == 3) {
			if (*e != '\0')
				return -1;
		} else {
			if (*e != '.')
				return -1;
			ads = e + 1;
		}
	}
	return 0;
}

static int
lws_tls_openhitls_add_eku_oid(BslList *oid_list, BslCid cid)
{
	BSL_Buffer *oid_buf;
	BslOidString *oid;

	oid = BSL_OBJ_GetOID(cid);
	if (!oid || !oid->octs || !oid->octetLen)
		return -1;
	oid_buf = BSL_SAL_Malloc(sizeof(*oid_buf));
	if (!oid_buf)
		return -1;
	oid_buf->data = (uint8_t *)oid->octs;
	oid_buf->dataLen = oid->octetLen;
	if (BSL_LIST_AddElement(oid_list, oid_buf, BSL_LIST_POS_END) != BSL_SUCCESS) {
		BSL_SAL_Free(oid_buf);
		return -1;
	}
	return 0;
}

static int
lws_tls_openhitls_get_ski(HITLS_X509_Cert *cert, BSL_Buffer *kid)
{
	CRYPT_EAL_PkeyCtx *pubkey = NULL;
	BSL_Buffer spki = {0};
	uint8_t *enc;
	uint32_t enc_len, vlen, md_len;
	int32_t ret;

	ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_PUBKEY, &pubkey, sizeof(CRYPT_EAL_PkeyCtx *));
	if (ret != HITLS_PKI_SUCCESS)
		return -1;
	ret = CRYPT_EAL_EncodeBuffKey(pubkey, NULL, BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, &spki);
	CRYPT_EAL_PkeyFreeCtx(pubkey);
	if (ret != CRYPT_SUCCESS)
		return -1;

	enc = spki.data;
	enc_len = spki.dataLen;
	/* SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, BIT STRING } */
	ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, &enc, &enc_len, &vlen);
	if (ret != BSL_SUCCESS) {
		BSL_SAL_Free(spki.data);
		return -1;
	}
	/* Skip AlgorithmIdentifier (inner SEQUENCE) to reach subjectPublicKey BIT STRING. */
	ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, &enc, &enc_len, &vlen);
	if (ret != BSL_SUCCESS || enc_len < vlen) {
		BSL_SAL_Free(spki.data);
		return -1;
	}
	enc += vlen;
	enc_len -= vlen;
	ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_BITSTRING, &enc, &enc_len, &vlen);
	if (ret != BSL_SUCCESS || enc_len < vlen || vlen < 1) {
		BSL_SAL_Free(spki.data);
		return -1;
	}
	/* Skip the BIT STRING unused-bits byte and hash the public key body. */
	enc++;
	vlen--;

	kid->data = BSL_SAL_Malloc(20); /* SHA-1 digest size */
	if (!kid->data) {
		BSL_SAL_Free(spki.data);
		return -1;
	}
	kid->dataLen = 20;
	md_len = kid->dataLen;
	ret = CRYPT_EAL_Md(CRYPT_MD_SHA1, enc, vlen, kid->data, &md_len);
	BSL_SAL_Free(spki.data);
	if (ret != CRYPT_SUCCESS) {
		BSL_SAL_Free(kid->data);
		kid->data = NULL;
		kid->dataLen = 0;
		return -1;
	}
	kid->dataLen = md_len;
	return 0;
}

static int
lws_tls_openhitls_set_san(HITLS_X509_Cert *cert, const char *san)
{
	HITLS_X509_ExtSan san_ext = {0};
	HITLS_X509_GeneralName *gn = NULL;
	uint8_t ip4[4];
	int32_t ret = HITLS_PKI_SUCCESS;
	size_t slen;

	if (!san || !*san)
		return 0;
	san_ext.critical = false;
	san_ext.names = BSL_LIST_New(sizeof(HITLS_X509_GeneralName *));
	if (!san_ext.names)
		return -1;
	gn = BSL_SAL_Calloc(1, sizeof(*gn));
	if (!gn)
		goto bail;

	if (!lws_tls_openhitls_parse_ipv4(san, ip4)) {
		gn->type = HITLS_X509_GN_IP;
		gn->value.dataLen = 4;
		gn->value.data = BSL_SAL_Dump(ip4, 4);
		if (!gn->value.data)
			goto bail;
	} else {
		slen = strlen(san);
		gn->type = HITLS_X509_GN_DNS;
		gn->value.dataLen = (uint32_t)slen;
		gn->value.data = BSL_SAL_Dump(san, (uint32_t)slen);
		if (!gn->value.data)
			goto bail;
	}

	if (BSL_LIST_AddElement(san_ext.names, gn, BSL_LIST_POS_END) != BSL_SUCCESS)
		goto bail;
	gn = NULL;
	ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_SAN, &san_ext, sizeof(san_ext));
bail:
	if (gn)
		HITLS_X509_FreeGeneralName(gn);
	BSL_LIST_FREE(san_ext.names, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeGeneralName);
	return ret == HITLS_PKI_SUCCESS ? 0 : -1;
}

static int
lws_tls_openhitls_cert_info(HITLS_X509_Cert *x509, enum lws_tls_cert_info type,
			     union lws_tls_cert_info_results *buf, size_t len)
{
	CRYPT_EAL_PkeyCtx *pubkey = NULL;
	HITLS_X509_ExtAki aki = {0};
	HITLS_X509_ExtSki ski = {0};
	BSL_Buffer encode = {0};
	BSL_TIME bsl_time = {0};
	uint32_t usage;
	int32_t ret;
	buf->ns.len = 0;

	if (!x509)
		return -1;
	if (!len)
		len = sizeof(buf->ns.name);

	switch (type) {
	case LWS_TLS_CERT_INFO_VALIDITY_FROM:
		ret = HITLS_X509_CertCtrl(x509, HITLS_X509_GET_BEFORE_TIME, &bsl_time, sizeof(BSL_TIME));
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_X509_GET_BEFORE_TIME failed, ret=0x%x\n", __func__, ret);
			return -1;
		}
		buf->time = lws_tls_openhitls_bsltime_to_unix(&bsl_time);
		if (buf->time == (time_t)-1)
			return -1;
		return 0;

	case LWS_TLS_CERT_INFO_VALIDITY_TO:
		ret = HITLS_X509_CertCtrl(x509, HITLS_X509_GET_AFTER_TIME, &bsl_time, sizeof(BSL_TIME));
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_X509_GET_AFTER_TIME failed, ret=0x%x\n", __func__, ret);
			return -1;
		}
		buf->time = lws_tls_openhitls_bsltime_to_unix(&bsl_time);
		if (buf->time == (time_t)-1)
			return -1;
		return 0;

	case LWS_TLS_CERT_INFO_COMMON_NAME:
		ret = HITLS_X509_CertCtrl(x509, HITLS_X509_GET_SUBJECT_CN_STR, &encode, sizeof(BSL_Buffer));
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_X509_GET_SUBJECT_CN_STR failed, ret=0x%x\n", __func__, ret);
			return -1;
		}
		buf->ns.len = (int)encode.dataLen;
		if (encode.dataLen > len) {
			BSL_SAL_Free(encode.data);
			return -1;
		}
		memcpy(buf->ns.name, encode.data, encode.dataLen);
		BSL_SAL_Free(encode.data);
		return 0;

	case LWS_TLS_CERT_INFO_ISSUER_NAME:
		ret = HITLS_X509_CertCtrl(x509, HITLS_X509_GET_ISSUER_DN_STR, &encode, sizeof(BSL_Buffer));
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_X509_GET_ISSUER_DN_STR failed, ret=0x%x\n", __func__, ret);
			return -1;
		}
		buf->ns.len = (int)encode.dataLen;
		if (encode.dataLen > len) {
			BSL_SAL_Free(encode.data);
			return -1;
		}
		memcpy(buf->ns.name, encode.data, encode.dataLen);
		BSL_SAL_Free(encode.data);
		return 0;

	case LWS_TLS_CERT_INFO_USAGE:
		ret = HITLS_X509_CertCtrl(x509, HITLS_X509_EXT_GET_KUSAGE, &usage, sizeof(usage));
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_X509_EXT_GET_KUSAGE failed, ret=0x%x\n", __func__, ret);
			return -1;
		}
		buf->usage = usage;
		return 0;

	case LWS_TLS_CERT_INFO_OPAQUE_PUBLIC_KEY:
		ret = HITLS_X509_CertCtrl(x509, HITLS_X509_GET_PUBKEY, &pubkey, sizeof(CRYPT_EAL_PkeyCtx *));
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_X509_GET_PUBKEY failed, ret=0x%x\n", __func__, ret);
			return -1;
		}
		ret = CRYPT_EAL_EncodeBuffKey(pubkey, NULL, BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, &encode);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CRYPT_EAL_EncodeBuffKey failed, ret=0x%x\n", __func__, ret);
			CRYPT_EAL_PkeyFreeCtx(pubkey);
			return -1;
		}
		if (encode.dataLen > len) {
			lwsl_err("%s: output buffer too small, need=%u, have=%zu\n", __func__, encode.dataLen, len);
			BSL_SAL_Free(encode.data);
			CRYPT_EAL_PkeyFreeCtx(pubkey);
			return -1;
		}
		buf->ns.len = (int)encode.dataLen;
		memcpy(buf->ns.name, encode.data, encode.dataLen);
		BSL_SAL_Free(encode.data);
		CRYPT_EAL_PkeyFreeCtx(pubkey);
		return 0;

	case LWS_TLS_CERT_INFO_DER_RAW:
		ret = HITLS_X509_CertCtrl(x509, HITLS_X509_GET_ENCODELEN, &encode.dataLen, sizeof(encode.dataLen));
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_X509_GET_ENCODELEN failed, ret=0x%x\n", __func__, ret);
			return -1;
		}
		buf->ns.len = (int)encode.dataLen;
		if (encode.dataLen > len) {
			lwsl_err("%s: output buffer too small, need=%u, have=%zu\n", __func__, encode.dataLen, len);
			return -1;
		}
		ret = HITLS_X509_CertCtrl(x509, HITLS_X509_GET_ENCODE, &encode.data, 0);
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_X509_GET_ENCODE failed, ret=0x%x\n", __func__, ret);
			return -1;
		}
		memcpy(buf->ns.name, encode.data, encode.dataLen);
		return 0;

	case LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID:
		ret = HITLS_X509_CertCtrl(x509, HITLS_X509_EXT_GET_AKI, &aki, sizeof(HITLS_X509_ExtAki));
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_X509_EXT_GET_AKI failed, ret=0x%x\n", __func__, ret);
			return 1;
		}
		if (!aki.kid.data || aki.kid.dataLen == 0) {
			HITLS_X509_ClearAuthorityKeyId(&aki);
			return 1;
		}
		buf->ns.len = (int)aki.kid.dataLen;
		if (len < (size_t)buf->ns.len) {
			HITLS_X509_ClearAuthorityKeyId(&aki);
			return -1;
		}
		memcpy(buf->ns.name, aki.kid.data, (size_t)buf->ns.len);
		HITLS_X509_ClearAuthorityKeyId(&aki);
		return 0;

	case LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID_ISSUER: {
		HITLS_X509_GeneralName *name = NULL;
		HITLS_X509_GeneralName *tmp;
		int print_flag = HITLS_PKI_PRINT_DN_ONELINE;
		BSL_UIO *uio;

		ret = HITLS_X509_CertCtrl(x509, HITLS_X509_EXT_GET_AKI, &aki, sizeof(HITLS_X509_ExtAki));
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_X509_EXT_GET_AKI failed, ret=0x%x\n", __func__, ret);
			return 1;
		}
		for (tmp = BSL_LIST_GET_FIRST(aki.issuerName); tmp != NULL; tmp = BSL_LIST_GET_NEXT(aki.issuerName)) {
			if (tmp->type == HITLS_X509_GN_DNNAME) {
				name = tmp;
				break;
			}
		}
		if (name == NULL) {
			HITLS_X509_ClearAuthorityKeyId(&aki);
			return 1;
		}
		ret = HITLS_PKI_PrintCtrl(HITLS_PKI_SET_PRINT_FLAG, &print_flag, sizeof(print_flag), NULL);
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_PKI_SET_PRINT_FLAG failed, ret=0x%x\n", __func__, ret);
			HITLS_X509_ClearAuthorityKeyId(&aki);
			return -1;
		}
		uio = BSL_UIO_New(BSL_UIO_MemMethod());
		if (!uio) {
			lwsl_err("%s: BSL_UIO_New failed\n", __func__);
			HITLS_X509_ClearAuthorityKeyId(&aki);
			return -1;
		}
		ret = HITLS_PKI_PrintCtrl(HITLS_PKI_PRINT_DNNAME, (BslList *)(uintptr_t)name->value.data,
					  sizeof(BslList), uio);
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_PKI_PRINT_DNNAME failed, ret=0x%x\n", __func__, ret);
			BSL_UIO_Free(uio);
			HITLS_X509_ClearAuthorityKeyId(&aki);
			return -1;
		}
		ret = BSL_UIO_Read(uio, buf->ns.name, (uint32_t)len, (uint32_t *)(void *)&buf->ns.len);
		if (ret != BSL_SUCCESS) {
			lwsl_err("%s: BSL_UIO_Read failed, ret=0x%x\n", __func__, ret);
			BSL_UIO_Free(uio);
			HITLS_X509_ClearAuthorityKeyId(&aki);
			return -1;
		}
		BSL_UIO_Free(uio);
		HITLS_X509_ClearAuthorityKeyId(&aki);
		return 0;
	}

	case LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID_SERIAL:
		ret = HITLS_X509_CertCtrl(x509, HITLS_X509_EXT_GET_AKI, &aki, sizeof(HITLS_X509_ExtAki));
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_X509_EXT_GET_AKI failed, ret=0x%x\n", __func__, ret);
			return 1;
		}
		if (!aki.serialNum.data || aki.serialNum.dataLen == 0) {
			HITLS_X509_ClearAuthorityKeyId(&aki);
			return 1;
		}
		buf->ns.len = (int)aki.serialNum.dataLen;
		if (len < (size_t)buf->ns.len) {
			HITLS_X509_ClearAuthorityKeyId(&aki);
			return -1;
		}
		memcpy(buf->ns.name, aki.serialNum.data, (size_t)buf->ns.len);
		HITLS_X509_ClearAuthorityKeyId(&aki);
		return 0;

	case LWS_TLS_CERT_INFO_SUBJECT_KEY_ID:
		ret = HITLS_X509_CertCtrl(x509, HITLS_X509_EXT_GET_SKI, &ski, sizeof(HITLS_X509_ExtSki));
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_X509_EXT_GET_SKI failed, ret=0x%x\n", __func__, ret);
			return 1;
		}
		if (!ski.kid.data || ski.kid.dataLen == 0)
			return 1;
		buf->ns.len = (int)ski.kid.dataLen;
		if (len < (size_t)buf->ns.len)
			return -1;
		memcpy(buf->ns.name, ski.kid.data, (size_t)buf->ns.len);
		return 0;

	default:
		return -1;
	}

	return 0;
}

int
lws_x509_info(struct lws_x509_cert *x509, enum lws_tls_cert_info type,
	      union lws_tls_cert_info_results *buf, size_t len)
{
	return lws_tls_openhitls_cert_info(x509->cert, type, buf, len);
}

#if defined(LWS_WITH_NETWORK)
int
lws_tls_vhost_cert_info(struct lws_vhost *vhost, enum lws_tls_cert_info type,
		        union lws_tls_cert_info_results *buf, size_t len)
{
	/* TODO: Implement when TLS context management is available */
	lwsl_notice("%s: not yet implemented\n", __func__);
	return -1;
}

int
lws_tls_peer_cert_info(struct lws *wsi, enum lws_tls_cert_info type, union lws_tls_cert_info_results *buf, size_t len)
{
	HITLS_CERT_X509 *peer_cert;
	HITLS_ERROR verify_result = HITLS_X509_V_OK;
	int ret = -1;

	wsi = lws_get_network_wsi(wsi);

	if (!wsi || !wsi->tls.ssl)
		return -1;

	peer_cert = HITLS_GetPeerCertificate(wsi->tls.ssl);
	if (!peer_cert) {
		lwsl_debug("%s: no peer cert\n", __func__);
		return -1;
	}

	switch (type) {
	case LWS_TLS_CERT_INFO_VERIFIED:
		if (HITLS_GetVerifyResult(wsi->tls.ssl, &verify_result) != HITLS_SUCCESS) {
			ret = -1;
			break;
		}

		buf->verified = verify_result == HITLS_X509_V_OK;
		ret = 0;
		break;

	default:
		ret = lws_tls_openhitls_cert_info((HITLS_X509_Cert *)peer_cert, type, buf, len);
		break;
	}

	HITLS_X509_CertFree((HITLS_X509_Cert *)peer_cert);

	return ret;
}
#endif

int
lws_x509_create(struct lws_x509_cert **x509)
{
	*x509 = lws_malloc(sizeof(**x509), __func__);
	if (*x509)
		(*x509)->cert = NULL;
	return !(*x509);
}

int
lws_x509_parse_from_pem(struct lws_x509_cert *x509, const void *pem, size_t len)
{
	BSL_Buffer buf;
	int32_t ret;
	buf.data = (uint8_t *)pem;
	buf.dataLen = (uint32_t)len;

	ret = HITLS_X509_CertParseBuff(BSL_FORMAT_PEM, &buf, &x509->cert);
	if (ret != HITLS_PKI_SUCCESS) {
		lwsl_err("%s: HITLS_X509_CertParseBuff failed, ret=0x%x\n", __func__, ret);
		return -1;
	}
	return 0;
}

void
lws_x509_destroy(struct lws_x509_cert **x509)
{
	if (!*x509)
		return;
	if ((*x509)->cert) {
		HITLS_X509_CertFree((*x509)->cert);
		(*x509)->cert = NULL;
	}
	lws_free_set_NULL(*x509);
}

int
lws_x509_create_self_signed(struct lws_context *context, uint8_t **cert_buf, size_t *cert_len,
			    uint8_t **key_buf, size_t *key_len, const char *san, int key_bits)
{
	CRYPT_EAL_PkeyCtx *pkey = NULL;
	HITLS_X509_Cert *cert = NULL;
	HITLS_X509_DN dn_name;
	HITLS_X509_ExtBCons bcons = {true, false, -1};
	HITLS_X509_ExtKeyUsage key_usage = {true, HITLS_X509_EXT_KU_DIGITAL_SIGN};
	HITLS_X509_ExtExKeyUsage exku = {false, NULL};
	HITLS_X509_ExtSki ski = {false, {0}};
	HITLS_X509_ExtAki aki = {false, {0}, NULL, {0}};
	BslList *dn = NULL;
	BSL_Buffer cert_der = {0}, key_der = {0};
	BSL_TIME before = {0}, after = {0};
	const char *cn;
	int32_t version = HITLS_X509_VERSION_3;
	int32_t ret32;
	int64_t now, before_utc, after_utc;
	uint8_t serial[8];
	int n;
	int ret = 1;
	(void)context;
	(void)key_bits;
	if (!cert_buf || !cert_len || !key_buf || !key_len)
		return 1;
	*cert_buf = NULL;
	*key_buf = NULL;
	*cert_len = 0;
	*key_len = 0;
	cn = (san && *san) ? san : "localhost";

	ret32 = CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);
	if (ret32 != CRYPT_SUCCESS && ret32 != CRYPT_EAL_ERR_DRBG_REPEAT_INIT) {
		lwsl_err("%s: CRYPT_EAL_RandInit(SHA256) failed, ret=0x%x\n", __func__, ret32);
		goto bail;
	}
	pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA);
	if (!pkey) {
		lwsl_err("%s: key context creation failed\n", __func__);
		goto bail;
	}
	ret32 = CRYPT_EAL_PkeySetParaById(pkey, CRYPT_ECC_NISTP256);
	if (ret32 == CRYPT_SUCCESS)
		ret32 = CRYPT_EAL_PkeyGen(pkey);
	if (ret32 != CRYPT_SUCCESS) {
		lwsl_err("%s: EC P-256 key generation failed, ret=0x%x\n", __func__, ret32);
		goto bail;
	}
	cert = HITLS_X509_CertNew();
	if (!cert) {
		lwsl_err("%s: HITLS_X509_CertNew failed\n", __func__);
		goto bail;
	}

	ret32 = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version, sizeof(version));
	if (ret32 != HITLS_PKI_SUCCESS) {
		lwsl_err("%s: HITLS_X509_SET_VERSION failed, ret=0x%x\n", __func__, ret32);
		goto bail;
	}

	ret32 = CRYPT_EAL_Randbytes(serial, sizeof(serial));
	if (ret32 != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_Randbytes failed, ret=0x%x\n", __func__, ret32);
		goto bail;
	}
	serial[0] &= 0x7f; /* Force positive ASN.1 INTEGER serial. */
	for (n = 0; n < (int)sizeof(serial); n++)
		if (serial[n])
			break;
	if (n == (int)sizeof(serial))
		serial[sizeof(serial) - 1] = 1;
	ret32 = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SERIALNUM, serial, sizeof(serial));
	if (ret32 != HITLS_PKI_SUCCESS) {
		lwsl_err("%s: HITLS_X509_SET_SERIALNUM failed, ret=0x%x\n", __func__, ret32);
		goto bail;
	}

	now = BSL_SAL_CurrentSysTimeGet();
	if (now <= 0) {
		lwsl_err("%s: BSL_SAL_CurrentSysTimeGet failed\n", __func__);
		goto bail;
	}
	before_utc = now > 86400 ? now - 86400 : 0;
	after_utc = now + 31536000;
	if (BSL_SAL_UtcTimeToDateConvert(before_utc, &before) != BSL_SUCCESS ||
	    BSL_SAL_UtcTimeToDateConvert(after_utc, &after) != BSL_SUCCESS) {
		lwsl_err("%s: time conversion failed\n", __func__);
		goto bail;
	}
	ret32 = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_BEFORE_TIME, &before, sizeof(before));
	if (ret32 != HITLS_PKI_SUCCESS) {
		lwsl_err("%s: HITLS_X509_SET_BEFORE_TIME failed, ret=0x%x\n", __func__, ret32);
		goto bail;
	}
	ret32 = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_AFTER_TIME, &after, sizeof(after));
	if (ret32 != HITLS_PKI_SUCCESS) {
		lwsl_err("%s: HITLS_X509_SET_AFTER_TIME failed, ret=0x%x\n", __func__, ret32);
		goto bail;
	}

	ret32 = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_PUBKEY, pkey, 0);
	if (ret32 != HITLS_PKI_SUCCESS) {
		lwsl_err("%s: HITLS_X509_SET_PUBKEY failed, ret=0x%x\n", __func__, ret32);
		goto bail;
	}

	dn = HITLS_X509_DnListNew();
	if (!dn) {
		lwsl_err("%s: HITLS_X509_DnListNew failed\n", __func__);
		goto bail;
	}
	dn_name.cid = BSL_CID_AT_COMMONNAME;
	dn_name.data = (uint8_t *)(uintptr_t)cn;
	dn_name.dataLen = (uint32_t)strlen(cn);
	ret32 = HITLS_X509_AddDnName(dn, &dn_name, 1);
	if (ret32 != HITLS_PKI_SUCCESS) {
		lwsl_err("%s: HITLS_X509_AddDnName failed, ret=0x%x\n", __func__, ret32);
		goto bail;
	}
	ret32 = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SUBJECT_DN, dn, sizeof(BslList));
	if (ret32 != HITLS_PKI_SUCCESS) {
		lwsl_err("%s: HITLS_X509_SET_SUBJECT_DN failed, ret=0x%x\n", __func__, ret32);
		goto bail;
	}
	ret32 = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_ISSUER_DN, dn, sizeof(BslList));
	if (ret32 != HITLS_PKI_SUCCESS) {
		lwsl_err("%s: HITLS_X509_SET_ISSUER_DN failed, ret=0x%x\n", __func__, ret32);
		goto bail;
	}
	HITLS_X509_DnListFree(dn);
	dn = NULL;

	ret32 = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_BCONS, &bcons, sizeof(bcons));
	if (ret32 != HITLS_PKI_SUCCESS) {
		lwsl_err("%s: HITLS_X509_EXT_SET_BCONS failed, ret=0x%x\n", __func__, ret32);
		goto bail;
	}

	ret32 = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_KUSAGE, &key_usage, sizeof(key_usage));
	if (ret32 != HITLS_PKI_SUCCESS) {
		lwsl_err("%s: HITLS_X509_EXT_SET_KUSAGE failed, ret=0x%x\n", __func__, ret32);
		goto bail;
	}

	exku.oidList = BSL_LIST_New(sizeof(BSL_Buffer));
	if (!exku.oidList) {
		lwsl_err("%s: BSL_LIST_New for EKU failed\n", __func__);
		goto bail;
	}
	if (lws_tls_openhitls_add_eku_oid(exku.oidList, BSL_CID_KP_SERVERAUTH) ||
	    lws_tls_openhitls_add_eku_oid(exku.oidList, BSL_CID_KP_CLIENTAUTH)) {
		lwsl_err("%s: add EKU OID failed\n", __func__);
		goto bail;
	}
	ret32 = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_EXKUSAGE, &exku, sizeof(exku));
	if (ret32 != HITLS_PKI_SUCCESS) {
		lwsl_err("%s: HITLS_X509_EXT_SET_EXKUSAGE failed, ret=0x%x\n", __func__, ret32);
		goto bail;
	}
	BSL_LIST_FREE(exku.oidList, NULL);
	exku.oidList = NULL;

	if (lws_tls_openhitls_set_san(cert, san)) {
		lwsl_err("%s: setting SAN failed\n", __func__);
		goto bail;
	}

	if (lws_tls_openhitls_get_ski(cert, &ski.kid)) {
		lwsl_err("%s: get SKI failed\n", __func__);
		goto bail;
	}
	ret32 = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_SKI, &ski, sizeof(ski));
	if (ret32 != HITLS_PKI_SUCCESS) {
		lwsl_err("%s: HITLS_X509_EXT_SET_SKI failed, ret=0x%x\n", __func__, ret32);
		goto bail;
	}
	aki.kid = ski.kid; /* keyid:always for self-signed cert */
	ret32 = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_AKI, &aki, sizeof(aki));
	if (ret32 != HITLS_PKI_SUCCESS) {
		lwsl_err("%s: HITLS_X509_EXT_SET_AKI failed, ret=0x%x\n", __func__, ret32);
		goto bail;
	}
	BSL_SAL_Free(ski.kid.data);
	ski.kid.data = NULL;

	ret32 = HITLS_X509_CertSign(CRYPT_MD_SHA256, pkey, NULL, cert);
	if (ret32 != HITLS_PKI_SUCCESS) {
		lwsl_err("%s: HITLS_X509_CertSign failed, ret=0x%x\n", __func__, ret32);
		goto bail;
	}

	ret32 = HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, cert, &cert_der);
	if (ret32 != HITLS_PKI_SUCCESS) {
		lwsl_err("%s: HITLS_X509_CertGenBuff failed, ret=0x%x\n", __func__, ret32);
		goto bail;
	}
	*cert_buf = malloc((size_t)cert_der.dataLen);
	if (!*cert_buf)
		goto bail;
	memcpy(*cert_buf, cert_der.data, cert_der.dataLen);
	*cert_len = (size_t)cert_der.dataLen;

	ret32 = CRYPT_EAL_EncodeBuffKey(pkey, NULL, BSL_FORMAT_ASN1, CRYPT_PRIKEY_ECC, &key_der);
	if (ret32 != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_EncodeBuffKey failed, ret=0x%x\n", __func__, ret32);
		goto bail;
	}
	*key_buf = malloc((size_t)key_der.dataLen);
	if (!*key_buf)
		goto bail;
	memcpy(*key_buf, key_der.data, key_der.dataLen);
	*key_len = (size_t)key_der.dataLen;

	ret = 0;
bail:
	if (ret) {
		free(*cert_buf);
		free(*key_buf);
		*cert_buf = NULL;
		*key_buf = NULL;
		*cert_len = 0;
		*key_len = 0;
	}
	if (dn)
		HITLS_X509_DnListFree(dn);
	if (exku.oidList)
		BSL_LIST_FREE(exku.oidList, NULL);
	if (ski.kid.data)
		BSL_SAL_Free(ski.kid.data);
	if (cert_der.data)
		BSL_SAL_Free(cert_der.data);
	if (key_der.data)
		BSL_SAL_Free(key_der.data);
	if (cert)
		HITLS_X509_CertFree(cert);
	if (pkey)
		CRYPT_EAL_PkeyFreeCtx(pkey);

	return ret;
}

int
lws_x509_verify(struct lws_x509_cert *x509, struct lws_x509_cert *trusted, const char *common_name)
{
	HITLS_X509_StoreCtx *store_ctx = NULL;
	HITLS_X509_List *chain = NULL;
	BSL_Buffer encode = {0};
	int32_t ret;

	if (!x509 || !x509->cert || !trusted || !trusted->cert)
		return -1;
	if (common_name) {
		ret = HITLS_X509_CertCtrl(x509->cert, HITLS_X509_GET_SUBJECT_CN_STR, &encode, sizeof(BSL_Buffer));
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_X509_GET_SUBJECT_CN_STR failed, ret=0x%x\n", __func__, ret);
			return -1;
		}
		if (encode.dataLen != strlen(common_name) || memcmp(encode.data, common_name, encode.dataLen)) {
			lwsl_err("%s: common name mismatch\n", __func__);
			BSL_SAL_Free(encode.data);
			return -1;
		}
		BSL_SAL_Free(encode.data);
	}
	store_ctx = HITLS_X509_StoreCtxNew();
	if (!store_ctx) {
		lwsl_err("%s: failed to create store context\n", __func__);
		return -1;
	}
	ret = HITLS_X509_StoreCtxCtrl(store_ctx, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, trusted->cert, 0);
	if (ret != HITLS_PKI_SUCCESS) {
		lwsl_err("%s: HITLS_X509_StoreCtxCtrl(SET_CA) failed, ret=0x%x\n", __func__, ret);
		HITLS_X509_StoreCtxFree(store_ctx);
		return -1;
	}
	ret = HITLS_X509_CertChainBuild(store_ctx, false, x509->cert, &chain);
	if (ret != BSL_SUCCESS) {
		lwsl_err("%s: HITLS_X509_CertChainBuild failed, ret=0x%x\n", __func__, ret);
		BSL_LIST_FREE(chain, NULL);
		HITLS_X509_StoreCtxFree(store_ctx);
		return -1;
	}
	ret = HITLS_X509_CertVerify(store_ctx, chain);
	HITLS_X509_StoreCtxFree(store_ctx);
	BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
	if (ret != HITLS_PKI_SUCCESS) {
		lwsl_err("%s: HITLS_X509_CertVerify failed, ret=0x%x\n", __func__, ret);
		return -1;
	}
	return 0;
}

#if defined(LWS_WITH_JOSE)
int
lws_x509_public_to_jwk(struct lws_jwk *jwk, struct lws_x509_cert *x509, const char *curves, int rsa_min_bits)
{
	CRYPT_EAL_PkeyCtx *pubkey = NULL;
	uint8_t *tmp_buf = NULL;
	uint32_t key_bytes, coord_len;
	int ret = -1;
	if (!jwk || !x509 || !x509->cert)
		return -1;
	memset(jwk, 0, sizeof(*jwk));
	ret = HITLS_X509_CertCtrl(x509->cert, HITLS_X509_GET_PUBKEY, &pubkey, sizeof(CRYPT_EAL_PkeyCtx *));
	if (ret != HITLS_PKI_SUCCESS) {
		lwsl_err("%s: HITLS_X509_GET_PUBKEY failed, ret=0x%x\n", __func__, ret);
		return -1;
	}

	CRYPT_PKEY_AlgId alg_id = CRYPT_EAL_PkeyGetId(pubkey);
	if (alg_id == CRYPT_PKEY_RSA) {
		CRYPT_EAL_PkeyPub rsa_pub = {0};
		uint8_t *n_buf = NULL, *e_buf = NULL;

		key_bytes = CRYPT_EAL_PkeyGetKeyLen(pubkey);
		if ((int)(key_bytes * 8) < rsa_min_bits) {
			lwsl_err("%s: RSA key too small (%u < %d)\n", __func__, key_bytes * 8, rsa_min_bits);
			goto bail1;
		}
		n_buf = lws_malloc(key_bytes, "jwk-rsa-n");
		e_buf = lws_malloc(key_bytes, "jwk-rsa-e");
		if (!n_buf || !e_buf) {
			lws_free(n_buf);
			lws_free(e_buf);
			goto bail1;
		}
		rsa_pub.id = CRYPT_PKEY_RSA;
		rsa_pub.key.rsaPub.n = n_buf;
		rsa_pub.key.rsaPub.nLen = key_bytes;
		rsa_pub.key.rsaPub.e = e_buf;
		rsa_pub.key.rsaPub.eLen = key_bytes;
		/* CRYPT_EAL_PkeyGetPub will fill in the actual lengths of n and e, which may be less than key_bytes */
		ret = CRYPT_EAL_PkeyGetPub(pubkey, &rsa_pub);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CRYPT_EAL_PkeyGetPub failed for RSA, ret=0x%x\n", __func__, ret);
			lws_free(n_buf);
			lws_free(e_buf);
			goto bail1;
		}
		jwk->kty = LWS_GENCRYPTO_KTY_RSA;
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].len = rsa_pub.key.rsaPub.nLen;
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].buf = lws_malloc(rsa_pub.key.rsaPub.nLen, "certkeyimp");
		if (!jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].buf) {
			lws_free(n_buf);
			lws_free(e_buf);
			goto bail1;
		}
		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].buf, rsa_pub.key.rsaPub.n, rsa_pub.key.rsaPub.nLen);
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].len = rsa_pub.key.rsaPub.eLen;
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf = lws_malloc(rsa_pub.key.rsaPub.eLen, "certkeyimp");
		if (!jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf) {
			lws_free(n_buf);
			lws_free(e_buf);
			goto bail2;
		}
		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf, rsa_pub.key.rsaPub.e, rsa_pub.key.rsaPub.eLen);
		lws_free(n_buf);
		lws_free(e_buf);
		ret = 0;
	} else if (alg_id == CRYPT_PKEY_ECDSA) {
		CRYPT_EAL_PkeyPub ecc_pub = {0};
		CRYPT_PKEY_ParaId curve_id;
		uint32_t pub_len;
		const struct lws_ec_curves *curve;

		if (!curves) {
			lwsl_err("%s: ec curves not allowed\n", __func__);
			goto bail1;
		}
		curve_id = CRYPT_EAL_PkeyGetParaId(pubkey);
		if (lws_genec_confirm_curve_allowed_by_tls_id(curves, curve_id, jwk)) {
			goto bail1;
		}
		curve = lws_genec_curve(lws_ec_curves, (char *)jwk->e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf);
		if (!curve) {
			lwsl_err("%s: curve not found\n", __func__);
			goto bail1;
		}
		coord_len = curve->key_bytes;
		pub_len = 1 + 2 * coord_len;
		tmp_buf = lws_malloc(pub_len, "jwk-ecc-pub");
		if (!tmp_buf)
			goto bail1;
		ecc_pub.id = CRYPT_PKEY_ECDSA;
		ecc_pub.key.eccPub.data = tmp_buf;
		ecc_pub.key.eccPub.len = pub_len;
		ret = CRYPT_EAL_PkeyGetPub(pubkey, &ecc_pub);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CRYPT_EAL_PkeyGetPub failed for EC, ret=0x%x\n", __func__, ret);
			lws_free(tmp_buf);
			goto bail1;
		}
		if (ecc_pub.key.eccPub.len != pub_len || ecc_pub.key.eccPub.data[0] != 0x04) {
			lwsl_err("%s: invalid EC public key format\n", __func__);
			lws_free(tmp_buf);
			goto bail1;
		}
		jwk->kty = LWS_GENCRYPTO_KTY_EC;
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].len = coord_len;
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf = lws_malloc(coord_len, "certkeyimp");
		if (!jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf) {
			lws_free(tmp_buf);
			goto bail1;
		}
		memcpy(jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf, ecc_pub.key.eccPub.data + 1, coord_len);
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].len = coord_len;
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf = lws_malloc(coord_len, "certkeyimp");
		if (!jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf) {
			lws_free(tmp_buf);
			goto bail2;
		}
		memcpy(jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf, ecc_pub.key.eccPub.data + 1 + coord_len, coord_len);
		lws_free(tmp_buf);
		ret = 0;
	} else {
		lwsl_err("%s: unsupported key type %d\n", __func__, alg_id);
		goto bail1;
	}
	CRYPT_EAL_PkeyFreeCtx(pubkey);
	return ret;
bail2:
	lws_jwk_destroy(jwk);
bail1:
	CRYPT_EAL_PkeyFreeCtx(pubkey);
	return -1;
}

int
lws_x509_jwk_privkey_pem(struct lws_context *cx, struct lws_jwk *jwk, void *pem, size_t len, const char *passphrase)
{
	CRYPT_EAL_PkeyCtx *pkey = NULL;
	CRYPT_EAL_PkeyPrv prv = {0};
	BSL_Buffer pem_buf, pwd_buf = {0};
	uint8_t *tmp_n = NULL, *tmp_e = NULL, *tmp_d = NULL;
	uint8_t *tmp_p = NULL, *tmp_q = NULL;
	uint8_t *tmp_ec_d = NULL;
	uint32_t key_bytes;
	int result = -1;
	int32_t ret;

	if (!jwk || !pem || !len)
		return -1;
	pem_buf.data = (uint8_t *)pem;
	pem_buf.dataLen = (uint32_t)len;
	if (passphrase) {
		pwd_buf.data = (uint8_t *)passphrase;
		pwd_buf.dataLen = (uint32_t)strlen(passphrase);
	}
	ret = CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM, CRYPT_ENCDEC_UNKNOW, &pem_buf, pwd_buf.data, pwd_buf.dataLen, &pkey);
	lws_explicit_bzero(pem, len);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: failed to parse PEM private key, ret=0x%x\n", __func__, ret);
		goto bail;
	}

	CRYPT_PKEY_AlgId alg_id = CRYPT_EAL_PkeyGetId(pkey);
	if (jwk->kty == LWS_GENCRYPTO_KTY_EC) {
		if (alg_id != CRYPT_PKEY_ECDSA) {
			lwsl_err("%s: jwk is EC but privkey is %d\n", __func__, alg_id);
			goto bail;
		}
		uint32_t coord_len = jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].len;
		if (coord_len == 0) {
			lwsl_err("%s: JWK EC Y coordinate length is 0\n", __func__);
			goto bail;
		}
		tmp_ec_d = lws_malloc(coord_len, "jwk-ec-d");
		if (!tmp_ec_d)
			goto bail;
		prv.id = CRYPT_PKEY_ECDSA;
		prv.key.eccPrv.data = tmp_ec_d;
		prv.key.eccPrv.len = coord_len;
		ret = CRYPT_EAL_PkeyGetPrv(pkey, &prv);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: failed to extract EC private key, ret=0x%x\n", __func__, ret);
			goto bail;
		}
		if (prv.key.eccPrv.len < coord_len) {
			uint32_t pad_len = coord_len - prv.key.eccPrv.len;
			memmove(tmp_ec_d + pad_len, tmp_ec_d, prv.key.eccPrv.len);
			memset(tmp_ec_d, 0, pad_len);
		}
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_D].buf = tmp_ec_d;
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_D].len = coord_len;
		tmp_ec_d = NULL;
	} else if (jwk->kty == LWS_GENCRYPTO_KTY_RSA) {
		if (alg_id != CRYPT_PKEY_RSA) {
			lwsl_err("%s: RSA jwk, non-RSA privkey %d\n", __func__, alg_id);
			goto bail;
		}
		key_bytes = CRYPT_EAL_PkeyGetKeyLen(pkey);
		if (key_bytes == 0) {
			lwsl_err("%s: failed to get RSA key length\n", __func__);
			goto bail;
		}
		tmp_n = lws_malloc(key_bytes, "jwk-rsa-n");
		tmp_e = lws_malloc(key_bytes, "jwk-rsa-e");
		tmp_d = lws_malloc(key_bytes, "jwk-rsa-d");
		tmp_p = lws_malloc(key_bytes, "jwk-rsa-p");
		tmp_q = lws_malloc(key_bytes, "jwk-rsa-q");
		if (!tmp_n || !tmp_e || !tmp_d || !tmp_p || !tmp_q)
			goto bail;
		prv.id = CRYPT_PKEY_RSA;
		prv.key.rsaPrv.n = tmp_n;
		prv.key.rsaPrv.nLen = key_bytes;
		prv.key.rsaPrv.e = tmp_e;
		prv.key.rsaPrv.eLen = key_bytes;
		prv.key.rsaPrv.d = tmp_d;
		prv.key.rsaPrv.dLen = key_bytes;
		prv.key.rsaPrv.p = tmp_p;
		prv.key.rsaPrv.pLen = key_bytes;
		prv.key.rsaPrv.q = tmp_q;
		prv.key.rsaPrv.qLen = key_bytes;

		ret = CRYPT_EAL_PkeyGetPrv(pkey, &prv);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: failed to extract RSA private key, ret=0x%x\n", __func__, ret);
			goto bail;
		}
		if (prv.key.rsaPrv.nLen != jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].len ||
		    memcmp(prv.key.rsaPrv.n, jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].buf,
			   prv.key.rsaPrv.nLen)) {
			lwsl_err("%s: RSA privkey n doesn't match jwk pubkey\n", __func__);
			goto bail;
		}
		if (prv.key.rsaPrv.eLen != jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].len ||
		    memcmp(prv.key.rsaPrv.e, jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf,
			   prv.key.rsaPrv.eLen)) {
			lwsl_err("%s: RSA privkey e doesn't match jwk pubkey\n", __func__);
			goto bail;
		}
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].buf = lws_malloc(prv.key.rsaPrv.dLen, "jwk-d");
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].buf = lws_malloc(prv.key.rsaPrv.pLen, "jwk-p");
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].buf = lws_malloc(prv.key.rsaPrv.qLen, "jwk-q");
		if (!jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].buf ||
		    !jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].buf ||
		    !jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].buf) {
			lws_free(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].buf);
			lws_free(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].buf);
			lws_free(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].buf);
			jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].buf = NULL;
			jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].buf = NULL;
			jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].buf = NULL;
			goto bail;
		}

		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].buf, prv.key.rsaPrv.d, prv.key.rsaPrv.dLen);
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].len = prv.key.rsaPrv.dLen;
		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].buf, prv.key.rsaPrv.p, prv.key.rsaPrv.pLen);
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].len = prv.key.rsaPrv.pLen;
		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].buf, prv.key.rsaPrv.q, prv.key.rsaPrv.qLen);
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].len = prv.key.rsaPrv.qLen;
	} else {
		lwsl_err("%s: unknown JWK kty %d\n", __func__, jwk->kty);
		goto bail;
	}
	result = 0;
bail:
	if (pkey)
		CRYPT_EAL_PkeyFreeCtx(pkey);
	lws_free(tmp_ec_d);
	lws_free(tmp_n);
	lws_free(tmp_e);
	lws_free(tmp_d);
	lws_free(tmp_p);
	lws_free(tmp_q);
	return result;
}
#endif
