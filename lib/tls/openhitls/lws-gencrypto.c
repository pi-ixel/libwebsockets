/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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
 *  lws-gencrypto common code
 */

#include "private-lib-core.h"
#include "private.h"

CRYPT_MD_AlgId
lws_genhash_type_to_hitls_md_id(enum lws_genhash_types hash_type)
{
	switch (hash_type) {
	case LWS_GENHASH_TYPE_MD5:
		return CRYPT_MD_MD5;
	case LWS_GENHASH_TYPE_SHA1:
		return CRYPT_MD_SHA1;
	case LWS_GENHASH_TYPE_SHA256:
		return CRYPT_MD_SHA256;
	case LWS_GENHASH_TYPE_SHA384:
		return CRYPT_MD_SHA384;
	case LWS_GENHASH_TYPE_SHA512:
		return CRYPT_MD_SHA512;
	default:
		return CRYPT_MD_MAX;
	}
}

CRYPT_CIPHER_AlgId
lws_genaes_mode_to_hitls_cipher_id(enum enum_aes_modes mode, size_t keylen)
{
	size_t keybits = keylen * 8;

	switch (keybits) {
	case 128:
		switch (mode) {
		case LWS_GAESM_CBC:
			return CRYPT_CIPHER_AES128_CBC;
		case LWS_GAESM_CTR:
			return CRYPT_CIPHER_AES128_CTR;
		case LWS_GAESM_ECB:
			return CRYPT_CIPHER_AES128_ECB;
		case LWS_GAESM_GCM:
			return CRYPT_CIPHER_AES128_GCM;
		case LWS_GAESM_KW:
			return CRYPT_CIPHER_AES128_WRAP_PAD;
		default:
			return CRYPT_CIPHER_MAX;
		}
	case 192:
		switch (mode) {
		case LWS_GAESM_CBC:
			return CRYPT_CIPHER_AES192_CBC;
		case LWS_GAESM_CTR:
			return CRYPT_CIPHER_AES192_CTR;
		case LWS_GAESM_ECB:
			return CRYPT_CIPHER_AES192_ECB;
		case LWS_GAESM_GCM:
			return CRYPT_CIPHER_AES192_GCM;
		case LWS_GAESM_KW:
			return CRYPT_CIPHER_AES192_WRAP_PAD;
		default:
			return CRYPT_CIPHER_MAX;
		}
	case 256:
		switch (mode) {
		case LWS_GAESM_CBC:
			return CRYPT_CIPHER_AES256_CBC;
		case LWS_GAESM_CTR:
			return CRYPT_CIPHER_AES256_CTR;
		case LWS_GAESM_ECB:
			return CRYPT_CIPHER_AES256_ECB;
		case LWS_GAESM_GCM:
			return CRYPT_CIPHER_AES256_GCM;
		case LWS_GAESM_KW:
			return CRYPT_CIPHER_AES256_WRAP_PAD;
		default:
			return CRYPT_CIPHER_MAX;
		}
	case 512:
		if (mode == LWS_GAESM_XTS)
			return CRYPT_CIPHER_AES256_XTS;
		return CRYPT_CIPHER_MAX;
	default:
		return CRYPT_CIPHER_MAX;
	}
}

int32_t
lws_genrsa_padding_to_hitls(enum enum_genrsa_mode mode)
{
	switch (mode) {
	case LGRSAM_PKCS1_1_5:
		return CRYPT_RSAES_PKCSV15;
	case LGRSAM_PKCS1_OAEP_PSS:
		return CRYPT_EMSA_PSS;
	default:
		return CRYPT_RSAES_PKCSV15;
	}
}

/*
 * Convert EC curve name to OpenHiTLS CRYPT_PKEY_ParaId
 */
CRYPT_PKEY_ParaId
lws_genec_curve_to_hitls_para_id(const char *curve_name)
{
	if (curve_name == NULL)
		return CRYPT_PKEY_PARAID_MAX;

	if (strcmp(curve_name, "P-256") == 0)
		return CRYPT_ECC_NISTP256;
	else if (strcmp(curve_name, "P-384") == 0)
		return CRYPT_ECC_NISTP384;
	else if (strcmp(curve_name, "P-521") == 0)
		return CRYPT_ECC_NISTP521;

	return CRYPT_PKEY_PARAID_MAX;
}

/*
 * Get curve key bytes from curve name
 */
int
lws_genec_curve_key_bytes(const char *curve_name)
{
	if (curve_name == NULL)
		return -1;

	if (strcmp(curve_name, "P-256") == 0)
		return 32;
	else if (strcmp(curve_name, "P-384") == 0)
		return 48;
	else if (strcmp(curve_name, "P-521") == 0)
		return 66;

	return -1;
}
