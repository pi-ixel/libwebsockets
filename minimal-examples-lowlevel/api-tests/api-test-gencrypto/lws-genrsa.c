/*
 * lws-api-test-gencrypto - lws-genrsa
 *
 * Written in 2010-2018 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

 #include <libwebsockets.h>
 #include <stdlib.h>
 
 static int
 test_genrsa_roundtrips(struct lws_context *context)
 {
	 static const uint8_t priv_plain[] = "private encrypt roundtrip";
	 static const uint8_t pub_plain[] = "public encrypt roundtrip";
	 struct lws_genrsa_ctx priv_ctx, pub_ctx;
	 struct lws_gencrypto_keyelem el[LWS_GENCRYPTO_RSA_KEYEL_COUNT];
	 struct lws_gencrypto_keyelem pub_el[LWS_GENCRYPTO_RSA_KEYEL_COUNT];
	 uint8_t *cipher = NULL, *plain = NULL;
	 size_t key_bytes;
	 int n;
	 int ret = 1;
 
	 memset(&priv_ctx, 0, sizeof(priv_ctx));
	 memset(&pub_ctx, 0, sizeof(pub_ctx));
	 memset(el, 0, sizeof(el));
	 memset(pub_el, 0, sizeof(pub_el));
 
	 if (lws_genrsa_new_keypair(context, &priv_ctx, LGRSAM_PKCS1_1_5, el,
					2048)) {
		 lwsl_err("%s: lws_genrsa_new_keypair failed\n", __func__);
		 goto bail;
	 }
 
	 pub_el[LWS_GENCRYPTO_RSA_KEYEL_E] = el[LWS_GENCRYPTO_RSA_KEYEL_E];
	 pub_el[LWS_GENCRYPTO_RSA_KEYEL_N] = el[LWS_GENCRYPTO_RSA_KEYEL_N];
 
	 if (lws_genrsa_create(&pub_ctx, pub_el, context, LGRSAM_PKCS1_1_5,
				   LWS_GENHASH_TYPE_UNKNOWN)) {
		 lwsl_err("%s: lws_genrsa_create public ctx failed\n", __func__);
		 goto bail;
	 }
 
	 key_bytes = el[LWS_GENCRYPTO_RSA_KEYEL_N].len;
	 cipher = malloc(key_bytes);
	 plain = malloc(key_bytes);
	 if (!cipher || !plain) {
		 lwsl_err("%s: OOM allocating test buffers\n", __func__);
		 goto bail;
	 }
 
	 n = lws_genrsa_private_encrypt(&priv_ctx, priv_plain,
						sizeof(priv_plain) - 1, cipher);
	 if (n < 0) {
		 lwsl_err("%s: lws_genrsa_private_encrypt failed\n", __func__);
		 goto bail;
	 }
 
	 n = lws_genrsa_public_decrypt(&pub_ctx, cipher, (size_t)n, plain,
					   key_bytes);
	 if (n != (int)(sizeof(priv_plain) - 1) ||
		 lws_timingsafe_bcmp(plain, priv_plain, sizeof(priv_plain) - 1)) {
		 lwsl_err("%s: private->public roundtrip mismatch\n", __func__);
		 goto bail;
	 }
 
	 n = lws_genrsa_public_encrypt(&pub_ctx, pub_plain, sizeof(pub_plain) - 1,
					   cipher);
	 if (n < 0) {
		 lwsl_err("%s: lws_genrsa_public_encrypt failed\n", __func__);
		 goto bail;
	 }
 
	 n = lws_genrsa_private_decrypt(&priv_ctx, cipher, (size_t)n, plain,
						key_bytes);
	 if (n != (int)(sizeof(pub_plain) - 1) ||
		 lws_timingsafe_bcmp(plain, pub_plain, sizeof(pub_plain) - 1)) {
		 lwsl_err("%s: public->private roundtrip mismatch\n", __func__);
		 goto bail;
	 }
 
	 ret = 0;
 
 bail:
	 if (cipher)
		 free(cipher);
	 if (plain)
		 free(plain);
	 lws_genrsa_destroy(&pub_ctx);
	 lws_genrsa_destroy(&priv_ctx);
	 lws_genrsa_destroy_elements(el);
 
	 return ret;
 }
 
 int
 test_genrsa(struct lws_context *context)
 {
	 if (test_genrsa_roundtrips(context))
		 goto bail;
 
	 lwsl_notice("%s: selftest OK\n", __func__);
 
	 return 0;
 
 bail:
	 lwsl_err("%s: selftest failed ++++++++++++++++++++\n", __func__);
 
	 return 1;
 }
 

//  #include <libwebsockets.h>

// static int
// test_genrsa_contains_hash(const uint8_t *buf, size_t len, const uint8_t *hash,
// 			 size_t hash_len)
// {
// 	size_t n;

// 	if (hash_len > len)
// 		return 0;

// 	for (n = 0; n <= len - hash_len; n++)
// 		if (!lws_timingsafe_bcmp(buf + n, hash, hash_len))
// 			return 1;

// 	return 0;
// }

// static int
// test_genrsa_roundtrips(struct lws_context *context)
// {
// 	static const uint8_t pub_plain[] = "public encrypt roundtrip";
// 	static const uint8_t hash_sha256[32] = {
// 		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
// 		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
// 		0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
// 		0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f
// 	};
// 	struct lws_genrsa_ctx priv_ctx, pub_ctx;
// 	struct lws_gencrypto_keyelem el[LWS_GENCRYPTO_RSA_KEYEL_COUNT];
// 	struct lws_gencrypto_keyelem pub_el[LWS_GENCRYPTO_RSA_KEYEL_COUNT];
// 	uint8_t *cipher = NULL, *plain = NULL, *sig = NULL, *recovered = NULL;
// 	size_t key_bytes;
// 	int n;
// 	int ret = 1;

// 	memset(&priv_ctx, 0, sizeof(priv_ctx));
// 	memset(&pub_ctx, 0, sizeof(pub_ctx));
// 	memset(el, 0, sizeof(el));
// 	memset(pub_el, 0, sizeof(pub_el));

// 	if (lws_genrsa_new_keypair(context, &priv_ctx, LGRSAM_PKCS1_1_5, el,
// 				   2048)) {
// 		lwsl_err("%s: lws_genrsa_new_keypair failed\n", __func__);
// 		goto bail;
// 	}

// 	pub_el[LWS_GENCRYPTO_RSA_KEYEL_E] = el[LWS_GENCRYPTO_RSA_KEYEL_E];
// 	pub_el[LWS_GENCRYPTO_RSA_KEYEL_N] = el[LWS_GENCRYPTO_RSA_KEYEL_N];

// 	if (lws_genrsa_create(&pub_ctx, pub_el, context, LGRSAM_PKCS1_1_5,
// 			      LWS_GENHASH_TYPE_UNKNOWN)) {
// 		lwsl_err("%s: lws_genrsa_create public ctx failed\n", __func__);
// 		goto bail;
// 	}

// 	key_bytes = el[LWS_GENCRYPTO_RSA_KEYEL_N].len;
// 	cipher = lws_malloc(key_bytes, "genrsa-cipher");
// 	plain = lws_malloc(key_bytes, "genrsa-plain");
// 	sig = lws_malloc(key_bytes, "genrsa-sign");
// 	recovered = lws_malloc(key_bytes, "genrsa-recovered");
// 	if (!cipher || !plain || !sig || !recovered) {
// 		lwsl_err("%s: OOM allocating test buffers\n", __func__);
// 		goto bail;
// 	}

// 	n = lws_genrsa_public_encrypt(&pub_ctx, pub_plain, sizeof(pub_plain) - 1,
// 				      cipher);
// 	if (n < 0) {
// 		lwsl_err("%s: lws_genrsa_public_encrypt failed\n", __func__);
// 		goto bail;
// 	}

// 	n = lws_genrsa_private_decrypt(&priv_ctx, cipher, (size_t)n, plain,
// 				       key_bytes);
// 	if (n != (int)(sizeof(pub_plain) - 1) ||
// 	    lws_timingsafe_bcmp(plain, pub_plain, sizeof(pub_plain) - 1)) {
// 		lwsl_err("%s: public->private roundtrip mismatch\n", __func__);
// 		goto bail;
// 	}

// 	n = lws_genrsa_hash_sign(&priv_ctx, hash_sha256, LWS_GENHASH_TYPE_SHA256,
// 				 sig, key_bytes);
// 	if (n < 0) {
// 		lwsl_err("%s: lws_genrsa_hash_sign failed\n", __func__);
// 		goto bail;
// 	}

// 	n = lws_genrsa_public_decrypt(&pub_ctx, sig, (size_t)n, recovered,
// 				      key_bytes);
// 	if (n <= 0 ||
// 	    !test_genrsa_contains_hash(recovered, (size_t)n, hash_sha256,
// 				       sizeof(hash_sha256))) {
// 		lwsl_err("%s: public_decrypt did not recover signed hash\n",
// 			 __func__);
// 		goto bail;
// 	}

// #if !defined(LWS_WITH_OPENHITLS)
// 	{
// 		static const uint8_t priv_plain[] = "private encrypt roundtrip";

// 		n = lws_genrsa_private_encrypt(&priv_ctx, priv_plain,
// 					       sizeof(priv_plain) - 1, cipher);
// 		if (n < 0) {
// 			lwsl_err("%s: lws_genrsa_private_encrypt failed\n",
// 				 __func__);
// 			goto bail;
// 		}

// 		n = lws_genrsa_public_decrypt(&pub_ctx, cipher, (size_t)n, plain,
// 					      key_bytes);
// 		if (n != (int)(sizeof(priv_plain) - 1) ||
// 		    lws_timingsafe_bcmp(plain, priv_plain,
// 					sizeof(priv_plain) - 1)) {
// 			lwsl_err("%s: private->public roundtrip mismatch\n",
// 				 __func__);
// 			goto bail;
// 		}
// 	}
// #endif

// 	ret = 0;

// bail:
// 	if (cipher)
// 		lws_free(cipher);
// 	if (plain)
// 		lws_free(plain);
// 	if (sig)
// 		lws_free(sig);
// 	if (recovered)
// 		lws_free(recovered);
// 	lws_genrsa_destroy(&pub_ctx);
// 	lws_genrsa_destroy(&priv_ctx);
// 	lws_genrsa_destroy_elements(el);

// 	return ret;
// }

// int
// test_genrsa(struct lws_context *context)
// {
// 	if (test_genrsa_roundtrips(context))
// 		goto bail;

// 	lwsl_notice("%s: selftest OK\n", __func__);

// 	return 0;

// bail:
// 	lwsl_err("%s: selftest failed ++++++++++++++++++++\n", __func__);

// 	return 1;
// }