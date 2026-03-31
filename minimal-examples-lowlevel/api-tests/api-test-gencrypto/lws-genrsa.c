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