//// SPDX-License-Identifier: MIT
//
//#include <stdlib.h>
//
//#include <kem_kyber.h>
//
//#if defined(OQS_ENABLE_KEM_kyber_768)
//
//OQS_KEM *OQS_KEM_kyber_768_new(void) {
//
//	OQS_KEM *kem = OQS_MEM_malloc(sizeof(OQS_KEM));
//	if (kem == NULL) {
//		return NULL;
//	}
//	kem->method_name = OQS_KEM_alg_kyber_768;
//	kem->alg_version = "https://github.com/pq-crystals/kyber/commit/28413dfbf523fdde181246451c2bd77199c0f7ff";
//
//	kem->claimed_nist_level = 3;
//	kem->ind_cca = true;
//
//	kem->length_public_key = OQS_KEM_kyber_768_length_public_key;
//	kem->length_secret_key = OQS_KEM_kyber_768_length_secret_key;
//	kem->length_ciphertext = OQS_KEM_kyber_768_length_ciphertext;
//	kem->length_shared_secret = OQS_KEM_kyber_768_length_shared_secret;
//	kem->length_keypair_seed = OQS_KEM_kyber_768_length_keypair_seed;
//
//	kem->keypair = OQS_KEM_kyber_768_keypair;
//	kem->keypair_derand = OQS_KEM_kyber_768_keypair_derand;
//	kem->encaps = OQS_KEM_kyber_768_encaps;
//	kem->decaps = OQS_KEM_kyber_768_decaps;
//
//	return kem;
//}
//
//extern int pqcrystals_kyber768_ref_keypair(uint8_t *pk, uint8_t *sk);
//extern int pqcrystals_kyber768_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
//extern int pqcrystals_kyber768_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
//
//#if defined(OQS_ENABLE_KEM_kyber_768_avx2)
//extern int pqcrystals_kyber768_avx2_keypair(uint8_t *pk, uint8_t *sk);
//extern int pqcrystals_kyber768_avx2_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
//extern int pqcrystals_kyber768_avx2_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
//#endif
//
//#if defined(OQS_ENABLE_KEM_kyber_768_aarch64)
//extern int PQCLEAN_KYBER768_AARCH64_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
//extern int PQCLEAN_KYBER768_AARCH64_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
//extern int PQCLEAN_KYBER768_AARCH64_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
//#endif
//
//#if defined(OQS_ENABLE_LIBJADE_KEM_kyber_768)
//extern int libjade_kyber768_ref_keypair(uint8_t *pk, uint8_t *sk);
//extern int libjade_kyber768_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
//extern int libjade_kyber768_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
//#endif
//
//#if defined(OQS_ENABLE_LIBJADE_KEM_kyber_768_avx2)
//extern int libjade_kyber768_avx2_keypair(uint8_t *pk, uint8_t *sk);
//extern int libjade_kyber768_avx2_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
//extern int libjade_kyber768_avx2_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
//#endif
//
//
//OQS_API OQS_STATUS OQS_KEM_kyber_768_keypair_derand(uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed) {
//	(void)public_key;
//	(void)secret_key;
//	(void)seed;
//	return OQS_ERROR;
//}
//
//OQS_API OQS_STATUS OQS_KEM_kyber_768_keypair(uint8_t *public_key, uint8_t *secret_key) {
//#if defined(OQS_LIBJADE_BUILD) && (defined(OQS_ENABLE_LIBJADE_KEM_kyber_768))
//#if defined(OQS_ENABLE_LIBJADE_KEM_kyber_768_avx2)
//#if defined(OQS_DIST_BUILD)
//	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
//#endif /* OQS_DIST_BUILD */
//		return (OQS_STATUS) libjade_kyber768_avx2_keypair(public_key, secret_key);
//#if defined(OQS_DIST_BUILD)
//	} else {
//		return (OQS_STATUS) libjade_kyber768_ref_keypair(public_key, secret_key);
//	}
//#endif /* OQS_DIST_BUILD */
//#else
//	return (OQS_STATUS) libjade_kyber768_ref_keypair(public_key, secret_key);
//#endif
//#else /*OQS_LIBJADE_BUILD && (OQS_ENABLE_LIBJADE_KEM_kyber_768)*/
//#if defined(OQS_ENABLE_KEM_kyber_768_avx2)
//#if defined(OQS_DIST_BUILD)
//	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
//#endif /* OQS_DIST_BUILD */
//		return (OQS_STATUS) pqcrystals_kyber768_avx2_keypair(public_key, secret_key);
//#if defined(OQS_DIST_BUILD)
//	} else {
//		return (OQS_STATUS) pqcrystals_kyber768_ref_keypair(public_key, secret_key);
//	}
//#endif /* OQS_DIST_BUILD */
//#elif defined(OQS_ENABLE_KEM_kyber_768_aarch64)
//#if defined(OQS_DIST_BUILD)
//	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)) {
//#endif /* OQS_DIST_BUILD */
//		return (OQS_STATUS) PQCLEAN_KYBER768_AARCH64_crypto_kem_keypair(public_key, secret_key);
//#if defined(OQS_DIST_BUILD)
//	} else {
//		return (OQS_STATUS) pqcrystals_kyber768_ref_keypair(public_key, secret_key);
//	}
//#endif /* OQS_DIST_BUILD */
//#else
//	return (OQS_STATUS) pqcrystals_kyber768_ref_keypair(public_key, secret_key);
//#endif
//#endif /* OQS_LIBJADE_BUILD */
//}
//
//OQS_API OQS_STATUS OQS_KEM_kyber_768_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
//#if defined(OQS_LIBJADE_BUILD) && (defined(OQS_ENABLE_LIBJADE_KEM_kyber_768))
//#if defined(OQS_ENABLE_LIBJADE_KEM_kyber_768_avx2)
//#if defined(OQS_DIST_BUILD)
//	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
//#endif /* OQS_DIST_BUILD */
//		return (OQS_STATUS) libjade_kyber768_avx2_enc(ciphertext, shared_secret, public_key);
//#if defined(OQS_DIST_BUILD)
//	} else {
//		return (OQS_STATUS) libjade_kyber768_ref_enc(ciphertext, shared_secret, public_key);
//	}
//#endif /* OQS_DIST_BUILD */
//#else
//	return (OQS_STATUS) libjade_kyber768_ref_enc(ciphertext, shared_secret, public_key);
//#endif
//#else /*OQS_LIBJADE_BUILD && (OQS_ENABLE_LIBJADE_KEM_kyber_768)*/
//#if defined(OQS_ENABLE_KEM_kyber_768_avx2)
//#if defined(OQS_DIST_BUILD)
//	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
//#endif /* OQS_DIST_BUILD */
//		return (OQS_STATUS) pqcrystals_kyber768_avx2_enc(ciphertext, shared_secret, public_key);
//#if defined(OQS_DIST_BUILD)
//	} else {
//		return (OQS_STATUS) pqcrystals_kyber768_ref_enc(ciphertext, shared_secret, public_key);
//	}
//#endif /* OQS_DIST_BUILD */
//#elif defined(OQS_ENABLE_KEM_kyber_768_aarch64)
//#if defined(OQS_DIST_BUILD)
//	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)) {
//#endif /* OQS_DIST_BUILD */
//		return (OQS_STATUS) PQCLEAN_KYBER768_AARCH64_crypto_kem_enc(ciphertext, shared_secret, public_key);
//#if defined(OQS_DIST_BUILD)
//	} else {
//		return (OQS_STATUS) pqcrystals_kyber768_ref_enc(ciphertext, shared_secret, public_key);
//	}
//#endif /* OQS_DIST_BUILD */
//#else
//	return (OQS_STATUS) pqcrystals_kyber768_ref_enc(ciphertext, shared_secret, public_key);
//#endif
//#endif /* OQS_LIBJADE_BUILD */
//}
//
//OQS_API OQS_STATUS OQS_KEM_kyber_768_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
//#if defined(OQS_LIBJADE_BUILD) && (defined(OQS_ENABLE_LIBJADE_KEM_kyber_768))
//#if defined(OQS_ENABLE_LIBJADE_KEM_kyber_768_avx2)
//#if defined(OQS_DIST_BUILD)
//	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
//#endif /* OQS_DIST_BUILD */
//		return (OQS_STATUS) libjade_kyber768_avx2_dec(shared_secret, ciphertext, secret_key);
//#if defined(OQS_DIST_BUILD)
//	} else {
//		return (OQS_STATUS) libjade_kyber768_ref_dec(shared_secret, ciphertext, secret_key);
//	}
//#endif /* OQS_DIST_BUILD */
//#else
//	return (OQS_STATUS) libjade_kyber768_ref_dec(shared_secret, ciphertext, secret_key);
//#endif
//#else /*OQS_LIBJADE_BUILD && (OQS_ENABLE_LIBJADE_KEM_kyber_768)*/
//#if defined(OQS_ENABLE_KEM_kyber_768_avx2)
//#if defined(OQS_DIST_BUILD)
//	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
//#endif /* OQS_DIST_BUILD */
//		return (OQS_STATUS) pqcrystals_kyber768_avx2_dec(shared_secret, ciphertext, secret_key);
//#if defined(OQS_DIST_BUILD)
//	} else {
//		return (OQS_STATUS) pqcrystals_kyber768_ref_dec(shared_secret, ciphertext, secret_key);
//	}
//#endif /* OQS_DIST_BUILD */
//#elif defined(OQS_ENABLE_KEM_kyber_768_aarch64)
//#if defined(OQS_DIST_BUILD)
//	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)) {
//#endif /* OQS_DIST_BUILD */
//		return (OQS_STATUS) PQCLEAN_KYBER768_AARCH64_crypto_kem_dec(shared_secret, ciphertext, secret_key);
//#if defined(OQS_DIST_BUILD)
//	} else {
//		return (OQS_STATUS) pqcrystals_kyber768_ref_dec(shared_secret, ciphertext, secret_key);
//	}
//#endif /* OQS_DIST_BUILD */
//#else
//	return (OQS_STATUS) pqcrystals_kyber768_ref_dec(shared_secret, ciphertext, secret_key);
//#endif
//#endif /* OQS_LIBJADE_BUILD */
//}
//
//#endif
