#ifndef OPENSSL_HEADER_CRYPTO_KYBER_INTERNAL_H
#define OPENSSL_HEADER_CRYPTO_KYBER_INTERNAL_H

#include <CKyberBoringSSL_base.h>
#include <experimental/CKyberBoringSSL_kyber.h>

#if defined(__cplusplus)
extern "C" {
#endif

// Common entropy lengths
#define KYBER_ENCAP_ENTROPY 32
#define KYBER_GENERATE_KEY_ENTROPY 64

// ========== Kyber768 ==========

// For Kyber768
OPENSSL_EXPORT void KYBER_generate_key_external_entropy(
    uint8_t out_encoded_public_key[KYBER_PUBLIC_KEY_BYTES],
    struct KYBER_private_key *out_private_key,
    const uint8_t entropy[KYBER_GENERATE_KEY_ENTROPY]);

OPENSSL_EXPORT void KYBER_encap_external_entropy(
    uint8_t out_ciphertext[KYBER_CIPHERTEXT_BYTES],
    uint8_t out_shared_secret[KYBER_SHARED_SECRET_BYTES],
    const struct KYBER_public_key *public_key,
    const uint8_t entropy[KYBER_ENCAP_ENTROPY]);

// ========== Kyber1024 ==========

// You’ll need to define these constants in your implementation headers
#define KYBER1024_PUBLIC_KEY_BYTES 1568
#define KYBER1024_PRIVATE_KEY_BYTES 3168
#define KYBER1024_CIPHERTEXT_BYTES 1568
#define KYBER1024_SHARED_SECRET_BYTES 32
#define KYBER1024_GENERATE_KEY_ENTROPY 64
#define KYBER1024_ENCAP_ENTROPY 32

// Kyber1024 struct (may reuse or require new ones)
struct KYBER1024_private_key;  // forward declare

OPENSSL_EXPORT void KYBER1024_generate_key_external_entropy(
    uint8_t out_encoded_public_key[KYBER1024_PUBLIC_KEY_BYTES],
    struct KYBER1024_private_key *out_private_key,
    const uint8_t entropy[KYBER1024_GENERATE_KEY_ENTROPY]);

OPENSSL_EXPORT void KYBER1024_encap_external_entropy(
    uint8_t out_ciphertext[KYBER1024_CIPHERTEXT_BYTES],
    uint8_t out_shared_secret[KYBER1024_SHARED_SECRET_BYTES],
    const struct KYBER_public_key *public_key, // Or define KYBER1024_public_key
    const uint8_t entropy[KYBER1024_ENCAP_ENTROPY]);

#if defined(__cplusplus)
}
#endif

#endif  // OPENSSL_HEADER_CRYPTO_KYBER_INTERNAL_H
