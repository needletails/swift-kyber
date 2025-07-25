/* Copyright 2024 The BoringSSL Authors
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#ifndef OPENSSL_HEADER_CRYPTO_BCM_INTERFACE_H
#define OPENSSL_HEADER_CRYPTO_BCM_INTERFACE_H

#include <CKyberBoringSSL_bcm_public.h>

// This header will eventually become the interface between BCM and the
// rest of libcrypto. More cleanly separating the two is still a work in
// progress (see https://crbug.com/boringssl/722) so, at the moment, we
// consider this no different from any other header in BCM.
//
// Over time, calls from libcrypto to BCM will all move to this header
// and the separation will become more meaningful.

#if defined(__cplusplus)
extern "C" {
#endif

// Enumerated types for return values from bcm functions, both infallible
// and fallible functions. Two success values are used to correspond to the
// FIPS service indicator. For the moment, the official service indicator
// remains the counter, not these values. Once we fully transition to
// these return values from bcm we will change that.
enum class bcm_infallible_t {
  approved,
  not_approved,
};

enum class bcm_status_t {
  approved,
  not_approved,
  failure,
};
typedef enum bcm_status_t bcm_status;
typedef enum bcm_infallible_t bcm_infallible;

OPENSSL_INLINE int bcm_success(bcm_status status) {
  return status == bcm_status::approved || status == bcm_status::not_approved;
}

OPENSSL_INLINE bcm_status_t bcm_as_approved_status(int result) {
  return result ? bcm_status::approved : bcm_status::failure;
}


// Random number generator.

#if defined(BORINGSSL_FIPS)

// We overread from /dev/urandom or RDRAND by a factor of 10 and XOR to whiten.
// TODO(bbe): disentangle this value which is used to calculate the size of the
// stack buffer in RAND_need entropy based on a calculation.
#define BORINGSSL_FIPS_OVERREAD 10

#endif  // BORINGSSL_FIPS

// BCM_rand_load_entropy supplies |entropy_len| bytes of entropy to the BCM
// module. The |want_additional_input| parameter is true iff the entropy was
// obtained from a source other than the system, e.g. directly from the CPU.
bcm_infallible BCM_rand_load_entropy(const uint8_t *entropy, size_t entropy_len,
                                     int want_additional_input);

// BCM_rand_bytes is the same as the public |RAND_bytes| function, other
// than returning a bcm_infallible status indicator.
OPENSSL_EXPORT bcm_infallible BCM_rand_bytes(uint8_t *out, size_t out_len);

// BCM_rand_bytes_hwrng attempts to fill |out| with |len| bytes of entropy from
// the CPU hardware random number generator if one is present.
// bcm_status_approved is returned on success, and a failure status is
// returned otherwise.
bcm_status BCM_rand_bytes_hwrng(uint8_t *out, size_t len);

// BCM_rand_bytes_with_additional_data samples from the RNG after mixing 32
// bytes from |user_additional_data| in.
bcm_infallible BCM_rand_bytes_with_additional_data(
    uint8_t *out, size_t out_len, const uint8_t user_additional_data[32]);


// SHA-1

// BCM_SHA_DIGEST_LENGTH is the length of a SHA-1 digest.
#define BCM_SHA_DIGEST_LENGTH 20

// BCM_sha1_init initialises |sha|.
bcm_infallible BCM_sha1_init(SHA_CTX *sha);

// BCM_SHA1_transform is a low-level function that performs a single, SHA-1
// block transformation using the state from |sha| and |SHA_CBLOCK| bytes from
// |block|.
bcm_infallible BCM_sha1_transform(SHA_CTX *c,
                                  const uint8_t data[BCM_SHA_CBLOCK]);

// BCM_sha1_update adds |len| bytes from |data| to |sha|.
bcm_infallible BCM_sha1_update(SHA_CTX *c, const void *data, size_t len);

// BCM_sha1_final adds the final padding to |sha| and writes the resulting
// digest to |out|, which must have at least |SHA_DIGEST_LENGTH| bytes of space.
bcm_infallible BCM_sha1_final(uint8_t out[BCM_SHA_DIGEST_LENGTH], SHA_CTX *c);


// BCM_fips_186_2_prf derives |out_len| bytes from |xkey| using the PRF
// defined in FIPS 186-2, Appendix 3.1, with change notice 1 applied. The b
// parameter is 160 and seed, XKEY, is also 160 bits. The optional XSEED user
// input is all zeros.
//
// The PRF generates a sequence of 320-bit numbers. Each number is encoded as a
// 40-byte string in big-endian and then concatenated to form |out|. If
// |out_len| is not a multiple of 40, the result is truncated. This matches the
// construction used in Section 7 of RFC 4186 and Section 7 of RFC 4187.
//
// This PRF is based on SHA-1, a weak hash function, and should not be used
// in new protocols. It is provided for compatibility with some legacy EAP
// methods.
bcm_infallible BCM_fips_186_2_prf(uint8_t *out, size_t out_len,
                                  const uint8_t xkey[BCM_SHA_DIGEST_LENGTH]);


// SHA-224

// SHA224_DIGEST_LENGTH is the length of a SHA-224 digest.
#define BCM_SHA224_DIGEST_LENGTH 28

// BCM_sha224_unit initialises |sha|.
bcm_infallible BCM_sha224_init(SHA256_CTX *sha);

// BCM_sha224_update adds |len| bytes from |data| to |sha|.
bcm_infallible BCM_sha224_update(SHA256_CTX *sha, const void *data, size_t len);

// BCM_sha224_final adds the final padding to |sha| and writes the resulting
// digest to |out|, which must have at least |SHA224_DIGEST_LENGTH| bytes of
// space. It aborts on programmer error.
bcm_infallible BCM_sha224_final(uint8_t out[BCM_SHA224_DIGEST_LENGTH],
                                SHA256_CTX *sha);


// SHA-256

// BCM_SHA256_DIGEST_LENGTH is the length of a SHA-256 digest.
#define BCM_SHA256_DIGEST_LENGTH 32

// BCM_sha256_init initialises |sha|.
bcm_infallible BCM_sha256_init(SHA256_CTX *sha);

// BCM_sha256_update adds |len| bytes from |data| to |sha|.
bcm_infallible BCM_sha256_update(SHA256_CTX *sha, const void *data, size_t len);

// BCM_sha256_final adds the final padding to |sha| and writes the resulting
// digest to |out|, which must have at least |BCM_SHA256_DIGEST_LENGTH| bytes of
// space. It aborts on programmer error.
bcm_infallible BCM_sha256_final(uint8_t out[BCM_SHA256_DIGEST_LENGTH],
                                SHA256_CTX *sha);

// BCM_sha256_transform is a low-level function that performs a single, SHA-256
// block transformation using the state from |sha| and |BCM_SHA256_CBLOCK| bytes
// from |block|.
bcm_infallible BCM_sha256_transform(SHA256_CTX *sha,
                                    const uint8_t block[BCM_SHA256_CBLOCK]);

// BCM_sha256_transform_blocks is a low-level function that takes |num_blocks| *
// |BCM_SHA256_CBLOCK| bytes of data and performs SHA-256 transforms on it to
// update |state|.
bcm_infallible BCM_sha256_transform_blocks(uint32_t state[8],
                                           const uint8_t *data,
                                           size_t num_blocks);


// SHA-384.

// BCM_SHA384_DIGEST_LENGTH is the length of a SHA-384 digest.
#define BCM_SHA384_DIGEST_LENGTH 48

// BCM_sha384_init initialises |sha|.
bcm_infallible BCM_sha384_init(SHA512_CTX *sha);

// BCM_sha384_update adds |len| bytes from |data| to |sha|.
bcm_infallible BCM_sha384_update(SHA512_CTX *sha, const void *data, size_t len);

// BCM_sha384_final adds the final padding to |sha| and writes the resulting
// digest to |out|, which must have at least |BCM_sha384_DIGEST_LENGTH| bytes of
// space. It may abort on programmer error.
bcm_infallible BCM_sha384_final(uint8_t out[BCM_SHA384_DIGEST_LENGTH],
                                SHA512_CTX *sha);


// SHA-512.

// BCM_SHA512_DIGEST_LENGTH is the length of a SHA-512 digest.
#define BCM_SHA512_DIGEST_LENGTH 64

// BCM_sha512_init initialises |sha|.
bcm_infallible BCM_sha512_init(SHA512_CTX *sha);

// BCM_sha512_update adds |len| bytes from |data| to |sha|.
bcm_infallible BCM_sha512_update(SHA512_CTX *sha, const void *data, size_t len);

// BCM_sha512_final adds the final padding to |sha| and writes the resulting
// digest to |out|, which must have at least |BCM_sha512_DIGEST_LENGTH| bytes of
// space.
bcm_infallible BCM_sha512_final(uint8_t out[BCM_SHA512_DIGEST_LENGTH],
                                SHA512_CTX *sha);

// BCM_sha512_transform is a low-level function that performs a single, SHA-512
// block transformation using the state from |sha| and |BCM_sha512_CBLOCK| bytes
// from |block|.
bcm_infallible BCM_sha512_transform(SHA512_CTX *sha,
                                    const uint8_t block[BCM_SHA512_CBLOCK]);


// SHA-512-256
//
// See https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf section 5.3.6

#define BCM_SHA512_256_DIGEST_LENGTH 32

// BCM_sha512_256_init initialises |sha|.
bcm_infallible BCM_sha512_256_init(SHA512_CTX *sha);

// BCM_sha512_256_update adds |len| bytes from |data| to |sha|.
bcm_infallible BCM_sha512_256_update(SHA512_CTX *sha, const void *data,
                                     size_t len);

// BCM_sha512_256_final adds the final padding to |sha| and writes the resulting
// digest to |out|, which must have at least |BCM_sha512_256_DIGEST_LENGTH|
// bytes of space. It may abort on programmer error.
bcm_infallible BCM_sha512_256_final(uint8_t out[BCM_SHA512_256_DIGEST_LENGTH],
                                    SHA512_CTX *sha);


// ML-DSA
//
// Where not commented, these functions have the same signature as the
// corresponding public function.

// BCM_MLDSA_SIGNATURE_RANDOMIZER_BYTES is the number of bytes of uniformly
// random entropy necessary to generate a signature in randomized mode.
#define BCM_MLDSA_SIGNATURE_RANDOMIZER_BYTES 32

// BCM_MLDSA_SEED_BYTES is the number of bytes in an ML-DSA seed value.
#define BCM_MLDSA_SEED_BYTES 32

// BCM_MLDSA65_PRIVATE_KEY_BYTES is the number of bytes in an encoded ML-DSA-65
// private key.
#define BCM_MLDSA65_PRIVATE_KEY_BYTES 4032

// BCM_MLDSA65_PUBLIC_KEY_BYTES is the number of bytes in an encoded ML-DSA-65
// public key.
#define BCM_MLDSA65_PUBLIC_KEY_BYTES 1952

// BCM_MLDSA65_SIGNATURE_BYTES is the number of bytes in an encoded ML-DSA-65
// signature.
#define BCM_MLDSA65_SIGNATURE_BYTES 3309

struct BCM_mldsa65_private_key {
  union {
    uint8_t bytes[32 + 32 + 64 + 256 * 4 * (5 + 6 + 6)];
    uint32_t alignment;
  } opaque;
};

struct BCM_mldsa65_public_key {
  union {
    uint8_t bytes[32 + 64 + 256 * 4 * 6];
    uint32_t alignment;
  } opaque;
};

OPENSSL_EXPORT bcm_status BCM_mldsa65_generate_key(
    uint8_t out_encoded_public_key[BCM_MLDSA65_PUBLIC_KEY_BYTES],
    uint8_t out_seed[BCM_MLDSA_SEED_BYTES],
    struct BCM_mldsa65_private_key *out_private_key);

OPENSSL_EXPORT bcm_status BCM_mldsa65_private_key_from_seed(
    struct BCM_mldsa65_private_key *out_private_key,
    const uint8_t seed[BCM_MLDSA_SEED_BYTES]);

OPENSSL_EXPORT bcm_status BCM_mldsa65_public_from_private(
    struct BCM_mldsa65_public_key *out_public_key,
    const struct BCM_mldsa65_private_key *private_key);

OPENSSL_EXPORT bcm_status BCM_mldsa65_sign(
    uint8_t out_encoded_signature[BCM_MLDSA65_SIGNATURE_BYTES],
    const struct BCM_mldsa65_private_key *private_key, const uint8_t *msg,
    size_t msg_len, const uint8_t *context, size_t context_len);

OPENSSL_EXPORT bcm_status BCM_mldsa65_verify(
    const struct BCM_mldsa65_public_key *public_key,
    const uint8_t signature[BCM_MLDSA65_SIGNATURE_BYTES], const uint8_t *msg,
    size_t msg_len, const uint8_t *context, size_t context_len);

OPENSSL_EXPORT bcm_status BCM_mldsa65_marshal_public_key(
    CBB *out, const struct BCM_mldsa65_public_key *public_key);

OPENSSL_EXPORT bcm_status BCM_mldsa65_parse_public_key(
    struct BCM_mldsa65_public_key *public_key, CBS *in);

OPENSSL_EXPORT bcm_status BCM_mldsa65_parse_private_key(
    struct BCM_mldsa65_private_key *private_key, CBS *in);

// BCM_mldsa65_generate_key_external_entropy generates a public/private key pair
// using the given seed, writes the encoded public key to
// |out_encoded_public_key| and sets |out_private_key| to the private key.
OPENSSL_EXPORT bcm_status BCM_mldsa65_generate_key_external_entropy(
    uint8_t out_encoded_public_key[BCM_MLDSA65_PUBLIC_KEY_BYTES],
    struct BCM_mldsa65_private_key *out_private_key,
    const uint8_t entropy[BCM_MLDSA_SEED_BYTES]);

// BCM_mldsa5_sign_internal signs |msg| using |private_key| and writes the
// signature to |out_encoded_signature|. The |context_prefix| and |context| are
// prefixed to the message, in that order, before signing. The |randomizer|
// value can be set to zero bytes in order to make a deterministic signature, or
// else filled with entropy for the usual |MLDSA_sign| behavior.
OPENSSL_EXPORT bcm_status BCM_mldsa65_sign_internal(
    uint8_t out_encoded_signature[BCM_MLDSA65_SIGNATURE_BYTES],
    const struct BCM_mldsa65_private_key *private_key, const uint8_t *msg,
    size_t msg_len, const uint8_t *context_prefix, size_t context_prefix_len,
    const uint8_t *context, size_t context_len,
    const uint8_t randomizer[BCM_MLDSA_SIGNATURE_RANDOMIZER_BYTES]);

// BCM_mldsa5_verify_internal verifies that |encoded_signature| is a valid
// signature of |msg| by |public_key|. The |context_prefix| and |context| are
// prefixed to the message before verification, in that order.
OPENSSL_EXPORT bcm_status BCM_mldsa65_verify_internal(
    const struct BCM_mldsa65_public_key *public_key,
    const uint8_t encoded_signature[BCM_MLDSA65_SIGNATURE_BYTES],
    const uint8_t *msg, size_t msg_len, const uint8_t *context_prefix,
    size_t context_prefix_len, const uint8_t *context, size_t context_len);

// BCM_mldsa65_marshal_private_key serializes |private_key| to |out| in the
// NIST format for ML-DSA-65 private keys.
OPENSSL_EXPORT bcm_status BCM_mldsa65_marshal_private_key(
    CBB *out, const struct BCM_mldsa65_private_key *private_key);


// BCM_MLDSA87_PRIVATE_KEY_BYTES is the number of bytes in an encoded ML-DSA-87
// private key.
#define BCM_MLDSA87_PRIVATE_KEY_BYTES 4896

// BCM_MLDSA87_PUBLIC_KEY_BYTES is the number of bytes in an encoded ML-DSA-87
// public key.
#define BCM_MLDSA87_PUBLIC_KEY_BYTES 2592

// BCM_MLDSA87_SIGNATURE_BYTES is the number of bytes in an encoded ML-DSA-87
// signature.
#define BCM_MLDSA87_SIGNATURE_BYTES 4627

struct BCM_mldsa87_private_key {
  union {
    uint8_t bytes[32 + 32 + 64 + 256 * 4 * (7 + 8 + 8)];
    uint32_t alignment;
  } opaque;
};

struct BCM_mldsa87_public_key {
  union {
    uint8_t bytes[32 + 64 + 256 * 4 * 8];
    uint32_t alignment;
  } opaque;
};

OPENSSL_EXPORT bcm_status BCM_mldsa87_generate_key(
    uint8_t out_encoded_public_key[BCM_MLDSA87_PUBLIC_KEY_BYTES],
    uint8_t out_seed[BCM_MLDSA_SEED_BYTES],
    struct BCM_mldsa87_private_key *out_private_key);

OPENSSL_EXPORT bcm_status BCM_mldsa87_private_key_from_seed(
    struct BCM_mldsa87_private_key *out_private_key,
    const uint8_t seed[BCM_MLDSA_SEED_BYTES]);

OPENSSL_EXPORT bcm_status BCM_mldsa87_public_from_private(
    struct BCM_mldsa87_public_key *out_public_key,
    const struct BCM_mldsa87_private_key *private_key);

OPENSSL_EXPORT bcm_status BCM_mldsa87_sign(
    uint8_t out_encoded_signature[BCM_MLDSA87_SIGNATURE_BYTES],
    const struct BCM_mldsa87_private_key *private_key, const uint8_t *msg,
    size_t msg_len, const uint8_t *context, size_t context_len);

OPENSSL_EXPORT bcm_status
BCM_mldsa87_verify(const struct BCM_mldsa87_public_key *public_key,
                   const uint8_t *signature, const uint8_t *msg, size_t msg_len,
                   const uint8_t *context, size_t context_len);

OPENSSL_EXPORT bcm_status BCM_mldsa87_marshal_public_key(
    CBB *out, const struct BCM_mldsa87_public_key *public_key);

OPENSSL_EXPORT bcm_status BCM_mldsa87_parse_public_key(
    struct BCM_mldsa87_public_key *public_key, CBS *in);

OPENSSL_EXPORT bcm_status BCM_mldsa87_parse_private_key(
    struct BCM_mldsa87_private_key *private_key, CBS *in);

// BCM_mldsa87_generate_key_external_entropy generates a public/private key pair
// using the given seed, writes the encoded public key to
// |out_encoded_public_key| and sets |out_private_key| to the private key.
OPENSSL_EXPORT bcm_status BCM_mldsa87_generate_key_external_entropy(
    uint8_t out_encoded_public_key[BCM_MLDSA87_PUBLIC_KEY_BYTES],
    struct BCM_mldsa87_private_key *out_private_key,
    const uint8_t entropy[BCM_MLDSA_SEED_BYTES]);

// BCM_mldsa87_sign_internal signs |msg| using |private_key| and writes the
// signature to |out_encoded_signature|. The |context_prefix| and |context| are
// prefixed to the message, in that order, before signing. The |randomizer|
// value can be set to zero bytes in order to make a deterministic signature, or
// else filled with entropy for the usual |MLDSA_sign| behavior.
OPENSSL_EXPORT bcm_status BCM_mldsa87_sign_internal(
    uint8_t out_encoded_signature[BCM_MLDSA87_SIGNATURE_BYTES],
    const struct BCM_mldsa87_private_key *private_key, const uint8_t *msg,
    size_t msg_len, const uint8_t *context_prefix, size_t context_prefix_len,
    const uint8_t *context, size_t context_len,
    const uint8_t randomizer[BCM_MLDSA_SIGNATURE_RANDOMIZER_BYTES]);

// BCM_mldsa87_verify_internal verifies that |encoded_signature| is a valid
// signature of |msg| by |public_key|. The |context_prefix| and |context| are
// prefixed to the message before verification, in that order.
OPENSSL_EXPORT bcm_status BCM_mldsa87_verify_internal(
    const struct BCM_mldsa87_public_key *public_key,
    const uint8_t encoded_signature[BCM_MLDSA87_SIGNATURE_BYTES],
    const uint8_t *msg, size_t msg_len, const uint8_t *context_prefix,
    size_t context_prefix_len, const uint8_t *context, size_t context_len);

// BCM_mldsa87_marshal_private_key serializes |private_key| to |out| in the
// NIST format for ML-DSA-87 private keys.
OPENSSL_EXPORT bcm_status BCM_mldsa87_marshal_private_key(
    CBB *out, const struct BCM_mldsa87_private_key *private_key);


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_CRYPTO_BCM_INTERFACE_H
