/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ==================================================================== */

#ifndef OPENSSL_HEADER_MODES_INTERNAL_H
#define OPENSSL_HEADER_MODES_INTERNAL_H

#include <CKyberBoringSSL_base.h>

#include <CKyberBoringSSL_aes.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "../../internal.h"

#if defined(__cplusplus)
extern "C" {
#endif


// block128_f is the type of an AES block cipher implementation.
//
// Unlike upstream OpenSSL, it and the other functions in this file hard-code
// |AES_KEY|. It is undefined in C to call a function pointer with anything
// other than the original type. Thus we either must match |block128_f| to the
// type signature of |AES_encrypt| and friends or pass in |void*| wrapper
// functions.
//
// These functions are called exclusively with AES, so we use the former.
typedef void (*block128_f)(const uint8_t in[16], uint8_t out[16],
                           const AES_KEY *key);

OPENSSL_INLINE void CRYPTO_xor16(uint8_t out[16], const uint8_t a[16],
                                 const uint8_t b[16]) {
  // TODO(davidben): Ideally we'd leave this to the compiler, which could use
  // vector registers, etc. But the compiler doesn't know that |in| and |out|
  // cannot partially alias. |restrict| is slightly two strict (we allow exact
  // aliasing), but perhaps in-place could be a separate function?
  static_assert(16 % sizeof(crypto_word_t) == 0,
                "block cannot be evenly divided into words");
  for (size_t i = 0; i < 16; i += sizeof(crypto_word_t)) {
    CRYPTO_store_word_le(
        out + i, CRYPTO_load_word_le(a + i) ^ CRYPTO_load_word_le(b + i));
  }
}


// CTR.

// ctr128_f is the type of a function that performs CTR-mode encryption.
typedef void (*ctr128_f)(const uint8_t *in, uint8_t *out, size_t blocks,
                         const AES_KEY *key, const uint8_t ivec[16]);

// CRYPTO_ctr128_encrypt encrypts (or decrypts, it's the same in CTR mode)
// |len| bytes from |in| to |out| using |block| in counter mode. There's no
// requirement that |len| be a multiple of any value and any partial blocks are
// stored in |ecount_buf| and |*num|, which must be zeroed before the initial
// call. The counter is a 128-bit, big-endian value in |ivec| and is
// incremented by this function.
void CRYPTO_ctr128_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                           const AES_KEY *key, uint8_t ivec[16],
                           uint8_t ecount_buf[16], unsigned *num,
                           block128_f block);

// CRYPTO_ctr128_encrypt_ctr32 acts like |CRYPTO_ctr128_encrypt| but takes
// |ctr|, a function that performs CTR mode but only deals with the lower 32
// bits of the counter. This is useful when |ctr| can be an optimised
// function.
void CRYPTO_ctr128_encrypt_ctr32(const uint8_t *in, uint8_t *out, size_t len,
                                 const AES_KEY *key, uint8_t ivec[16],
                                 uint8_t ecount_buf[16], unsigned *num,
                                 ctr128_f ctr);


// GCM.
//
// This API differs from the upstream API slightly. The |GCM128_CONTEXT| does
// not have a |key| pointer that points to the key as upstream's version does.
// Instead, every function takes a |key| parameter. This way |GCM128_CONTEXT|
// can be safely copied. Additionally, |gcm_key| is split into a separate
// struct.

// gcm_impl_t specifies an assembly implementation of AES-GCM.
enum gcm_impl_t {
  gcm_separate = 0,  // No combined AES-GCM, but may have AES-CTR and GHASH.
  gcm_x86_aesni,
  gcm_x86_vaes_avx10_256,
  gcm_x86_vaes_avx10_512,
  gcm_arm64_aes,
};

typedef struct { uint64_t hi,lo; } u128;

// gmult_func multiplies |Xi| by the GCM key and writes the result back to
// |Xi|.
typedef void (*gmult_func)(uint8_t Xi[16], const u128 Htable[16]);

// ghash_func repeatedly multiplies |Xi| by the GCM key and adds in blocks from
// |inp|. The result is written back to |Xi| and the |len| argument must be a
// multiple of 16.
typedef void (*ghash_func)(uint8_t Xi[16], const u128 Htable[16],
                           const uint8_t *inp, size_t len);

typedef struct gcm128_key_st {
  // |gcm_*_ssse3| require a 16-byte-aligned |Htable| when hashing data, but not
  // initialization. |GCM128_KEY| is not itself aligned to simplify embedding in
  // |EVP_AEAD_CTX|, but |Htable|'s offset must be a multiple of 16.
  // TODO(crbug.com/boringssl/604): Revisit this.
  u128 Htable[16];
  gmult_func gmult;
  ghash_func ghash;

  block128_f block;
  enum gcm_impl_t impl;
} GCM128_KEY;

// GCM128_CONTEXT contains state for a single GCM operation. The structure
// should be zero-initialized before use.
typedef struct {
  // The following 5 names follow names in GCM specification
  uint8_t Yi[16];
  uint8_t EKi[16];
  uint8_t EK0[16];
  struct {
    uint64_t aad;
    uint64_t msg;
  } len;
  uint8_t Xi[16];

  // |gcm_*_ssse3| require |Htable| to be 16-byte-aligned.
  // TODO(crbug.com/boringssl/604): Revisit this.
  alignas(16) GCM128_KEY gcm_key;

  unsigned mres, ares;
} GCM128_CONTEXT;

#if defined(OPENSSL_X86) || defined(OPENSSL_X86_64)
// crypto_gcm_clmul_enabled returns one if the CLMUL implementation of GCM is
// used.
int crypto_gcm_clmul_enabled(void);
#endif

// CRYPTO_ghash_init writes a precomputed table of powers of |gcm_key| to
// |out_table| and sets |*out_mult| and |*out_hash| to (potentially hardware
// accelerated) functions for performing operations in the GHASH field.
void CRYPTO_ghash_init(gmult_func *out_mult, ghash_func *out_hash,
                       u128 out_table[16], const uint8_t gcm_key[16]);

// CRYPTO_gcm128_init_key initialises |gcm_key| to use |block| (typically AES)
// with the given key. |block_is_hwaes| is one if |block| is |aes_hw_encrypt|.
void CRYPTO_gcm128_init_key(GCM128_KEY *gcm_key, const AES_KEY *key,
                            block128_f block, int block_is_hwaes);

// CRYPTO_gcm128_setiv sets the IV (nonce) for |ctx|. The |key| must be the
// same key that was passed to |CRYPTO_gcm128_init|.
void CRYPTO_gcm128_setiv(GCM128_CONTEXT *ctx, const AES_KEY *key,
                         const uint8_t *iv, size_t iv_len);

// CRYPTO_gcm128_aad sets the authenticated data for an instance of GCM.
// This must be called before and data is encrypted. It returns one on success
// and zero otherwise.
int CRYPTO_gcm128_aad(GCM128_CONTEXT *ctx, const uint8_t *aad, size_t len);

// CRYPTO_gcm128_encrypt encrypts |len| bytes from |in| to |out|. The |key|
// must be the same key that was passed to |CRYPTO_gcm128_init|. It returns one
// on success and zero otherwise.
int CRYPTO_gcm128_encrypt(GCM128_CONTEXT *ctx, const AES_KEY *key,
                          const uint8_t *in, uint8_t *out, size_t len);

// CRYPTO_gcm128_decrypt decrypts |len| bytes from |in| to |out|. The |key|
// must be the same key that was passed to |CRYPTO_gcm128_init|. It returns one
// on success and zero otherwise.
int CRYPTO_gcm128_decrypt(GCM128_CONTEXT *ctx, const AES_KEY *key,
                          const uint8_t *in, uint8_t *out, size_t len);

// CRYPTO_gcm128_encrypt_ctr32 encrypts |len| bytes from |in| to |out| using
// a CTR function that only handles the bottom 32 bits of the nonce, like
// |CRYPTO_ctr128_encrypt_ctr32|. The |key| must be the same key that was
// passed to |CRYPTO_gcm128_init|. It returns one on success and zero
// otherwise.
int CRYPTO_gcm128_encrypt_ctr32(GCM128_CONTEXT *ctx, const AES_KEY *key,
                                const uint8_t *in, uint8_t *out, size_t len,
                                ctr128_f stream);

// CRYPTO_gcm128_decrypt_ctr32 decrypts |len| bytes from |in| to |out| using
// a CTR function that only handles the bottom 32 bits of the nonce, like
// |CRYPTO_ctr128_encrypt_ctr32|. The |key| must be the same key that was
// passed to |CRYPTO_gcm128_init|. It returns one on success and zero
// otherwise.
int CRYPTO_gcm128_decrypt_ctr32(GCM128_CONTEXT *ctx, const AES_KEY *key,
                                const uint8_t *in, uint8_t *out, size_t len,
                                ctr128_f stream);

// CRYPTO_gcm128_finish calculates the authenticator and compares it against
// |len| bytes of |tag|. It returns one on success and zero otherwise.
int CRYPTO_gcm128_finish(GCM128_CONTEXT *ctx, const uint8_t *tag, size_t len);

// CRYPTO_gcm128_tag calculates the authenticator and copies it into |tag|.
// The minimum of |len| and 16 bytes are copied into |tag|.
void CRYPTO_gcm128_tag(GCM128_CONTEXT *ctx, uint8_t *tag, size_t len);


// GCM assembly.

void gcm_init_nohw(u128 Htable[16], const uint64_t H[2]);
void gcm_gmult_nohw(uint8_t Xi[16], const u128 Htable[16]);
void gcm_ghash_nohw(uint8_t Xi[16], const u128 Htable[16], const uint8_t *inp,
                    size_t len);

#if !defined(OPENSSL_NO_ASM)

#if defined(OPENSSL_X86) || defined(OPENSSL_X86_64)
#define GCM_FUNCREF
void gcm_init_clmul(u128 Htable[16], const uint64_t Xi[2]);
void gcm_gmult_clmul(uint8_t Xi[16], const u128 Htable[16]);
void gcm_ghash_clmul(uint8_t Xi[16], const u128 Htable[16], const uint8_t *inp,
                     size_t len);

// |gcm_gmult_ssse3| and |gcm_ghash_ssse3| require |Htable| to be
// 16-byte-aligned, but |gcm_init_ssse3| does not.
void gcm_init_ssse3(u128 Htable[16], const uint64_t Xi[2]);
void gcm_gmult_ssse3(uint8_t Xi[16], const u128 Htable[16]);
void gcm_ghash_ssse3(uint8_t Xi[16], const u128 Htable[16], const uint8_t *in,
                     size_t len);

#if defined(OPENSSL_X86_64)
#define GHASH_ASM_X86_64
void gcm_init_avx(u128 Htable[16], const uint64_t Xi[2]);
void gcm_gmult_avx(uint8_t Xi[16], const u128 Htable[16]);
void gcm_ghash_avx(uint8_t Xi[16], const u128 Htable[16], const uint8_t *in,
                   size_t len);

#define HW_GCM
size_t aesni_gcm_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                         const AES_KEY *key, uint8_t ivec[16],
                         const u128 Htable[16], uint8_t Xi[16]);
size_t aesni_gcm_decrypt(const uint8_t *in, uint8_t *out, size_t len,
                         const AES_KEY *key, uint8_t ivec[16],
                         const u128 Htable[16], uint8_t Xi[16]);

void gcm_init_vpclmulqdq_avx10(u128 Htable[16], const uint64_t H[2]);
void gcm_gmult_vpclmulqdq_avx10(uint8_t Xi[16], const u128 Htable[16]);
void gcm_ghash_vpclmulqdq_avx10_256(uint8_t Xi[16], const u128 Htable[16],
                                    const uint8_t *in, size_t len);
void gcm_ghash_vpclmulqdq_avx10_512(uint8_t Xi[16], const u128 Htable[16],
                                    const uint8_t *in, size_t len);
void aes_gcm_enc_update_vaes_avx10_256(const uint8_t *in, uint8_t *out,
                                       size_t len, const AES_KEY *key,
                                       const uint8_t ivec[16],
                                       const u128 Htable[16], uint8_t Xi[16]);
void aes_gcm_dec_update_vaes_avx10_256(const uint8_t *in, uint8_t *out,
                                       size_t len, const AES_KEY *key,
                                       const uint8_t ivec[16],
                                       const u128 Htable[16], uint8_t Xi[16]);
void aes_gcm_enc_update_vaes_avx10_512(const uint8_t *in, uint8_t *out,
                                       size_t len, const AES_KEY *key,
                                       const uint8_t ivec[16],
                                       const u128 Htable[16], uint8_t Xi[16]);
void aes_gcm_dec_update_vaes_avx10_512(const uint8_t *in, uint8_t *out,
                                       size_t len, const AES_KEY *key,
                                       const uint8_t ivec[16],
                                       const u128 Htable[16], uint8_t Xi[16]);

#endif  // OPENSSL_X86_64

#if defined(OPENSSL_X86)
#define GHASH_ASM_X86
#endif  // OPENSSL_X86

#elif defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64)

#define GHASH_ASM_ARM
#define GCM_FUNCREF

OPENSSL_INLINE int gcm_pmull_capable(void) {
  return CRYPTO_is_ARMv8_PMULL_capable();
}

void gcm_init_v8(u128 Htable[16], const uint64_t H[2]);
void gcm_gmult_v8(uint8_t Xi[16], const u128 Htable[16]);
void gcm_ghash_v8(uint8_t Xi[16], const u128 Htable[16], const uint8_t *inp,
                  size_t len);

OPENSSL_INLINE int gcm_neon_capable(void) { return CRYPTO_is_NEON_capable(); }

void gcm_init_neon(u128 Htable[16], const uint64_t H[2]);
void gcm_gmult_neon(uint8_t Xi[16], const u128 Htable[16]);
void gcm_ghash_neon(uint8_t Xi[16], const u128 Htable[16], const uint8_t *inp,
                    size_t len);

#if defined(OPENSSL_AARCH64)
#define HW_GCM
// These functions are defined in aesv8-gcm-armv8.pl.
void aes_gcm_enc_kernel(const uint8_t *in, uint64_t in_bits, void *out,
                        void *Xi, uint8_t *ivec, const AES_KEY *key,
                        const u128 Htable[16]);
void aes_gcm_dec_kernel(const uint8_t *in, uint64_t in_bits, void *out,
                        void *Xi, uint8_t *ivec, const AES_KEY *key,
                        const u128 Htable[16]);
#endif

#endif
#endif  // OPENSSL_NO_ASM


// CBC.

// cbc128_f is the type of a function that performs CBC-mode encryption.
typedef void (*cbc128_f)(const uint8_t *in, uint8_t *out, size_t len,
                         const AES_KEY *key, uint8_t ivec[16], int enc);

// CRYPTO_cbc128_encrypt encrypts |len| bytes from |in| to |out| using the
// given IV and block cipher in CBC mode. The input need not be a multiple of
// 128 bits long, but the output will round up to the nearest 128 bit multiple,
// zero padding the input if needed. The IV will be updated on return.
void CRYPTO_cbc128_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                           const AES_KEY *key, uint8_t ivec[16],
                           block128_f block);

// CRYPTO_cbc128_decrypt decrypts |len| bytes from |in| to |out| using the
// given IV and block cipher in CBC mode. If |len| is not a multiple of 128
// bits then only that many bytes will be written, but a multiple of 128 bits
// is always read from |in|. The IV will be updated on return.
void CRYPTO_cbc128_decrypt(const uint8_t *in, uint8_t *out, size_t len,
                           const AES_KEY *key, uint8_t ivec[16],
                           block128_f block);


// OFB.

// CRYPTO_ofb128_encrypt encrypts (or decrypts, it's the same with OFB mode)
// |len| bytes from |in| to |out| using |block| in OFB mode. There's no
// requirement that |len| be a multiple of any value and any partial blocks are
// stored in |ivec| and |*num|, the latter must be zero before the initial
// call.
void CRYPTO_ofb128_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                           const AES_KEY *key, uint8_t ivec[16], unsigned *num,
                           block128_f block);


// CFB.

// CRYPTO_cfb128_encrypt encrypts (or decrypts, if |enc| is zero) |len| bytes
// from |in| to |out| using |block| in CFB mode. There's no requirement that
// |len| be a multiple of any value and any partial blocks are stored in |ivec|
// and |*num|, the latter must be zero before the initial call.
void CRYPTO_cfb128_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                           const AES_KEY *key, uint8_t ivec[16], unsigned *num,
                           int enc, block128_f block);

// CRYPTO_cfb128_8_encrypt encrypts (or decrypts, if |enc| is zero) |len| bytes
// from |in| to |out| using |block| in CFB-8 mode. Prior to the first call
// |num| should be set to zero.
void CRYPTO_cfb128_8_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                             const AES_KEY *key, uint8_t ivec[16],
                             unsigned *num, int enc, block128_f block);

// CRYPTO_cfb128_1_encrypt encrypts (or decrypts, if |enc| is zero) |len| bytes
// from |in| to |out| using |block| in CFB-1 mode. Prior to the first call
// |num| should be set to zero.
void CRYPTO_cfb128_1_encrypt(const uint8_t *in, uint8_t *out, size_t bits,
                             const AES_KEY *key, uint8_t ivec[16],
                             unsigned *num, int enc, block128_f block);

size_t CRYPTO_cts128_encrypt_block(const uint8_t *in, uint8_t *out, size_t len,
                                   const AES_KEY *key, uint8_t ivec[16],
                                   block128_f block);


// POLYVAL.
//
// POLYVAL is a polynomial authenticator that operates over a field very
// similar to the one that GHASH uses. See
// https://www.rfc-editor.org/rfc/rfc8452.html#section-3.

struct polyval_ctx {
  uint8_t S[16];
  // |gcm_*_ssse3| require |Htable| to be 16-byte-aligned.
  // TODO(crbug.com/boringssl/604): Revisit this.
  alignas(16) u128 Htable[16];
  gmult_func gmult;
  ghash_func ghash;
};

// CRYPTO_POLYVAL_init initialises |ctx| using |key|.
void CRYPTO_POLYVAL_init(struct polyval_ctx *ctx, const uint8_t key[16]);

// CRYPTO_POLYVAL_update_blocks updates the accumulator in |ctx| given the
// blocks from |in|. Only a whole number of blocks can be processed so |in_len|
// must be a multiple of 16.
void CRYPTO_POLYVAL_update_blocks(struct polyval_ctx *ctx, const uint8_t *in,
                                  size_t in_len);

// CRYPTO_POLYVAL_finish writes the accumulator from |ctx| to |out|.
void CRYPTO_POLYVAL_finish(const struct polyval_ctx *ctx, uint8_t out[16]);


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_MODES_INTERNAL_H
