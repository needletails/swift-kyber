/* Copyright 2017 The BoringSSL Authors
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

#include <CKyberBoringSSL_evp.h>

#include <CKyberBoringSSL_curve25519.h>
#include <CKyberBoringSSL_err.h>
#include <CKyberBoringSSL_mem.h>

#include "internal.h"


// Ed25519 has no parameters to copy.
static int pkey_ed25519_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src) { return 1; }

static int pkey_ed25519_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) {
  ED25519_KEY *key =
      reinterpret_cast<ED25519_KEY *>(OPENSSL_malloc(sizeof(ED25519_KEY)));
  if (key == NULL) {
    return 0;
  }

  evp_pkey_set_method(pkey, &ed25519_asn1_meth);

  uint8_t pubkey_unused[32];
  ED25519_keypair(pubkey_unused, key->key);
  key->has_private = 1;

  OPENSSL_free(pkey->pkey);
  pkey->pkey = key;
  return 1;
}

static int pkey_ed25519_sign_message(EVP_PKEY_CTX *ctx, uint8_t *sig,
                                     size_t *siglen, const uint8_t *tbs,
                                     size_t tbslen) {
  const ED25519_KEY *key =
      reinterpret_cast<const ED25519_KEY *>(ctx->pkey->pkey);
  if (!key->has_private) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_NOT_A_PRIVATE_KEY);
    return 0;
  }

  if (sig == NULL) {
    *siglen = 64;
    return 1;
  }

  if (*siglen < 64) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_BUFFER_TOO_SMALL);
    return 0;
  }

  if (!ED25519_sign(sig, tbs, tbslen, key->key)) {
    return 0;
  }

  *siglen = 64;
  return 1;
}

static int pkey_ed25519_verify_message(EVP_PKEY_CTX *ctx, const uint8_t *sig,
                                       size_t siglen, const uint8_t *tbs,
                                       size_t tbslen) {
  const ED25519_KEY *key =
      reinterpret_cast<const ED25519_KEY *>(ctx->pkey->pkey);
  if (siglen != 64 ||
      !ED25519_verify(tbs, tbslen, sig, key->key + ED25519_PUBLIC_KEY_OFFSET)) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_INVALID_SIGNATURE);
    return 0;
  }

  return 1;
}

const EVP_PKEY_METHOD ed25519_pkey_meth = {
    /*pkey_id=*/EVP_PKEY_ED25519,
    /*init=*/nullptr,
    /*copy=*/pkey_ed25519_copy,
    /*cleanup=*/nullptr,
    /*keygen=*/pkey_ed25519_keygen,
    /*sign=*/nullptr,
    /*sign_message=*/pkey_ed25519_sign_message,
    /*verify=*/nullptr,
    /*verify_message=*/pkey_ed25519_verify_message,
    /*verify_recover=*/nullptr,
    /*encrypt=*/nullptr,
    /*decrypt=*/nullptr,
    /*derive=*/nullptr,
    /*paramgen=*/nullptr,
    /*ctrl=*/nullptr,
};
