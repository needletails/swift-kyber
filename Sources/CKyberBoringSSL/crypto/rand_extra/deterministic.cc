/* Copyright 2016 The BoringSSL Authors
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

#include <CKyberBoringSSL_rand.h>

#include "../bcm_support.h"
#include "sysrand_internal.h"

#if defined(OPENSSL_RAND_DETERMINISTIC)

#include <string.h>

#include <CKyberBoringSSL_chacha.h>

#include "../internal.h"


// g_num_calls is the number of calls to |CRYPTO_sysrand| that have occurred.
//
// This is intentionally not thread-safe. If the fuzzer mode is ever used in a
// multi-threaded program, replace this with a thread-local. (A mutex would not
// be deterministic.)
static uint64_t g_num_calls = 0;
static CRYPTO_MUTEX g_num_calls_lock = CRYPTO_MUTEX_INIT;

void RAND_reset_for_fuzzing(void) { g_num_calls = 0; }

void CRYPTO_init_sysrand(void) {}

void CRYPTO_sysrand(uint8_t *out, size_t requested) {
  static const uint8_t kZeroKey[32] = {0};

  CRYPTO_MUTEX_lock_write(&g_num_calls_lock);
  uint64_t num_calls = g_num_calls++;
  CRYPTO_MUTEX_unlock_write(&g_num_calls_lock);

  uint8_t nonce[12];
  OPENSSL_memset(nonce, 0, sizeof(nonce));
  OPENSSL_memcpy(nonce, &num_calls, sizeof(num_calls));

  OPENSSL_memset(out, 0, requested);
  CRYPTO_chacha_20(out, out, requested, kZeroKey, nonce, 0);
}

int CRYPTO_sysrand_if_available(uint8_t *buf, size_t len) {
  CRYPTO_sysrand(buf, len);
  return 1;
}

void CRYPTO_sysrand_for_seed(uint8_t *out, size_t requested) {
  CRYPTO_sysrand(out, requested);
}

#endif  // OPENSSL_RAND_DETERMINISTIC
