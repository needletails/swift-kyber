/* Copyright 2014 The BoringSSL Authors
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

#ifndef OPENSSL_HEADER_CRYPTO_H
#define OPENSSL_HEADER_CRYPTO_H

#include "CKyberBoringSSL_base.h"
#include "CKyberBoringSSL_sha.h"

// Upstream OpenSSL defines |OPENSSL_malloc|, etc., in crypto.h rather than
// mem.h.
#include "CKyberBoringSSL_mem.h"

// Upstream OpenSSL defines |CRYPTO_LOCK|, etc., in crypto.h rather than
// thread.h.
#include "CKyberBoringSSL_thread.h"


#if defined(__cplusplus)
extern "C" {
#endif


// crypto.h contains functions for library-wide initialization and properties.


// CRYPTO_is_confidential_build returns one if the linked version of BoringSSL
// has been built with the BORINGSSL_CONFIDENTIAL define and zero otherwise.
//
// This is used by some consumers to identify whether they are using an
// internal version of BoringSSL.
OPENSSL_EXPORT int CRYPTO_is_confidential_build(void);

// CRYPTO_has_asm returns one unless BoringSSL was built with OPENSSL_NO_ASM,
// in which case it returns zero.
OPENSSL_EXPORT int CRYPTO_has_asm(void);

// BORINGSSL_self_test triggers the FIPS KAT-based self tests. It returns one on
// success and zero on error.
OPENSSL_EXPORT int BORINGSSL_self_test(void);

// BORINGSSL_integrity_test triggers the module's integrity test where the code
// and data of the module is matched against a hash injected at build time. It
// returns one on success or zero if there's a mismatch. This function only
// exists if the module was built in FIPS mode without ASAN.
OPENSSL_EXPORT int BORINGSSL_integrity_test(void);

// CRYPTO_pre_sandbox_init initializes the crypto library, pre-acquiring some
// unusual resources to aid running in sandboxed environments. It is safe to
// call this function multiple times and concurrently from multiple threads.
//
// For more details on using BoringSSL in a sandboxed environment, see
// SANDBOXING.md in the source tree.
OPENSSL_EXPORT void CRYPTO_pre_sandbox_init(void);

#if defined(OPENSSL_ARM) && defined(OPENSSL_LINUX) && \
    !defined(OPENSSL_STATIC_ARMCAP)
// CRYPTO_needs_hwcap2_workaround returns one if the ARMv8 AArch32 AT_HWCAP2
// workaround was needed. See https://crbug.com/boringssl/46.
OPENSSL_EXPORT int CRYPTO_needs_hwcap2_workaround(void);
#endif  // OPENSSL_ARM && OPENSSL_LINUX && !OPENSSL_STATIC_ARMCAP


// FIPS monitoring

// FIPS_mode returns zero unless BoringSSL is built with BORINGSSL_FIPS, in
// which case it returns one.
OPENSSL_EXPORT int FIPS_mode(void);

// fips_counter_t denotes specific APIs/algorithms. A counter is maintained for
// each in FIPS mode so that tests can be written to assert that the expected,
// FIPS functions are being called by a certain peice of code.
enum fips_counter_t {
  fips_counter_evp_aes_128_gcm = 0,
  fips_counter_evp_aes_256_gcm = 1,
  fips_counter_evp_aes_128_ctr = 2,
  fips_counter_evp_aes_256_ctr = 3,

  fips_counter_max = 3,
};

// FIPS_read_counter returns a counter of the number of times the specific
// function denoted by |counter| has been used. This always returns zero unless
// BoringSSL was built with BORINGSSL_FIPS_COUNTERS defined.
OPENSSL_EXPORT size_t FIPS_read_counter(enum fips_counter_t counter);


// Deprecated functions.

// OPENSSL_VERSION_TEXT contains a string the identifies the version of
// “OpenSSL”. node.js requires a version number in this text.
#define OPENSSL_VERSION_TEXT "OpenSSL 1.1.1 (compatible; BoringSSL)"

#define OPENSSL_VERSION 0
#define OPENSSL_CFLAGS 1
#define OPENSSL_BUILT_ON 2
#define OPENSSL_PLATFORM 3
#define OPENSSL_DIR 4

// OpenSSL_version is a compatibility function that returns the string
// "BoringSSL" if |which| is |OPENSSL_VERSION| and placeholder strings
// otherwise.
OPENSSL_EXPORT const char *OpenSSL_version(int which);

#define SSLEAY_VERSION OPENSSL_VERSION
#define SSLEAY_CFLAGS OPENSSL_CFLAGS
#define SSLEAY_BUILT_ON OPENSSL_BUILT_ON
#define SSLEAY_PLATFORM OPENSSL_PLATFORM
#define SSLEAY_DIR OPENSSL_DIR

// SSLeay_version calls |OpenSSL_version|.
OPENSSL_EXPORT const char *SSLeay_version(int which);

// SSLeay is a compatibility function that returns OPENSSL_VERSION_NUMBER from
// base.h.
OPENSSL_EXPORT unsigned long SSLeay(void);

// OpenSSL_version_num is a compatibility function that returns
// OPENSSL_VERSION_NUMBER from base.h.
OPENSSL_EXPORT unsigned long OpenSSL_version_num(void);

// CRYPTO_malloc_init returns one.
OPENSSL_EXPORT int CRYPTO_malloc_init(void);

// OPENSSL_malloc_init returns one.
OPENSSL_EXPORT int OPENSSL_malloc_init(void);

// ENGINE_load_builtin_engines does nothing.
OPENSSL_EXPORT void ENGINE_load_builtin_engines(void);

// ENGINE_register_all_complete returns one.
OPENSSL_EXPORT int ENGINE_register_all_complete(void);

// OPENSSL_load_builtin_modules does nothing.
OPENSSL_EXPORT void OPENSSL_load_builtin_modules(void);

// OPENSSL_INIT_* are options in OpenSSL to configure the library. In BoringSSL,
// they do nothing.
#define OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS 0
#define OPENSSL_INIT_LOAD_CRYPTO_STRINGS 0
#define OPENSSL_INIT_ADD_ALL_CIPHERS 0
#define OPENSSL_INIT_ADD_ALL_DIGESTS 0
#define OPENSSL_INIT_NO_ADD_ALL_CIPHERS 0
#define OPENSSL_INIT_NO_ADD_ALL_DIGESTS 0
#define OPENSSL_INIT_LOAD_CONFIG 0
#define OPENSSL_INIT_NO_LOAD_CONFIG 0
#define OPENSSL_INIT_NO_ATEXIT 0
#define OPENSSL_INIT_ATFORK 0
#define OPENSSL_INIT_ENGINE_RDRAND 0
#define OPENSSL_INIT_ENGINE_DYNAMIC 0
#define OPENSSL_INIT_ENGINE_OPENSSL 0
#define OPENSSL_INIT_ENGINE_CRYPTODEV 0
#define OPENSSL_INIT_ENGINE_CAPI 0
#define OPENSSL_INIT_ENGINE_PADLOCK 0
#define OPENSSL_INIT_ENGINE_AFALG 0
#define OPENSSL_INIT_ENGINE_ALL_BUILTIN 0

// OPENSSL_init_crypto returns one.
OPENSSL_EXPORT int OPENSSL_init_crypto(uint64_t opts,
                                       const OPENSSL_INIT_SETTINGS *settings);

// OPENSSL_cleanup does nothing.
OPENSSL_EXPORT void OPENSSL_cleanup(void);

// FIPS_mode_set returns one if |on| matches whether BoringSSL was built with
// |BORINGSSL_FIPS| and zero otherwise.
OPENSSL_EXPORT int FIPS_mode_set(int on);

// FIPS_module_name returns the name of the FIPS module.
OPENSSL_EXPORT const char *FIPS_module_name(void);

// FIPS_module_hash returns the 32-byte hash of the FIPS module.
OPENSSL_EXPORT const uint8_t *FIPS_module_hash(void);

// FIPS_version returns the version of the FIPS module, or zero if the build
// isn't exactly at a verified version. The version, expressed in base 10, will
// be a date in the form yyyymmddXX where XX is often "00", but can be
// incremented if multiple versions are defined on a single day.
//
// (This format exceeds a |uint32_t| in the year 4294.)
OPENSSL_EXPORT uint32_t FIPS_version(void);

// FIPS_query_algorithm_status returns one if |algorithm| is FIPS validated in
// the current BoringSSL and zero otherwise.
OPENSSL_EXPORT int FIPS_query_algorithm_status(const char *algorithm);

#if defined(OPENSSL_ARM) && defined(OPENSSL_LINUX) && \
    !defined(OPENSSL_STATIC_ARMCAP)
// CRYPTO_has_broken_NEON returns zero.
OPENSSL_EXPORT int CRYPTO_has_broken_NEON(void);
#endif

// CRYPTO_library_init does nothing. Historically, it was needed in some build
// configurations to initialization the library. This is no longer necessary.
OPENSSL_EXPORT void CRYPTO_library_init(void);


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_CRYPTO_H
