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

#include "internal.h"

#if defined(OPENSSL_AARCH64) && defined(OPENSSL_LINUX) && \
    !defined(OPENSSL_STATIC_ARMCAP) && !defined(OPENSSL_NO_ASM)

#include <sys/auxv.h>

#include <CKyberBoringSSL_arm_arch.h>


void OPENSSL_cpuid_setup(void) {
  unsigned long hwcap = getauxval(AT_HWCAP);

  // See /usr/include/asm/hwcap.h on an aarch64 installation for the source of
  // these values.
  static const unsigned long kNEON = 1 << 1;
  static const unsigned long kAES = 1 << 3;
  static const unsigned long kPMULL = 1 << 4;
  static const unsigned long kSHA1 = 1 << 5;
  static const unsigned long kSHA256 = 1 << 6;
  static const unsigned long kSHA512 = 1 << 21;

  if ((hwcap & kNEON) == 0) {
    // Matching OpenSSL, if NEON is missing, don't report other features
    // either.
    return;
  }

  OPENSSL_armcap_P |= ARMV7_NEON;

  if (hwcap & kAES) {
    OPENSSL_armcap_P |= ARMV8_AES;
  }
  if (hwcap & kPMULL) {
    OPENSSL_armcap_P |= ARMV8_PMULL;
  }
  if (hwcap & kSHA1) {
    OPENSSL_armcap_P |= ARMV8_SHA1;
  }
  if (hwcap & kSHA256) {
    OPENSSL_armcap_P |= ARMV8_SHA256;
  }
  if (hwcap & kSHA512) {
    OPENSSL_armcap_P |= ARMV8_SHA512;
  }
}

#endif  // OPENSSL_AARCH64 && OPENSSL_LINUX && !OPENSSL_STATIC_ARMCAP
