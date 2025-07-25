/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.] */

#include <CKyberBoringSSL_asn1.h>

#include <limits.h>
#include <string.h>

#include <CKyberBoringSSL_err.h>
#include <CKyberBoringSSL_mem.h>

#include "../internal.h"
#include "internal.h"


int ASN1_BIT_STRING_set(ASN1_BIT_STRING *x, const unsigned char *d,
                        ossl_ssize_t len) {
  return ASN1_STRING_set(x, d, len);
}

int asn1_bit_string_length(const ASN1_BIT_STRING *str,
                           uint8_t *out_padding_bits) {
  int len = str->length;
  if (str->flags & ASN1_STRING_FLAG_BITS_LEFT) {
    // If the string is already empty, it cannot have padding bits.
    *out_padding_bits = len == 0 ? 0 : str->flags & 0x07;
    return len;
  }

  // TODO(https://crbug.com/boringssl/447): If we move this logic to
  // |ASN1_BIT_STRING_set_bit|, can we remove this representation?
  while (len > 0 && str->data[len - 1] == 0) {
    len--;
  }
  uint8_t padding_bits = 0;
  if (len > 0) {
    uint8_t last = str->data[len - 1];
    assert(last != 0);
    for (; padding_bits < 7; padding_bits++) {
      if (last & (1 << padding_bits)) {
        break;
      }
    }
  }
  *out_padding_bits = padding_bits;
  return len;
}

int ASN1_BIT_STRING_num_bytes(const ASN1_BIT_STRING *str, size_t *out) {
  uint8_t padding_bits;
  int len = asn1_bit_string_length(str, &padding_bits);
  if (padding_bits != 0) {
    return 0;
  }
  *out = len;
  return 1;
}

int i2c_ASN1_BIT_STRING(const ASN1_BIT_STRING *a, unsigned char **pp) {
  if (a == NULL) {
    return 0;
  }

  uint8_t bits;
  int len = asn1_bit_string_length(a, &bits);
  if (len > INT_MAX - 1) {
    OPENSSL_PUT_ERROR(ASN1, ERR_R_OVERFLOW);
    return 0;
  }
  int ret = 1 + len;
  if (pp == NULL) {
    return ret;
  }

  uint8_t *p = *pp;
  *(p++) = bits;
  OPENSSL_memcpy(p, a->data, len);
  if (len > 0) {
    p[len - 1] &= (0xff << bits);
  }
  p += len;
  *pp = p;
  return ret;
}

ASN1_BIT_STRING *c2i_ASN1_BIT_STRING(ASN1_BIT_STRING **a,
                                     const unsigned char **pp, long len) {
  ASN1_BIT_STRING *ret = NULL;
  const unsigned char *p;
  unsigned char *s;
  int padding;
  uint8_t padding_mask;

  if (len < 1) {
    OPENSSL_PUT_ERROR(ASN1, ASN1_R_STRING_TOO_SHORT);
    goto err;
  }

  if (len > INT_MAX) {
    OPENSSL_PUT_ERROR(ASN1, ASN1_R_STRING_TOO_LONG);
    goto err;
  }

  if ((a == NULL) || ((*a) == NULL)) {
    if ((ret = ASN1_BIT_STRING_new()) == NULL) {
      return NULL;
    }
  } else {
    ret = (*a);
  }

  p = *pp;
  padding = *(p++);
  len--;
  if (padding > 7) {
    OPENSSL_PUT_ERROR(ASN1, ASN1_R_INVALID_BIT_STRING_BITS_LEFT);
    goto err;
  }

  // Unused bits in a BIT STRING must be zero.
  padding_mask = (1 << padding) - 1;
  if (padding != 0 && (len < 1 || (p[len - 1] & padding_mask) != 0)) {
    OPENSSL_PUT_ERROR(ASN1, ASN1_R_INVALID_BIT_STRING_PADDING);
    goto err;
  }

  // We do this to preserve the settings.  If we modify the settings, via
  // the _set_bit function, we will recalculate on output
  ret->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);    // clear
  ret->flags |= (ASN1_STRING_FLAG_BITS_LEFT | padding);  // set

  if (len > 0) {
    s = reinterpret_cast<uint8_t *>(OPENSSL_memdup(p, len));
    if (s == NULL) {
      goto err;
    }
    p += len;
  } else {
    s = NULL;
  }

  ret->length = (int)len;
  OPENSSL_free(ret->data);
  ret->data = s;
  ret->type = V_ASN1_BIT_STRING;
  if (a != NULL) {
    (*a) = ret;
  }
  *pp = p;
  return ret;
err:
  if ((ret != NULL) && ((a == NULL) || (*a != ret))) {
    ASN1_BIT_STRING_free(ret);
  }
  return NULL;
}

// These next 2 functions from Goetz Babin-Ebell <babinebell@trustcenter.de>
int ASN1_BIT_STRING_set_bit(ASN1_BIT_STRING *a, int n, int value) {
  int w, v, iv;
  unsigned char *c;

  w = n / 8;
  v = 1 << (7 - (n & 0x07));
  iv = ~v;
  if (!value) {
    v = 0;
  }

  if (a == NULL) {
    return 0;
  }

  a->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);  // clear, set on write

  if ((a->length < (w + 1)) || (a->data == NULL)) {
    if (!value) {
      return 1;  // Don't need to set
    }
    if (a->data == NULL) {
      c = (unsigned char *)OPENSSL_malloc(w + 1);
    } else {
      c = (unsigned char *)OPENSSL_realloc(a->data, w + 1);
    }
    if (c == NULL) {
      return 0;
    }
    if (w + 1 - a->length > 0) {
      OPENSSL_memset(c + a->length, 0, w + 1 - a->length);
    }
    a->data = c;
    a->length = w + 1;
  }
  a->data[w] = ((a->data[w]) & iv) | v;
  while ((a->length > 0) && (a->data[a->length - 1] == 0)) {
    a->length--;
  }
  return 1;
}

int ASN1_BIT_STRING_get_bit(const ASN1_BIT_STRING *a, int n) {
  int w, v;

  w = n / 8;
  v = 1 << (7 - (n & 0x07));
  if ((a == NULL) || (a->length < (w + 1)) || (a->data == NULL)) {
    return 0;
  }
  return ((a->data[w] & v) != 0);
}

// Checks if the given bit string contains only bits specified by
// the flags vector. Returns 0 if there is at least one bit set in 'a'
// which is not specified in 'flags', 1 otherwise.
// 'len' is the length of 'flags'.
int ASN1_BIT_STRING_check(const ASN1_BIT_STRING *a, const unsigned char *flags,
                          int flags_len) {
  int i, ok;
  // Check if there is one bit set at all.
  if (!a || !a->data) {
    return 1;
  }

  // Check each byte of the internal representation of the bit string.
  ok = 1;
  for (i = 0; i < a->length && ok; ++i) {
    unsigned char mask = i < flags_len ? ~flags[i] : 0xff;
    // We are done if there is an unneeded bit set.
    ok = (a->data[i] & mask) == 0;
  }
  return ok;
}
