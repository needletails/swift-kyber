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

#include <CKyberBoringSSL_bn.h>

#include <string.h>

#include <CKyberBoringSSL_err.h>
#include <CKyberBoringSSL_mem.h>

#include "../../internal.h"
#include "internal.h"


int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b) {
  const BIGNUM *tmp;
  int a_neg = a->neg, ret;

  //  a +  b	a+b
  //  a + -b	a-b
  // -a +  b	b-a
  // -a + -b	-(a+b)
  if (a_neg ^ b->neg) {
    // only one is negative
    if (a_neg) {
      tmp = a;
      a = b;
      b = tmp;
    }

    // we are now a - b
    if (BN_ucmp(a, b) < 0) {
      if (!BN_usub(r, b, a)) {
        return 0;
      }
      r->neg = 1;
    } else {
      if (!BN_usub(r, a, b)) {
        return 0;
      }
      r->neg = 0;
    }
    return 1;
  }

  ret = BN_uadd(r, a, b);
  r->neg = a_neg;
  return ret;
}

int bn_uadd_consttime(BIGNUM *r, const BIGNUM *a, const BIGNUM *b) {
  // Widths are public, so we normalize to make |a| the larger one.
  if (a->width < b->width) {
    const BIGNUM *tmp = a;
    a = b;
    b = tmp;
  }

  int max = a->width;
  int min = b->width;
  if (!bn_wexpand(r, max + 1)) {
    return 0;
  }
  r->width = max + 1;

  BN_ULONG carry = bn_add_words(r->d, a->d, b->d, min);
  for (int i = min; i < max; i++) {
    r->d[i] = CRYPTO_addc_w(a->d[i], 0, carry, &carry);
  }

  r->d[max] = carry;
  return 1;
}

int BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b) {
  if (!bn_uadd_consttime(r, a, b)) {
    return 0;
  }
  bn_set_minimal_width(r);
  return 1;
}

int BN_add_word(BIGNUM *a, BN_ULONG w) {
  BN_ULONG l;
  int i;

  // degenerate case: w is zero
  if (!w) {
    return 1;
  }

  // degenerate case: a is zero
  if (BN_is_zero(a)) {
    return BN_set_word(a, w);
  }

  // handle 'a' when negative
  if (a->neg) {
    a->neg = 0;
    i = BN_sub_word(a, w);
    if (!BN_is_zero(a)) {
      a->neg = !(a->neg);
    }
    return i;
  }

  for (i = 0; w != 0 && i < a->width; i++) {
    a->d[i] = l = a->d[i] + w;
    w = (w > l) ? 1 : 0;
  }

  if (w && i == a->width) {
    if (!bn_wexpand(a, a->width + 1)) {
      return 0;
    }
    a->width++;
    a->d[i] = w;
  }

  return 1;
}

int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b) {
  int add = 0, neg = 0;
  const BIGNUM *tmp;

  //  a -  b	a-b
  //  a - -b	a+b
  // -a -  b	-(a+b)
  // -a - -b	b-a
  if (a->neg) {
    if (b->neg) {
      tmp = a;
      a = b;
      b = tmp;
    } else {
      add = 1;
      neg = 1;
    }
  } else {
    if (b->neg) {
      add = 1;
      neg = 0;
    }
  }

  if (add) {
    if (!BN_uadd(r, a, b)) {
      return 0;
    }

    r->neg = neg;
    return 1;
  }

  if (BN_ucmp(a, b) < 0) {
    if (!BN_usub(r, b, a)) {
      return 0;
    }
    r->neg = 1;
  } else {
    if (!BN_usub(r, a, b)) {
      return 0;
    }
    r->neg = 0;
  }

  return 1;
}

int bn_usub_consttime(BIGNUM *r, const BIGNUM *a, const BIGNUM *b) {
  // |b| may have more words than |a| given non-minimal inputs, but all words
  // beyond |a->width| must then be zero.
  int b_width = b->width;
  if (b_width > a->width) {
    if (!bn_fits_in_words(b, a->width)) {
      OPENSSL_PUT_ERROR(BN, BN_R_ARG2_LT_ARG3);
      return 0;
    }
    b_width = a->width;
  }

  if (!bn_wexpand(r, a->width)) {
    return 0;
  }

  BN_ULONG borrow = bn_sub_words(r->d, a->d, b->d, b_width);
  for (int i = b_width; i < a->width; i++) {
    r->d[i] = CRYPTO_subc_w(a->d[i], 0, borrow, &borrow);
  }

  if (borrow) {
    OPENSSL_PUT_ERROR(BN, BN_R_ARG2_LT_ARG3);
    return 0;
  }

  r->width = a->width;
  r->neg = 0;
  return 1;
}

int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b) {
  if (!bn_usub_consttime(r, a, b)) {
    return 0;
  }
  bn_set_minimal_width(r);
  return 1;
}

int BN_sub_word(BIGNUM *a, BN_ULONG w) {
  int i;

  // degenerate case: w is zero
  if (!w) {
    return 1;
  }

  // degenerate case: a is zero
  if (BN_is_zero(a)) {
    i = BN_set_word(a, w);
    if (i != 0) {
      BN_set_negative(a, 1);
    }
    return i;
  }

  // handle 'a' when negative
  if (a->neg) {
    a->neg = 0;
    i = BN_add_word(a, w);
    a->neg = 1;
    return i;
  }

  if ((bn_minimal_width(a) == 1) && (a->d[0] < w)) {
    a->d[0] = w - a->d[0];
    a->neg = 1;
    return 1;
  }

  i = 0;
  for (;;) {
    if (a->d[i] >= w) {
      a->d[i] -= w;
      break;
    } else {
      a->d[i] -= w;
      i++;
      w = 1;
    }
  }

  if ((a->d[i] == 0) && (i == (a->width - 1))) {
    a->width--;
  }

  return 1;
}
