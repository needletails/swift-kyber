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
#include <CKyberBoringSSL_err.h>
#include <CKyberBoringSSL_evp.h>
#include <CKyberBoringSSL_obj.h>
#include <CKyberBoringSSL_stack.h>
#include <CKyberBoringSSL_x509.h>

#include "internal.h"


int X509v3_get_ext_count(const STACK_OF(X509_EXTENSION) *x) {
  if (x == NULL) {
    return 0;
  }
  return (int)sk_X509_EXTENSION_num(x);
}

int X509v3_get_ext_by_NID(const STACK_OF(X509_EXTENSION) *x, int nid,
                          int lastpos) {
  const ASN1_OBJECT *obj = OBJ_nid2obj(nid);
  if (obj == NULL) {
    return -1;
  }
  return X509v3_get_ext_by_OBJ(x, obj, lastpos);
}

int X509v3_get_ext_by_OBJ(const STACK_OF(X509_EXTENSION) *sk,
                          const ASN1_OBJECT *obj, int lastpos) {
  if (sk == NULL) {
    return -1;
  }
  lastpos++;
  if (lastpos < 0) {
    lastpos = 0;
  }
  int n = (int)sk_X509_EXTENSION_num(sk);
  for (; lastpos < n; lastpos++) {
    const X509_EXTENSION *ex = sk_X509_EXTENSION_value(sk, lastpos);
    if (OBJ_cmp(ex->object, obj) == 0) {
      return lastpos;
    }
  }
  return -1;
}

int X509v3_get_ext_by_critical(const STACK_OF(X509_EXTENSION) *sk, int crit,
                               int lastpos) {
  if (sk == NULL) {
    return -1;
  }

  lastpos++;
  if (lastpos < 0) {
    lastpos = 0;
  }

  crit = !!crit;
  int n = (int)sk_X509_EXTENSION_num(sk);
  for (; lastpos < n; lastpos++) {
    const X509_EXTENSION *ex = sk_X509_EXTENSION_value(sk, lastpos);
    if (X509_EXTENSION_get_critical(ex) == crit) {
      return lastpos;
    }
  }
  return -1;
}

X509_EXTENSION *X509v3_get_ext(const STACK_OF(X509_EXTENSION) *x, int loc) {
  if (x == NULL || loc < 0 || sk_X509_EXTENSION_num(x) <= (size_t)loc) {
    return NULL;
  } else {
    return sk_X509_EXTENSION_value(x, loc);
  }
}

X509_EXTENSION *X509v3_delete_ext(STACK_OF(X509_EXTENSION) *x, int loc) {
  X509_EXTENSION *ret;

  if (x == NULL || loc < 0 || sk_X509_EXTENSION_num(x) <= (size_t)loc) {
    return NULL;
  }
  ret = sk_X509_EXTENSION_delete(x, loc);
  return ret;
}

STACK_OF(X509_EXTENSION) *X509v3_add_ext(STACK_OF(X509_EXTENSION) **x,
                                         const X509_EXTENSION *ex, int loc) {
  X509_EXTENSION *new_ex = NULL;
  STACK_OF(X509_EXTENSION) *sk = NULL;
  int free_sk = 0, n;

  if (x == NULL) {
    OPENSSL_PUT_ERROR(X509, ERR_R_PASSED_NULL_PARAMETER);
    goto err;
  }

  if (*x == NULL) {
    if ((sk = sk_X509_EXTENSION_new_null()) == NULL) {
      goto err;
    }
    free_sk = 1;
  } else {
    sk = *x;
  }

  n = (int)sk_X509_EXTENSION_num(sk);
  if (loc > n) {
    loc = n;
  } else if (loc < 0) {
    loc = n;
  }

  if ((new_ex = X509_EXTENSION_dup(ex)) == NULL) {
    goto err;
  }
  if (!sk_X509_EXTENSION_insert(sk, new_ex, loc)) {
    goto err;
  }
  if (*x == NULL) {
    *x = sk;
  }
  return sk;

err:
  X509_EXTENSION_free(new_ex);
  if (free_sk) {
    sk_X509_EXTENSION_free(sk);
  }
  return NULL;
}

X509_EXTENSION *X509_EXTENSION_create_by_NID(X509_EXTENSION **ex, int nid,
                                             int crit,
                                             const ASN1_OCTET_STRING *data) {
  const ASN1_OBJECT *obj;
  X509_EXTENSION *ret;

  obj = OBJ_nid2obj(nid);
  if (obj == NULL) {
    OPENSSL_PUT_ERROR(X509, X509_R_UNKNOWN_NID);
    return NULL;
  }
  ret = X509_EXTENSION_create_by_OBJ(ex, obj, crit, data);
  return ret;
}

X509_EXTENSION *X509_EXTENSION_create_by_OBJ(X509_EXTENSION **ex,
                                             const ASN1_OBJECT *obj, int crit,
                                             const ASN1_OCTET_STRING *data) {
  X509_EXTENSION *ret;

  if ((ex == NULL) || (*ex == NULL)) {
    if ((ret = X509_EXTENSION_new()) == NULL) {
      return NULL;
    }
  } else {
    ret = *ex;
  }

  if (!X509_EXTENSION_set_object(ret, obj)) {
    goto err;
  }
  if (!X509_EXTENSION_set_critical(ret, crit)) {
    goto err;
  }
  if (!X509_EXTENSION_set_data(ret, data)) {
    goto err;
  }

  if ((ex != NULL) && (*ex == NULL)) {
    *ex = ret;
  }
  return ret;
err:
  if ((ex == NULL) || (ret != *ex)) {
    X509_EXTENSION_free(ret);
  }
  return NULL;
}

int X509_EXTENSION_set_object(X509_EXTENSION *ex, const ASN1_OBJECT *obj) {
  if ((ex == NULL) || (obj == NULL)) {
    return 0;
  }
  ASN1_OBJECT_free(ex->object);
  ex->object = OBJ_dup(obj);
  return ex->object != NULL;
}

int X509_EXTENSION_set_critical(X509_EXTENSION *ex, int crit) {
  if (ex == NULL) {
    return 0;
  }
  // The critical field is DEFAULT FALSE, so non-critical extensions should omit
  // the value.
  ex->critical = crit ? ASN1_BOOLEAN_TRUE : ASN1_BOOLEAN_NONE;
  return 1;
}

int X509_EXTENSION_set_data(X509_EXTENSION *ex, const ASN1_OCTET_STRING *data) {
  int i;

  if (ex == NULL) {
    return 0;
  }
  i = ASN1_OCTET_STRING_set(ex->value, data->data, data->length);
  if (!i) {
    return 0;
  }
  return 1;
}

ASN1_OBJECT *X509_EXTENSION_get_object(const X509_EXTENSION *ex) {
  if (ex == NULL) {
    return NULL;
  }
  return ex->object;
}

ASN1_OCTET_STRING *X509_EXTENSION_get_data(const X509_EXTENSION *ex) {
  if (ex == NULL) {
    return NULL;
  }
  return ex->value;
}

int X509_EXTENSION_get_critical(const X509_EXTENSION *ex) {
  if (ex == NULL) {
    return 0;
  }
  if (ex->critical > 0) {
    return 1;
  }
  return 0;
}
