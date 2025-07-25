/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com). */

#include <stdio.h>

#include <CKyberBoringSSL_asn1t.h>
#include <CKyberBoringSSL_evp.h>
#include <CKyberBoringSSL_obj.h>
#include <CKyberBoringSSL_x509.h>

#include "internal.h"


// X509_CERT_AUX routines. These are used to encode additional user
// modifiable data about a certificate. This data is appended to the X509
// encoding when the *_X509_AUX routines are used. This means that the
// "traditional" X509 routines will simply ignore the extra data.

static X509_CERT_AUX *aux_get(X509 *x);

ASN1_SEQUENCE(X509_CERT_AUX) = {
    ASN1_SEQUENCE_OF_OPT(X509_CERT_AUX, trust, ASN1_OBJECT),
    ASN1_IMP_SEQUENCE_OF_OPT(X509_CERT_AUX, reject, ASN1_OBJECT, 0),
    ASN1_OPT(X509_CERT_AUX, alias, ASN1_UTF8STRING),
    ASN1_OPT(X509_CERT_AUX, keyid, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(X509_CERT_AUX)

IMPLEMENT_ASN1_FUNCTIONS_const(X509_CERT_AUX)

static X509_CERT_AUX *aux_get(X509 *x) {
  if (!x) {
    return NULL;
  }
  if (!x->aux && !(x->aux = X509_CERT_AUX_new())) {
    return NULL;
  }
  return x->aux;
}

int X509_alias_set1(X509 *x, const uint8_t *name, ossl_ssize_t len) {
  X509_CERT_AUX *aux;
  // TODO(davidben): Empty aliases are not meaningful in PKCS#12, and the
  // getters cannot quite represent them. Also erase the object if |len| is
  // zero.
  if (!name) {
    if (!x || !x->aux || !x->aux->alias) {
      return 1;
    }
    ASN1_UTF8STRING_free(x->aux->alias);
    x->aux->alias = NULL;
    return 1;
  }
  if (!(aux = aux_get(x))) {
    return 0;
  }
  if (!aux->alias && !(aux->alias = ASN1_UTF8STRING_new())) {
    return 0;
  }
  return ASN1_STRING_set(aux->alias, name, len);
}

int X509_keyid_set1(X509 *x, const uint8_t *id, ossl_ssize_t len) {
  X509_CERT_AUX *aux;
  // TODO(davidben): Empty key IDs are not meaningful in PKCS#12, and the
  // getters cannot quite represent them. Also erase the object if |len| is
  // zero.
  if (!id) {
    if (!x || !x->aux || !x->aux->keyid) {
      return 1;
    }
    ASN1_OCTET_STRING_free(x->aux->keyid);
    x->aux->keyid = NULL;
    return 1;
  }
  if (!(aux = aux_get(x))) {
    return 0;
  }
  if (!aux->keyid && !(aux->keyid = ASN1_OCTET_STRING_new())) {
    return 0;
  }
  return ASN1_STRING_set(aux->keyid, id, len);
}

const uint8_t *X509_alias_get0(const X509 *x, int *out_len) {
  const ASN1_UTF8STRING *alias = x->aux != NULL ? x->aux->alias : NULL;
  if (out_len != NULL) {
    *out_len = alias != NULL ? alias->length : 0;
  }
  return alias != NULL ? alias->data : NULL;
}

const uint8_t *X509_keyid_get0(const X509 *x, int *out_len) {
  const ASN1_OCTET_STRING *keyid = x->aux != NULL ? x->aux->keyid : NULL;
  if (out_len != NULL) {
    *out_len = keyid != NULL ? keyid->length : 0;
  }
  return keyid != NULL ? keyid->data : NULL;
}

int X509_add1_trust_object(X509 *x, const ASN1_OBJECT *obj) {
  X509_CERT_AUX *aux;
  ASN1_OBJECT *objtmp = OBJ_dup(obj);
  if (objtmp == NULL) {
    goto err;
  }
  aux = aux_get(x);
  if (aux->trust == NULL) {
    aux->trust = sk_ASN1_OBJECT_new_null();
    if (aux->trust == NULL) {
      goto err;
    }
  }
  if (!sk_ASN1_OBJECT_push(aux->trust, objtmp)) {
    goto err;
  }
  return 1;

err:
  ASN1_OBJECT_free(objtmp);
  return 0;
}

int X509_add1_reject_object(X509 *x, const ASN1_OBJECT *obj) {
  X509_CERT_AUX *aux;
  ASN1_OBJECT *objtmp = OBJ_dup(obj);
  if (objtmp == NULL) {
    goto err;
  }
  aux = aux_get(x);
  if (aux->reject == NULL) {
    aux->reject = sk_ASN1_OBJECT_new_null();
    if (aux->reject == NULL) {
      goto err;
    }
  }
  if (!sk_ASN1_OBJECT_push(aux->reject, objtmp)) {
    goto err;
  }
  return 1;

err:
  ASN1_OBJECT_free(objtmp);
  return 0;
}

void X509_trust_clear(X509 *x) {
  if (x->aux && x->aux->trust) {
    sk_ASN1_OBJECT_pop_free(x->aux->trust, ASN1_OBJECT_free);
    x->aux->trust = NULL;
  }
}

void X509_reject_clear(X509 *x) {
  if (x->aux && x->aux->reject) {
    sk_ASN1_OBJECT_pop_free(x->aux->reject, ASN1_OBJECT_free);
    x->aux->reject = NULL;
  }
}
