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
#include <CKyberBoringSSL_conf.h>
#include <CKyberBoringSSL_err.h>
#include <CKyberBoringSSL_obj.h>
#include <CKyberBoringSSL_x509.h>

#include "ext_dat.h"
#include "internal.h"


static void *v2i_EXTENDED_KEY_USAGE(const X509V3_EXT_METHOD *method,
                                    const X509V3_CTX *ctx,
                                    const STACK_OF(CONF_VALUE) *nval);
static STACK_OF(CONF_VALUE) *i2v_EXTENDED_KEY_USAGE(
    const X509V3_EXT_METHOD *method, void *eku, STACK_OF(CONF_VALUE) *extlist);

const X509V3_EXT_METHOD v3_ext_ku = {
    NID_ext_key_usage,
    0,
    ASN1_ITEM_ref(EXTENDED_KEY_USAGE),
    0,
    0,
    0,
    0,
    0,
    0,
    i2v_EXTENDED_KEY_USAGE,
    v2i_EXTENDED_KEY_USAGE,
    0,
    0,
    NULL,
};

// NB OCSP acceptable responses also is a SEQUENCE OF OBJECT
const X509V3_EXT_METHOD v3_ocsp_accresp = {
    NID_id_pkix_OCSP_acceptableResponses,
    0,
    ASN1_ITEM_ref(EXTENDED_KEY_USAGE),
    0,
    0,
    0,
    0,
    0,
    0,
    i2v_EXTENDED_KEY_USAGE,
    v2i_EXTENDED_KEY_USAGE,
    0,
    0,
    NULL,
};

ASN1_ITEM_TEMPLATE(EXTENDED_KEY_USAGE) = ASN1_EX_TEMPLATE_TYPE(
    ASN1_TFLG_SEQUENCE_OF, 0, EXTENDED_KEY_USAGE, ASN1_OBJECT)
ASN1_ITEM_TEMPLATE_END(EXTENDED_KEY_USAGE)

IMPLEMENT_ASN1_FUNCTIONS_const(EXTENDED_KEY_USAGE)

static STACK_OF(CONF_VALUE) *i2v_EXTENDED_KEY_USAGE(
    const X509V3_EXT_METHOD *method, void *a, STACK_OF(CONF_VALUE) *ext_list) {
  const EXTENDED_KEY_USAGE *eku =
      reinterpret_cast<const EXTENDED_KEY_USAGE *>(a);
  for (size_t i = 0; i < sk_ASN1_OBJECT_num(eku); i++) {
    const ASN1_OBJECT *obj = sk_ASN1_OBJECT_value(eku, i);
    char obj_tmp[80];
    i2t_ASN1_OBJECT(obj_tmp, 80, obj);
    X509V3_add_value(NULL, obj_tmp, &ext_list);
  }
  return ext_list;
}

static void *v2i_EXTENDED_KEY_USAGE(const X509V3_EXT_METHOD *method,
                                    const X509V3_CTX *ctx,
                                    const STACK_OF(CONF_VALUE) *nval) {
  EXTENDED_KEY_USAGE *extku = sk_ASN1_OBJECT_new_null();
  if (extku == NULL) {
    return NULL;
  }

  for (size_t i = 0; i < sk_CONF_VALUE_num(nval); i++) {
    const CONF_VALUE *val = sk_CONF_VALUE_value(nval, i);
    const char *extval;
    if (val->value) {
      extval = val->value;
    } else {
      extval = val->name;
    }
    ASN1_OBJECT *obj = OBJ_txt2obj(extval, 0);
    if (obj == NULL || !sk_ASN1_OBJECT_push(extku, obj)) {
      ASN1_OBJECT_free(obj);
      sk_ASN1_OBJECT_pop_free(extku, ASN1_OBJECT_free);
      OPENSSL_PUT_ERROR(X509V3, X509V3_R_INVALID_OBJECT_IDENTIFIER);
      X509V3_conf_err(val);
      return NULL;
    }
  }

  return extku;
}
