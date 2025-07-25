/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 2003 The OpenSSL Project.  All rights reserved.
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


static void *v2i_POLICY_MAPPINGS(const X509V3_EXT_METHOD *method,
                                 const X509V3_CTX *ctx,
                                 const STACK_OF(CONF_VALUE) *nval);
static STACK_OF(CONF_VALUE) *i2v_POLICY_MAPPINGS(
    const X509V3_EXT_METHOD *method, void *pmps, STACK_OF(CONF_VALUE) *extlist);

const X509V3_EXT_METHOD v3_policy_mappings = {
    NID_policy_mappings,
    0,
    ASN1_ITEM_ref(POLICY_MAPPINGS),
    0,
    0,
    0,
    0,
    0,
    0,
    i2v_POLICY_MAPPINGS,
    v2i_POLICY_MAPPINGS,
    0,
    0,
    NULL,
};

ASN1_SEQUENCE(POLICY_MAPPING) = {
    ASN1_SIMPLE(POLICY_MAPPING, issuerDomainPolicy, ASN1_OBJECT),
    ASN1_SIMPLE(POLICY_MAPPING, subjectDomainPolicy, ASN1_OBJECT),
} ASN1_SEQUENCE_END(POLICY_MAPPING)

ASN1_ITEM_TEMPLATE(POLICY_MAPPINGS) = ASN1_EX_TEMPLATE_TYPE(
    ASN1_TFLG_SEQUENCE_OF, 0, POLICY_MAPPINGS, POLICY_MAPPING)
ASN1_ITEM_TEMPLATE_END(POLICY_MAPPINGS)

IMPLEMENT_ASN1_ALLOC_FUNCTIONS(POLICY_MAPPING)

static STACK_OF(CONF_VALUE) *i2v_POLICY_MAPPINGS(
    const X509V3_EXT_METHOD *method, void *a, STACK_OF(CONF_VALUE) *ext_list) {
  const POLICY_MAPPINGS *pmaps = reinterpret_cast<POLICY_MAPPINGS *>(a);
  for (size_t i = 0; i < sk_POLICY_MAPPING_num(pmaps); i++) {
    const POLICY_MAPPING *pmap = sk_POLICY_MAPPING_value(pmaps, i);
    char obj_tmp1[80], obj_tmp2[80];
    i2t_ASN1_OBJECT(obj_tmp1, 80, pmap->issuerDomainPolicy);
    i2t_ASN1_OBJECT(obj_tmp2, 80, pmap->subjectDomainPolicy);
    X509V3_add_value(obj_tmp1, obj_tmp2, &ext_list);
  }
  return ext_list;
}

static void *v2i_POLICY_MAPPINGS(const X509V3_EXT_METHOD *method,
                                 const X509V3_CTX *ctx,
                                 const STACK_OF(CONF_VALUE) *nval) {
  POLICY_MAPPINGS *pmaps = sk_POLICY_MAPPING_new_null();
  if (pmaps == NULL) {
    return NULL;
  }

  for (size_t i = 0; i < sk_CONF_VALUE_num(nval); i++) {
    const CONF_VALUE *val = sk_CONF_VALUE_value(nval, i);
    if (!val->value || !val->name) {
      OPENSSL_PUT_ERROR(X509V3, X509V3_R_INVALID_OBJECT_IDENTIFIER);
      X509V3_conf_err(val);
      goto err;
    }

    POLICY_MAPPING *pmap = POLICY_MAPPING_new();
    if (pmap == NULL || !sk_POLICY_MAPPING_push(pmaps, pmap)) {
      POLICY_MAPPING_free(pmap);
      goto err;
    }

    pmap->issuerDomainPolicy = OBJ_txt2obj(val->name, 0);
    pmap->subjectDomainPolicy = OBJ_txt2obj(val->value, 0);
    if (!pmap->issuerDomainPolicy || !pmap->subjectDomainPolicy) {
      OPENSSL_PUT_ERROR(X509V3, X509V3_R_INVALID_OBJECT_IDENTIFIER);
      X509V3_conf_err(val);
      goto err;
    }
  }
  return pmaps;

err:
  sk_POLICY_MAPPING_pop_free(pmaps, POLICY_MAPPING_free);
  return NULL;
}
