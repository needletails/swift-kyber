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

#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <CKyberBoringSSL_digest.h>
#include <CKyberBoringSSL_err.h>
#include <CKyberBoringSSL_mem.h>
#include <CKyberBoringSSL_obj.h>
#include <CKyberBoringSSL_x509.h>

#include "ext_dat.h"
#include "internal.h"


char *i2s_ASN1_OCTET_STRING(const X509V3_EXT_METHOD *method,
                            const ASN1_OCTET_STRING *oct) {
  return x509v3_bytes_to_hex(oct->data, oct->length);
}

ASN1_OCTET_STRING *s2i_ASN1_OCTET_STRING(const X509V3_EXT_METHOD *method,
                                         const X509V3_CTX *ctx,
                                         const char *str) {
  size_t len;
  uint8_t *data = x509v3_hex_to_bytes(str, &len);
  ASN1_OCTET_STRING *oct;
  if (data == NULL) {
    return NULL;
  }
  if (len > INT_MAX) {
    OPENSSL_PUT_ERROR(X509V3, ERR_R_OVERFLOW);
    goto err;
  }

  oct = ASN1_OCTET_STRING_new();
  if (oct == NULL) {
    goto err;
  }
  ASN1_STRING_set0(oct, data, (int)len);
  return oct;

err:
  OPENSSL_free(data);
  return NULL;
}

static char *i2s_ASN1_OCTET_STRING_cb(const X509V3_EXT_METHOD *method,
                                      void *ext) {
  return i2s_ASN1_OCTET_STRING(method,
                               reinterpret_cast<ASN1_OCTET_STRING *>(ext));
}

static void *s2i_skey_id(const X509V3_EXT_METHOD *method, const X509V3_CTX *ctx,
                         const char *str) {
  ASN1_OCTET_STRING *oct;
  ASN1_BIT_STRING *pk;
  unsigned char pkey_dig[EVP_MAX_MD_SIZE];
  unsigned int diglen;

  if (strcmp(str, "hash")) {
    return s2i_ASN1_OCTET_STRING(method, ctx, str);
  }

  if (!(oct = ASN1_OCTET_STRING_new())) {
    return NULL;
  }

  if (ctx && (ctx->flags == X509V3_CTX_TEST)) {
    return oct;
  }

  if (!ctx || (!ctx->subject_req && !ctx->subject_cert)) {
    OPENSSL_PUT_ERROR(X509V3, X509V3_R_NO_PUBLIC_KEY);
    goto err;
  }

  if (ctx->subject_req) {
    pk = ctx->subject_req->req_info->pubkey->public_key;
  } else {
    pk = ctx->subject_cert->cert_info->key->public_key;
  }

  if (!pk) {
    OPENSSL_PUT_ERROR(X509V3, X509V3_R_NO_PUBLIC_KEY);
    goto err;
  }

  if (!EVP_Digest(pk->data, pk->length, pkey_dig, &diglen, EVP_sha1(), NULL)) {
    goto err;
  }

  if (!ASN1_OCTET_STRING_set(oct, pkey_dig, diglen)) {
    goto err;
  }

  return oct;

err:
  ASN1_OCTET_STRING_free(oct);
  return NULL;
}

const X509V3_EXT_METHOD v3_skey_id = {
    NID_subject_key_identifier,
    0,
    ASN1_ITEM_ref(ASN1_OCTET_STRING),
    0,
    0,
    0,
    0,
    i2s_ASN1_OCTET_STRING_cb,
    s2i_skey_id,
    0,
    0,
    0,
    0,
    NULL,
};
