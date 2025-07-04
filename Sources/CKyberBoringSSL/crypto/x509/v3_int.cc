/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999-2004 The OpenSSL Project.  All rights reserved.
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

#include <CKyberBoringSSL_obj.h>
#include <CKyberBoringSSL_x509.h>

#include "ext_dat.h"


static char *i2s_ASN1_INTEGER_cb(const X509V3_EXT_METHOD *method, void *ext) {
  return i2s_ASN1_INTEGER(method, reinterpret_cast<ASN1_INTEGER *>(ext));
}

static void *s2i_asn1_int(const X509V3_EXT_METHOD *meth, const X509V3_CTX *ctx,
                          const char *value) {
  return s2i_ASN1_INTEGER(meth, value);
}

const X509V3_EXT_METHOD v3_crl_num = {
    NID_crl_number,
    0,
    ASN1_ITEM_ref(ASN1_INTEGER),
    0,
    0,
    0,
    0,
    i2s_ASN1_INTEGER_cb,
    0,
    0,
    0,
    0,
    0,
    NULL,
};

const X509V3_EXT_METHOD v3_delta_crl = {
    NID_delta_crl,
    0,
    ASN1_ITEM_ref(ASN1_INTEGER),
    0,
    0,
    0,
    0,
    i2s_ASN1_INTEGER_cb,
    0,
    0,
    0,
    0,
    0,
    NULL,
};

const X509V3_EXT_METHOD v3_inhibit_anyp = {
    NID_inhibit_any_policy,
    0,
    ASN1_ITEM_ref(ASN1_INTEGER),
    0,
    0,
    0,
    0,
    i2s_ASN1_INTEGER_cb,
    s2i_asn1_int,
    0,
    0,
    0,
    0,
    NULL,
};
