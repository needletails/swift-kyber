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

#include <stdio.h>

#include <CKyberBoringSSL_asn1t.h>
#include <CKyberBoringSSL_thread.h>
#include <CKyberBoringSSL_x509.h>

#include "internal.h"


// X509_REQ_INFO is handled in an unusual way to get round invalid encodings.
// Some broken certificate requests don't encode the attributes field if it
// is empty. This is in violation of PKCS#10 but we need to tolerate it. We
// do this by making the attributes field OPTIONAL then using the callback to
// initialise it to an empty STACK. This means that the field will be
// correctly encoded unless we NULL out the field.

static int rinf_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                   void *exarg) {
  X509_REQ_INFO *rinf = (X509_REQ_INFO *)*pval;

  if (operation == ASN1_OP_NEW_POST) {
    rinf->attributes = sk_X509_ATTRIBUTE_new_null();
    if (!rinf->attributes) {
      return 0;
    }
  }

  if (operation == ASN1_OP_D2I_POST) {
    // The only defined CSR version is v1(0). For compatibility, we also accept
    // a hypothetical v3(2). Although not defined, older versions of certbot
    // use it. See https://github.com/certbot/certbot/pull/9334.
    long version = ASN1_INTEGER_get(rinf->version);
    if (version != X509_REQ_VERSION_1 && version != 2) {
      OPENSSL_PUT_ERROR(X509, X509_R_INVALID_VERSION);
      return 0;
    }
  }

  return 1;
}

ASN1_SEQUENCE_enc(X509_REQ_INFO, enc, rinf_cb) = {
    ASN1_SIMPLE(X509_REQ_INFO, version, ASN1_INTEGER),
    ASN1_SIMPLE(X509_REQ_INFO, subject, X509_NAME),
    ASN1_SIMPLE(X509_REQ_INFO, pubkey, X509_PUBKEY),
    // This isn't really OPTIONAL but it gets around invalid encodings.
    ASN1_IMP_SET_OF_OPT(X509_REQ_INFO, attributes, X509_ATTRIBUTE, 0),
} ASN1_SEQUENCE_END_enc(X509_REQ_INFO, X509_REQ_INFO)

IMPLEMENT_ASN1_FUNCTIONS(X509_REQ_INFO)

ASN1_SEQUENCE(X509_REQ) = {
    ASN1_SIMPLE(X509_REQ, req_info, X509_REQ_INFO),
    ASN1_SIMPLE(X509_REQ, sig_alg, X509_ALGOR),
    ASN1_SIMPLE(X509_REQ, signature, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(X509_REQ)

IMPLEMENT_ASN1_FUNCTIONS(X509_REQ)

IMPLEMENT_ASN1_DUP_FUNCTION(X509_REQ)
