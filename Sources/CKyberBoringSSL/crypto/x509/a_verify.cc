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

#include <CKyberBoringSSL_x509.h>

#include <stdio.h>
#include <sys/types.h>

#include <CKyberBoringSSL_bn.h>
#include <CKyberBoringSSL_digest.h>
#include <CKyberBoringSSL_err.h>
#include <CKyberBoringSSL_evp.h>
#include <CKyberBoringSSL_mem.h>
#include <CKyberBoringSSL_obj.h>

#include "internal.h"

int ASN1_item_verify(const ASN1_ITEM *it, const X509_ALGOR *a,
                     const ASN1_BIT_STRING *signature, void *asn,
                     EVP_PKEY *pkey) {
  if (!pkey) {
    OPENSSL_PUT_ERROR(X509, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  size_t sig_len;
  if (signature->type == V_ASN1_BIT_STRING) {
    if (!ASN1_BIT_STRING_num_bytes(signature, &sig_len)) {
      OPENSSL_PUT_ERROR(X509, X509_R_INVALID_BIT_STRING_BITS_LEFT);
      return 0;
    }
  } else {
    sig_len = (size_t)ASN1_STRING_length(signature);
  }

  EVP_MD_CTX ctx;
  uint8_t *buf_in = NULL;
  int ret = 0, inl = 0;
  EVP_MD_CTX_init(&ctx);

  if (!x509_digest_verify_init(&ctx, a, pkey)) {
    goto err;
  }

  inl = ASN1_item_i2d(reinterpret_cast<ASN1_VALUE *>(asn), &buf_in, it);

  if (buf_in == NULL) {
    goto err;
  }

  if (!EVP_DigestVerify(&ctx, ASN1_STRING_get0_data(signature), sig_len, buf_in,
                        inl)) {
    OPENSSL_PUT_ERROR(X509, ERR_R_EVP_LIB);
    goto err;
  }

  ret = 1;

err:
  OPENSSL_free(buf_in);
  EVP_MD_CTX_cleanup(&ctx);
  return ret;
}
