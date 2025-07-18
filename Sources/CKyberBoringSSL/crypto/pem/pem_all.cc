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
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2002 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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

#include <CKyberBoringSSL_bio.h>
#include <CKyberBoringSSL_dh.h>
#include <CKyberBoringSSL_dsa.h>
#include <CKyberBoringSSL_evp.h>
#include <CKyberBoringSSL_pem.h>
#include <CKyberBoringSSL_pkcs7.h>
#include <CKyberBoringSSL_rsa.h>
#include <CKyberBoringSSL_x509.h>

static RSA *pkey_get_rsa(EVP_PKEY *key, RSA **rsa);
static DSA *pkey_get_dsa(EVP_PKEY *key, DSA **dsa);
static EC_KEY *pkey_get_eckey(EVP_PKEY *key, EC_KEY **eckey);

IMPLEMENT_PEM_rw(X509_REQ, X509_REQ, PEM_STRING_X509_REQ, X509_REQ)

IMPLEMENT_PEM_write(X509_REQ_NEW, X509_REQ, PEM_STRING_X509_REQ_OLD, X509_REQ)
IMPLEMENT_PEM_rw(X509_CRL, X509_CRL, PEM_STRING_X509_CRL, X509_CRL)
IMPLEMENT_PEM_rw(PKCS7, PKCS7, PEM_STRING_PKCS7, PKCS7)

// We treat RSA or DSA private keys as a special case. For private keys we
// read in an EVP_PKEY structure with PEM_read_bio_PrivateKey() and extract
// the relevant private key: this means can handle "traditional" and PKCS#8
// formats transparently.
static RSA *pkey_get_rsa(EVP_PKEY *key, RSA **rsa) {
  RSA *rtmp;
  if (!key) {
    return NULL;
  }
  rtmp = EVP_PKEY_get1_RSA(key);
  EVP_PKEY_free(key);
  if (!rtmp) {
    return NULL;
  }
  if (rsa) {
    RSA_free(*rsa);
    *rsa = rtmp;
  }
  return rtmp;
}

RSA *PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **rsa, pem_password_cb *cb,
                                void *u) {
  EVP_PKEY *pktmp;
  pktmp = PEM_read_bio_PrivateKey(bp, NULL, cb, u);
  return pkey_get_rsa(pktmp, rsa);
}

RSA *PEM_read_RSAPrivateKey(FILE *fp, RSA **rsa, pem_password_cb *cb, void *u) {
  EVP_PKEY *pktmp;
  pktmp = PEM_read_PrivateKey(fp, NULL, cb, u);
  return pkey_get_rsa(pktmp, rsa);
}

IMPLEMENT_PEM_write_cb_const(RSAPrivateKey, RSA, PEM_STRING_RSA, RSAPrivateKey)


IMPLEMENT_PEM_rw_const(RSAPublicKey, RSA, PEM_STRING_RSA_PUBLIC, RSAPublicKey)
IMPLEMENT_PEM_rw(RSA_PUBKEY, RSA, PEM_STRING_PUBLIC, RSA_PUBKEY)
#ifndef OPENSSL_NO_DSA
static DSA *pkey_get_dsa(EVP_PKEY *key, DSA **dsa) {
  DSA *dtmp;
  if (!key) {
    return NULL;
  }
  dtmp = EVP_PKEY_get1_DSA(key);
  EVP_PKEY_free(key);
  if (!dtmp) {
    return NULL;
  }
  if (dsa) {
    DSA_free(*dsa);
    *dsa = dtmp;
  }
  return dtmp;
}

DSA *PEM_read_bio_DSAPrivateKey(BIO *bp, DSA **dsa, pem_password_cb *cb,
                                void *u) {
  EVP_PKEY *pktmp;
  pktmp = PEM_read_bio_PrivateKey(bp, NULL, cb, u);
  return pkey_get_dsa(pktmp, dsa);  // will free pktmp
}

IMPLEMENT_PEM_write_cb_const(DSAPrivateKey, DSA, PEM_STRING_DSA, DSAPrivateKey)

IMPLEMENT_PEM_rw(DSA_PUBKEY, DSA, PEM_STRING_PUBLIC, DSA_PUBKEY)
DSA *PEM_read_DSAPrivateKey(FILE *fp, DSA **dsa, pem_password_cb *cb, void *u) {
  EVP_PKEY *pktmp;
  pktmp = PEM_read_PrivateKey(fp, NULL, cb, u);
  return pkey_get_dsa(pktmp, dsa);  // will free pktmp
}

IMPLEMENT_PEM_rw_const(DSAparams, DSA, PEM_STRING_DSAPARAMS, DSAparams)
#endif
static EC_KEY *pkey_get_eckey(EVP_PKEY *key, EC_KEY **eckey) {
  EC_KEY *dtmp;
  if (!key) {
    return NULL;
  }
  dtmp = EVP_PKEY_get1_EC_KEY(key);
  EVP_PKEY_free(key);
  if (!dtmp) {
    return NULL;
  }
  if (eckey) {
    EC_KEY_free(*eckey);
    *eckey = dtmp;
  }
  return dtmp;
}

EC_KEY *PEM_read_bio_ECPrivateKey(BIO *bp, EC_KEY **key, pem_password_cb *cb,
                                  void *u) {
  EVP_PKEY *pktmp;
  pktmp = PEM_read_bio_PrivateKey(bp, NULL, cb, u);
  return pkey_get_eckey(pktmp, key);  // will free pktmp
}

IMPLEMENT_PEM_write_cb(ECPrivateKey, EC_KEY, PEM_STRING_ECPRIVATEKEY,
                       ECPrivateKey)

IMPLEMENT_PEM_rw(EC_PUBKEY, EC_KEY, PEM_STRING_PUBLIC, EC_PUBKEY)
EC_KEY *PEM_read_ECPrivateKey(FILE *fp, EC_KEY **eckey, pem_password_cb *cb,
                              void *u) {
  EVP_PKEY *pktmp;
  pktmp = PEM_read_PrivateKey(fp, NULL, cb, u);
  return pkey_get_eckey(pktmp, eckey);  // will free pktmp
}


IMPLEMENT_PEM_rw_const(DHparams, DH, PEM_STRING_DHPARAMS, DHparams)

IMPLEMENT_PEM_rw(PUBKEY, EVP_PKEY, PEM_STRING_PUBLIC, PUBKEY)
