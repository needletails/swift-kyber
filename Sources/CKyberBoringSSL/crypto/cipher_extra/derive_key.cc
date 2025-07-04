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

#include <CKyberBoringSSL_cipher.h>

#include <assert.h>

#include <CKyberBoringSSL_digest.h>
#include <CKyberBoringSSL_mem.h>


#define PKCS5_SALT_LEN 8

int EVP_BytesToKey(const EVP_CIPHER *type, const EVP_MD *md,
                   const uint8_t *salt, const uint8_t *data, size_t data_len,
                   unsigned count, uint8_t *key, uint8_t *iv) {
  EVP_MD_CTX c;
  uint8_t md_buf[EVP_MAX_MD_SIZE];
  unsigned addmd = 0;
  unsigned mds = 0, i;
  int rv = 0;

  unsigned nkey = EVP_CIPHER_key_length(type);
  unsigned niv = EVP_CIPHER_iv_length(type);

  assert(nkey <= EVP_MAX_KEY_LENGTH);
  assert(niv <= EVP_MAX_IV_LENGTH);

  if (data == NULL) {
    return nkey;
  }

  EVP_MD_CTX_init(&c);
  for (;;) {
    if (!EVP_DigestInit_ex(&c, md, NULL)) {
      goto err;
    }
    if (addmd++) {
      if (!EVP_DigestUpdate(&c, md_buf, mds)) {
        goto err;
      }
    }
    if (!EVP_DigestUpdate(&c, data, data_len)) {
      goto err;
    }
    if (salt != NULL) {
      if (!EVP_DigestUpdate(&c, salt, PKCS5_SALT_LEN)) {
        goto err;
      }
    }
    if (!EVP_DigestFinal_ex(&c, md_buf, &mds)) {
      goto err;
    }

    for (i = 1; i < count; i++) {
      if (!EVP_DigestInit_ex(&c, md, NULL) ||
          !EVP_DigestUpdate(&c, md_buf, mds) ||
          !EVP_DigestFinal_ex(&c, md_buf, &mds)) {
        goto err;
      }
    }

    i = 0;
    if (nkey) {
      for (;;) {
        if (nkey == 0 || i == mds) {
          break;
        }
        if (key != NULL) {
          *(key++) = md_buf[i];
        }
        nkey--;
        i++;
      }
    }

    if (niv && i != mds) {
      for (;;) {
        if (niv == 0 || i == mds) {
          break;
        }
        if (iv != NULL) {
          *(iv++) = md_buf[i];
        }
        niv--;
        i++;
      }
    }
    if (nkey == 0 && niv == 0) {
      break;
    }
  }
  rv = EVP_CIPHER_key_length(type);

err:
  EVP_MD_CTX_cleanup(&c);
  OPENSSL_cleanse(md_buf, EVP_MAX_MD_SIZE);
  return rv;
}
