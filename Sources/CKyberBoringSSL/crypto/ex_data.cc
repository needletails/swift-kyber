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
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
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

#include <CKyberBoringSSL_ex_data.h>

#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <CKyberBoringSSL_crypto.h>
#include <CKyberBoringSSL_err.h>
#include <CKyberBoringSSL_mem.h>
#include <CKyberBoringSSL_thread.h>

#include "internal.h"


DEFINE_STACK_OF(CRYPTO_EX_DATA_FUNCS)

struct crypto_ex_data_func_st {
  long argl;   // Arbitary long
  void *argp;  // Arbitary void pointer
  CRYPTO_EX_free *free_func;
  // next points to the next |CRYPTO_EX_DATA_FUNCS| or NULL if this is the last
  // one. It may only be read if synchronized with a read from |num_funcs|.
  CRYPTO_EX_DATA_FUNCS *next;
};

int CRYPTO_get_ex_new_index_ex(CRYPTO_EX_DATA_CLASS *ex_data_class, long argl,
                               void *argp, CRYPTO_EX_free *free_func) {
  CRYPTO_EX_DATA_FUNCS *funcs = reinterpret_cast<CRYPTO_EX_DATA_FUNCS *>(
      OPENSSL_malloc(sizeof(CRYPTO_EX_DATA_FUNCS)));
  if (funcs == NULL) {
    return -1;
  }

  funcs->argl = argl;
  funcs->argp = argp;
  funcs->free_func = free_func;
  funcs->next = NULL;

  CRYPTO_MUTEX_lock_write(&ex_data_class->lock);

  uint32_t num_funcs = CRYPTO_atomic_load_u32(&ex_data_class->num_funcs);
  // The index must fit in |int|.
  if (num_funcs > (size_t)(INT_MAX - ex_data_class->num_reserved)) {
    OPENSSL_PUT_ERROR(CRYPTO, ERR_R_OVERFLOW);
    CRYPTO_MUTEX_unlock_write(&ex_data_class->lock);
    return -1;
  }

  // Append |funcs| to the linked list.
  if (ex_data_class->last == NULL) {
    assert(num_funcs == 0);
    ex_data_class->funcs = funcs;
    ex_data_class->last = funcs;
  } else {
    ex_data_class->last->next = funcs;
    ex_data_class->last = funcs;
  }

  CRYPTO_atomic_store_u32(&ex_data_class->num_funcs, num_funcs + 1);
  CRYPTO_MUTEX_unlock_write(&ex_data_class->lock);
  return (int)num_funcs + ex_data_class->num_reserved;
}

int CRYPTO_set_ex_data(CRYPTO_EX_DATA *ad, int index, void *val) {
  if (index < 0) {
    // A caller that can accidentally pass in an invalid index into this
    // function will hit an memory error if |index| happened to be valid, and
    // expected |val| to be of a different type.
    abort();
  }

  if (ad->sk == NULL) {
    ad->sk = sk_void_new_null();
    if (ad->sk == NULL) {
      return 0;
    }
  }

  // Add NULL values until the stack is long enough.
  for (size_t i = sk_void_num(ad->sk); i <= (size_t)index; i++) {
    if (!sk_void_push(ad->sk, NULL)) {
      return 0;
    }
  }

  sk_void_set(ad->sk, (size_t)index, val);
  return 1;
}

void *CRYPTO_get_ex_data(const CRYPTO_EX_DATA *ad, int idx) {
  if (ad->sk == NULL || idx < 0 || (size_t)idx >= sk_void_num(ad->sk)) {
    return NULL;
  }
  return sk_void_value(ad->sk, idx);
}

void CRYPTO_new_ex_data(CRYPTO_EX_DATA *ad) { ad->sk = NULL; }

void CRYPTO_free_ex_data(CRYPTO_EX_DATA_CLASS *ex_data_class, void *obj,
                         CRYPTO_EX_DATA *ad) {
  if (ad->sk == NULL) {
    // Nothing to do.
    return;
  }

  uint32_t num_funcs = CRYPTO_atomic_load_u32(&ex_data_class->num_funcs);
  // |CRYPTO_get_ex_new_index_ex| will not allocate indices beyond |INT_MAX|.
  assert(num_funcs <= (size_t)(INT_MAX - ex_data_class->num_reserved));

  // Defer dereferencing |ex_data_class->funcs| and |funcs->next|. It must come
  // after the |num_funcs| comparison to be correctly synchronized.
  CRYPTO_EX_DATA_FUNCS *const *funcs = &ex_data_class->funcs;
  for (uint32_t i = 0; i < num_funcs; i++) {
    if ((*funcs)->free_func != NULL) {
      int index = (int)i + ex_data_class->num_reserved;
      void *ptr = CRYPTO_get_ex_data(ad, index);
      (*funcs)->free_func(obj, ptr, ad, index, (*funcs)->argl, (*funcs)->argp);
    }
    funcs = &(*funcs)->next;
  }

  sk_void_free(ad->sk);
  ad->sk = NULL;
}

void CRYPTO_cleanup_all_ex_data(void) {}
