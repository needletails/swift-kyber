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

#include <CKyberBoringSSL_asn1.h>

#include <assert.h>
#include <string.h>

#include <CKyberBoringSSL_asn1t.h>
#include <CKyberBoringSSL_err.h>
#include <CKyberBoringSSL_mem.h>
#include <CKyberBoringSSL_obj.h>
#include <CKyberBoringSSL_pool.h>
#include <CKyberBoringSSL_thread.h>

#include "../internal.h"
#include "internal.h"


// Utility functions for manipulating fields and offsets

// Add 'offset' to 'addr'
#define offset2ptr(addr, offset) (void *)(((char *)(addr)) + (offset))

// Given an ASN1_ITEM CHOICE type return the selector value
int asn1_get_choice_selector(ASN1_VALUE **pval, const ASN1_ITEM *it) {
  int *sel = reinterpret_cast<int *>(offset2ptr(*pval, it->utype));
  return *sel;
}

// Given an ASN1_ITEM CHOICE type set the selector value, return old value.
int asn1_set_choice_selector(ASN1_VALUE **pval, int value,
                             const ASN1_ITEM *it) {
  int *sel, ret;
  sel = reinterpret_cast<int *>(offset2ptr(*pval, it->utype));
  ret = *sel;
  *sel = value;
  return ret;
}

static CRYPTO_refcount_t *asn1_get_references(ASN1_VALUE **pval,
                                              const ASN1_ITEM *it) {
  if (it->itype != ASN1_ITYPE_SEQUENCE) {
    return NULL;
  }
  const ASN1_AUX *aux = reinterpret_cast<const ASN1_AUX *>(it->funcs);
  if (!aux || !(aux->flags & ASN1_AFLG_REFCOUNT)) {
    return NULL;
  }
  return reinterpret_cast<CRYPTO_refcount_t *>(
      offset2ptr(*pval, aux->ref_offset));
}

void asn1_refcount_set_one(ASN1_VALUE **pval, const ASN1_ITEM *it) {
  CRYPTO_refcount_t *references = asn1_get_references(pval, it);
  if (references != NULL) {
    *references = 1;
  }
}

int asn1_refcount_dec_and_test_zero(ASN1_VALUE **pval, const ASN1_ITEM *it) {
  CRYPTO_refcount_t *references = asn1_get_references(pval, it);
  if (references != NULL) {
    return CRYPTO_refcount_dec_and_test_zero(references);
  }
  return 1;
}

static ASN1_ENCODING *asn1_get_enc_ptr(ASN1_VALUE **pval, const ASN1_ITEM *it) {
  assert(it->itype == ASN1_ITYPE_SEQUENCE);
  const ASN1_AUX *aux;
  if (!pval || !*pval) {
    return NULL;
  }
  aux = reinterpret_cast<const ASN1_AUX *>(it->funcs);
  if (!aux || !(aux->flags & ASN1_AFLG_ENCODING)) {
    return NULL;
  }
  return reinterpret_cast<ASN1_ENCODING *>(offset2ptr(*pval, aux->enc_offset));
}

void asn1_enc_init(ASN1_VALUE **pval, const ASN1_ITEM *it) {
  ASN1_ENCODING *enc = asn1_get_enc_ptr(pval, it);
  if (enc) {
    enc->enc = NULL;
    enc->len = 0;
    enc->buf = NULL;
  }
}

void asn1_enc_free(ASN1_VALUE **pval, const ASN1_ITEM *it) {
  ASN1_ENCODING *enc = asn1_get_enc_ptr(pval, it);
  if (enc) {
    asn1_encoding_clear(enc);
  }
}

int asn1_enc_save(ASN1_VALUE **pval, const uint8_t *in, size_t in_len,
                  const ASN1_ITEM *it, CRYPTO_BUFFER *buf) {
  ASN1_ENCODING *enc;
  enc = asn1_get_enc_ptr(pval, it);
  if (!enc) {
    return 1;
  }

  asn1_encoding_clear(enc);
  if (buf != NULL) {
    assert(CRYPTO_BUFFER_data(buf) <= in &&
           in + in_len <= CRYPTO_BUFFER_data(buf) + CRYPTO_BUFFER_len(buf));
    CRYPTO_BUFFER_up_ref(buf);
    enc->buf = buf;
    enc->enc = (uint8_t *)in;
  } else {
    enc->enc = reinterpret_cast<uint8_t *>(OPENSSL_memdup(in, in_len));
    if (!enc->enc) {
      return 0;
    }
  }

  enc->len = in_len;
  return 1;
}

void asn1_encoding_clear(ASN1_ENCODING *enc) {
  if (enc->buf != NULL) {
    CRYPTO_BUFFER_free(enc->buf);
  } else {
    OPENSSL_free(enc->enc);
  }
  enc->enc = NULL;
  enc->len = 0;
  enc->buf = NULL;
}

int asn1_enc_restore(int *len, unsigned char **out, ASN1_VALUE **pval,
                     const ASN1_ITEM *it) {
  ASN1_ENCODING *enc = asn1_get_enc_ptr(pval, it);
  if (!enc || enc->len == 0) {
    return 0;
  }
  if (out) {
    OPENSSL_memcpy(*out, enc->enc, enc->len);
    *out += enc->len;
  }
  if (len) {
    *len = enc->len;
  }
  return 1;
}

// Given an ASN1_TEMPLATE get a pointer to a field
ASN1_VALUE **asn1_get_field_ptr(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt) {
  ASN1_VALUE **pvaltmp =
      reinterpret_cast<ASN1_VALUE **>(offset2ptr(*pval, tt->offset));
  // NOTE for BOOLEAN types the field is just a plain int so we can't return
  // int **, so settle for (int *).
  return pvaltmp;
}

// Handle ANY DEFINED BY template, find the selector, look up the relevant
// ASN1_TEMPLATE in the table and return it.
const ASN1_TEMPLATE *asn1_do_adb(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt,
                                 int nullerr) {
  const ASN1_ADB *adb;
  const ASN1_ADB_TABLE *atbl;
  ASN1_VALUE **sfld;
  int i;
  if (!(tt->flags & ASN1_TFLG_ADB_MASK)) {
    return tt;
  }

  // Else ANY DEFINED BY ... get the table
  adb = ASN1_ADB_ptr(tt->item);

  // Get the selector field
  sfld = reinterpret_cast<ASN1_VALUE **>(offset2ptr(*pval, adb->offset));

  // Check if NULL
  int selector;
  if (*sfld == NULL) {
    if (!adb->null_tt) {
      goto err;
    }
    return adb->null_tt;
  }

  // Convert type to a NID:
  // NB: don't check for NID_undef here because it
  // might be a legitimate value in the table
  assert(tt->flags & ASN1_TFLG_ADB_OID);
  selector = OBJ_obj2nid((ASN1_OBJECT *)*sfld);

  // Try to find matching entry in table Maybe should check application types
  // first to allow application override? Might also be useful to have a flag
  // which indicates table is sorted and we can do a binary search. For now
  // stick to a linear search.

  for (atbl = adb->tbl, i = 0; i < adb->tblcount; i++, atbl++) {
    if (atbl->value == selector) {
      return &atbl->tt;
    }
  }

  // FIXME: need to search application table too

  // No match, return default type
  if (!adb->default_tt) {
    goto err;
  }
  return adb->default_tt;

err:
  // FIXME: should log the value or OID of unsupported type
  if (nullerr) {
    OPENSSL_PUT_ERROR(ASN1, ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE);
  }
  return NULL;
}
