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

#include <CKyberBoringSSL_asn1t.h>
#include <CKyberBoringSSL_mem.h>

#include "internal.h"

// Free up an ASN1 structure

void ASN1_item_free(ASN1_VALUE *val, const ASN1_ITEM *it) {
  ASN1_item_ex_free(&val, it);
}

void ASN1_item_ex_free(ASN1_VALUE **pval, const ASN1_ITEM *it) {
  if (!pval) {
    return;
  }
  if ((it->itype != ASN1_ITYPE_PRIMITIVE) && !*pval) {
    return;
  }

  switch (it->itype) {
    case ASN1_ITYPE_PRIMITIVE:
      if (it->templates) {
        ASN1_template_free(pval, it->templates);
      } else {
        ASN1_primitive_free(pval, it);
      }
      break;

    case ASN1_ITYPE_MSTRING:
      ASN1_primitive_free(pval, it);
      break;

    case ASN1_ITYPE_CHOICE: {
      const ASN1_AUX *aux = reinterpret_cast<const ASN1_AUX *>(it->funcs);
      ASN1_aux_cb *asn1_cb = aux != NULL ? aux->asn1_cb : NULL;
      if (asn1_cb) {
        if (asn1_cb(ASN1_OP_FREE_PRE, pval, it, NULL) == 2) {
          return;
        }
      }
      int i = asn1_get_choice_selector(pval, it);
      if ((i >= 0) && (i < it->tcount)) {
        const ASN1_TEMPLATE *tt = it->templates + i;
        ASN1_VALUE **pchval = asn1_get_field_ptr(pval, tt);
        ASN1_template_free(pchval, tt);
      }
      if (asn1_cb) {
        asn1_cb(ASN1_OP_FREE_POST, pval, it, NULL);
      }
      OPENSSL_free(*pval);
      *pval = NULL;
      break;
    }

    case ASN1_ITYPE_EXTERN: {
      const ASN1_EXTERN_FUNCS *ef =
          reinterpret_cast<const ASN1_EXTERN_FUNCS *>(it->funcs);
      if (ef && ef->asn1_ex_free) {
        ef->asn1_ex_free(pval, it);
      }
      break;
    }

    case ASN1_ITYPE_SEQUENCE: {
      if (!asn1_refcount_dec_and_test_zero(pval, it)) {
        return;
      }
      const ASN1_AUX *aux = reinterpret_cast<const ASN1_AUX *>(it->funcs);
      ASN1_aux_cb *asn1_cb = aux != NULL ? aux->asn1_cb : NULL;
      if (asn1_cb) {
        if (asn1_cb(ASN1_OP_FREE_PRE, pval, it, NULL) == 2) {
          return;
        }
      }
      asn1_enc_free(pval, it);
      // If we free up as normal we will invalidate any ANY DEFINED BY
      // field and we wont be able to determine the type of the field it
      // defines. So free up in reverse order.
      for (int i = it->tcount - 1; i >= 0; i--) {
        const ASN1_TEMPLATE *seqtt = asn1_do_adb(pval, &it->templates[i], 0);
        if (!seqtt) {
          continue;
        }
        ASN1_VALUE **pseqval = asn1_get_field_ptr(pval, seqtt);
        ASN1_template_free(pseqval, seqtt);
      }
      if (asn1_cb) {
        asn1_cb(ASN1_OP_FREE_POST, pval, it, NULL);
      }
      OPENSSL_free(*pval);
      *pval = NULL;
      break;
    }
  }
}

void ASN1_template_free(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt) {
  if (tt->flags & ASN1_TFLG_SK_MASK) {
    STACK_OF(ASN1_VALUE) *sk = (STACK_OF(ASN1_VALUE) *)*pval;
    for (size_t i = 0; i < sk_ASN1_VALUE_num(sk); i++) {
      ASN1_VALUE *vtmp = sk_ASN1_VALUE_value(sk, i);
      ASN1_item_ex_free(&vtmp, ASN1_ITEM_ptr(tt->item));
    }
    sk_ASN1_VALUE_free(sk);
    *pval = NULL;
  } else {
    ASN1_item_ex_free(pval, ASN1_ITEM_ptr(tt->item));
  }
}

void ASN1_primitive_free(ASN1_VALUE **pval, const ASN1_ITEM *it) {
  // Historically, |it->funcs| for primitive types contained an
  // |ASN1_PRIMITIVE_FUNCS| table of calbacks.
  assert(it->funcs == NULL);

  int utype = it->itype == ASN1_ITYPE_MSTRING ? -1 : it->utype;
  switch (utype) {
    case V_ASN1_OBJECT:
      ASN1_OBJECT_free((ASN1_OBJECT *)*pval);
      break;

    case V_ASN1_BOOLEAN:
      if (it) {
        *(ASN1_BOOLEAN *)pval = (ASN1_BOOLEAN)it->size;
      } else {
        *(ASN1_BOOLEAN *)pval = ASN1_BOOLEAN_NONE;
      }
      return;

    case V_ASN1_NULL:
      break;

    case V_ASN1_ANY:
      if (*pval != NULL) {
        asn1_type_cleanup((ASN1_TYPE *)*pval);
        OPENSSL_free(*pval);
      }
      break;

    default:
      ASN1_STRING_free((ASN1_STRING *)*pval);
      *pval = NULL;
      break;
  }
  *pval = NULL;
}
