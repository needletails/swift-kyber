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
#include <CKyberBoringSSL_err.h>
#include <CKyberBoringSSL_obj.h>
#include <CKyberBoringSSL_x509.h>

#include "../asn1/internal.h"
#include "internal.h"


X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_NID(X509_ATTRIBUTE **attr, int nid,
                                             int attrtype, const void *data,
                                             int len) {
  const ASN1_OBJECT *obj;

  obj = OBJ_nid2obj(nid);
  if (obj == NULL) {
    OPENSSL_PUT_ERROR(X509, X509_R_UNKNOWN_NID);
    return NULL;
  }
  return X509_ATTRIBUTE_create_by_OBJ(attr, obj, attrtype, data, len);
}

X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_OBJ(X509_ATTRIBUTE **attr,
                                             const ASN1_OBJECT *obj,
                                             int attrtype, const void *data,
                                             int len) {
  X509_ATTRIBUTE *ret;

  if ((attr == NULL) || (*attr == NULL)) {
    if ((ret = X509_ATTRIBUTE_new()) == NULL) {
      return NULL;
    }
  } else {
    ret = *attr;
  }

  if (!X509_ATTRIBUTE_set1_object(ret, obj)) {
    goto err;
  }
  if (!X509_ATTRIBUTE_set1_data(ret, attrtype, data, len)) {
    goto err;
  }

  if ((attr != NULL) && (*attr == NULL)) {
    *attr = ret;
  }
  return ret;
err:
  if ((attr == NULL) || (ret != *attr)) {
    X509_ATTRIBUTE_free(ret);
  }
  return NULL;
}

X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_txt(X509_ATTRIBUTE **attr,
                                             const char *attrname, int type,
                                             const unsigned char *bytes,
                                             int len) {
  ASN1_OBJECT *obj;
  X509_ATTRIBUTE *nattr;

  obj = OBJ_txt2obj(attrname, 0);
  if (obj == NULL) {
    OPENSSL_PUT_ERROR(X509, X509_R_INVALID_FIELD_NAME);
    ERR_add_error_data(2, "name=", attrname);
    return NULL;
  }
  nattr = X509_ATTRIBUTE_create_by_OBJ(attr, obj, type, bytes, len);
  ASN1_OBJECT_free(obj);
  return nattr;
}

int X509_ATTRIBUTE_set1_object(X509_ATTRIBUTE *attr, const ASN1_OBJECT *obj) {
  if ((attr == NULL) || (obj == NULL)) {
    return 0;
  }
  ASN1_OBJECT_free(attr->object);
  attr->object = OBJ_dup(obj);
  return attr->object != NULL;
}

int X509_ATTRIBUTE_set1_data(X509_ATTRIBUTE *attr, int attrtype,
                             const void *data, int len) {
  if (!attr) {
    return 0;
  }

  if (attrtype == 0) {
    // Do nothing. This is used to create an empty value set in
    // |X509_ATTRIBUTE_create_by_*|. This is invalid, but supported by OpenSSL.
    return 1;
  }

  ASN1_TYPE *typ = ASN1_TYPE_new();
  if (typ == NULL) {
    return 0;
  }

  // This function is several functions in one.
  if (attrtype & MBSTRING_FLAG) {
    // |data| is an encoded string. We must decode and re-encode it to |attr|'s
    // preferred ASN.1 type. Note |len| may be -1, in which case
    // |ASN1_STRING_set_by_NID| calls |strlen| automatically.
    ASN1_STRING *str =
        ASN1_STRING_set_by_NID(NULL, reinterpret_cast<const uint8_t *>(data),
                               len, attrtype, OBJ_obj2nid(attr->object));
    if (str == NULL) {
      OPENSSL_PUT_ERROR(X509, ERR_R_ASN1_LIB);
      goto err;
    }
    asn1_type_set0_string(typ, str);
  } else if (len != -1) {
    // |attrtype| must be a valid |ASN1_STRING| type. |data| and |len| is a
    // value in the corresponding |ASN1_STRING| representation.
    ASN1_STRING *str = ASN1_STRING_type_new(attrtype);
    if (str == NULL || !ASN1_STRING_set(str, data, len)) {
      ASN1_STRING_free(str);
      goto err;
    }
    asn1_type_set0_string(typ, str);
  } else {
    // |attrtype| must be a valid |ASN1_TYPE| type. |data| is a pointer to an
    // object of the corresponding type.
    if (!ASN1_TYPE_set1(typ, attrtype, data)) {
      goto err;
    }
  }

  if (!sk_ASN1_TYPE_push(attr->set, typ)) {
    goto err;
  }
  return 1;

err:
  ASN1_TYPE_free(typ);
  return 0;
}

int X509_ATTRIBUTE_count(const X509_ATTRIBUTE *attr) {
  return (int)sk_ASN1_TYPE_num(attr->set);
}

ASN1_OBJECT *X509_ATTRIBUTE_get0_object(X509_ATTRIBUTE *attr) {
  if (attr == NULL) {
    return NULL;
  }
  return attr->object;
}

void *X509_ATTRIBUTE_get0_data(X509_ATTRIBUTE *attr, int idx, int attrtype,
                               void *unused) {
  ASN1_TYPE *ttmp;
  ttmp = X509_ATTRIBUTE_get0_type(attr, idx);
  if (!ttmp) {
    return NULL;
  }
  if (attrtype != ASN1_TYPE_get(ttmp)) {
    OPENSSL_PUT_ERROR(X509, X509_R_WRONG_TYPE);
    return NULL;
  }
  return (void *)asn1_type_value_as_pointer(ttmp);
}

ASN1_TYPE *X509_ATTRIBUTE_get0_type(X509_ATTRIBUTE *attr, int idx) {
  if (attr == NULL) {
    return NULL;
  }
  if (idx >= X509_ATTRIBUTE_count(attr)) {
    return NULL;
  }
  return sk_ASN1_TYPE_value(attr->set, idx);
}
