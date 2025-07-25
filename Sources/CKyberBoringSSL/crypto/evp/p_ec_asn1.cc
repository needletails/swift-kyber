/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2006.
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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

#include <CKyberBoringSSL_evp.h>

#include <CKyberBoringSSL_bn.h>
#include <CKyberBoringSSL_bytestring.h>
#include <CKyberBoringSSL_ec.h>
#include <CKyberBoringSSL_ec_key.h>
#include <CKyberBoringSSL_ecdsa.h>
#include <CKyberBoringSSL_err.h>

#include "internal.h"


static int eckey_pub_encode(CBB *out, const EVP_PKEY *key) {
  const EC_KEY *ec_key = reinterpret_cast<const EC_KEY *>(key->pkey);
  const EC_GROUP *group = EC_KEY_get0_group(ec_key);
  const EC_POINT *public_key = EC_KEY_get0_public_key(ec_key);

  // See RFC 5480, section 2.
  CBB spki, algorithm, oid, key_bitstring;
  if (!CBB_add_asn1(out, &spki, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&spki, &algorithm, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&algorithm, &oid, CBS_ASN1_OBJECT) ||
      !CBB_add_bytes(&oid, ec_asn1_meth.oid, ec_asn1_meth.oid_len) ||
      !EC_KEY_marshal_curve_name(&algorithm, group) ||
      !CBB_add_asn1(&spki, &key_bitstring, CBS_ASN1_BITSTRING) ||
      !CBB_add_u8(&key_bitstring, 0 /* padding */) ||
      !EC_POINT_point2cbb(&key_bitstring, group, public_key,
                          POINT_CONVERSION_UNCOMPRESSED, NULL) ||
      !CBB_flush(out)) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_ENCODE_ERROR);
    return 0;
  }

  return 1;
}

static int eckey_pub_decode(EVP_PKEY *out, CBS *params, CBS *key) {
  // See RFC 5480, section 2.

  // The parameters are a named curve.
  EC_KEY *eckey = NULL;
  const EC_GROUP *group = EC_KEY_parse_curve_name(params);
  if (group == NULL || CBS_len(params) != 0) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    goto err;
  }

  eckey = EC_KEY_new();
  if (eckey == NULL ||  //
      !EC_KEY_set_group(eckey, group) ||
      !EC_KEY_oct2key(eckey, CBS_data(key), CBS_len(key), NULL)) {
    goto err;
  }

  EVP_PKEY_assign_EC_KEY(out, eckey);
  return 1;

err:
  EC_KEY_free(eckey);
  return 0;
}

static int eckey_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b) {
  const EC_KEY *a_ec = reinterpret_cast<const EC_KEY *>(a->pkey);
  const EC_KEY *b_ec = reinterpret_cast<const EC_KEY *>(b->pkey);
  const EC_GROUP *group = EC_KEY_get0_group(b_ec);
  const EC_POINT *pa = EC_KEY_get0_public_key(a_ec),
                 *pb = EC_KEY_get0_public_key(b_ec);
  int r = EC_POINT_cmp(group, pa, pb, NULL);
  if (r == 0) {
    return 1;
  } else if (r == 1) {
    return 0;
  } else {
    return -2;
  }
}

static int eckey_priv_decode(EVP_PKEY *out, CBS *params, CBS *key) {
  // See RFC 5915.
  const EC_GROUP *group = EC_KEY_parse_parameters(params);
  if (group == NULL || CBS_len(params) != 0) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return 0;
  }

  EC_KEY *ec_key = EC_KEY_parse_private_key(key, group);
  if (ec_key == NULL || CBS_len(key) != 0) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    EC_KEY_free(ec_key);
    return 0;
  }

  EVP_PKEY_assign_EC_KEY(out, ec_key);
  return 1;
}

static int eckey_priv_encode(CBB *out, const EVP_PKEY *key) {
  const EC_KEY *ec_key = reinterpret_cast<const EC_KEY *>(key->pkey);

  // Omit the redundant copy of the curve name. This contradicts RFC 5915 but
  // aligns with PKCS #11. SEC 1 only says they may be omitted if known by other
  // means. Both OpenSSL and NSS omit the redundant parameters, so we omit them
  // as well.
  unsigned enc_flags = EC_KEY_get_enc_flags(ec_key) | EC_PKEY_NO_PARAMETERS;

  // See RFC 5915.
  CBB pkcs8, algorithm, oid, private_key;
  if (!CBB_add_asn1(out, &pkcs8, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1_uint64(&pkcs8, 0 /* version */) ||
      !CBB_add_asn1(&pkcs8, &algorithm, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&algorithm, &oid, CBS_ASN1_OBJECT) ||
      !CBB_add_bytes(&oid, ec_asn1_meth.oid, ec_asn1_meth.oid_len) ||
      !EC_KEY_marshal_curve_name(&algorithm, EC_KEY_get0_group(ec_key)) ||
      !CBB_add_asn1(&pkcs8, &private_key, CBS_ASN1_OCTETSTRING) ||
      !EC_KEY_marshal_private_key(&private_key, ec_key, enc_flags) ||
      !CBB_flush(out)) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_ENCODE_ERROR);
    return 0;
  }

  return 1;
}

static int eckey_set1_tls_encodedpoint(EVP_PKEY *pkey, const uint8_t *in,
                                       size_t len) {
  EC_KEY *ec_key = reinterpret_cast<EC_KEY *>(pkey->pkey);
  if (ec_key == NULL) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_NO_KEY_SET);
    return 0;
  }

  return EC_KEY_oct2key(ec_key, in, len, NULL);
}

static size_t eckey_get1_tls_encodedpoint(const EVP_PKEY *pkey,
                                          uint8_t **out_ptr) {
  const EC_KEY *ec_key = reinterpret_cast<const EC_KEY *>(pkey->pkey);
  if (ec_key == NULL) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_NO_KEY_SET);
    return 0;
  }

  return EC_KEY_key2buf(ec_key, POINT_CONVERSION_UNCOMPRESSED, out_ptr, NULL);
}

static int int_ec_size(const EVP_PKEY *pkey) {
  const EC_KEY *ec_key = reinterpret_cast<const EC_KEY *>(pkey->pkey);
  return ECDSA_size(ec_key);
}

static int ec_bits(const EVP_PKEY *pkey) {
  const EC_KEY *ec_key = reinterpret_cast<const EC_KEY *>(pkey->pkey);
  const EC_GROUP *group = EC_KEY_get0_group(ec_key);
  if (group == NULL) {
    ERR_clear_error();
    return 0;
  }
  return EC_GROUP_order_bits(group);
}

static int ec_missing_parameters(const EVP_PKEY *pkey) {
  const EC_KEY *ec_key = reinterpret_cast<const EC_KEY *>(pkey->pkey);
  return ec_key == NULL || EC_KEY_get0_group(ec_key) == NULL;
}

static int ec_copy_parameters(EVP_PKEY *to, const EVP_PKEY *from) {
  const EC_KEY *from_key = reinterpret_cast<const EC_KEY *>(from->pkey);
  if (from_key == NULL) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_NO_KEY_SET);
    return 0;
  }
  const EC_GROUP *group = EC_KEY_get0_group(from_key);
  if (group == NULL) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_MISSING_PARAMETERS);
    return 0;
  }
  if (to->pkey == NULL) {
    to->pkey = EC_KEY_new();
    if (to->pkey == NULL) {
      return 0;
    }
  }
  return EC_KEY_set_group(reinterpret_cast<EC_KEY *>(to->pkey), group);
}

static int ec_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b) {
  const EC_KEY *a_ec = reinterpret_cast<const EC_KEY *>(a->pkey);
  const EC_KEY *b_ec = reinterpret_cast<const EC_KEY *>(b->pkey);
  if (a_ec == NULL || b_ec == NULL) {
    return -2;
  }
  const EC_GROUP *group_a = EC_KEY_get0_group(a_ec),
                 *group_b = EC_KEY_get0_group(b_ec);
  if (group_a == NULL || group_b == NULL) {
    return -2;
  }
  if (EC_GROUP_cmp(group_a, group_b, NULL) != 0) {
    // mismatch
    return 0;
  }
  return 1;
}

static void int_ec_free(EVP_PKEY *pkey) {
  EC_KEY_free(reinterpret_cast<EC_KEY *>(pkey->pkey));
  pkey->pkey = NULL;
}

static int eckey_opaque(const EVP_PKEY *pkey) {
  const EC_KEY *ec_key = reinterpret_cast<const EC_KEY *>(pkey->pkey);
  return EC_KEY_is_opaque(ec_key);
}

const EVP_PKEY_ASN1_METHOD ec_asn1_meth = {
    EVP_PKEY_EC,
    // 1.2.840.10045.2.1
    {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01},
    7,

    &ec_pkey_meth,

    eckey_pub_decode,
    eckey_pub_encode,
    eckey_pub_cmp,

    eckey_priv_decode,
    eckey_priv_encode,

    /*set_priv_raw=*/NULL,
    /*set_pub_raw=*/NULL,
    /*get_priv_raw=*/NULL,
    /*get_pub_raw=*/NULL,
    eckey_set1_tls_encodedpoint,
    eckey_get1_tls_encodedpoint,

    eckey_opaque,

    int_ec_size,
    ec_bits,

    ec_missing_parameters,
    ec_copy_parameters,
    ec_cmp_parameters,

    int_ec_free,
};

int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey, EC_KEY *key) {
  if (EVP_PKEY_assign_EC_KEY(pkey, key)) {
    EC_KEY_up_ref(key);
    return 1;
  }
  return 0;
}

int EVP_PKEY_assign_EC_KEY(EVP_PKEY *pkey, EC_KEY *key) {
  evp_pkey_set_method(pkey, &ec_asn1_meth);
  pkey->pkey = key;
  return key != NULL;
}

EC_KEY *EVP_PKEY_get0_EC_KEY(const EVP_PKEY *pkey) {
  if (pkey->type != EVP_PKEY_EC) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_EXPECTING_AN_EC_KEY_KEY);
    return NULL;
  }
  return reinterpret_cast<EC_KEY *>(pkey->pkey);
}

EC_KEY *EVP_PKEY_get1_EC_KEY(const EVP_PKEY *pkey) {
  EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
  if (ec_key != NULL) {
    EC_KEY_up_ref(ec_key);
  }
  return ec_key;
}
