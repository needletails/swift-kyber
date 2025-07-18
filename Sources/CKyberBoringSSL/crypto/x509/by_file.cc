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

#include <stdlib.h>

#include <CKyberBoringSSL_err.h>
#include <CKyberBoringSSL_pem.h>
#include <CKyberBoringSSL_thread.h>

#include "internal.h"


static int by_file_ctrl(X509_LOOKUP *ctx, int cmd, const char *argc, long argl,
                        char **ret);
static const X509_LOOKUP_METHOD x509_file_lookup = {
    NULL,          // new
    NULL,          // free
    by_file_ctrl,  // ctrl
    NULL,          // get_by_subject
};

const X509_LOOKUP_METHOD *X509_LOOKUP_file(void) { return &x509_file_lookup; }

static int by_file_ctrl(X509_LOOKUP *ctx, int cmd, const char *argp, long argl,
                        char **ret) {
  if (cmd != X509_L_FILE_LOAD) {
    return 0;
  }
  const char *file = argp;
  int type = argl;
  if (argl == X509_FILETYPE_DEFAULT) {
    if ((file = getenv(X509_get_default_cert_file_env())) == NULL) {
      file = X509_get_default_cert_file();
    }
    type = X509_FILETYPE_PEM;
  }
  if (X509_load_cert_crl_file(ctx, file, type) != 0) {
    return 1;
  }
  if (argl == X509_FILETYPE_DEFAULT) {
    OPENSSL_PUT_ERROR(X509, X509_R_LOADING_DEFAULTS);
  }
  return 0;
}

int X509_load_cert_file(X509_LOOKUP *ctx, const char *file, int type) {
  int ret = 0;
  BIO *in = NULL;
  int i, count = 0;
  X509 *x = NULL;

  in = BIO_new(BIO_s_file());

  if ((in == NULL) || (BIO_read_filename(in, file) <= 0)) {
    OPENSSL_PUT_ERROR(X509, ERR_R_SYS_LIB);
    goto err;
  }

  if (type == X509_FILETYPE_PEM) {
    for (;;) {
      x = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
      if (x == NULL) {
        uint32_t error = ERR_peek_last_error();
        if (ERR_GET_LIB(error) == ERR_LIB_PEM &&
            ERR_GET_REASON(error) == PEM_R_NO_START_LINE && count > 0) {
          ERR_clear_error();
          break;
        }
        OPENSSL_PUT_ERROR(X509, ERR_R_PEM_LIB);
        goto err;
      }
      i = X509_STORE_add_cert(ctx->store_ctx, x);
      if (!i) {
        goto err;
      }
      count++;
      X509_free(x);
      x = NULL;
    }
    ret = count;
  } else if (type == X509_FILETYPE_ASN1) {
    x = d2i_X509_bio(in, NULL);
    if (x == NULL) {
      OPENSSL_PUT_ERROR(X509, ERR_R_ASN1_LIB);
      goto err;
    }
    i = X509_STORE_add_cert(ctx->store_ctx, x);
    if (!i) {
      goto err;
    }
    ret = i;
  } else {
    OPENSSL_PUT_ERROR(X509, X509_R_BAD_X509_FILETYPE);
    goto err;
  }

  if (ret == 0) {
    OPENSSL_PUT_ERROR(X509, X509_R_NO_CERTIFICATE_FOUND);
  }

err:
  X509_free(x);
  BIO_free(in);
  return ret;
}

int X509_load_crl_file(X509_LOOKUP *ctx, const char *file, int type) {
  int ret = 0;
  BIO *in = NULL;
  int i, count = 0;
  X509_CRL *x = NULL;

  in = BIO_new(BIO_s_file());

  if ((in == NULL) || (BIO_read_filename(in, file) <= 0)) {
    OPENSSL_PUT_ERROR(X509, ERR_R_SYS_LIB);
    goto err;
  }

  if (type == X509_FILETYPE_PEM) {
    for (;;) {
      x = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL);
      if (x == NULL) {
        uint32_t error = ERR_peek_last_error();
        if (ERR_GET_LIB(error) == ERR_LIB_PEM &&
            ERR_GET_REASON(error) == PEM_R_NO_START_LINE && count > 0) {
          ERR_clear_error();
          break;
        }
        OPENSSL_PUT_ERROR(X509, ERR_R_PEM_LIB);
        goto err;
      }
      i = X509_STORE_add_crl(ctx->store_ctx, x);
      if (!i) {
        goto err;
      }
      count++;
      X509_CRL_free(x);
      x = NULL;
    }
    ret = count;
  } else if (type == X509_FILETYPE_ASN1) {
    x = d2i_X509_CRL_bio(in, NULL);
    if (x == NULL) {
      OPENSSL_PUT_ERROR(X509, ERR_R_ASN1_LIB);
      goto err;
    }
    i = X509_STORE_add_crl(ctx->store_ctx, x);
    if (!i) {
      goto err;
    }
    ret = i;
  } else {
    OPENSSL_PUT_ERROR(X509, X509_R_BAD_X509_FILETYPE);
    goto err;
  }

  if (ret == 0) {
    OPENSSL_PUT_ERROR(X509, X509_R_NO_CRL_FOUND);
  }

err:
  X509_CRL_free(x);
  BIO_free(in);
  return ret;
}

int X509_load_cert_crl_file(X509_LOOKUP *ctx, const char *file, int type) {
  STACK_OF(X509_INFO) *inf;
  X509_INFO *itmp;
  BIO *in;
  size_t i;
  int count = 0;

  if (type != X509_FILETYPE_PEM) {
    return X509_load_cert_file(ctx, file, type);
  }
  in = BIO_new_file(file, "rb");
  if (!in) {
    OPENSSL_PUT_ERROR(X509, ERR_R_SYS_LIB);
    return 0;
  }
  inf = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL);
  BIO_free(in);
  if (!inf) {
    OPENSSL_PUT_ERROR(X509, ERR_R_PEM_LIB);
    return 0;
  }
  for (i = 0; i < sk_X509_INFO_num(inf); i++) {
    itmp = sk_X509_INFO_value(inf, i);
    if (itmp->x509) {
      if (!X509_STORE_add_cert(ctx->store_ctx, itmp->x509)) {
        goto err;
      }
      count++;
    }
    if (itmp->crl) {
      if (!X509_STORE_add_crl(ctx->store_ctx, itmp->crl)) {
        goto err;
      }
      count++;
    }
  }

  if (count == 0) {
    OPENSSL_PUT_ERROR(X509, X509_R_NO_CERTIFICATE_OR_CRL_FOUND);
  }

err:
  sk_X509_INFO_pop_free(inf, X509_INFO_free);
  return count;
}

int X509_LOOKUP_load_file(X509_LOOKUP *lookup, const char *name, int type) {
  return X509_LOOKUP_ctrl(lookup, X509_L_FILE_LOAD, name, type, NULL);
}
