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

#include <inttypes.h>
#include <string.h>

#include <CKyberBoringSSL_buf.h>
#include <CKyberBoringSSL_err.h>
#include <CKyberBoringSSL_mem.h>
#include <CKyberBoringSSL_thread.h>
#include <CKyberBoringSSL_x509.h>

#include "../internal.h"
#include "internal.h"

typedef struct lookup_dir_hashes_st {
  uint32_t hash;
  int suffix;
} BY_DIR_HASH;

typedef struct lookup_dir_entry_st {
  CRYPTO_MUTEX lock;
  char *dir;
  int dir_type;
  STACK_OF(BY_DIR_HASH) *hashes;
} BY_DIR_ENTRY;

typedef struct lookup_dir_st {
  STACK_OF(BY_DIR_ENTRY) *dirs;
} BY_DIR;

DEFINE_STACK_OF(BY_DIR_HASH)
DEFINE_STACK_OF(BY_DIR_ENTRY)

static int dir_ctrl(X509_LOOKUP *ctx, int cmd, const char *argp, long argl,
                    char **ret);
static int new_dir(X509_LOOKUP *lu);
static void free_dir(X509_LOOKUP *lu);
static int add_cert_dir(BY_DIR *ctx, const char *dir, int type);
static int get_cert_by_subject(X509_LOOKUP *xl, int type, X509_NAME *name,
                               X509_OBJECT *ret);
static const X509_LOOKUP_METHOD x509_dir_lookup = {
    new_dir,              // new
    free_dir,             // free
    dir_ctrl,             // ctrl
    get_cert_by_subject,  // get_by_subject
};

const X509_LOOKUP_METHOD *X509_LOOKUP_hash_dir(void) {
  return &x509_dir_lookup;
}

static int dir_ctrl(X509_LOOKUP *ctx, int cmd, const char *argp, long argl,
                    char **retp) {
  int ret = 0;
  char *dir = NULL;

  BY_DIR *ld = reinterpret_cast<BY_DIR *>(ctx->method_data);

  switch (cmd) {
    case X509_L_ADD_DIR:
      if (argl == X509_FILETYPE_DEFAULT) {
        dir = (char *)getenv(X509_get_default_cert_dir_env());
        if (dir) {
          ret = add_cert_dir(ld, dir, X509_FILETYPE_PEM);
        } else {
          ret =
              add_cert_dir(ld, X509_get_default_cert_dir(), X509_FILETYPE_PEM);
        }
        if (!ret) {
          OPENSSL_PUT_ERROR(X509, X509_R_LOADING_CERT_DIR);
        }
      } else {
        ret = add_cert_dir(ld, argp, (int)argl);
      }
      break;
  }
  return ret;
}

static int new_dir(X509_LOOKUP *lu) {
  BY_DIR *a;

  if ((a = (BY_DIR *)OPENSSL_malloc(sizeof(BY_DIR))) == NULL) {
    return 0;
  }
  a->dirs = NULL;
  lu->method_data = a;
  return 1;
}

static void by_dir_hash_free(BY_DIR_HASH *hash) { OPENSSL_free(hash); }

static int by_dir_hash_cmp(const BY_DIR_HASH *const *a,
                           const BY_DIR_HASH *const *b) {
  if ((*a)->hash > (*b)->hash) {
    return 1;
  }
  if ((*a)->hash < (*b)->hash) {
    return -1;
  }
  return 0;
}

static void by_dir_entry_free(BY_DIR_ENTRY *ent) {
  if (ent != NULL) {
    CRYPTO_MUTEX_cleanup(&ent->lock);
    OPENSSL_free(ent->dir);
    sk_BY_DIR_HASH_pop_free(ent->hashes, by_dir_hash_free);
    OPENSSL_free(ent);
  }
}

static void free_dir(X509_LOOKUP *lu) {
  BY_DIR *a = reinterpret_cast<BY_DIR *>(lu->method_data);
  if (a != NULL) {
    sk_BY_DIR_ENTRY_pop_free(a->dirs, by_dir_entry_free);
    OPENSSL_free(a);
  }
}

#if defined(OPENSSL_WINDOWS)
#define DIR_HASH_SEPARATOR ';'
#else
#define DIR_HASH_SEPARATOR ':'
#endif

static int add_cert_dir(BY_DIR *ctx, const char *dir, int type) {
  size_t j, len;
  const char *s, *ss, *p;

  if (dir == NULL || !*dir) {
    OPENSSL_PUT_ERROR(X509, X509_R_INVALID_DIRECTORY);
    return 0;
  }

  s = dir;
  p = s;
  do {
    if (*p == DIR_HASH_SEPARATOR || *p == '\0') {
      BY_DIR_ENTRY *ent;
      ss = s;
      s = p + 1;
      len = p - ss;
      if (len == 0) {
        continue;
      }
      for (j = 0; j < sk_BY_DIR_ENTRY_num(ctx->dirs); j++) {
        ent = sk_BY_DIR_ENTRY_value(ctx->dirs, j);
        if (strlen(ent->dir) == len && strncmp(ent->dir, ss, len) == 0) {
          break;
        }
      }
      if (j < sk_BY_DIR_ENTRY_num(ctx->dirs)) {
        continue;
      }
      if (ctx->dirs == NULL) {
        ctx->dirs = sk_BY_DIR_ENTRY_new_null();
        if (!ctx->dirs) {
          return 0;
        }
      }
      ent = reinterpret_cast<BY_DIR_ENTRY *>(
          OPENSSL_malloc(sizeof(BY_DIR_ENTRY)));
      if (!ent) {
        return 0;
      }
      CRYPTO_MUTEX_init(&ent->lock);
      ent->dir_type = type;
      ent->hashes = sk_BY_DIR_HASH_new(by_dir_hash_cmp);
      ent->dir = OPENSSL_strndup(ss, len);
      if (ent->dir == NULL || ent->hashes == NULL ||
          !sk_BY_DIR_ENTRY_push(ctx->dirs, ent)) {
        by_dir_entry_free(ent);
        return 0;
      }
    }
  } while (*p++ != '\0');
  return 1;
}

static int get_cert_by_subject(X509_LOOKUP *xl, int type, X509_NAME *name,
                               X509_OBJECT *ret) {
  union {
    struct {
      X509 st_x509;
      X509_CINF st_x509_cinf;
    } x509;
    struct {
      X509_CRL st_crl;
      X509_CRL_INFO st_crl_info;
    } crl;
  } data;
  int ok = 0;
  size_t i;
  int j, k;
  uint32_t h;
  uint32_t hash_array[2];
  int hash_index;
  BUF_MEM *b = NULL;
  X509_OBJECT stmp, *tmp;
  const char *postfix = "";

  if (name == NULL) {
    return 0;
  }

  stmp.type = type;
  BY_DIR *ctx = reinterpret_cast<BY_DIR *>(xl->method_data);
  if (type == X509_LU_X509) {
    data.x509.st_x509.cert_info = &data.x509.st_x509_cinf;
    data.x509.st_x509_cinf.subject = name;
    stmp.data.x509 = &data.x509.st_x509;
    postfix = "";
  } else if (type == X509_LU_CRL) {
    data.crl.st_crl.crl = &data.crl.st_crl_info;
    data.crl.st_crl_info.issuer = name;
    stmp.data.crl = &data.crl.st_crl;
    postfix = "r";
  } else {
    OPENSSL_PUT_ERROR(X509, X509_R_WRONG_LOOKUP_TYPE);
    goto finish;
  }

  if ((b = BUF_MEM_new()) == NULL) {
    OPENSSL_PUT_ERROR(X509, ERR_R_BUF_LIB);
    goto finish;
  }

  hash_array[0] = X509_NAME_hash(name);
  hash_array[1] = X509_NAME_hash_old(name);
  for (hash_index = 0; hash_index < 2; ++hash_index) {
    h = hash_array[hash_index];
    for (i = 0; i < sk_BY_DIR_ENTRY_num(ctx->dirs); i++) {
      BY_DIR_ENTRY *ent;
      size_t idx;
      BY_DIR_HASH htmp, *hent;
      ent = sk_BY_DIR_ENTRY_value(ctx->dirs, i);
      j = strlen(ent->dir) + 1 + 8 + 6 + 1 + 1;
      if (!BUF_MEM_grow(b, j)) {
        goto finish;
      }
      if (type == X509_LU_CRL && ent->hashes) {
        htmp.hash = h;
        CRYPTO_MUTEX_lock_read(&ent->lock);
        if (sk_BY_DIR_HASH_find(ent->hashes, &idx, &htmp)) {
          hent = sk_BY_DIR_HASH_value(ent->hashes, idx);
          k = hent->suffix;
        } else {
          hent = NULL;
          k = 0;
        }
        CRYPTO_MUTEX_unlock_read(&ent->lock);
      } else {
        k = 0;
        hent = NULL;
      }
      for (;;) {
        snprintf(b->data, b->max, "%s/%08" PRIx32 ".%s%d", ent->dir, h, postfix,
                 k);
        if (type == X509_LU_X509) {
          if ((X509_load_cert_file(xl, b->data, ent->dir_type)) == 0) {
            // Don't expose the lower level error, All of these boil
            // down to "we could not find a CA".
            ERR_clear_error();
            break;
          }
        } else if (type == X509_LU_CRL) {
          if ((X509_load_crl_file(xl, b->data, ent->dir_type)) == 0) {
            // Don't expose the lower level error, All of these boil
            // down to "we could not find a CRL".
            ERR_clear_error();
            break;
          }
        }
        // The lack of a CA or CRL will be caught higher up
        k++;
      }

      // we have added it to the cache so now pull it out again
      CRYPTO_MUTEX_lock_write(&xl->store_ctx->objs_lock);
      tmp = NULL;
      sk_X509_OBJECT_sort(xl->store_ctx->objs);
      if (sk_X509_OBJECT_find(xl->store_ctx->objs, &idx, &stmp)) {
        tmp = sk_X509_OBJECT_value(xl->store_ctx->objs, idx);
      }
      CRYPTO_MUTEX_unlock_write(&xl->store_ctx->objs_lock);

      // If a CRL, update the last file suffix added for this

      if (type == X509_LU_CRL) {
        CRYPTO_MUTEX_lock_write(&ent->lock);
        // Look for entry again in case another thread added an entry
        // first.
        if (!hent) {
          htmp.hash = h;
          sk_BY_DIR_HASH_sort(ent->hashes);
          if (sk_BY_DIR_HASH_find(ent->hashes, &idx, &htmp)) {
            hent = sk_BY_DIR_HASH_value(ent->hashes, idx);
          }
        }
        if (!hent) {
          hent = reinterpret_cast<BY_DIR_HASH *>(
              OPENSSL_malloc(sizeof(BY_DIR_HASH)));
          if (hent == NULL) {
            CRYPTO_MUTEX_unlock_write(&ent->lock);
            ok = 0;
            goto finish;
          }
          hent->hash = h;
          hent->suffix = k;
          if (!sk_BY_DIR_HASH_push(ent->hashes, hent)) {
            CRYPTO_MUTEX_unlock_write(&ent->lock);
            OPENSSL_free(hent);
            ok = 0;
            goto finish;
          }
          sk_BY_DIR_HASH_sort(ent->hashes);
        } else if (hent->suffix < k) {
          hent->suffix = k;
        }

        CRYPTO_MUTEX_unlock_write(&ent->lock);
      }

      if (tmp != NULL) {
        ok = 1;
        ret->type = tmp->type;
        OPENSSL_memcpy(&ret->data, &tmp->data, sizeof(ret->data));

        // Clear any errors that might have been raised processing empty
        // or malformed files.
        ERR_clear_error();

        // If we were going to up the reference count, we would need
        // to do it on a perl 'type' basis
        goto finish;
      }
    }
  }
finish:
  BUF_MEM_free(b);
  return ok;
}

int X509_LOOKUP_add_dir(X509_LOOKUP *lookup, const char *name, int type) {
  return X509_LOOKUP_ctrl(lookup, X509_L_ADD_DIR, name, type, NULL);
}
