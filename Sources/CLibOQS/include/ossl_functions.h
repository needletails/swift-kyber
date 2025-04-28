// SPDX-License-Identifier: MIT

#include <stdio.h>
#include <CKyberBoringSSL_evp.h>
#include <CKyberBoringSSL_rand.h>
#include <CKyberBoringSSL_err.h>
#include <CKyberBoringSSL_crypto.h>
#include <CKyberBoringSSL_engine.h>
#include <CKyberBoringSSL_ossl_typ.h>

// Function declarations from OpenSSL used in liboqs:

void ERR_print_errors_fp(FILE *fp);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *c);
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad);
int EVP_DigestFinalXOF(EVP_MD_CTX *ctx, unsigned char *md, size_t len);
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl,
                       const unsigned char *key, const unsigned char *iv);
int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                      const unsigned char *in, int inl);
int EVP_MD_CTX_copy_ex(EVP_MD_CTX *out, const EVP_MD_CTX *in);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
EVP_MD_CTX *EVP_MD_CTX_new(void);
int EVP_MD_CTX_reset(EVP_MD_CTX *ctx);
const EVP_CIPHER *EVP_aes_128_ecb(void);
const EVP_CIPHER *EVP_aes_128_ctr(void);
const EVP_CIPHER *EVP_aes_256_ecb(void);
const EVP_CIPHER *EVP_aes_256_ctr(void);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
EVP_CIPHER *EVP_CIPHER_fetch(OSSL_LIB_CTX *ctx, const char *algorithm, const char *properties);
void EVP_CIPHER_free(EVP_CIPHER *cipher);
EVP_MD *EVP_MD_fetch(OSSL_LIB_CTX *ctx, const char *algorithm, const char *properties);
void EVP_MD_free(EVP_MD *md);
#else
const EVP_MD *EVP_sha256(void);
const EVP_MD *EVP_sha384(void);
//const EVP_MD *EVP_sha3_256(void);
//const EVP_MD *EVP_sha3_384(void);
//const EVP_MD *EVP_sha3_512(void);
const EVP_MD *EVP_sha512(void);
//const EVP_MD *EVP_shake128(void);
//const EVP_MD *EVP_shake256(void);
#endif

void OPENSSL_cleanse(void *ptr, size_t len);
//int RAND_bytes(unsigned char *buf, int num);
int RAND_poll(void);
int RAND_status(void);

// Declare OPENSSL_thread_stop before using it
//void OPENSSL_thread_stop(void);

//void *CRYPTO_malloc(size_t num, const char *file, int line);
//void *CRYPTO_zalloc(size_t num, const char *file, int line);
//char *CRYPTO_strdup(const char *str, const char *file, int line);
void CRYPTO_free(void *ptr, const char *file, int line);
