// SPDX-License-Identifier: MIT

#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include <CKyberBoringSSL_rand.h>
#include <assert.h>

//#define randombytes OQS_randombytes
static inline void randombytes(uint8_t *random_array, size_t bytes_to_read) {
    int ok = RAND_bytes(random_array, bytes_to_read);
    assert(ok == 1);
}

#endif
