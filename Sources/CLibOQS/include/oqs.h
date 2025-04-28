//
//  oqs.h
//  swift-kyber
//
//  Created by Cole M on 4/24/25.
//

/**
 * \file oqs.h
 * \brief Overall header file for the liboqs public API.
 *
 * C programs using liboqs can include just this one file, and it will include all
 * other necessary headers from liboqs.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef OQS_H
#define OQS_H

#include <oqsconfig.h>

#include <common.h>
#include <rand.h>
#include <kem.h>
#include <sig.h>
#include <sig_stfl.h>
#include <aes_ops.h>
#include <sha2_ops.h>
#include <sha3_ops.h>
#include <sha3x4_ops.h>

#endif // OQS_H
