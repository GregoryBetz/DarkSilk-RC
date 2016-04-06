// Copyright (c) 2014-2016 The Bitcoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DARKSILK_CRYPTO_BLAKE2B256_H
#define DARKSILK_CRYPTO_BLAKE2B256_H

#include <stdint.h>
#include <stdlib.h>

#include "crypto/argon2/blake2/blake2.h"

/** A hasher class for BLAKE2B-256. */
class CBLAKE2B256
{
private:
    blake2b_state S[8];
    unsigned char buf[64];
    size_t bytes;

public:
    static const size_t OUTPUT_SIZE = 32;

    CBLAKE2B256();
    CBLAKE2B256& Write(const unsigned char* data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    CBLAKE2B256& Reset();
};

#endif // DARKSILK_CRYPTO_BLAKE2B256_H


