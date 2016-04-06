// Copyright (c) 2014-2016 The Bitcoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/blake256.h"
#include "crypto/common.h"

////// CBLAKE2B256-256

CBLAKE2B256::CBLAKE2B256() : bytes(0)
{
    blake2b_init(S, OUTPUT_SIZE);
}

CBLAKE2B256& CBLAKE2B256::Write(const unsigned char* data, size_t len)
{
    bytes = len;
    blake2b_update(S, ((unsigned char*)&data[0]), bytes);
    return *this;
}

void CBLAKE2B256::Finalize(unsigned char hash[OUTPUT_SIZE])
{
    static const unsigned char pad[64] = {0x80};
    unsigned char sizedesc[8];
    uint64_t s[8];
    s[0] = (uint64_t)S[0].h;
    s[1] = (uint64_t)S[1].h;
    s[2] = (uint64_t)S[2].h;
    s[3] = (uint64_t)S[3].h;
    s[4] = (uint64_t)S[4].h;
    s[5] = (uint64_t)S[5].h;
    s[6] = (uint64_t)S[6].h;
    s[7] = (uint64_t)S[7].h;
    WriteBE32(sizedesc, bytes << 3);
    Write(pad, 1 + ((119 - (bytes % 64)) % 64));
    Write(sizedesc, 8);
    WriteBE32(hash, s[0]);
    WriteBE32(hash + 4, s[1]);
    WriteBE32(hash + 8, s[2]);
    WriteBE32(hash + 12, s[3]);
    WriteBE32(hash + 16, s[4]);
    WriteBE32(hash + 20, s[5]);
    WriteBE32(hash + 24, s[6]);
    WriteBE32(hash + 28, s[7]);
    blake2b_final(S, (unsigned char*)&hash, OUTPUT_SIZE);
}

CBLAKE2B256& CBLAKE2B256::Reset()
{
    bytes = 0;
    blake2b_init(S, OUTPUT_SIZE);
    return *this;
}

