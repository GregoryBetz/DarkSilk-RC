// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DARKSILK_POW_H
#define DARKSILK_POW_H

#include <stdint.h>

static const int64_t POW_DRIFT = 10 * 60; // 600 seconds
static const int64_t POS_DRIFT = 10 * 64; // 640 seconds

// TODO (Amir): Move CheckProofOfWork to pow.cpp/h.
///! Check whether a block hash satisfies the proof-of-work requirement specified by nBits
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params&);
bool CheckProofOfWork(uint256 hash, unsigned int nBits);

inline int64_t FutureDrift(int64_t nTime, bool fProofOfStake=false) { return nTime + (fProofOfStake ? POS_DRIFT : POW_DRIFT); }

unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, bool fProofOfStake);

#endif
