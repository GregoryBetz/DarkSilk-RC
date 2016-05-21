// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2016 Silk Network
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DARKSILK_CONSENSUS_CONSENSUS_H
#define DARKSILK_CONSENSUS_CONSENSUS_H


/// The maximum allowed size for a serialized block, in bytes (network rule)
static const unsigned int MAX_BLOCK_SIZE = 20000000; // 20MB Maximum Block Size (50x Bitcoin Core)
// The maximum allowed number of signature check operations in a block (network rule)
static const unsigned int MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE/50;

/** Flags for LockTime() */
enum {
    /* Use GetMedianTimePast() instead of nTime for end point timestamp. */
    LOCKTIME_MEDIAN_TIME_PAST = (1 << 1),
};

#endif // DARKSILK_CONSENSUS_CONSENSUS_H