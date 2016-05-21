// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2016 Silk Network
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DARKSILK_CONSENSUS_CONSENSUS_H
#define DARKSILK_CONSENSUS_CONSENSUS_H

/** Flags for LockTime() */
enum {
    /* Use GetMedianTimePast() instead of nTime for end point timestamp. */
    LOCKTIME_MEDIAN_TIME_PAST = (1 << 1),
};

#endif // DARKSILK_CONSENSUS_CONSENSUS_H