// Copyright (c) 2009-2016 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Developers
// Copyright (c) 2015-2016 Silk Network
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DARKSILK_REWARD_H
#define DARKSILK_REWARD_H

#include "amount.h"
#include "main.h"
#include "reward.h"

CAmount GetProofOfWorkReward(CAmount nFees);
CAmount GetBlockValue(int nBits, int nHeight, const CAmount& nFees, bool fProofOfWork = true);
CAmount GetStormnodePayment(int nHeight, CAmount blockValue);

#endif // DARKSILK_REWARD_H
