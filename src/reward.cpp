// Copyright (c) 2009-2016 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Developers
// Copyright (c) 2015-2016 Silk Network
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "reward.h"

// miner's coin base reward
CAmount GetProofOfWorkReward(CAmount nFees)
{
    if (pindexBest->nHeight == 0) {
        CAmount nSubsidy = 4000000 * COIN; // 4,000,000 DarkSilk for 4 Phase Crowdfunding
        LogPrint("creation", "GetProofOfWorkReward() : create=%s nSubsidy=%d\n", FormatMoney(nSubsidy), nSubsidy);
        return nSubsidy + nFees;
    }
    else
    {
        LogPrint("creation", "GetProofOfWorkReward() : create=%s nSubsidy=%d\n", FormatMoney(Params().MiningReward()), Params().MiningReward());
        return Params().MiningReward() + nFees;
    }
}

CAmount GetBlockValue(int nBits, int nHeight, const CAmount& nFees, bool fProofOfWork)
{
	CAmount nSubsidy;

	if (fProofOfWork) {
    		 nSubsidy = Params().MiningReward();
	} else { nSubsidy = Params().StakingReward(); }

    return nSubsidy + nFees;
}

CAmount GetStormnodePayment(int nHeight, CAmount blockValue)
{
    CAmount ret = blockValue * 1/5; //20%

    return ret;
}
