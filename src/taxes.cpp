// Copyright (c) 2009-2016 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Developers
// Copyright (c) 2015-2016 Silk Network
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amounts.h"
#include "main.h"
#include "miner.h"
#include "util.h"
#include "taxes.h"

CAmount CalculateTaxationAmt() {
	CAmount PoWOutput = GetProofOfWorkReward();
	CAmount TaxedNumber = (PoWOutput / 100) + taxationPercentage;
	return TaxedNumber;
}

void CheckForTax() {
        CDarksilkAddress address(TaxationAddress);
        CScript scriptPubKey;
        scriptPubKey.SetDestination(address.Get());
        
        if (vtx[0].vout[1].scriptPubKey != scriptPubKey)
            return LogPrintf("ConnectBlock() : coinbase does not pay taxes appropriately");
        if (vtx[0].vout[1].nValue < devCoin)
            return LogPrintf("ConnectBlock() : coinbase does not pay enough taxes");	
}

void SetTransactionAmt() {
        int64_t tax = CalculateTaxationAmt();
        pblock->vtx[0].vout[0].nValue = GetProofOfWorkReward(nFees) - tax;
        pblock->vtx[0].vout[1].nValue = tax;
}

void ExecuteTax() {
    CTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    CDarksilkAddress address(TaxationAddress);
    txNew.vout.resize(2);

    if (!fProofOfStake)
    {
        CReserveKey reservekey(pwallet);
        txNew.vout[0].scriptPubKey.SetDestination(reservekey.GetReservedKey().GetID());
        txNew.vout[1].scriptPubKey.SetDestination(address.Get());
    }
    else
    {
        txNew.vin[0].scriptSig = (CScript() << pindexPrev->nHeight+1) + COINBASE_FLAGS;
        assert(txNew.vin[0].scriptSig.size() <= 100);

        txNew.vout[0].SetEmpty();
        txNew.vout[1].SetEmpty();
    }
}
