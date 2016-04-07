// Copyright (c) 2014-2016 The Dash Developers
// Copyright (c) 2009-2016 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef ACTIVESTORMNODE_H
#define ACTIVESTORMNODE_H

#include "sync.h"
#include "key.h"
#include "wallet/wallet.h"

static const int  ACTIVE_STORMNODE_INITIAL = 0; // initial state
static const int  ACTIVE_STORMNODE_SYNC_IN_PROCESS = 1;
static const int  ACTIVE_STORMNODE_INPUT_TOO_NEW = 2;
static const int  ACTIVE_STORMNODE_NOT_CAPABLE = 3;
static const int  ACTIVE_STORMNODE_STARTED = 4;

// Responsible for activating the Stormnode and pinging the network
class CActiveStormnode
{
private:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

    /// Ping Stormnode
    bool SendStormnodePing(std::string& errorMessage);

    /// Register any Stormnode
    bool Register(CTxIn vin, CService service, CKey key, CPubKey pubKey, CKey keyStormnode, CPubKey pubKeyStormnode, std::string &retErrorMessage);

    /// Get 10000 DRKSLK input that can be used for the Stormnode
    bool GetStormNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey, std::string strTxHash, std::string strOutputIndex);
    bool GetVinFromOutput(COutput out, CTxIn& vin, CPubKey& pubkey, CKey& secretKey);

public:
    // Initialized by init.cpp
    // Keys for the main Stormnode
    CPubKey pubKeyStormnode;

    // Initialized while registering Stormnode
    CTxIn vin;
    CService service;

    int status;
    std::string notCapableReason;

    CActiveStormnode()
    {
        status = ACTIVE_STORMNODE_INITIAL;
    }

    /// Manage status of main Stormnode
    void ManageStatus();
    std::string GetStatus();

    /// Register remote Stormnode
    bool Register(std::string strService, std::string strKey, std::string strTxHash, std::string strOutputIndex, std::string& errorMessage);

    /// Get 10,000 DRKSLK input that can be used for the Stormnode
    bool GetStormNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey);
    vector<COutput> SelectCoinsStormnode();

    /// Enable cold wallet mode (run a Stormnode with no funds)
    bool EnableHotColdStormNode(CTxIn& vin, CService& addr);
};

#endif
