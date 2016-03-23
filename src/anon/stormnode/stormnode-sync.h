// Copyright (c) 2014-2016 The Dash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef STORMNODE_SYNC_H
#define STORMNODE_SYNC_H

#include "anon/stormnode/stormnode-payments.h"
#include "main.h"

static const int32_t STORMNODE_SYNC_INITIAL = 0;
static const int32_t STORMNODE_SYNC_SPORKS = 1;
static const int32_t STORMNODE_SYNC_LIST = 2;
static const int32_t STORMNODE_SYNC_SNW = 3;
static const int32_t STORMNODE_SYNC_BUDGET = 4;
static const int32_t STORMNODE_SYNC_BUDGET_PROP = 10;
static const int32_t STORMNODE_SYNC_BUDGET_FIN = 11;
static const int32_t STORMNODE_SYNC_FAILED = 998;
static const int32_t STORMNODE_SYNC_FINISHED = 999;

static const int32_t STORMNODE_SYNC_TIMEOUT = 5;
static const int32_t STORMNODE_SYNC_THRESHOLD = 6;

class CStormnodeSync;
extern CStormnodeSync stormnodeSync;

//
// CStormnodeSync : Sync stormnode assets in stages
//

class CStormnodeSync
{
public:
    std::map<uint256, int> mapSeenSyncSNB;
    std::map<uint256, int> mapSeenSyncSNW;
    std::map<uint256, int> mapSeenSyncBudget;

    int64_t lastStormnodeList;
    int64_t lastStormnodeWinner;
    int64_t lastBudgetItem;
    int64_t lastFailure;
    int nCountFailures;

    // sum of all counts
    int sumStormnodeList;
    int sumStormnodeWinner;
    int sumBudgetItemProp;
    int sumBudgetItemFin;
    // peers that reported counts
    int countStormnodeList;
    int countStormnodeWinner;
    int countBudgetItemProp;
    int countBudgetItemFin;

    // Count peers we've requested the list from
    int RequestedStormnodeAssets;
    int RequestedStormnodeAttempt;

    // Time when current stormnode asset sync started
    int64_t nAssetSyncStarted;

    CStormnodeSync();

    void AddedStormnodeList(uint256 hash);
    void AddedStormnodeWinner(uint256 hash);
    void AddedBudgetItem(uint256 hash);
    void GetNextAsset();
    std::string GetSyncStatus();
    void ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);
    bool IsBudgetFinEmpty();
    bool IsBudgetPropEmpty();

    void Reset();
    void Process();
    bool IsSynced();
    bool IsBlockchainSynced();
    void ClearFulfilledRequest();
};

#endif
