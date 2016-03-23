// Copyright (c) 2014-2016 The Dash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "anon/stormnode/stormnode-sync.h"
#include "anon/stormnode/activestormnode.h"
#include "anon/stormnode/stormnode-budget.h"
#include "anon/stormnode/stormnode-payments.h"
#include "anon/stormnode/stormnode.h"
#include "anon/stormnode/stormnodeman.h"
#include "anon/stormnode/spork.h"
#include "util.h"
#include "addrman.h"

class CStormnodeSync;
CStormnodeSync stormnodeSync;

CStormnodeSync::CStormnodeSync()
{
    Reset();
}

bool CStormnodeSync::IsSynced()
{
    return RequestedStormnodeAssets == STORMNODE_SYNC_FINISHED;
}

bool CStormnodeSync::IsBlockchainSynced()
{
    static bool fBlockchainSynced = false;
    static int64_t lastProcess = GetTime();

    // if the last call to this function was more than 60 minutes ago (client was in sleep mode) reset the sync process
    if(GetTime() - lastProcess > 60*60) {
        Reset();
        fBlockchainSynced = false;
    }
    lastProcess = GetTime();

    if(fBlockchainSynced) return true;

    if (fImporting || fReindex) return false;

    TRY_LOCK(cs_main, lockMain);
    if(!lockMain) return false;

    CBlockIndex* pindex = pindexBest;
    if(pindex == NULL) return false;


    if(pindex->nTime + 60*60 < GetTime())
        return false;

    fBlockchainSynced = true;

    return true;
}

void CStormnodeSync::Reset()
{   
    lastStormnodeList = 0;
    lastStormnodeWinner = 0;
    lastBudgetItem = 0;
    mapSeenSyncSNB.clear();
    mapSeenSyncSNW.clear();
    mapSeenSyncBudget.clear();
    lastFailure = 0;
    nCountFailures = 0;
    sumStormnodeList = 0;
    sumStormnodeWinner = 0;
    sumBudgetItemProp = 0;
    sumBudgetItemFin = 0;
    countStormnodeList = 0;
    countStormnodeWinner = 0;
    countBudgetItemProp = 0;
    countBudgetItemFin = 0;
    RequestedStormnodeAssets = STORMNODE_SYNC_INITIAL;
    RequestedStormnodeAttempt = 0;
    nAssetSyncStarted = GetTime();
}

void CStormnodeSync::AddedStormnodeList(uint256 hash)
{
    if(snodeman.mapSeenStormnodeBroadcast.count(hash)) {
        if(mapSeenSyncSNB[hash] < STORMNODE_SYNC_THRESHOLD) {
            lastStormnodeList = GetTime();
            mapSeenSyncSNB[hash]++;
        }
    } else {
        lastStormnodeList = GetTime();
        mapSeenSyncSNB.insert(make_pair(hash, 1));
    }
}

void CStormnodeSync::AddedStormnodeWinner(uint256 hash)
{
    if(stormnodePayments.mapStormnodePayeeVotes.count(hash)) {
        if(mapSeenSyncSNW[hash] < STORMNODE_SYNC_THRESHOLD) {
            lastStormnodeWinner = GetTime();
            mapSeenSyncSNW[hash]++;
        }
    } else {
        lastStormnodeWinner = GetTime();
        mapSeenSyncSNW.insert(make_pair(hash, 1));
    }
}

void CStormnodeSync::AddedBudgetItem(uint256 hash)
{
    if(budget.mapSeenStormnodeBudgetProposals.count(hash) || budget.mapSeenStormnodeBudgetVotes.count(hash) ||
            budget.mapSeenFinalizedBudgets.count(hash) || budget.mapSeenFinalizedBudgetVotes.count(hash)) {
        if(mapSeenSyncBudget[hash] < STORMNODE_SYNC_THRESHOLD) {
            lastBudgetItem = GetTime();
            mapSeenSyncBudget[hash]++;
        }
    } else {
        lastBudgetItem = GetTime();
        mapSeenSyncBudget.insert(make_pair(hash, 1));
    }
}

bool CStormnodeSync::IsBudgetPropEmpty()
{
    return sumBudgetItemProp==0 && countBudgetItemProp>0;
}

bool CStormnodeSync::IsBudgetFinEmpty()
{
    return sumBudgetItemFin==0 && countBudgetItemFin>0;
}

void CStormnodeSync::GetNextAsset()
{
    switch(RequestedStormnodeAssets)
    {
        case(STORMNODE_SYNC_INITIAL):
        case(STORMNODE_SYNC_FAILED): // should never be used here actually, use Reset() instead
            ClearFulfilledRequest();
            RequestedStormnodeAssets = STORMNODE_SYNC_SPORKS;
            break;
        case(STORMNODE_SYNC_SPORKS):
            RequestedStormnodeAssets = STORMNODE_SYNC_LIST;
            break;
        case(STORMNODE_SYNC_LIST):
            RequestedStormnodeAssets = STORMNODE_SYNC_SNW;
            break;
        case(STORMNODE_SYNC_SNW):
            RequestedStormnodeAssets = STORMNODE_SYNC_BUDGET;
            break;
        case(STORMNODE_SYNC_BUDGET):
            LogPrintf("CStormnodeSync::GetNextAsset - Sync has finished\n");
            RequestedStormnodeAssets = STORMNODE_SYNC_FINISHED;
            break;
    }
    RequestedStormnodeAttempt = 0;
    nAssetSyncStarted = GetTime();
}

std::string CStormnodeSync::GetSyncStatus()
{
    switch (stormnodeSync.RequestedStormnodeAssets) {
        case STORMNODE_SYNC_INITIAL: return _("Synchronization pending...");
        case STORMNODE_SYNC_SPORKS: return _("Synchronizing sporks...");
        case STORMNODE_SYNC_LIST: return _("Synchronizing stormnodes...");
        case STORMNODE_SYNC_SNW: return _("Synchronizing stormnode winners...");
        case STORMNODE_SYNC_BUDGET: return _("Synchronizing budgets...");
        case STORMNODE_SYNC_FAILED: return _("Synchronization failed");
        case STORMNODE_SYNC_FINISHED: return _("Synchronization finished");
    }
    return "";
}

void CStormnodeSync::ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{
    if (strCommand == "ssc") { //Sync status count
        int nItemID;
        int nCount;
        vRecv >> nItemID >> nCount;

        if(RequestedStormnodeAssets >= STORMNODE_SYNC_FINISHED) return;

        //this means we will receive no further communication
        switch(nItemID)
        {
            case(STORMNODE_SYNC_LIST):
                if(nItemID != RequestedStormnodeAssets) return;
                sumStormnodeList += nCount;
                countStormnodeList++;
                break;
            case(STORMNODE_SYNC_SNW):
                if(nItemID != RequestedStormnodeAssets) return;
                sumStormnodeWinner += nCount;
                countStormnodeWinner++;
                break;
            case(STORMNODE_SYNC_BUDGET_PROP):
                if(RequestedStormnodeAssets != STORMNODE_SYNC_BUDGET) return;
                sumBudgetItemProp += nCount;
                countBudgetItemProp++;
                break;
            case(STORMNODE_SYNC_BUDGET_FIN):
                if(RequestedStormnodeAssets != STORMNODE_SYNC_BUDGET) return;
                sumBudgetItemFin += nCount;
                countBudgetItemFin++;
                break;
        }
        
        LogPrintf("CStormnodeSync:ProcessMessage - ssc - got inventory count %d %d\n", nItemID, nCount);
    }
}

void CStormnodeSync::ClearFulfilledRequest()
{
    TRY_LOCK(cs_vNodes, lockRecv);
    if(!lockRecv) return;

    BOOST_FOREACH(CNode* pnode, vNodes)
    {
        pnode->ClearFulfilledRequest("getspork");
        pnode->ClearFulfilledRequest("snsync");
        pnode->ClearFulfilledRequest("snwsync");
        pnode->ClearFulfilledRequest("busync");
    }
}

void CStormnodeSync::Process()
{
    static int tick = 0;

    if(tick++ % STORMNODE_SYNC_TIMEOUT != 0) return;

    if(IsSynced()) {
        /* 
            Resync if we lose all stormnodes from sleep/wake or failure to sync originally
        */
        if(snodeman.CountEnabled() == 0) {
            Reset();
        } else
            return;
    }

    //try syncing again
    if(RequestedStormnodeAssets == STORMNODE_SYNC_FAILED && lastFailure + (1*60) < GetTime()) {
        Reset();
    } else if (RequestedStormnodeAssets == STORMNODE_SYNC_FAILED) {
        return;
    }

    if(fDebug) LogPrintf("CStormnodeSync::Process() - tick %d RequestedStormnodeAssets %d\n", tick, RequestedStormnodeAssets);

    if(RequestedStormnodeAssets == STORMNODE_SYNC_INITIAL) GetNextAsset();

    // sporks synced but blockchain is not, wait until we're almost at a recent block to continue
    if(Params().NetworkID() != CChainParams::TESTNET &&
            !IsBlockchainSynced() && RequestedStormnodeAssets > STORMNODE_SYNC_SPORKS) return;

    TRY_LOCK(cs_vNodes, lockRecv);
    if(!lockRecv) return;

    BOOST_FOREACH(CNode* pnode, vNodes)
    {
        if(Params().NetworkID() == CChainParams::TESTNET){
            if(RequestedStormnodeAttempt <= 2) {
                pnode->PushMessage("getsporks"); //get current network sporks
            } else if(RequestedStormnodeAttempt < 4) {
                snodeman.SsegUpdate(pnode);
            } else if(RequestedStormnodeAttempt < 6) {
                int nSnCount = snodeman.CountEnabled();
                pnode->PushMessage("snget", nSnCount); //sync payees
                uint256 n = 0;
                pnode->PushMessage("snvs", n); //sync stormnode votes
            } else {
                RequestedStormnodeAssets = STORMNODE_SYNC_FINISHED;
            }
            RequestedStormnodeAttempt++;
            return;
        }

        //set to synced
        if(RequestedStormnodeAssets == STORMNODE_SYNC_SPORKS){
            if(pnode->HasFulfilledRequest("getspork")) continue;
            pnode->FulfilledRequest("getspork");

            pnode->PushMessage("getsporks"); //get current network sporks
            if(RequestedStormnodeAttempt >= 2) GetNextAsset();
            RequestedStormnodeAttempt++;
            
            return;
        }

        if (pnode->nVersion >= stormnodePayments.GetMinStormnodePaymentsProto()) {

            if(RequestedStormnodeAssets == STORMNODE_SYNC_LIST) {
                if(fDebug) LogPrintf("CStormnodeSync::Process() - lastStormnodeList %lld (GetTime() - STORMNODE_SYNC_TIMEOUT) %lld\n", lastStormnodeList, GetTime() - STORMNODE_SYNC_TIMEOUT);
                if(lastStormnodeList > 0 && lastStormnodeList < GetTime() - STORMNODE_SYNC_TIMEOUT * 2 && RequestedStormnodeAttempt >= STORMNODE_SYNC_THRESHOLD){ //hasn't received a new item in the last five seconds, so we'll move to the
                    GetNextAsset();
                    return;
                }

                if(pnode->HasFulfilledRequest("snsync")) continue;
                pnode->FulfilledRequest("snsync");

                // timeout
                if(lastStormnodeList == 0 &&
                (RequestedStormnodeAttempt >= STORMNODE_SYNC_THRESHOLD * 3 || GetTime() - nAssetSyncStarted > STORMNODE_SYNC_TIMEOUT * 5)) {
                    if(IsSporkActive(SPORK_8_STORMNODE_PAYMENT_ENFORCEMENT)) {
                        LogPrintf("CStormnodeSync::Process - ERROR - Sync has failed, will retry later\n");
                        RequestedStormnodeAssets = STORMNODE_SYNC_FAILED;
                        RequestedStormnodeAttempt = 0;
                        lastFailure = GetTime();
                        nCountFailures++;
                    } else {
                        GetNextAsset();
                    }
                    return;
                }

                if(RequestedStormnodeAttempt >= STORMNODE_SYNC_THRESHOLD * 3) return;

                snodeman.SsegUpdate(pnode);
                RequestedStormnodeAttempt++;
                return;
            }

            if(RequestedStormnodeAssets == STORMNODE_SYNC_SNW) {
                if(lastStormnodeWinner > 0 && lastStormnodeWinner < GetTime() - STORMNODE_SYNC_TIMEOUT * 2 && RequestedStormnodeAttempt >= STORMNODE_SYNC_THRESHOLD){ //hasn't received a new item in the last five seconds, so we'll move to the
                    GetNextAsset();
                    return;
                }

                if(pnode->HasFulfilledRequest("snwsync")) continue;
                pnode->FulfilledRequest("snwsync");

                // timeout
                if(lastStormnodeWinner == 0 &&
                (RequestedStormnodeAttempt >= STORMNODE_SYNC_THRESHOLD * 3 || GetTime() - nAssetSyncStarted > STORMNODE_SYNC_TIMEOUT * 5)) {
                    if(IsSporkActive(SPORK_8_STORMNODE_PAYMENT_ENFORCEMENT)) {
                        LogPrintf("CStormnodeSync::Process - ERROR - Sync has failed, will retry later\n");
                        RequestedStormnodeAssets = STORMNODE_SYNC_FAILED;
                        RequestedStormnodeAttempt = 0;
                        lastFailure = GetTime();
                        nCountFailures++;
                    } else {
                        GetNextAsset();
                    }
                    return;
                }

                if(RequestedStormnodeAttempt >= STORMNODE_SYNC_THRESHOLD * 3) return;

                CBlockIndex* pindexPrev = pindexBest;
                if(pindexPrev == NULL) return;

                int nSnCount = snodeman.CountEnabled();
                pnode->PushMessage("snget", nSnCount); //sync payees
                RequestedStormnodeAttempt++;

                return;
            }
        }

        if (pnode->nVersion >= MIN_BUDGET_PEER_PROTO_VERSION) {

            if(RequestedStormnodeAssets == STORMNODE_SYNC_BUDGET){
                //we'll start rejecting votes if we accidentally get set as synced too soon
                if(lastBudgetItem > 0 && lastBudgetItem < GetTime() - STORMNODE_SYNC_TIMEOUT * 2 && RequestedStormnodeAttempt >= STORMNODE_SYNC_THRESHOLD){ //hasn't received a new item in the last five seconds, so we'll move to the
                    //LogPrintf("CStormnodeSync::Process - HasNextFinalizedBudget %d nCountFailures %d IsBudgetPropEmpty %d\n", budget.HasNextFinalizedBudget(), nCountFailures, IsBudgetPropEmpty());
                    //if(budget.HasNextFinalizedBudget() || nCountFailures >= 2 || IsBudgetPropEmpty()) {
                        GetNextAsset();

                        //try to activate our stormnode if possible
                        activeStormnode.ManageStatus();
                    // } else { //we've failed to sync, this state will reject the next budget block
                    //     LogPrintf("CStormnodeSync::Process - ERROR - Sync has failed, will retry later\n");
                    //     RequestedStormnodeAssets = STORMNODE_SYNC_FAILED;
                    //     RequestedStormnodeAttempt = 0;
                    //     lastFailure = GetTime();
                    //     nCountFailures++;
                    // }
                    return;
                }

                // timeout
                if(lastBudgetItem == 0 &&
                (RequestedStormnodeAttempt >= STORMNODE_SYNC_THRESHOLD * 3 || GetTime() - nAssetSyncStarted > STORMNODE_SYNC_TIMEOUT * 5)) {
                    // maybe there is no budgets at all, so just finish syncing
                    GetNextAsset();
                    activeStormnode.ManageStatus();
                    return;
                }

                if(pnode->HasFulfilledRequest("busync")) continue;
                pnode->FulfilledRequest("busync");

                if(RequestedStormnodeAttempt >= STORMNODE_SYNC_THRESHOLD * 3) return;

                uint256 n = 0;
                pnode->PushMessage("snvs", n); //sync stormnode votes
                RequestedStormnodeAttempt++;
                
                return;
            }

        }
    }
}
