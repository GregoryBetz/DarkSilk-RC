// Copyright (c) 2009-2016 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Developers
// Copyright (c) 2015-2016 Silk Network
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/thread.hpp>

#include "main.h"
#include "addrman.h"
#include "alert.h"
#include "chainparams.h"
#include "checkpoints.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "wallet/db.h"
#include "init.h"
#include "kernel.h"
#include "txdb.h"
#include "ui_interface.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"
#include "consensus/consensus.h"
#include "anon/instantx/instantx.h"
#include "anon/sandstorm/sandstorm.h"
#include "anon/stormnode/stormnodeman.h"
#include "anon/stormnode/stormnode-budget.h"
#include "anon/stormnode/stormnode-payments.h"
#include "anon/stormnode/stormnode-sync.h"
#include "anon/stormnode/spork.h"
#include "smessage.h"
#include "txdb-leveldb.h"

using namespace std;
using namespace boost;

//
// Global state
//
CBigNum bnProofOfStakeLimit(~uint256(0) >> 20); //PoS starting difficulty = 0.0002441

CCriticalSection cs_setpwalletRegistered;
set<CWallet*> setpwalletRegistered;

CCriticalSection cs_main;

CChain chainActive;

/// Fees smaller than this (in satoshis) are considered zero fee (for relaying and mining)
/// We are ~xxx times smaller then bitcoin now (2016-01-11), set minRelayTxFee only 10 times higher
/// so it's still 10 times lower comparing to bitcoin.
CFeeRate minRelayTxFee = CFeeRate(MIN_TX_FEE);

CTxMemPool mempool(::minRelayTxFee);

struct COrphanTx {
    CTransaction tx;
    NodeId fromPeer;
};

map<uint256, CBlockIndex*> mapBlockIndex;
set<pair<COutPoint, unsigned int> > setStakeSeen;

//TODO(AA)
unsigned int nStakeMinAge = 10 * 60; // 1 day
unsigned int nModifierInterval = 10 * 60; // 10 minutes to elapse before new modifier is computed
int nStakeMinConfirmations = 10; // 2790 blocks or ~1 day before coins can be staked
bool fTxIndex = true;

CBlockIndex* pindexGenesisBlock = NULL;
int nBestHeight = -1;

uint256 nBestChainTrust = 0;
uint256 nBestInvalidTrust = 0;
uint256 hashBestChain = 0;

CBlockIndex* pindexBest = NULL;

int64_t nTimeBestReceived = 0;
CConditionVariable cvBlockChange;

bool fImporting = false;
bool fReindex = false;
bool fAddrIndex = false;

struct COrphanBlock {
    uint256 hashBlock;
    uint256 hashPrev;
    std::pair<COutPoint, unsigned int> stake;
    vector<unsigned char> vchBlock;
};
map<uint256, COrphanBlock*> mapOrphanBlocks;
multimap<uint256, COrphanBlock*> mapOrphanBlocksByPrev;
set<pair<COutPoint, unsigned int> > setStakeSeenOrphan;
size_t nOrphanBlocksSize = 0;
map<uint256, int64_t> mapRejectedBlocks;

map<uint256, COrphanTx> mapOrphanTransactions;
map<uint256, set<uint256> > mapOrphanTransactionsByPrev;


void EraseOrphansFor(NodeId peer);
void static EraseOrphanTx(uint256 hash);

// Constant stuff for coinbase transactions we create:
CScript COINBASE_FLAGS;

const string strMessageMagic = "DarkSilk Signed Message:\n";

std::set<uint256> setValidatedTx;

CCoinsViewCache *pcoinsTip = NULL;
CBlockTreeDB *pblocktree = NULL;

unsigned int nCoinCacheSize = 5000;

// Internal stuff
namespace {

    struct CBlockIndexWorkComparator
    {
        bool operator()(CBlockIndex *pa, CBlockIndex *pb) const {
            // First sort by most total work, ...
            if (pa->nChainWork > pb->nChainWork) return false;
            if (pa->nChainWork < pb->nChainWork) return true;

            // ... then by earliest time received, ...
            if (pa->nSequenceId < pb->nSequenceId) return false;
            if (pa->nSequenceId > pb->nSequenceId) return true;

            // Use pointer address as tie breaker (should only happen with blocks
            // loaded from disk, as those all have id 0).
            if (pa < pb) return false;
            if (pa > pb) return true;

            // Identical blocks.
            return false;
        }
    };

    CBlockIndex *pindexBestInvalid;
    /**
     * The set of all CBlockIndex entries with BLOCK_VALID_TRANSACTIONS (for itself and all ancestors) and
     * as good as our current tip or better. Entries may be failed, though.
     */
    set<CBlockIndex*, CBlockIndexWorkComparator> setBlockIndexCandidates;

    /// Number of nodes with fSyncStarted.
    int nSyncStarted = 0;
    /** All pairs A->B, where A (or one if its ancestors) misses transactions, but B has transactions. */
    multimap<CBlockIndex*, CBlockIndex*> mapBlocksUnlinked;

    CCriticalSection cs_LastBlockFile;
    //std::vector<CBlockFileInfo> vinfoBlockFile;
    //int nLastBlockFile = 0;

    /**
     * Every received block is assigned a unique and increasing identifier, so we
     * know which one to give priority in case of a fork.
     */
    CCriticalSection cs_nBlockSequenceId;
    /** Blocks loaded from disk are assigned id 0, so start the counter at 1. */
    //uint32_t nBlockSequenceId = 1;

    /**
     * Sources of received blocks, to be able to send them reject messages or ban
     * them, if processing happens afterwards. Protected by cs_main.
     */
    map<uint256, NodeId> mapBlockSource;

    /// Blocks that are in flight, and that are in the queue to be downloaded. Protected by cs_main.
    struct QueuedBlock {
        uint256 hash;
        CBlockIndex *pindex;  //! Optional.
        int64_t nTime;  //! Time of "getdata" request in microseconds.
        int nValidatedQueuedBefore;  //! Number of blocks queued with validated headers (globally) at the time this one is requested.
        bool fValidatedHeaders;  //! Whether this block has validated headers at the time of request.
    };
    map<uint256, pair<NodeId, list<QueuedBlock>::iterator> > mapBlocksInFlight;
    map<uint256, pair<NodeId, list<uint256>::iterator> > mapBlocksToDownload;


    /** Number of blocks in flight with validated headers. */
    int nQueuedValidatedHeaders = 0;

    /// Number of preferable block download peers.
    int nPreferredDownload = 0;

    /** Dirty block index entries. */
    set<CBlockIndex*> setDirtyBlockIndex;

    /** Dirty block file entries. */
    set<int> setDirtyFileInfo;
    int nLastBlockFile = 0;
    std::vector<CBlockFileInfo> vinfoBlockFile;


} // anon namespace

//////////////////////////////////////////////////////////////////////////////
//
// dispatching functions
//

// These functions dispatch to one or all registered wallets

namespace {
    struct CMainSignals {
        // Notifies listeners of updated transaction data (passing hash, transaction, and optionally the block it is found in.
        boost::signals2::signal<void (const CTransaction &, const CBlock *, bool)> SyncTransaction;
        // Notifies listeners of updated transaction data (transaction, and optionally the block it is found in.
        boost::signals2::signal<void (const CTransaction &, const CBlockIndex *pindex, const CBlock *)> SyncTransactionNew;
        // Notifies listeners of an erased transaction (currently disabled, requires transaction replacement).
        boost::signals2::signal<void (const uint256 &)> EraseTransaction;
        // Notifies listeners of an updated transaction without new data (for now: a coinbase potentially becoming visible).
        boost::signals2::signal<void (const uint256 &)> UpdatedTransaction;
        // Notifies listeners of a new active block chain.
        boost::signals2::signal<void (const CBlockLocator &)> SetBestChain;
        // Notifies listeners about an inventory item being seen on the network.
        boost::signals2::signal<void (const uint256 &)> Inventory;
        // Tells listeners to broadcast their data.
        boost::signals2::signal<void (bool)> Broadcast;
    } g_signals;
}

void RegisterWallet(CWalletInterface* pwalletIn) {
    g_signals.SyncTransaction.connect(boost::bind(&CWalletInterface::SyncTransaction, pwalletIn, _1, _2, _3));
    g_signals.EraseTransaction.connect(boost::bind(&CWalletInterface::EraseFromWallet, pwalletIn, _1));
    g_signals.UpdatedTransaction.connect(boost::bind(&CWalletInterface::UpdatedTransaction, pwalletIn, _1));
    g_signals.SetBestChain.connect(boost::bind(&CWalletInterface::SetBestChain, pwalletIn, _1));
    g_signals.Inventory.connect(boost::bind(&CWalletInterface::Inventory, pwalletIn, _1));
    g_signals.Broadcast.connect(boost::bind(&CWalletInterface::ResendWalletTransactions, pwalletIn, _1));
}

void UnregisterWallet(CWalletInterface* pwalletIn) {
    g_signals.Broadcast.disconnect(boost::bind(&CWalletInterface::ResendWalletTransactions, pwalletIn, _1));
    g_signals.Inventory.disconnect(boost::bind(&CWalletInterface::Inventory, pwalletIn, _1));
    g_signals.SetBestChain.disconnect(boost::bind(&CWalletInterface::SetBestChain, pwalletIn, _1));
    g_signals.UpdatedTransaction.disconnect(boost::bind(&CWalletInterface::UpdatedTransaction, pwalletIn, _1));
    g_signals.EraseTransaction.disconnect(boost::bind(&CWalletInterface::EraseFromWallet, pwalletIn, _1));
    g_signals.SyncTransaction.disconnect(boost::bind(&CWalletInterface::SyncTransaction, pwalletIn, _1, _2, _3));
}

void UnregisterAllValidationInterfaces() {
    g_signals.Broadcast.disconnect_all_slots();
    g_signals.Inventory.disconnect_all_slots();
    g_signals.SetBestChain.disconnect_all_slots();
    g_signals.UpdatedTransaction.disconnect_all_slots();
    g_signals.EraseTransaction.disconnect_all_slots();
    g_signals.SyncTransaction.disconnect_all_slots();
}

//TODO (Amir): Remove after chainActive.
void SyncWithWallets(const CTransaction &tx, const CBlock *pblock, bool fConnect) {
    g_signals.SyncTransaction(tx, pblock, fConnect);
}

//New SyncWithWallets function.
void SyncWithWallets(const CTransaction &tx, const CBlockIndex *pindex, const CBlock *pblock) {
    g_signals.SyncTransactionNew(tx, pindex, pblock);
}

void ResendWalletTransactions(bool fForce) {
    g_signals.Broadcast(fForce);
}


//////////////////////////////////////////////////////////////////////////////
//
// Registration of network node signals.
//

namespace {

struct CBlockReject {
    unsigned char chRejectCode;
    string strRejectReason;
    uint256 hashBlock;
};

/**
 * Maintain validation-specific state about nodes, protected by cs_main, instead
 * by CNode's own locks. This simplifies asynchronous operation, where
 * processing of incoming data is done after the ProcessMessage call returns,
 * and we're no longer holding the node's locks.
 */
struct CNodeState {
    //! The peer's address
    CService address;
    //! Whether we have a fully established connection.
    bool fCurrentlyConnected;
    //! Accumulated misbehaviour score for this peer.
    int nMisbehavior;
    //! Whether this peer should be disconnected and banned (unless whitelisted).
    bool fShouldBan;
    //! String name of this peer (debugging/logging purposes).
    std::string name;
    //! List of asynchronously-determined block rejections to notify this peer about.
    std::vector<CBlockReject> rejects;
    //! The best known block we know this peer has announced.
    CBlockIndex *pindexBestKnownBlock;
    //! The hash of the last unknown block this peer has announced.
    uint256 hashLastUnknownBlock;
    //! The last full block we both have.
    CBlockIndex *pindexLastCommonBlock;
    //! Whether we've started headers synchronization with this peer.
    bool fSyncStarted;
    //! Since when we're stalling block download progress (in microseconds), or 0.
    int64_t nStallingSince;
    list<QueuedBlock> vBlocksInFlight;
    int nBlocksInFlight;
    //! Whether we consider this a preferred download peer.
    bool fPreferredDownload;
    list<uint256> vBlocksToDownload;
    int nBlocksToDownload;
    int64_t nLastBlockReceive;
    int64_t nLastBlockProcess;

    CNodeState() {
        fCurrentlyConnected = false;
        nMisbehavior = 0;
        fShouldBan = false;
        pindexBestKnownBlock = NULL;
        hashLastUnknownBlock = uint256(0);
        pindexLastCommonBlock = NULL;
        fSyncStarted = false;
        nStallingSince = 0;
        nBlocksInFlight = 0;
        fPreferredDownload = false;
        nBlocksToDownload = 0;
        nLastBlockReceive = 0;
        nLastBlockProcess = 0;
    }
};

/** Map maintaining per-node state. Requires cs_main. */
map<NodeId, CNodeState> mapNodeState;

// Requires cs_main.
CNodeState *State(NodeId pnode) {
    map<NodeId, CNodeState>::iterator it = mapNodeState.find(pnode);
    if (it == mapNodeState.end())
        return NULL;
    return &it->second;
}

void InitializeNode(NodeId nodeid, const CNode *pnode) {
    LOCK(cs_main);
    CNodeState &state = mapNodeState.insert(std::make_pair(nodeid, CNodeState())).first->second;
    state.name = pnode->addrName;
    state.address = pnode->addr;
}

void EraseOrphansFor(NodeId peer)
{
    int nErased = 0;
    map<uint256, COrphanTx>::iterator iter = mapOrphanTransactions.begin();
    while (iter != mapOrphanTransactions.end())
    {
        map<uint256, COrphanTx>::iterator maybeErase = iter++; // increment to avoid iterator becoming invalid
        if (maybeErase->second.fromPeer == peer)
        {
            EraseOrphanTx(maybeErase->second.tx.GetHash());
            ++nErased;
        }
    }
    if (nErased > 0) LogPrint("mempool", "Erased %d orphan tx from peer %d\n", nErased, peer);
}
/*

// Requires cs_main.
void MarkBlockAsInFlight(NodeId nodeid, const uint256 &hash) {

}*/

void FinalizeNode(NodeId nodeid) {
    LOCK(cs_main);
    CNodeState *state = State(nodeid);

    if (state->fSyncStarted)
        nSyncStarted--;

    if (state->nMisbehavior == 0 && state->fCurrentlyConnected) {
        AddressCurrentlyConnected(state->address);
    }

    BOOST_FOREACH(const QueuedBlock& entry, state->vBlocksInFlight) {
        nQueuedValidatedHeaders -= entry.fValidatedHeaders;
        mapBlocksInFlight.erase(entry.hash);
    }
    
    BOOST_FOREACH(const uint256& hash, state->vBlocksToDownload)
        mapBlocksToDownload.erase(hash);

    EraseOrphansFor(nodeid);
    nPreferredDownload -= state->fPreferredDownload;

    mapNodeState.erase(nodeid);

}

// Requires cs_main.
void MarkBlockAsReceived(const uint256 &hash, NodeId nodeFrom = -1) {
    map<uint256, pair<NodeId, list<QueuedBlock>::iterator> >::iterator itInFlight = mapBlocksInFlight.find(hash);
    if (itInFlight != mapBlocksInFlight.end()) {
        CNodeState *state = State(itInFlight->second.first);
        nQueuedValidatedHeaders -= itInFlight->second.second->fValidatedHeaders;
        state->vBlocksInFlight.erase(itInFlight->second.second);
        state->nBlocksInFlight--;
        state->nStallingSince = 0;
        mapBlocksInFlight.erase(itInFlight);
    }

    map<uint256, pair<NodeId, list<uint256>::iterator> >::iterator itToDownload = mapBlocksToDownload.find(hash);
    if (itToDownload != mapBlocksToDownload.end()) {
        CNodeState *state = State(itToDownload->second.first);
        state->vBlocksToDownload.erase(itToDownload->second.second);
        state->nBlocksToDownload--;
        mapBlocksToDownload.erase(itToDownload);
    }

}

// Requires cs_main.
bool AddBlockToQueue(NodeId nodeid, const uint256 &hash) {
    if (mapBlocksToDownload.count(hash) || mapBlocksInFlight.count(hash))
        return false;

    CNodeState *state = State(nodeid);
    if (state == NULL)
        return false;

    list<uint256>::iterator it = state->vBlocksToDownload.insert(state->vBlocksToDownload.end(), hash);
    state->nBlocksToDownload++;
    if (state->nBlocksToDownload > 5000)
        Misbehaving(nodeid, 10);
    mapBlocksToDownload[hash] = std::make_pair(nodeid, it);
    return true;
}

// Requires cs_main.
void MarkBlockAsInFlight(NodeId nodeid, const uint256& hash, CBlockIndex *pindex = NULL) {
    CNodeState *state = State(nodeid);
    assert(state != NULL);
    // Make sure it's not listed somewhere already.
    MarkBlockAsReceived(hash);

    QueuedBlock newentry { hash, pindex, GetTimeMicros(), nQueuedValidatedHeaders, pindex != NULL};
    nQueuedValidatedHeaders += newentry.fValidatedHeaders;
    list<QueuedBlock>::iterator it = state->vBlocksInFlight.insert(state->vBlocksInFlight.end(), newentry);
    state->nBlocksInFlight++;
    mapBlocksInFlight[hash] = std::make_pair(nodeid, it);
}
} // anon namespace

bool GetNodeStateStats(NodeId nodeid, CNodeStateStats &stats) {
    LOCK(cs_main);
    CNodeState *state = State(nodeid);
    if (state == NULL)
        return false;
    stats.nMisbehavior = state->nMisbehavior;
    stats.nSyncHeight = state->pindexBestKnownBlock ? state->pindexBestKnownBlock->nHeight : -1;
    stats.nCommonHeight = state->pindexLastCommonBlock ? state->pindexLastCommonBlock->nHeight : -1;
    BOOST_FOREACH(const QueuedBlock& queue, state->vBlocksInFlight) {
        if (queue.pindex)
            stats.vHeightInFlight.push_back(queue.pindex->nHeight);
    }
    return true;
}

void RegisterNodeSignals(CNodeSignals& nodeSignals)
{
    //nodeSignals.GetHeight.connect(&GetHeight); //TODO (AA): implement GetHeight
    nodeSignals.ProcessMessages.connect(&ProcessMessages);
    nodeSignals.SendMessages.connect(&SendMessages);
    nodeSignals.InitializeNode.connect(&InitializeNode);
    nodeSignals.FinalizeNode.connect(&FinalizeNode);
}

void UnregisterNodeSignals(CNodeSignals& nodeSignals)
{
    //nodeSignals.GetHeight.disconnect(&GetHeight); //TODO (AA): implement GetHeight
    nodeSignals.ProcessMessages.disconnect(&ProcessMessages);
    nodeSignals.SendMessages.disconnect(&SendMessages);
    nodeSignals.InitializeNode.disconnect(&InitializeNode);
    nodeSignals.FinalizeNode.disconnect(&FinalizeNode);
}

/// Abort with a message
bool AbortNode(const std::string& strMessage, const std::string& userMessage)
{
    strMiscWarning = strMessage;
    LogPrintf("*** %s\n", strMessage);
    uiInterface.ThreadSafeMessageBox(
        userMessage.empty() ? _("Error: A fatal internal error occurred, see debug.log for details") : userMessage,
        "", CClientUIInterface::MSG_ERROR);
    StartShutdown();
    return false;
}

bool AbortNode(CValidationState& state, const std::string& strMessage, const std::string& userMessage="")
{
    AbortNode(strMessage, userMessage);
    return state.Error(strMessage);
}

int GetHeight()
{
    while(true){
        TRY_LOCK(cs_main, lockMain);
        if(!lockMain) { MilliSleep(50); continue; }
        return nBestHeight;
    }
}

//////////////////////////////////////////////////////////////////////////////
//
// mapOrphanTransactions
//
bool AddOrphanTx(const CTransaction& tx, NodeId peer)
{
    uint256 hash = tx.GetHash();
    if (mapOrphanTransactions.count(hash))
        return false;

    // Ignore big transactions, to avoid a
    // send-big-orphans memory exhaustion attack. If a peer has a legitimate
    // large transaction with a missing parent then we assume
    // it will rebroadcast it later, after the parent transaction(s)
    // have been mined or received.
    // 10,000 orphans, each of which is at most 5,000 bytes big is
    // at most 500 megabytes of orphans:
    unsigned int sz = tx.GetSerializeSize(SER_NETWORK, CTransaction::CURRENT_VERSION);
    if (sz > 5000)
    {
        LogPrint("mempool", "ignoring large orphan tx (size: %u, hash: %s)\n", sz, hash.ToString());
        return false;
    }

    mapOrphanTransactions[hash].tx = tx;
    mapOrphanTransactions[hash].fromPeer = peer;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
        mapOrphanTransactionsByPrev[txin.prevout.hash].insert(hash);

    LogPrint("mempool", "stored orphan tx %s (mapsz %u prevsz %u)\n", hash.ToString(),
             mapOrphanTransactions.size(), mapOrphanTransactionsByPrev.size());
    return true;
}

void static EraseOrphanTx(uint256 hash)
{
    map<uint256, COrphanTx>::iterator it = mapOrphanTransactions.find(hash);
    if (it == mapOrphanTransactions.end())
        return;
    BOOST_FOREACH(const CTxIn& txin, it->second.tx.vin)
    {
        map<uint256, set<uint256> >::iterator itPrev = mapOrphanTransactionsByPrev.find(txin.prevout.hash);
        if (itPrev == mapOrphanTransactionsByPrev.end())
            continue;
        itPrev->second.erase(hash);
        if (itPrev->second.empty())
            mapOrphanTransactionsByPrev.erase(itPrev);
    }
    mapOrphanTransactions.erase(it);
}

unsigned int LimitOrphanTxSize(unsigned int nMaxOrphans)
{
    unsigned int nEvicted = 0;
    while (mapOrphanTransactions.size() > nMaxOrphans)
    {
        // Evict a random orphan:
        uint256 randomhash = GetRandHash();
        map<uint256, COrphanTx>::iterator it = mapOrphanTransactions.lower_bound(randomhash);
        if (it == mapOrphanTransactions.end())
            it = mapOrphanTransactions.begin();
        EraseOrphanTx(it->first);
        ++nEvicted;
    }
    return nEvicted;
}

//////////////////////////////////////////////////////////////////////////////
//
// CTransaction and CTxIndex
//

bool IsStandardTx(const CTransaction& tx, string& reason)
{
    if (tx.nVersion > CTransaction::CURRENT_VERSION || tx.nVersion < 1) {
        reason = "version";
        return false;
    }

    // Treat non-final transactions as non-standard to prevent a specific type
    // of double-spend attack, as well as DoS attacks. (if the transaction
    // can't be mined, the attacker isn't expending resources broadcasting it)
    // Basically we don't want to propagate transactions that can't be included in
    // the next block.
    //
    // However, IsFinalTx() is confusing... Without arguments, it uses
    // nBestHeight to evaluate nLockTime; when a block is accepted, nBestHeight
    // is set to the value of nHeight in the block. However, when IsFinalTx()
    // is called within CBlock::AcceptBlock(), the height of the block *being*
    // evaluated is what is used. Thus if we want to know if a transaction can
    // be part of the *next* block, we need to call IsFinalTx() with one more
    // than nBestHeight.
    //
    // Timestamps on the other hand don't get any special treatment, because we
    // can't know what timestamp the next block will have, and there aren't
    // timestamp applications where it matters.
    if (!IsFinalTx(tx, nBestHeight + 1)) {
        reason = "non-final";
        return false;
    }
    // nTime has different purpose from nLockTime but can be used in similar attacks
    if (tx.nTime > FutureDrift(GetAdjustedTime(), true)) {
        reason = "time-too-new";
        return false;
    }

    // Extremely large transactions with lots of inputs can cost the network
    // almost as much to process as they cost the sender in fees, because
    // computing signature hashes is O(ninputs*txsize). Limiting transactions
    // to MAX_STANDARD_TX_SIZE mitigates CPU exhaustion attacks.
    unsigned int sz = tx.GetSerializeSize(SER_NETWORK, CTransaction::CURRENT_VERSION);
    if (sz >= MAX_STANDARD_TX_SIZE) {
        reason = "tx-size";
        return false;
    }

    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        // Biggest 'standard' txin is a 15-of-15 P2SH multisig with compressed
        // keys. (remember the 520 byte limit on redeemScript size) That works
        // out to a (15*(33+1))+3=513 byte redeemScript, 513+1+15*(73+1)+3=1627
        // bytes of scriptSig, which we round off to 1650 bytes for some minor
        // future-proofing. That's also enough to spend a 20-of-20
        // CHECKMULTISIG scriptPubKey, though such a scriptPubKey is not
        // considered standard)
        if (txin.scriptSig.size() > 1650) {
            reason = "scriptsig-size";
            return false;
        }
        if (!txin.scriptSig.IsPushOnly()) {
            reason = "scriptsig-not-pushonly";
            return false;
        }
        if (!txin.scriptSig.HasCanonicalPushes()) {
            reason = "scriptsig-non-canonical-push";
            return false;
        }
    }

    unsigned int nDataOut = 0;
    txnouttype whichType;
    BOOST_FOREACH(const CTxOut& txout, tx.vout) {
        if (!::IsStandard(txout.scriptPubKey, whichType)) {
            reason = "scriptpubkey";
            return false;
        }
        if (whichType == TX_NULL_DATA)
            nDataOut++;
        else if (txout.nValue == 0) {
            reason = "dust";
            return false;
        }
        if (!txout.scriptPubKey.HasCanonicalPushes()) {
            reason = "scriptpubkey-non-canonical-push";
            return false;
        }
    }

    // not more than one data txout per non-data txout is permitted
    // only one data txout is permitted too
    if (nDataOut > 1 && nDataOut > tx.vout.size()/2) {
        reason = "multi-op-return";
        return false;
    }

    return true;
}

bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime)
{
    AssertLockHeld(cs_main);
    // Time based nLockTime implemented in 0.1.6
    if (tx.nLockTime == 0)
        return true;
    if (nBlockHeight == 0)
        nBlockHeight = nBestHeight;
    if (nBlockTime == 0)
        nBlockTime = GetAdjustedTime();
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return true;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
        if (!txin.IsFinal())
            return false;
    return true;
}

//
// Check transaction inputs to mitigate two
// potential denial-of-service attacks:
//
// 1. scriptSigs with extra data stuffed into them,
//    not consumed by scriptPubKey (or P2SH script)
// 2. P2SH scripts with a crazy number of expensive
//    CHECKSIG/CHECKMULTISIG operations
//
bool AreInputsStandard(const CTransaction& tx, const MapPrevTx& mapInputs)
{
    if (tx.IsCoinBase())
        return true; // Coinbases don't use vin normally

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        CTransactionPoS txPoS;
        const CTxOut& prev = txPoS.GetOutputFor(tx.vin[i], mapInputs);

        vector<vector<unsigned char> > vSolutions;
        txnouttype whichType;
        // get the scriptPubKey corresponding to this input:
        const CScript& prevScript = prev.scriptPubKey;
        if (!Solver(prevScript, whichType, vSolutions))
            return false;
        int nArgsExpected = ScriptSigArgsExpected(whichType, vSolutions);
        if (nArgsExpected < 0)
            return false;

        // Transactions with extra stuff in their scriptSigs are
        // non-standard. Note that this EvalScript() call will
        // be quick, because if there are any operations
        // beside "push data" in the scriptSig
        // IsStandard() will have already returned false
        // and this method isn't called.
        vector<vector<unsigned char> > stack;
        if (!EvalScript(stack, tx.vin[i].scriptSig, tx, i, SCRIPT_VERIFY_NONE, 0))
            return false;

        if (whichType == TX_SCRIPTHASH)
        {
            if (stack.empty())
                return false;
            CScript subscript(stack.back().begin(), stack.back().end());
            vector<vector<unsigned char> > vSolutions2;
            txnouttype whichType2;
            if (Solver(subscript, whichType2, vSolutions2))
            {
                int tmpExpected = ScriptSigArgsExpected(whichType2, vSolutions2);

                if (whichType2 == TX_SCRIPTHASH)
                    return false;
                if (tmpExpected < 0)
                    return false;

                nArgsExpected += tmpExpected;
            }
            else
            {
                // Any other Script with less than 15 sigops OK:
                unsigned int sigops = subscript.GetSigOpCount(true);
                // ... extra data left on the stack after execution is OK, too:
                return (sigops <= MAX_P2SH_SIGOPS);
            }
        }

        if (stack.size() != (unsigned int)nArgsExpected)
            return false;
    }

    return true;
}

unsigned int GetLegacySigOpCount(const CTransaction& tx)
{
    unsigned int nSigOps = 0;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    BOOST_FOREACH(const CTxOut& txout, tx.vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}

unsigned int GetP2SHSigOpCount(const CTransaction& tx, const MapPrevTx& inputs)
{
    if (tx.IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        CTransactionPoS txPoS;
        const CTxOut& prevout = txPoS.GetOutputFor(tx.vin[i], inputs);
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(tx.vin[i].scriptSig);
    }
    return nSigOps;
}

int CMerkleTx::SetMerkleBranch(const CBlock* pblock)
{
    AssertLockHeld(cs_main);

    CBlock blockTmp;
    if (pblock == NULL)
    {
        // Load the block this tx is in
        CTxIndex txindex;
        if (!CTxDB("r").ReadTxIndex(GetHash(), txindex))
            return 0;
        if (!blockTmp.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos))
            return 0;
        pblock = &blockTmp;
    }

    // Update the tx's hashBlock
    hashBlock = pblock->GetHash();

    // Locate the transaction
    for (nIndex = 0; nIndex < (int)pblock->vtx.size(); nIndex++)
        if (pblock->vtx[nIndex] == *(CTransaction*)this)
            break;
    if (nIndex == (int)pblock->vtx.size())
    {
        vMerkleBranch.clear();
        nIndex = -1;
        LogPrintf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
        return 0;
    }

    // Fill in merkle branch
    vMerkleBranch = pblock->GetMerkleBranch(nIndex);

    // Is the tx in a block that's in the main chain
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    return nBestHeight - pindex->nHeight + 1;
}

CAmount GetMinFee(const CTransaction& tx, unsigned int nBytes, bool fAllowFree, enum GetMinFee_mode mode)
{
    // Base fee is either MIN_TX_FEE or MIN_RELAY_TX_FEE
    CAmount nBaseFee = (mode == GMF_RELAY) ? MIN_RELAY_TX_FEE : MIN_TX_FEE;

    CAmount nMinFee = (1 + (CAmount)nBytes / 1000) * nBaseFee;

    if (fAllowFree)
    {
        // There is a free transaction area in blocks created by most miners,
        // * If we are relaying we allow transactions up to DEFAULT_BLOCK_PRIORITY_SIZE - 1000
        //   to be considered to fall into this category. We don't want to encourage sending
        //   multiple transactions instead of one big transaction to avoid fees.
        // * If we are creating a transaction we allow transactions up to 1,000 bytes
        //   to be considered safe and assume they can likely make it into this section.
        if (nBytes < (mode == GMF_SEND ? 1000 : (DEFAULT_BLOCK_PRIORITY_SIZE - 1000)))
            nMinFee = 0;
    }

    // This code can be removed after enough miners have upgraded to version 0.9.
    // Until then, be safe when sending and require a fee if any output
    // is less than CENT:
    if (nMinFee < nBaseFee && mode == GMF_SEND)
    {
        BOOST_FOREACH(const CTxOut& txout, tx.vout)
            if (txout.nValue < CENT)
                nMinFee = nBaseFee;
    }

    if (!MoneyRange(nMinFee))
        nMinFee = MAX_MONEY;
    return nMinFee;
}

bool AcceptToMemoryPool(CTxMemPool& pool, CValidationState &state, CTransaction &tx, bool fLimitFree, bool* pfMissingInputs, bool ignoreFees)
{
    AssertLockHeld(cs_main);
    if (pfMissingInputs)
        *pfMissingInputs = false;

    if (!tx.CheckTransaction(state))
        return error("AcceptToMemoryPool : CheckTransaction failed");

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return tx.DoS(100, error("AcceptToMemoryPool : coinbase as individual tx"));

    // ppcoin: coinstake is also only valid in a block, not as a loose transaction
    if (tx.IsCoinStake())
        return tx.DoS(100, error("AcceptToMemoryPool : coinstake as individual tx"));

    // Rather not work on nonstandard transactions (unless -testnet)
    string reason;
    if (!TestNet() && !IsStandardTx(tx, reason))
        return error("AcceptToMemoryPool : nonstandard transaction: %s",
                     reason);

    // is it already in the memory pool?
    uint256 hash = tx.GetHash();
    if (pool.exists(hash))
        return false;

    // ----------- instantX transaction scanning -----------

    BOOST_FOREACH(const CTxIn& in, tx.vin){
        if(mapLockedInputs.count(in.prevout)){
            if(mapLockedInputs[in.prevout] != tx.GetHash()){
                return tx.DoS(0, error("AcceptToMemoryPool : conflicts with existing transaction lock: %s", reason));
            }
        }
    }

    // Check for conflicts with in-memory transactions
    {
    LOCK(pool.cs); // protect pool.mapNextTx
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        COutPoint outpoint = tx.vin[i].prevout;
        if (pool.mapNextTx.count(outpoint))
        {
            // Disable replacement feature for now
            return false;
        }
    }
    }

    {
        CTxDB txdb("r");

        // do all inputs exist?
        // Note that this does not check for the presence of actual outputs (see the next check for that),
        // only helps filling in pfMissingInputs (to determine missing vs spent).
        BOOST_FOREACH(const CTxIn txin, tx.vin) {
            if (!txdb.ContainsTx(txin.prevout.hash)) {
                if (pfMissingInputs)
                    *pfMissingInputs = true;
                return false;
            }
        }

        MapPrevTx mapInputs;
        map<uint256, CTxIndex> mapUnused;
        bool fInvalid = false;
        CTransactionPoS txPoS;
        if (!txPoS.FetchInputs(tx, txdb, mapUnused, false, false, mapInputs, fInvalid))
        {
            if (fInvalid)
                return error("AcceptToMemoryPool : FetchInputs found invalid tx %s", hash.ToString());
            return false;
        }

        // Check for non-standard pay-to-script-hash in inputs
        if (!TestNet() && !AreInputsStandard(tx, mapInputs))
            return error("AcceptToMemoryPool : nonstandard transaction input");

        // Check that the transaction doesn't have an excessive number of
        // sigops, making it impossible to mine. Since the coinbase transaction
        // itself can contain sigops MAX_TX_SIGOPS is less than
        // MAX_BLOCK_SIGOPS; we still consider this an invalid rather than
        // merely non-standard transaction.
        unsigned int nSigOps = GetLegacySigOpCount(tx);
        nSigOps += GetP2SHSigOpCount(tx, mapInputs);
        if (nSigOps > MAX_TX_SIGOPS)
            return tx.DoS(0,
                          error("AcceptToMemoryPool : too many sigops %s, %d > %d",
                                hash.ToString(), nSigOps, MAX_TX_SIGOPS));

        CAmount nFees = txPoS.GetValueIn(tx, mapInputs) - txPoS.GetValueOut(tx);
        unsigned int nSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);

        if(!ignoreFees){
           CAmount txMinFee = GetMinFee(tx, nSize, true, GMF_RELAY);
           if (fLimitFree && nFees < txMinFee)
               return error("AcceptToMemoryPool : not enough fees %s, %d < %d",
                           hash.ToString(),
                           nFees, txMinFee);

        // Continuously rate-limit free transactions
        // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
        // be annoying or make others' transactions take longer to confirm.
        if (fLimitFree && nFees < MIN_RELAY_TX_FEE)
            {
            static CCriticalSection csFreeLimiter;
            static double dFreeCount;
            static int64_t nLastTime;
            int64_t nNow = GetTime();

            LOCK(csFreeLimiter);

            // Use an exponentially decaying ~10-minute window:
            dFreeCount *= pow(1.0 - 1.0/600.0, (double)(nNow - nLastTime));
            nLastTime = nNow;
            // -limitfreerelay unit is thousand-bytes-per-minute
            // At default rate it would take over a month to fill 1GB
            if (dFreeCount > GetArg("-limitfreerelay", 15)*10*1000)
                return error("AcceptableInputs : free transaction rejected by rate limiter");
            LogPrint("mempool", "Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount+nSize);
            dFreeCount += nSize;
            }
        }
        // Check against previous transactions
        // This is done last to help prevent CPU exhaustion denial-of-service attacks.
        if (!txPoS.ConnectInputs(tx, txdb, mapInputs, mapUnused, CDiskTxPos(1,1,1), pindexBest, false, false, STANDARD_SCRIPT_VERIFY_FLAGS))
        {
            return error("AcceptToMemoryPool : ConnectInputs failed %s", hash.ToString());
        }

        // Check again against just the consensus-critical mandatory script
        // verification flags, in case of bugs in the standard flags that cause
        // transactions to pass as valid when they're actually invalid. For
        // instance the STRICTENC flag was incorrectly allowing certain
        // CHECKSIG NOT scripts to pass, even though they were invalid.
        //
        // There is a similar check in CreateNewBlock() to prevent creating
        // invalid blocks, however allowing such transactions into the mempool
        // can be exploited as a DoS attack.
        if (!txPoS.ConnectInputs(tx, txdb, mapInputs, mapUnused, CDiskTxPos(1,1,1), pindexBest, false, false, MANDATORY_SCRIPT_VERIFY_FLAGS))
        {
            return error("AcceptToMemoryPool: : BUG! PLEASE REPORT THIS! ConnectInputs failed against MANDATORY but not STANDARD flags %s", hash.ToString());
        }
    }

    // Store transaction in memory
    pool.addUnchecked(hash, tx);
    setValidatedTx.insert(hash);

    SyncWithWallets(tx);

    LogPrint("mempool", "AcceptToMemoryPool : accepted %s (poolsz %u)\n",
           hash.ToString(),
           pool.mapTx.size());
    return true;
}

/*bool AcceptToMemoryPoolNew(CTxMemPool& pool, CTransaction &tx, bool fLimitFree,  bool* pfMissingInputs, bool fRejectInsaneFee, bool ignoreFees)
{
    AssertLockHeld(cs_main);
    if (pfMissingInputs)
        *pfMissingInputs = false;

    if (!tx.CheckTransaction())
        return error("AcceptToMemoryPool : CheckTransaction failed");

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return tx.DoS(100, error("AcceptToMemoryPool : coinbase as individual tx"));

    // ppcoin: coinstake is also only valid in a block, not as a loose transaction
    if (tx.IsCoinStake())
        return tx.DoS(100, error("AcceptToMemoryPool : coinstake as individual tx")); //TODO (Amir): BUG FIX: Why is the wallet getting throwing error? primitives issues...

    // Rather not work on nonstandard transactions (unless -testnet)
    string reason;
    if (!TestNet() && !IsStandardTx(tx, reason))
        return error("AcceptToMemoryPool : nonstandard transaction: %s", reason);

    // is it already in the memory pool?
    uint256 hash = tx.GetHash();
    if (pool.exists(hash))
        return false;

    // ----------- instantX transaction scanning -----------

    BOOST_FOREACH(const CTxIn& in, tx.vin){
        if(mapLockedInputs.count(in.prevout)){
            if(mapLockedInputs[in.prevout] != tx.GetHash()){
                return error("AcceptableInputs : conflicts with existing transaction lock: %s", reason),
                                 REJECT_INVALID, "tx-lock-conflict";
            }
        }
    }

    // Check for conflicts with in-memory transactions
    {
        LOCK(pool.cs); // protect pool.mapNextTx
        for (unsigned int i = 0; i < tx.vin.size(); i++)
        {
            COutPoint outpoint = tx.vin[i].prevout;
            if (pool.mapNextTx.count(outpoint))
            {
                // Disable replacement feature for now
                return false;
            }
        }
    }

    MapPrevTx mapInputs;
    map<uint256, CTxIndex> mapUnused;
    bool fInvalid = false;
    CTransactionPoS txPoS;
    {
        CCoinsView dummy;
        CCoinsViewCache view(&dummy);
        CTxDB txdb("r");
        CAmount nValueIn = 0;

        {

            LOCK(pool.cs);
            CCoinsViewMemPool viewMemPool(pcoinsTip, pool);
            view.SetBackend(viewMemPool);

            // do we already have it?
            if (view.HaveCoins(hash))
                return false;

            // do all inputs exist?
            // Note that this does not check for the presence of actual outputs (see the next check for that),
            // only helps filling in pfMissingInputs (to determine missing vs spent).
            //TODO (Amir): Put this check back???
            BOOST_FOREACH(const CTxIn txin, tx.vin) {
                if (!view.HaveCoins(txin.prevout.hash)) {
                    if (pfMissingInputs)
                        *pfMissingInputs = true;
                    return false;
                }
            }


            if (!txPoS.FetchInputs(tx, txdb, mapUnused, false, false, mapInputs, fInvalid))
            {
                if (fInvalid)
                    return error("AcceptToMemoryPool : FetchInputs found invalid tx %s", hash.ToString());

                return false;
            }
            // are the actual inputs available?
            if (!view.HaveInputs(tx))
                return (error("AcceptableInputs : inputs already spent"), REJECT_DUPLICATE, "bad-txns-inputs-spent");

            // Bring the best block into scope
            view.GetBestBlock();

            nValueIn = view.GetValueIn(tx);

            // we have all inputs cached now, so switch back to dummy, so we don't need to keep lock on mempool
            view.SetBackend(dummy);
        }

        // Check for non-standard pay-to-script-hash in inputs
        // for any real tx this will be checked on AcceptToMemoryPool anyway
        //        if (Params().RequireStandard() && !AreInputsStandard(tx, view))
        //            return error("AcceptableInputs: : nonstandard transaction input");

        // Check that the transaction doesn't have an excessive number of
        // sigops, making it impossible to mine. Since the coinbase transaction
        // itself can contain sigops MAX_TX_SIGOPS is less than
        // MAX_BLOCK_SIGOPS; we still consider this an invalid rather than
        // merely non-standard transaction.
        MapPrevTx mapInputs;
        unsigned int nSigOps = GetLegacySigOpCount(tx);
        nSigOps += GetP2SHSigOpCount(tx, mapInputs);
        if (nSigOps > MAX_TX_SIGOPS)
            return error("AcceptableInputs : too many sigops %s, %d > %d",
                                   hash.ToString(), nSigOps, MAX_TX_SIGOPS,
                             REJECT_NONSTANDARD, "bad-txns-too-many-sigops");

        CAmount nValueOut = tx.GetValueOut();
        CAmount nFees = nValueIn-nValueOut;

        unsigned int nSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);

        // Don't accept it if it can't get into a block
        // but prioritise sstx and don't check fees for it
        if(mapSandstormBroadcastTxes.count(hash)) {
            // Normally we would PrioritiseTransaction But currently it is unimplemented
             //mempool.PrioritiseTransaction(hash, hash.ToString(), 10000, 0.1 * COIN);  //TODO (Amir): Put this line back. needs PrioritiseTransaction
        } else if(!ignoreFees){
            int64_t txMinFee = GetMinFee(tx, nSize, true, GMF_RELAY);
            if (fLimitFree && nFees < txMinFee)
                return error("AcceptToMemoryPool : not enough fees %s, %d < %d",
                            hash.ToString(),
                            nFees, txMinFee);

        // Continuously rate-limit free transactions
        // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
        // be annoying or make others' transactions take longer to confirm.
        if (fLimitFree && nFees < MIN_RELAY_TX_FEE)
            {
            static CCriticalSection csFreeLimiter;
            static double dFreeCount;
            static int64_t nLastTime;
            int64_t nNow = GetTime();

            LOCK(csFreeLimiter);

            // Use an exponentially decaying ~10-minute window:
            dFreeCount *= pow(1.0 - 1.0/600.0, (double)(nNow - nLastTime));
            nLastTime = nNow;
            // -limitfreerelay unit is thousand-bytes-per-minute
            // At default rate it would take over a month to fill 1GB
            if (dFreeCount > GetArg("-limitfreerelay", 15)*10*1000)
                return error("AcceptableInputs : free transaction rejected by rate limiter");
            LogPrint("mempool", "Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount+nSize);
            dFreeCount += nSize;
            }
        }


        if (fRejectInsaneFee && nFees > MIN_RELAY_TX_FEE * 10000)
            return error("AcceptableInputs: : insane fees %s, %d > %d",
                         hash.ToString(),
                         nFees, MIN_RELAY_TX_FEE * 10000);

        // Check against previous transactions
        // This is done last to help prevent CPU exhaustion denial-of-service attacks.

        if (!txPoS.ConnectInputs(tx, txdb, mapInputs, mapUnused, CDiskTxPos(1,1,1), pindexBest, false, false, STANDARD_SCRIPT_VERIFY_FLAGS))
        {
            return error("AcceptToMemoryPool : ConnectInputs failed %s", hash.ToString());
        }

        // Check again against just the consensus-critical mandatory script
        // verification flags, in case of bugs in the standard flags that cause
        // transactions to pass as valid when they're actually invalid. For
        // instance the STRICTENC flag was incorrectly allowing certain
        // CHECKSIG NOT scripts to pass, even though they were invalid.
        //
        // There is a similar check in CreateNewBlock() to prevent creating
        // invalid blocks, however allowing such transactions into the mempool
        // can be exploited as a DoS attack.
        if (!txPoS.ConnectInputs(tx, txdb, mapInputs, mapUnused, CDiskTxPos(1,1,1), pindexBest, false, false, MANDATORY_SCRIPT_VERIFY_FLAGS))
        {
            return error("AcceptToMemoryPool: : BUG! PLEASE REPORT THIS! ConnectInputs failed against MANDATORY but not STANDARD flags %s", hash.ToString());
        }
    }

    // Store transaction in memory
    pool.addUnchecked(hash, tx);
    setValidatedTx.insert(hash);

    SyncWithWallets(tx, NULL);

    LogPrint("mempool", "AcceptToMemoryPool : accepted %s (poolsz %u)\n",
           hash.ToString(),
           pool.mapTx.size());
    return true;
}*/

bool AcceptableInputs(CTxMemPool& pool, CValidationState &state, CTransaction &tx, bool fLimitFree,
                         bool* pfMissingInputs, bool fRejectInsaneFee, bool isSSTX)
{
    AssertLockHeld(cs_main);

    if (!tx.CheckTransaction(state))
        return error("AcceptableInputs : CheckTransaction failed");

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return tx.DoS(100, error("AcceptableInputs : coinbase as individual tx"));

    // ppcoin: coinstake is also only valid in a block, not as a loose transaction
    if (tx.IsCoinStake())
        return tx.DoS(100, error("AcceptableInputs : coinstake as individual tx"));

    // Rather not work on nonstandard transactions (unless -testnet)
    string reason;
    //if (!TestNet() && !IsStandardTx(tx, reason))
    //    return error("AcceptableInputs : nonstandard transaction: %s",
    //                 reason);

    // is it already in the memory pool?
    uint256 hash = tx.GetHash();
    if (pool.exists(hash))
        return false;

    // ----------- InstantX transaction scanning -----------

    BOOST_FOREACH(const CTxIn& in, tx.vin){
        if(mapLockedInputs.count(in.prevout)){
            if(mapLockedInputs[in.prevout] != tx.GetHash()){
                return state.DoS(0,
                                 error("AcceptableInputs : conflicts with existing transaction lock: %s", reason),
                                 REJECT_INVALID, "tx-lock-conflict");
            }
        }
    }

    // Check for conflicts with in-memory transactions
    {
    LOCK(pool.cs); // protect pool.mapNextTx
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        COutPoint outpoint = tx.vin[i].prevout;
        if (pool.mapNextTx.count(outpoint))
        {
            // Disable replacement feature for now
            return false;
        }
    }
    }

    {
        CTxDB txdb("r");

        // do we already have it?
        if (txdb.ContainsTx(hash))
            return false;

        MapPrevTx mapInputs;
        map<uint256, CTxIndex> mapUnused;
        bool fInvalid = false;
        CTransactionPoS txPoS;
        if (!txPoS.FetchInputs(tx, txdb, mapUnused, false, false, mapInputs, fInvalid))
        {
            if (fInvalid)
                return error("AcceptableInputs : FetchInputs found invalid tx %s", hash.ToString());
            return false;
        }

        // Check for non-standard pay-to-script-hash in inputs
        //if (!TestNet() && !AreInputsStandard(tx, mapInputs))
          //  return error("AcceptToMemoryPool : nonstandard transaction input");

        // Check that the transaction doesn't have an excessive number of
        // sigops, making it impossible to mine. Since the coinbase transaction
        // itself can contain sigops MAX_TX_SIGOPS is less than
        // MAX_BLOCK_SIGOPS; we still consider this an invalid rather than
        // merely non-standard transaction.
        unsigned int nSigOps = GetLegacySigOpCount(tx);
        nSigOps += GetP2SHSigOpCount(tx, mapInputs);
        if (nSigOps > MAX_TX_SIGOPS)
            return tx.DoS(0,
                          error("AcceptableInputs : too many sigops %s, %d > %d",
                                hash.ToString(), nSigOps, MAX_TX_SIGOPS));

        CAmount nFees = txPoS.GetValueIn(tx, mapInputs)-txPoS.GetValueOut(tx);
        unsigned int nSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
        CAmount txMinFee = GetMinFee(tx, nSize, true, GMF_RELAY);


        // Don't accept it if it can't get into a block
        if(isSSTX) {
            // Normally we would PrioritiseTransaction But currently it is unimplemented
            // mempool.PrioritiseTransaction(hash, hash.ToString(), 1000, 0.1*COIN);
        } else { // same as !ignoreFees for AcceptToMemoryPool
            if (fLimitFree && nFees < txMinFee)
                return error("AcceptableInputs : not enough fees %s, %d < %d",
                            hash.ToString(),
                            nFees, txMinFee);

        // Continuously rate-limit free transactions
        // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
        // be annoying or make others' transactions take longer to confirm.
        if (fLimitFree && nFees < MIN_RELAY_TX_FEE)
        {
            static CCriticalSection csFreeLimiter;
            static double dFreeCount;
            static int64_t nLastTime;
            int64_t nNow = GetTime();

             LOCK(csFreeLimiter);

            // Use an exponentially decaying ~10-minute window:
            dFreeCount *= pow(1.0 - 1.0/600.0, (double)(nNow - nLastTime));
            nLastTime = nNow;
            // -limitfreerelay unit is thousand-bytes-per-minute
            // At default rate it would take over a month to fill 1GB
            if (dFreeCount > GetArg("-limitfreerelay", 15)*10*1000)
                return error("AcceptableInputs : free transaction rejected by rate limiter");
            LogPrint("mempool", "Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount+nSize);
            dFreeCount += nSize;
        }
    }

        if (fRejectInsaneFee && nFees > txMinFee * 10000)
            return error("AcceptableInputs: : insane fees %s, %d > %d",
                         hash.ToString(),
                         nFees, MIN_RELAY_TX_FEE * 10000);

        // Check against previous transactions
        // This is done last to help prevent CPU exhaustion denial-of-service attacks.
        if (!txPoS.ConnectInputs(tx, txdb, mapInputs, mapUnused, CDiskTxPos(1,1,1), pindexBest, true, false, STANDARD_SCRIPT_VERIFY_FLAGS, false))
        {
            return error("AcceptableInputs : ConnectInputs failed %s", hash.ToString());
        }
    }


    /*LogPrint("mempool", "AcceptableInputs : accepted %s (poolsz %u)\n",
           hash.ToString(),
           pool.mapTx.size());
    */
    return true;
}

int CMerkleTx::GetDepthInMainChainINTERNAL(CBlockIndex* &pindexRet) const
{
    if (hashBlock == 0 || nIndex == -1)
        return 0;
    AssertLockHeld(cs_main);

    // Find the block it claims to be in
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    // Make sure the merkle branch connects to this block
    if (!fMerkleVerified)
    {
        if (CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != pindex->hashMerkleRoot)
            return 0;
        fMerkleVerified = true;
    }

    pindexRet = pindex;
    return pindexBest->nHeight - pindex->nHeight + 1;
}

int CMerkleTx::GetTransactionLockSignatures() const
{
    if(!IsSporkActive(SPORK_2_INSTANTX)) return -3;
    if(!fEnableInstantX) return -1;

    //compile consessus vote
    std::map<uint256, CTransactionLock>::iterator i = mapTxLocks.find(GetHash());
    if (i != mapTxLocks.end()){
        return (*i).second.CountSignatures();
    }

    return -1;
}

bool CMerkleTx::IsTransactionLockTimedOut() const
{
    if(!fEnableInstantX) return 0;

    //compile consessus vote
    std::map<uint256, CTransactionLock>::iterator i = mapTxLocks.find(GetHash());
    if (i != mapTxLocks.end()){
        return GetTime() > (*i).second.nTimeout;
    }

    return false;
}

int CMerkleTx::GetDepthInMainChain(CBlockIndex* &pindexRet, bool enableIX) const
{
    AssertLockHeld(cs_main);
    int nResult = GetDepthInMainChainINTERNAL(pindexRet);
    if (nResult == 0 && !mempool.exists(GetHash()))
        return -1; // Not in chain, not in mempool

    if(enableIX){
        if (nResult < 6){
            int signatures = GetTransactionLockSignatures();
            if(signatures >= INSTANTX_SIGNATURES_REQUIRED){
                return nInstantXDepth+nResult;
            }
        }
    }

    return nResult;
}

int CMerkleTx::GetBlocksToMaturity() const
{
    if (!(IsCoinBase() || IsCoinStake()))
        return 0;
    return max(0, COINBASE_MATURITY - GetDepthInMainChain());
}

bool CMerkleTx::AcceptToMemoryPool(bool fLimitFree, bool fRejectInsaneFee, bool ignoreFees)
{   
    CValidationState state;
    return ::AcceptToMemoryPool(mempool, state, *this, fLimitFree, NULL, ignoreFees);
}

bool CWalletTx::AcceptWalletTransaction(CTxDB& txdb)
{

    {
        // Add previous supporting transactions first
        BOOST_FOREACH(CMerkleTx& tx, vtxPrev)
        {
            if (!(tx.IsCoinBase() || tx.IsCoinStake()))
            {
                uint256 hash = tx.GetHash();
                if (!mempool.exists(hash) && !txdb.ContainsTx(hash))
                    tx.AcceptToMemoryPool(false);
            }
        }
        return AcceptToMemoryPool(false);
    }
    return false;
}

bool CWalletTx::AcceptWalletTransaction()
{
    CTxDB txdb("r");
    return AcceptWalletTransaction(txdb);
}

int GetInputAge(CTxIn& vin)
{
    const uint256& prevHash = vin.prevout.hash;
    CTransaction tx;
    uint256 hashBlock;
    bool fFound = GetTransaction(prevHash, tx, hashBlock);
    if(fFound)
    {
    if(mapBlockIndex.find(hashBlock) != mapBlockIndex.end())
    {
        return pindexBest->nHeight - mapBlockIndex[hashBlock]->nHeight;
    }
    else
        return 0;
    }
    else
    return 0;
}

int GetInputAgeIX(uint256 nTXHash, CTxIn& vin)
{
    int sigs = 0;
    int nResult = GetInputAge(vin);
    if(nResult < 0) nResult = 0;

    if (nResult < 6){
        std::map<uint256, CTransactionLock>::iterator i = mapTxLocks.find(nTXHash);
        if (i != mapTxLocks.end()){
            sigs = (*i).second.CountSignatures();
        }
        if(sigs >= INSTANTX_SIGNATURES_REQUIRED){
            return nInstantXDepth+nResult;
        }
    }

    return -1;
}

int GetIXConfirmations(uint256 nTXHash)
{
    int sigs = 0;

    std::map<uint256, CTransactionLock>::iterator i = mapTxLocks.find(nTXHash);
    if (i != mapTxLocks.end()){
        sigs = (*i).second.CountSignatures();
    }
    if(sigs >= INSTANTX_SIGNATURES_REQUIRED){
        return nInstantXDepth;
    }

    return 0;
}

int CTxIndex::GetDepthInMainChain() const
{
    // Read block header
    CBlock block;
    if (!block.ReadFromDisk(pos.nFile, pos.nBlockPos, false))
        return 0;
    // Find the block in the index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(block.GetHash());
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;
    return 1 + nBestHeight - pindex->nHeight;
}

/// Return transaction in tx, and if it was found inside a block, its hash is placed in hashBlock
bool GetTransaction(const uint256 &hash, CTransaction &tx, uint256 &hashBlock)
{
    {
        LOCK(cs_main);
        {
            if (mempool.lookup(hash, tx))
            {
                return true;
            }
        }
        CTxDB txdb("r");
        CTxIndex txindex;
        CTransactionPoS txPoS;
        if (txPoS.ReadFromDisk(tx, txdb, hash, txindex))
        {
            CBlock block;
            if (block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
                hashBlock = block.GetHash();
            return true;
        }
        // look for transaction in disconnected blocks to find orphaned CoinBase and CoinStake transactions
        BOOST_FOREACH(PAIRTYPE(const uint256, CBlockIndex*)& item, mapBlockIndex)
        {
            CBlockIndex* pindex = item.second;
            if (pindex == pindexBest || pindex->pnext != 0)
                continue;
            CBlock block;
            if (!block.ReadFromDisk(pindex))
                continue;
            BOOST_FOREACH(const CTransaction& txOrphan, block.vtx)
            {
                if (txOrphan.GetHash() == hash)
                {
                    tx = txOrphan;
                    return true;
                }
            }
        }
    }
    return false;
}

//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

uint256 static GetOrphanRoot(const uint256& hash)
{
    map<uint256, COrphanBlock*>::iterator it = mapOrphanBlocks.find(hash);
    if (it == mapOrphanBlocks.end())
        return hash;

    // Work back to the first block in the orphan chain
    do {
        map<uint256, COrphanBlock*>::iterator it2 = mapOrphanBlocks.find(it->second->hashPrev);
        if (it2 == mapOrphanBlocks.end())
            return it->first;
        it = it2;
    } while(true);
}

// ppcoin: find block wanted by given orphan block
uint256 WantedByOrphan(const COrphanBlock* pblockOrphan)
{
    // Work back to the first block in the orphan chain
    while (mapOrphanBlocks.count(pblockOrphan->hashPrev))
        pblockOrphan = mapOrphanBlocks[pblockOrphan->hashPrev];
    return pblockOrphan->hashPrev;
}

// Remove a random orphan block (which does not have any dependent orphans).
void static PruneOrphanBlocks()
{
    size_t nMaxOrphanBlocksSize = GetArg("-maxorphanblocksmib", DEFAULT_MAX_ORPHAN_BLOCKS) * ((size_t) 1 << 20);
    while (nOrphanBlocksSize > nMaxOrphanBlocksSize)
    {
        // Pick a random orphan block.
        int pos = insecure_rand() % mapOrphanBlocksByPrev.size();
        std::multimap<uint256, COrphanBlock*>::iterator it = mapOrphanBlocksByPrev.begin();
        while (pos--) it++;

        // As long as this block has other orphans depending on it, move to one of those successors.
        do {
            std::multimap<uint256, COrphanBlock*>::iterator it2 = mapOrphanBlocksByPrev.find(it->second->hashBlock);
            if (it2 == mapOrphanBlocksByPrev.end())
                break;
            it = it2;
        } while(1);

        setStakeSeenOrphan.erase(it->second->stake);
        uint256 hash = it->second->hashBlock;
        nOrphanBlocksSize -= it->second->vchBlock.size();
        delete it->second;
        mapOrphanBlocksByPrev.erase(it);
        mapOrphanBlocks.erase(hash);
    }
}

static CBigNum GetProofOfStakeLimit(int nHeight)
{
        return bnProofOfStakeLimit;
}

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
        LogPrint("creation", "GetProofOfWorkReward() : create=%s nSubsidy=%d\n", FormatMoney(STATIC_POW_REWARD), STATIC_POW_REWARD);
        return STATIC_POW_REWARD + nFees;
    }
}

// ppcoin: find last block index up to pindex
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake)
{
    while (pindex && pindex->pprev && (pindex->IsProofOfStake() != fProofOfStake))
        pindex = pindex->pprev;
    return pindex;
}

unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, bool fProofOfStake)
{
    CBigNum bnTargetLimit = fProofOfStake ? GetProofOfStakeLimit(pindexLast->nHeight) : Params().ProofOfWorkLimit();

    if (pindexLast == NULL)
        return bnTargetLimit.GetCompact(); // genesis block

    const CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);
    if (pindexPrev->pprev == NULL)
        return bnTargetLimit.GetCompact(); // first block
    const CBlockIndex* pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);
    if (pindexPrevPrev->pprev == NULL)
        return bnTargetLimit.GetCompact(); // second block

    int64_t nTargetSpacing = fProofOfStake ? Params().StakeSpacing() : Params().PoWSpacing();
    int64_t nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();

    if (nActualSpacing < 0) {
        nActualSpacing = nTargetSpacing;
    }
    else if (fProofOfStake && nActualSpacing > nTargetSpacing * 10) {
         nActualSpacing = nTargetSpacing * 10;
    }

    // target change every block
    // retarget with exponential moving toward target spacing
    // Includes fix for wrong retargeting difficulty by Mammix2
    CBigNum bnNew;
    bnNew.SetCompact(pindexPrev->nBits);

    int64_t nInterval = fProofOfStake ? 10 : 10;
    bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
    bnNew /= ((nInterval + 1) * nTargetSpacing);

    if (bnNew <= 0 || bnNew > bnTargetLimit)
        bnNew = bnTargetLimit;

    return bnNew.GetCompact();
}

CAmount GetBlockValue(int nBits, int nHeight, const CAmount& nFees, bool fProofOfWork)
{
    if (fProofOfWork) {
        return STATIC_POW_REWARD + nFees;
    }
    else {
        return STATIC_POS_REWARD + nFees;
    }
}

CAmount GetStormnodePayment(int nHeight, CAmount blockValue)
{
    CAmount ret = blockValue * 1/5; //20%

    return ret;
}

// Requires cs_main.
void Misbehaving(NodeId pnode, int howmuch)
{
    if (howmuch == 0)
        return;

    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pn, vNodes)
    {
        if(pn->GetId() == pnode)
        {
            pn->nMisbehavior += howmuch;
            int banscore = GetArg("-banscore", 100);
            if (pn->nMisbehavior >= banscore && pn->nMisbehavior - howmuch < banscore)
            {
                LogPrintf("Misbehaving: %s (%d -> %d) BAN THRESHOLD EXCEEDED\n", pn->addrName, pn->nMisbehavior-howmuch, pn->nMisbehavior);
                //pn->fShouldBan = true;
            }
            else
                LogPrintf("Misbehaving: %s (%d -> %d)\n", pn->addrName, pn->nMisbehavior-howmuch, pn->nMisbehavior);

            break;
        }
    }
}

bool IsConfirmedInNPrevBlocks(const CTxIndex& txindex, const CBlockIndex* pindexFrom, int nMaxDepth, int& nActualDepth)
{
    for (const CBlockIndex* pindex = pindexFrom; pindex && pindexFrom->nHeight - pindex->nHeight < nMaxDepth; pindex = pindex->pprev)
    {
        if (pindex->nBlockPos == txindex.pos.nBlockPos && pindex->nFile == txindex.pos.nFile)
        {
            nActualDepth = pindexFrom->nHeight - pindex->nHeight;
            return true;
        }
    }
    return false;
}

bool DisconnectBlocksAndReprocess(int blocks)
{
    //TODO (Amir): put back.  needs CChain chainActive implemented.
    //LOCK(cs_main);
    //CValidationState state;
    //LogPrintf("DisconnectBlocksAndReprocess: Got command to replay %d blocks\n", blocks);
    //for(int i = 0; i <= blocks; i++)
    //    DisconnectTip(state);

    LogPrintf("DisconnectBlocksAndReprocess for %u not implemented!  \n", blocks);
    return true;
}

bool FindTransactionsByDestination(const CTxDestination &dest, std::vector<uint256> &vtxhash) {
    uint160 addrid = 0;
    const CKeyID *pkeyid = boost::get<CKeyID>(&dest);
    if (pkeyid)
        addrid = static_cast<uint160>(*pkeyid);
    if (!addrid) {
        const CScriptID *pscriptid = boost::get<CScriptID>(&dest);
        if (pscriptid)
            addrid = static_cast<uint160>(*pscriptid);
    }
    if (!addrid)
    {
        LogPrintf("FindTransactionsByDestination(): Couldn't parse dest into addrid\n");
        return false;
    }

    LOCK(cs_main);
    CTxDB txdb("r");
    if(!txdb.ReadAddrIndex(addrid, vtxhash))
    {
    LogPrintf("FindTransactionsByDestination(): txdb.ReadAddrIndex failed\n");
    return false;
    }
    return true;
}

// ppcoin: total coin age spent in transaction, in the unit of coin-days.
// Only those coins meeting minimum age requirement counts. As those
// transactions not in main chain are not currently indexed so we
// might not find out about their coin age. Older transactions are
// guaranteed to be in main chain by sync-checkpoint. This rule is
// introduced to help nodes establish a consistent view of the coin
// age (trust score) of competing branches.
/*
bool CTransaction::GetCoinAge(CTxDB& txdb, const CBlockIndex* pindexPrev, uint64_t& nCoinAge) const
{
    CBigNum bnCentSecond = 0;  // coin age in the unit of cent-seconds
    nCoinAge = 0;

    if (IsCoinBase())
        return true;

    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        // First try finding the previous transaction in database
        CTransaction txPrev;
        CTxIndex txindex;
        if (!txPrev.ReadFromDisk(txdb, txin.prevout, txindex))
            continue;  // previous transaction not in main chain
        if (nTime < txPrev.nTime)
            return false;  // Transaction timestamp violation

        int nSpendDepth;

        if (IsConfirmedInNPrevBlocks(txindex, pindexPrev, nStakeMinConfirmations - 1, nSpendDepth))
        {
            LogPrint("coinage", "coin age skip nSpendDepth=%d\n", nSpendDepth + 1);
            continue; // only count coins meeting min confirmations requirement
        }

        int64_t nValueIn = txPrev.vout[txin.prevout.n].nValue;
        bnCentSecond += CBigNum(nValueIn) * (nTime-txPrev.nTime) / CENT;

        LogPrint("coinage", "coin age nValueIn=%d nTimeDiff=%d bnCentSecond=%s\n", nValueIn, nTime - txPrev.nTime, bnCentSecond.ToString());
    }

    CBigNum bnCoinDay = bnCentSecond * CENT / COIN / (24 * 60 * 60);
    LogPrint("coinage", "coin age bnCoinDay=%s\n", bnCoinDay.ToString());
    nCoinAge = bnCoinDay.getuint64();
    return true;
}
*/

void PushGetBlocks(CNode* pnode, CBlockIndex* pindexBegin, uint256 hashEnd)
{
    // Filter out duplicate requests
    if (pindexBegin == pnode->pindexLastGetBlocksBegin && hashEnd == pnode->hashLastGetBlocksEnd)
        return;
    pnode->pindexLastGetBlocksBegin = pindexBegin;
    pnode->hashLastGetBlocksEnd = hashEnd;

    pnode->PushMessage("getblocks", CBlockLocator(pindexBegin), hashEnd);
}

bool static IsCanonicalBlockSignature(CBlock* pblock)
{
    if (pblock->IsProofOfWork()) {
        return pblock->vchBlockSig.empty();
    }

    return IsDERSignature(pblock->vchBlockSig, false);
}

bool ProcessBlock(CNode* pfrom, CBlock* pblock)
{
    AssertLockHeld(cs_main);

    // Check for duplicate
    uint256 hash = pblock->GetHash();
    if (mapBlockIndex.count(hash))
        return error("ProcessBlock() : already have block %d %s", mapBlockIndex[hash]->nHeight, hash.ToString());
    if (mapOrphanBlocks.count(hash))
        return error("ProcessBlock() : already have block (orphan) %s", hash.ToString());

    // ppcoin: check proof-of-stake
    // Limited duplicity on stake: prevents block flood attack
    // Duplicate stake allowed only when there is orphan child block
    if (!fReindex && !fImporting && pblock->IsProofOfStake() && setStakeSeen.count(pblock->GetProofOfStake()) && !mapOrphanBlocksByPrev.count(hash))
        return error("ProcessBlock() : duplicate proof-of-stake (%s, %d) for block %s", pblock->GetProofOfStake().first.ToString(), pblock->GetProofOfStake().second, hash.ToString());

        if (pblock->hashPrevBlock != hashBestChain)
    {
        // Extra checks to prevent "fill up memory by spamming with bogus blocks"
        const CBlockIndex* pcheckpoint = Checkpoints::AutoSelectSyncCheckpoint();
        int64_t deltaTime = pblock->GetBlockTime() - pcheckpoint->nTime;
        if (deltaTime < 0)
        {
            if (pfrom)
                pfrom->Misbehaving(1);
            return error("ProcessBlock() : block with timestamp before last checkpoint");
        }
    }

    if (!IsCanonicalBlockSignature(pblock)) {
        if (pfrom && pfrom->nVersion >= CANONICAL_BLOCK_SIG_VERSION) {
            pfrom->Misbehaving(100);
        }
        return error("ProcessBlock(): bad block signature encoding");        
    }

    // Preliminary checks
    CValidationState state;
    if (!pblock->CheckBlock(state))
        return error("ProcessBlock() : CheckBlock FAILED");

    // If we don't already have its previous block, shunt it off to holding area until we get it
    if (!mapBlockIndex.count(pblock->hashPrevBlock))
    {
        LogPrintf("ProcessBlock: ORPHAN BLOCK %lu, prev=%s\n", (unsigned long)mapOrphanBlocks.size(), pblock->hashPrevBlock.ToString());

        // Accept orphans as long as there is a node to request its parents from
        if (pfrom) {
            // ppcoin: check proof-of-stake
            if (pblock->IsProofOfStake())
            {
                // Limited duplicity on stake: prevents block flood attack
                // Duplicate stake allowed only when there is orphan child block
                if (setStakeSeenOrphan.count(pblock->GetProofOfStake()) && !mapOrphanBlocksByPrev.count(hash))
                    return error("ProcessBlock() : duplicate proof-of-stake (%s, %d) for orphan block %s", pblock->GetProofOfStake().first.ToString(), pblock->GetProofOfStake().second, hash.ToString());
            }
            PruneOrphanBlocks();
            COrphanBlock* pblock2 = new COrphanBlock();
            {
                CDataStream ss(SER_DISK, CLIENT_VERSION);
                ss << *pblock;
                pblock2->vchBlock = std::vector<unsigned char>(ss.begin(), ss.end());
            }
            pblock2->hashBlock = hash;
            pblock2->hashPrev = pblock->hashPrevBlock;
            pblock2->stake = pblock->GetProofOfStake();
            nOrphanBlocksSize += pblock2->vchBlock.size();
            mapOrphanBlocks.insert(make_pair(hash, pblock2));
            mapOrphanBlocksByPrev.insert(make_pair(pblock2->hashPrev, pblock2));
            if (pblock->IsProofOfStake())
                setStakeSeenOrphan.insert(pblock->GetProofOfStake());

            // Ask this guy to fill in what we're missing
            PushGetBlocks(pfrom, pindexBest, GetOrphanRoot(hash));
            // ppcoin: getblocks may not obtain the ancestor block rejected
            // earlier by duplicate-stake check so we ask for it again directly
            if (!IsInitialBlockDownload())
                pfrom->AskFor(CInv(MSG_BLOCK, WantedByOrphan(pblock2)));
        }
        return true;
    }

    // Store to disk
    if (!pblock->AcceptBlock())
        return error("ProcessBlock() : AcceptBlock FAILED");

    // Recursively process any orphan blocks that depended on this one
    vector<uint256> vWorkQueue;
    vWorkQueue.push_back(hash);
    for (unsigned int i = 0; i < vWorkQueue.size(); i++)
    {
        uint256 hashPrev = vWorkQueue[i];
        for (multimap<uint256, COrphanBlock*>::iterator mi = mapOrphanBlocksByPrev.lower_bound(hashPrev);
             mi != mapOrphanBlocksByPrev.upper_bound(hashPrev);
             ++mi)
        {
            CBlock block;
            {
                CDataStream ss(mi->second->vchBlock, SER_DISK, CLIENT_VERSION);
                ss >> block;
            }
            block.BuildMerkleTree();
            if (block.AcceptBlock())
                vWorkQueue.push_back(mi->second->hashBlock);
            mapOrphanBlocks.erase(mi->second->hashBlock);
            setStakeSeenOrphan.erase(block.GetProofOfStake());
            nOrphanBlocksSize -= mi->second->vchBlock.size();
            delete mi->second;
        }
        mapOrphanBlocksByPrev.erase(hashPrev);
    }

    //TODO (Amir): Do we need this code?
    /*if(!fLiteMode && !IsInitialBlockDownload()){
        if (!fImporting && !fReindex && pindexBest->nHeight > Checkpoints::GetTotalBlocksEstimate()){

            CScript payee;
            if(stormnodePayments.GetBlockPayee(pindexBest->nHeight+1, payee)){
                //UPDATE STORMNODE LAST PAID TIME
                CStormnode* psn = snodeman.Find(payee);
                if(psn != NULL) {
                    psn->nLastPaid = GetAdjustedTime();
                }
                LogPrintf("ProcessBlock() : Update Stormnode Last Paid Time - %d\n", pindexBest->nHeight);
            }

            sandStormPool.CheckTimeout();
            sandStormPool.NewBlock();
            stormnodePayments.ProcessBlock(GetHeight()+10);
            budget.NewBlock();
        }
    }*/

    LogPrintf("ProcessBlock: ACCEPTED\n");

    return true;
}

bool CheckDiskSpace(uint64_t nAdditionalBytes)
{
    uint64_t nFreeBytesAvailable = filesystem::space(GetDataDir()).available;

    // Check for nMinDiskSpace bytes (currently 50MB)
    if (nFreeBytesAvailable < nMinDiskSpace + nAdditionalBytes)
    {
        string strMessage = _("Error: Disk space is low!");
        strMiscWarning = strMessage;
        LogPrintf("*** %s\n", strMessage);
        uiInterface.ThreadSafeMessageBox(strMessage, "", CClientUIInterface::MSG_ERROR);
        StartShutdown();
        return false;
    }
    return true;
}

void static InvalidBlockFound(CBlockIndex *pindex, const CValidationState &state) {
    int nDoS = 0;
    if (state.IsInvalid(nDoS)) {
        std::map<uint256, NodeId>::iterator it = mapBlockSource.find(pindex->GetBlockHash());
        if (it != mapBlockSource.end() && State(it->second)) {
            CBlockReject reject = {state.GetRejectCode(), state.GetRejectReason().substr(0, MAX_REJECT_MESSAGE_LENGTH), pindex->GetBlockHash()};
            State(it->second)->rejects.push_back(reject);
            if (nDoS > 0)
                Misbehaving(it->second, nDoS);
        }
    }
    if (!state.CorruptionPossible()) {
        pindex->nStatus |= BLOCK_FAILED_VALID;
        setDirtyBlockIndex.insert(pindex);
        setBlockIndexCandidates.erase(pindex);
        InvalidChainFound(pindex);
    }
}

void UnloadBlockIndex()
{
    mapBlockIndex.clear();
    setBlockIndexCandidates.clear();
    chainActive.SetTip(NULL);
    pindexBestInvalid = NULL;
}

bool LoadBlockIndex(bool fAllowNew)
{
    LOCK(cs_main);

    //
    // Load block index
    //
    CTxDB txdb("cr+");
    if (!txdb.LoadBlockIndex())
        return false;

    //
    // Init with genesis block
    //
    if (mapBlockIndex.empty())
    {
        if (!fAllowNew)
            return false;

        CBlock &block = const_cast<CBlock&>(Params().GenesisBlock());
        // Start new block file
        unsigned int nFile;
        unsigned int nBlockPos;
        if (!block.WriteToDisk(nFile, nBlockPos))
            return error("LoadBlockIndex() : writing genesis block to disk failed");
        if (!block.AddToBlockIndex(nFile, nBlockPos, Params().HashGenesisBlock()))
            return error("LoadBlockIndex() : genesis block not accepted");
    }

    return true;
}

bool InitBlockIndex() {
    //TODO (Amir): Implement this after chainActive
    /*
    LOCK(cs_main);
    // Check whether we're already initialized
    if (chainActive.Genesis() != NULL)
        return true;

    // Use the provided setting for -txindex in the new database
    fTxIndex = GetBoolArg("-txindex", true);
    pblocktree->WriteFlag("txindex", fTxIndex);
    LogPrintf("Initializing databases...\n");

    // Only add the genesis block if not reindexing (in which case we reuse the one already on disk)
    if (!fReindex) {
        try {
            CBlock &block = const_cast<CBlock&>(Params().GenesisBlock());
            // Start new block file
            unsigned int nBlockSize = ::GetSerializeSize(block, SER_DISK, CLIENT_VERSION);
            CDiskBlockPos blockPos;
            CValidationState state;
            if (!FindBlockPos(state, blockPos, nBlockSize+8, 0, block.GetBlockTime()))
                return error("LoadBlockIndex() : FindBlockPos failed");
            if (!WriteBlockToDisk(block, blockPos))
                return error("LoadBlockIndex() : writing genesis block to disk failed");
            CBlockIndex *pindex = AddToBlockIndex(block);
            if (!ReceivedBlockTransactions(block, state, pindex, blockPos))
                return error("LoadBlockIndex() : genesis block not accepted");
            if (!ActivateBestChain(state, &block))
                return error("LoadBlockIndex() : genesis block cannot be activated");
            // Force a chainstate write so that when we VerifyDB in a moment, it doesnt check stale data
            return FlushStateToDisk(state, FLUSH_STATE_ALWAYS);
        } catch(std::runtime_error &e) {
            return error("LoadBlockIndex() : failed to initialize block database: %s", e.what());
        }
    }
*/
    return true;
}

void PrintBlockTree()
{
    AssertLockHeld(cs_main);
    // pre-compute tree structure
    map<CBlockIndex*, vector<CBlockIndex*> > mapNext;
    for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
    {
        CBlockIndex* pindex = (*mi).second;
        mapNext[pindex->pprev].push_back(pindex);
        // test
        //while (rand() % 3 == 0)
        //    mapNext[pindex->pprev].push_back(pindex);
    }

    vector<pair<int, CBlockIndex*> > vStack;
    vStack.push_back(make_pair(0, pindexGenesisBlock));

    int nPrevCol = 0;
    while (!vStack.empty())
    {
        int nCol = vStack.back().first;
        CBlockIndex* pindex = vStack.back().second;
        vStack.pop_back();

        // print split or gap
        if (nCol > nPrevCol)
        {
            for (int i = 0; i < nCol-1; i++)
                LogPrintf("| ");
            LogPrintf("|\\\n");
        }
        else if (nCol < nPrevCol)
        {
            for (int i = 0; i < nCol; i++)
                LogPrintf("| ");
            LogPrintf("|\n");
       }
        nPrevCol = nCol;

        // print columns
        for (int i = 0; i < nCol; i++)
            LogPrintf("| ");

        // print item
        CBlock block;
        block.ReadFromDisk(pindex);
        LogPrintf("%d (%u,%u) %s  %08x  %s  mint %7s  tx %u",
            pindex->nHeight,
            pindex->nFile,
            pindex->nBlockPos,
            block.GetHash().ToString(),
            block.nBits,
            DateTimeStrFormat("%x %H:%M:%S", block.GetBlockTime()),
            FormatMoney(pindex->nMint),
            block.vtx.size());

        // put the main time-chain first
        vector<CBlockIndex*>& vNext = mapNext[pindex];
        for (unsigned int i = 0; i < vNext.size(); i++)
        {
            if (vNext[i]->pnext)
            {
                swap(vNext[0], vNext[i]);
                break;
            }
        }

        // iterate children
        for (unsigned int i = 0; i < vNext.size(); i++)
            vStack.push_back(make_pair(nCol+i, vNext[i]));
    }
}

bool LoadExternalBlockFile(FILE* fileIn)
{
    int64_t nStart = GetTimeMillis();

    int nLoaded = 0;
    {
        try {
            CAutoFile blkdat(fileIn, SER_DISK, CLIENT_VERSION);
            unsigned int nPos = 0;
            while (nPos != (unsigned int)-1 && blkdat.good())
            {
                boost::this_thread::interruption_point();
                unsigned char pchData[65536];
                do {
                    fseek(blkdat, nPos, SEEK_SET);
                    int nRead = fread(pchData, 1, sizeof(pchData), blkdat);
                    if (nRead <= 8)
                    {
                        nPos = (unsigned int)-1;
                        break;
                    }
                    void* nFind = memchr(pchData, Params().MessageStart()[0], nRead+1-MESSAGE_START_SIZE);
                    if (nFind)
                    {
                        if (memcmp(nFind, Params().MessageStart(), MESSAGE_START_SIZE)==0)
                        {
                            nPos += ((unsigned char*)nFind - pchData) + MESSAGE_START_SIZE;
                            break;
                        }
                        nPos += ((unsigned char*)nFind - pchData) + 1;
                    }
                    else
                        nPos += sizeof(pchData) - MESSAGE_START_SIZE + 1;
                    boost::this_thread::interruption_point();
                } while(true);
                if (nPos == (unsigned int)-1)
                    break;
                fseek(blkdat, nPos, SEEK_SET);
                unsigned int nSize;
                blkdat >> nSize;
                if (nSize > 0 && nSize <= MAX_BLOCK_SIZE)
                {
                    CBlock block;
                    blkdat >> block;
                    LOCK(cs_main);
                    if (ProcessBlock(NULL,&block))
                    {
                        nLoaded++;
                        nPos += 4 + nSize;
                    }
                }
            }
        }
        catch (std::exception &e) {
            LogPrintf("%s() : Deserialize or I/O error caught during load\n",
                   __PRETTY_FUNCTION__);
        }
    }
    LogPrintf("Loaded %i blocks from external file in %dms\n", nLoaded, GetTimeMillis() - nStart);
    return nLoaded > 0;
}

struct CImportingNow
{
    CImportingNow() {
        assert(fImporting == false);
        fImporting = true;
    }

    ~CImportingNow() {
        assert(fImporting == true);
        fImporting = false;
    }
};

void ThreadImport(std::vector<boost::filesystem::path> vImportFiles)
{
    RenameThread("darksilk-loadblk");

    CImportingNow imp;

    // -loadblock=
    BOOST_FOREACH(boost::filesystem::path &path, vImportFiles) {
        FILE *file = fopen(path.string().c_str(), "rb");
        if (file)
            LoadExternalBlockFile(file);
    }

    // hardcoded $DATADIR/bootstrap.dat
    filesystem::path pathBootstrap = GetDataDir() / "bootstrap.dat";
    if (filesystem::exists(pathBootstrap)) {
        FILE *file = fopen(pathBootstrap.string().c_str(), "rb");
        if (file) {
            filesystem::path pathBootstrapOld = GetDataDir() / "bootstrap.dat.old";
            LoadExternalBlockFile(file);
            RenameOver(pathBootstrap, pathBootstrapOld);
        }
    }
}

//////////////////////////////////////////////////////////////////////////////
//
// CAlert
//

extern map<uint256, CAlert> mapAlerts;
extern CCriticalSection cs_mapAlerts;

string GetWarnings(string strFor)
{
    int nPriority = 0;
    string strStatusBar;
    string strRPC;

    if (GetBoolArg("-testsafemode", false))
        strRPC = "test";

    if (!CLIENT_VERSION_IS_RELEASE)
        strStatusBar = _("This is a pre-release test build - use at your own risk - do not use for mining or merchant applications");

    // Misc warnings like out of disk space and clock is wrong
    if (strMiscWarning != "")
    {
        nPriority = 1000;
        strStatusBar = strMiscWarning;
    }

    // Alerts
    {
        LOCK(cs_mapAlerts);
        BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
        {
            const CAlert& alert = item.second;
            if (alert.AppliesToMe() && alert.nPriority > nPriority)
            {
                nPriority = alert.nPriority;
                strStatusBar = alert.strStatusBar;
                if (nPriority > 1000)
                    strRPC = strStatusBar;
            }
        }
    }

    if (strFor == "statusbar")
        return strStatusBar;
    else if (strFor == "rpc")
        return strRPC;
    assert(!"GetWarnings() : invalid parameter");
    return "error";
}

//////////////////////////////////////////////////////////////////////////////
//
// Messages
//

bool static AlreadyHave(CTxDB& txdb, const CInv& inv)
{
    switch (inv.type)
    {
    case MSG_TX:
        {
        bool txInMap = false;
        txInMap = mempool.exists(inv.hash);
        return txInMap ||
               mapOrphanTransactions.count(inv.hash) ||
               txdb.ContainsTx(inv.hash);
        }

    case MSG_BLOCK:
        return mapBlockIndex.count(inv.hash) ||
               mapOrphanBlocks.count(inv.hash);
    case MSG_TXLOCK_REQUEST:
        return mapTxLockReq.count(inv.hash) ||
               mapTxLockReqRejected.count(inv.hash);
    case MSG_TXLOCK_VOTE:
        return mapTxLockVote.count(inv.hash);
    case MSG_SPORK:
        return mapSporks.count(inv.hash);
    case MSG_STORMNODE_WINNER:
        if(stormnodePayments.mapStormnodePayeeVotes.count(inv.hash)) {
            stormnodeSync.AddedStormnodeWinner(inv.hash);
            return true;
        }
        return false;
    case MSG_BUDGET_VOTE:
        if(budget.mapSeenStormnodeBudgetVotes.count(inv.hash)) {
            stormnodeSync.AddedBudgetItem(inv.hash);
            return true;
        }
        return false;
    case MSG_BUDGET_PROPOSAL:
        if(budget.mapSeenStormnodeBudgetProposals.count(inv.hash)) {
            stormnodeSync.AddedBudgetItem(inv.hash);
            return true;
        }
        return false;
    case MSG_BUDGET_FINALIZED_VOTE:
        if(budget.mapSeenFinalizedBudgetVotes.count(inv.hash)) {
            stormnodeSync.AddedBudgetItem(inv.hash);
            return true;
        }
        return false;
    case MSG_BUDGET_FINALIZED:
        if(budget.mapSeenFinalizedBudgets.count(inv.hash)) {
            stormnodeSync.AddedBudgetItem(inv.hash);
            return true;
        }
        return false;
    case MSG_STORMNODE_ANNOUNCE:
        if(snodeman.mapSeenStormnodeBroadcast.count(inv.hash)) {
            stormnodeSync.AddedStormnodeList(inv.hash);
            return true;
        }
        return false;
    case MSG_STORMNODE_PING:
        return snodeman.mapSeenStormnodePing.count(inv.hash);
    }
    // Don't know what it is, just say we already got one
    return true;
}

void static ProcessGetData(CNode* pfrom)
{
    std::deque<CInv>::iterator it = pfrom->vRecvGetData.begin();

    vector<CInv> vNotFound;

    LOCK(cs_main);

    while (it != pfrom->vRecvGetData.end()) {
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->nSendSize >= SendBufferSize())
            break;

        const CInv &inv = *it;
        {
            boost::this_thread::interruption_point();
            it++;

            if (inv.type == MSG_BLOCK || inv.type == MSG_FILTERED_BLOCK)
            {
                // Send block from disk
                map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(inv.hash);
                if (mi != mapBlockIndex.end())
                {
                    CBlock block;
                    block.ReadFromDisk((*mi).second);
                    pfrom->PushMessage("block", block);

                    // Trigger them to send a getblocks request for the next batch of inventory
                    if (inv.hash == pfrom->hashContinue)
                    {
                        // Bypass PushInventory, this must send even if redundant,
                        // and we want it right after the last block so they don't
                        // wait for other stuff first.
                        vector<CInv> vInv;
                        vInv.push_back(CInv(MSG_BLOCK, hashBestChain));
                        pfrom->PushMessage("inv", vInv);
                        pfrom->hashContinue = 0;
                    }
                }
            }
            else if (inv.IsKnownType())
            {
                if(fDebug) LogPrintf("ProcessGetData -- Starting \n");
                // Send stream from relay memory
                bool pushed = false;

                /*
                    {
                    LOCK(cs_mapRelay);
                    map<CInv, CDataStream>::iterator mi = mapRelay.find(inv);
                    if (mi != mapRelay.end()) {
                        pfrom->PushMessage(inv.GetCommand(), (*mi).second);
                        pushed = true;
                    }
                }
                */

                if (!pushed && inv.type == MSG_TX) {
                   string txHash = inv.hash.ToString().c_str();
                   if(fDebug) LogPrintf("ProcessGetData -- txHash %d \n", txHash);

                    if(mapSandstormBroadcastTxes.count(inv.hash)){
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss <<
                            mapSandstormBroadcastTxes[inv.hash].tx <<
                            mapSandstormBroadcastTxes[inv.hash].vin <<
                            mapSandstormBroadcastTxes[inv.hash].vchSig <<
                            mapSandstormBroadcastTxes[inv.hash].sigTime;

                        pfrom->PushMessage("sstx", ss);
                        pushed = true;
                    } else {
                        CTransaction tx;
                        if (mempool.lookup(inv.hash, tx)) {
                            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                            ss.reserve(1000);
                            ss << tx;
                            pfrom->PushMessage("tx", ss);
                            pushed = true;
                        }
                    }
                }
                if (!pushed && inv.type == MSG_TXLOCK_VOTE) {
                    if(mapTxLockVote.count(inv.hash)){
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << mapTxLockVote[inv.hash];
                        pfrom->PushMessage("txlvote", ss);
                        pushed = true;
                    }
                }
                if (!pushed && inv.type == MSG_TXLOCK_REQUEST) {
                    if(mapTxLockReq.count(inv.hash)){
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << mapTxLockReq[inv.hash];
                        pfrom->PushMessage("txlreq", ss);
                        pushed = true;
                    }
                }
                if (!pushed && inv.type == MSG_SPORK) {
                    if(mapSporks.count(inv.hash)){
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << mapSporks[inv.hash];
                        pfrom->PushMessage("spork", ss);
                        pushed = true;
                    }
                }
                if (!pushed && inv.type == MSG_STORMNODE_WINNER) {
                     if(stormnodePayments.mapStormnodePayeeVotes.count(inv.hash)){
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << stormnodePayments.mapStormnodePayeeVotes[inv.hash];
                        pfrom->PushMessage("snw", ss);
                        pushed = true;
                    }
                }
                if (!pushed && inv.type == MSG_BUDGET_VOTE) {
                    if(budget.mapSeenStormnodeBudgetVotes.count(inv.hash)){
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << budget.mapSeenStormnodeBudgetVotes[inv.hash];
                        pfrom->PushMessage("svote", ss);
                        pushed = true;
                    }
                }
                if (!pushed && inv.type == MSG_BUDGET_PROPOSAL) {
                    if(budget.mapSeenStormnodeBudgetProposals.count(inv.hash)){
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << budget.mapSeenStormnodeBudgetProposals[inv.hash];
                        pfrom->PushMessage("sprop", ss);
                        pushed = true;
                    }
                }
                
                if (!pushed && inv.type == MSG_BUDGET_FINALIZED_VOTE) {
                    if(budget.mapSeenFinalizedBudgetVotes.count(inv.hash)){
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << budget.mapSeenFinalizedBudgetVotes[inv.hash];
                        pfrom->PushMessage("fbvote", ss);
                        pushed = true;
                    }
                }

                if (!pushed && inv.type == MSG_BUDGET_FINALIZED) {
                    if(budget.mapSeenFinalizedBudgets.count(inv.hash)){
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << budget.mapSeenFinalizedBudgets[inv.hash];
                        pfrom->PushMessage("fbs", ss);
                        pushed = true;
                    }
                }

                if (!pushed && inv.type == MSG_STORMNODE_ANNOUNCE) {
                    if(snodeman.mapSeenStormnodeBroadcast.count(inv.hash)){
                        bool fRequested = false; // Requested full stormnode list
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << snodeman.mapSeenStormnodeBroadcast[inv.hash];
                        ss << fRequested;
                        pfrom->PushMessage("snb", ss);
                        pushed = true;
                    }
                }

                if (!pushed && inv.type == MSG_STORMNODE_PING) {
                    if(snodeman.mapSeenStormnodePing.count(inv.hash)){
                        bool fRequested = false; // Requested full stormnode list
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << snodeman.mapSeenStormnodePing[inv.hash];
                        ss << fRequested;
                        pfrom->PushMessage("snp", ss);
                        pushed = true;
                    }
                }

                if (!pushed) {
                    vNotFound.push_back(inv);
                }
            }

            // Track requests for our stuff.
            g_signals.Inventory(inv.hash);

            if (inv.type == MSG_BLOCK || inv.type == MSG_FILTERED_BLOCK )
                break;
        }
    }

    pfrom->vRecvGetData.erase(pfrom->vRecvGetData.begin(), it);

    if (!vNotFound.empty()) {
        // Let the peer know that we didn't find what it asked for, so it doesn't
        // have to wait around forever. Currently only SPV clients actually care
        // about this message: it's needed when they are recursively walking the
        // dependencies of relevant unconfirmed transactions. SPV clients want to
        // do that because they want to know about (and store and rebroadcast and
        // risk analyze) the dependencies of transactions relevant to them, without
        // having to download the entire memory pool.
        pfrom->PushMessage("notfound", vNotFound);
    }
}

bool static ProcessMessage(CNode* pfrom, string strCommand, CDataStream& vRecv, int64_t nTimeReceived)
{
    RandAddSeedPerfmon();
    LogPrint("net", "received: %s (%u bytes)\n", strCommand, vRecv.size());
    if (mapArgs.count("-dropmessagestest") && GetRand(atoi(mapArgs["-dropmessagestest"])) == 0)
    {
        LogPrintf("dropmessagestest DROPPING RECV MESSAGE\n");
        return true;
    }

    State(pfrom->GetId())->nLastBlockProcess = GetTimeMicros();

    if (strCommand == "version")
    {
        // Each connection can only send one version message
        if (pfrom->nVersion != 0)
        {
            pfrom->Misbehaving(1);
            return false;
        }

        int64_t nTime;
        CAddress addrMe;
        CAddress addrFrom;
        uint64_t nNonce = 1;
        vRecv >> pfrom->nVersion >> pfrom->nServices >> nTime >> addrMe;
        if (pfrom->nVersion < MIN_PEER_PROTO_VERSION)
        {
            // disconnect from peers older than this proto version
            LogPrintf("partner %s using obsolete version %i; disconnecting\n", pfrom->addr.ToString(), pfrom->nVersion);
            pfrom->fDisconnect = true;
            return false;
        }

        if (pfrom->nVersion == 10300)
            pfrom->nVersion = 300;
        if (!vRecv.empty())
            vRecv >> addrFrom >> nNonce;
        if (!vRecv.empty()) {
            vRecv >> LIMITED_STRING(pfrom->strSubVer, 256);
            pfrom->cleanSubVer = SanitizeSubVersionString(pfrom->strSubVer);
        }
        if (!vRecv.empty())
            vRecv >> pfrom->nStartingHeight;

        // Disconnect if we connected to ourself
        if (nNonce == nLocalHostNonce && nNonce > 1)
        {
            LogPrintf("connected to self at %s, disconnecting\n", pfrom->addr.ToString());
            pfrom->fDisconnect = true;
            return true;
        }

        pfrom->addrLocal = addrMe;
        if (pfrom->fInbound && addrMe.IsRoutable())
        {
            SeenLocal(addrMe);
        }

        // Be shy and don't send version until we hear
        if (pfrom->fInbound)
            pfrom->PushVersion();

        pfrom->fClient = !(pfrom->nServices & NODE_NETWORK);

        // Change version
        pfrom->PushMessage("verack");
        pfrom->ssSend.SetVersion(min(pfrom->nVersion, PROTOCOL_VERSION));

        if (!pfrom->fInbound)
        {
            // Advertise our address
            if (fListen && !IsInitialBlockDownload())
            {
                CAddress addr = GetLocalAddress(&pfrom->addr);
                if (addr.IsRoutable())
                {
                    pfrom->PushAddress(addr);
                } else if (IsPeerAddrLocalGood(pfrom)) {
                    addr.SetIP(pfrom->addrLocal);
                    pfrom->PushAddress(addr);
                }
            }

            // Get recent addresses
            if (pfrom->fOneShot || pfrom->nVersion >= CADDR_TIME_VERSION || addrman.size() < 1000)
            {
                pfrom->PushMessage("getaddr");
                pfrom->fGetAddr = true;
            }
            addrman.Good(pfrom->addr);
        } else {
            if (((CNetAddr)pfrom->addr) == (CNetAddr)addrFrom)
            {
                addrman.Add(addrFrom, addrFrom);
                addrman.Good(addrFrom);
            }
        }

        // Relay alerts
        {
            LOCK(cs_mapAlerts);
            BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
                item.second.RelayTo(pfrom);
        }

        string remoteAddr;
        if (fLogIPs)
            remoteAddr = ", peeraddr=" + pfrom->addr.ToString();
 
        pfrom->fSuccessfullyConnected = true;

        LogPrintf("receive version message: version %d, blocks=%d, us=%s, them=%s, peer=%s\n", pfrom->nVersion, pfrom->nStartingHeight, addrMe.ToString(), addrFrom.ToString(), pfrom->addr.ToString());

        int64_t nTimeOffset = nTime - GetTime();
        pfrom->nTimeOffset = nTimeOffset;

        if (GetBoolArg("-synctime", true))
            AddTimeData(pfrom->addr, nTimeOffset);
    }


    else if (pfrom->nVersion == 0)
    {
        // Must have a version message before anything else
        pfrom->Misbehaving(1);
        return false;
    }


    else if (strCommand == "verack")
    {
        pfrom->SetRecvVersion(min(pfrom->nVersion, PROTOCOL_VERSION));
    }


    else if (strCommand == "addr")
    {
        vector<CAddress> vAddr;
        vRecv >> vAddr;

        // Don't want addr from older versions unless seeding
        if (pfrom->nVersion < CADDR_TIME_VERSION && addrman.size() > 1000)
            return true;
        if (vAddr.size() > 1000)
        {
            pfrom->Misbehaving(20);
            return error("message addr size() = %u", vAddr.size());
        }

        // Store the new addresses
        vector<CAddress> vAddrOk;
        int64_t nNow = GetAdjustedTime();
        int64_t nSince = nNow - 10 * 60;
        BOOST_FOREACH(CAddress& addr, vAddr)
        {
            boost::this_thread::interruption_point();

            if (addr.nTime <= 100000000 || addr.nTime > nNow + 10 * 60)
                addr.nTime = nNow - 5 * 24 * 60 * 60;
            pfrom->AddAddressKnown(addr);
            bool fReachable = IsReachable(addr);
            if (addr.nTime > nSince && !pfrom->fGetAddr && vAddr.size() <= 10 && addr.IsRoutable())
            {
                // Relay to a limited number of other nodes
                {
                    LOCK(cs_vNodes);
                    // Use deterministic randomness to send to the same nodes for 24 hours
                    // at a time so the setAddrKnowns of the chosen nodes prevent repeats
                    static uint256 hashSalt;
                    if (hashSalt == 0)
                        hashSalt = GetRandHash();
                    uint64_t hashAddr = addr.GetHash();
                    uint256 hashRand = hashSalt ^ (hashAddr<<32) ^ ((GetTime()+hashAddr)/(24*60*60));
                    hashRand = Hash(BEGIN(hashRand), END(hashRand));
                    multimap<uint256, CNode*> mapMix;
                    BOOST_FOREACH(CNode* pnode, vNodes)
                    {
                        if (pnode->nVersion < CADDR_TIME_VERSION)
                            continue;
                        unsigned int nPointer;
                        memcpy(&nPointer, &pnode, sizeof(nPointer));
                        uint256 hashKey = hashRand ^ nPointer;
                        hashKey = Hash(BEGIN(hashKey), END(hashKey));
                        mapMix.insert(make_pair(hashKey, pnode));
                    }
                    int nRelayNodes = fReachable ? 2 : 1; // limited relaying of addresses outside our network(s)
                    for (multimap<uint256, CNode*>::iterator mi = mapMix.begin(); mi != mapMix.end() && nRelayNodes-- > 0; ++mi)
                        ((*mi).second)->PushAddress(addr);
                }
            }
            // Do not store addresses outside our network
            if (fReachable)
                vAddrOk.push_back(addr);
        }
        addrman.Add(vAddrOk, pfrom->addr, 2 * 60 * 60);
        if (vAddr.size() < 1000)
            pfrom->fGetAddr = false;
        if (pfrom->fOneShot)
            pfrom->fDisconnect = true;
    }

    else if (strCommand == "inv")
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
            pfrom->Misbehaving(20);
            return error("message inv size() = %u", vInv.size());
        }

        LOCK(cs_main);
        CTxDB txdb("r");

        for (unsigned int nInv = 0; nInv < vInv.size(); nInv++)
        {
            const CInv &inv = vInv[nInv];

            boost::this_thread::interruption_point();
            pfrom->AddInventoryKnown(inv);

            bool fAlreadyHave = AlreadyHave(txdb, inv);
            LogPrint("net", "  got inventory: %s  %s\n", inv.ToString(), fAlreadyHave ? "have" : "new");

            if (!fAlreadyHave) {
               if (!fImporting && !fReindex) {
                   if (inv.type == MSG_BLOCK)
                       AddBlockToQueue(pfrom->GetId(), inv.hash);
                   else
                       pfrom->AskFor(inv);
               }
            } else if (inv.type == MSG_BLOCK && mapOrphanBlocks.count(inv.hash)) {
               PushGetBlocks(pfrom, pindexBest, GetOrphanRoot(inv.hash));
               // In case we are on a very long side-chain, it is possible that we already have
               // the last block in an inv bundle sent in response to getblocks. Try to detect
               // this situation and push another getblocks to continue.
               if (fDebug)
                   LogPrintf("force request: %s\n", inv.ToString());
            }

            // Track requests for our stuff
            g_signals.Inventory(inv.hash);
        }
    }


    else if (strCommand == "getdata")
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
            pfrom->Misbehaving(20);
            return error("message getdata size() = %u", vInv.size());
        }

        if (fDebug || (vInv.size() != 1))
            LogPrint("net", "received getdata (%u invsz)\n", vInv.size());

        if ((fDebug && vInv.size() > 0) || (vInv.size() == 1))
            LogPrint("net", "received getdata for: %s\n", vInv[0].ToString());

        pfrom->vRecvGetData.insert(pfrom->vRecvGetData.end(), vInv.begin(), vInv.end());
        ProcessGetData(pfrom);
    }


    else if (strCommand == "getblocks")
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        LOCK(cs_main);

        // Find the last block the caller has in the main chain
        CBlockIndex* pindex = locator.GetBlockIndex();

        // Send the rest of the chain
        if (pindex)
            pindex = pindex->pnext;
        int nLimit = 5000;
        LogPrint("net", "getblocks %d to %s limit %d\n", (pindex ? pindex->nHeight : -1), hashStop.ToString(), nLimit);
        for (; pindex; pindex = pindex->pnext)
        {
            if (pindex->GetBlockHash() == hashStop)
            {
                LogPrint("net", "  getblocks stopping at %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
                break;
            }
            pfrom->PushInventory(CInv(MSG_BLOCK, pindex->GetBlockHash()));
            if (--nLimit <= 0)
            {
                // When this block is requested, we'll send an inv that'll make them
                // getblocks the next batch of inventory.
                LogPrint("net", "  getblocks stopping at limit %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
                pfrom->hashContinue = pindex->GetBlockHash();
                break;
            }
        }
    }

    else if (strCommand == "getheaders")
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        LOCK(cs_main);

        CBlockIndex* pindex = NULL;
        if (locator.IsNull())
        {
            // If locator is null, return the hashStop block
            map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashStop);
            if (mi == mapBlockIndex.end())
                return true;
            pindex = (*mi).second;
        }
        else
        {
            // Find the last block the caller has in the main chain
            pindex = locator.GetBlockIndex();
            if (pindex)
                pindex = pindex->pnext;
        }

        vector<CBlock> vHeaders;
        int nLimit = 2000;
        LogPrint("net", "getheaders %d to %s\n", (pindex ? pindex->nHeight : -1), hashStop.ToString());
        for (; pindex; pindex = pindex->pnext)
        {
            vHeaders.push_back(pindex->GetBlockHeader());
            if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
                break;
        }
        pfrom->PushMessage("headers", vHeaders);
    }


    else if (strCommand == "tx"|| strCommand == "sstx")
    {
        vector<uint256> vWorkQueue;
        vector<uint256> vEraseQueue;
        CTransaction tx;

        //stormnode signed transaction
        bool allowFree = false;
        CTxIn vin;
        vector<unsigned char> vchSig;
        int64_t sigTime;
        CInv inv;
        CTxDB txdb("r");

        if(strCommand == "tx") {
               CInv inv(MSG_TX, tx.GetHash());
            // Check for recently rejected (and do other quick existence checks)
            if (AlreadyHave(txdb, inv))
                return true;

            vRecv >> tx;
        } else if (strCommand == "sstx") {
               CInv inv(MSG_SSTX, tx.GetHash());
            // Check for recently rejected (and do other quick existence checks)
            if (AlreadyHave(txdb, inv))
                return true;
            //these allow sasternodes to publish a limited amount of free transactions
            vRecv >> tx >> vin >> vchSig >> sigTime;

            CStormnode* psn = snodeman.Find(vin);
                if(psn != NULL)
                {
                    if(!psn->allowFreeTx){
                        //multiple peers can send us a valid stormnode transaction
                        if(fDebug) LogPrintf("sstx: Stormnode sending too many transactions %s\n", tx.GetHash().ToString().c_str());
                        return true;
                    }

                    std::string strMessage = tx.GetHash().ToString() + boost::lexical_cast<std::string>(sigTime);

                    std::string errorMessage = "";
                    if(!sandStormSigner.VerifyMessage(psn->pubkey2, vchSig, strMessage, errorMessage)){
                        LogPrintf("sstx: Got bad stormnode address signature %s \n", vin.ToString().c_str());
                        //pfrom->Misbehaving(20);
                        return false;
                    }

                    LogPrintf("sstx: Got Stormnode transaction %s\n", tx.GetHash().ToString().c_str());

                    allowFree = true;
                    psn->allowFreeTx = false;

                    if(!mapSandstormBroadcastTxes.count(tx.GetHash())){
                        CSandstormBroadcastTx sstx;
                        sstx.tx = tx;
                        sstx.vin = vin;
                        sstx.vchSig = vchSig;
                        sstx.sigTime = sigTime;

                        mapSandstormBroadcastTxes.insert(make_pair(tx.GetHash(), sstx));
                }
            }
        }

        pfrom->AddInventoryKnown(inv);

        LOCK(cs_main);

        bool fMissingInputs = false;
        CValidationState state;

        mapAlreadyAskedFor.erase(inv); 

        if (AcceptToMemoryPool(mempool, state, tx, true, &fMissingInputs, allowFree))
        {
            RelayTransaction(tx);
            vWorkQueue.push_back(inv.hash);
            vEraseQueue.push_back(inv.hash);

            // Recursively process any orphan transactions that depended on this one
            for (unsigned int i = 0; i < vWorkQueue.size(); i++)
            {
                map<uint256, set<uint256> >::iterator itByPrev = mapOrphanTransactionsByPrev.find(vWorkQueue[i]);
                if (itByPrev == mapOrphanTransactionsByPrev.end())
                    continue;
                for (set<uint256>::iterator mi = itByPrev->second.begin();
                     mi != itByPrev->second.end();
                     ++mi)
                {
                    const uint256& orphanTxHash = *mi;
                    COrphanTx& orphanTx = mapOrphanTransactions[orphanTxHash];
                    bool fMissingInputs2 = false;

                    if (AcceptToMemoryPool(mempool, state, orphanTx.tx, true, &fMissingInputs2))
                    {
                        LogPrint("mempool", "   accepted orphan tx %s\n", orphanTxHash.ToString());
                        RelayTransaction(orphanTx.tx);
                        vWorkQueue.push_back(orphanTxHash);
                        vEraseQueue.push_back(orphanTxHash);
                    }
                    else if (!fMissingInputs2)
                    {
                        // invalid or too-little-fee orphan
                        vEraseQueue.push_back(orphanTxHash);
                        LogPrint("mempool", "   removed orphan tx %s\n", orphanTxHash.ToString());
                    }
                }
            }

            BOOST_FOREACH(uint256 hash, vEraseQueue)
                EraseOrphanTx(hash);
        }
        else if (fMissingInputs)
        {
            AddOrphanTx(tx, pfrom->GetId());

            // DoS prevention: do not allow mapOrphanTransactions to grow unbounded
            unsigned int nEvicted = LimitOrphanTxSize(MAX_ORPHAN_TRANSACTIONS);
            if (nEvicted > 0)
                LogPrint("mempool", "mapOrphan overflow, removed %u tx\n", nEvicted);
        } else if (pfrom->fWhitelisted) {
            // Always relay transactions received from whitelisted peers, even
            // if they are already in the mempool (allowing the node to function
            // as a gateway for nodes hidden behind it).

            RelayTransaction(tx);
        }

        if(strCommand == "sstx"){
            CInv inv(MSG_SSTX, tx.GetHash());
            RelayInv(inv);
        }

        int nDoS = 0;
        if (state.IsInvalid(nDoS))
        {
            LogPrint("mempool", "%s from peer=%d %s was not accepted into the memory pool: %s\n", tx.GetHash().ToString(),
                pfrom->id, pfrom->cleanSubVer,
                state.GetRejectReason());
            pfrom->PushMessage("reject", strCommand, state.GetRejectCode(),
                               state.GetRejectReason().substr(0, MAX_REJECT_MESSAGE_LENGTH), inv.hash);
             if (tx.nDoS) pfrom->Misbehaving(tx.nDoS);
        }
    }        


    else if (strCommand == "block" && !fImporting && !fReindex) // Ignore blocks received while importing
    {
        CBlock block;
        vRecv >> block;
        uint256 hashBlock = block.GetHash();

        LogPrint("net", "received block %s\n", hashBlock.ToString());

        CInv inv(MSG_BLOCK, hashBlock);
        pfrom->AddInventoryKnown(inv);

        LOCK(cs_main);
        // Remember who we got this block from.
        mapBlockSource[inv.hash] = pfrom->GetId();
        MarkBlockAsReceived(inv.hash, pfrom->GetId());

        if (ProcessBlock(pfrom, &block))//TODO (Amir): Change ProcessBlock?
            mapAlreadyAskedFor.erase(inv); //TODO (Amir): Not needed?
        if (block.nDoS) pfrom->Misbehaving(block.nDoS);
        if (fSecMsgEnabled)
            SecureMsgScanBlock(block);
    }

    // This asymmetric behavior for inbound and outbound connections was introduced
    // to prevent a fingerprinting attack: an attacker can send specific fake addresses
    // to users' AddrMan and later request them by sending getaddr messages.
    // Making users (which are behind NAT and can only make outgoing connections) ignore
    // getaddr message mitigates the attack.
    else if ((strCommand == "getaddr") && (pfrom->fInbound))
    {
        // Don't return addresses older than nCutOff timestamp
        int64_t nCutOff = GetTime() - (nNodeLifespan * 24 * 60 * 60);
        pfrom->vAddrToSend.clear();
        vector<CAddress> vAddr = addrman.GetAddr();
        BOOST_FOREACH(const CAddress &addr, vAddr)
            if(addr.nTime > nCutOff)
                pfrom->PushAddress(addr);
    }


    else if (strCommand == "mempool")
    {
        LOCK(cs_main);

        std::vector<uint256> vtxid;
        mempool.queryHashes(vtxid);
        vector<CInv> vInv;
        for (unsigned int i = 0; i < vtxid.size(); i++) {
            CInv inv(MSG_TX, vtxid[i]);
            vInv.push_back(inv);
            if (i == (MAX_INV_SZ - 1))
                    break;
        }
        if (vInv.size() > 0)
            pfrom->PushMessage("inv", vInv);
    }


    else if (strCommand == "ping")
    {
        uint64_t nonce = 0;
        vRecv >> nonce;
        // Echo the message back with the nonce. This allows for two useful features:
        //
        // 1) A remote node can quickly check if the connection is operational
        // 2) Remote nodes can measure the latency of the network thread. If this node
        //    is overloaded it won't respond to pings quickly and the remote node can
        //    avoid sending us more work, like chain download requests.
        //
        // The nonce stops the remote getting confused between different pings: without
        // it, if the remote node sends a ping once per second and this node takes 5
        // seconds to respond to each, the 5th ping the remote sends would appear to
        // return very quickly.
        pfrom->PushMessage("pong", nonce);

    }


    else if (strCommand == "pong")
    {
        int64_t pingUsecEnd = nTimeReceived;
        uint64_t nonce = 0;
        size_t nAvail = vRecv.in_avail();
        bool bPingFinished = false;
        std::string sProblem;

        if (nAvail >= sizeof(nonce)) {
            vRecv >> nonce;

            // Only process pong message if there is an outstanding ping (old ping without nonce should never pong)
            if (pfrom->nPingNonceSent != 0) {
                if (nonce == pfrom->nPingNonceSent) {
                    // Matching pong received, this ping is no longer outstanding
                    bPingFinished = true;
                    int64_t pingUsecTime = pingUsecEnd - pfrom->nPingUsecStart;
                    if (pingUsecTime > 0) {
                        // Successful ping time measurement, replace previous
                        pfrom->nPingUsecTime = pingUsecTime;
                    } else {
                        // This should never happen
                        sProblem = "Timing mishap";
                    }
                } else {
                    // Nonce mismatches are normal when pings are overlapping
                    sProblem = "Nonce mismatch";
                    if (nonce == 0) {
                        // This is most likely a bug in another implementation somewhere, cancel this ping
                        bPingFinished = true;
                        sProblem = "Nonce zero";
                    }
                }
            } else {
                sProblem = "Unsolicited pong without ping";
            }
        } else {
            // This is most likely a bug in another implementation somewhere, cancel this ping
            bPingFinished = true;
            sProblem = "Short payload";
        }

        if (!(sProblem.empty())) {
            LogPrint("net", "pong %s %s: %s, %x expected, %x received, %zu bytes\n"
                , pfrom->addr.ToString()
                , pfrom->strSubVer
                , sProblem
                , pfrom->nPingNonceSent
                , nonce
                , nAvail);
        }
        if (bPingFinished) {
            pfrom->nPingNonceSent = 0;
        }
    }


    else if (strCommand == "alert")
    {
        CAlert alert;
        vRecv >> alert;

        uint256 alertHash = alert.GetHash();
        if (pfrom->setKnown.count(alertHash) == 0)
        {
            if (alert.ProcessAlert())
            {
                // Relay
                pfrom->setKnown.insert(alertHash);
                {
                    LOCK(cs_vNodes);
                    BOOST_FOREACH(CNode* pnode, vNodes)
                        alert.RelayTo(pnode);
                }
            }
            else {
                // Small DoS penalty so peers that send us lots of
                // duplicate/expired/invalid-signature/whatever alerts
                // eventually get banned.
                // This isn't a Misbehaving(100) (immediate ban) because the
                // peer might be an older or different implementation with
                // a different signature key, etc.
                pfrom->Misbehaving(10);
            }
        }
    }
else if (strCommand == "filterload")
    {
        CBloomFilter filter;
        vRecv >> filter;

        if (!filter.IsWithinSizeConstraints())
            // There is no excuse for sending a too-large filter
            Misbehaving(pfrom->GetId(), 100);
        else
        {
            LOCK(pfrom->cs_filter);
            delete pfrom->pfilter;
            pfrom->pfilter = new CBloomFilter(filter);
            pfrom->pfilter->UpdateEmptyFull();
        }
        pfrom->fRelayTxes = true;
    }


    else if (strCommand == "filteradd")
    {
        vector<unsigned char> vData;
        vRecv >> vData;

        // Nodes must NEVER send a data item > 520 bytes (the max size for a script data object,
        // and thus, the maximum size any matched object can have) in a filteradd message
        if (vData.size() > MAX_SCRIPT_ELEMENT_SIZE)
        {
            Misbehaving(pfrom->GetId(), 100);
        } else {
            LOCK(pfrom->cs_filter);
            if (pfrom->pfilter)
                pfrom->pfilter->insert(vData);
            else
                Misbehaving(pfrom->GetId(), 100);
        }
    }


    else if (strCommand == "filterclear")
    {
        LOCK(pfrom->cs_filter);
        delete pfrom->pfilter;
        pfrom->pfilter = new CBloomFilter();
        pfrom->fRelayTxes = true;
    }


    else if (strCommand == "reject")
    {
        if (fDebug) {
            try {
                string strMsg; unsigned char ccode; string strReason;
                vRecv >> LIMITED_STRING(strMsg, CMessageHeader::COMMAND_SIZE) >> ccode >> LIMITED_STRING(strReason, MAX_REJECT_MESSAGE_LENGTH);

                ostringstream ss;
                ss << strMsg << " code " << itostr(ccode) << ": " << strReason;

                if (strMsg == "block" || strMsg == "tx")
                {
                    uint256 hash;
                    vRecv >> hash;
                    ss << ": hash " << hash.ToString();
                }
                LogPrint("net", "Reject %s\n", SanitizeString(ss.str()));
            } catch (std::ios_base::failure& e) {
                // Avoid feedback loops by preventing reject messages from triggering a new reject message.
                LogPrint("net", "Unparseable reject message received\n");
            }
        }
    }
    else
    {
        sandStormPool.ProcessMessageSandstorm(pfrom, strCommand, vRecv);
        snodeman.ProcessMessage(pfrom, strCommand, vRecv);
        budget.ProcessMessage(pfrom, strCommand, vRecv);
        stormnodePayments.ProcessMessageStormnodePayments(pfrom, strCommand, vRecv);
        ProcessMessageInstantX(pfrom, strCommand, vRecv);
        ProcessSpork(pfrom, strCommand, vRecv);
    if (fSecMsgEnabled)
        SecureMsgReceiveData(pfrom, strCommand, vRecv);
        // Ignore unknown commands for extensibility
    }


    // Update the last seen time for this node's address
    if (pfrom->fNetworkNode)
        if (strCommand == "version" || strCommand == "addr" || strCommand == "inv" || strCommand == "getdata" || strCommand == "ping")
            AddressCurrentlyConnected(pfrom->addr);


    return true;
}

// requires LOCK(cs_vRecvMsg)
bool ProcessMessages(CNode* pfrom)
{
    //if (fDebug)
    //    LogPrintf("ProcessMessages(%zu messages)\n", pfrom->vRecvMsg.size());

    //
    // Message format
    //  (4) message start
    //  (12) command
    //  (4) size
    //  (4) checksum
    //  (x) data
    //
    bool fOk = true;

    if (!pfrom->vRecvGetData.empty())
        ProcessGetData(pfrom);

    // this maintains the order of responses
    if (!pfrom->vRecvGetData.empty()) return fOk;

    std::deque<CNetMessage>::iterator it = pfrom->vRecvMsg.begin();
    while (!pfrom->fDisconnect && it != pfrom->vRecvMsg.end()) {
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->nSendSize >= SendBufferSize())
            break;

        // get next message
        CNetMessage& msg = *it;

        //if (fDebug)
        //    LogPrintf("ProcessMessages(message %u msgsz, %zu bytes, complete:%s)\n",
        //            msg.hdr.nMessageSize, msg.vRecv.size(),
        //            msg.complete() ? "Y" : "N");

        // end, if an incomplete message is found
        if (!msg.complete())
            break;

        // at this point, any failure means we can delete the current message
        it++;

        // Scan for message start
        if (memcmp(msg.hdr.pchMessageStart, Params().MessageStart(), MESSAGE_START_SIZE) != 0) {
            LogPrintf("\n\nPROCESSMESSAGE: INVALID MESSAGESTART\n\n");
            fOk = false;
            break;
        }

        // Read header
        CMessageHeader& hdr = msg.hdr;
        if (!hdr.IsValid())
        {
            LogPrintf("\n\nPROCESSMESSAGE: ERRORS IN HEADER %s\n\n\n", hdr.GetCommand());
            continue;
        }
        string strCommand = hdr.GetCommand();

        // Message size
        unsigned int nMessageSize = hdr.nMessageSize;

        // Checksum
        CDataStream& vRecv = msg.vRecv;
        uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
        unsigned int nChecksum = 0;
        memcpy(&nChecksum, &hash, sizeof(nChecksum));
        if (nChecksum != hdr.nChecksum)
        {
            LogPrintf("ProcessMessages(%s, %u bytes) : CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x\n",
               strCommand, nMessageSize, nChecksum, hdr.nChecksum);
            continue;
        }

        // Process message
        bool fRet = false;
        try
        {
            fRet = ProcessMessage(pfrom, strCommand, vRecv, msg.nTime);
            boost::this_thread::interruption_point();
        }
        catch (std::ios_base::failure& e)
        {
            if (strstr(e.what(), "end of data"))
            {
                // Allow exceptions from under-length message on vRecv
                LogPrintf("ProcessMessages(%s, %u bytes) : Exception '%s' caught, normally caused by a message being shorter than its stated length\n", strCommand, nMessageSize, e.what());
            }
            else if (strstr(e.what(), "size too large"))
            {
                // Allow exceptions from over-long size
                LogPrintf("ProcessMessages(%s, %u bytes) : Exception '%s' caught\n", strCommand, nMessageSize, e.what());
            }
            else
            {
                PrintExceptionContinue(&e, "ProcessMessages()");
            }
        }
        catch (boost::thread_interrupted) {
            throw;
        }
        catch (std::exception& e) {
            PrintExceptionContinue(&e, "ProcessMessages()");
        } catch (...) {
            PrintExceptionContinue(NULL, "ProcessMessages()");
        }

        if (!fRet)
            LogPrintf("ProcessMessage(%s, %u bytes) FAILED\n", strCommand, nMessageSize);

        break;
    }

    // In case the connection got shut down, its receive buffer was wiped
    if (!pfrom->fDisconnect)
        pfrom->vRecvMsg.erase(pfrom->vRecvMsg.begin(), it);

    return fOk;
}


bool SendMessages(CNode* pto, bool fSendTrickle)
{
    {
        // Don't send anything until we get their version message
        if (pto->nVersion == 0)
            return true;

        //
        // Message: ping
        //
        bool pingSend = false;
        if (pto->fPingQueued) {
            // RPC ping request by user
            pingSend = true;
        }
        if (pto->nPingNonceSent == 0 && pto->nPingUsecStart + PING_INTERVAL * 1000000 < GetTimeMicros()) {
            // Ping automatically sent as a latency probe & keepalive.
            pingSend = true;
        }
        if (pingSend) {
            uint64_t nonce = 0;
            while (nonce == 0) {
                GetRandBytes((unsigned char*)&nonce, sizeof(nonce));
            }
            pto->fPingQueued = false;
            pto->nPingUsecStart = GetTimeMicros();
            pto->nPingNonceSent = nonce;
            pto->PushMessage("ping", nonce);
        }

        TRY_LOCK(cs_main, lockMain); // Acquire cs_main for IsInitialBlockDownload() and CNodeState()
        if (!lockMain)
            return true;

        // Start block sync
        if (pto->fStartSync && !fImporting && !fReindex) {
            pto->fStartSync = false;
            PushGetBlocks(pto, pindexBest, uint256(0));
        }

        // Resend wallet transactions that haven't gotten in a block yet
        // Except during reindex, importing and IBD, when old wallet
        // transactions become unconfirmed and spams other nodes.
        if (!fReindex && !fImporting && !IsInitialBlockDownload())
        {
            ResendWalletTransactions();
        }

        // Address refresh broadcast
        static int64_t nLastRebroadcast;
        if (!IsInitialBlockDownload() && (GetTime() - nLastRebroadcast > 24 * 60 * 60))
        {
            LOCK(cs_vNodes);
            BOOST_FOREACH(CNode* pnode, vNodes)
            {
                // Periodically clear setAddrKnown to allow refresh broadcasts
                if (nLastRebroadcast)
                    pnode->setAddrKnown.clear();

                // Rebroadcast our address
                AdvertizeLocal(pnode);
            }
            if (!vNodes.empty())
                nLastRebroadcast = GetTime();
        }

        //
        // Message: addr
        //
        if (fSendTrickle)
        {
            vector<CAddress> vAddr;
            vAddr.reserve(pto->vAddrToSend.size());
            BOOST_FOREACH(const CAddress& addr, pto->vAddrToSend)
            {
                // returns true if wasn't already contained in the set
                if (pto->setAddrKnown.insert(addr).second)
                {
                    vAddr.push_back(addr);
                    // receiver rejects addr messages larger than 1000
                    if (vAddr.size() >= 1000)
                    {
                        pto->PushMessage("addr", vAddr);
                        vAddr.clear();
                    }
                }
            }
            pto->vAddrToSend.clear();
            if (!vAddr.empty())
                pto->PushMessage("addr", vAddr);
        }

//TODO (AA) - ChainActive/Headers First needs implementing

/*        CNodeState &state = *State(pto->GetId());
        if (state.fShouldBan) {
            if (pto->fWhitelisted)
                LogPrintf("Warning: not punishing whitelisted peer %s!\n", pto->addr.ToString());
            else {
                pto->fDisconnect = true;
                if (pto->addr.IsLocal())
                    LogPrintf("Warning: not banning local peer %s!\n", pto->addr.ToString());
                else
                {
                    CNode::Ban(pto->addr);
                }
            }
            state.fShouldBan = false;
        }

        BOOST_FOREACH(const CBlockReject& reject, state.rejects)
            pto->PushMessage("reject", (string)"block", reject.chRejectCode, reject.strRejectReason, reject.hashBlock);
        state.rejects.clear();

        // Start block sync
        if (pindexBestHeader == NULL)
            pindexBestHeader = chainActive.Tip();
        bool fFetch = state.fPreferredDownload || (nPreferredDownload == 0 && !pto->fClient && !pto->fOneShot); // Download if this is a nice peer, or we have no nice peers and this one might do.
        if (!state.fSyncStarted && !pto->fClient && fFetch && !fImporting && !fReindex) {
            // Only actively request headers from a single peer, unless we're close to end of initial download.
            if (nSyncStarted == 0 || pindexBestHeader->GetBlockTime() > GetAdjustedTime() - 6 * 60 * 60) { // NOTE: was "close to today" and 24h in Bitcoin
                state.fSyncStarted = true;
                nSyncStarted++;
                CBlockIndex *pindexStart = pindexBestHeader->pprev ? pindexBestHeader->pprev : pindexBestHeader;
                LogPrint("net", "initial getheaders (%d) to peer=%d (startheight:%d)\n", pindexStart->nHeight, pto->id, pto->nStartingHeight);
                pto->PushMessage("getheaders", chainActive.GetLocator(pindexStart), uint256(0));
            }
        }

        // Resend wallet transactions that haven't gotten in a block yet
        // Except during reindex, importing and IBD, when old wallet
        // transactions become unconfirmed and spams other nodes.
        if (!fReindex && !fImporting && !IsInitialBlockDownload())
        {
            g_signals.Broadcast();
        }
*/
        //
        // Message: inventory
        //
        vector<CInv> vInv;
        vector<CInv> vInvWait;
        {
            LOCK(pto->cs_inventory);
            vInv.reserve(pto->vInventoryToSend.size());
            vInvWait.reserve(pto->vInventoryToSend.size());
            BOOST_FOREACH(const CInv& inv, pto->vInventoryToSend)
            {
                if (pto->setInventoryKnown.count(inv))
                    continue;

                // trickle out tx inv to protect privacy
                if (inv.type == MSG_TX && !fSendTrickle)
                {
                    // 1/4 of tx invs blast to all immediately
                    static uint256 hashSalt;
                    if (hashSalt == 0)
                        hashSalt = GetRandHash();
                    uint256 hashRand = inv.hash ^ hashSalt;
                    hashRand = Hash(BEGIN(hashRand), END(hashRand));
                    bool fTrickleWait = ((hashRand & 3) != 0);

                    if (fTrickleWait)
                    {
                        vInvWait.push_back(inv);
                        continue;
                    }
                }

                // returns true if wasn't already contained in the set
                if (pto->setInventoryKnown.insert(inv).second)
                {
                    vInv.push_back(inv);
                    if (vInv.size() >= 1000)
                    {
                        pto->PushMessage("inv", vInv);
                        vInv.clear();
                    }
                }
            }
            pto->vInventoryToSend = vInvWait;
        }
        if (!vInv.empty())
            pto->PushMessage("inv", vInv);


        // Detect stalled peers. Require that blocks are in flight, we haven't
        // received a (requested) block in one minute, and that all blocks are
        // in flight for over two minutes, since we first had a chance to
        // process an incoming block.
        CNodeState &state = *State(pto->GetId());
        int64_t nNow = GetTimeMicros();
        if (!pto->fDisconnect && state.nBlocksInFlight &&
            state.nLastBlockReceive < state.nLastBlockProcess - BLOCK_DOWNLOAD_TIMEOUT*1000000 &&
            state.vBlocksInFlight.front().nTime < state.nLastBlockProcess - 2*BLOCK_DOWNLOAD_TIMEOUT*1000000) {
            LogPrintf("Peer %s is stalling block download, disconnecting\n", state.name.c_str());
            pto->fDisconnect = true;
        }

        //
        // Message: getdata (blocks)
        //
        vector<CInv> vGetData;
        while (!pto->fDisconnect && state.nBlocksToDownload && state.nBlocksInFlight < MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
            uint256 hash = state.vBlocksToDownload.front();
            vGetData.push_back(CInv(MSG_BLOCK, hash));
            MarkBlockAsInFlight(pto->GetId(), hash);
            LogPrint("net", "Requesting block %s from %s\n", hash.ToString().c_str(), state.name.c_str());
            if (vGetData.size() >= 1000)
            {
                pto->PushMessage("getdata", vGetData);
                vGetData.clear();
            }
        }
        //
        // Message: getdata (non-blocks)
        //

        CTxDB txdb("r");
        while (!pto->mapAskFor.empty() && (*pto->mapAskFor.begin()).first <= nNow)
        {
            const CInv& inv = (*pto->mapAskFor.begin()).second;
            if (!AlreadyHave(txdb, inv))
            {
                if (fDebug)
                    LogPrint("net", "Requesting %s peer=%d\n", inv.ToString(), pto->id);
                vGetData.push_back(inv);
                if (vGetData.size() >= 1000)
                {
                    pto->PushMessage("getdata", vGetData);
                    vGetData.clear();
                }
            }
            pto->mapAskFor.erase(pto->mapAskFor.begin());
        }
        if (!vGetData.empty())
            pto->PushMessage("getdata", vGetData);
        if (fSecMsgEnabled)
            SecureMsgSendData(pto, fSendTrickle); // should be in cs_main?
    }
    return true;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//CTransactionPoS
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
CAmount CTransactionPoS::GetValueOut(CTransaction& tx) const
{
    set<COutPoint> vInOutPoints;

    CAmount nValueOut = 0;
    BOOST_FOREACH(const CTxOut& txout, tx.vout)
    {
        nValueOut += txout.nValue;
        if (!MoneyRange(txout.nValue) || !MoneyRange(nValueOut))
        {
            printf("CTransactionPoS::GetValueOut, value out of range tx.vout = %ld, nValueOut = %ld, MAX_MONEY = %ld \n", txout.nValue, nValueOut, MAX_MONEY);
            throw std::runtime_error("CTransaction::GetValueOut() : value out of range");
        }
    }
    return nValueOut;
}

bool CTransactionPoS::ReadFromDisk(CTransaction& tx, CDiskTxPos pos, FILE** pfileRet)
{
    CAutoFile filein = CAutoFile(OpenBlockFile(pos.nFile, 0, pfileRet ? "rb+" : "rb"), SER_DISK, CLIENT_VERSION);
    if (!filein)
        return error("CTransactionPoS::ReadFromDisk() : OpenBlockFile failed");

    // Read transaction
    if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
        return error("CTransactionPoS::ReadFromDisk() : fseek failed");

    try {
        filein >> tx;
    }
    catch (std::exception &e) {
        return error("%s() : deserialize or I/O error", __PRETTY_FUNCTION__);
    }

    // Return file pointer
    if (pfileRet)
    {
        if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
            return error("CTransactionPoS::ReadFromDisk() : second fseek failed");
        *pfileRet = filein.release();
    }
    return true;
}

bool CTransactionPoS::ReadFromDisk(CTransaction& tx, CTxDB& txdb, const uint256& hash, CTxIndex& txindexRet)
{
    tx.SetNull();
    if (!txdb.ReadTxIndex(hash, txindexRet))
        return false;
    CTransactionPoS txPoS;
    if (!txPoS.ReadFromDisk(tx, txindexRet.pos))
        return false;
    return true;
}

bool CTransactionPoS::ReadFromDisk(CTransaction& tx, CTxDB& txdb, COutPoint prevout, CTxIndex& txindexRet)
{
    if (!ReadFromDisk(tx, txdb, prevout.hash, txindexRet))
        return false;
    if (prevout.n >= tx.vout.size())
    {
        tx.SetNull();
        return false;
    }
    return true;
}

bool CTransactionPoS::ReadFromDisk(CTransaction& tx, CTxDB& txdb, COutPoint prevout)
{
    CTxIndex txindex;
    return ReadFromDisk(tx, txdb, prevout, txindex);
}

bool CTransactionPoS::ReadFromDisk(CTransaction& tx, COutPoint prevout)
{
    CTxDB txdb("r");
    CTxIndex txindex;
    return ReadFromDisk(tx, txdb, prevout, txindex);
}

bool CTransactionPoS::DisconnectInputs(CTransaction& tx, CTxDB& txdb)
{
    // Relinquish previous transactions' spent pointers
    if (!tx.IsCoinBase())
    {
        BOOST_FOREACH(const CTxIn& txin, tx.vin)
        {
            COutPoint prevout = txin.prevout;

            // Get prev txindex from disk
            CTxIndex txindex;
            if (!txdb.ReadTxIndex(prevout.hash, txindex))
                return error("DisconnectInputs() : ReadTxIndex failed");

            if (prevout.n >= txindex.vSpent.size())
                return error("DisconnectInputs() : prevout.n out of range");

            // Mark outpoint as not spent
            txindex.vSpent[prevout.n].SetNull();

            // Write back
            if (!txdb.UpdateTxIndex(prevout.hash, txindex))
                return error("DisconnectInputs() : UpdateTxIndex failed");
        }
    }
    // Remove transaction from index
    // This can fail if a duplicate of this transaction was in a chain that got
    // reorganized away. This is only possible if this transaction was completely
    // spent, so erasing it would be a no-op anyway.
    txdb.EraseTxIndex(tx);

    return true;
}


bool CTransactionPoS::FetchInputs(CTransaction& tx, CTxDB& txdb, const map<uint256, CTxIndex>& mapTestPool,
                               bool fBlock, bool fMiner, MapPrevTx& inputsRet, bool& fInvalid)
{
    // FetchInputs can return false either because we just haven't seen some inputs
    // (in which case the transaction should be stored as an orphan)
    // or because the transaction is malformed (in which case the transaction should
    // be dropped).  If tx is definitely invalid, fInvalid will be set to true.
    fInvalid = false;

    if (tx.IsCoinBase())
        return true; // Coinbase transactions have no inputs to fetch.

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        COutPoint prevout = tx.vin[i].prevout;
        if (inputsRet.count(prevout.hash))
            continue; // Got it already

        // Read txindex
        CTxIndex& txindex = inputsRet[prevout.hash].first;
        bool fFound = true;
        if ((fBlock || fMiner) && mapTestPool.count(prevout.hash))
        {
            // Get txindex from current proposed changes
            txindex = mapTestPool.find(prevout.hash)->second;
        }
        else
        {
            // Read txindex from txdb
            fFound = txdb.ReadTxIndex(prevout.hash, txindex);
        }
        if (!fFound && (fBlock || fMiner))
            return fMiner ? false : error("FetchInputs() : %s prev tx %s index entry not found", tx.GetHash().ToString(),  prevout.hash.ToString());

        // Read txPrev
        CTransaction& txPrev = inputsRet[prevout.hash].second;
        if (!fFound || txindex.pos == CDiskTxPos(1,1,1))
        {
            // Get prev tx from single transactions in memory
            if (!mempool.lookup(prevout.hash, txPrev))
                return error("FetchInputs() : %s mempool Tx prev not found %s", tx.GetHash().ToString(),  prevout.hash.ToString());
            if (!fFound)
                txindex.vSpent.resize(txPrev.vout.size());
        }
        else
        {
            CTransactionPoS txPoS;
            // Get prev tx from disk
            if (!txPoS.ReadFromDisk(txPrev, txindex.pos))
                return error("FetchInputs() : %s ReadFromDisk prev tx %s failed", tx.GetHash().ToString(),  prevout.hash.ToString());
        }
    }

    // Make sure all prevout.n indexes are valid:
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const COutPoint prevout = tx.vin[i].prevout;
        assert(inputsRet.count(prevout.hash) != 0);
        const CTxIndex& txindex = inputsRet[prevout.hash].first;
        const CTransaction& txPrev = inputsRet[prevout.hash].second;
        if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size())
        {
            // Revisit this if/when transaction replacement is implemented and allows
            // adding inputs:
            fInvalid = true;
            return tx.DoS(100, error("FetchInputs() : %s prevout.n out of range %d %u %u prev tx %s\n%s", tx.GetHash().ToString(), prevout.n, txPrev.vout.size(), txindex.vSpent.size(), prevout.hash.ToString(), txPrev.ToString()));
        }
    }

    return true;
}

const CTxOut& CTransactionPoS::GetOutputFor(const CTxIn& input, const MapPrevTx& inputs) const
{
    MapPrevTx::const_iterator mi = inputs.find(input.prevout.hash);
    if (mi == inputs.end())
        throw std::runtime_error("CTransactionPoS::GetOutputFor() : prevout.hash not found");

    const CTransaction& txPrev = (mi->second).second;
    if (input.prevout.n >= txPrev.vout.size())
        throw std::runtime_error("CTransactionPoS::GetOutputFor() : prevout.n out of range");

    return txPrev.vout[input.prevout.n];
}

CAmount CTransactionPoS::GetValueIn(CTransaction& tx, const MapPrevTx& inputs) const
{
    if (tx.IsCoinBase())
        return 0;

    CAmount nResult = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        nResult += GetOutputFor(tx.vin[i], inputs).nValue;
    }
    return nResult;

}

bool CTransactionPoS::ConnectInputs(CTransaction& tx, CTxDB& txdb, MapPrevTx inputs, map<uint256, CTxIndex>& mapTestPool, const CDiskTxPos& posThisTx,
    const CBlockIndex* pindexBlock, bool fBlock, bool fMiner, unsigned int flags, bool fValidateSig)
{
    // Take over previous transactions' spent pointers
    // fBlock is true when this is called from AcceptBlock when a new best-block is added to the blockchain
    // fMiner is true when called from the internal darksilk miner
    // ... both are false when called from CTransactionPoS::AcceptToMemoryPool
    if (!tx.IsCoinBase())
    {
        CAmount nValueIn = 0;
        CAmount nFees = 0;
        for (unsigned int i = 0; i < tx.vin.size(); i++)
        {
            COutPoint prevout = tx.vin[i].prevout;
            assert(inputs.count(prevout.hash) > 0);
            CTxIndex& txindex = inputs[prevout.hash].first;
            CTransaction& txPrev = inputs[prevout.hash].second;

            if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size())
                return tx.DoS(100, error("ConnectInputs() : %s prevout.n out of range %d %u %u prev tx %s\n%s", tx.GetHash().ToString(), prevout.n, txPrev.vout.size(), txindex.vSpent.size(), prevout.hash.ToString(), txPrev.ToString()));

            // If prev is coinbase or coinstake, check that it's matured
            if (txPrev.IsCoinBase() || txPrev.IsCoinStake())
            {
                int nSpendDepth;
                if (IsConfirmedInNPrevBlocks(txindex, pindexBlock, COINBASE_MATURITY, nSpendDepth))
                    return error("ConnectInputs() : tried to spend %s at depth %d", txPrev.IsCoinBase() ? "coinbase" : "coinstake", nSpendDepth);
            }
            // ppcoin: check transaction timestamp
            if (txPrev.nTime > tx.nTime)
                return tx.DoS(100, error("ConnectInputs() : transaction timestamp earlier than input transaction"));

            if (txPrev.vout[prevout.n].IsEmpty())
                return tx.DoS(1, error("ConnectInputs() : special marker is not spendable"));

            // Check for negative or overflow input values
            nValueIn += txPrev.vout[prevout.n].nValue;
            if (!MoneyRange(txPrev.vout[prevout.n].nValue) || !MoneyRange(nValueIn))
                return tx.DoS(100, error("ConnectInputs() : txin values out of range"));

        }
        // The first loop above does all the inexpensive checks.
        // Only if ALL inputs pass do we perform expensive ECDSA signature checks.
        // Helps prevent CPU exhaustion attacks.
        for (unsigned int i = 0; i < tx.vin.size(); i++)
        {
            COutPoint prevout = tx.vin[i].prevout;
            assert(inputs.count(prevout.hash) > 0);
            CTxIndex& txindex = inputs[prevout.hash].first;
            CTransaction& txPrev = inputs[prevout.hash].second;

            // Check for conflicts (double-spend)
            // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
            // for an attacker to attempt to split the network.
            if (!txindex.vSpent[prevout.n].IsNull())
                return fMiner ? false : error("ConnectInputs() : %s prev tx already used at %s", tx.GetHash().ToString(), txindex.vSpent[prevout.n].ToString());

            if(fValidateSig)
       {
            // Skip ECDSA signature verification when connecting blocks (fBlock=true)
            // before the last blockchain checkpoint. This is safe because block merkle hashes are
            // still computed and checked, and any change will be caught at the next checkpoint.
            if (!(fBlock && (nBestHeight < Checkpoints::GetTotalBlocksEstimate())))
            {
                // Verify signature
                if (!VerifySignature(txPrev, tx, i, flags, 0))
                {
                    if (flags & STANDARD_NOT_MANDATORY_VERIFY_FLAGS) {
                        // Check whether the failure was caused by a
                        // non-mandatory script verification check, such as
                        // non-null dummy arguments;
                        // if so, don't trigger DoS protection to
                        // avoid splitting the network between upgraded and
                        // non-upgraded nodes.
                        if (VerifySignature(txPrev, tx, i, flags & ~STANDARD_NOT_MANDATORY_VERIFY_FLAGS, 0))
                            return error("ConnectInputs() : %s non-mandatory VerifySignature failed", tx.GetHash().ToString());
                    }
                    // Failures of other flags indicate a transaction that is
                    // invalid in new blocks, e.g. a invalid P2SH. We DoS ban
                    // such nodes as they are not following the protocol. That
                    // said during an upgrade careful thought should be taken
                    // as to the correct behavior - we may want to continue
                    // peering with non-upgraded nodes even after a soft-fork
                    // super-majority vote has passed.
                    return tx.DoS(100,error("ConnectInputs() : %s VerifySignature failed", tx.GetHash().ToString()));
                }
            }
       }

            // Mark outpoints as spent
            txindex.vSpent[prevout.n] = posThisTx;

            // Write back
            if (fBlock || fMiner)
            {
                mapTestPool[prevout.hash] = txindex;
            }
        }

        if (!tx.IsCoinStake())
        {
            CTransactionPoS txPoS;
            CAmount iValOut = txPoS.GetValueOut(tx);
            //int64_t iDiff = iValOut - nValueIn;
            if (nValueIn < iValOut) //TODO (Amir): Tx sending error here...
                return tx.DoS(100, error("ConnectInputs() : %s value in < value out", tx.GetHash().ToString()));

            // Tally transaction fees
            CAmount nTxFee = nValueIn - iValOut;
            if (nTxFee < 0)
                return tx.DoS(100, error("ConnectInputs() : %s nTxFee < 0", tx.GetHash().ToString()));

            /* enforce transaction fees for every block
            int64_t nRequiredFee = GetMinFee(*tx);
            if (nTxFee < nRequiredFee)
                return fBlock? DoS(100, error("ConnectInputs() : %s not paying required fee=%s, paid=%s", tx.GetHash().ToString(), FormatMoney(nRequiredFee), FormatMoney(nTxFee))) : false;
            */

            nFees += nTxFee;
            if (!MoneyRange(nFees))
                return tx.DoS(100, error("ConnectInputs() : nFees out of range"));
        }
    }

    return true;
}

void static FlushBlockFile(bool fFinalize = false)
{
    LOCK(cs_LastBlockFile);

    CDiskBlockPos posOld(nLastBlockFile, 0);

    FILE *fileOld = OpenBlockFile(posOld);
    if (fileOld) {
        if (fFinalize)
            TruncateFile(fileOld, vinfoBlockFile[nLastBlockFile].nSize);
        FileCommit(fileOld);
        fclose(fileOld);
    }

    fileOld = OpenUndoFile(posOld);
    if (fileOld) {
        if (fFinalize)
            TruncateFile(fileOld, vinfoBlockFile[nLastBlockFile].nUndoSize);
        FileCommit(fileOld);
        fclose(fileOld);
    }
}

enum FlushStateMode {
    FLUSH_STATE_IF_NEEDED,
    FLUSH_STATE_PERIODIC,
    FLUSH_STATE_ALWAYS
};

static filesystem::path BlockFilePath(unsigned int nFile)
{
    string strBlockFn = strprintf("blk%04u.dat", nFile);
    return GetDataDir() / strBlockFn;
}

boost::filesystem::path GetBlockPosFilename(const CDiskBlockPos &pos, const char *prefix)
{
    return GetDataDir() / "blocks" / strprintf("%s%05u.dat", prefix, pos.nFile);
}

FILE* OpenDiskFile(const CDiskBlockPos &pos, const char *prefix, bool fReadOnly)
{
    if (pos.IsNull())
        return NULL;
    boost::filesystem::path path = GetBlockPosFilename(pos, prefix);
    boost::filesystem::create_directories(path.parent_path());
    FILE* file = fopen(path.string().c_str(), "rb+");
    if (!file && !fReadOnly)
        file = fopen(path.string().c_str(), "wb+");
    if (!file) {
        LogPrintf("Unable to open file %s\n", path.string());
        return NULL;
    }
    if (pos.nPos) {
        if (fseek(file, pos.nPos, SEEK_SET)) {
            LogPrintf("Unable to seek to position %u of %s\n", pos.nPos, path.string());
            fclose(file);
            return NULL;
        }
    }
    return file;
}

FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode)
{
    if ((nFile < 1) || (nFile == (unsigned int) -1))
        return NULL;
    FILE* file = fopen(BlockFilePath(nFile).string().c_str(), pszMode);
    if (!file)
        return NULL;
    if (nBlockPos != 0 && !strchr(pszMode, 'a') && !strchr(pszMode, 'w'))
    {
        if (fseek(file, nBlockPos, SEEK_SET) != 0)
        {
            fclose(file);
            return NULL;
        }
    }
    return file;
}

FILE* OpenBlockFile(const CDiskBlockPos &pos, bool fReadOnly) {
    return OpenDiskFile(pos, "blk", fReadOnly);
}

FILE* OpenUndoFile(const CDiskBlockPos &pos, bool fReadOnly) {
    return OpenDiskFile(pos, "rev", fReadOnly);
}


///! Update the on-disk chain state.
///! The caches and indexes are flushed if either they're too large, forceWrite is set, or
///! fast is not set and it's been a while since the last write.
bool static FlushStateToDisk(CValidationState &state, FlushStateMode mode) {
    LOCK(cs_main);
    static int64_t nLastWrite = 0;
    try {
    if ((mode == FLUSH_STATE_ALWAYS) ||
        ((mode == FLUSH_STATE_PERIODIC || mode == FLUSH_STATE_IF_NEEDED) && pcoinsTip->GetCacheSize() > nCoinCacheSize) ||
        (mode == FLUSH_STATE_PERIODIC && GetTimeMicros() > nLastWrite + DATABASE_WRITE_INTERVAL * 1000000)) {
        // Typical CCoins structures on disk are around 100 bytes in size.
        // Pushing a new one to the database can cause it to be written
        // twice (once in the log, and once in the tables). This is already
        // an overestimation, as most will delete an existing entry or
        // overwrite one. Still, use a conservative safety factor of 2.
        if (!CheckDiskSpace(100 * 2 * 2 * pcoinsTip->GetCacheSize()))
            return state.Error("out of disk space");
        // First make sure all block and undo data is flushed to disk.
        FlushBlockFile();
        // Then update all block file information (which may refer to block and undo files).
        bool fileschanged = false;
        for (set<int>::iterator it = setDirtyFileInfo.begin(); it != setDirtyFileInfo.end(); ) {
            if (!pblocktree->WriteBlockFileInfo(*it, vinfoBlockFile[*it])) {
                return AbortNode(state, "Failed to write to block index");
            }
            fileschanged = true;
            setDirtyFileInfo.erase(it++);
        }
        if (fileschanged && !pblocktree->WriteLastBlockFile(nLastBlockFile)) {
            return AbortNode(state, "Failed to write to block index");
        }
        for (set<CBlockIndex*>::iterator it = setDirtyBlockIndex.begin(); it != setDirtyBlockIndex.end(); ) {
             if (!pblocktree->WriteBlockIndex(CDiskBlockIndex(*it))) {
                 return AbortNode(state, "Failed to write to block index");
             }
             setDirtyBlockIndex.erase(it++);
        }

        pblocktree->Sync();

        // Finally flush the chainstate (which may refer to block index entries).
        if (!pcoinsTip->Flush())
            return AbortNode(state, "Failed to write to coin database");
        // Update best block in wallet (so we can detect restored wallets).
        //TODO (Amir): put back when chainActive is implemented.
        //if (mode != FLUSH_STATE_IF_NEEDED) {
        //    g_signals.SetBestChain(chainActive.GetLocator());
        //}
        nLastWrite = GetTimeMicros();
    }
    } catch (const std::runtime_error& e) {
        return AbortNode(state, "System error while flushing: ") + e.what();
    }
    return true;
}

void FlushStateToDisk() {
    CValidationState state;
    FlushStateToDisk(state, FLUSH_STATE_ALWAYS);
}

//////////////////////////////////////////////////////////////////////////////
//
// CChain (chainActive)
//

/*
static int64_t nTimeReadFromDisk = 0;
static int64_t nTimeConnectTotal = 0;
static int64_t nTimeFlush = 0;
static int64_t nTimeChainState = 0;
static int64_t nTimePostConnect = 0;
*/

bool WriteBlockToDisk(const CBlock& block, CDiskBlockPos& pos, const CMessageHeader::MessageStartChars& messageStart)
{
    // Open history file to append
    CAutoFile fileout(OpenBlockFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("WriteBlockToDisk: OpenBlockFile failed");

    // Write index header
    unsigned int nSize = fileout.GetSerializeSize(block);
    fileout << FLATDATA(messageStart) << nSize;

    // Write block
    long fileOutPos = ftell(fileout.Get());
    if (fileOutPos < 0)
        return error("WriteBlockToDisk: ftell failed");
    pos.nPos = (unsigned int)fileOutPos;
    fileout << block;

    return true;
}

bool ReadBlockFromDisk(CBlock& block, const CDiskBlockPos& pos, const Consensus::Params& consensusParams)
{
    block.SetNull();

    // Open history file to read
    CAutoFile filein(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("ReadBlockFromDisk: OpenBlockFile failed for %s", pos.ToString());

    // Read block
    try {
        filein >> block;
    }
    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s at %s", __func__, e.what(), pos.ToString());
    }

    // Check the header
    if (!CheckProofOfWork(block.GetHash(), block.nBits, consensusParams))
        return error("ReadBlockFromDisk: Errors in block header at %s", pos.ToString());

    return true;
}

bool ReadBlockFromDisk(CBlock& block, const CBlockIndex* pindex, const Consensus::Params& consensusParams)
{
    if (!ReadBlockFromDisk(block, pindex->GetBlockPos(), consensusParams))
        return false;
    if (block.GetHash() != pindex->GetBlockHash())
        return error("ReadBlockFromDisk(CBlock&, CBlockIndex*): GetHash() doesn't match index for %s at %s",
                pindex->ToString(), pindex->GetBlockPos().ToString());
    return true;
}
namespace {
    bool UndoReadFromDisk(CBlockUndo& blockundo, const CDiskBlockPos& pos, const uint256& hashBlock)
    {
        // Open history file to read
        CAutoFile filein(OpenUndoFile(pos, true), SER_DISK, CLIENT_VERSION);
        if (filein.IsNull())
            return error("%s: OpenBlockFile failed", __func__);

        // Read block
        uint256 hashChecksum;
        try {
            filein >> blockundo;
            filein >> hashChecksum;
        }
        catch (const std::exception& e) {
            return error("%s: Deserialize or I/O error - %s", __func__, e.what());
        }

        // Verify checksum
        CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
        hasher << hashBlock;
        hasher << blockundo;
        if (hashChecksum != hasher.GetHash())
            return error("%s: Checksum mismatch", __func__);

        return true;
    }
} //End Anon namespace.

/**
 * Apply the undo operation of a CTxInUndo to the given chain state.
 * @param undo The undo object.
 * @param view The coins view to which to apply the changes.
 * @param out The out point that corresponds to the tx input.
 * @return True on success.
 */
static bool ApplyTxInUndo(const CTxInUndo& undo, CCoinsViewCache& view, const COutPoint& out)
{
    bool fClean = true;

    CCoinsModifier coins = view.ModifyCoins(out.hash);
    if (undo.nHeight != 0) {
        // undo data contains height: this is the last output of the prevout tx being spent
        if (!coins->IsPruned())
            fClean = fClean && error("%s: undo data overwriting existing transaction", __func__);
        coins->Clear();
        coins->fCoinBase = undo.fCoinBase;
        coins->nHeight = undo.nHeight;
        coins->nVersion = undo.nVersion;
    } else {
        if (coins->IsPruned())
            fClean = fClean && error("%s: undo data adding output to missing transaction", __func__);
    }
    if (coins->IsAvailable(out.n))
        fClean = fClean && error("%s: undo data overwriting existing output", __func__);
    if (coins->vout.size() < out.n+1)
        coins->vout.resize(out.n+1);
    coins->vout[out.n] = undo.txout;

    return fClean;
}

bool DisconnectBlock(const CBlock& block, CValidationState& state, const CBlockIndex* pindex, CCoinsViewCache& view, bool* pfClean)
{
    assert(pindex->GetBlockHash() == view.GetBestBlock());

    if (pfClean)
        *pfClean = false;

    bool fClean = true;

    CBlockUndo blockUndo;
    CDiskBlockPos pos = pindex->GetUndoPos();
    if (pos.IsNull())
        return error("DisconnectBlock(): no undo data available");
    if (!UndoReadFromDisk(blockUndo, pos, pindex->pprev->GetBlockHash()))
        return error("DisconnectBlock(): failure reading undo data");

    if (blockUndo.vtxundo.size() + 1 != block.vtx.size())
        return error("DisconnectBlock(): block and undo data inconsistent");

    // undo transactions in reverse order
    for (int i = block.vtx.size() - 1; i >= 0; i--) {
        const CTransaction &tx = block.vtx[i];
        uint256 hash = tx.GetHash();

        // Check that all outputs are available and match the outputs in the block itself
        // exactly.
        {
        CCoinsModifier outs = view.ModifyCoins(hash);
        outs->ClearUnspendable();

        CCoins outsBlock(tx, pindex->nHeight);
        // The CCoins serialization does not serialize negative numbers.
        // No network rules currently depend on the version here, so an inconsistency is harmless
        // but it must be corrected before txout nversion ever influences a network rule.
        if (outsBlock.nVersion < 0)
            outs->nVersion = outsBlock.nVersion;
        if (*outs != outsBlock)
            fClean = fClean && error("DisconnectBlock(): added transaction mismatch? database corrupted");

        // remove outputs
        outs->Clear();
        }

        // restore inputs
        if (i > 0) { // not coinbases
            const CTxUndo &txundo = blockUndo.vtxundo[i-1];
            if (txundo.vprevout.size() != tx.vin.size())
                return error("DisconnectBlock(): transaction and undo data inconsistent");
            for (unsigned int j = tx.vin.size(); j-- > 0;) {
                const COutPoint &out = tx.vin[j].prevout;
                const CTxInUndo &undo = txundo.vprevout[j];
                if (!ApplyTxInUndo(undo, view, out))
                    fClean = false;
            }
        }
    }

    // move best block pointer to prevout block
    view.SetBestBlock(pindex->pprev->GetBlockHash());

    if (pfClean) {
        *pfClean = fClean;
        return true;
    }

    return fClean;
}

///! Update chainActive and related internal data structures.
void static UpdateTip(CBlockIndex *pindexNew) {
    chainActive.SetTip(pindexNew);

    // New best block
    nTimeBestReceived = GetTime();
    mempool.AddTransactionsUpdated(1);

    /*LogPrintf("UpdateTip: new best=%s  height=%d  log2_work=%.8g  tx=%lu  date=%s progress=%f  cache=%u\n",
      chainActive.Tip()->GetBlockHash().ToString(), chainActive.Height(), log(chainActive.Tip()->nChainWork.getdouble())/log(2.0), (unsigned long)chainActive.Tip()->nChainTx,
      DateTimeStrFormat("%Y-%m-%d %H:%M:%S", chainActive.Tip()->GetBlockTime()),
      Checkpoints::GuessVerificationProgress(chainActive.Tip()), (unsigned int)pcoinsTip->GetCacheSize());

    cvBlockChange.notify_all();

    // Check the version of the last 100 blocks to see if we need to upgrade:
    static bool fWarned = false;
    if (!IsInitialBlockDownload() && !fWarned)
    {
        int nUpgraded = 0;
        const CBlockIndex* pindex = chainActive.Tip();
        for (int i = 0; i < 100 && pindex != NULL; i++)
        {
            if (pindex->nVersion > CBlock::CURRENT_VERSION)
                ++nUpgraded;
            pindex = pindex->pprev;
        }
        if (nUpgraded > 0)
            LogPrintf("SetBestChain: %d of last 100 blocks above version %d\n", nUpgraded, (int)CBlock::CURRENT_VERSION);
        if (nUpgraded > 100/2)
        {
            // strMiscWarning is read by GetWarnings(), called by Qt and the JSON-RPC code to warn the user:
            strMiscWarning = _("Warning: This version is obsolete, upgrade required!");
            CAlert::Notify(strMiscWarning, true);
            fWarned = true;
        }
    }*/
}

///! Disconnect chainActive's tip. You probably want to call mempool.removeForReorg and manually re-limit mempool size after this, with cs_main held.
bool static DisconnectTip(CValidationState& state, const Consensus::Params& consensusParams)
{
    CBlockIndex *pindexDelete = chainActive.Tip();
    assert(pindexDelete);
    // Read block from disk.
    CBlock block;
    if (!ReadBlockFromDisk(block, pindexDelete, consensusParams))
        return AbortNode(state, "Failed to read block");
    // Apply the block atomically to the chain state.
    int64_t nStart = GetTimeMicros();
    {
        CCoinsViewCache view(pcoinsTip);
        if (!DisconnectBlock(block, state, pindexDelete, view))
            return error("DisconnectTip(): DisconnectBlock %s failed", pindexDelete->GetBlockHash().ToString());
        assert(view.Flush());
    }
    LogPrint("bench", "- Disconnect block: %.2fms\n", (GetTimeMicros() - nStart) * 0.001);
    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(state, FLUSH_STATE_IF_NEEDED))
        return false;
    // Resurrect mempool transactions from the disconnected block.
    std::vector<uint256> vHashUpdate;
    BOOST_FOREACH(CTransaction &tx, block.vtx) {
        // ignore validation errors in resurrected transactions
        list<CTransaction> removed;
        CValidationState stateDummy;
        if (tx.IsCoinBase() || !AcceptToMemoryPool(mempool, stateDummy, tx, false, NULL, true)) {
            mempool.remove(tx, removed, true);
        } else if (mempool.exists(tx.GetHash())) {
            vHashUpdate.push_back(tx.GetHash());
        }
    }
    // AcceptToMemoryPool/addUnchecked all assume that new mempool entries have
    // no in-mempool children, which is generally not true when adding
    // previously-confirmed transactions back to the mempool.
    // UpdateTransactionsFromBlock finds descendants of any transactions in this
    // block that were added back and cleans up the mempool state.
    mempool.UpdateTransactionsFromBlock(vHashUpdate);
    // Update chainActive and related variables.
    UpdateTip(pindexDelete->pprev);
    // Let wallets know transactions went from 1-confirmed to
    // 0-confirmed or conflicted:
    BOOST_FOREACH(const CTransaction &tx, block.vtx) {
        SyncWithWallets(tx, pindexDelete->pprev, NULL);
    }
    return true;
}

///! Connect a new block to chainActive. pblock is either NULL or a pointer to a CBlock
///! corresponding to pindexNew, to bypass loading it again from disk.
bool static ConnectTip(CValidationState &state, CBlockIndex *pindexNew, CBlock *pblock) {
    assert(pindexNew->pprev == chainActive.Tip());
    /*mempool.check(pcoinsTip);
    // Read block from disk.
    int64_t nTime1 = GetTimeMicros();
    CBlock block;
    if (!pblock) {
        if (!ReadBlockFromDisk(block, pindexNew))
            return state.Abort("Failed to read block");
        pblock = &block;
    }
    // Apply the block atomically to the chain state.
    int64_t nTime2 = GetTimeMicros(); nTimeReadFromDisk += nTime2 - nTime1;
    int64_t nTime3;
    LogPrint("bench", "  - Load block from disk: %.2fms [%.2fs]\n", (nTime2 - nTime1) * 0.001, nTimeReadFromDisk * 0.000001);
    {
        CCoinsViewCache view(pcoinsTip);
        CInv inv(MSG_BLOCK, pindexNew->GetBlockHash());
        bool rv = ConnectBlock(*pblock, state, pindexNew, view);
        g_signals.BlockChecked(*pblock, state);
        if (!rv) {
            if (state.IsInvalid())
                InvalidBlockFound(pindexNew, state);
            return error("ConnectTip() : ConnectBlock %s failed", pindexNew->GetBlockHash().ToString());
        }
        mapBlockSource.erase(inv.hash);
        nTime3 = GetTimeMicros(); nTimeConnectTotal += nTime3 - nTime2;
        LogPrint("bench", "  - Connect total: %.2fms [%.2fs]\n", (nTime3 - nTime2) * 0.001, nTimeConnectTotal * 0.000001);
        assert(view.Flush());
    }
    int64_t nTime4 = GetTimeMicros(); nTimeFlush += nTime4 - nTime3;
    LogPrint("bench", "  - Flush: %.2fms [%.2fs]\n", (nTime4 - nTime3) * 0.001, nTimeFlush * 0.000001);
    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(state, FLUSH_STATE_IF_NEEDED))
        return false;
    int64_t nTime5 = GetTimeMicros(); nTimeChainState += nTime5 - nTime4;
    LogPrint("bench", "  - Writing chainstate: %.2fms [%.2fs]\n", (nTime5 - nTime4) * 0.001, nTimeChainState * 0.000001);
    // Remove conflicting transactions from the mempool.
    list<CTransaction> txConflicted;
    mempool.removeForBlock(pblock->vtx, pindexNew->nHeight, txConflicted);
    mempool.check(pcoinsTip);
    // Update chainActive & related variables.
    UpdateTip(pindexNew);
    // Tell wallet about transactions that went from mempool
    // to conflicted:
    BOOST_FOREACH(const CTransaction &tx, txConflicted) {
        SyncWithWallets(tx, NULL);
    }
    // ... and about transactions that got confirmed:
    BOOST_FOREACH(const CTransaction &tx, pblock->vtx) {
        SyncWithWallets(tx, pblock);
    }

    int64_t nTime6 = GetTimeMicros(); nTimePostConnect += nTime6 - nTime5; nTimeTotal += nTime6 - nTime1;
    LogPrint("bench", "  - Connect postprocess: %.2fms [%.2fs]\n", (nTime6 - nTime5) * 0.001, nTimePostConnect * 0.000001);
    LogPrint("bench", "- Connect block: %.2fms [%.2fs]\n", (nTime6 - nTime1) * 0.001, nTimeTotal * 0.000001);
    */
    return true;
}

bool CBlock::SetBestChain(CTxDB& txdb, CBlockIndex* pindexNew)
{
    uint256 hash = GetHash();

    if (!txdb.TxnBegin())
        return error("SetBestChain() : TxnBegin failed");

    if (pindexGenesisBlock == NULL && hash == Params().HashGenesisBlock())
    {
        txdb.WriteHashBestChain(hash);
        if (!txdb.TxnCommit())
            return error("SetBestChain() : TxnCommit failed");
        pindexGenesisBlock = pindexNew;
    }
    else if (hashPrevBlock == hashBestChain)
    {
        if (!SetBestChainInner(txdb, pindexNew))
            return error("SetBestChain() : SetBestChainInner failed");
    }
    else
    {
        // the first block in the new chain that will cause it to become the new best chain
        CBlockIndex *pindexIntermediate = pindexNew;

        // list of blocks that need to be connected afterwards
        std::vector<CBlockIndex*> vpindexSecondary;

        // Reorganize is costly in terms of db load, as it works in a single db transaction.
        // Try to limit how much needs to be done inside
        while (pindexIntermediate->pprev && pindexIntermediate->pprev->nChainTrust > pindexBest->nChainTrust)
        {
            vpindexSecondary.push_back(pindexIntermediate);
            pindexIntermediate = pindexIntermediate->pprev;
        }

        if (!vpindexSecondary.empty())
            LogPrintf("Postponing %u reconnects\n", vpindexSecondary.size());

        // Switch to new best branch
        if (!Reorganize(txdb, pindexIntermediate))
        {
            txdb.TxnAbort();
            InvalidChainFound(pindexNew);
            return error("SetBestChain() : Reorganize failed");
        }

        // Connect further blocks
        BOOST_REVERSE_FOREACH(CBlockIndex *pindex, vpindexSecondary)
        {
            CBlock block;
            if (!block.ReadFromDisk(pindex))
            {
                LogPrintf("SetBestChain() : ReadFromDisk failed\n");
                break;
            }
            if (!txdb.TxnBegin()) {
                LogPrintf("SetBestChain() : TxnBegin 2 failed\n");
                break;
            }
            // errors now are not fatal, we still did a reorganisation to a new chain in a valid way
            if (!block.SetBestChainInner(txdb, pindex))
                break;
        }
    }

    // Update best block in wallet (so we can detect restored wallets)
    bool fIsInitialDownload = IsInitialBlockDownload();
    if ((pindexNew->nHeight % 20160) == 0 || (!fIsInitialDownload && (pindexNew->nHeight % 144) == 0))
    {
        const CBlockLocator locator(pindexNew);
        g_signals.SetBestChain(locator);
    }

    // New best block
    hashBestChain = hash;
    pindexBest = pindexNew;
    pblockindexFBBHLast = NULL;
    nBestHeight = pindexBest->nHeight;
    nBestChainTrust = pindexNew->nChainTrust;
    nTimeBestReceived = GetTime();
    mempool.AddTransactionsUpdated(1);

    uint256 nBestBlockTrust = pindexBest->nHeight != 0 ? (pindexBest->nChainTrust - pindexBest->pprev->nChainTrust) : pindexBest->nChainTrust;

    LogPrintf("SetBestChain: new best=%s  height=%d  trust=%s  blocktrust=%d  date=%s\n",
      hashBestChain.ToString(), nBestHeight,
      CBigNum(nBestChainTrust).ToString(),
      nBestBlockTrust.Get64(),
      DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()));

    // Check the version of the last 100 blocks to see if we need to upgrade:
    if (!fIsInitialDownload)
    {
        int nUpgraded = 0;
        const CBlockIndex* pindex = pindexBest;
        for (int i = 0; i < 100 && pindex != NULL; i++)
        {
            if (pindex->nVersion > CBlock::CURRENT_VERSION)
                ++nUpgraded;
            pindex = pindex->pprev;
        }
        if (nUpgraded > 0)
            LogPrintf("SetBestChain: %d of last 100 blocks above version %d\n", nUpgraded, (int)CBlock::CURRENT_VERSION);
        if (nUpgraded > 100/2)
            // strMiscWarning is read by GetWarnings(), called by Qt and the JSON-RPC code to warn the user:
            strMiscWarning = _("Warning: This version is obsolete, upgrade required!");
    }

    std::string strCmd = GetArg("-blocknotify", "");

    if (!fIsInitialDownload && !strCmd.empty())
    {
        boost::replace_all(strCmd, "%s", hashBestChain.GetHex());
        boost::thread t(runCommand, strCmd); // thread runs free
    }

    return true;
}

bool CBlock::AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos, const uint256& hashProof)
{
    AssertLockHeld(cs_main);

    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return error("AddToBlockIndex() : %s already exists", hash.ToString());

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(nFile, nBlockPos, *this);
    if (!pindexNew)
        return error("AddToBlockIndex() : new CBlockIndex failed");
    pindexNew->phashBlock = &hash;
    map<uint256, CBlockIndex*>::iterator miPrev = mapBlockIndex.find(hashPrevBlock);
    if (miPrev != mapBlockIndex.end())
    {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
    }

    // ppcoin: compute chain trust score
    pindexNew->nChainTrust = (pindexNew->pprev ? pindexNew->pprev->nChainTrust : 0) + pindexNew->GetBlockTrust();

    // ppcoin: compute stake entropy bit for stake modifier
    if (!pindexNew->SetStakeEntropyBit(GetStakeEntropyBit()))
        return error("AddToBlockIndex() : SetStakeEntropyBit() failed");

    // Record proof hash value
    pindexNew->hashProof = hashProof;

    // ppcoin: compute stake modifier
    uint64_t nStakeModifier = 0;
    bool fGeneratedStakeModifier = false;
    if (!ComputeNextStakeModifier(pindexNew->pprev, nStakeModifier, fGeneratedStakeModifier))
        return error("AddToBlockIndex() : ComputeNextStakeModifier() failed");
    pindexNew->SetStakeModifier(nStakeModifier, fGeneratedStakeModifier);
    pindexNew->bnStakeModifierV2 = ComputeStakeModifierV2(pindexNew->pprev, IsProofOfWork() ? hash : vtx[1].vin[0].prevout.hash);

    // Add to mapBlockIndex
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    if (pindexNew->IsProofOfStake())
        setStakeSeen.insert(make_pair(pindexNew->prevoutStake, pindexNew->nStakeTime));
    pindexNew->phashBlock = &((*mi).first);

    // Write to disk block index
    CTxDB txdb;
    if (!txdb.TxnBegin())
        return false;
    txdb.WriteBlockIndex(CDiskBlockIndex(pindexNew));
    if (!txdb.TxnCommit())
        return false;

    // New best
    if (pindexNew->nChainTrust > nBestChainTrust)
        if (!SetBestChain(txdb, pindexNew))
            return false;

    if (pindexNew == pindexBest)
    {
        // Notify UI to display prev block's coinbase if it was ours
        static uint256 hashPrevBestCoinBase;
        g_signals.UpdatedTransaction(hashPrevBestCoinBase);
        hashPrevBestCoinBase = vtx[0].GetHash();
    }

    return true;
}

CVerifyDB::CVerifyDB()
{
    //TODO (Amir): Implement after chainActive
    //uiInterface.ShowProgress(_("Verifying blocks..."), 0);
}

CVerifyDB::~CVerifyDB()
{
    //TODO (Amir): Implement after chainActive
    //uiInterface.ShowProgress("", 100);
}

bool CVerifyDB::VerifyDB(CCoinsView *coinsview, int nCheckLevel, int nCheckDepth)
{
    //TODO (Amir): Implement after chainActive
    /*
    LOCK(cs_main);
    if (chainActive.Tip() == NULL || chainActive.Tip()->pprev == NULL)
        return true;

    // Verify blocks in the best chain
    if (nCheckDepth <= 0)
        nCheckDepth = 1000000000; // suffices until the year 19000
    if (nCheckDepth > chainActive.Height())
        nCheckDepth = chainActive.Height();
    nCheckLevel = std::max(0, std::min(4, nCheckLevel));
    LogPrintf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
    CCoinsViewCache coins(coinsview);
    CBlockIndex* pindexState = chainActive.Tip();
    CBlockIndex* pindexFailure = NULL;
    int nGoodTransactions = 0;
    CValidationState state;
    for (CBlockIndex* pindex = chainActive.Tip(); pindex && pindex->pprev; pindex = pindex->pprev)
    {
        boost::this_thread::interruption_point();
        uiInterface.ShowProgress(_("Verifying blocks..."), std::max(1, std::min(99, (int)(((double)(chainActive.Height() - pindex->nHeight)) / (double)nCheckDepth * (nCheckLevel >= 4 ? 50 : 100)))));
        if (pindex->nHeight < chainActive.Height()-nCheckDepth)
            break;
        CBlock block;
        // check level 0: read from disk
        if (!ReadBlockFromDisk(block, pindex))
            return error("VerifyDB() : *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
        // check level 1: verify block validity
        if (nCheckLevel >= 1 && !CheckBlock(block, state))
            return error("VerifyDB() : *** found bad block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
        // check level 2: verify undo validity
        if (nCheckLevel >= 2 && pindex) {
            CBlockUndo undo;
            CDiskBlockPos pos = pindex->GetUndoPos();
            if (!pos.IsNull()) {
                if (!undo.ReadFromDisk(pos, pindex->pprev->GetBlockHash()))
                    return error("VerifyDB() : *** found bad undo data at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
            }
        }
        // check level 3: check for inconsistencies during memory-only disconnect of tip blocks
        if (nCheckLevel >= 3 && pindex == pindexState && (coins.GetCacheSize() + pcoinsTip->GetCacheSize()) <= nCoinCacheSize) {
            bool fClean = true;
            if (!DisconnectBlock(block, state, pindex, coins, &fClean))
                return error("VerifyDB() : *** irrecoverable inconsistency in block data at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
            pindexState = pindex->pprev;
            if (!fClean) {
                nGoodTransactions = 0;
                pindexFailure = pindex;
            } else
                nGoodTransactions += block.vtx.size();
        }
        if (ShutdownRequested())
            return true;
    }
    if (pindexFailure)
        return error("VerifyDB() : *** coin database inconsistencies found (last %i blocks, %i good transactions before that)\n", chainActive.Height() - pindexFailure->nHeight + 1, nGoodTransactions);

    // check level 4: try reconnecting blocks
    if (nCheckLevel >= 4) {
        CBlockIndex *pindex = pindexState;
        while (pindex != chainActive.Tip()) {
            boost::this_thread::interruption_point();
            uiInterface.ShowProgress(_("Verifying blocks..."), std::max(1, std::min(99, 100 - (int)(((double)(chainActive.Height() - pindex->nHeight)) / (double)nCheckDepth * 50))));
            pindex = chainActive.Next(pindex);
            CBlock block;
            if (!ReadBlockFromDisk(block, pindex))
                return error("VerifyDB() : *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
            if (!ConnectBlock(block, state, pindex, coins))
                return error("VerifyDB() : *** found unconnectable block at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
        }
    }

    LogPrintf("No coin database inconsistencies in last %i blocks (%i transactions)\n", chainActive.Height() - pindexState->nHeight, nGoodTransactions);
    */
    LogPrintf("VerifyDB not implemented! \n");
    return true;
}
