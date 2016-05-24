// Copyright (c) 2009-2016 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/algorithm/string/replace.hpp>

#include "chain.h"
#include "wallet/wallet.h"
#include "checkpoints.h"
#include "anon/stormnode/spork.h"
#include "kernel.h"
#include "txdb-leveldb.h"

#ifdef ENABLE_WALLET

extern std::map<COutPoint, uint256> mapLockedInputs;
CBlockIndex* pblockindexFBBHLast;

static unsigned int nCurrentBlockFile = 1;


CBlockIndex* FindBlockByHeight(int nHeight)
{
    CBlockIndex *pblockindex;
    if (nHeight < nBestHeight / 2)
        pblockindex = pindexGenesisBlock;
    else
        pblockindex = pindexBest;
    if (pblockindexFBBHLast && abs(nHeight - pblockindex->nHeight) > abs(nHeight - pblockindexFBBHLast->nHeight))
        pblockindex = pblockindexFBBHLast;
    while (pblockindex->nHeight > nHeight)
        pblockindex = pblockindex->pprev;
    while (pblockindex->nHeight < nHeight)
        pblockindex = pblockindex->pnext;
    pblockindexFBBHLast = pblockindex;
    return pblockindex;
}

// darksilk: attempt to generate suitable proof-of-stake
bool CBlock::SignBlock(CWallet& wallet, CAmount nFees)
{
    // if we are trying to sign
    //    something except proof-of-stake block template
    if (!vtx[0].vout[0].IsEmpty())
        return false;

    // if we are trying to sign
    //    a complete proof-of-stake block
    if (IsProofOfStake())
        return true;

    static int64_t nLastCoinStakeSearchTime = GetAdjustedTime(); // startup timestamp

    CKey key;
    CTransaction txCoinStake;
    txCoinStake.nTime &= ~STAKE_TIMESTAMP_MASK;

    int64_t nSearchTime = txCoinStake.nTime; // search to current time

    if (nSearchTime > nLastCoinStakeSearchTime)
    {
        int64_t nSearchInterval = 1;
        if (wallet.CreateCoinStake(wallet, nBits, nSearchInterval, nFees, txCoinStake, key))
        {
            if (txCoinStake.nTime >= pindexBest->GetPastTimeLimit()+1)
            {
                // make sure coinstake would meet timestamp protocol
                //    as it would be the same as the block timestamp
                vtx[0].nTime = nTime = txCoinStake.nTime;

                // we have to make sure that we have no future timestamps in
                //    our transactions set
                for (vector<CTransaction>::iterator it = vtx.begin(); it != vtx.end();)
                    if (it->nTime > nTime) { it = vtx.erase(it); } else { ++it; }

                vtx.insert(vtx.begin() + 1, txCoinStake);
                hashMerkleRoot = BuildMerkleTree();

                // append a signature to our block
                return key.Sign(GetHash(), vchBlockSig);
            }
        }
        nLastCoinStakeSearchInterval = nSearchTime - nLastCoinStakeSearchTime;
        nLastCoinStakeSearchTime = nSearchTime;
    }

    return false;
}
#endif

bool CBlock::AcceptBlock()
{
    AssertLockHeld(cs_main);

    if (nVersion > CURRENT_VERSION)
        return DoS(100, error("AcceptBlock() : reject unknown block version %d", nVersion));

    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return error("AcceptBlock() : block already in mapBlockIndex");

    // Get prev block index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashPrevBlock);
    if (mi == mapBlockIndex.end())
        return DoS(10, error("AcceptBlock() : prev block not found"));
    CBlockIndex* pindexPrev = (*mi).second;
    int nHeight = pindexPrev->nHeight+1;

    if (IsProofOfStake() && nHeight < Params().FirstPOSBlock())
        return DoS(100, error("AcceptBlock() : reject proof-of-stake at height <= %d", nHeight));

    // Check coinbase timestamp
    if (GetBlockTime() > FutureDrift((int64_t)vtx[0].nTime, IsProofOfStake()))
        return DoS(50, error("AcceptBlock() : coinbase timestamp is too early"));

    // Check coinstake timestamp
    if (IsProofOfStake() && !CheckCoinStakeTimestamp(nHeight, GetBlockTime(), (int64_t)vtx[1].nTime))
        return DoS(50, error("AcceptBlock() : coinstake timestamp violation nTimeBlock=%d nTimeTx=%u", GetBlockTime(), vtx[1].nTime));

    // Check proof-of-work or proof-of-stake
    if (nBits != GetNextTargetRequired(pindexPrev, IsProofOfStake()))
        return DoS(100, error("AcceptBlock() : incorrect %s", IsProofOfWork() ? "proof-of-work" : "proof-of-stake"));

    // Check timestamp against prev
    LogPrintf("GetBlockTime(): %d, <=? pindexPrev->GetPastTimeLimit(): %d\nFutureDrift(GetBlockTime()): %d, <?pindexPrev->GetBlockTime(): %d\n",GetBlockTime(),pindexPrev->GetPastTimeLimit(),FutureDrift(GetBlockTime()),pindexPrev->GetBlockTime());
    if (GetBlockTime() <= pindexPrev->GetPastTimeLimit() || FutureDrift(GetBlockTime(), IsProofOfStake()) < pindexPrev->GetBlockTime())
        return error("AcceptBlock() : block's timestamp is too early");

    // Check that all transactions are finalized
    BOOST_FOREACH(const CTransaction& tx, vtx)
        if (!IsFinalTx(tx, nHeight, GetBlockTime()))
            return DoS(10, error("AcceptBlock() : contains a non-final transaction"));

    // Check that the block chain matches the known block chain up to a checkpoint
    if (!Checkpoints::CheckHardened(nHeight, hash))
        return DoS(100, error("AcceptBlock() : rejected by hardened checkpoint lock-in at %d", nHeight));

    uint256 hashProof;
    // Verify hash target and signature of coinstake tx
    if (IsProofOfStake())
    {
        uint256 targetProofOfStake;
        if (!CheckProofOfStake(pindexPrev, vtx[1], nBits, hashProof, targetProofOfStake))
        {
            return error("AcceptBlock() : check proof-of-stake failed for block %s", hash.ToString());
        }
    }
    // PoW is checked in CheckBlock()
    if (IsProofOfWork())
    {
        hashProof = GetPoWHash();
    }

    // Check that the block satisfies synchronized checkpoint
    if (!Checkpoints::CheckSync(nHeight))
        return error("AcceptBlock() : rejected by synchronized checkpoint");

    // Enforce rule that the coinbase starts with serialized block height
    CScript expect = CScript() << nHeight;
    if (vtx[0].vin[0].scriptSig.size() < expect.size() ||
        !std::equal(expect.begin(), expect.end(), vtx[0].vin[0].scriptSig.begin()))
        return DoS(100, error("AcceptBlock() : block height mismatch in coinbase"));

    // Write block to history file
    if (!CheckDiskSpace(::GetSerializeSize(*this, SER_DISK, CLIENT_VERSION)))
        return error("AcceptBlock() : out of disk space");

    unsigned int nFile = -1;
    unsigned int nBlockPos = 0;
    if (!WriteToDisk(nFile, nBlockPos))
        return error("AcceptBlock() : WriteToDisk failed");

    if (!AddToBlockIndex(nFile, nBlockPos, hashProof))
        return error("AcceptBlock() : AddToBlockIndex failed");

    // Relay inventory, but don't relay old inventory during initial block download
    int nBlockEstimate = Checkpoints::GetTotalBlocksEstimate();
    if (hashBestChain == hash)
    {
        LOCK(cs_vNodes);
        BOOST_FOREACH(CNode* pnode, vNodes)
            if (nBestHeight > (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : nBlockEstimate))
                pnode->PushInventory(CInv(MSG_BLOCK, hash));
    }

    return true;
}

bool CBlock::DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex)
{
    // Disconnect in reverse order
    CTransactionPoS txPoS;
    for (int i = vtx.size()-1; i >= 0; i--)
        if (!txPoS.DisconnectInputs(vtx[i],txdb))
            return false;

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    if (pindex->pprev)
    {
        CDiskBlockIndex blockindexPrev(pindex->pprev);
        blockindexPrev.hashNext = 0;
        if (!txdb.WriteBlockIndex(blockindexPrev))
            return error("DisconnectBlock() : WriteBlockIndex failed");
    }

    // ppcoin: clean up wallet after disconnecting coinstake
    BOOST_FOREACH(CTransaction& tx, vtx)
        SyncWithWallets(tx, this, false);

    return true;
}

bool static BuildAddrIndex(const CScript &script, std::vector<uint160>& addrIds)
{
    CScript::const_iterator pc = script.begin();
    CScript::const_iterator pend = script.end();
    std::vector<unsigned char> data;
    opcodetype opcode;
    bool fHaveData = false;
    while (pc < pend) {
        script.GetOp(pc, opcode, data);
        if (0 <= opcode && opcode <= OP_PUSHDATA4 && data.size() >= 8) { // data element
            uint160 addrid = 0;
            if (data.size() <= 20) {
                memcpy(&addrid, &data[0], data.size());
            } else {
                addrid = Hash160(data);
            }
            addrIds.push_back(addrid);
            fHaveData = true;
        }
    }
    if (!fHaveData) {
        uint160 addrid = Hash160(script);
    addrIds.push_back(addrid);
        return true;
    }
    else
    {
    if(addrIds.size() > 0)
        return true;
    else
        return false;
    }
}

void CBlock::RebuildAddressIndex(CTxDB& txdb)
{
    BOOST_FOREACH(CTransaction& tx, vtx)
    {
        uint256 hashTx = tx.GetHash();
    // inputs
    if(!tx.IsCoinBase())
    {
            MapPrevTx mapInputs;
        map<uint256, CTxIndex> mapQueuedChangesT;
        bool fInvalid;
        CTransactionPoS txPoS;
        if (!txPoS.FetchInputs(tx, txdb, mapQueuedChangesT, true, false, mapInputs, fInvalid))
            return;

        MapPrevTx::const_iterator mi;
        for(MapPrevTx::const_iterator mi = mapInputs.begin(); mi != mapInputs.end(); ++mi)
            {
                BOOST_FOREACH(const CTxOut &atxout, (*mi).second.second.vout)
                {
                    std::vector<uint160> addrIds;
                    if(BuildAddrIndex(atxout.scriptPubKey, addrIds))
                    {
                                    BOOST_FOREACH(uint160 addrId, addrIds)
                            {
                            if(!txdb.WriteAddrIndex(addrId, hashTx))
                            LogPrintf("RebuildAddressIndex(): txins WriteAddrIndex failed addrId: %s txhash: %s\n", addrId.ToString().c_str(), hashTx.ToString().c_str());
                                    }
                    }
                }
            }
        }
        // outputs
        BOOST_FOREACH(const CTxOut &atxout, tx.vout) {
            std::vector<uint160> addrIds;
                if(BuildAddrIndex(atxout.scriptPubKey, addrIds))
            {
            BOOST_FOREACH(uint160 addrId, addrIds)
            {
                if(!txdb.WriteAddrIndex(addrId, hashTx))
                    LogPrintf("RebuildAddressIndex(): txouts WriteAddrIndex failed addrId: %s txhash: %s\n", addrId.ToString().c_str(), hashTx.ToString().c_str());
                    }
            }
        }
    }
}

static int64_t nTimeConnect = 0;

bool CBlock::ConnectBlock(CTxDB& txdb, CBlockIndex* pindex, bool fJustCheck)
{   
    CValidationState state;
    // Check it again in case a previous version let a bad block in, but skip BlockSig checking
    if (!CheckBlock(state, !fJustCheck, !fJustCheck, false))
        return false;

    unsigned int flags = SCRIPT_VERIFY_NOCACHE |
                SCRIPT_VERIFY_NULLDUMMY |
                SCRIPT_VERIFY_STRICTENC |
                SCRIPT_VERIFY_ALLOW_EMPTY_SIG |
                SCRIPT_VERIFY_FIX_HASHTYPE |
                SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;

    //// issue here: it doesn't know the version
    unsigned int nTxPos;
    if (fJustCheck)
        // FetchInputs treats CDiskTxPos(1,1,1) as a special "refer to memorypool" indicator
        // Since we're just checking the block and not actually connecting it, it might not (and probably shouldn't) be on the disk to get the transaction from
        nTxPos = 1;
    else
        nTxPos = pindex->nBlockPos + ::GetSerializeSize(CBlock(), SER_DISK, CLIENT_VERSION) - (2 * GetSizeOfCompactSize(0)) + GetSizeOfCompactSize(vtx.size());

    map<uint256, CTxIndex> mapQueuedChanges;
    CAmount nFees = 0;
    CAmount nValueIn = 0;
    CAmount nValueOut = 0;
    CAmount nStakeReward = 0;
    unsigned int nSigOps = 0;
    int nTxCacheHits = 0;
    int nInputs = 0;
    int64_t nTimeStart = GetTimeMicros();
    BOOST_FOREACH(CTransaction& tx, vtx)
    {
        uint256 hashTx = tx.GetHash();
        nInputs += tx.vin.size();

        nSigOps += GetLegacySigOpCount(tx);
        if (nSigOps > MAX_BLOCK_SIGOPS)
            return DoS(100, error("ConnectBlock() : too many sigops"));

        CDiskTxPos posThisTx(pindex->nFile, pindex->nBlockPos, nTxPos);
        if (!fJustCheck)
            nTxPos += ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);

        MapPrevTx mapInputs;
        CTransactionPoS txPoS;
        if (tx.IsCoinBase())
        {
            nValueOut += txPoS.GetValueOut(tx);
        }
        else
        {
            bool fInvalid;
            if (!txPoS.FetchInputs(tx, txdb, mapQueuedChanges, true, false, mapInputs, fInvalid))
                return false;

            // Add in sigops done by pay-to-script-hash inputs;
            // this is to prevent a "rogue miner" from creating
            // an incredibly-expensive-to-validate block.
            nSigOps += GetP2SHSigOpCount(tx, mapInputs);
            if (nSigOps > MAX_BLOCK_SIGOPS)
                return DoS(100, error("ConnectBlock() : too many sigops"));

            CAmount nTxValueIn = txPoS.GetValueIn(tx, mapInputs);
            CAmount nTxValueOut = txPoS.GetValueOut(tx);
            nValueIn += nTxValueIn;
            nValueOut += nTxValueOut;
            if (!tx.IsCoinStake())
                nFees += nTxValueIn - nTxValueOut;
            if (tx.IsCoinStake())
                nStakeReward = nTxValueOut - nTxValueIn;

        //if(setValidatedTx.find(hashTx) == setValidatedTx.end())
        //{
                if (!txPoS.ConnectInputs(tx, txdb, mapInputs, mapQueuedChanges, posThisTx, pindex, true, false, flags))
                    return false;
        //else
        //    setValidatedTx.insert(hashTx);
        //}
        //else
        //{
    //  ++nTxCacheHits;
      //  }
        }

        mapQueuedChanges[hashTx] = CTxIndex(posThisTx, tx.vout.size());
    }

    int64_t nTime1 = GetTimeMicros(); nTimeConnect += nTime1 - nTimeStart;
    if(fDebug)
    {
        LogPrintf("bench      - Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin) [%.2fs]\n", (unsigned)vtx.size(), 0.001 * (nTime1 - nTimeStart), 0.001 * (nTime1 - nTimeStart) / vtx.size(), nInputs <= 1 ? 0 : 0.001 * (nTime1 - nTimeStart) / (nInputs-1), nTimeConnect * 0.000001);
        LogPrintf("bench      - %u transaction validations cached\n", nTxCacheHits);
    }

    if (IsProofOfWork())
    {
        CAmount nReward = GetProofOfWorkReward(nFees);
        // Check coinbase reward
        CTransactionPoS txPoS;
        if (txPoS.GetValueOut(vtx[0]) > nReward)
            return DoS(50, error("ConnectBlock() : coinbase reward exceeded (actual=%d vs calculated=%d)",
                   txPoS.GetValueOut(vtx[0]),
                   nReward));
    }
    if (IsProofOfStake())
    {
        CAmount nCalculatedStakeReward = STATIC_POS_REWARD + nFees;

        if (nStakeReward > nCalculatedStakeReward)
            return DoS(100, error("ConnectBlock() : coinstake pays too much(actual=%d vs calculated=%d)", nStakeReward, nCalculatedStakeReward));
    }

    // ppcoin: track money supply and mint amount info
    pindex->nMint = nValueOut - nValueIn + nFees;
    pindex->nMoneySupply = (pindex->pprev? pindex->pprev->nMoneySupply : 0) + nValueOut - nValueIn;
    if (!txdb.WriteBlockIndex(CDiskBlockIndex(pindex)))
        return error("Connect() : WriteBlockIndex for pindex failed");

    if (fJustCheck)
        return true;

    // Write queued txindex changes
    for (map<uint256, CTxIndex>::iterator mi = mapQueuedChanges.begin(); mi != mapQueuedChanges.end(); ++mi)
    {
        if (!txdb.UpdateTxIndex((*mi).first, (*mi).second))
            return error("ConnectBlock() : UpdateTxIndex failed");
    }

    // Write Address Index
    BOOST_FOREACH(CTransaction& tx, vtx)
    {
        uint256 hashTx = tx.GetHash();
        // inputs
        if(!tx.IsCoinBase())
        {
            MapPrevTx mapInputs;
            map<uint256, CTxIndex> mapQueuedChangesT;
            bool fInvalid;
            CTransactionPoS txPoS;
            if (!txPoS.FetchInputs(tx, txdb, mapQueuedChangesT, true, false, mapInputs, fInvalid))
                return false;

            MapPrevTx::const_iterator mi;
            for(MapPrevTx::const_iterator mi = mapInputs.begin(); mi != mapInputs.end(); ++mi)
            {
                BOOST_FOREACH(const CTxOut &atxout, (*mi).second.second.vout)
                {
                std::vector<uint160> addrIds;
                if(BuildAddrIndex(atxout.scriptPubKey, addrIds))
                {
                                BOOST_FOREACH(uint160 addrId, addrIds)
                        {
                        if(!txdb.WriteAddrIndex(addrId, hashTx))
                        LogPrintf("ConnectBlock(): txins WriteAddrIndex failed addrId: %s txhash: %s\n", addrId.ToString().c_str(), hashTx.ToString().c_str());
                                }
                }
                }
            }
        }

        // outputs
        BOOST_FOREACH(const CTxOut &atxout, tx.vout) {
            std::vector<uint160> addrIds;
            if(BuildAddrIndex(atxout.scriptPubKey, addrIds))
            {
                BOOST_FOREACH(uint160 addrId, addrIds)
                {
                    if(!txdb.WriteAddrIndex(addrId, hashTx))
                        LogPrintf("ConnectBlock(): txouts WriteAddrIndex failed addrId: %s txhash: %s\n", addrId.ToString().c_str(), hashTx.ToString().c_str());
                }
            }
        }
    }

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    if (pindex->pprev)
    {
        CDiskBlockIndex blockindexPrev(pindex->pprev);
        blockindexPrev.hashNext = pindex->GetBlockHash();
        if (!txdb.WriteBlockIndex(blockindexPrev))
            return error("ConnectBlock() : WriteBlockIndex failed");
    }

    // Watch for transactions paying to me
    BOOST_FOREACH(CTransaction& tx, vtx)
        SyncWithWallets(tx, this);

    return true;
}

void InvalidChainFound(CBlockIndex* pindexNew)
{
    if (pindexNew->nChainTrust > nBestInvalidTrust)
    {
        nBestInvalidTrust = pindexNew->nChainTrust;
        CTxDB().WriteBestInvalidTrust(CBigNum(nBestInvalidTrust));
    }

    uint256 nBestInvalidBlockTrust = pindexNew->nChainTrust - pindexNew->pprev->nChainTrust;
    uint256 nBestBlockTrust = pindexBest->nHeight != 0 ? (pindexBest->nChainTrust - pindexBest->pprev->nChainTrust) : pindexBest->nChainTrust;

    LogPrintf("InvalidChainFound: invalid block=%s  height=%d  trust=%s  blocktrust=%d  date=%s\n",
      pindexNew->GetBlockHash().ToString(), pindexNew->nHeight,
      CBigNum(pindexNew->nChainTrust).ToString(), nBestInvalidBlockTrust.Get64(),
      DateTimeStrFormat("%x %H:%M:%S", pindexNew->GetBlockTime()));
    LogPrintf("InvalidChainFound:  current best=%s  height=%d  trust=%s  blocktrust=%d  date=%s\n",
      hashBestChain.ToString(), nBestHeight,
      CBigNum(pindexBest->nChainTrust).ToString(),
      nBestBlockTrust.Get64(),
      DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()));
}

bool Reorganize(CTxDB& txdb, CBlockIndex* pindexNew)
{
    LogPrintf("REORGANIZE\n");

    // Find the fork
    CBlockIndex* pfork = pindexBest;
    CBlockIndex* plonger = pindexNew;
    while (pfork != plonger)
    {
        while (plonger->nHeight > pfork->nHeight)
            if (!(plonger = plonger->pprev))
                return error("Reorganize() : plonger->pprev is null");
        if (pfork == plonger)
            break;
        if (!(pfork = pfork->pprev))
            return error("Reorganize() : pfork->pprev is null");
    }

    // List of what to disconnect
    vector<CBlockIndex*> vDisconnect;
    for (CBlockIndex* pindex = pindexBest; pindex != pfork; pindex = pindex->pprev)
        vDisconnect.push_back(pindex);

    // List of what to connect
    vector<CBlockIndex*> vConnect;
    for (CBlockIndex* pindex = pindexNew; pindex != pfork; pindex = pindex->pprev)
        vConnect.push_back(pindex);
    reverse(vConnect.begin(), vConnect.end());

    LogPrintf("REORGANIZE: Disconnect %u blocks; %s..%s\n", vDisconnect.size(), pfork->GetBlockHash().ToString(), pindexBest->GetBlockHash().ToString());
    LogPrintf("REORGANIZE: Connect %u blocks; %s..%s\n", vConnect.size(), pfork->GetBlockHash().ToString(), pindexNew->GetBlockHash().ToString());

    // Disconnect shorter branch
    list<CTransaction> vResurrect;
    BOOST_FOREACH(CBlockIndex* pindex, vDisconnect)
    {
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return error("Reorganize() : ReadFromDisk for disconnect failed");
        if (!block.DisconnectBlock(txdb, pindex))
            return error("Reorganize() : DisconnectBlock %s failed", pindex->GetBlockHash().ToString());

        // Queue memory transactions to resurrect.
        // We only do this for blocks after the last checkpoint (reorganisation before that
        // point should only happen with -reindex/-loadblock, or a misbehaving peer.
        BOOST_REVERSE_FOREACH(const CTransaction& tx, block.vtx)
            if (!(tx.IsCoinBase() || tx.IsCoinStake()) && pindex->nHeight > Checkpoints::GetTotalBlocksEstimate())
                vResurrect.push_front(tx);
    }

    // Connect longer branch
    CValidationState state;
    vector<CTransaction> vDelete;
    for (unsigned int i = 0; i < vConnect.size(); i++)
    {
        CBlockIndex* pindex = vConnect[i];
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return error("Reorganize() : ReadFromDisk for connect failed");
        if (!block.ConnectBlock(txdb, pindex))
        {
            // Invalid block
            return error("Reorganize() : ConnectBlock %s failed", pindex->GetBlockHash().ToString());
        }

        // Queue memory transactions to delete
        BOOST_FOREACH(const CTransaction& tx, block.vtx)
            vDelete.push_back(tx);
    }
    if (!txdb.WriteHashBestChain(pindexNew->GetBlockHash()))
        return error("Reorganize() : WriteHashBestChain failed");

    // Make sure it's successfully written to disk before changing memory structure
    if (!txdb.TxnCommit())
        return error("Reorganize() : TxnCommit failed");

    // Disconnect shorter branch
    BOOST_FOREACH(CBlockIndex* pindex, vDisconnect)
        if (pindex->pprev)
            pindex->pprev->pnext = NULL;

    // Connect longer branch
    BOOST_FOREACH(CBlockIndex* pindex, vConnect)
        if (pindex->pprev)
            pindex->pprev->pnext = pindex;

    // Resurrect memory transactions that were in the disconnected branch
    BOOST_FOREACH(CTransaction& tx, vResurrect)
        AcceptToMemoryPool(mempool, state, tx, false, NULL);

    // Delete redundant memory transactions that are in the connected branch
    BOOST_FOREACH(CTransaction& tx, vDelete) {
        mempool.remove(tx);
        mempool.removeConflicts(tx);
    }

    LogPrintf("REORGANIZE: done\n");

    return true;
}

uint256 CBlockIndex::GetBlockTrust() const
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);

    if (bnTarget <= 0)
        return 0;

    return ((CBigNum(1)<<256) / (bnTarget+1)).getuint256();
}

/// CChain implementation
void CChain::SetTip(CBlockIndex *pindex) {
    if (pindex == NULL) {
        vChain.clear();
        return;
    }
    vChain.resize(pindex->nHeight + 1);
    while (pindex && vChain[pindex->nHeight] != pindex) {
        vChain[pindex->nHeight] = pindex;
        pindex = pindex->pprev;
    }
}

FILE* AppendBlockFile(unsigned int& nFileRet)
{
    nFileRet = 0;
    while (true)
    {
        FILE* file = OpenBlockFile(nCurrentBlockFile, 0, "ab");
        if (!file)
            return NULL;
        if (fseek(file, 0, SEEK_END) != 0)
            return NULL;
        // FAT32 file size max 4GB, fseek and ftell max 2GB, so we must stay under 2GB
        if (ftell(file) < (long)(0x7F000000 - MAX_SIZE))
        {
            nFileRet = nCurrentBlockFile;
            return file;
        }
        fclose(file);
        nCurrentBlockFile++;
    }
}

bool IsInitialBlockDownload()
{
    LOCK(cs_main);
    if (pindexBest == NULL || nBestHeight < Checkpoints::GetTotalBlocksEstimate())
        return true;

    static int64_t nLastUpdate;
    static CBlockIndex* pindexLastBest;

    if (pindexBest != pindexLastBest)
    {
        pindexLastBest = pindexBest;
        nLastUpdate = GetTime();
    }
    return (GetTime() - nLastUpdate < 15 &&
            pindexBest->GetBlockTime() < GetTime() - 8 * 60 * 60);
}

bool CBlock::CheckBlock(CValidationState& state, bool fCheckPOW, bool fCheckMerkleRoot, bool fCheckSig)
{
    // These are checks that are independent of context
    // that can be verified before saving an orphan block.

    // Size limits
    if (vtx.empty() || vtx.size() > MAX_BLOCK_SIZE || ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION) > MAX_BLOCK_SIZE)
        return DoS(100, error("CheckBlock() : size limits failed"));

    // Check proof of work matches claimed amount
    if (fCheckPOW && IsProofOfWork() && !CheckProofOfWork(GetPoWHash(), nBits))
        return DoS(50, error("CheckBlock() : proof of work failed"));

    // Check timestamp
    if (GetBlockTime() > FutureDrift(GetAdjustedTime(), IsProofOfStake()))
        return error("CheckBlock() : block timestamp too far in the future");

    // First transaction must be coinbase, the rest must not be
    if (vtx.empty() || !vtx[0].IsCoinBase())
        return DoS(100, error("CheckBlock() : first tx is not coinbase"));
    for (unsigned int i = 1; i < vtx.size(); i++)
        if (vtx[i].IsCoinBase())
            return DoS(100, error("CheckBlock() : more than one coinbase"));

    if (IsProofOfStake())
    {
        // Coinbase output should be empty if proof-of-stake block
        if (vtx[0].vout.size() != 1 || !vtx[0].vout[0].IsEmpty())
            return DoS(100, error("CheckBlock() : coinbase output not empty for proof-of-stake block"));

        // Second transaction must be coinstake, the rest must not be
        if (vtx.empty() || !vtx[1].IsCoinStake())
            return DoS(100, error("CheckBlock() : second tx is not coinstake"));
        for (unsigned int i = 2; i < vtx.size(); i++)
            if (vtx[i].IsCoinStake())
                return DoS(100, error("CheckBlock() : more than one coinstake"));
    }

    // Check proof-of-stake block signature
    if (fCheckSig && !CheckBlockSignature())
        return DoS(100, error("CheckBlock() : bad proof-of-stake block signature"));


// ----------- instantX transaction scanning -----------

    if(IsSporkActive(SPORK_3_INSTANTX_BLOCK_FILTERING)){
        BOOST_FOREACH(const CTransaction& tx, vtx){
            if (!tx.IsCoinBase()){
                //only reject blocks when it's based on complete consensus
                BOOST_FOREACH(const CTxIn& in, tx.vin){
                    if(mapLockedInputs.count(in.prevout)){
                        if(mapLockedInputs[in.prevout] != tx.GetHash()){
                            if(fDebug) { LogPrintf("CheckBlock() : found conflicting transaction with transaction lock %s %s\n", mapLockedInputs[in.prevout].ToString().c_str(), tx.GetHash().ToString().c_str()); }
                            return DoS(0, error("CheckBlock() : found conflicting transaction with transaction lock"));
                        }
                    }
                }
            }
        }
    } else {
        LogPrintf("CheckBlock() : skipping transaction locking checks\n");
    }


    // ----------- stormnode payments -----------

    CBlockIndex *pindexPrev = pindexBest;

    if(pindexPrev == NULL)
    {
        //TODO (AA): Put these back once primitives are completed
        //if(IsBlockPayeeValid(block.vtx[0], pindexPrev->nHeight+1))
        //{
        //    return DoS(100, error("CheckBlock() : Couldn't find stormnode payment or payee"));
        //}
    }

    // Check transactions
    BOOST_FOREACH(CTransaction& tx, vtx){
        if (!tx.CheckTransaction(state))
            return DoS(tx.nDoS, error("CheckBlock() : CheckTransaction failed"));

        // ppcoin: check transaction timestamp
        if (GetBlockTime() < (int64_t)tx.nTime)
            return DoS(50, error("CheckBlock() : block timestamp earlier than transaction timestamp"));
    }

    // Check for duplicate txids. This is caught by ConnectInputs(),
    // but catching it earlier avoids a potential DoS attack:
    set<uint256> uniqueTx;
    BOOST_FOREACH(const CTransaction& tx, vtx)
    {
        uniqueTx.insert(tx.GetHash());
    }
    if (uniqueTx.size() != vtx.size())
        return DoS(100, error("CheckBlock() : duplicate transaction"));

    unsigned int nSigOps = 0;
    BOOST_FOREACH(const CTransaction& tx, vtx)
    {
        nSigOps += GetLegacySigOpCount(tx);
    }
    if (nSigOps > MAX_BLOCK_SIGOPS)
        return DoS(100, error("CheckBlock() : out-of-bounds SigOpCount"));

    // Check merkle root
    if (fCheckMerkleRoot && hashMerkleRoot != BuildMerkleTree())
        return DoS(100, error("CheckBlock() : hashMerkleRoot mismatch"));


    return true;
}

// Called from inside SetBestChain: attaches a block to the new best chain being built
bool CBlock::SetBestChainInner(CTxDB& txdb, CBlockIndex *pindexNew)
{
    uint256 hash = GetHash();

    // Adding to current best branch
    if (!ConnectBlock(txdb, pindexNew) || !txdb.WriteHashBestChain(hash))
    {
        txdb.TxnAbort();
        InvalidChainFound(pindexNew);
        return false;
    }
    if (!txdb.TxnCommit())
        return error("SetBestChain() : TxnCommit failed");

    // Add to current best branch
    pindexNew->pprev->pnext = pindexNew;

    // Delete redundant memory transactions
    BOOST_FOREACH(CTransaction& tx, vtx)
        mempool.remove(tx);

    return true;
}

bool CBlock::ReadFromDisk(const CBlockIndex* pindex, bool fReadTransactions)
{
    if (!fReadTransactions)
    {
        *this = pindex->GetBlockHeader();
        return true;
    }
    if (!ReadFromDisk(pindex->nFile, pindex->nBlockPos, fReadTransactions))
        return false;
    if (GetHash() != pindex->GetBlockHash())
        return error("CBlock::ReadFromDisk() : GetHash() doesn't match index");
    return true;
}

bool CBlock::WriteToDisk(unsigned int& nFileRet, unsigned int& nBlockPosRet)
{
    // Open history file to append
    CAutoFile fileout = CAutoFile(AppendBlockFile(nFileRet), SER_DISK, CLIENT_VERSION);
    if (!fileout)
        return error("CBlock::WriteToDisk() : AppendBlockFile failed");

    // Write index header
    unsigned int nSize = fileout.GetSerializeSize(*this);
    fileout << FLATDATA(Params().MessageStart()) << nSize;

    // Write block
    long fileOutPos = ftell(fileout);
    if (fileOutPos < 0)
        return error("CBlock::WriteToDisk() : ftell failed");
    nBlockPosRet = fileOutPos;
    fileout << *this;

    // Flush stdio buffers and commit to disk before returning
    fflush(fileout);
    if (!IsInitialBlockDownload() || (nBestHeight+1) % 500 == 0)
        FileCommit(fileout);

    return true;
}

bool CBlock::ReadFromDisk(unsigned int nFile, unsigned int nBlockPos, bool fReadTransactions)
{
    SetNull();

    // Open history file to read
    CAutoFile filein = CAutoFile(OpenBlockFile(nFile, nBlockPos, "rb"), SER_DISK, CLIENT_VERSION);
    if (!filein)
        return error("CBlock::ReadFromDisk() : OpenBlockFile failed");
    if (!fReadTransactions)
        filein.nType |= SER_BLOCKHEADERONLY;

    // Read block
    try {
        filein >> *this;
    }
    catch (std::exception &e) {
        return error("%s() : deserialize or I/O error", __PRETTY_FUNCTION__);
    }

    // Check the header
    if (fReadTransactions && IsProofOfWork() && !CheckProofOfWork(GetPoWHash(), nBits))
        return error("CBlock::ReadFromDisk() : errors in block header");

    return true;
}
