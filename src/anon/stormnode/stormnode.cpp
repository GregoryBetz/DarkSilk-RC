// Copyright (c) 2014-2016 The Dash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/lexical_cast.hpp>

#include "anon/stormnode/stormnode.h"
#include "anon/sandstorm/sandstorm.h"
#include "anon/stormnode/stormnode-payments.h"
#include "anon/stormnode/stormnode-sync.h"
#include "anon/stormnode/stormnodeman.h"
#include "util.h"
#include "sync.h"
#include "addrman.h"
#include "init.h"

// keep track of the scanning errors I've seen
map<uint256, int> mapSeenStormnodeScanningErrors;
// cache block hashes as we calculate them
std::map<int64_t, uint256> mapCacheBlockHashes;

//Get the last hash that matches the modulus given. Processed in reverse order
bool GetBlockHash(uint256& hash, int nBlockHeight)
{   
    LOCK(cs_main);
    if (pindexBest == NULL) return false;

    if(nBlockHeight == 0)
        nBlockHeight = pindexBest->nHeight;

    if(mapCacheBlockHashes.count(nBlockHeight)){
        hash = mapCacheBlockHashes[nBlockHeight];
        return true;
    }

    const CBlockIndex *BlockLastSolved = pindexBest;
    const CBlockIndex *BlockReading = pindexBest;

    if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || pindexBest->nHeight+1 < nBlockHeight) return false;

    int nBlocksAgo = 0;
    if(nBlockHeight > 0) nBlocksAgo = (pindexBest->nHeight+1)-nBlockHeight;
    assert(nBlocksAgo >= 0);

    int n = 0;
    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
        if(n >= nBlocksAgo){
            hash = BlockReading->GetBlockHash();
            mapCacheBlockHashes[nBlockHeight] = hash;
            return true;
        }
        n++;

        if (BlockReading->pprev == NULL) { assert(BlockReading); break; }
        BlockReading = BlockReading->pprev;
    }

    return false;
}

CStormnode::CStormnode()
{
    LOCK(cs);
    vin = CTxIn();
    addr = CService();
    pubkey = CPubKey();
    pubkey2 = CPubKey();
    vchSig = std::vector<unsigned char>();
    activeState = STORMNODE_ENABLED;
    sigTime = GetAdjustedTime();
    lastPing = CStormnodePing();
    cacheInputAge = 0;
    cacheInputAgeBlock = 0;
    unitTest = false;
    allowFreeTx = true;
    protocolVersion = PROTOCOL_VERSION;
    nLastSsq = 0;
    nScanningErrorCount = 0;
    nLastScanningErrorBlockHeight = 0;
    lastTimeChecked = 0;
}

CStormnode::CStormnode(const CStormnode& other)
{
    LOCK(cs);
    vin = other.vin;
    addr = other.addr;
    pubkey = other.pubkey;
    pubkey2 = other.pubkey2;
    vchSig = other.vchSig;
    activeState = other.activeState;
    sigTime = other.sigTime;
    lastPing = other.lastPing;
    cacheInputAge = other.cacheInputAge;
    cacheInputAgeBlock = other.cacheInputAgeBlock;
    unitTest = other.unitTest;
    allowFreeTx = other.allowFreeTx;
    protocolVersion = other.protocolVersion;
    nLastSsq = other.nLastSsq;
    nScanningErrorCount = other.nScanningErrorCount;
    nLastScanningErrorBlockHeight = other.nLastScanningErrorBlockHeight;
    lastTimeChecked = 0;
}

CStormnode::CStormnode(const CStormnodeBroadcast& snb)
{
    LOCK(cs);
    vin = snb.vin;
    addr = snb.addr;
    pubkey = snb.pubkey;
    pubkey2 = snb.pubkey2;
    vchSig = snb.vchSig;
    activeState = STORMNODE_ENABLED;
    sigTime = snb.sigTime;
    lastPing = snb.lastPing;
    cacheInputAge = 0;
    cacheInputAgeBlock = 0;
    unitTest = false;
    allowFreeTx = true;
    protocolVersion = snb.protocolVersion;
    nLastSsq = snb.nLastSsq;
    nScanningErrorCount = 0;
    nLastScanningErrorBlockHeight = 0;
    lastTimeChecked = 0;
}

//
// When a new stormnode broadcast is sent, update our information
//
bool CStormnode::UpdateFromNewBroadcast(CStormnodeBroadcast& snb)
{
    if(snb.sigTime > sigTime) {
        pubkey2 = snb.pubkey2;
        sigTime = snb.sigTime;
        vchSig = snb.vchSig;
        protocolVersion = snb.protocolVersion;
        addr = snb.addr;
        lastTimeChecked = 0;
        int nDoS = 0;
        if(snb.lastPing == CStormnodePing() || (snb.lastPing != CStormnodePing() && snb.lastPing.CheckAndUpdate(nDoS, false))) {
            lastPing = snb.lastPing;
            snodeman.mapSeenStormnodePing.insert(make_pair(lastPing.GetHash(), lastPing));
        }
        return true;
    }
    return false;
}

//
// Deterministically calculate a given "score" for a Stormnode depending on how close it's hash is to
// the proof of work for that block. The further away they are the better, the furthest will win the election
// and get paid this block
//
uint256 CStormnode::CalculateScore(int mod, int64_t nBlockHeight)
{
    {
        LOCK(cs_main);
        if(pindexBest == NULL) return uint256();
    }

    uint256 hash = 0;
    uint256 aux = vin.prevout.hash + vin.prevout.n;

    if(!GetBlockHash(hash, nBlockHeight)) {
        LogPrintf("CalculateScore ERROR - nHeight %d - Returned 0\n", nBlockHeight);
        return 0;
    }

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << hash;
    uint256 hash2 = ss.GetHash();

    CHashWriter ss2(SER_GETHASH, PROTOCOL_VERSION);
    ss2 << hash;
    ss2 << aux;
    uint256 hash3 = ss2.GetHash();

    uint256 r = (hash3 > hash2 ? hash3 - hash2 : hash2 - hash3);

    return r;
}

void CStormnode::Check(bool forceCheck)
{
    if(ShutdownRequested()) return;

    if(!forceCheck && (GetTime() - lastTimeChecked < STORMNODE_CHECK_SECONDS)) return;
    lastTimeChecked = GetTime();


    //once spent, stop doing the checks
    if(activeState == STORMNODE_VIN_SPENT) return;

    if(!IsPingedWithin(STORMNODE_REMOVAL_SECONDS)){
        activeState = STORMNODE_REMOVE;
        return;
    }

    if(!IsPingedWithin(STORMNODE_EXPIRATION_SECONDS)){
        activeState = STORMNODE_EXPIRED;
        return;
    }

    if(lastPing.sigTime - sigTime < STORMNODE_MIN_SNP_SECONDS){
        activeState = STORMNODE_PRE_ENABLED;
        return;
    }

    if(!unitTest){
        //TODO (Amir): put this back.
        /*CValidationState state;
        CTransaction tx = CTransaction(); //TODO (Amir): Use CMutableTransaction here?
        CTxOut vout = CTxOut(9999.99*COIN, sandStormSigner.collateralPubKey);
        tx.vin.push_back(vin);
        tx.vout.push_back(vout);

        {
            TRY_LOCK(cs_main, lockMain);
            if(!lockMain) return;

            //if(!AcceptableInputs(mempool, state, CTransaction(tx), false, NULL)){
            if(!AcceptableInputs(mempool, tx, false, NULL)){
                activeState = STORMNODE_VIN_SPENT;
                return;

            }
        }*/
    }

    activeState = STORMNODE_ENABLED; // OK
}

int64_t CStormnode::SecondsSincePayment() {
    CScript pubkeyScript;
    pubkeyScript = GetScriptForDestination(pubkey.GetID());

    int64_t sec = (GetAdjustedTime() - GetLastPaid());
    int64_t month = 60*60*24*30;
    if(sec < month) return sec; //if it's less than 30 days, give seconds

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << vin;
    ss << sigTime;
    uint256 hash =  ss.GetHash();

    //TODO (Amir): ramifications of using a PoS hash and GetCompact here???
    // return some deterministic value for unknown/unpaid but force it to be more than 30 days old
    return month + hash.GetCompact(false);
}

int64_t CStormnode::GetLastPaid() {
    CBlockIndex *pindexPrev = NULL;
    {
        LOCK(cs_main);
        pindexPrev = pindexBest;
        if(!pindexPrev) return 0;
    }    if(pindexPrev == NULL) return false;

    CScript snpayee;
    snpayee = GetScriptForDestination(pubkey.GetID());

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << vin;
    ss << sigTime;
    uint256 hash =  ss.GetHash();

    // use a deterministic offset to break a tie -- 2.5 minutes
    //TODO (Amir): Ramifications of using a GetCompact PoS hash?
    int64_t nOffset = hash.GetCompact(false) % 150;

    const CBlockIndex *BlockReading = pindexPrev;

    int nSnCount = snodeman.CountEnabled()*1.25;
    int n = 0;
    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
        if(n >= nSnCount){
            return 0;
        }
        n++;

        if(stormnodePayments.mapStormnodeBlocks.count(BlockReading->nHeight)){
            /*
                Search for this payee, with at least 2 votes. This will aid in consensus allowing the network
                to converge on the same payees quickly, then keep the same schedule.
            */
            if(stormnodePayments.mapStormnodeBlocks[BlockReading->nHeight].HasPayeeWithVotes(snpayee, 2)){
                return BlockReading->nTime + nOffset;
            }
        }

        if (BlockReading->pprev == NULL) { assert(BlockReading); break; }
        BlockReading = BlockReading->pprev;
    }

    return 0;
}

CStormnodeBroadcast::CStormnodeBroadcast()
{
    vin = CTxIn();
    addr = CService();
    pubkey = CPubKey();
    pubkey2 = CPubKey();
    vchSig = std::vector<unsigned char>();
    activeState = STORMNODE_ENABLED;
    sigTime = GetAdjustedTime();
    lastPing = CStormnodePing();
    cacheInputAge = 0;
    cacheInputAgeBlock = 0;
    unitTest = false;
    allowFreeTx = true;
    protocolVersion = PROTOCOL_VERSION;
    nLastSsq = 0;
    nScanningErrorCount = 0;
    nLastScanningErrorBlockHeight = 0;
}

CStormnodeBroadcast::CStormnodeBroadcast(CService newAddr, CTxIn newVin, CPubKey newPubkey, CPubKey newPubkey2, int protocolVersionIn)
{
    vin = newVin;
    addr = newAddr;
    pubkey = newPubkey;
    pubkey2 = newPubkey2;
    vchSig = std::vector<unsigned char>();
    activeState = STORMNODE_ENABLED;
    sigTime = GetAdjustedTime();
    lastPing = CStormnodePing();
    cacheInputAge = 0;
    cacheInputAgeBlock = 0;
    unitTest = false;
    allowFreeTx = true;
    protocolVersion = protocolVersionIn;
    nLastSsq = 0;
    nScanningErrorCount = 0;
    nLastScanningErrorBlockHeight = 0;
}

CStormnodeBroadcast::CStormnodeBroadcast(const CStormnode& sn)
{
    vin = sn.vin;
    addr = sn.addr;
    pubkey = sn.pubkey;
    pubkey2 = sn.pubkey2;
    vchSig = sn.vchSig;
    activeState = sn.activeState;
    sigTime = sn.sigTime;
    lastPing = sn.lastPing;
    cacheInputAge = sn.cacheInputAge;
    cacheInputAgeBlock = sn.cacheInputAgeBlock;
    unitTest = sn.unitTest;
    allowFreeTx = sn.allowFreeTx;
    protocolVersion = sn.protocolVersion;
    nLastSsq = sn.nLastSsq;
    nScanningErrorCount = sn.nScanningErrorCount;
    nLastScanningErrorBlockHeight = sn.nLastScanningErrorBlockHeight;
}

bool CStormnodeBroadcast::CheckAndUpdate(int& nDos)
{
    // make sure signature isn't in the future (past is OK)
    if (sigTime > GetAdjustedTime() + 60 * 60) {
        LogPrintf("CStormnodeBroadcast::CheckAndUpdate - Signature rejected, too far into the future %s\n", vin.ToString());
        nDos = 1;
        return false;
    }

    std::string vchPubKey(pubkey.begin(), pubkey.end());
    std::string vchPubKey2(pubkey2.begin(), pubkey2.end());
    std::string strMessage = addr.ToString() + boost::lexical_cast<std::string>(sigTime) + vchPubKey + vchPubKey2 + boost::lexical_cast<std::string>(protocolVersion);

    if(protocolVersion < stormnodePayments.GetMinStormnodePaymentsProto()) {
        LogPrintf("CStormnodeBroadcast::CheckAndUpdate - ignoring outdated Stormnode %s protocol version %d\n", vin.ToString(), protocolVersion);
        return false;
    }

    CScript pubkeyScript;
    pubkeyScript = GetScriptForDestination(pubkey.GetID());

    if(pubkeyScript.size() != 25) {
        LogPrintf("CStormnodeBroadcast::CheckAndUpdate - pubkey the wrong size\n");
        nDos = 100;
        return false;
    }

    CScript pubkeyScript2;
    pubkeyScript2 = GetScriptForDestination(pubkey2.GetID());

    if(pubkeyScript2.size() != 25) {
        LogPrintf("CStormnodeBroadcast::CheckAndUpdate - pubkey2 the wrong size\n");
        nDos = 100;
        return false;
    }

    if(!vin.scriptSig.empty()) {
        LogPrintf("CStormnodeBroadcast::CheckAndUpdate - Ignore Not Empty ScriptSig %s\n",vin.ToString());
        return false;
    }

    std::string errorMessage = "";
    if(!sandStormSigner.VerifyMessage(pubkey, vchSig, strMessage, errorMessage)){
        LogPrintf("CStormnodeBroadcast::CheckAndUpdate - Got bad Stormnode address signature\n");
        nDos = 100;
        return false;
    }

    if(Params().NetworkID() == CChainParams::MAIN) {
        if(addr.GetPort() != 31000) return false;
    } else if(addr.GetPort() == 31000) return false;

    //search existing Stormnode list, this is where we update existing Stormnodes with new snb broadcasts
    CStormnode* psn = snodeman.Find(vin);

    // no such stormnode, nothing to update
    if(psn == NULL) return true ;
    else {

        // this broadcast is older or equal than the one that we already have - it's bad and should never happen
        // unless someone is doing something fishy
        // (mapSeenMasternodeBroadcast in CMasternodeMan::ProcessMessage should filter legit duplicates) 
        if(psn->sigTime > sigTime) {
            LogPrintf("CStormnodeBroadcast::CheckAndUpdate - Bad sigTime %d for Stormnode %20s %105s (existing broadcast is at %d)\n",
                          sigTime, addr.ToString(), vin.ToString(), psn->sigTime);
            return false;
        }
        // masternode is not enabled yet/already, nothing to update
        if(!psn->IsEnabled()) return true;
    }

    // sn.pubkey = pubkey, IsVinAssociatedWithPubkey is validated once below,
    //   after that they just need to match
    if(psn->pubkey == pubkey && !psn->IsBroadcastedWithin(STORMNODE_MIN_SNB_SECONDS)) {
        //take the newest entry
        LogPrintf("CStormnodeBroadcast::CheckAndUpdate - Got updated entry for %s\n", addr.ToString());
        if(psn->UpdateFromNewBroadcast((*this))){
            psn->Check();
            if(psn->IsEnabled()) Relay();
        }
        stormnodeSync.AddedStormnodeList(GetHash());
    }

    return true;
}

bool CStormnodeBroadcast::CheckInputsAndAdd(int& nDoS)
{
    // we are a stormnode with the same vin (i.e. already activated) and this snb is ours (matches our Stormnode privkey)
    // so nothing to do here for us
    if(fStormNode && vin.prevout == activeStormnode.vin.prevout && pubkey2 == activeStormnode.pubKeyStormnode)
        return true;

    int nDos;
    // Incorrect ping or its sigtime
    if (lastPing == CStormnodePing() || !lastPing.CheckAndUpdate(nDos, false, true))
        return false;

    // search existing Stormnode list
    CStormnode* psn = snodeman.Find(vin);

    if(psn != NULL) {
        // nothing to do here if we already know about this stormnode and it's (pre)enabled
        if(psn->IsEnabled() || psn->IsPreEnabled()) return true;
        // if it's not enabled, remove old SN first and continue
        else snodeman.Remove(psn->vin);
    }

    CValidationState state;
    CTransaction tx; //TODO (Amir): Use CMutableTransaction here?
    CTxOut vout = CTxOut(9999.99*COIN, sandStormPool.collateralPubKey);
    tx.vin.push_back(vin);
    tx.vout.push_back(vout);

    {
        TRY_LOCK(cs_main, lockMain);
        if(!lockMain) {
            // not snb fault, let it to be checked again later
            snodeman.mapSeenStormnodeBroadcast.erase(GetHash());
            stormnodeSync.mapSeenSyncSNB.erase(GetHash());
            return false;
        }

        //TODO (Amir): Use state in AcceptableInputs
        if(!AcceptableInputs(mempool, state, tx, false, NULL)) {
            //set nDos
            state.IsInvalid(nDoS);
            return false;
        }
    }

    LogPrint("stormnode", "CStormnodeBroadcast::CheckInputsAndAdd - Accepted Stormnode entry\n");

    if(GetInputAge(vin) < STORMNODE_MIN_CONFIRMATIONS){
        LogPrintf("CStormnodeBroadcast::CheckInputsAndAdd - Input must have at least %d confirmations\n", STORMNODE_MIN_CONFIRMATIONS);
        // maybe we miss few blocks, let this snb to be checked again later
        snodeman.mapSeenStormnodeBroadcast.erase(GetHash());
        stormnodeSync.mapSeenSyncSNB.erase(GetHash());
        return false;
    }

    // verify that sig time is legit in past
    // should be at least not earlier than block when 10000 DRKSLK tx got STORMNODE_MIN_CONFIRMATIONS
    uint256 hashBlock = 0;
    CTransaction tx2;
    GetTransaction(vin.prevout.hash, tx2, hashBlock);
    //TODO (Amir): Put these line back...
    /*{
        LOCK(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end() && (*mi).second)
        {
            CBlockIndex* pSNIndex = (*mi).second; // block for 10000 DRKSLK tx -> 1 confirmation
            CBlockIndex* pConfIndex = chainActive[pSNIndex->nHeight + STORMNODE_MIN_CONFIRMATIONS - 1]; // block where tx got STORMNODE_MIN_CONFIRMATIONS
            if(pConfIndex->GetBlockTime() > sigTime)
            {
                LogPrintf("CStormnodeBroadcast::CheckInputsAndAdd - Bad sigTime %d for Masternode %20s %105s (%i conf block is at %d)\n",
                          sigTime, addr.ToString(), vin.ToString(), MASTERNODE_MIN_CONFIRMATIONS, pConfIndex->GetBlockTime());
                return false;
            }
        }
    }*/

    LogPrintf("CStormnodeBroadcast::CheckInputsAndAdd - Got NEW Stormnode entry - %s - %s - %s - %lli \n", GetHash().ToString(), addr.ToString(), vin.ToString(), sigTime);
    CStormnode sn(*this);
    snodeman.Add(sn);

    // if it matches our Stormnode privkey, then we've been remotely activated
    if(pubkey2 == activeStormnode.pubKeyStormnode && protocolVersion == PROTOCOL_VERSION){
        activeStormnode.EnableHotColdStormNode(vin, addr);
    }

    bool isLocal = addr.IsRFC1918() || addr.IsLocal();

    if(!isLocal) Relay();

    return true;
}

void CStormnodeBroadcast::Relay()
{
    CInv inv(MSG_STORMNODE_ANNOUNCE, GetHash());
    RelayInv(inv);
}

bool CStormnodeBroadcast::Sign(CKey& keyCollateralAddress)
{
    std::string errorMessage;

    std::string vchPubKey(pubkey.begin(), pubkey.end());
    std::string vchPubKey2(pubkey2.begin(), pubkey2.end());

    sigTime = GetAdjustedTime();

    std::string strMessage = addr.ToString() + boost::lexical_cast<std::string>(sigTime) + vchPubKey + vchPubKey2 + boost::lexical_cast<std::string>(protocolVersion);

    if(!sandStormSigner.SignMessage(strMessage, errorMessage, vchSig, keyCollateralAddress)) {
        LogPrintf("CStormnodeBroadcast::Sign() - Error: %s\n", errorMessage);
        return false;
    }

    return true;
}

bool CStormnodeBroadcast::VerifySignature()
{
    std::string errorMessage;

    std::string vchPubKey(pubkey.begin(), pubkey.end());
    std::string vchPubKey2(pubkey2.begin(), pubkey2.end());

    std::string strMessage = addr.ToString() + boost::lexical_cast<std::string>(sigTime) + vchPubKey + vchPubKey2 + boost::lexical_cast<std::string>(protocolVersion);

    if(!sandStormSigner.VerifyMessage(pubkey, vchSig, strMessage, errorMessage)) {
        LogPrintf("CMasternodeBroadcast::VerifySignature() - Error: %s\n", errorMessage);
        return false;
    }

    return true;
}

CStormnodePing::CStormnodePing()
{
    vin = CTxIn();
    blockHash = uint256(0);
    sigTime = 0;
    vchSig = std::vector<unsigned char>();
}

CStormnodePing::CStormnodePing(CTxIn& newVin)
{
    {
        LOCK(cs_main);
        CBlockIndex* pindexPrev = pindexBest;
        if(!pindexPrev) return;
    }

    vin = newVin;
    //TODO (Amir): Needs chainActive to work. put this back...
    //blockHash = chainActive[nHeight - 12]->GetBlockHash();
    sigTime = GetAdjustedTime();
    vchSig = std::vector<unsigned char>();
}


bool CStormnodePing::Sign(CKey& keyStormnode, CPubKey& pubKeyStormnode)
{
    std::string errorMessage;
    std::string strStormNodeSignMessage;

    sigTime = GetAdjustedTime();
    std::string strMessage = vin.ToString() + blockHash.ToString() + boost::lexical_cast<std::string>(sigTime);

    if(!sandStormSigner.SignMessage(strMessage, errorMessage, vchSig, keyStormnode)) {
        LogPrintf("CStormnodePing::Sign() - Error: %s\n", errorMessage);
        return false;
    }

    if(!sandStormSigner.VerifyMessage(pubKeyStormnode, vchSig, strMessage, errorMessage)) {
        LogPrintf("CStormnodePing::Sign() - Error: %s\n", errorMessage);
        return false;
    }

    return true;
}

bool CStormnodePing::VerifySignature(CPubKey& pubKeyStormnode, int &nDos) {
    std::string strMessage = vin.ToString() + blockHash.ToString() + boost::lexical_cast<std::string>(sigTime);
    std::string errorMessage = "";

    if(!sandStormSigner.VerifyMessage(pubKeyStormnode, vchSig, strMessage, errorMessage))
    {
        LogPrintf("CMasternodePing::VerifySignature - Got bad Stormnode ping signature %s Error: %s\n", vin.ToString(), errorMessage);
        nDos = 33;
        return false;
    }
    return true;
}

bool CStormnodePing::CheckAndUpdate(int& nDos, bool fRequireEnabled, bool fCheckSigTimeOnly)
{
    if (sigTime > GetAdjustedTime() + 60 * 60) {
        LogPrintf("CStormnodePing::CheckAndUpdate - Signature rejected, too far into the future %s\n", vin.ToString());
        nDos = 1;
        return false;
    }

    if (sigTime <= GetAdjustedTime() - 60 * 60) {
        LogPrintf("CStormnodePing::CheckAndUpdate - Signature rejected, too far into the past %s - %d %d \n", vin.ToString(), sigTime, GetAdjustedTime());
        nDos = 1;
        return false;
    }

    if (fCheckSigTimeOnly) {
        CStormnode* psn = snodeman.Find(vin);
        if (psn) return VerifySignature(psn->pubkey2, nDos);
        return true;
    }

    LogPrint("stormnode", "CStormnodePing::CheckAndUpdate - New Ping - %s - %s - %lli\n", GetHash().ToString(), blockHash.ToString(), sigTime);

    // see if we have this Stormnode
    CStormnode* psn = snodeman.Find(vin);
    if(psn != NULL && psn->protocolVersion >= stormnodePayments.GetMinStormnodePaymentsProto())
    {
        if (fRequireEnabled && !psn->IsEnabled() && !psn->IsPreEnabled()) return false;

        // LogPrintf("snping - Found corresponding sn for vin: %s\n", vin.ToString());
        // update only if there is no known ping for this stormnode or
        // last ping was more then STORMNODE_MIN_SNP_SECONDS-60 ago comparing to this one
        if(!psn->IsPingedWithin(STORMNODE_MIN_SNP_SECONDS - 60, sigTime))
        {
            if (!VerifySignature(psn->pubkey2, nDos))
                return false;

            //TODO (Amir): Put these lines back...
            /*
            {
                LOCK(cs_main);
                BlockMap::iterator mi = mapBlockIndex.find(blockHash);
                if (mi != mapBlockIndex.end() && (*mi).second)
                {
                    if((*mi).second->nHeight < chainActive.Height() - 24)
                    {
                        LogPrintf("CStormnodePing::CheckAndUpdate - Stormnode %s block hash %s is too old\n", vin.ToString(), blockHash.ToString());
                        // Do nothing here (no Stormnode update, no mnping relay)
                        // Let this node to be visible but fail to accept snping

                        return false;
                    }
                } else {
                    if (fDebug) LogPrintf("CStormnodePing::CheckAndUpdate - Stormnode %s block hash %s is unknown\n", vin.ToString(), blockHash.ToString());
                    // maybe we stuck so we shouldn't ban this node, just fail to accept it
                    // TODO: or should we also request this block?

                    return false;
                }
            }*/

            //TODO: Remove these two lines after above is implemented    
            LogPrintf("CStormnodePing::CheckAndUpdate - Not Implemented Yet!");
            return false;

            psn->lastPing = *this;

            //snodeman.mapSeenStormnodeBroadcast.lastPing is probably outdated, so we'll update it
            CStormnodeBroadcast snb(*psn);
            uint256 hash = snb.GetHash();
            if(snodeman.mapSeenStormnodeBroadcast.count(hash)) {
                snodeman.mapSeenStormnodeBroadcast[hash].lastPing = *this;
            }

            psn->Check(true);
            if(!psn->IsEnabled()) return false;

            LogPrint("stormnode", "CStormnodePing::CheckAndUpdate -Stormnode ping accepted, vin: %s\n", vin.ToString());

            Relay();
            return true;
        }
        LogPrint("stormnode", "CStormnodePing::CheckAndUpdate - Stormnode ping arrived too early, vin: %s\n", vin.ToString());
        //nDos = 1; //disable, this is happening frequently and causing banned peers
        return false;
    }
    LogPrint("stormnode", "CStormnodePing::CheckAndUpdate - Couldn't find compatible Stormnode entry, vin: %s\n", vin.ToString());

    return false;
}

void CStormnodePing::Relay()
{
    CInv inv(MSG_STORMNODE_PING, GetHash());
    RelayInv(inv);
}
