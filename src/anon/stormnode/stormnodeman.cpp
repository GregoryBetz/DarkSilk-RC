// Copyright (c) 2014-2016 The Dash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/lexical_cast.hpp>
#include <boost/filesystem.hpp>

#include "anon/stormnode/stormnodeman.h"
#include "anon/stormnode/activestormnode.h"
#include "anon/sandstorm/sandstorm.h"
#include "anon/stormnode/stormnode.h"
#include "anon/stormnode/stormnode-payments.h"
#include "anon/stormnode/stormnode-sync.h"
#include "util.h"
#include "addrman.h"
#include "anon/stormnode/spork.h"

/** Stormnode manager */
CStormnodeMan snodeman;

struct CompareLastPaid
{
    bool operator()(const pair<int64_t, CTxIn>& t1,
                    const pair<int64_t, CTxIn>& t2) const
    {
        return t1.first < t2.first;
    }
};

struct CompareScoreTxIn
{
    bool operator()(const pair<int64_t, CTxIn>& t1,
                    const pair<int64_t, CTxIn>& t2) const
    {
        return t1.first < t2.first;
    }
};

struct CompareScoreSN
{
    bool operator()(const pair<int64_t, CStormnode>& t1,
                    const pair<int64_t, CStormnode>& t2) const
    {
        return t1.first < t2.first;
    }
};

//
// CStormnodeDB
//

CStormnodeDB::CStormnodeDB()
{
    pathSN = GetDataDir() / "sncache.dat";
    strMagicMessage = "StormnodeCache";
}

bool CStormnodeDB::Write(const CStormnodeMan& snodemanToSave)
{
    int64_t nStart = GetTimeMillis();

    // serialize, checksum data up to that point, then append checksum
    CDataStream ssStormnodes(SER_DISK, CLIENT_VERSION);
    ssStormnodes << strMagicMessage; // stormnode cache file specific magic message
    ssStormnodes << FLATDATA(Params().MessageStart()); // network specific magic number
    ssStormnodes << snodemanToSave;
    uint256 hash = Hash(ssStormnodes.begin(), ssStormnodes.end());
    ssStormnodes << hash;

    // open output file, and associate with CAutoFile
    FILE *file = fopen(pathSN.string().c_str(), "wb");
    CAutoFile fileout(file, SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("%s : Failed to open file %s", __func__, pathSN.string());

    // Write and commit header, data
    try {
        fileout << ssStormnodes;
    }
    catch (std::exception &e) {
        return error("%s : Serialize or I/O error - %s", __func__, e.what());
    }
//    FileCommit(fileout);
    fileout.fclose();

    LogPrintf("Written info to sncache.dat  %dms\n", GetTimeMillis() - nStart);
    LogPrintf("  %s\n", snodemanToSave.ToString());

    return true;
}

CStormnodeDB::ReadResult CStormnodeDB::Read(CStormnodeMan& snodemanToLoad, bool fDryRun)
{
    int64_t nStart = GetTimeMillis();
    // open input file, and associate with CAutoFile
    FILE *file = fopen(pathSN.string().c_str(), "rb");
    CAutoFile filein(file, SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
    {
        error("%s : Failed to open file %s", __func__, pathSN.string());
        return FileError;
    }

    // use file size to size memory buffer
    int fileSize = boost::filesystem::file_size(pathSN);
    int dataSize = fileSize - sizeof(uint256);
    // Don't try to resize to a negative number if file is small
    if (dataSize < 0)
        dataSize = 0;
    vector<unsigned char> vchData;
    vchData.resize(dataSize);
    uint256 hashIn;

    // read data and checksum from file
    try {
        filein.read((char *)&vchData[0], dataSize);
        filein >> hashIn;
    }
    catch (std::exception &e) {
        error("%s : Deserialize or I/O error - %s", __func__, e.what());
        return HashReadError;
    }
    filein.fclose();

    CDataStream ssStormnodes(vchData, SER_DISK, CLIENT_VERSION);

    // verify stored checksum matches input data
    uint256 hashTmp = Hash(ssStormnodes.begin(), ssStormnodes.end());
    if (hashIn != hashTmp)
    {
        error("%s : Checksum mismatch, data corrupted", __func__);
        return IncorrectHash;
    }

    unsigned char pchMsgTmp[4];
    std::string strMagicMessageTmp;
    try {
        // de-serialize file header (stormnode cache file specific magic message) and ..

        ssStormnodes >> strMagicMessageTmp;

        // ... verify the message matches predefined one
        if (strMagicMessage != strMagicMessageTmp)
        {
            error("%s : Invalid stormnode cache magic message", __func__);
            return IncorrectMagicMessage;
        }

        // de-serialize file header (network specific magic number) and ..
        ssStormnodes >> FLATDATA(pchMsgTmp);

        // ... verify the network matches ours
        if (memcmp(pchMsgTmp, Params().MessageStart(), sizeof(pchMsgTmp)))
        {
            error("%s : Invalid network magic number", __func__);
            return IncorrectMagicNumber;
        }
        // de-serialize data into CStormnodeMan object
        ssStormnodes >> snodemanToLoad;
    }
    catch (std::exception &e) {
        snodemanToLoad.Clear();
        error("%s : Deserialize or I/O error - %s", __func__, e.what());
        return IncorrectFormat;
    }

    LogPrintf("Loaded info from sncache.dat  %dms\n", GetTimeMillis() - nStart);
    LogPrintf("  %s\n", snodemanToLoad.ToString());
    if(!fDryRun) {
        LogPrintf("Stormnode manager - cleaning....\n");
        snodemanToLoad.CheckAndRemove(true);
        LogPrintf("Stormnode manager - result:\n");
        LogPrintf("  %s\n", snodemanToLoad.ToString());
    }

    return Ok;
}

void DumpStormnodes()
{
    int64_t nStart = GetTimeMillis();

    CStormnodeDB sndb;
    CStormnodeMan tempSnodeman;

    LogPrintf("Verifying sncache.dat format...\n");
    CStormnodeDB::ReadResult readResult = sndb.Read(tempSnodeman, true);
    // there was an error and it was not an error on file opening => do not proceed
    if (readResult == CStormnodeDB::FileError)
        LogPrintf("Missing stormnode cache file - sncache.dat, will try to recreate\n");
    else if (readResult != CStormnodeDB::Ok)
    {
        LogPrintf("Error reading sncache.dat: ");
        if(readResult == CStormnodeDB::IncorrectFormat)
            LogPrintf("magic is ok but data has invalid format, will try to recreate\n");
        else
        {
            LogPrintf("file format is unknown or invalid, please fix it manually\n");
            return;
        }
    }
    LogPrintf("Writting info to sncache.dat...\n");
    sndb.Write(snodeman);

    LogPrintf("Stormnode dump finished  %dms\n", GetTimeMillis() - nStart);
}

CStormnodeMan::CStormnodeMan() {
    nSsqCount = 0;
}

bool CStormnodeMan::Add(CStormnode &sn)
{
    LOCK(cs);

    if (!sn.IsEnabled() && !sn.IsPreEnabled())
        return false;

    CStormnode *psn = Find(sn.vin);
    if (psn == NULL)
    {
        LogPrint("stormnode", "CStormnodeMan: Adding new Stormnode %s - %i now\n", sn.addr.ToString(), size() + 1);
        vStormnodes.push_back(sn);
        return true;
    }

    return false;
}

void CStormnodeMan::AskForSN(CNode* pnode, CTxIn &vin)
{
    std::map<COutPoint, int64_t>::iterator i = mWeAskedForStormnodeListEntry.find(vin.prevout);
    if (i != mWeAskedForStormnodeListEntry.end())
    {
        int64_t t = (*i).second;
        if (GetTime() < t) return; // we've asked recently
    }

    // ask for the snb info once from the node that sent snp

    LogPrintf("CStormnodeMan::AskForSN - Asking node for missing entry, vin: %s\n", vin.ToString());
    pnode->PushMessage("sseg", vin);
    int64_t askAgain = GetTime() + STORMNODE_MIN_SNP_SECONDS;
    mWeAskedForStormnodeListEntry[vin.prevout] = askAgain;
}

void CStormnodeMan::Check()
{
    LOCK(cs);

    BOOST_FOREACH(CStormnode& sn, vStormnodes) {
        sn.Check();
    }
}

void CStormnodeMan::CheckAndRemove(bool forceExpiredRemoval)
{
    Check();

    LOCK(cs);

    //remove inactive and outdated
    vector<CStormnode>::iterator it = vStormnodes.begin();
    while(it != vStormnodes.end()){
        if((*it).activeState == CStormnode::STORMNODE_REMOVE ||
                (*it).activeState == CStormnode::STORMNODE_VIN_SPENT ||
                (forceExpiredRemoval && (*it).activeState == CStormnode::STORMNODE_EXPIRED) ||
                (*it).protocolVersion < stormnodePayments.GetMinStormnodePaymentsProto()) {
            LogPrint("stormnode", "CStormnodeMan: CheckAndRemove - Removing inactive Stormnode %s - %i now\n", (*it).addr.ToString(), size() - 1);

            //erase all of the broadcasts we've seen from this vin
            // -- if we missed a few pings and the node was removed, this will allow is to get it back without them
            //    sending a brand new snb
            map<uint256, CStormnodeBroadcast>::iterator it3 = mapSeenStormnodeBroadcast.begin();
            while(it3 != mapSeenStormnodeBroadcast.end()){
                if((*it3).second.vin == (*it).vin){
                    stormnodeSync.mapSeenSyncSNB.erase((*it3).first);
                    mapSeenStormnodeBroadcast.erase(it3++);
                } else {
                    ++it3;
                }
            }

            // allow us to ask for this stormnode again if we see another ping
            map<COutPoint, int64_t>::iterator it2 = mWeAskedForStormnodeListEntry.begin();
            while(it2 != mWeAskedForStormnodeListEntry.end()){
                if((*it2).first == (*it).vin.prevout){
                    mWeAskedForStormnodeListEntry.erase(it2++);
                } else {
                    ++it2;
                }
            }

            it = vStormnodes.erase(it);
        } else {
            ++it;
        }
    }

    // check who's asked for the Stormnode list
    map<CNetAddr, int64_t>::iterator it1 = mAskedUsForStormnodeList.begin();
    while(it1 != mAskedUsForStormnodeList.end()){
        if((*it1).second < GetTime()) {
            mAskedUsForStormnodeList.erase(it1++);
        } else {
            ++it1;
        }
    }

    // check who we asked for the Stormnode list
    it1 = mWeAskedForStormnodeList.begin();
    while(it1 != mWeAskedForStormnodeList.end()){
        if((*it1).second < GetTime()){
            mWeAskedForStormnodeList.erase(it1++);
        } else {
            ++it1;
        }
    }

    // check which Stormnodes we've asked for
    map<COutPoint, int64_t>::iterator it2 = mWeAskedForStormnodeListEntry.begin();
    while(it2 != mWeAskedForStormnodeListEntry.end()){
        if((*it2).second < GetTime()){
            mWeAskedForStormnodeListEntry.erase(it2++);
        } else {
            ++it2;
        }
    }

    // remove expired mapSeenStormnodeBroadcast
    map<uint256, CStormnodeBroadcast>::iterator it3 = mapSeenStormnodeBroadcast.begin();
    while(it3 != mapSeenStormnodeBroadcast.end()){
        if((*it3).second.lastPing.sigTime < GetTime() - STORMNODE_REMOVAL_SECONDS*2){
            LogPrint("stormnode", "CStormnodeMan::CheckAndRemove - Removing expired Stormnode broadcast %s\n", (*it3).second.GetHash().ToString());
            stormnodeSync.mapSeenSyncSNB.erase((*it3).second.GetHash());
            mapSeenStormnodeBroadcast.erase(it3++);
        } else {
            ++it3;
        }
    }

    // remove expired mapSeenStormnodePing
    map<uint256, CStormnodePing>::iterator it4 = mapSeenStormnodePing.begin();
    while(it4 != mapSeenStormnodePing.end()){
        if((*it4).second.sigTime < GetTime() - STORMNODE_REMOVAL_SECONDS*2){
            LogPrint("stormnode", "CStormnodeMan::CheckAndRemove - Removing expired Stormnode ping %s\n", (*it3).second.GetHash().ToString());
            mapSeenStormnodePing.erase(it4++);
        } else {
            ++it4;
        }
    }

}

void CStormnodeMan::Clear()
{
    LOCK(cs);
    vStormnodes.clear();
    mAskedUsForStormnodeList.clear();
    mWeAskedForStormnodeList.clear();
    mWeAskedForStormnodeListEntry.clear();
    mapSeenStormnodeBroadcast.clear();
    mapSeenStormnodePing.clear();
    nSsqCount = 0;
}

int CStormnodeMan::CountEnabled(int protocolVersion)
{
    int i = 0;
    protocolVersion = protocolVersion == -1 ? stormnodePayments.GetMinStormnodePaymentsProto() : protocolVersion;

    BOOST_FOREACH(CStormnode& sn, vStormnodes) {
        sn.Check();
        if(sn.protocolVersion < protocolVersion || !sn.IsEnabled()) continue;
        i++;
    }

    return i;
}

void CStormnodeMan::SsegUpdate(CNode* pnode)
{
    LOCK(cs);

    if(Params().NetworkID() == CChainParams::MAIN) {
        if(!(pnode->addr.IsRFC1918() || pnode->addr.IsLocal())){
            std::map<CNetAddr, int64_t>::iterator it = mWeAskedForStormnodeList.find(pnode->addr);
            if (it != mWeAskedForStormnodeList.end())
            {
                if (GetTime() < (*it).second) {
                    LogPrintf("sseg - we already asked %s for the list; skipping...\n", pnode->addr.ToString());
                    return;
                }
            }
        }
    }

    pnode->PushMessage("sseg", CTxIn());
    int64_t askAgain = GetTime() + STORMNODES_SSEG_SECONDS;
    mWeAskedForStormnodeList[pnode->addr] = askAgain;
}

CStormnode *CStormnodeMan::Find(const CScript &payee)
{
    LOCK(cs);
    CScript payee2;

    BOOST_FOREACH(CStormnode& sn, vStormnodes)
    {
        payee2 = GetScriptForDestination(sn.pubkey.GetID());
        if(payee2 == payee)
            return &sn;
    }
    return NULL;
}

CStormnode *CStormnodeMan::Find(const CTxIn &vin)
{
    LOCK(cs);

    BOOST_FOREACH(CStormnode& sn, vStormnodes)
    {
        if(sn.vin.prevout == vin.prevout)
            return &sn;
    }
    return NULL;
}


CStormnode *CStormnodeMan::Find(const CPubKey &pubKeyStormnode)
{
    LOCK(cs);

    BOOST_FOREACH(CStormnode& sn, vStormnodes)
    {
        if(sn.pubkey2 == pubKeyStormnode)
            return &sn;
    }
    return NULL;
}

//
// Deterministically select the oldest/best stormnode to pay on the network
//
CStormnode* CStormnodeMan::GetNextStormnodeInQueueForPayment(int nBlockHeight, bool fFilterSigTime, int& nCount)
{
    LOCK(cs);

    CStormnode *pBestStormnode = NULL;
    std::vector<pair<int64_t, CTxIn> > vecStormnodeLastPaid;

    /*
        Make a vector with all of the last paid times
    */

    int nSnCount = CountEnabled();
    BOOST_FOREACH(CStormnode &sn, vStormnodes)
    {
        sn.Check();
        if(!sn.IsEnabled()) continue;

        // check protocol version
        if(sn.protocolVersion < stormnodePayments.GetMinStormnodePaymentsProto()) continue;

        //it's in the list (up to 8 entries ahead of current block to allow propagation) -- so let's skip it
        if(stormnodePayments.IsScheduled(sn, nBlockHeight)) continue;

        //it's too new, wait for a cycle
        if(fFilterSigTime && sn.sigTime + (nSnCount*2.6*60) > GetAdjustedTime()) continue;

        //make sure it has as many confirmations as there are stormnodes
        if(sn.GetStormnodeInputAge() < nSnCount) continue;

        vecStormnodeLastPaid.push_back(make_pair(sn.SecondsSincePayment(), sn.vin));
    }

    nCount = (int)vecStormnodeLastPaid.size();

    //when the network is in the process of upgrading, don't penalize nodes that recently restarted
    if(fFilterSigTime && nCount < nSnCount/3) return GetNextStormnodeInQueueForPayment(nBlockHeight, false, nCount);

    // Sort them high to low
    sort(vecStormnodeLastPaid.rbegin(), vecStormnodeLastPaid.rend(), CompareLastPaid());

    // Look at 1/10 of the oldest nodes (by last payment), calculate their scores and pay the best one
    //  -- This doesn't look at who is being paid in the +8-10 blocks, allowing for double payments very rarely
    //  -- 1/100 payments should be a double payment on mainnet - (1/(3000/10))*2
    //  -- (chance per block * chances before IsScheduled will fire)
    int nTenthNetwork = CountEnabled()/10;
    int nCountTenth = 0;
    uint256 nHigh = 0;
    BOOST_FOREACH (PAIRTYPE(int64_t, CTxIn)& s, vecStormnodeLastPaid){
        CStormnode* psn = Find(s.second);
        if(!psn) break;

        uint256 n = psn->CalculateScore(1, nBlockHeight-100);
        if(n > nHigh){
            nHigh = n;
            pBestStormnode = psn;
        }
        nCountTenth++;
        if(nCountTenth >= nTenthNetwork) break;
    }
    return pBestStormnode;
}

CStormnode *CStormnodeMan::FindRandomNotInVec(std::vector<CTxIn> &vecToExclude, int protocolVersion)
{
    LOCK(cs);

    protocolVersion = protocolVersion == -1 ? stormnodePayments.GetMinStormnodePaymentsProto() : protocolVersion;

    int nCountEnabled = CountEnabled(protocolVersion);
    LogPrintf("CStormnodeMan::FindRandomNotInVec - nCountEnabled - vecToExclude.size() %d\n", nCountEnabled - vecToExclude.size());
    if(nCountEnabled - vecToExclude.size() < 1) return NULL;

    int rand = GetRandInt(nCountEnabled - vecToExclude.size());
    LogPrintf("CStormnodeMan::FindRandomNotInVec - rand %d\n", rand);
    bool found;

    BOOST_FOREACH(CStormnode &sn, vStormnodes) {
        if(sn.protocolVersion < protocolVersion || !sn.IsEnabled()) continue;
        found = false;
        BOOST_FOREACH(CTxIn &usedVin, vecToExclude) {
            if(sn.vin.prevout == usedVin.prevout) {
                found = true;
                break;
            }
        }
        if(found) continue;
        if(--rand < 1) {
            return &sn;
        }
    }

    return NULL;
}

CStormnode* CStormnodeMan::GetCurrentStormNode(int mod, int64_t nBlockHeight, int minProtocol)
{
    int64_t score = 0;
    CStormnode* winner = NULL;

    // scan for winner
    BOOST_FOREACH(CStormnode& sn, vStormnodes) {
        sn.Check();
        if(sn.protocolVersion < minProtocol || !sn.IsEnabled()) continue;

        // calculate the score for each Stormnode
        uint256 n = sn.CalculateScore(mod, nBlockHeight);
        int64_t n2 = n.GetCompact(false);

        // determine the winner
        if(n2 > score){
            score = n2;
            winner = &sn;
        }
    }

    return winner;
}

int CStormnodeMan::GetStormnodeRank(const CTxIn& vin, int64_t nBlockHeight, int minProtocol, bool fOnlyActive)
{
    std::vector<pair<int64_t, CTxIn> > vecStormnodeScores;

    //make sure we know about this block
    uint256 hash = 0;
    if(!GetBlockHash(hash, nBlockHeight)) return -1;

    // scan for winner
    BOOST_FOREACH(CStormnode& sn, vStormnodes) {
        if(sn.protocolVersion < minProtocol) continue;
        if(fOnlyActive) {
            sn.Check();
            if(!sn.IsEnabled()) continue;
        }
        uint256 n = sn.CalculateScore(1, nBlockHeight);
        int64_t n2 = n.GetCompact(false);

        vecStormnodeScores.push_back(make_pair(n2, sn.vin));
    }

    sort(vecStormnodeScores.rbegin(), vecStormnodeScores.rend(), CompareScoreTxIn());

    int rank = 0;
    BOOST_FOREACH (PAIRTYPE(int64_t, CTxIn)& s, vecStormnodeScores){
        rank++;
        if(s.second.prevout == vin.prevout) {
            return rank;
        }
    }

    return -1;
}

std::vector<pair<int, CStormnode> > CStormnodeMan::GetStormnodeRanks(int64_t nBlockHeight, int minProtocol)
{
    std::vector<pair<int64_t, CStormnode> > vecStormnodeScores;
    std::vector<pair<int, CStormnode> > vecStormnodeRanks;

    //make sure we know about this block
    uint256 hash = 0;
    if(!GetBlockHash(hash, nBlockHeight)) return vecStormnodeRanks;

    // scan for winner
    BOOST_FOREACH(CStormnode& sn, vStormnodes) {

        sn.Check();

        if(sn.protocolVersion < minProtocol) continue;
        if(!sn.IsEnabled()) {
            continue;
        }

        uint256 n = sn.CalculateScore(1, nBlockHeight);
        int64_t n2 = n.GetCompact(false);

        vecStormnodeScores.push_back(make_pair(n2, sn));
    }

    sort(vecStormnodeScores.rbegin(), vecStormnodeScores.rend(), CompareScoreSN());

    int rank = 0;
    BOOST_FOREACH (PAIRTYPE(int64_t, CStormnode)& s, vecStormnodeScores){
        rank++;
        vecStormnodeRanks.push_back(make_pair(rank, s.second));
    }

    return vecStormnodeRanks;
}

CStormnode* CStormnodeMan::GetStormnodeByRank(int nRank, int64_t nBlockHeight, int minProtocol, bool fOnlyActive)
{
    std::vector<pair<int64_t, CTxIn> > vecStormnodeScores;

    // scan for winner
    BOOST_FOREACH(CStormnode& sn, vStormnodes) {

        if(sn.protocolVersion < minProtocol) continue;
        if(fOnlyActive) {
            sn.Check();
            if(!sn.IsEnabled()) continue;
        }

        uint256 n = sn.CalculateScore(1, nBlockHeight);
        int64_t n2 = n.GetCompact(false);

        vecStormnodeScores.push_back(make_pair(n2, sn.vin));
    }

    sort(vecStormnodeScores.rbegin(), vecStormnodeScores.rend(), CompareScoreTxIn());

    int rank = 0;
    BOOST_FOREACH (PAIRTYPE(int64_t, CTxIn)& s, vecStormnodeScores){
        rank++;
        if(rank == nRank) {
            return Find(s.second);
        }
    }

    return NULL;
}

void CStormnodeMan::ProcessStormnodeConnections()
{
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes) {
        if(pnode->fSandStormMaster){
            if(sandStormPool.pSubmittedToStormnode != NULL && pnode->addr == sandStormPool.pSubmittedToStormnode->addr) continue;
            LogPrintf("Closing Stormnode connection %s \n", pnode->addr.ToString());
            pnode->fSandStormMaster = false;
            pnode->Release();
        }
    }
}

void CStormnodeMan::ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{

    if(fLiteMode) return; //disable all SandStorm/Stormnode related functionality
    if(!stormnodeSync.IsBlockchainSynced()) return;

    LOCK(cs_process_message);

    if (strCommand == "snb") { //Stormnode Broadcast
        CStormnodeBroadcast snb;
        vRecv >> snb;

        if(mapSeenStormnodeBroadcast.count(snb.GetHash())) { //seen
            stormnodeSync.AddedStormnodeList(snb.GetHash());
            return;
        }
        mapSeenStormnodeBroadcast.insert(make_pair(snb.GetHash(), snb));

        int nDoS = 0;
        if(!snb.CheckAndUpdate(nDoS)){

            if(nDoS > 0)
                Misbehaving(pfrom->GetId(), nDoS);

            //failed
            return;
        }

        // make sure the vout that was signed is related to the transaction that spawned the Stormnode
        //  - this is expensive, so it's only done once per Stormnode
        if(!sandStormSigner.IsVinAssociatedWithPubkey(snb.vin, snb.pubkey)) {
            LogPrintf("snb - Got mismatched pubkey and vin\n");
            Misbehaving(pfrom->GetId(), 33);
            return;
        }

        // make sure it's still unspent
        //  - this is checked later by .check() in many places and by ThreadCheckSandStormPool()
        if(snb.CheckInputsAndAdd(nDoS)) {
            // use this as a peer
            addrman.Add(CAddress(snb.addr), pfrom->addr, 2*60*60);
            stormnodeSync.AddedStormnodeList(snb.GetHash());
        } else {
            LogPrintf("snb - Rejected Stormnode entry %s\n", snb.addr.ToString());

            if (nDoS > 0)
                Misbehaving(pfrom->GetId(), nDoS);
        }
    }

    else if (strCommand == "snp") { //Stormnode Ping
        CStormnodePing snp;
        vRecv >> snp;

        LogPrint("stormnode", "snp - Stormnode ping, vin: %s\n", snp.vin.ToString());

        if(mapSeenStormnodePing.count(snp.GetHash())) return; //seen
        mapSeenStormnodePing.insert(make_pair(snp.GetHash(), snp));

        int nDoS = 0;
        if(snp.CheckAndUpdate(nDoS)) return;

        if(nDoS > 0) {
            // if anything significant failed, mark that node
            Misbehaving(pfrom->GetId(), nDoS);
        } else {
            // if nothing significant failed, search existing Stormnode list
            CStormnode* psn = Find(snp.vin);
            // if it's known, don't ask for the snb, just return
            if(psn != NULL) return;
        }

        // something significant is broken or sn is unknown,
        // we might have to ask for a stormnode entry once
        AskForSN(pfrom, snp.vin);

    } else if (strCommand == "sseg") { //Get Stormnode list or specific entry

        CTxIn vin;
        vRecv >> vin;

        if(vin == CTxIn()) { //only should ask for this once
            //local network
            bool isLocal = (pfrom->addr.IsRFC1918() || pfrom->addr.IsLocal());

            if(!isLocal && Params().NetworkID() == CChainParams::MAIN) {
                std::map<CNetAddr, int64_t>::iterator i = mAskedUsForStormnodeList.find(pfrom->addr);
                if (i != mAskedUsForStormnodeList.end()){
                    int64_t t = (*i).second;
                    if (GetTime() < t) {
                        Misbehaving(pfrom->GetId(), 34);
                        LogPrintf("sseg - peer already asked me for the list\n");
                        return;
                    }
                }
                int64_t askAgain = GetTime() + STORMNODES_SSEG_SECONDS;
                mAskedUsForStormnodeList[pfrom->addr] = askAgain;
            }
        } //else, asking for a specific node which is ok


        int nInvCount = 0;

        BOOST_FOREACH(CStormnode& sn, vStormnodes) {
            if(sn.addr.IsRFC1918() || sn.addr.IsLocal()) continue; //local network

            if(sn.IsEnabled()) {
                LogPrint("stormnode", "sseg - Sending Stormnode entry - %s \n", sn.addr.ToString());
                if(vin == CTxIn() || vin == sn.vin){
                    CStormnodeBroadcast snb = CStormnodeBroadcast(sn);
                    uint256 hash = snb.GetHash();
                    pfrom->PushInventory(CInv(MSG_STORMNODE_ANNOUNCE, hash));
                    nInvCount++;

                    if(!mapSeenStormnodeBroadcast.count(hash)) mapSeenStormnodeBroadcast.insert(make_pair(hash, snb));

                    if(vin == sn.vin) {
                        LogPrintf("sseg - Sent 1 Stormnode entries to %s\n", pfrom->addr.ToString());
                        return;
                    }
                }
            }
        }

        if(vin == CTxIn()) {
            pfrom->PushMessage("ssc", STORMNODE_SYNC_LIST, nInvCount);
            LogPrintf("sseg - Sent %d Stormnode entries to %s\n", nInvCount, pfrom->addr.ToString());
        }
    }
}

void CStormnodeMan::Remove(CTxIn vin)
{
    LOCK(cs);

    vector<CStormnode>::iterator it = vStormnodes.begin();
    while(it != vStormnodes.end()){
        if((*it).vin == vin){
            LogPrint("stormnode", "CStormnodeMan: Removing Stormnode %s - %i now\n", (*it).addr.ToString(), size() - 1);
            vStormnodes.erase(it);
            break;
        }
        ++it;
    }
}

std::string CStormnodeMan::ToString() const
{
    std::ostringstream info;

    info << "Stormnodes: " << (int)vStormnodes.size() <<
            ", peers who asked us for Stormnode list: " << (int)mAskedUsForStormnodeList.size() <<
            ", peers we asked for Stormnode list: " << (int)mWeAskedForStormnodeList.size() <<
            ", entries in Stormnode list we asked for: " << (int)mWeAskedForStormnodeListEntry.size() <<
            ", nSsqCount: " << (int)nSsqCount;

    return info.str();
}
