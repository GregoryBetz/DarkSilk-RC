// Copyright (c) 2014-2016 The Dash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/lexical_cast.hpp>
#include <boost/filesystem.hpp>

#include "anon/stormnode/stormnode-payments.h"
#include "anon/stormnode/stormnode-budget.h"
#include "anon/stormnode/stormnode-sync.h"
#include "anon/stormnode/stormnodeman.h"
#include "anon/sandstorm/sandstorm.h"
#include "util.h"
#include "sync.h"
#include "anon/stormnode/spork.h"
#include "addrman.h"

/** Object for who's going to get paid on which blocks */
CStormnodePayments stormnodePayments;

CCriticalSection cs_vecPayments;
CCriticalSection cs_mapStormnodeBlocks;
CCriticalSection cs_mapStormnodePayeeVotes;

//
// CStormnodePaymentDB
//

CStormnodePaymentDB::CStormnodePaymentDB()
{
    pathDB = GetDataDir() / "snpayments.dat";
    strMagicMessage = "StormnodePayments";
}

bool CStormnodePaymentDB::Write(const CStormnodePayments& objToSave)
{
    int64_t nStart = GetTimeMillis();

    // serialize, checksum data up to that point, then append checksum
    CDataStream ssObj(SER_DISK, CLIENT_VERSION);
    ssObj << strMagicMessage; // stormnode cache file specific magic message
    ssObj << FLATDATA(Params().MessageStart()); // network specific magic number
    ssObj << objToSave;
    uint256 hash = Hash(ssObj.begin(), ssObj.end());
    ssObj << hash;

    // open output file, and associate with CAutoFile
    FILE *file = fopen(pathDB.string().c_str(), "wb");
    CAutoFile fileout(file, SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("%s : Failed to open file %s", __func__, pathDB.string());

    // Write and commit header, data
    try {
        fileout << ssObj;
    }
    catch (std::exception &e) {
        return error("%s : Serialize or I/O error - %s", __func__, e.what());
    }
    fileout.fclose();

    LogPrintf("Written info to snpayments.dat  %dms\n", GetTimeMillis() - nStart);

    return true;
}

CStormnodePaymentDB::ReadResult CStormnodePaymentDB::Read(CStormnodePayments& objToLoad, bool fDryRun)
{

    int64_t nStart = GetTimeMillis();
    // open input file, and associate with CAutoFile
    FILE *file = fopen(pathDB.string().c_str(), "rb");
    CAutoFile filein(file, SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
    {
        error("%s : Failed to open file %s", __func__, pathDB.string());
        return FileError;
    }

    // use file size to size memory buffer
    int fileSize = boost::filesystem::file_size(pathDB);
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

    CDataStream ssObj(vchData, SER_DISK, CLIENT_VERSION);

    // verify stored checksum matches input data
    uint256 hashTmp = Hash(ssObj.begin(), ssObj.end());
    if (hashIn != hashTmp)
    {
        error("%s : Checksum mismatch, data corrupted", __func__);
        return IncorrectHash;
    }


    unsigned char pchMsgTmp[4];
    std::string strMagicMessageTmp;
    try {
        // de-serialize file header (stormnode cache file specific magic message) and ..
        ssObj >> strMagicMessageTmp;

        // ... verify the message matches predefined one
        if (strMagicMessage != strMagicMessageTmp)
        {
            error("%s : Invalid stormnode payement cache magic message", __func__);
            return IncorrectMagicMessage;
        }


        // de-serialize file header (network specific magic number) and ..
        ssObj >> FLATDATA(pchMsgTmp);

        // ... verify the network matches ours
        if (memcmp(pchMsgTmp, Params().MessageStart(), sizeof(pchMsgTmp)))
        {
            error("%s : Invalid network magic number", __func__);
            return IncorrectMagicNumber;
        }

        // de-serialize data into CStormnodePayments object
        ssObj >> objToLoad;
    }
    catch (std::exception &e) {
        objToLoad.Clear();
        error("%s : Deserialize or I/O error - %s", __func__, e.what());
        return IncorrectFormat;
    }

    LogPrintf("Loaded info from snpayments.dat  %dms\n", GetTimeMillis() - nStart);
    LogPrintf("  %s\n", objToLoad.ToString());
    if(!fDryRun) {
        LogPrintf("Stormnode payments manager - cleaning....\n");
        objToLoad.CleanPaymentList();
        LogPrintf("Stormnode payments manager - result:\n");
        LogPrintf("  %s\n", objToLoad.ToString());
    }

    return Ok;
}

void DumpStormnodePayments()
{
    int64_t nStart = GetTimeMillis();

    CStormnodePaymentDB paymentdb;
    CStormnodePayments tempPayments;

    LogPrintf("Verifying snpayments.dat format...\n");
    CStormnodePaymentDB::ReadResult readResult = paymentdb.Read(tempPayments, true);
    // there was an error and it was not an error on file opening => do not proceed
    if (readResult == CStormnodePaymentDB::FileError)
        LogPrintf("Missing budgets file - snpayments.dat, will try to recreate\n");
    else if (readResult != CStormnodePaymentDB::Ok)
    {
        LogPrintf("Error reading snpayments.dat: ");
        if(readResult == CStormnodePaymentDB::IncorrectFormat)
            LogPrintf("magic is ok but data has invalid format, will try to recreate\n");
        else
        {
            LogPrintf("file format is unknown or invalid, please fix it manually\n");
            return;
        }
    }
    LogPrintf("Writting info to snpayments.dat...\n");
    paymentdb.Write(stormnodePayments);

    LogPrintf("Budget dump finished  %dms\n", GetTimeMillis() - nStart);
}

bool IsBlockValueValid(const CBlock& block, CAmount nExpectedValue){

    int nHeight = 0;

    {
        LOCK(cs_main);
        if(!pindexBest) return true;
        if(pindexBest->GetBlockHash() == block.hashPrevBlock)
        {
            nHeight = pindexBest->nHeight+1;
        } else { //out of order
            BlockMap::iterator mi = mapBlockIndex.find(block.hashPrevBlock);
            if (mi != mapBlockIndex.end() && (*mi).second)
                nHeight = (*mi).second->nHeight+1;
        }
    }

    if(nHeight == 0){
        LogPrintf("IsBlockValueValid() : WARNING: Couldn't find previous block");
    }

    if(!stormnodeSync.IsSynced()) { //there is no budget data to use to check anything
        //super blocks will always be on these blocks, max 100 per budgeting
        if(nHeight % GetBudgetPaymentCycleBlocks() < 100){
            return true;
        } else {
            if(block.vtx[0].GetValueOut() > nExpectedValue) return false;
        }
    } else { // we're synced and have data so check the budget schedule

        //are these blocks even enabled
        if(!IsSporkActive(SPORK_13_ENABLE_SUPERBLOCKS)){
            return block.vtx[0].GetValueOut() <= nExpectedValue;
        }

        if(budget.IsBudgetPaymentBlock(nHeight)){
            //the value of the block is evaluated in CheckBlock
            return true;
        } else {
            if(block.vtx[0].GetValueOut() > nExpectedValue) return false;
        }
    }

    return true;
}

bool IsBlockPayeeValid(const CTransaction& txNew, int nBlockHeight)
{
    if(!stormnodeSync.IsSynced()) { //there is no budget data to use to check anything -- find the longest chain
        LogPrint("snpayments", "Client not synced, skipping block payee checks\n");
        return true;
    }

    //check if it's a budget block
    if(IsSporkActive(SPORK_13_ENABLE_SUPERBLOCKS)){
        if(budget.IsBudgetPaymentBlock(nBlockHeight)){
            if(budget.IsTransactionValid(txNew, nBlockHeight)){
                return true;
            } else {
                LogPrintf("Invalid budget payment detected %s\n", txNew.ToString().c_str());
                if(IsSporkActive(SPORK_9_STORMNODE_BUDGET_ENFORCEMENT)){
                    return false;
                } else {
                    LogPrintf("Budget enforcement is disabled, accepting block\n");
                    return true;
                }
            }
        }
    }

    //check for stormnode payee
    if(stormnodePayments.IsTransactionValid(txNew, nBlockHeight))
    {
        return true;
    } else {
        LogPrintf("Invalid sn payment detected %s\n", txNew.ToString().c_str());
        if(IsSporkActive(SPORK_8_STORMNODE_PAYMENT_ENFORCEMENT)){
            return false;
        } else {
            LogPrintf("Stormnode payment enforcement is disabled, accepting block\n");
            return true;
        }
    }

    return false;
}


void FillBlockPayee(CTransaction& txNew, CAmount nFees) //TODO (Amir): Use CMutableTransaction here
{
    if(!pindexBest) return;

    if(IsSporkActive(SPORK_13_ENABLE_SUPERBLOCKS) && budget.IsBudgetPaymentBlock(pindexBest->nHeight+1)){
        budget.FillBlockPayee(txNew, nFees);
    } else {
        stormnodePayments.FillBlockPayee(txNew, nFees);
    }
}

std::string GetRequiredPaymentsString(int nBlockHeight)
{
    if(IsSporkActive(SPORK_13_ENABLE_SUPERBLOCKS) && budget.IsBudgetPaymentBlock(nBlockHeight)){
        return budget.GetRequiredPaymentsString(nBlockHeight);
    } else {
        return stormnodePayments.GetRequiredPaymentsString(nBlockHeight);
    }
}

//TODO (Amir): Use CMutableTransaction.
void CStormnodePayments::FillBlockPayee(CTransaction& txNew, CAmount nFees)
{
    CBlockIndex* pindexPrev = pindexBest;
    if(!pindexPrev) return;

    bool hasPayment = true;
    CScript payee;

    //spork
    if(!stormnodePayments.GetBlockPayee(pindexPrev->nHeight+1, payee)){
        //no stormnode detected
        CStormnode* winningNode = snodeman.GetCurrentStormNode();
        if(winningNode){
            payee = GetScriptForDestination(winningNode->pubkey.GetID());
        } else {
            LogPrintf("CreateNewBlock: Failed to detect stormnode to pay\n");
            hasPayment = false;
        }
    }

    if(hasPayment){

        //txNew.vout.resize(2);

        txNew.vout[1].scriptPubKey = payee;
        //txNew.vout[1].nValue = stormnodePayment;

        //txNew.vout[0].nValue -= stormnodePayment;

        // Stormnode Payments
        CAmount blockValue = GetBlockValue(pindexPrev->nBits, pindexPrev->nHeight, nFees);
        CAmount stormnodePayment = GetStormnodePayment(pindexPrev->nHeight+1, blockValue);

        if(txNew.vout.size() == 4) // 2 stake outputs, stake was split, plus a stormnode payment
        {
            txNew.vout[1].nValue = stormnodePayment;
            blockValue -= stormnodePayment;
            txNew.vout[2].nValue = (blockValue / 2 / CENT) * CENT;
            txNew.vout[3].nValue = blockValue - txNew.vout[1].nValue;
        }
        else if(txNew.vout.size() == 3) // only 1 stake output, was not split, plus a stormnode payment
        {
            txNew.vout[1].nValue = stormnodePayment;
            blockValue -= stormnodePayment;
            txNew.vout[2].nValue = blockValue;
        }
        CTxDestination address1;
        ExtractDestination(payee, address1);
        CDarkSilkAddress address2(address1);

        LogPrintf("Stormnode payment to %s\n", address2.ToString().c_str());
    }
}

int CStormnodePayments::GetMinStormnodePaymentsProto() {
    return IsSporkActive(SPORK_10_STORMNODE_PAY_UPDATED_NODES)
            ? MIN_STORMNODE_PAYMENT_PROTO_VERSION_2
            : MIN_STORMNODE_PAYMENT_PROTO_VERSION_1;
}

void CStormnodePayments::ProcessMessageStormnodePayments(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{
    if(!stormnodeSync.IsBlockchainSynced()) return;

    if(fLiteMode) return; //disable all Sandstorm/Stormnode related functionality


    if (strCommand == "snget") { //Stormnode Payments Request Sync
        if(fLiteMode) return; //disable all Sandstorm/Stormnode related functionality

        int nCountNeeded;
        vRecv >> nCountNeeded;

        if(Params().NetworkID() == CChainParams::MAIN){
            if(pfrom->HasFulfilledRequest("snget")) {
                LogPrintf("snget - peer already asked me for the list\n");
                Misbehaving(pfrom->GetId(), 20);
                return;
            }
        }

        pfrom->FulfilledRequest("snget");
        stormnodePayments.Sync(pfrom, nCountNeeded);
        LogPrintf("snget - Sent Stormnode winners to %s\n", pfrom->addr.ToString().c_str());
    }
    else if (strCommand == "snw") { //Stormnode Payments Declare Winner
        //this is required in litemodef
        CStormnodePaymentWinner winner;
        vRecv >> winner;

        if(pfrom->nVersion < MIN_SNW_PEER_PROTO_VERSION) return;

        if(pindexBest == NULL) return;

        if(stormnodePayments.mapStormnodePayeeVotes.count(winner.GetHash())){
            LogPrint("snpayments", "snw - Already seen - %s bestHeight %d\n", winner.GetHash().ToString().c_str(), pindexBest->nHeight);
            stormnodeSync.AddedStormnodeWinner(winner.GetHash());
            return;
        }

        int nFirstBlock = pindexBest->nHeight - (snodeman.CountEnabled()*1.25);
        if(winner.nBlockHeight < nFirstBlock || winner.nBlockHeight > pindexBest->nHeight+20){
            LogPrint("snpayments", "snw - winner out of range - FirstBlock %d Height %d bestHeight %d\n", nFirstBlock, winner.nBlockHeight, pindexBest->nHeight);
            return;
        }

        std::string strError = "";
        if(!winner.IsValid(pfrom, strError)){
            if(strError != "") LogPrintf("snw - invalid message - %s\n", strError);
            return;
        }

        if(!stormnodePayments.CanVote(winner.vinStormnode.prevout, winner.nBlockHeight)){
            LogPrintf("snw - stormnode already voted - %s\n", winner.vinStormnode.prevout.ToStringShort());
            return;
        }

        if(!winner.SignatureValid()){
            LogPrintf("snw - invalid signature\n");
            if(stormnodeSync.IsSynced()) Misbehaving(pfrom->GetId(), 20);
            // it could just be a non-synced stormnode
            snodeman.AskForSN(pfrom, winner.vinStormnode);
            return;
        }

        CTxDestination address1;
        ExtractDestination(winner.payee, address1);
        CDarkSilkAddress address2(address1);

        LogPrint("snpayments", "snw - winning vote - Addr %s Height %d bestHeight %d - %s\n", address2.ToString().c_str(), winner.nBlockHeight, pindexBest->nHeight, winner.vinStormnode.prevout.ToStringShort());

        if(stormnodePayments.AddWinningStormnode(winner)){
            winner.Relay();
            stormnodeSync.AddedStormnodeWinner(winner.GetHash());
        }
    }
}

bool CStormnodePaymentWinner::Sign(CKey& keyStormnode, CPubKey& pubKeyStormnode)
{
    std::string errorMessage;
    std::string strStormNodeSignMessage;

    std::string strMessage =  vinStormnode.prevout.ToStringShort() +
                boost::lexical_cast<std::string>(nBlockHeight) +
                payee.ToString();

    if(!sandStormSigner.SignMessage(strMessage, errorMessage, vchSig, keyStormnode)) {
        LogPrintf("CStormnodePing::Sign() - Error: %s\n", errorMessage.c_str());
        return false;
    }

    if(!sandStormSigner.VerifyMessage(pubKeyStormnode, vchSig, strMessage, errorMessage)) {
        LogPrintf("CStormnodePing::Sign() - Error: %s\n", errorMessage.c_str());
        return false;
    }

    return true;
}

bool CStormnodePayments::GetBlockPayee(int nBlockHeight, CScript& payee)
{
    if(mapStormnodeBlocks.count(nBlockHeight)){
        return mapStormnodeBlocks[nBlockHeight].GetPayee(payee);
    }

    return false;
}

// Is this stormnode scheduled to get paid soon?
// -- Only look ahead up to 8 blocks to allow for propagation of the latest 2 winners
bool CStormnodePayments::IsScheduled(CStormnode& sn, int nNotBlockHeight)
{
    LOCK(cs_mapStormnodeBlocks);

    CBlockIndex* pindexPrev = pindexBest;
    if(pindexPrev == NULL) return false;

    CScript snpayee;
    snpayee = GetScriptForDestination(sn.pubkey.GetID());

    CScript payee;
    for(int64_t h = pindexPrev->nHeight; h <= pindexPrev->nHeight+8; h++){
        if(h == nNotBlockHeight) continue;
        if(mapStormnodeBlocks.count(h)){
            if(mapStormnodeBlocks[h].GetPayee(payee)){
                if(snpayee == payee) {
                    return true;
                }
            }
        }
    }

    return false;
}

bool CStormnodePayments::AddWinningStormnode(CStormnodePaymentWinner& winnerIn)
{
    uint256 blockHash = 0;
    if(!GetBlockHash(blockHash, winnerIn.nBlockHeight-100)) {
        return false;
    }

    {
        LOCK2(cs_mapStormnodePayeeVotes, cs_mapStormnodeBlocks);

        if(mapStormnodePayeeVotes.count(winnerIn.GetHash())){
           return false;
        }

        mapStormnodePayeeVotes[winnerIn.GetHash()] = winnerIn;

        if(!mapStormnodeBlocks.count(winnerIn.nBlockHeight)){
           CStormnodeBlockPayees blockPayees(winnerIn.nBlockHeight);
           mapStormnodeBlocks[winnerIn.nBlockHeight] = blockPayees;
        }
    }

    int n = 1;
    if(IsReferenceNode(winnerIn.vinStormnode)) n = 100;
    mapStormnodeBlocks[winnerIn.nBlockHeight].AddPayee(winnerIn.payee, n);

    return true;
}

bool CStormnodeBlockPayees::IsTransactionValid(const CTransaction& txNew)
{
    LOCK(cs_vecPayments);

    int nMaxSignatures = 0;
    std::string strPayeesPossible = "";

    CAmount stormnodePayment = GetStormnodePayment(nBlockHeight, txNew.GetValueOut());

    //require at least 6 signatures

    BOOST_FOREACH(CStormnodePayee& payee, vecPayments)
        if(payee.nVotes >= nMaxSignatures && payee.nVotes >= SNPAYMENTS_SIGNATURES_REQUIRED)
            nMaxSignatures = payee.nVotes;

    // if we don't have at least 6 signatures on a payee, approve whichever is the longest chain
    if(nMaxSignatures < SNPAYMENTS_SIGNATURES_REQUIRED) return true;

    BOOST_FOREACH(CStormnodePayee& payee, vecPayments)
    {
        bool found = false;
        BOOST_FOREACH(CTxOut out, txNew.vout){
            if(payee.scriptPubKey == out.scriptPubKey && stormnodePayment == out.nValue){
                found = true;
            }
        }

        if(payee.nVotes >= SNPAYMENTS_SIGNATURES_REQUIRED){
            if(found) return true;

            CTxDestination address1;
            ExtractDestination(payee.scriptPubKey, address1);
            CDarkSilkAddress address2(address1);

            if(strPayeesPossible == ""){
                strPayeesPossible += address2.ToString();
            } else {
                strPayeesPossible += "," + address2.ToString();
            }
        }
    }


    LogPrintf("CStormnodePayments::IsTransactionValid - Missing required payment - %s\n", strPayeesPossible.c_str());
    return false;
}

std::string CStormnodeBlockPayees::GetRequiredPaymentsString()
{
    LOCK(cs_vecPayments);

    std::string ret = "Unknown";

    BOOST_FOREACH(CStormnodePayee& payee, vecPayments)
    {
        CTxDestination address1;
        ExtractDestination(payee.scriptPubKey, address1);
        CDarkSilkAddress address2(address1);

        if(ret != "Unknown"){
            ret += ", " + address2.ToString() + ":" + boost::lexical_cast<std::string>(payee.nVotes);
        } else {
            ret = address2.ToString() + ":" + boost::lexical_cast<std::string>(payee.nVotes);
        }
    }

    return ret;
}

std::string CStormnodePayments::GetRequiredPaymentsString(int nBlockHeight)
{
    LOCK(cs_mapStormnodeBlocks);

    if(mapStormnodeBlocks.count(nBlockHeight)){
        return mapStormnodeBlocks[nBlockHeight].GetRequiredPaymentsString();
    }

    return "Unknown";
}

bool CStormnodePayments::IsTransactionValid(const CTransaction& txNew, int nBlockHeight)
{
    LOCK(cs_mapStormnodeBlocks);

    if(mapStormnodeBlocks.count(nBlockHeight)){
        return mapStormnodeBlocks[nBlockHeight].IsTransactionValid(txNew);
    }

    return true;
}

void CStormnodePayments::CleanPaymentList()
{
    LOCK2(cs_mapStormnodePayeeVotes, cs_mapStormnodeBlocks);

    if(pindexBest == NULL) return;

    //keep up to five cycles for historical sake
    int nLimit = std::max(int(snodeman.size()*1.25), 1000);

    std::map<uint256, CStormnodePaymentWinner>::iterator it = mapStormnodePayeeVotes.begin();
    while(it != mapStormnodePayeeVotes.end()) {
        CStormnodePaymentWinner winner = (*it).second;

        if(pindexBest->nHeight - winner.nBlockHeight > nLimit){
            LogPrint("snpayments", "CStormnodePayments::CleanPaymentList - Removing old Stormnode payment - block %d\n", winner.nBlockHeight);
            stormnodeSync.mapSeenSyncSNW.erase((*it).first);
            mapStormnodePayeeVotes.erase(it++);
            mapStormnodeBlocks.erase(winner.nBlockHeight);
        } else {
            ++it;
        }
    }
}

bool IsReferenceNode(CTxIn& vin)
{
    //reference node - hybrid mode
    if(vin.prevout.ToStringShort() == "099c01bea63abd1692f60806bb646fa1d288e2d049281225f17e499024084e28-0") return true; // mainnet //TODO (Amir): Change these.
    if(vin.prevout.ToStringShort() == "fbc16ae5229d6d99181802fd76a4feee5e7640164dcebc7f8feb04a7bea026f8-0") return true; // testnet
    if(vin.prevout.ToStringShort() == "e466f5d8beb4c2d22a314310dc58e0ea89505c95409754d0d68fb874952608cc-1") return true; // regtest

    return false;
}

bool CStormnodePaymentWinner::IsValid(CNode* pnode, std::string& strError)
{
    if(IsReferenceNode(vinStormnode)) return true;

    CStormnode* psn = snodeman.Find(vinStormnode);

    if(!psn)
    {
        strError = strprintf("Unknown Stormnode %s", vinStormnode.prevout.ToStringShort());
        LogPrintf ("CStormnodePaymentWinner::IsValid - %s\n", strError);
        snodeman.AskForSN(pnode, vinStormnode);
        return false;
    }

    if(psn->protocolVersion < MIN_SNW_PEER_PROTO_VERSION)
    {
        strError = strprintf("Stormnode protocol too old %d - req %d", psn->protocolVersion, MIN_SNW_PEER_PROTO_VERSION);
        LogPrintf ("CStormnodePaymentWinner::IsValid - %s\n", strError);
        return false;
    }

    int n = snodeman.GetStormnodeRank(vinStormnode, nBlockHeight-100, MIN_SNW_PEER_PROTO_VERSION);

    if(n > SNPAYMENTS_SIGNATURES_TOTAL)
    {
        //It's common to have stormnodes mistakenly think they are in the top 10
        // We don't want to print all of these messages, or punish them unless they're way off
        if(n > SNPAYMENTS_SIGNATURES_TOTAL*2)
        {
            strError = strprintf("Stormnode not in the top %d (%d)", SNPAYMENTS_SIGNATURES_TOTAL, n);
            LogPrintf("CStormnodePaymentWinner::IsValid - %s\n", strError);
            if(stormnodeSync.IsSynced()) Misbehaving(pnode->GetId(), 20);
        }
        return false;
    }

    return true;
}

bool CStormnodePayments::ProcessBlock(int nBlockHeight)
{
    if(!fStormNode) return false;

    //reference node - hybrid mode

    if(!IsReferenceNode(activeStormnode.vin)){
        int n = snodeman.GetStormnodeRank(activeStormnode.vin, nBlockHeight-100, MIN_SNW_PEER_PROTO_VERSION);

        if(n == -1)
        {
            LogPrint("snpayments", "CStormnodePayments::ProcessBlock - Unknown Stormnode\n");
            return false;
        }

        if(n > SNPAYMENTS_SIGNATURES_TOTAL)
        {
            LogPrint("snpayments", "CStormnodePayments::ProcessBlock - Stormnode not in the top %d (%d)\n", SNPAYMENTS_SIGNATURES_TOTAL, n);
            return false;
        }
    }

    if(nBlockHeight <= nLastBlockHeight) return false;

    CStormnodePaymentWinner newWinner(activeStormnode.vin);

    if(budget.IsBudgetPaymentBlock(nBlockHeight)){
        //is budget payment block -- handled by the budgeting software
    } else {
        LogPrintf("CStormnodePayments::ProcessBlock() Start nHeight %d - vin %s. \n", nBlockHeight, activeStormnode.vin.ToString().c_str());

        // pay to the oldest SN that still had no payment but its input is old enough and it was active long enough
        int nCount = 0;
        CStormnode *psn = snodeman.GetNextStormnodeInQueueForPayment(nBlockHeight, true, nCount); //TODO (Amir): this needs stormnodeman update.

        if(psn != NULL)
        {
            LogPrintf("CStormnodePayments::ProcessBlock() Found by FindOldestNotInVec \n");

            newWinner.nBlockHeight = nBlockHeight;

            CScript payee = GetScriptForDestination(psn->pubkey.GetID());
            newWinner.AddPayee(payee);

            CTxDestination address1;
            ExtractDestination(payee, address1);
            CDarkSilkAddress address2(address1);

            LogPrintf("CStormnodePayments::ProcessBlock() Winner payee %s nHeight %d. \n", address2.ToString().c_str(), newWinner.nBlockHeight);
        } else {
            LogPrintf("CStormnodePayments::ProcessBlock() Failed to find stormnode to pay\n");
        }

    }

    std::string errorMessage;
    CPubKey pubKeyStormnode;
    CKey keyStormnode;

    if(!sandStormSigner.SetKey(strStormNodePrivKey, errorMessage, keyStormnode, pubKeyStormnode))
    {
        LogPrintf("CStormnodePayments::ProcessBlock() - Error upon calling SetKey: %s\n", errorMessage.c_str());
        return false;
    }

    LogPrintf("CStormnodePayments::ProcessBlock() - Signing Winner\n");
    if(newWinner.Sign(keyStormnode, pubKeyStormnode))
    {
        LogPrintf("CStormnodePayments::ProcessBlock() - AddWinningStormnode\n");

        if(AddWinningStormnode(newWinner))
        {
            newWinner.Relay();
            nLastBlockHeight = nBlockHeight;
            return true;
        }
    }

    return false;
}

void CStormnodePaymentWinner::Relay()
{
    CInv inv(MSG_STORMNODE_WINNER, GetHash());
    RelayInv(inv);
}

bool CStormnodePaymentWinner::SignatureValid()
{

    CStormnode* psn = snodeman.Find(vinStormnode);

    if(psn != NULL)
    {
        std::string strMessage =  vinStormnode.prevout.ToStringShort() +
                    boost::lexical_cast<std::string>(nBlockHeight) +
                    payee.ToString();

        std::string errorMessage = "";
        if(!sandStormSigner.VerifyMessage(psn->pubkey2, vchSig, strMessage, errorMessage)){
            return error("CStormnodePaymentWinner::SignatureValid() - Got bad Stormnode address signature %s \n", vinStormnode.ToString().c_str());
        }

        return true;
    }

    return false;
}

void CStormnodePayments::Sync(CNode* node, int nCountNeeded)
{
    LOCK(cs_mapStormnodePayeeVotes);

    if(pindexBest == NULL) return;

    int nCount = (snodeman.CountEnabled()*1.25);
    if(nCountNeeded > nCount) nCountNeeded = nCount;

    int nInvCount = 0;
    std::map<uint256, CStormnodePaymentWinner>::iterator it = mapStormnodePayeeVotes.begin();
    while(it != mapStormnodePayeeVotes.end()) {
        CStormnodePaymentWinner winner = (*it).second;
        if(winner.nBlockHeight >= pindexBest->nHeight-nCountNeeded && winner.nBlockHeight <= pindexBest->nHeight + 20) {
            node->PushInventory(CInv(MSG_STORMNODE_WINNER, winner.GetHash()));
            nInvCount++;
        }
        ++it;
    }
    node->PushMessage("ssc", STORMNODE_SYNC_SNW, nInvCount);
}

std::string CStormnodePayments::ToString() const
{
    std::ostringstream info;

    info << "Votes: " << (int)mapStormnodePayeeVotes.size() <<
            ", Blocks: " << (int)mapStormnodeBlocks.size();

    return info.str();
}



int CStormnodePayments::GetOldestBlock()
{
    LOCK(cs_mapStormnodeBlocks);

    int nOldestBlock = std::numeric_limits<int>::max();

    std::map<int, CStormnodeBlockPayees>::iterator it = mapStormnodeBlocks.begin();
    while(it != mapStormnodeBlocks.end()) {
        if((*it).first < nOldestBlock) {
            nOldestBlock = (*it).first;
        }
        it++;
    }

    return nOldestBlock;
}



int CStormnodePayments::GetNewestBlock()
{
    LOCK(cs_mapStormnodeBlocks);

    int nNewestBlock = 0;

    std::map<int, CStormnodeBlockPayees>::iterator it = mapStormnodeBlocks.begin();
    while(it != mapStormnodeBlocks.end()) {
        if((*it).first > nNewestBlock) {
            nNewestBlock = (*it).first;
        }
        it++;
    }

    return nNewestBlock;
}
