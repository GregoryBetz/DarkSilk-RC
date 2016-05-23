// Copyright (c) 2014-2016 The Dash Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "anon/stormnode/activestormnode.h"
#include "addrman.h"
#include "protocol.h"
#include "anon/stormnode/stormnode-sync.h"
#include "anon/stormnode/stormnodeconfig.h"
#include "anon/stormnode/stormnodeman.h"
#include "anon/stormnode/spork.h"
#include "init.h"

//
// Bootup the Stormnode, look for a 10,000 DRKSLK input and register on the network
//
void CActiveStormnode::ManageStatus()
{
    std::string errorMessage;

    if(!fStormNode) return;

    if (fDebug) LogPrintf("CActiveStormnode::ManageStatus() - Begin\n");

    //need correct blocks to send ping
    if(!stormnodeSync.IsBlockchainSynced()) {
        status = ACTIVE_STORMNODE_SYNC_IN_PROCESS;
        LogPrintf("CActiveStormnode::ManageStatus() - %s\n", GetStatus());
        return;
    }

    if(status == ACTIVE_STORMNODE_SYNC_IN_PROCESS) status = ACTIVE_STORMNODE_INITIAL;

    if(status == ACTIVE_STORMNODE_INITIAL) {
        CStormnode *psn;
        psn = snodeman.Find(pubKeyStormnode);
        if(psn != NULL) {
            psn->Check();
            if((psn->IsEnabled() || psn->IsPreEnabled()) && psn->protocolVersion == PROTOCOL_VERSION)
                    EnableHotColdStormNode(psn->vin, psn->addr);
        }
    }

    if(status != ACTIVE_STORMNODE_STARTED) {

        // Set defaults
        status = ACTIVE_STORMNODE_NOT_CAPABLE;
        notCapableReason = "";

        if(pwalletMain->IsLocked()){
            notCapableReason = "Wallet is locked.";
            LogPrintf("CActiveStormnode::ManageStatus() - not capable: %s\n", notCapableReason);
            return;
        }

        if(pwalletMain->GetBalance() == 0){
            notCapableReason = "Hot node, waiting for remote activation.";
            LogPrintf("CActiveStormnode::ManageStatus() - not capable: %s\n", notCapableReason);
            return;
        }

        if(strStormNodeAddr.empty()) {
            if(!GetLocal(service)) {
                notCapableReason = "Can't detect external address. Please use the stormnodeaddr configuration option.";
                LogPrintf("CActiveStormnode::ManageStatus() - not capable: %s\n", notCapableReason);
                return;
            }
        } else {
            service = CService(strStormNodeAddr, true);
        }

        if(Params().NetworkID() == CChainParams::MAIN) {
            if(service.GetPort() != 31000) {
                notCapableReason = strprintf("Invalid port: %u - only 31000 is supported on mainnet.", service.GetPort());
                LogPrintf("CActiveStormnode::ManageStatus() - not capable: %s\n", notCapableReason);
                return;
            }
        } else if(service.GetPort() == 31000) {
            notCapableReason = strprintf("Invalid port: %u - 31000 is only supported on mainnet.", service.GetPort());
            LogPrintf("CActiveStormnode::ManageStatus() - not capable: %s\n", notCapableReason);
            return;
        }

        LogPrintf("CActiveStormnode::ManageStatus() - Checking inbound connection to '%s'\n", service.ToString());

        CNode *pnode = ConnectNode((CAddress)service, NULL, false);
        if(!pnode){
            notCapableReason = "Could not connect to " + service.ToString();
            LogPrintf("CActiveStormnode::ManageStatus() - not capable: %s\n", notCapableReason);
            return;
        }
        pnode->Release();

        // Choose coins to use
        CPubKey pubKeyCollateralAddress;
        CKey keyCollateralAddress;

        if(GetStormNodeVin(vin, pubKeyCollateralAddress, keyCollateralAddress)) {

            if(GetInputAge(vin) < STORMNODE_MIN_CONFIRMATIONS){
                status = ACTIVE_STORMNODE_INPUT_TOO_NEW;
                notCapableReason = strprintf("%s - %d confirmations", GetStatus(), GetInputAge(vin));
                LogPrintf("CActiveStormnode::ManageStatus() - %s\n", notCapableReason);
                return;
            }

            LOCK(pwalletMain->cs_wallet);
            pwalletMain->LockCoin(vin.prevout);

            // send to all nodes
            CPubKey pubKeyStormnode;
            CKey keyStormnode;

            if(!sandStormSigner.SetKey(strStormNodePrivKey, errorMessage, keyStormnode, pubKeyStormnode))
            {
                notCapableReason = "Error upon calling SetKey: " + errorMessage;
                LogPrintf("Register::ManageStatus() - %s\n", notCapableReason);
                return;
            }

            CStormnodeBroadcast snb;
            if(!CreateBroadcast(vin, service, keyCollateralAddress, pubKeyCollateralAddress, keyStormnode, pubKeyStormnode, errorMessage, snb)) {
                notCapableReason = "Error on Register: " + errorMessage;
                LogPrintf("Register::ManageStatus() - %s\n", notCapableReason);
                return;
            }

            // update to stormnode list
            LogPrintf("CActiveStormnode::ManageStatus() - Update Stormnode List\n");
            snodeman.UpdateStormnodeList(snb);

            // send to all peers
            LogPrintf("CActiveStormnode::ManageStatus() - Relay broadcast vin = %s\n", vin.ToString());
            snb.Relay();

            LogPrintf("CActiveStormnode::ManageStatus() - Is capable Stormnode!\n");
            status = ACTIVE_STORMNODE_STARTED;

            return;
        } else {
            notCapableReason = "Could not find suitable coins!";
            LogPrintf("CActiveStormnode::ManageStatus() - %s\n", notCapableReason);
            return;
        }
    }

    //send to all peers
    if(!SendStormnodePing(errorMessage)) {
        LogPrintf("CActiveStormnode::ManageStatus() - Error on Ping: %s\n", errorMessage);
    }
}

std::string CActiveStormnode::GetStatus() {
    switch (status) {
    case ACTIVE_STORMNODE_INITIAL: return "Node just started, not yet activated";
    case ACTIVE_STORMNODE_SYNC_IN_PROCESS: return "Sync in progress. Must wait until sync is complete to start Stormnode";
    case ACTIVE_STORMNODE_INPUT_TOO_NEW: return strprintf("Stormnode input must have at least %d confirmations", STORMNODE_MIN_CONFIRMATIONS);
    case ACTIVE_STORMNODE_NOT_CAPABLE: return "Not capable stormnode: " + notCapableReason;
    case ACTIVE_STORMNODE_STARTED: return "Stormnode successfully started";
    default: return "unknown";
    }
}

bool CActiveStormnode::SendStormnodePing(std::string& errorMessage) {
    if(status != ACTIVE_STORMNODE_STARTED) {
        errorMessage = "Stormnode is not in a running status";
        return false;
    }

    CPubKey pubKeyStormnode;
    CKey keyStormnode;

    if(!sandStormSigner.SetKey(strStormNodePrivKey, errorMessage, keyStormnode, pubKeyStormnode))
    {
        errorMessage = strprintf("Error upon calling SetKey: %s\n", errorMessage);
        return false;
    }

    LogPrintf("CActiveStormnode::SendStormnodePing() - Relay Stormnode Ping vin = %s\n", vin.ToString());

    CStormnodePing snp(vin);
    if(!snp.Sign(keyStormnode, pubKeyStormnode))
    {
        errorMessage = "Couldn't sign Stormnode Ping";
        return false;
    }

    // Update lastPing for our stormnode in Stormnode list
    CStormnode* psn = snodeman.Find(vin);
    if(psn != NULL)
    {
        if(psn->IsPingedWithin(STORMNODE_PING_SECONDS, snp.sigTime)){
            errorMessage = "Too early to send Stormnode Ping";
            return false;
        }

        psn->lastPing = snp;
        snodeman.mapSeenStormnodePing.insert(make_pair(snp.GetHash(), snp));

        //snodeman.mapSeenStormnodeBroadcast.lastPing is probably outdated, so we'll update it
        CStormnodeBroadcast snb(*psn);
        uint256 hash = snb.GetHash();
        if(snodeman.mapSeenStormnodeBroadcast.count(hash)) snodeman.mapSeenStormnodeBroadcast[hash].lastPing = snp;

        snp.Relay();

        return true;
    }
    else
    {
        // Seems like we are trying to send a ping while the Stormnode is not registered in the network
        errorMessage = "Sandstorm Stormnode List doesn't include our Stormnode, shutting down Stormnode pinging service! " + vin.ToString();
        status = ACTIVE_STORMNODE_NOT_CAPABLE;
        notCapableReason = errorMessage;
        return false;
    }

}

bool CActiveStormnode::CreateBroadcast(std::string strService, std::string strKeyStormnode, std::string strTxHash, std::string strOutputIndex, std::string& errorMessage, CStormnodeBroadcast &snb, bool fOffline) {
    CTxIn vin;
    CPubKey pubKeyCollateralAddress;
    CKey keyCollateralAddress;
    CPubKey pubKeyStormnode;
    CKey keyStormnode;

    //need correct blocks to send ping
    if(!fOffline && !stormnodeSync.IsBlockchainSynced()) {
        errorMessage = "Sync in progress. Must wait until sync is complete to start Stormnode";
        LogPrintf("CActiveStormnode::CreateBroadcast() - %s\n", errorMessage);
        return false;
    }

    if(!sandStormSigner.SetKey(strKeyStormnode, errorMessage, keyStormnode, pubKeyStormnode))
    {
        errorMessage = strprintf("Can't find keys for stormnode %s - %s", strService, errorMessage);
        LogPrintf("CActiveStormnode::CreateBroadcast() - %s\n", errorMessage);
        return false;
    }

    if(!GetStormNodeVin(vin, pubKeyCollateralAddress, keyCollateralAddress, strTxHash, strOutputIndex)) {
        errorMessage = strprintf("Could not allocate vin %s:%s for stormnode %s", strTxHash, strOutputIndex, strService);
        LogPrintf("CActiveStormnode::CreateBroadcast() - %s\n", errorMessage);
        return false;
    }

    CService service = CService(strService);
    if(Params().NetworkID() == CChainParams::MAIN) {
        if(service.GetPort() != 31000) {
            errorMessage = strprintf("Invalid port %u for stormnode %s - only 31000 is supported on mainnet.", service.GetPort(), strService);
            LogPrintf("CActiveStormnode::CreateBroadcast() - %s\n", errorMessage);
            return false;
        }
    } else if(service.GetPort() == 31000) {
        errorMessage = strprintf("Invalid port %u for stormnode %s - 31000 is only supported on mainnet.", service.GetPort(), strService);
        LogPrintf("CActiveStormnode::CreateBroadcast() - %s\n", errorMessage);
        return false;
    }

    addrman.Add(CAddress(service), CNetAddr("127.0.0.1"), 2*60*60);

    return CreateBroadcast(vin, CService(strService, true), keyCollateralAddress, pubKeyCollateralAddress, keyStormnode, pubKeyStormnode, errorMessage, snb);
}


bool CActiveStormnode::CreateBroadcast(CTxIn vin, CService service, CKey keyCollateralAddress, CPubKey pubKeyCollateralAddress, CKey keyStormnode, CPubKey pubKeyStormnode, std::string &errorMessage, CStormnodeBroadcast &snb) {
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    CStormnodePing snp(vin);
    if(!snp.Sign(keyStormnode, pubKeyStormnode)){
        errorMessage = strprintf("Failed to sign ping, vin: %s", vin.ToString());
        LogPrintf("CActiveStormnode::CreateBroadcast() -  %s\n", errorMessage);
        snb = CStormnodeBroadcast();
        return false;
    }
    snodeman.mapSeenStormnodePing.insert(make_pair(snp.GetHash(), snp));

    snb = CStormnodeBroadcast(service, vin, pubKeyCollateralAddress, pubKeyStormnode, PROTOCOL_VERSION);
    snb.lastPing = snp;
    if(!snb.Sign(keyCollateralAddress)){
        errorMessage = strprintf("Failed to sign broadcast, vin: %s", vin.ToString());
        LogPrintf("CActiveStormnode::CreateBroadcast() - %s\n", errorMessage);
        snb = CStormnodeBroadcast();
        return false;
    }

    return true;
}

bool CActiveStormnode::GetStormNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey) {
    return GetStormNodeVin(vin, pubkey, secretKey, "", "");
}

bool CActiveStormnode::GetStormNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey, std::string strTxHash, std::string strOutputIndex) {
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    // Find possible candidates
    TRY_LOCK(pwalletMain->cs_wallet, fWallet);
    if(!fWallet) return false;

    vector<COutput> possibleCoins = SelectCoinsStormnode();
    COutput *selectedOutput;

    // Find the vin
    if(!strTxHash.empty()) {
        // Let's find it
        uint256 txHash(strTxHash);
        int outputIndex = atoi(strOutputIndex.c_str());
        bool found = false;
        BOOST_FOREACH(COutput& out, possibleCoins) {
            if(out.tx->GetHash() == txHash && out.i == outputIndex)
            {
                selectedOutput = &out;
                found = true;
                break;
            }
        }
        if(!found) {
            LogPrintf("CActiveStormnode::GetStormNodeVin - Could not locate valid vin\n");
            return false;
        }
    } else {
        // No output specified,  Select the first one
        if(possibleCoins.size() > 0) {
            selectedOutput = &possibleCoins[0];
        } else {
            LogPrintf("CActiveStormnode::GetStormNodeVin - Could not locate specified vin from possible list\n");
            return false;
        }
    }

    // At this point we have a selected output, retrieve the associated info
    return GetVinFromOutput(*selectedOutput, vin, pubkey, secretKey);
}


// Extract Stormnode vin information from output
bool CActiveStormnode::GetVinFromOutput(COutput out, CTxIn& vin, CPubKey& pubkey, CKey& secretKey) {
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    CScript pubScript;

    vin = CTxIn(out.tx->GetHash(),out.i);
    pubScript = out.tx->vout[out.i].scriptPubKey; // the inputs PubKey

    CTxDestination address1;
    ExtractDestination(pubScript, address1);
    CDarkSilkAddress address2(address1);

    CKeyID keyID;
    if (!address2.GetKeyID(keyID)) {
        LogPrintf("CActiveStormnode::GetStormNodeVin - Address does not refer to a key\n");
        return false;
    }

    if (!pwalletMain->GetKey(keyID, secretKey)) {
        LogPrintf ("CActiveStormnode::GetStormNodeVin - Private key for address is not known\n");
        return false;
    }

    pubkey = secretKey.GetPubKey();
    return true;
}

// get all possible outputs for running Stormnode
vector<COutput> CActiveStormnode::SelectCoinsStormnode()
{
    vector<COutput> vCoins;
    vector<COutput> filteredCoins;
    vector<COutPoint> confLockedCoins;

    // Temporary unlock SN coins from stormnode.conf
    if(GetBoolArg("-snconflock", true)) {
        uint256 snTxHash;
        BOOST_FOREACH(CStormnodeConfig::CStormnodeEntry sne, stormnodeConfig.getEntries()) {
            snTxHash.SetHex(sne.getTxHash());
            COutPoint outpoint = COutPoint(snTxHash, atoi(sne.getOutputIndex().c_str()));
            confLockedCoins.push_back(outpoint);
            pwalletMain->UnlockCoin(outpoint);
        }
    }

    // Retrieve all possible outputs
    pwalletMain->AvailableCoins(vCoins);

    // Lock SN coins from stormnode.conf back if they where temporary unlocked
    if(!confLockedCoins.empty()) {
        BOOST_FOREACH(COutPoint outpoint, confLockedCoins)
            pwalletMain->LockCoin(outpoint);
    }

    // Filter
    BOOST_FOREACH(const COutput& out, vCoins)
    {
        if(out.tx->vout[out.i].nValue == 10000*COIN) { //exactly
            filteredCoins.push_back(out);
        }
    }
    return filteredCoins;
}

// when starting a Stormnode, this can enable to run as a hot wallet with no funds
bool CActiveStormnode::EnableHotColdStormNode(CTxIn& newVin, CService& newService)
{
    if(!fStormNode) return false;

    status = ACTIVE_STORMNODE_STARTED;

    //The values below are needed for signing snping messages going forward
    vin = newVin;
    service = newService;

    LogPrintf("CActiveStormnode::EnableHotColdStormNode() - Enabled! You may shut down the cold daemon.\n");

    return true;
}
