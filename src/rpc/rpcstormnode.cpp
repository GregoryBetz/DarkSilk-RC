// Copyright (c) 2014-2016 The Dash Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <fstream>
#include <iomanip>

#include "main.h"
#include "wallet/db.h"
#include "init.h"
#include "wallet/wallet.h"
#include "anon/stormnode/activestormnode.h"
#include "anon/stormnode/stormnode-budget.h"
#include "anon/stormnode/stormnode-payments.h"
#include "anon/stormnode/stormnode-sync.h"
#include "anon/stormnode/stormnodeconfig.h"
#include "anon/stormnode/stormnodeman.h"
#include "anon/sandstorm/sandstorm.h"
#include "rpc/rpcserver.h"

using namespace json_spirit;

Value sandstorm(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "sandstorm \"command\"\n"
            "\nArguments:\n"
            "1. \"command\"        (string or set of strings, required) The command to execute\n"
            "\nAvailable commands:\n"
            "  start       - Start mixing\n"
            "  stop        - Stop mixing\n"
            "  reset       - Reset mixing\n"
            "  status      - Print mixing status\n"
            + HelpRequiringPassphrase());

    if(params[0].get_str() == "start"){
        if (pwalletMain->IsLocked())
            throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

        if(fStormNode)
            return "Mixing is not supported from stormnodes";

        fEnableSandstorm = true;
        bool result = sandStormPool.DoAutomaticDenominating();
//        fEnableSandstorm = result;
        return "Mixing " + (result ? "started successfully" : ("start failed: " + sandStormPool.GetStatus() + ", will retry"));
    }

    if(params[0].get_str() == "stop"){
        fEnableSandstorm = false;
        return "Mixing was stopped";
    }

    if(params[0].get_str() == "reset"){
        sandStormPool.Reset();
        return "Mixing was reset";
    }

    if(params[0].get_str() == "status"){
        return "Mixing status: " + sandStormPool.GetStatus();
    }

    return "Unknown command, please see \"help sandstorm\"";
}


Value getpoolinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getpoolinfo\n"
            "Returns an object containing anonymous pool-related information.");

    Object obj;
    if (sandStormPool.pSubmittedToStormnode)
        obj.push_back(Pair("stormnode",        sandStormPool.pSubmittedToStormnode->addr.ToString()));
    obj.push_back(Pair("queue",                 (int64_t)vecSandstormQueue.size()));
    obj.push_back(Pair("state",                 sandStormPool.GetState()));
    obj.push_back(Pair("entries",               sandStormPool.GetEntriesCount()));
    obj.push_back(Pair("entries_accepted",      sandStormPool.GetCountEntriesAccepted()));
    return obj;
}


Value stormnode(const Array& params, bool fHelp)
{
    string strCommand;
    if (params.size() >= 1)
        strCommand = params[0].get_str();

    if (fHelp  ||
        (strCommand != "start" && strCommand != "start-alias" && strCommand != "start-many" && strCommand != "start-all" && strCommand != "start-missing" &&
         strCommand != "start-disabled" && strCommand != "list" && strCommand != "list-conf" && strCommand != "count"  && strCommand != "enforce" &&
        strCommand != "debug" && strCommand != "current" && strCommand != "winners" && strCommand != "genkey" && strCommand != "connect" &&
        strCommand != "outputs" && strCommand != "status" && strCommand != "calcscore"))
        throw runtime_error(
                "stormnode \"command\"... ( \"passphrase\" )\n"
                "Set of commands to execute stormnode related actions\n"
                "\nArguments:\n"
                "1. \"command\"        (string or set of strings, required) The command to execute\n"
                "2. \"passphrase\"     (string, optional) The wallet passphrase\n"
                "\nAvailable commands:\n"
                "  count        - Print number of all known stormnodes (optional: 'ds', 'enabled', 'all', 'qualify')\n"
                "  current      - Print info on current stormnode winner\n"
                "  debug        - Print stormnode status\n"
                "  genkey       - Generate new stormnodeprivkey\n"
                "  enforce      - Enforce stormnode payments\n"
                "  outputs      - Print stormnode compatible outputs\n"
                "  start        - Start local Hot stormnode configured in darksilk.conf\n"
                "  start-alias  - Start single remote stormnode by assigned alias configured in stormnode.conf\n"
                "  start-<mode> - Start remote stormnodes configured in stormnode.conf (<mode>: 'all', 'missing', 'disabled')\n"
                "  status       - Print stormnode status information\n"
                "  list         - Print list of all known stormnodes (see stormnodelist for more info)\n"
                "  list-conf    - Print stormnode.conf in JSON format\n"
                "  winners      - Print list of stormnode winners\n"
                );

    if (strCommand == "list")
    {
        Array newParams(params.size() - 1);
        std::copy(params.begin() + 1, params.end(), newParams.begin());
        return stormnodelist(newParams, fHelp);
    }

    if (strCommand == "budget")
    {
        return "Show budgets";
    }

    if(strCommand == "connect")
    {
        std::string strAddress = "";
        if (params.size() == 2){
            strAddress = params[1].get_str();
        } else {
            throw runtime_error("Stormnode address required\n");
        }

        CService addr = CService(strAddress);

        CNode *pnode = ConnectNode((CAddress)addr, NULL, false);
        if(pnode){
            pnode->Release();
            return "successfully connected";
        } else {
            throw runtime_error("error connecting\n");
        }
    }

    if (strCommand == "count")
    {
        if (params.size() > 2){
            throw runtime_error("too many parameters\n");
        }
        if (params.size() == 2)
        {
            int nCount = 0;

            {
                LOCK(cs_main);
                if(pindexBest)
                    snodeman.GetNextStormnodeInQueueForPayment(pindexBest->nHeight, true, nCount);
            }

            if(params[1] == "ds") return snodeman.CountEnabled(MIN_POOL_PEER_PROTO_VERSION);
            if(params[1] == "enabled") return snodeman.CountEnabled();
            if(params[1] == "qualify") return nCount;
            if(params[1] == "all") return strprintf("Total: %d (DS Compatible: %d / Enabled: %d / Qualify: %d)",
                                                    snodeman.size(),
                                                    snodeman.CountEnabled(MIN_POOL_PEER_PROTO_VERSION),
                                                    snodeman.CountEnabled(),
                                                    nCount);
        }
        return snodeman.size();
    }

    if (strCommand == "current")
    {   
        int nCount = 0;
        LOCK(cs_main);
        CStormnode* winner = NULL;
        if(pindexBest)
            winner = snodeman.GetNextStormnodeInQueueForPayment(pindexBest->nHeight - 100, true, nCount);
        if(winner) {
            Object obj;

            obj.push_back(Pair("IP:port",       winner->addr.ToString()));
            obj.push_back(Pair("protocol",      (int64_t)winner->protocolVersion));
            obj.push_back(Pair("vin",           winner->vin.prevout.ToStringShort()));
            obj.push_back(Pair("pubkey",        CDarkSilkAddress(winner->pubkey.GetID()).ToString()));
            obj.push_back(Pair("lastseen",      (winner->lastPing == CStormnodePing()) ? winner->sigTime :
                                                        winner->lastPing.sigTime));
            obj.push_back(Pair("activeseconds", (winner->lastPing == CStormnodePing()) ? 0 :
                                                        (winner->lastPing.sigTime - winner->sigTime)));
            return obj;
        }

        return "unknown";
    }

    if (strCommand == "debug")
    {
        if(activeStormnode.status != ACTIVE_STORMNODE_INITIAL || !stormnodeSync.IsBlockchainSynced())
            return activeStormnode.GetStatus();

        CTxIn vin = CTxIn();
        CPubKey pubkey = CScript();
        CKey key;
        bool found = activeStormnode.GetStormNodeVin(vin, pubkey, key);
        if(!found){
            throw runtime_error("Missing stormnode input, please look at the documentation for instructions on stormnode creation\n");
        } else {
            return activeStormnode.GetStatus();
        }
    }

    if(strCommand == "enforce")
    {
        return (uint64_t)enforceStormnodePaymentsTime;
    }

    if (strCommand == "start")
    {
        if(!fStormNode) throw runtime_error("you must set stormnode=1 in the configuration\n");

        if(pwalletMain->IsLocked()) {
            SecureString strWalletPass;
            strWalletPass.reserve(100);

            if (params.size() == 2){
                strWalletPass = params[1].get_str().c_str();
            } else {
                throw runtime_error("Your wallet is locked, passphrase is required\n");
            }

            if(!pwalletMain->Unlock(strWalletPass)){
                throw runtime_error("incorrect passphrase\n");
            }
        }

        if(activeStormnode.status != ACTIVE_STORMNODE_STARTED){
            activeStormnode.status = ACTIVE_STORMNODE_INITIAL; // TODO: consider better way
            activeStormnode.ManageStatus();
            pwalletMain->Lock();
        }

        return activeStormnode.GetStatus();
    }

    if (strCommand == "start-alias")
    {
        if (params.size() < 2){
            throw runtime_error("command needs at least 2 parameters\n");
        }

        std::string alias = params[1].get_str();

        if(pwalletMain->IsLocked()) {
            SecureString strWalletPass;
            strWalletPass.reserve(100);

            if (params.size() == 3){
                strWalletPass = params[2].get_str().c_str();
            } else {
                throw runtime_error("Your wallet is locked, passphrase is required\n");
            }

            if(!pwalletMain->Unlock(strWalletPass)){
                throw runtime_error("incorrect passphrase\n");
            }
        }

        bool found = false;

        Object statusObj;
        statusObj.push_back(Pair("alias", alias));

        BOOST_FOREACH(CStormnodeConfig::CStormnodeEntry sne, stormnodeConfig.getEntries()) {
            if(sne.getAlias() == alias) {
                found = true;
                std::string errorMessage;
                CStormnodeBroadcast snb;

                bool result = activeStormnode.CreateBroadcast(sne.getIp(), sne.getPrivKey(), sne.getTxHash(), sne.getOutputIndex(), errorMessage, snb);

                statusObj.push_back(Pair("result", result ? "successful" : "failed"));
                if(result) {
                    snodeman.UpdateStormnodeList(snb);
                    snb.Relay();
                } else {
                    statusObj.push_back(Pair("errorMessage", errorMessage));
                }
                break;
            }
        }

        if(!found) {
            statusObj.push_back(Pair("result", "failed"));
            statusObj.push_back(Pair("errorMessage", "could not find alias in config. Verify with list-conf."));
        }

        pwalletMain->Lock();
        return statusObj;

    }

    if (strCommand == "start-many" || strCommand == "start-all" || strCommand == "start-missing" || strCommand == "start-disabled")
    {
        if(pwalletMain->IsLocked()) {
            SecureString strWalletPass;
            strWalletPass.reserve(100);

            if (params.size() == 2){
                strWalletPass = params[1].get_str().c_str();
            } else {
                throw runtime_error("Your wallet is locked, passphrase is required\n");
            }

            if(!pwalletMain->Unlock(strWalletPass)){
                throw runtime_error("incorrect passphrase\n");
            }
        }

        if((strCommand == "start-missing" || strCommand == "start-disabled") &&
         (stormnodeSync.RequestedStormnodeAssets <= STORMNODE_SYNC_LIST ||
          stormnodeSync.RequestedStormnodeAssets == STORMNODE_SYNC_FAILED)) {
            throw runtime_error("You can't use this command until stormnode list is synced\n");
        }

        std::vector<CStormnodeConfig::CStormnodeEntry> snEntries;
        snEntries = stormnodeConfig.getEntries();

        int successful = 0;
        int failed = 0;

        Object resultsObj;

        BOOST_FOREACH(CStormnodeConfig::CStormnodeEntry sne, stormnodeConfig.getEntries()) {
            std::string errorMessage;

            CTxIn vin = CTxIn(uint256(sne.getTxHash()), uint32_t(atoi(sne.getOutputIndex().c_str())));
            CStormnode *psn = snodeman.Find(vin);
            CStormnodeBroadcast snb;

            if(strCommand == "start-missing" && psn) continue;
            if(strCommand == "start-disabled" && psn && psn->IsEnabled()) continue;

            bool result = activeStormnode.CreateBroadcast(sne.getIp(), sne.getPrivKey(), sne.getTxHash(), sne.getOutputIndex(), errorMessage, snb);

            Object statusObj;
            statusObj.push_back(Pair("alias", sne.getAlias()));
            statusObj.push_back(Pair("result", result ? "successful" : "failed"));

            if(result) {
                successful++;
                snodeman.UpdateStormnodeList(snb);
                snb.Relay();
            } else {
                failed++;
                statusObj.push_back(Pair("errorMessage", errorMessage));
            }

            resultsObj.push_back(Pair("status", statusObj));
        }
        pwalletMain->Lock();

        Object returnObj;
        returnObj.push_back(Pair("overall", strprintf("Successfully started %d stormnodes, failed to start %d, total %d", successful, failed, successful + failed)));
        returnObj.push_back(Pair("detail", resultsObj));

        return returnObj;
    }

    if (strCommand == "create")
    {

        throw runtime_error("Not implemented yet, please look at the documentation for instructions on stormnode creation\n");
    }

    if (strCommand == "genkey")
    {
        CKey secret;
        secret.MakeNewKey(false);

        return CDarkSilkSecret(secret).ToString();
    }

    if(strCommand == "list-conf")
    {
        std::vector<CStormnodeConfig::CStormnodeEntry> snEntries;
        snEntries = stormnodeConfig.getEntries();

        Object resultObj;

        BOOST_FOREACH(CStormnodeConfig::CStormnodeEntry sne, stormnodeConfig.getEntries()) {
            CTxIn vin = CTxIn(uint256(sne.getTxHash()), uint32_t(atoi(sne.getOutputIndex().c_str())));
            CStormnode *psn = snodeman.Find(vin);

            std::string strStatus = psn ? psn->Status() : "MISSING";

            Object snObj;
            snObj.push_back(Pair("alias", sne.getAlias()));
            snObj.push_back(Pair("address", sne.getIp()));
            snObj.push_back(Pair("privateKey", sne.getPrivKey()));
            snObj.push_back(Pair("txHash", sne.getTxHash()));
            snObj.push_back(Pair("outputIndex", sne.getOutputIndex()));
            snObj.push_back(Pair("status", strStatus));
            resultObj.push_back(Pair("stormnode", snObj));
        }

        return resultObj;
    }

    if (strCommand == "outputs"){
        // Find possible candidates
        vector<COutput> possibleCoins = activeStormnode.SelectCoinsStormnode();

        Object obj;
        BOOST_FOREACH(COutput& out, possibleCoins) {
            obj.push_back(Pair(out.tx->GetHash().ToString(), strprintf("%d", out.i)));
        }

        return obj;

    }

    if(strCommand == "status")
    {
        if(!fStormNode) throw runtime_error("This is not a stormnode\n");

        Object snObj;
        CStormnode *psn = snodeman.Find(activeStormnode.vin);

        snObj.push_back(Pair("vin", activeStormnode.vin.ToString()));
        snObj.push_back(Pair("service", activeStormnode.service.ToString()));
        if (psn) snObj.push_back(Pair("pubkey", CDarkSilkAddress(psn->pubkey.GetID()).ToString()));
        snObj.push_back(Pair("status", activeStormnode.GetStatus()));
        return snObj;
    }

    if (strCommand == "winners")
    {
        int nLast = 10;

        if (params.size() >= 2){
            nLast = atoi(params[1].get_str());
        }

        Object obj;

        for(int nHeight = pindexBest->nHeight-nLast; nHeight < pindexBest->nHeight+20; nHeight++)
        {
            obj.push_back(Pair(strprintf("%d", nHeight), GetRequiredPaymentsString(nHeight)));
        }

        return obj;
    }

    /*
        Shows which stormnode wins by score each block
    */
    if (strCommand == "calcscore")
    {

        int nLast = 10;

        if (params.size() >= 2){
            nLast = atoi(params[1].get_str());
        }
        Object obj;

        std::vector<CStormnode> vStormnodes = snodeman.GetFullStormnodeVector();
        for(int nHeight = pindexBest->nHeight-nLast; nHeight < pindexBest->nHeight+20; nHeight++){
            uint256 nHigh = 0;
            CStormnode *pBestStormnode = NULL;
            BOOST_FOREACH(CStormnode& sn, vStormnodes) {
                uint256 n = sn.CalculateScore(1, nHeight-100);
                if(n > nHigh){
                    nHigh = n;
                    pBestStormnode = &sn;
                }
            }
            if(pBestStormnode)
                obj.push_back(Pair(strprintf("%d", nHeight), pBestStormnode->vin.prevout.ToStringShort().c_str()));
        }

        return obj;
    }

    return Value::null;
}

Value stormnodelist(const Array& params, bool fHelp)
{
    std::string strMode = "status";
    std::string strFilter = "";

    if (params.size() >= 1) strMode = params[0].get_str();
    if (params.size() == 2) strFilter = params[1].get_str();

    if (fHelp ||
            (strMode != "status" && strMode != "vin" && strMode != "pubkey" && strMode != "lastseen" && strMode != "activeseconds" && strMode != "rank" && strMode != "addr"
                && strMode != "protocol" && strMode != "full" && strMode != "lastpaid"))
    {
        throw runtime_error(
                "stormnodelist ( \"mode\" \"filter\" )\n"
                "Get a list of stormnodes in different modes\n"
                "\nArguments:\n"
                "1. \"mode\"      (string, optional/required to use filter, defaults = status) The mode to run list in\n"
                "2. \"filter\"    (string, optional) Filter results. Partial match by IP by default in all modes,\n"
                "                                    additional matches in some modes are also available\n"
                "\nAvailable modes:\n"
                "  activeseconds  - Print number of seconds stormnode recognized by the network as enabled\n"
                "                   (since latest issued \"stormnode start/start-many/start-alias\")\n"
                "  addr           - Print ip address associated with a stormnode (can be additionally filtered, partial match)\n"
                "  full           - Print info in format 'status protocol pubkey IP lastseen activeseconds lastpaid'\n"
                "                   (can be additionally filtered, partial match)\n"
                "  lastseen       - Print timestamp of when a stormnode was last seen on the network\n"
                "  lastpaid       - The last time a node was paid on the network\n"
                "  protocol       - Print protocol of a stormnode (can be additionally filtered, exact match))\n"
                "  pubkey         - Print public key associated with a stormnode (can be additionally filtered,\n"
                "                   partial match)\n"
                "  rank           - Print rank of a stormnode based on current block\n"
                "  status         - Print stormnode status: ENABLED / EXPIRED / VIN_SPENT / REMOVE / POS_ERROR\n"
                "                   (can be additionally filtered, partial match)\n"
                );
    }

    Object obj;
    if (strMode == "rank") {
        std::vector<pair<int, CStormnode> > vStormnodeRanks = snodeman.GetStormnodeRanks(pindexBest->nHeight);
        BOOST_FOREACH(PAIRTYPE(int, CStormnode)& s, vStormnodeRanks) {
            std::string strVin = s.second.vin.prevout.ToStringShort();
            if(strFilter !="" && strVin.find(strFilter) == string::npos) continue;
            obj.push_back(Pair(strVin,       s.first));
        }
    } else {
        std::vector<CStormnode> vStormnodes = snodeman.GetFullStormnodeVector();
        BOOST_FOREACH(CStormnode& sn, vStormnodes) {
            std::string strVin = sn.vin.prevout.ToStringShort();
            if (strMode == "activeseconds") {
                if(strFilter !="" && strVin.find(strFilter) == string::npos) continue;
                obj.push_back(Pair(strVin,       (int64_t)(sn.lastPing.sigTime - sn.sigTime)));
            } else if (strMode == "addr") {
                if(strFilter !="" && sn.vin.prevout.hash.ToString().find(strFilter) == string::npos &&
                    strVin.find(strFilter) == string::npos) continue;
                obj.push_back(Pair(strVin,       sn.addr.ToString()));
            } else if (strMode == "full") {
                std::ostringstream addrStream;
                addrStream << setw(21) << strVin;

                std::ostringstream stringStream;
                stringStream << setw(9) <<
                               sn.Status() << " " <<
                               sn.protocolVersion << " " <<
                               CDarkSilkAddress(sn.pubkey.GetID()).ToString() << " " << setw(21) <<
                               sn.addr.ToString() << " " <<
                               (int64_t)sn.lastPing.sigTime << " " << setw(8) <<
                               (int64_t)(sn.lastPing.sigTime - sn.sigTime) << " " <<
                               (int64_t)sn.GetLastPaid();
                std::string output = stringStream.str();
                stringStream << " " << strVin;
                if(strFilter !="" && stringStream.str().find(strFilter) == string::npos &&
                        strVin.find(strFilter) == string::npos) continue;
                obj.push_back(Pair(addrStream.str(), output));
            } else if (strMode == "lastseen") {
                if(strFilter !="" && strVin.find(strFilter) == string::npos) continue;
                obj.push_back(Pair(strVin,       (int64_t)sn.lastPing.sigTime));
            } else if (strMode == "lastpaid"){
                if(strFilter !="" && sn.vin.prevout.hash.ToString().find(strFilter) == string::npos &&
                    strVin.find(strFilter) == string::npos) continue;
                obj.push_back(Pair(strVin,      (int64_t)sn.GetLastPaid()));
            } else if (strMode == "protocol") {
                if(strFilter !="" && strFilter != strprintf("%d", sn.protocolVersion) &&
                    strVin.find(strFilter) == string::npos) continue;
                obj.push_back(Pair(strVin,       (int64_t)sn.protocolVersion));
            } else if (strMode == "pubkey") {
                CDarkSilkAddress address(sn.pubkey.GetID());

                if(strFilter !="" && address.ToString().find(strFilter) == string::npos &&
                    strVin.find(strFilter) == string::npos) continue;
                obj.push_back(Pair(strVin,       address.ToString()));
            } else if(strMode == "status") {
                std::string strStatus = sn.Status();
                if(strFilter !="" && strVin.find(strFilter) == string::npos && strStatus.find(strFilter) == string::npos) continue;
                obj.push_back(Pair(strVin,       strStatus));
            }
        }
    }
    return obj;

}

bool DecodeHexVecSnb(std::vector<CStormnodeBroadcast>& vecSnb, std::string strHexSnb) {

    if (!IsHex(strHexSnb))
        return false;

    vector<unsigned char> snbData(ParseHex(strHexSnb));
    CDataStream ssData(snbData, SER_NETWORK, PROTOCOL_VERSION);
    try {
        ssData >> vecSnb;
    }
    catch (const std::exception&) {
        return false;
    }

    return true;
}

Value stormnodebroadcast(const Array& params, bool fHelp)
{
    string strCommand;
    if (params.size() >= 1)
        strCommand = params[0].get_str();

    if (fHelp  ||
        (strCommand != "create-alias" && strCommand != "create-all" && strCommand != "decode" && strCommand != "relay"))
        throw runtime_error(
                "stormnodebroadcast \"command\"... ( \"passphrase\" )\n"
                "Set of commands to create and relay stormnode broadcast messages\n"
                "\nArguments:\n"
                "1. \"command\"        (string or set of strings, required) The command to execute\n"
                "2. \"passphrase\"     (string, optional) The wallet passphrase\n"
                "\nAvailable commands:\n"
                "  create-alias  - Create single remote stormnode broadcast message by assigned alias configured in stormnode.conf\n"
                "  create-all    - Create remote stormnode broadcast messages for all stormnodes configured in stormnode.conf\n"
                "  decode        - Decode stormnode broadcast message\n"
                "  relay         - Relay stormnode broadcast message to the network\n"
                + HelpRequiringPassphrase());

    if (strCommand == "create-alias")
    {
        // wait for reindex and/or import to finish
        if (fImporting || fReindex)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Wait for reindex and/or import to finish");

        if (params.size() < 2)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Command needs at least 2 parameters");

        std::string alias = params[1].get_str();

        if(pwalletMain->IsLocked()) {
            SecureString strWalletPass;
            strWalletPass.reserve(100);

            if (params.size() == 3){
                strWalletPass = params[2].get_str().c_str();
            } else {
                throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Your wallet is locked, passphrase is required");
            }

            if(!pwalletMain->Unlock(strWalletPass)){
                throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "The wallet passphrase entered was incorrect");
            }
        }

        bool found = false;

        Object statusObj;
        std::vector<CStormnodeBroadcast> vecSnb;

        statusObj.push_back(Pair("alias", alias));

        BOOST_FOREACH(CStormnodeConfig::CStormnodeEntry sne, stormnodeConfig.getEntries()) {
            if(sne.getAlias() == alias) {
                found = true;
                std::string errorMessage;
                CStormnodeBroadcast snb;

                bool result = activeStormnode.CreateBroadcast(sne.getIp(), sne.getPrivKey(), sne.getTxHash(), sne.getOutputIndex(), errorMessage, snb, true);

                statusObj.push_back(Pair("result", result ? "successful" : "failed"));
                if(result) {
                    vecSnb.push_back(snb);
                    CDataStream ssVecSnb(SER_NETWORK, PROTOCOL_VERSION);
                    ssVecSnb << vecSnb;
                    statusObj.push_back(Pair("hex", HexStr(ssVecSnb.begin(), ssVecSnb.end())));
                } else {
                    statusObj.push_back(Pair("errorMessage", errorMessage));
                }
                break;
            }
        }

        if(!found) {
            statusObj.push_back(Pair("result", "not found"));
            statusObj.push_back(Pair("errorMessage", "Could not find alias in config. Verify with list-conf."));
        }

        pwalletMain->Lock();
        return statusObj;

    }

    if (strCommand == "create-all")
    {
        // wait for reindex and/or import to finish
        if (fImporting || fReindex)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Wait for reindex and/or import to finish");

        if(pwalletMain->IsLocked()) {
            SecureString strWalletPass;
            strWalletPass.reserve(100);

            if (params.size() == 2){
                strWalletPass = params[1].get_str().c_str();
            } else {
                throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Your wallet is locked, passphrase is required");
            }

            if(!pwalletMain->Unlock(strWalletPass)){
                throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "The wallet passphrase entered was incorrect");
            }
        }

        std::vector<CStormnodeConfig::CStormnodeEntry> snEntries;
        snEntries = stormnodeConfig.getEntries();

        int successful = 0;
        int failed = 0;

        Object resultsObj;
        std::vector<CStormnodeBroadcast> vecSnb;

        BOOST_FOREACH(CStormnodeConfig::CStormnodeEntry sne, stormnodeConfig.getEntries()) {
            std::string errorMessage;

            CTxIn vin = CTxIn(uint256(sne.getTxHash()), uint32_t(atoi(sne.getOutputIndex().c_str())));
            CStormnodeBroadcast snb;

            bool result = activeStormnode.CreateBroadcast(sne.getIp(), sne.getPrivKey(), sne.getTxHash(), sne.getOutputIndex(), errorMessage, snb, true);

            Object statusObj;
            statusObj.push_back(Pair("alias", sne.getAlias()));
            statusObj.push_back(Pair("result", result ? "successful" : "failed"));

            if(result) {
                successful++;
                vecSnb.push_back(snb);
            } else {
                failed++;
                statusObj.push_back(Pair("errorMessage", errorMessage));
            }

            resultsObj.push_back(Pair("status", statusObj));
        }
        pwalletMain->Lock();

        CDataStream ssVecSnb(SER_NETWORK, PROTOCOL_VERSION);
        ssVecSnb << vecSnb;
        Object returnObj;
        returnObj.push_back(Pair("overall", strprintf("Successfully created broadcast messages for %d stormnodes, failed to create %d, total %d", successful, failed, successful + failed)));
        returnObj.push_back(Pair("detail", resultsObj));
        returnObj.push_back(Pair("hex", HexStr(ssVecSnb.begin(), ssVecSnb.end())));

        return returnObj;
    }

    if (strCommand == "decode")
    {
        if (params.size() != 2)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Correct usage is 'stormnodebroadcast decode \"hexstring\"'");

        int successful = 0;
        int failed = 0;

        std::vector<CStormnodeBroadcast> vecSnb;
        Object returnObj;

        if (!DecodeHexVecSnb(vecSnb, params[1].get_str()))
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Stormnode broadcast message decode failed");

        BOOST_FOREACH(CStormnodeBroadcast& snb, vecSnb) {
            Object resultObj;

            if(snb.VerifySignature()) {
                successful++;
                resultObj.push_back(Pair("vin", snb.vin.ToString()));
                resultObj.push_back(Pair("addr", snb.addr.ToString()));
                resultObj.push_back(Pair("pubkey", CDarkSilkAddress(snb.pubkey.GetID()).ToString()));
                resultObj.push_back(Pair("pubkey2", CDarkSilkAddress(snb.pubkey2.GetID()).ToString()));
                resultObj.push_back(Pair("vchSig", EncodeBase64(&snb.vchSig[0], snb.vchSig.size())));
                resultObj.push_back(Pair("sigTime", snb.sigTime));
                resultObj.push_back(Pair("protocolVersion", snb.protocolVersion));
                resultObj.push_back(Pair("nLastSsq", snb.nLastSsq));

                Object lastPingObj;
                lastPingObj.push_back(Pair("vin", snb.lastPing.vin.ToString()));
                lastPingObj.push_back(Pair("blockHash", snb.lastPing.blockHash.ToString()));
                lastPingObj.push_back(Pair("sigTime", snb.lastPing.sigTime));
                lastPingObj.push_back(Pair("vchSig", EncodeBase64(&snb.lastPing.vchSig[0], snb.lastPing.vchSig.size())));

                resultObj.push_back(Pair("lastPing", lastPingObj));
            } else {
                failed++;
                resultObj.push_back(Pair("errorMessage", "Stormnode broadcast signature verification failed"));
            }

            returnObj.push_back(Pair(snb.GetHash().ToString(), resultObj));
        }

        returnObj.push_back(Pair("overall", strprintf("Successfully decoded broadcast messages for %d stormnodes, failed to decode %d, total %d", successful, failed, successful + failed)));

        return returnObj;
    }

    if (strCommand == "relay")
    {
        if (params.size() < 2 || params.size() > 3)
            throw JSONRPCError(RPC_INVALID_PARAMETER,   "stormnodebroadcast relay \"hexstring\" ( fast )\n"
                                                        "\nArguments:\n"
                                                        "1. \"hex\"      (string, required) Broadcast messages hex string\n"
                                                        "2. fast       (string, optional) If none, using safe method\n");

        int successful = 0;
        int failed = 0;
        bool fSafe = params.size() == 2;

        std::vector<CStormnodeBroadcast> vecSnb;
        Object returnObj;

        if (!DecodeHexVecSnb(vecSnb, params[1].get_str()))
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Stormnode broadcast message decode failed");

        // verify all signatures first, bailout if any of them broken
        BOOST_FOREACH(CStormnodeBroadcast& snb, vecSnb) {
            Object resultObj;

            resultObj.push_back(Pair("vin", snb.vin.ToString()));
            resultObj.push_back(Pair("addr", snb.addr.ToString()));

            int nDos = 0;
            bool fResult;
            if (snb.VerifySignature()) {
                if (fSafe) {
                    fResult = snodeman.CheckSnbAndUpdateStormnodeList(snb, nDos);
                } else {
                    snodeman.UpdateStormnodeList(snb);
                    snb.Relay();
                    fResult = true;
                }
            } else fResult = false;

            if(fResult) {
                successful++;
                resultObj.push_back(Pair(snb.GetHash().ToString(), "successful"));
            } else {
                failed++;
                resultObj.push_back(Pair("errorMessage", "Stormnode broadcast signature verification failed"));
            }

            returnObj.push_back(Pair(snb.GetHash().ToString(), resultObj));
        }

        returnObj.push_back(Pair("overall", strprintf("Successfully relayed broadcast messages for %d stormnodes, failed to relay %d, total %d", successful, failed, successful + failed)));

        return returnObj;
    }

    return Value::null;
}
