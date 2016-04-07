// Copyright (c) 2014-2016 The Dash Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <fstream>

#include "rpc/rpcserver.h"
#include "main.h"
#include "reward.h"
#include "wallet/db.h"
#include "init.h"
#include "anon/stormnode/activestormnode.h"
#include "anon/stormnode/stormnode-budget.h"
#include "anon/stormnode/stormnode-payments.h"
#include "anon/stormnode/stormnode-sync.h"
#include "anon/stormnode/stormnodeconfig.h"
#include "anon/stormnode/stormnodeman.h"
#include "util.h"
#include "anon/sandstorm/sandstorm.h"

using namespace json_spirit;
using namespace std;

Value snbudget(const Array& params, bool fHelp)
{
    string strCommand;
    if (params.size() >= 1)
        strCommand = params[0].get_str();

    if (fHelp  ||
        (strCommand != "vote-many" && strCommand != "prepare" && strCommand != "submit" &&
         strCommand != "vote" && strCommand != "getvotes" && strCommand != "getproposal" && strCommand != "getproposalhash" &&
         strCommand != "list" && strCommand != "projection" && strCommand != "check" && strCommand != "nextblock"))
        throw runtime_error(
                "snbudget \"command\"...\n"
                "Manage proposals\n"
                "\nAvailable commands:\n"
                "  check              - Scan proposals and remove invalid from proposals list\n"
                "  prepare            - Prepare proposal by signing and creating tx\n"
                "  submit             - Submit proposal to network\n"
                "  getproposalhash    - Get proposal hash(es) by proposal name\n"
                "  getproposal        - Show proposal\n"
                "  getvotes           - Show detailed votes list for proposal\n"
                "  list               - List all proposals\n"
                "  nextblock          - Get info about next superblock for budget system\n"
                "  projection         - Show the projection of which proposals will be paid the next cycle\n"
                "  vote               - Vote on a proposal by single stormnode (using darksilk.conf setup)\n"
                "  vote-many          - Vote on a proposal by all stormnodes (using stormnode.conf setup)\n"
                );

    if(strCommand == "nextblock")
    {   
        LOCK(cs_main);
        CBlockIndex* pindexPrev = pindexBest;
        if(!pindexPrev) return "unknown";

        int nNext = pindexPrev->nHeight - pindexPrev->nHeight % GetBudgetPaymentCycleBlocks() + GetBudgetPaymentCycleBlocks();
        return nNext;
    }

    if(strCommand == "nextsuperblocksize")
    {   
        LOCK(cs_main);
        CBlockIndex* pindexPrev = pindexBest;
        if(!pindexPrev) return "unknown";

        int nHeight = pindexPrev->nHeight - pindexPrev->nHeight % GetBudgetPaymentCycleBlocks() + GetBudgetPaymentCycleBlocks();

        CAmount nTotal = budget.GetTotalBudget(nHeight);
        return nTotal;
    }

    if(strCommand == "prepare")
    {
        if (params.size() != 7)
            throw runtime_error("Correct usage is 'snbudget prepare <proposal-name> <url> <payment-count> <block-start> <darksilk-address> <monthly-payment-darksilk>'");

        int nBlockMin = 0;
        LOCK(cs_main);
        CBlockIndex* pindex = pindexBest;

        std::vector<CStormnodeConfig::CStormnodeEntry> snEntries;
        snEntries = stormnodeConfig.getEntries();

        std::string strProposalName = SanitizeString(params[1].get_str());
        std::string strURL = SanitizeString(params[2].get_str());
        int nPaymentCount = params[3].get_int();
        int nBlockStart = params[4].get_int();

        //set block min
        if(pindex != NULL) nBlockMin = pindex->nHeight;

        if(nBlockStart < nBlockMin)
            return "Invalid block start, must be more than current height.";

        CDarkSilkAddress address(params[5].get_str());
        if (!address.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid DarkSilk address");

        // Parse DRKSLK address
        CScript scriptPubKey = GetScriptForDestination(address.Get());
        CAmount nAmount = AmountFromValue(params[6]);

        //*************************************************************************

        // create transaction 15 minutes into the future, to allow for confirmation time
        CBudgetProposalBroadcast budgetProposalBroadcast(strProposalName, strURL, nPaymentCount, scriptPubKey, nAmount, nBlockStart, 0);

        std::string strError = "";
        if(!budgetProposalBroadcast.IsValid(strError, false))
            return "Proposal is not valid - " + budgetProposalBroadcast.GetHash().ToString() + " - " + strError;

        bool useIX = false; //true;
        // if (params.size() > 7) {
        //     if(params[7].get_str() != "false" && params[7].get_str() != "true")
        //         return "Invalid use_ix, must be true or false";
        //     useIX = params[7].get_str() == "true" ? true : false;
        // }

        CWalletTx wtx;
        if(!pwalletMain->GetBudgetSystemCollateralTX(wtx, budgetProposalBroadcast.GetHash(), useIX)){
            return "Error making collateral transaction for proposal. Please check your wallet balance and make sure your wallet is unlocked.";
        }

        // make our change address
        CReserveKey reservekey(pwalletMain);
        //send the tx to the network
        pwalletMain->CommitTransaction(wtx, reservekey, useIX ? "ix" : "tx");

        return wtx.GetHash().ToString();
    }

    if(strCommand == "submit")
    {
        if (params.size() != 8)
            throw runtime_error("Correct usage is 'snbudget submit <proposal-name> <url> <payment-count> <block-start> <darksilk-address> <monthly-payment-darksilk> <fee-tx>'");

        if(!stormnodeSync.IsBlockchainSynced()){
            return "Must wait for client to sync with stormnode network. Try again in a minute or so.";
        }

        int nBlockMin = 0;
        LOCK(cs_main);
        CBlockIndex* pindexPrev = pindexBest;

        std::vector<CStormnodeConfig::CStormnodeEntry> snEntries;
        snEntries = stormnodeConfig.getEntries();

        std::string strProposalName = SanitizeString(params[1].get_str());
        std::string strURL = SanitizeString(params[2].get_str());
        int nPaymentCount = params[3].get_int();
        int nBlockStart = params[4].get_int();

        //set block min
        if(pindexPrev != NULL) nBlockMin = pindexPrev->nHeight;

        if(nBlockStart < nBlockMin)
            return "Invalid payment count, must be more than current height.";

        CDarkSilkAddress address(params[5].get_str());
        if (!address.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid DarkSilk address");

        // Parse DRKSLK address
        CScript scriptPubKey = GetScriptForDestination(address.Get());
        CAmount nAmount = AmountFromValue(params[6]);
        uint256 hash = ParseHashV(params[7], "Proposal hash");

        //create the proposal incase we're the first to make it
        CBudgetProposalBroadcast budgetProposalBroadcast(strProposalName, strURL, nPaymentCount, scriptPubKey, nAmount, nBlockStart, hash);

        std::string strError = "";

        if(!budgetProposalBroadcast.IsValid(strError)){
            return "Proposal is not valid - " + budgetProposalBroadcast.GetHash().ToString() + " - " + strError;
        }

        int nConf = 0;
        if(!IsBudgetCollateralValid(hash, budgetProposalBroadcast.GetHash(), strError, budgetProposalBroadcast.nTime, nConf)){
            return "Proposal FeeTX is not valid - " + hash.ToString() + " - " + strError;
        }

        budget.mapSeenStormnodeBudgetProposals.insert(make_pair(budgetProposalBroadcast.GetHash(), budgetProposalBroadcast));
        budgetProposalBroadcast.Relay();
        budget.AddProposal(budgetProposalBroadcast);

        return budgetProposalBroadcast.GetHash().ToString();

    }

    if(strCommand == "vote-many")
    {
        if(params.size() != 3)
            throw runtime_error("Correct usage is 'snbudget vote-many <proposal-hash> <yes|no>'");

        uint256 hash;
        std::string strVote;

        hash = ParseHashV(params[1], "Proposal hash");
        strVote = params[2].get_str();

        if(strVote != "yes" && strVote != "no") return "You can only vote 'yes' or 'no'";
        int nVote = VOTE_ABSTAIN;
        if(strVote == "yes") nVote = VOTE_YES;
        if(strVote == "no") nVote = VOTE_NO;

        int success = 0;
        int failed = 0;

        std::vector<CStormnodeConfig::CStormnodeEntry> snEntries;
        snEntries = stormnodeConfig.getEntries();

        Object resultsObj;

        BOOST_FOREACH(CStormnodeConfig::CStormnodeEntry sne, stormnodeConfig.getEntries()) {
            std::string errorMessage;
            std::vector<unsigned char> vchStormNodeSignature;
            std::string strStormNodeSignMessage;

            CPubKey pubKeyCollateralAddress;
            CKey keyCollateralAddress;
            CPubKey pubKeyStormnode;
            CKey keyStormnode;

            Object statusObj;

            if(!sandStormSigner.SetKey(sne.getPrivKey(), errorMessage, keyStormnode, pubKeyStormnode)){
                failed++;
                statusObj.push_back(Pair("result", "failed"));
                statusObj.push_back(Pair("errorMessage", "Stormnode signing error, could not set key correctly: " + errorMessage));
                resultsObj.push_back(Pair(sne.getAlias(), statusObj));
                continue;
            }

            CStormnode* psm = snodeman.Find(pubKeyStormnode);
            if(psm == NULL)
            {
                failed++;
                statusObj.push_back(Pair("result", "failed"));
                statusObj.push_back(Pair("errorMessage", "Can't find stormnode by pubkey"));
                resultsObj.push_back(Pair(sne.getAlias(), statusObj));
                continue;
            }

            CBudgetVote vote(psm->vin, hash, nVote);
            if(!vote.Sign(keyStormnode, pubKeyStormnode)){
                failed++;
                statusObj.push_back(Pair("result", "failed"));
                statusObj.push_back(Pair("errorMessage", "Failure to sign."));
                resultsObj.push_back(Pair(sne.getAlias(), statusObj));
                continue;
            }


            std::string strError = "";
            if(budget.UpdateProposal(vote, NULL, strError)) {
                budget.mapSeenStormnodeBudgetVotes.insert(make_pair(vote.GetHash(), vote));
                vote.Relay();
                success++;
                statusObj.push_back(Pair("result", "success"));
            } else {
                failed++;
                statusObj.push_back(Pair("result", strError.c_str()));
            }

            resultsObj.push_back(Pair(sne.getAlias(), statusObj));
        }

        Object returnObj;
        returnObj.push_back(Pair("overall", strprintf("Voted successfully %d time(s) and failed %d time(s).", success, failed)));
        returnObj.push_back(Pair("detail", resultsObj));

        return returnObj;
    }

    if(strCommand == "vote-alias")
    {
        if (params.size() != 4)
            throw runtime_error("Correct usage is 'snbudget vote <proposal-hash> <yes|no>'");

        uint256 hash;
        std::string strVote;

        hash = ParseHashV(params[1], "Proposal hash");
        strVote = params[2].get_str();
        std::string strAlias = params[3].get_str();

        if(strVote != "yes" && strVote != "no") return "You can only vote 'yes' or 'no'";
        int nVote = VOTE_ABSTAIN;
        if(strVote == "yes") nVote = VOTE_YES;
        if(strVote == "no") nVote = VOTE_NO;

        int success = 0;
        int failed = 0;

        std::vector<CStormnodeConfig::CStormnodeEntry> snEntries;
        snEntries = stormnodeConfig.getEntries();

        Object resultsObj;

        BOOST_FOREACH(CStormnodeConfig::CStormnodeEntry sne, stormnodeConfig.getEntries()) {

            if( strAlias != sne.getAlias()) continue;

            std::string errorMessage;
            std::vector<unsigned char> vchStormNodeSignature;
            std::string strStormNodeSignMessage;

            CPubKey pubKeyCollateralAddress;
            CKey keyCollateralAddress;
            CPubKey pubKeyStormnode;
            CKey keyStormnode;

            Object statusObj;

        if(!sandStormSigner.SetKey(sne.getPrivKey(), errorMessage, keyStormnode, pubKeyStormnode)){
                failed++;
                statusObj.push_back(Pair("result", "failed"));
                statusObj.push_back(Pair("errorMessage", "Stormnode signing error, could not set key correctly: " + errorMessage));
                resultsObj.push_back(Pair(sne.getAlias(), statusObj));
                continue;
            }

            CStormnode* psn = snodeman.Find(pubKeyStormnode);
            if(psn == NULL)
            {
                failed++;
                statusObj.push_back(Pair("result", "failed"));
                statusObj.push_back(Pair("errorMessage", "Can't find stormnode by pubkey"));
                resultsObj.push_back(Pair(sne.getAlias(), statusObj));
                continue;
            }

            CBudgetVote vote(psn->vin, hash, nVote);
            if(!vote.Sign(keyStormnode, pubKeyStormnode)){
                failed++;
                statusObj.push_back(Pair("result", "failed"));
                statusObj.push_back(Pair("errorMessage", "Failure to sign."));
                resultsObj.push_back(Pair(sne.getAlias(), statusObj));
                continue;
            }


            std::string strError = "";
            if(budget.UpdateProposal(vote, NULL, strError)) {
                budget.mapSeenStormnodeBudgetVotes.insert(make_pair(vote.GetHash(), vote));
                vote.Relay();
                success++;
                statusObj.push_back(Pair("result", "success"));
            } else {
                failed++;
                statusObj.push_back(Pair("result", strError.c_str()));
            }

            resultsObj.push_back(Pair(sne.getAlias(), statusObj));
        }

        Object returnObj;
        returnObj.push_back(Pair("overall", strprintf("Voted successfully %d time(s) and failed %d time(s).", success, failed)));
        returnObj.push_back(Pair("detail", resultsObj));

        return returnObj;
    }

    if(strCommand == "vote")
    {
        if (params.size() != 3)
            throw runtime_error("Correct usage is 'snbudget vote <proposal-hash> <yes|no>'");

        uint256 hash = ParseHashV(params[1], "Proposal hash");
        std::string strVote = params[2].get_str();

        if(strVote != "yes" && strVote != "no") return "You can only vote 'yes' or 'no'";
        int nVote = VOTE_ABSTAIN;
        if(strVote == "yes") nVote = VOTE_YES;
        if(strVote == "no") nVote = VOTE_NO;

        CPubKey pubKeyStormnode;
        CKey keyStormnode;
        std::string errorMessage;

        if(!sandStormSigner.SetKey(strStormNodePrivKey, errorMessage, keyStormnode, pubKeyStormnode))
            return "Error upon calling SetKey";

        CStormnode* psn = snodeman.Find(activeStormnode.vin);
        if(psn == NULL)
        {
            return "Failure to find stormnode in list : " + activeStormnode.vin.ToString();
        }

        CBudgetVote vote(activeStormnode.vin, hash, nVote);
        if(!vote.Sign(keyStormnode, pubKeyStormnode)){
            return "Failure to sign.";
        }

        std::string strError = "";
        if(budget.UpdateProposal(vote, NULL, strError)){
            budget.mapSeenStormnodeBudgetVotes.insert(make_pair(vote.GetHash(), vote));
            vote.Relay();
            return "Voted successfully";
        } else {
            return "Error voting : " + strError;
        }
    }

    if(strCommand == "projection")
    {
        Object resultObj;
        CAmount nTotalAllotted = 0;

        std::vector<CBudgetProposal*> winningProps = budget.GetBudget();
        BOOST_FOREACH(CBudgetProposal* pbudgetProposal, winningProps)
        {
            nTotalAllotted += pbudgetProposal->GetAllotted();

            CTxDestination address1;
            ExtractDestination(pbudgetProposal->GetPayee(), address1);
            CDarkSilkAddress address2(address1);

            Object bObj;
            bObj.push_back(Pair("URL",  pbudgetProposal->GetURL()));
            bObj.push_back(Pair("Hash",  pbudgetProposal->GetHash().ToString()));
            bObj.push_back(Pair("BlockStart",  (int64_t)pbudgetProposal->GetBlockStart()));
            bObj.push_back(Pair("BlockEnd",    (int64_t)pbudgetProposal->GetBlockEnd()));
            bObj.push_back(Pair("TotalPaymentCount",  (int64_t)pbudgetProposal->GetTotalPaymentCount()));
            bObj.push_back(Pair("RemainingPaymentCount",  (int64_t)pbudgetProposal->GetRemainingPaymentCount()));
            bObj.push_back(Pair("PaymentAddress",   address2.ToString()));
            bObj.push_back(Pair("Ratio",  pbudgetProposal->GetRatio()));
            bObj.push_back(Pair("AbsoluteYesCount",  (int64_t)pbudgetProposal->GetYesCount()-(int64_t)pbudgetProposal->GetNoCount()));
            bObj.push_back(Pair("YesCount",  (int64_t)pbudgetProposal->GetYesCount()));
            bObj.push_back(Pair("NoCount",  (int64_t)pbudgetProposal->GetNoCount()));
            bObj.push_back(Pair("AbstainCount",  (int64_t)pbudgetProposal->GetAbstainCount()));
            bObj.push_back(Pair("TotalPayment",  ValueFromAmount(pbudgetProposal->GetAmount()*pbudgetProposal->GetTotalPaymentCount())));
            bObj.push_back(Pair("MonthlyPayment",  ValueFromAmount(pbudgetProposal->GetAmount())));
            bObj.push_back(Pair("Alloted",  ValueFromAmount(pbudgetProposal->GetAllotted())));

            std::string strError = "";
            bObj.push_back(Pair("IsValid",  pbudgetProposal->IsValid(strError)));
            bObj.push_back(Pair("IsValidReason",  strError.c_str()));
            bObj.push_back(Pair("fValid",  pbudgetProposal->fValid));

            resultObj.push_back(Pair(pbudgetProposal->GetName(), bObj));
        }
        resultObj.push_back(Pair("TotalBudgetAlloted",  ValueFromAmount(nTotalAllotted)));

        return resultObj;
    }

    if(strCommand == "list")
    {
        if (params.size() > 2)
            throw runtime_error("Correct usage is 'snbudget list [valid]'");

        std::string strShow = "valid";

        if (params.size() == 2) strShow = params[1].get_str();

        Object resultObj;
        CAmount nTotalAllotted = 0;

        std::vector<CBudgetProposal*> winningProps = budget.GetAllProposals();
        BOOST_FOREACH(CBudgetProposal* pbudgetProposal, winningProps)
        {
            if(strShow == "valid" && !pbudgetProposal->fValid) continue;

            nTotalAllotted += pbudgetProposal->GetAllotted();

            CTxDestination address1;
            ExtractDestination(pbudgetProposal->GetPayee(), address1);
            CDarkSilkAddress address2(address1);

            Object bObj;
            bObj.push_back(Pair("Name",  pbudgetProposal->GetName()));
            bObj.push_back(Pair("URL",  pbudgetProposal->GetURL()));
            bObj.push_back(Pair("Hash",  pbudgetProposal->GetHash().ToString()));
            bObj.push_back(Pair("FeeHash",  pbudgetProposal->nFeeTXHash.ToString()));
            bObj.push_back(Pair("BlockStart",  (int64_t)pbudgetProposal->GetBlockStart()));
            bObj.push_back(Pair("BlockEnd",    (int64_t)pbudgetProposal->GetBlockEnd()));
            bObj.push_back(Pair("TotalPaymentCount",  (int64_t)pbudgetProposal->GetTotalPaymentCount()));
            bObj.push_back(Pair("RemainingPaymentCount",  (int64_t)pbudgetProposal->GetRemainingPaymentCount()));
            bObj.push_back(Pair("PaymentAddress",   address2.ToString()));
            bObj.push_back(Pair("Ratio",  pbudgetProposal->GetRatio()));
            bObj.push_back(Pair("AbsoluteYesCount",  (int64_t)pbudgetProposal->GetYesCount()-(int64_t)pbudgetProposal->GetNoCount()));
            bObj.push_back(Pair("YesCount",  (int64_t)pbudgetProposal->GetYesCount()));
            bObj.push_back(Pair("NoCount",  (int64_t)pbudgetProposal->GetNoCount()));
            bObj.push_back(Pair("AbstainCount",  (int64_t)pbudgetProposal->GetAbstainCount()));
            bObj.push_back(Pair("TotalPayment",  ValueFromAmount(pbudgetProposal->GetAmount()*pbudgetProposal->GetTotalPaymentCount())));
            bObj.push_back(Pair("MonthlyPayment",  ValueFromAmount(pbudgetProposal->GetAmount())));

            bObj.push_back(Pair("IsEstablished",  pbudgetProposal->IsEstablished()));

            std::string strError = "";
            bObj.push_back(Pair("IsValid",  pbudgetProposal->IsValid(strError)));
            bObj.push_back(Pair("IsValidReason",  strError.c_str()));
            bObj.push_back(Pair("fValid",  pbudgetProposal->fValid));

            resultObj.push_back(Pair(pbudgetProposal->GetName(), bObj));
        }

        return resultObj;
    }

    if(strCommand == "getproposalhash")
    {
        if (params.size() != 2)
            throw runtime_error("Correct usage is 'snbudget getproposalhash <proposal-name>'");

        std::string strProposalName = SanitizeString(params[1].get_str());

        CBudgetProposal* pbudgetProposal = budget.FindProposal(strProposalName);

        if(pbudgetProposal == NULL) return "Unknown proposal";

        Object resultObj;

        std::vector<CBudgetProposal*> winningProps = budget.GetAllProposals();
        BOOST_FOREACH(CBudgetProposal* pbudgetProposal, winningProps)
        {
            if(pbudgetProposal->GetName() != strProposalName) continue;
            if(!pbudgetProposal->fValid) continue;

            CTxDestination address1;
            ExtractDestination(pbudgetProposal->GetPayee(), address1);
            CDarkSilkAddress address2(address1);

            resultObj.push_back(Pair(pbudgetProposal->GetHash().ToString(), pbudgetProposal->GetHash().ToString()));
        }

        if(resultObj.size() > 1) return resultObj;

        return pbudgetProposal->GetHash().ToString();
    }

    if(strCommand == "getproposal")
    {
        if (params.size() != 2)
            throw runtime_error("Correct usage is 'snbudget getproposal <proposal-hash>'");

        uint256 hash = ParseHashV(params[1], "Proposal hash");

        CBudgetProposal* pbudgetProposal = budget.FindProposal(hash);

        if(pbudgetProposal == NULL) return "Unknown proposal";

        CTxDestination address1;
        ExtractDestination(pbudgetProposal->GetPayee(), address1);
        CDarkSilkAddress address2(address1);

        Object obj;
        obj.push_back(Pair("Name",  pbudgetProposal->GetName()));
        obj.push_back(Pair("Hash",  pbudgetProposal->GetHash().ToString()));
        obj.push_back(Pair("FeeHash",  pbudgetProposal->nFeeTXHash.ToString()));
        obj.push_back(Pair("URL",  pbudgetProposal->GetURL()));
        obj.push_back(Pair("BlockStart",  (int64_t)pbudgetProposal->GetBlockStart()));
        obj.push_back(Pair("BlockEnd",    (int64_t)pbudgetProposal->GetBlockEnd()));
        obj.push_back(Pair("TotalPaymentCount",  (int64_t)pbudgetProposal->GetTotalPaymentCount()));
        obj.push_back(Pair("RemainingPaymentCount",  (int64_t)pbudgetProposal->GetRemainingPaymentCount()));
        obj.push_back(Pair("PaymentAddress",   address2.ToString()));
        obj.push_back(Pair("Ratio",  pbudgetProposal->GetRatio()));
        obj.push_back(Pair("AbsoluteYesCount",  (int64_t)pbudgetProposal->GetYesCount()-(int64_t)pbudgetProposal->GetNoCount()));
        obj.push_back(Pair("YesCount",  (int64_t)pbudgetProposal->GetYesCount()));
        obj.push_back(Pair("NoCount",  (int64_t)pbudgetProposal->GetNoCount()));
        obj.push_back(Pair("AbstainCount",  (int64_t)pbudgetProposal->GetAbstainCount()));
        obj.push_back(Pair("TotalPayment",  ValueFromAmount(pbudgetProposal->GetAmount()*pbudgetProposal->GetTotalPaymentCount())));
        obj.push_back(Pair("MonthlyPayment",  ValueFromAmount(pbudgetProposal->GetAmount())));

        obj.push_back(Pair("IsEstablished",  pbudgetProposal->IsEstablished()));

        std::string strError = "";
        obj.push_back(Pair("IsValid",  pbudgetProposal->IsValid(strError)));
        obj.push_back(Pair("fValid",  pbudgetProposal->fValid));

        return obj;
    }

    if(strCommand == "getvotes")
    {
        if (params.size() != 2)
            throw runtime_error("Correct usage is 'snbudget getvotes <proposal-hash>'");

        uint256 hash = ParseHashV(params[1], "Proposal hash");

        Object obj;

        CBudgetProposal* pbudgetProposal = budget.FindProposal(hash);

        if(pbudgetProposal == NULL) return "Unknown proposal";

        std::map<uint256, CBudgetVote>::iterator it = pbudgetProposal->mapVotes.begin();
        while(it != pbudgetProposal->mapVotes.end()){

            Object bObj;
            bObj.push_back(Pair("nHash",  (*it).first.ToString().c_str()));
            bObj.push_back(Pair("Vote",  (*it).second.GetVoteString()));
            bObj.push_back(Pair("nTime",  (int64_t)(*it).second.nTime));
            bObj.push_back(Pair("fValid",  (*it).second.fValid));

            obj.push_back(Pair((*it).second.vin.prevout.ToStringShort(), bObj));

            it++;
        }


        return obj;
    }

    if(strCommand == "check")
    {
        budget.CheckAndRemove();

        return "Success";
    }

    return Value::null;
}

Value snbudgetvoteraw(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 6)
        throw runtime_error(
                "snbudgetvoteraw <stormnode-tx-hash> <stormnode-tx-index> <proposal-hash> <yes|no> <time> <vote-sig>\n"
                "Compile and relay a proposal vote with provided external signature instead of signing vote internally\n"
                );

    uint256 hashSnTx = ParseHashV(params[0], "sn tx hash");
    int nSnTxIndex = params[1].get_int();
    CTxIn vin = CTxIn(hashSnTx, nSnTxIndex);

    uint256 hashProposal = ParseHashV(params[2], "Proposal hash");
    std::string strVote = params[3].get_str();

    if(strVote != "yes" && strVote != "no") return "You can only vote 'yes' or 'no'";
    int nVote = VOTE_ABSTAIN;
    if(strVote == "yes") nVote = VOTE_YES;
    if(strVote == "no") nVote = VOTE_NO;

    int64_t nTime = params[4].get_int64();
    std::string strSig = params[5].get_str();
    bool fInvalid = false;
    vector<unsigned char> vchSig = DecodeBase64(strSig.c_str(), &fInvalid);

    if (fInvalid)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");

    CStormnode* psm = snodeman.Find(vin);
    if(psm == NULL)
    {
        return "Failure to find stormnode in list : " + vin.ToString();
    }

    CBudgetVote vote(vin, hashProposal, nVote);
    vote.nTime = nTime;
    vote.vchSig = vchSig;

    if(!vote.IsValid(true)){
        return "Failure to verify vote.";
    }

    std::string strError = "";
    if(budget.UpdateProposal(vote, NULL, strError)){
        budget.mapSeenStormnodeBudgetVotes.insert(make_pair(vote.GetHash(), vote));
        vote.Relay();
        return "Voted successfully";
    } else {
        return "Error voting : " + strError;
    }
}

Value snfinalbudget(const Array& params, bool fHelp)
{
    string strCommand;
    if (params.size() >= 1)
        strCommand = params[0].get_str();

    if (fHelp  ||
        (strCommand != "vote-many" && strCommand != "vote" && strCommand != "show" && strCommand != "getvotes" && strCommand != "prepare" && strCommand != "submit"))
        throw runtime_error(
                "snfinalbudget \"command\"...\n"
                "Manage current budgets\n"
                "\nAvailable commands:\n"
                "  vote-many   - Vote on a finalized budget\n"
                "  vote        - Vote on a finalized budget\n"
                "  show        - Show existing finalized budgets\n"
                "  getvotes    - Get vote information for each finalized budget\n"
                "  prepare     - Manually prepare a finalized budget\n"
                "  submit      - Manually submit a finalized budget\n"
                );

    if(strCommand == "vote-many")
    {
        if (params.size() != 2)
            throw runtime_error("Correct usage is 'snfinalbudget vote-many <budget-hash>'");

        std::string strHash = params[1].get_str();
        uint256 hash(strHash);

        int success = 0;
        int failed = 0;

        std::vector<CStormnodeConfig::CStormnodeEntry> snEntries;
        snEntries = stormnodeConfig.getEntries();

        Object resultsObj;

        BOOST_FOREACH(CStormnodeConfig::CStormnodeEntry sne, stormnodeConfig.getEntries()) {
            std::string errorMessage;
            std::vector<unsigned char> vchStormNodeSignature;
            std::string strStormNodeSignMessage;

            CPubKey pubKeyCollateralAddress;
            CKey keyCollateralAddress;
            CPubKey pubKeyStormnode;
            CKey keyStormnode;

            Object statusObj;

            if(!sandStormSigner.SetKey(sne.getPrivKey(), errorMessage, keyStormnode, pubKeyStormnode)){
                failed++;
                statusObj.push_back(Pair("result", "failed"));
                statusObj.push_back(Pair("errorMessage", "Stormnode signing error, could not set key correctly: " + errorMessage));
                resultsObj.push_back(Pair(sne.getAlias(), statusObj));
                continue;
            }

            CStormnode* psm = snodeman.Find(pubKeyStormnode);
            if(psm == NULL)
            {
                failed++;
                statusObj.push_back(Pair("result", "failed"));
                statusObj.push_back(Pair("errorMessage", "Can't find stormnode by pubkey"));
                resultsObj.push_back(Pair(sne.getAlias(), statusObj));
                continue;
            }


            CFinalizedBudgetVote vote(psm->vin, hash);
            if(!vote.Sign(keyStormnode, pubKeyStormnode)){
                failed++;
                statusObj.push_back(Pair("result", "failed"));
                statusObj.push_back(Pair("errorMessage", "Failure to sign."));
                resultsObj.push_back(Pair(sne.getAlias(), statusObj));
                continue;
            }

            std::string strError = "";
            if(budget.UpdateFinalizedBudget(vote, NULL, strError)){
                budget.mapSeenFinalizedBudgetVotes.insert(make_pair(vote.GetHash(), vote));
                vote.Relay();
                success++;
                statusObj.push_back(Pair("result", "success"));
            } else {
                failed++;
                statusObj.push_back(Pair("result", strError.c_str()));
            }

            resultsObj.push_back(Pair(sne.getAlias(), statusObj));
        }

        Object returnObj;
        returnObj.push_back(Pair("overall", strprintf("Voted successfully %d time(s) and failed %d time(s).", success, failed)));
        returnObj.push_back(Pair("detail", resultsObj));

        return returnObj;
    }

    if(strCommand == "vote")
    {
        if (params.size() != 2)
            throw runtime_error("Correct usage is 'snfinalbudget vote <budget-hash>'");

        std::string strHash = params[1].get_str();
        uint256 hash(strHash);

        CPubKey pubKeyStormnode;
        CKey keyStormnode;
        std::string errorMessage;

        if(!sandStormSigner.SetKey(strStormNodePrivKey, errorMessage, keyStormnode, pubKeyStormnode))
            return "Error upon calling SetKey";

        CStormnode* psm = snodeman.Find(activeStormnode.vin);
        if(psm == NULL)
        {
            return "Failure to find stormnode in list : " + activeStormnode.vin.ToString();
        }

        CFinalizedBudgetVote vote(activeStormnode.vin, hash);
        if(!vote.Sign(keyStormnode, pubKeyStormnode)){
            return "Failure to sign.";
        }

        std::string strError = "";
        if(budget.UpdateFinalizedBudget(vote, NULL, strError)){
            budget.mapSeenFinalizedBudgetVotes.insert(make_pair(vote.GetHash(), vote));
            vote.Relay();
            return "success";
        } else {
            return "Error voting : " + strError;
        }

    }

    if(strCommand == "list")
    {
        Object resultObj;

        std::vector<CFinalizedBudget*> winningFbs = budget.GetFinalizedBudgets();
        BOOST_FOREACH(CFinalizedBudget* finalizedBudget, winningFbs)
        {
            Object bObj;
            bObj.push_back(Pair("FeeTX",  finalizedBudget->nFeeTXHash.ToString()));
            bObj.push_back(Pair("Hash",  finalizedBudget->GetHash().ToString()));
            bObj.push_back(Pair("BlockStart",  (int64_t)finalizedBudget->GetBlockStart()));
            bObj.push_back(Pair("BlockEnd",    (int64_t)finalizedBudget->GetBlockEnd()));
            bObj.push_back(Pair("Proposals",  finalizedBudget->GetProposals()));
            bObj.push_back(Pair("VoteCount",  (int64_t)finalizedBudget->GetVoteCount()));
            bObj.push_back(Pair("Status",  finalizedBudget->GetStatus()));

            std::string strError = "";
            bObj.push_back(Pair("IsValid",  finalizedBudget->IsValid(strError)));
            bObj.push_back(Pair("IsValidReason",  strError.c_str()));

            resultObj.push_back(Pair(finalizedBudget->GetName(), bObj));
        }

        return resultObj;

    }

    if(strCommand == "getvotes")
    {
        if (params.size() != 2)
            throw runtime_error("Correct usage is 'snbudget getvotes <budget-hash>'");

        std::string strHash = SanitizeString(params[1].get_str());
        uint256 hash(strHash);

        Object obj;

        CFinalizedBudget* pfinalBudget = budget.FindFinalizedBudget(hash);

        if(pfinalBudget == NULL) return "Unknown budget hash";

        std::map<uint256, CFinalizedBudgetVote>::iterator it = pfinalBudget->mapVotes.begin();
        while(it != pfinalBudget->mapVotes.end()){

            Object bObj;
            bObj.push_back(Pair("nHash",  (*it).first.ToString().c_str()));
            bObj.push_back(Pair("nTime",  (int64_t)(*it).second.nTime));
            bObj.push_back(Pair("fValid",  (*it).second.fValid));

            obj.push_back(Pair((*it).second.vin.prevout.ToStringShort(), bObj));

            it++;
        }


        return obj;
    }

    /* TODO 
        Switch the preparation to a public key which the core team has
        The budget should be able to be created by any high up core team member then voted on by the network separately. 
    */
        if(strCommand == "prepare")
    {
        if (params.size() != 2)
            throw runtime_error("Correct usage is 'mnfinalbudget prepare comma-separated-hashes'");

        std::string strHashes = params[1].get_str();
        std::istringstream ss(strHashes);
        std::string token;

        std::vector<CTxBudgetPayment> vecTxBudgetPayments;

        while(std::getline(ss, token, ',')) {
            uint256 nHash(token);
            CBudgetProposal* prop = budget.FindProposal(nHash);

            CTxBudgetPayment txBudgetPayment;
            txBudgetPayment.nProposalHash = prop->GetHash();
            txBudgetPayment.payee = prop->GetPayee();
            txBudgetPayment.nAmount = prop->GetAllotted();
            vecTxBudgetPayments.push_back(txBudgetPayment);
        }

        if(vecTxBudgetPayments.size() < 1) {
            return "Invalid finalized proposal";
        }

        LOCK(cs_main);
        CBlockIndex* pindexPrev = pindexBest;
        if(!pindexPrev) return "invalid chaintip";

        int nBlockStart = pindexPrev->nHeight - pindexPrev->nHeight % GetBudgetPaymentCycleBlocks() + GetBudgetPaymentCycleBlocks();

        CFinalizedBudgetBroadcast tempBudget("main", nBlockStart, vecTxBudgetPayments, 0);
        // if(mapSeenFinalizedBudgets.count(tempBudget.GetHash())) {
        //     return "already exists"; //already exists
        // }

        //create fee tx
        CTransaction tx;
        
        CWalletTx wtx;
        if(!pwalletMain->GetBudgetSystemCollateralTX(wtx, tempBudget.GetHash(), false)){
            printf("Can't make collateral transaction\n");
            return "can't make colateral tx";
        }
        
        // make our change address
        CReserveKey reservekey(pwalletMain);
        //send the tx to the network
        pwalletMain->CommitTransaction(wtx, reservekey, "ix");

        return wtx.GetHash().ToString();
    }

    if(strCommand == "submit")
    {
        if (params.size() != 3)
            throw runtime_error("Correct usage is 'snfinalbudget submit comma-separated-hashes collateralhash'");

        std::string strHashes = params[1].get_str();
        std::istringstream ss(strHashes);
        std::string token;

        std::vector<CTxBudgetPayment> vecTxBudgetPayments;

        uint256 nColHash(params[2].get_str());

        while(std::getline(ss, token, ',')) {
            uint256 nHash(token);
            CBudgetProposal* prop = budget.FindProposal(nHash);

            CTxBudgetPayment txBudgetPayment;
            txBudgetPayment.nProposalHash = prop->GetHash();
            txBudgetPayment.payee = prop->GetPayee();
            txBudgetPayment.nAmount = prop->GetAllotted();
            vecTxBudgetPayments.push_back(txBudgetPayment);

            printf("%ld\n", txBudgetPayment.nAmount);
        }

        if(vecTxBudgetPayments.size() < 1) {
            return "Invalid finalized proposal";
        }

        LOCK(cs_main);
        CBlockIndex* pindexPrev = pindexBest;
        if(!pindexPrev) return "invalid pindexBest";

        int nBlockStart = pindexPrev->nHeight - pindexPrev->nHeight % GetBudgetPaymentCycleBlocks() + GetBudgetPaymentCycleBlocks();
      
        // CTxIn in(COutPoint(nColHash, 0));
        // int conf = GetInputAgeIX(nColHash, in);
        
        //     Wait will we have 1 extra confirmation, otherwise some clients might reject this feeTX
        //     -- This function is tied to NewBlock, so we will propagate this budget while the block is also propagating
        
        // if(conf < BUDGET_FEE_CONFIRMATIONS+1){
        //     printf ("Collateral requires at least %d confirmations - %s - %d confirmations\n", BUDGET_FEE_CONFIRMATIONS, nColHash.ToString().c_str(), conf);
        //     return "invalid collateral";
        // }

        //create the proposal incase we're the first to make it
        CFinalizedBudgetBroadcast finalizedBudgetBroadcast("main", nBlockStart, vecTxBudgetPayments, nColHash);

        std::string strError = "";
        if(!finalizedBudgetBroadcast.IsValid(strError)){
            printf("CBudgetManager::SubmitFinalBudget - Invalid finalized budget - %s \n", strError.c_str());
            return "invalid finalized budget";
        }

        finalizedBudgetBroadcast.Relay();
        budget.AddFinalizedBudget(finalizedBudgetBroadcast);

        return finalizedBudgetBroadcast.GetHash().ToString();
    }

    return Value::null;
}
