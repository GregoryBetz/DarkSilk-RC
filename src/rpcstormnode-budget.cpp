// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "db.h"
#include "init.h"
#include "activestormnode.h"
#include "stormnodeman.h"
#include "stormnode-payments.h"
#include "stormnode-budget.h"
#include "stormnodeconfig.h"
#include "rpcserver.h"
//#include "utilmoneystr.h"

#include <boost/lexical_cast.hpp>
#include <fstream>
using namespace json_spirit;
using namespace std;

Value snbudget(const Array& params, bool fHelp)
{
    string strCommand;
    if (params.size() >= 1)
        strCommand = params[0].get_str();

    if (fHelp  ||
        (strCommand != "vote-many" && strCommand != "vote" && strCommand != "getvotes" && strCommand != "getinfo" && strCommand != "show"))
        throw runtime_error(
                "snbudget \"command\"... ( \"passphrase\" )\n"
                "Vote or show current budgets\n"
                "\nAvailable commands:\n"
                "  vote-many          - Vote on a Dash initiative\n"
                "  vote-alias         - Vote on a Dash initiative\n"
                "  vote               - Vote on a Dash initiative/budget\n"
                "  getvotes           - Show current stormnode budgets\n"
                "  getinfo            - Show current stormnode budgets\n"
                "  show               - Show all budgets\n"
                );

    if(strCommand == "vote-many")
    {
        int nBlockMin = 0;
        CBlockIndex* pindexPrev = pindexBest;

        std::vector<CStormnodeConfig::CStormnodeEntry> snEntries;
        snEntries = stormnodeConfig.getEntries();

        if (params.size() != 8)
            throw runtime_error("Correct usage of vote-many is 'snbudget vote-many PROPOSAL-NAME URL PAYMENT_COUNT BLOCK_START DARKSILK_ADDRESS DARKSILK_AMOUNT YES|NO|ABSTAIN'");

        std::string strProposalName = params[1].get_str();
        if(strProposalName.size() > 20)
            return "Invalid proposal name, limit of 20 characters.";

        std::string strURL = params[2].get_str();
        if(strURL.size() > 64)
            return "Invalid url, limit of 64 characters.";

        int nPaymentCount = params[3].get_int();
        if(nPaymentCount < 1)
            return "Invalid payment count, must be more than zero.";

        //set block min
        if(pindexPrev != NULL) nBlockMin = pindexPrev->nHeight - GetBudgetPaymentCycleBlocks()*(nPaymentCount+1);

        int nBlockStart = params[4].get_int();
        if(nBlockStart < nBlockMin)
            return "Invalid payment count, must be more than current height.";

        CDarkSilkAddress address(params[5].get_str());
        if (!address.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Dash address");

        // Parse Dash address
        CScript scriptPubKey = GetScriptForDestination(address.Get());

        CAmount nAmount = AmountFromValue(params[6]);
        std::string strVote = params[7].get_str().c_str();

        if(strVote != "yes" && strVote != "no") return "You can only vote 'yes' or 'no'";
        int nVote = VOTE_ABSTAIN;
        if(strVote == "yes") nVote = VOTE_YES;
        if(strVote == "no") nVote = VOTE_NO;

        int success = 0;
        int failed = 0;

        Object resultObj;

        BOOST_FOREACH(CStormnodeConfig::CStormnodeEntry sne, stormnodeConfig.getEntries()) {
            std::string errorMessage;
            std::vector<unsigned char> vchStormNodeSignature;
            std::string strStormNodeSignMessage;

            CPubKey pubKeyCollateralAddress;
            CKey keyCollateralAddress;
            CPubKey pubKeyStormnode;
            CKey keyStormnode;

            if(!sandStormSigner.SetKey(sne.getPrivKey(), errorMessage, keyStormnode, pubKeyStormnode)){
                printf(" Error upon calling SetKey for %s\n", sne.getAlias().c_str());
                failed++;
                continue;
            }

            CStormnode* psn = snodeman.Find(pubKeyStormnode);
            if(psn == NULL)
            {
                printf("Can't find stormnode by pubkey for %s\n", sne.getAlias().c_str());
                failed++;
                continue;
            }    

            //create the proposal incase we're the first to make it
            CBudgetProposalBroadcast prop(psn->vin, strProposalName, strURL, nPaymentCount, scriptPubKey, nAmount, nBlockStart);
            if(!prop.Sign(keyStormnode, pubKeyStormnode)){
                return "Failure to sign.";
            }
            mapSeenStormnodeBudgetProposals.insert(make_pair(prop.GetHash(), prop));
            prop.Relay();

            CBudgetVote vote(psn->vin, prop.GetHash(), nVote);
            if(!vote.Sign(keyStormnode, pubKeyStormnode)){
                return "Failure to sign.";
            }

            mapSeenStormnodeBudgetVotes.insert(make_pair(vote.GetHash(), vote));
            vote.Relay();

            success++;
        }

        return("Voted successfully " + boost::lexical_cast<std::string>(success) + " time(s) and failed " + boost::lexical_cast<std::string>(failed) + " time(s).");
    }

    if(strCommand == "vote")
    {
        int nBlockMin = 0;
        CBlockIndex* pindexPrev = pindexBest;

        std::vector<CStormnodeConfig::CStormnodeEntry> snEntries;
        snEntries = stormnodeConfig.getEntries();

        if (params.size() != 8)
            throw runtime_error("Correct usage of vote-many is 'snbudget vote PROPOSAL-NAME URL PAYMENT_COUNT BLOCK_START DARKSILK_ADDRESS DARKSILK_AMOUNT YES|NO|ABSTAIN'");

        std::string strProposalName = params[1].get_str();
        if(strProposalName.size() > 20)
            return "Invalid proposal name, limit of 20 characters.";

        std::string strURL = params[2].get_str();
        if(strURL.size() > 64)
            return "Invalid url, limit of 64 characters.";

        int nPaymentCount = params[3].get_int();
        if(nPaymentCount < 1)
            return "Invalid payment count, must be more than zero.";

        //set block min
        if(pindexPrev != NULL) nBlockMin = pindexPrev->nHeight - GetBudgetPaymentCycleBlocks()*(nPaymentCount+1);

        int nBlockStart = params[4].get_int();
        if(nBlockStart < nBlockMin)
            return "Invalid payment count, must be more than current height.";

        CDarkSilkAddress address(params[5].get_str());
        if (!address.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Dash address");

        // Parse Dash address
        CScript scriptPubKey = GetScriptForDestination(address.Get());

        CAmount nAmount = AmountFromValue(params[6]);
        std::string strVote = params[7].get_str().c_str();

        if(strVote != "yes" && strVote != "no") return "You can only vote 'yes' or 'no'";
        int nVote = VOTE_ABSTAIN;
        if(strVote == "yes") nVote = VOTE_YES;
        if(strVote == "no") nVote = VOTE_NO;

        CPubKey pubKeyStormnode;
        CKey keyStormnode;
        std::string errorMessage;

        if(!sandStormSigner.SetKey(strStormNodePrivKey, errorMessage, keyStormnode, pubKeyStormnode))
            return(" Error upon calling SetKey");

        //create the proposal incase we're the first to make it
        CBudgetProposalBroadcast prop(activeStormnode.vin, strProposalName, strURL, nPaymentCount, scriptPubKey, nAmount, nBlockStart);
        if(!prop.Sign(keyStormnode, pubKeyStormnode)){
            return "Failure to sign.";
        }

        mapSeenStormnodeBudgetProposals.insert(make_pair(prop.GetHash(), prop));
        prop.Relay();
        budget.AddProposal(prop);

        CBudgetVote vote(activeStormnode.vin, prop.GetHash(), nVote);
        if(!vote.Sign(keyStormnode, pubKeyStormnode)){
            return "Failure to sign.";
        }

        mapSeenStormnodeBudgetVotes.insert(make_pair(vote.GetHash(), vote));
        vote.Relay();
        budget.UpdateProposal(vote);

    }



    if(strCommand == "show")
    {
        Object resultObj;
        int64_t nTotalAllotted = 0;

        std::vector<CBudgetProposal*> winningProps = budget.GetBudget();
        BOOST_FOREACH(CBudgetProposal* prop, winningProps)
        {
            nTotalAllotted += prop->GetAllotted();

            CTxDestination address1;
            ExtractDestination(prop->GetPayee(), address1);
            CDarkSilkAddress address2(address1);

            Object bObj;
            bObj.push_back(Pair("URL",  prop->GetURL()));
            bObj.push_back(Pair("Hash",  prop->GetHash().ToString().c_str()));
            bObj.push_back(Pair("BlockStart",  (int64_t)prop->GetBlockStart()));
            bObj.push_back(Pair("BlockEnd",    (int64_t)prop->GetBlockEnd()));
            bObj.push_back(Pair("TotalPaymentCount",  (int64_t)prop->GetTotalPaymentCount()));
            bObj.push_back(Pair("RemainingPaymentCount",  (int64_t)prop->GetRemainingPaymentCount()));
            bObj.push_back(Pair("PaymentAddress",   address2.ToString().c_str()));
            bObj.push_back(Pair("Ratio",  prop->GetRatio()));
            bObj.push_back(Pair("Yeas",  (int64_t)prop->GetYeas()));
            bObj.push_back(Pair("Nays",  (int64_t)prop->GetNays()));
            bObj.push_back(Pair("Abstains",  (int64_t)prop->GetAbstains()));
            bObj.push_back(Pair("Alloted",  (int64_t)prop->GetAllotted()));
            bObj.push_back(Pair("TotalBudgetAlloted",  nTotalAllotted));
            resultObj.push_back(Pair(prop->GetName().c_str(), bObj));
        }

        return resultObj;
    }

    if(strCommand == "getinfo")
    {
        if (params.size() != 2)
            throw runtime_error("Correct usage of getinfo is 'snbudget getinfo profilename'");

        std::string strProposalName = params[1].get_str();

        CBudgetProposal* prop = budget.Find(strProposalName);

        if(prop == NULL) return "Unknown proposal name";

        CTxDestination address1;
        ExtractDestination(prop->GetPayee(), address1);
        CDarkSilkAddress address2(address1);

        Object obj;
        obj.push_back(Pair("Name",  prop->GetName().c_str()));
        obj.push_back(Pair("Hash",  prop->GetHash().ToString().c_str()));
        obj.push_back(Pair("URL",  prop->GetURL().c_str()));
        obj.push_back(Pair("BlockStart",  (int64_t)prop->GetBlockStart()));
        obj.push_back(Pair("BlockEnd",    (int64_t)prop->GetBlockEnd()));
        obj.push_back(Pair("TotalPaymentCount",  (int64_t)prop->GetTotalPaymentCount()));
        obj.push_back(Pair("RemainingPaymentCount",  (int64_t)prop->GetRemainingPaymentCount()));
        obj.push_back(Pair("PaymentAddress",   address2.ToString().c_str()));
        obj.push_back(Pair("Ratio",  prop->GetRatio()));
        obj.push_back(Pair("Yeas",  (int64_t)prop->GetYeas()));
        obj.push_back(Pair("Nays",  (int64_t)prop->GetNays()));
        obj.push_back(Pair("Abstains",  (int64_t)prop->GetAbstains()));
        obj.push_back(Pair("Alloted",  (int64_t)prop->GetAllotted()));

        return obj;
    }

    if(strCommand == "getvotes")
    {
        if (params.size() != 2)
            throw runtime_error("Correct usage of getvotes is 'snbudget getinfo profilename'");

        std::string strProposalName = params[1].get_str();

        Object obj;
        
        CBudgetProposal* prop = budget.Find(strProposalName);

        if(prop == NULL) return "Unknown proposal name";

        std::map<uint256, CBudgetVote>::iterator it = prop->mapVotes.begin();
        while(it != prop->mapVotes.end()){
            obj.push_back(Pair((*it).second.vin.prevout.ToStringShort().c_str(),  (*it).second.GetVoteString().c_str()));
            it++;
        }
        

        return obj;
    }

    return Value::null;
}

Value snfinalbudget(const Array& params, bool fHelp)
{
    string strCommand;
    if (params.size() >= 1)
        strCommand = params[0].get_str();

    if (fHelp  ||
        (strCommand != "suggest" && strCommand != "vote-many" && strCommand != "vote" && strCommand != "show"))
        throw runtime_error(
                "snbudget \"command\"... ( \"passphrase\" )\n"
                "Vote or show current budgets\n"
                "\nAvailable commands:\n"
                "  suggest     - Suggest a budget to be paid\n"
                "  vote-many   - Vote on a finalized budget\n"
                "  vote        - Vote on a finalized budget\n"
                "  show        - Show existing finalized budgets\n"
                );

    if(strCommand == "suggest")
    {
        std::vector<CStormnodeConfig::CStormnodeEntry> snEntries;
        snEntries = stormnodeConfig.getEntries();
        
        CBlockIndex* pindexPrev = pindexBest;
        if(!pindexPrev)
            return "Must be synced to suggest";

        if (params.size() < 3)
            throw runtime_error("Correct usage of suggest is 'snfinalbudget suggest BUDGET_NAME PROPNAME [PROP2 PROP3 PROP4]'");

        std::string strBudgetName = params[1].get_str();
        if(strBudgetName.size() > 20)
            return "Invalid budget name, limit of 20 characters.";

        int nBlockStart = pindexPrev->nHeight-(pindexPrev->nHeight % GetBudgetPaymentCycleBlocks())+GetBudgetPaymentCycleBlocks();

        std::vector<uint256> vecProps;
        for(int i = 2; i < (int)params.size(); i++)
        {
            std::string strHash = params[i].get_str();
            uint256 hash(strHash);

            vecProps.push_back(hash);
        }

        CPubKey pubKeyStormnode;
        CKey keyStormnode;
        std::string errorMessage;

        if(!sandStormSigner.SetKey(strStormNodePrivKey, errorMessage, keyStormnode, pubKeyStormnode))
            return(" Error upon calling SetKey");

        //create the proposal incase we're the first to make it
        CFinalizedBudgetBroadcast prop(activeStormnode.vin, strBudgetName, nBlockStart, vecProps);
        if(!prop.Sign(keyStormnode, pubKeyStormnode)){
            return "Failure to sign.";
        }

        if(!prop.IsValid())
            return "Invalid prop (are all the hashes correct?)";

        mapSeenFinalizedBudgets.insert(make_pair(prop.GetHash(), prop));
        prop.Relay();
        budget.AddFinalizedBudget(prop);

        CFinalizedBudgetVote vote(activeStormnode.vin, prop.GetHash());
        if(!vote.Sign(keyStormnode, pubKeyStormnode)){
            return "Failure to sign.";
        }

        mapSeenFinalizedBudgetVotes.insert(make_pair(vote.GetHash(), vote));
        vote.Relay();
        budget.UpdateFinalizedBudget(vote);

        return "success";

    }


    if(strCommand == "vote-many")
    {
        std::vector<CStormnodeConfig::CStormnodeEntry> snEntries;
        snEntries = stormnodeConfig.getEntries();

        if (params.size() != 2)
            throw runtime_error("Correct usage of vote-many is 'snfinalbudget vote-many BUDGET_HASH'");

        std::string strHash = params[1].get_str();
        uint256 hash(strHash);

        int success = 0;
        int failed = 0;

        Object resultObj;

        BOOST_FOREACH(CStormnodeConfig::CStormnodeEntry sne, stormnodeConfig.getEntries()) {
            std::string errorMessage;
            std::vector<unsigned char> vchStormNodeSignature;
            std::string strStormNodeSignMessage;

            CPubKey pubKeyCollateralAddress;
            CKey keyCollateralAddress;
            CPubKey pubKeyStormnode;
            CKey keyStormnode;

            if(!sandStormSigner.SetKey(sne.getPrivKey(), errorMessage, keyStormnode, pubKeyStormnode)){
                printf(" Error upon calling SetKey for %s\n", sne.getAlias().c_str());
                failed++;
                continue;
            }

            CStormnode* psn = snodeman.Find(pubKeyStormnode);
            if(psn == NULL)
            {
                printf("Can't find stormnode by pubkey for %s\n", sne.getAlias().c_str());
                failed++;
                continue;
            }    


            CFinalizedBudgetVote vote(psn->vin, hash);
            if(!vote.Sign(keyStormnode, pubKeyStormnode)){
                failed++;
                continue;
            }

            mapSeenFinalizedBudgetVotes.insert(make_pair(vote.GetHash(), vote));
            vote.Relay();
            budget.UpdateFinalizedBudget(vote);

            success++;
        }

        return("Voted successfully " + boost::lexical_cast<std::string>(success) + " time(s) and failed " + boost::lexical_cast<std::string>(failed) + " time(s).");
    }

    if(strCommand == "vote")
    {
        std::vector<CStormnodeConfig::CStormnodeEntry> snEntries;
        snEntries = stormnodeConfig.getEntries();

        if (params.size() != 2)
            throw runtime_error("Correct usage of vote is 'snfinalbudget vote BUDGET_HASH'");

        std::string strHash = params[1].get_str();
        uint256 hash(strHash);

        CPubKey pubKeyStormnode;
        CKey keyStormnode;
        std::string errorMessage;

        if(!sandStormSigner.SetKey(strStormNodePrivKey, errorMessage, keyStormnode, pubKeyStormnode))
            return(" Error upon calling SetKey");

        CFinalizedBudgetVote vote(activeStormnode.vin, hash);
        if(!vote.Sign(keyStormnode, pubKeyStormnode)){
            return "Failure to sign.";
        }

        mapSeenFinalizedBudgetVotes.insert(make_pair(vote.GetHash(), vote));
        vote.Relay();
        budget.UpdateFinalizedBudget(vote);

        return "success";
    }

    if(strCommand == "show")
    {
        Object resultObj;

        std::vector<CFinalizedBudget*> winningFbs = budget.GetFinalizedBudgets();
        BOOST_FOREACH(CFinalizedBudget* prop, winningFbs)
        {
            Object bObj;
            bObj.push_back(Pair("SubmittedBy",  prop->GetSubmittedBy().c_str()));
            bObj.push_back(Pair("Hash",  prop->GetHash().ToString().c_str()));
            bObj.push_back(Pair("BlockStart",  (int64_t)prop->GetBlockStart()));
            bObj.push_back(Pair("BlockEnd",    (int64_t)prop->GetBlockEnd()));
            bObj.push_back(Pair("Proposals",  prop->GetProposals().c_str()));
            bObj.push_back(Pair("VoteCount",  (int64_t)prop->GetVoteCount()));
            resultObj.push_back(Pair(prop->GetName().c_str(), bObj));
        }

        return resultObj;

    }

    return Value::null;
}
