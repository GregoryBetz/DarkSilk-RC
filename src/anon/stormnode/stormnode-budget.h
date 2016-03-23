// Copyright (c) 2014-2016 The Dash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef STORMNODE_BUDGET_H
#define STORMNODE_BUDGET_H

#include <boost/lexical_cast.hpp>

#include "main.h"
#include "sync.h"
#include "net.h"
#include "key.h"
#include "util.h"
#include "base58.h"
#include "anon/stormnode/stormnode.h"
#include "init.h"

using namespace std;

extern CCriticalSection cs_budget;

class CBudgetManager;
class CFinalizedBudgetBroadcast;
class CFinalizedBudget;
class CFinalizedBudgetVote;
class CBudgetProposal;
class CBudgetProposalBroadcast;
class CBudgetVote;
class CTxBudgetPayment;

static const int VOTE_ABSTAIN = 0;
static const int VOTE_YES = 1;
static const int VOTE_NO = 2;

static const CAmount BUDGET_FEE_TX = (100*COIN); //Proposal fee of 100DRKSLK
static const int64_t BUDGET_FEE_CONFIRMATIONS = 10; 
static const int64_t BUDGET_VOTE_UPDATE_MIN = 64*20;

static const uint32_t FIXED_STORMNODE_BUDGET_AMOUNT = 10000; //Budget amount fixed at 10000DRKSLK
static const uint32_t FIXED_STORMNODE_BUDGET_FREQUENCY = 41091; //Every Month or 12 x per year (60*60*24*(365.25/12))/64 (blocks = 64 secs per block)

extern std::vector<CBudgetProposalBroadcast> vecImmatureBudgetProposals;
extern std::vector<CFinalizedBudgetBroadcast> vecImmatureFinalizedBudgets;

extern CBudgetManager budget;
void DumpBudgets();

// Define amount of blocks in budget payment cycle
int GetBudgetPaymentCycleBlocks();
// Check the collateral transaction for the budget proposal/finalized budget
bool IsBudgetCollateralValid(uint256 nTxCollateralHash, uint256 nExpectedHash, std::string& strError, int64_t& nTime, int& nConf);

/// Save Budget Manager (budget.dat)
class CBudgetDB
{
private:
    boost::filesystem::path pathDB;
    std::string strMagicMessage;
public:
    enum ReadResult {
        Ok,
        FileError,
        HashReadError,
        IncorrectHash,
        IncorrectMagicMessage,
        IncorrectMagicNumber,
        IncorrectFormat
    };

    CBudgetDB();
    bool Write(const CBudgetManager &objToSave);
    ReadResult Read(CBudgetManager& objToLoad, bool fDryRun = false);
};

//
// Budget Manager : Contains all proposals for the budget
//
class CBudgetManager
{
private:
    //hold txes until they mature enough to use
    map<uint256, CTransaction> mapCollateral;

public:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

    // keep track of the scanning errors I've seen
    map<uint256, CBudgetProposal> mapProposals;
    map<uint256, CFinalizedBudget> mapFinalizedBudgets;

    std::map<uint256, CBudgetProposalBroadcast> mapSeenStormnodeBudgetProposals;
    std::map<uint256, CBudgetVote> mapSeenStormnodeBudgetVotes;
    std::map<uint256, CBudgetVote> mapOrphanStormnodeBudgetVotes;
    std::map<uint256, CFinalizedBudgetBroadcast> mapSeenFinalizedBudgets;
    std::map<uint256, CFinalizedBudgetVote> mapSeenFinalizedBudgetVotes;
    std::map<uint256, CFinalizedBudgetVote> mapOrphanFinalizedBudgetVotes;


    CBudgetManager() {
        mapProposals.clear();
        mapFinalizedBudgets.clear();
    }

    void ClearSeen() {
        mapSeenStormnodeBudgetProposals.clear();
        mapSeenStormnodeBudgetVotes.clear();
        mapSeenFinalizedBudgets.clear();
        mapSeenFinalizedBudgetVotes.clear();
    }

    int sizeFinalized() {return (int)mapFinalizedBudgets.size();}
    int sizeProposals() {return (int)mapProposals.size();}

    void ResetSync();
    void MarkSynced();
    void Sync(CNode* node, uint256 nProp, bool fPartial=false);

    void ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);
    void NewBlock();
    CBudgetProposal *FindProposal(const std::string &strProposalName);
    CBudgetProposal *FindProposal(uint256 nHash);
    CFinalizedBudget *FindFinalizedBudget(uint256 nHash);
    std::pair<std::string, std::string> GetVotes(std::string strProposalName);

    CAmount GetTotalBudget(int nHeight);
    std::vector<CBudgetProposal*> GetBudget();
    std::vector<CBudgetProposal*> GetAllProposals();
    std::vector<CFinalizedBudget*> GetFinalizedBudgets();
    bool IsBudgetPaymentBlock(int nBlockHeight);
    bool AddProposal(CBudgetProposal& budgetProposal);
    bool AddFinalizedBudget(CFinalizedBudget& finalizedBudget);
    void SubmitFinalBudget();
    bool HasNextFinalizedBudget();

    bool UpdateProposal(CBudgetVote& vote, CNode* pfrom, std::string& strError);
    bool UpdateFinalizedBudget(CFinalizedBudgetVote& vote, CNode* pfrom, std::string& strError);
    bool PropExists(uint256 nHash);
    bool IsTransactionValid(const CTransaction& txNew, int nBlockHeight);
    std::string GetRequiredPaymentsString(int nBlockHeight);
    void FillBlockPayee(CTransaction& txNew, CAmount nFees); //TODO (Amir): Use CMutableTransaction

    void CheckOrphanVotes();

    void Clear(){
        LOCK(cs);

        LogPrintf("Budget object cleared\n");
        mapProposals.clear();
        mapFinalizedBudgets.clear();
        mapSeenStormnodeBudgetProposals.clear();
        mapSeenStormnodeBudgetVotes.clear();
        mapSeenFinalizedBudgets.clear();
        mapSeenFinalizedBudgetVotes.clear();
        mapOrphanStormnodeBudgetVotes.clear();
        mapOrphanFinalizedBudgetVotes.clear();
    }

    void CheckAndRemove();
    std::string ToString() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(mapSeenStormnodeBudgetProposals);
        READWRITE(mapSeenStormnodeBudgetVotes);
        READWRITE(mapSeenFinalizedBudgets);
        READWRITE(mapSeenFinalizedBudgetVotes);
        READWRITE(mapOrphanStormnodeBudgetVotes);
        READWRITE(mapSeenStormnodeBudgetVotes);

        READWRITE(mapProposals);
        READWRITE(mapFinalizedBudgets);
    }
};

class CTxBudgetPayment
{
public:
    uint256 nProposalHash;
    CScript payee;
    CAmount nAmount;

    CTxBudgetPayment() {
        payee = CScript();
        nAmount = 0;
        nProposalHash = 0;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(payee);
        READWRITE(nAmount);
        READWRITE(nProposalHash);
    }
};

//
// Finalized Budget : Contains the suggested proposals to pay on a given block
//
class CFinalizedBudget
{
private:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;
    bool fAutoChecked; //If it matches what we see, we'll auto vote for it (stormnode only)

public:
    bool fValid;
    std::string strBudgetName;
    int nBlockStart;
    std::vector<CTxBudgetPayment> vecBudgetPayments;
    map<uint256, CFinalizedBudgetVote> mapVotes;
    uint256 nFeeTXHash;
    int64_t nTime;

    CFinalizedBudget();
    CFinalizedBudget(const CFinalizedBudget& other);

    void CleanAndRemove(bool fSignatureCheck);
    bool AddOrUpdateVote(CFinalizedBudgetVote& vote, std::string& strError);
    double GetScore();
    bool HasMinimumRequiredSupport();

    bool IsValid(std::string& strError, bool fCheckCollateral=true);

    std::string GetName() {return strBudgetName; }
    std::string GetProposals();
    int GetBlockStart() {return nBlockStart;}
    int GetBlockEnd() {return nBlockStart + (int)(vecBudgetPayments.size() - 1);}
    int GetVoteCount() {return (int)mapVotes.size();}

    bool IsTransactionValid(const CTransaction& txNew, int nBlockHeight);

    bool GetBudgetPaymentByBlock(int64_t nBlockHeight, CTxBudgetPayment& payment)
    {
        LOCK(cs);

        int i = nBlockHeight - GetBlockStart();
        if(i < 0) return false;
        if(i > (int)vecBudgetPayments.size() - 1) return false;
        payment = vecBudgetPayments[i];
        return true;
    }
    bool GetPayeeAndAmount(int64_t nBlockHeight, CScript& payee, CAmount& nAmount)
    {
        LOCK(cs);

        int i = nBlockHeight - GetBlockStart();
        if(i < 0) return false;
        if(i > (int)vecBudgetPayments.size() - 1) return false;
        payee = vecBudgetPayments[i].payee;
        nAmount = vecBudgetPayments[i].nAmount;
        return true;
    }

    //check to see if we should vote on this
    void AutoCheck();
    //total darksilk paid out by this budget
    CAmount GetTotalPayout();
    //vote on this finalized budget as a stormnode
    void SubmitVote();

    //checks the hashes to make sure we know about them
    string GetStatus();

    uint256 GetHash()
    {
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << strBudgetName;
        ss << nBlockStart;
        ss << vecBudgetPayments;

        uint256 h1 = ss.GetHash();
        return h1;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(LIMITED_STRING(strBudgetName, 20));
        READWRITE(nFeeTXHash);
        READWRITE(nTime);
        READWRITE(nBlockStart);
        READWRITE(vecBudgetPayments);
        READWRITE(fAutoChecked);
        READWRITE(mapVotes);
    }
};

// FinalizedBudget are cast then sent to peers with this object, which leaves the votes out
class CFinalizedBudgetBroadcast : public CFinalizedBudget
{
private:
    std::vector<unsigned char> vchSig;

public:
    CFinalizedBudgetBroadcast();
    CFinalizedBudgetBroadcast(const CFinalizedBudget& other);
    CFinalizedBudgetBroadcast(std::string strBudgetNameIn, int nBlockStartIn, std::vector<CTxBudgetPayment> vecBudgetPaymentsIn, uint256 nFeeTXHashIn);

    void swap(CFinalizedBudgetBroadcast& first, CFinalizedBudgetBroadcast& second) // nothrow
    {
        // enable ADL (not necessary in our case, but good practice)
        using std::swap;

        // by swapping the members of two classes,
        // the two classes are effectively swapped
        swap(first.strBudgetName, second.strBudgetName);
        swap(first.nBlockStart, second.nBlockStart);
        first.mapVotes.swap(second.mapVotes);
        first.vecBudgetPayments.swap(second.vecBudgetPayments);
        swap(first.nFeeTXHash, second.nFeeTXHash);
        swap(first.nTime, second.nTime);
    }

    CFinalizedBudgetBroadcast& operator=(CFinalizedBudgetBroadcast from)
    {
        swap(*this, from);
        return *this;
    }

    void Relay();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        //for syncing with other clients
        READWRITE(LIMITED_STRING(strBudgetName, 20));
        READWRITE(nBlockStart);
        READWRITE(vecBudgetPayments);
        READWRITE(nFeeTXHash);
    }
};

//
// CFinalizedBudgetVote - Allow a stormnode node to vote and broadcast throughout the network
//

class CFinalizedBudgetVote
{
public:
    bool fValid; //if the vote is currently valid / counted
    bool fSynced; //if we've sent this to our peers
    CTxIn vin;
    uint256 nBudgetHash;
    int64_t nTime;
    std::vector<unsigned char> vchSig;

    CFinalizedBudgetVote();
    CFinalizedBudgetVote(CTxIn vinIn, uint256 nBudgetHashIn);

    bool Sign(CKey& keyStormnode, CPubKey& pubKeyStormnode);
    bool SignatureValid(bool fSignatureCheck);
    void Relay();

    uint256 GetHash(){
            CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
            ss << vin;
            ss << nBudgetHash;
            ss << nTime;
            return ss.GetHash();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(vin);
        READWRITE(nBudgetHash);
        READWRITE(nTime);
        READWRITE(vchSig);
    }
};

//
// Budget Proposal : Contains the stormnode votes for each budget
//

class CBudgetProposal
{
private:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;
    CAmount nAlloted;


public:
    bool fValid;
    std::string strProposalName;
    
    /* 
        json object with name, short-description, long-description, pdf-url and any other info
        This allows the proposal website to stay 100% decentralized
    */
    std::string strURL;
    int nBlockStart;
    int nBlockEnd;
    CAmount nAmount;
    CScript address;
    int64_t nTime;
    uint256 nFeeTXHash;

    map<uint256, CBudgetVote> mapVotes;
    //cache object

    CBudgetProposal();
    CBudgetProposal(const CBudgetProposal& other);
    CBudgetProposal(std::string strProposalNameIn, std::string strURLIn, int nPaymentCount, CScript addressIn, CAmount nAmountIn, int nBlockStartIn, uint256 nFeeTXHashIn);

    void Calculate();
    bool AddOrUpdateVote(CBudgetVote& vote, std::string& strError);
    bool HasMinimumRequiredSupport();
    std::pair<std::string, std::string> GetVotes();

    bool IsValid(std::string& strError, bool fCheckCollateral=true);

    bool IsEstablished()
    {
        //Proposals must be at least a day old to make it into a budget
        if(Params().NetworkID() == CChainParams::MAIN) return (nTime < GetTime() - (60*60*24));

        //for testing purposes - 20 minutes
        return (nTime < GetTime() - (60*20));
    }

    std::string GetName() {return strProposalName; }
    std::string GetURL() {return strURL; }
    int GetBlockStart() {return nBlockStart;}
    int GetBlockEnd() {return nBlockEnd;}
    CScript GetPayee() {return address;}
    int GetTotalPaymentCount();
    int GetRemainingPaymentCount();
    int GetBlockStartCycle();
    int GetBlockCurrentCycle();
    int GetBlockEndCycle();
    double GetRatio();
    int GetAbsoluteYesCount();
    int GetYesCount();
    int GetNoCount();
    int GetAbstainCount();
    CAmount GetAmount() {return nAmount;}
    void SetAllotted(CAmount nAllotedIn) {nAlloted = nAllotedIn;}
    CAmount GetAllotted() {return nAlloted;}

    void CleanAndRemove(bool fSignatureCheck);

    uint256 GetHash(){     
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << strProposalName;
        ss << strURL;
        ss << nBlockStart;
        ss << nBlockEnd;
        ss << nAmount;
        ss << address;
        uint256 h1 = ss.GetHash();
        
        return h1;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        //for syncing with other clients
        READWRITE(LIMITED_STRING(strProposalName, 20));
        READWRITE(LIMITED_STRING(strURL, 64));
        READWRITE(nTime);
        READWRITE(nBlockStart);
        READWRITE(nBlockEnd);
        READWRITE(nAmount);
        READWRITE(address);
        READWRITE(nTime);
        READWRITE(nFeeTXHash);

        //for saving to the serialized db
        READWRITE(mapVotes);
    }
};

// Proposals are cast then sent to peers with this object, which leaves the votes out
class CBudgetProposalBroadcast : public CBudgetProposal
{
public:
    CBudgetProposalBroadcast() : CBudgetProposal(){}
    CBudgetProposalBroadcast(const CBudgetProposal& other) : CBudgetProposal(other){}
    CBudgetProposalBroadcast(const CBudgetProposalBroadcast& other) : CBudgetProposal(other){}
    CBudgetProposalBroadcast(std::string strProposalNameIn, std::string strURLIn, int nPaymentCount, CScript addressIn, CAmount nAmountIn, int nBlockStartIn, uint256 nFeeTXHashIn) {}

    void swap(CBudgetProposalBroadcast& first, CBudgetProposalBroadcast& second) // nothrow
    {
        // enable ADL (not necessary in our case, but good practice)
        using std::swap;

        // by swapping the members of two classes,
        // the two classes are effectively swapped
        swap(first.strProposalName, second.strProposalName);
        swap(first.nBlockStart, second.nBlockStart);
        swap(first.strURL, second.strURL);
        swap(first.nBlockEnd, second.nBlockEnd);
        swap(first.nAmount, second.nAmount);
        swap(first.address, second.address);
        swap(first.nTime, second.nTime);
        swap(first.nFeeTXHash, second.nFeeTXHash);
        first.mapVotes.swap(second.mapVotes);
    }

    CBudgetProposalBroadcast& operator=(CBudgetProposalBroadcast from)
    {
        swap(*this, from);
        return *this;
    }

    void Relay();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(LIMITED_STRING(strProposalName, 20));
        READWRITE(LIMITED_STRING(strURL, 64));
        READWRITE(nTime);
        READWRITE(nBlockStart);
        READWRITE(nBlockEnd);
        READWRITE(nAmount);
        READWRITE(address);
        READWRITE(nFeeTXHash);
    }
};
// CBudgetVote - Allow a stormnode node to vote and broadcast throughout the network
//

class CBudgetVote
{
public:
    bool fValid; //if the vote is currently valid / counted
    bool fSynced; //if we've sent this to our peers

    CTxIn vin;
    uint256 nProposalHash;
    int nVote;
    int64_t nTime;
    std::vector<unsigned char> vchSig;

    CBudgetVote();
    CBudgetVote(CTxIn vin, uint256 nProposalHash, int nVoteIn);

    bool Sign(CKey& keyStormnode, CPubKey& pubKeyStormnode);
    bool SignatureValid(bool fSignatureCheck);
    void Relay();

    std::string GetVoteString() {
        std::string ret = "ABSTAIN";
        if(nVote == VOTE_YES) ret = "YES";
        if(nVote == VOTE_NO) ret = "NO";
        return ret;
    }

    uint256 GetHash(){
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << vin;
        ss << nProposalHash;
        ss << nVote;
        ss << nTime;
        return ss.GetHash();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(vin);
        READWRITE(nProposalHash);
        READWRITE(nVote);
        READWRITE(nTime);
        READWRITE(vchSig);
    }
};

#endif
