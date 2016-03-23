// Copyright (c) 2014-2016 The Dash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef STORMNODE_PAYMENTS_H
#define STORMNODE_PAYMENTS_H

#include <boost/lexical_cast.hpp>

#include "key.h"
#include "main.h"
#include "anon/stormnode/stormnode.h"

using namespace std;

extern CCriticalSection cs_vecPayments;
extern CCriticalSection cs_mapStormnodeBlocks;
extern CCriticalSection cs_mapStormnodePayeeVotes;

class CStormnodePayments;
class CStormnodePaymentWinner;
class CStormnodeBlockPayees;

extern CStormnodePayments stormnodePayments;

#define SNPAYMENTS_SIGNATURES_REQUIRED           10
#define SNPAYMENTS_SIGNATURES_TOTAL              15

void ProcessMessageStormnodePayments(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);
bool IsReferenceNode(CTxIn& vin);
bool IsBlockPayeeValid(const CTransaction& txNew, int nBlockHeight);
std::string GetRequiredPaymentsString(int nBlockHeight);
bool IsBlockValueValid(const CBlock& block, CAmount nExpectedValue);
void FillBlockPayee(CTransaction& txNew, CAmount nFees);

void DumpStormnodePayments();

/** Save Stormnode Payment Data (snpayments.dat)
 */
class CStormnodePaymentDB
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

    CStormnodePaymentDB();
    bool Write(const CStormnodePayments &objToSave);
    ReadResult Read(CStormnodePayments& objToLoad, bool fDryRun = false);
};

class CStormnodePayee
{
public:
    CScript scriptPubKey;
    int nVotes;

    CStormnodePayee() {
        scriptPubKey = CScript();
        nVotes = 0;
    }

    CStormnodePayee(CScript payee, int nVotesIn) {
        scriptPubKey = payee;
        nVotes = nVotesIn;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(scriptPubKey);
        READWRITE(nVotes);
    }
};

// Keep track of votes for payees from stormnodes
class CStormnodeBlockPayees
{
public:
    int nBlockHeight;
    std::vector<CStormnodePayee> vecPayments;

    CStormnodeBlockPayees(){
        nBlockHeight = 0;
        vecPayments.clear();
    }
    CStormnodeBlockPayees(int nBlockHeightIn) {
        nBlockHeight = nBlockHeightIn;
        vecPayments.clear();
    }

    void AddPayee(CScript payeeIn, int nIncrement){
        LOCK(cs_vecPayments);

        BOOST_FOREACH(CStormnodePayee& payee, vecPayments){
            if(payee.scriptPubKey == payeeIn) {
                payee.nVotes += nIncrement;
                return;
            }
        }

        CStormnodePayee c(payeeIn, nIncrement);
        vecPayments.push_back(c);
    }

    bool GetPayee(CScript& payee)
    {
        LOCK(cs_vecPayments);

        int nVotes = -1;
        BOOST_FOREACH(CStormnodePayee& p, vecPayments){
            if(p.nVotes > nVotes){
                payee = p.scriptPubKey;
                nVotes = p.nVotes;
            }
        }

        return (nVotes > -1);
    }

    bool HasPayeeWithVotes(CScript payee, int nVotesReq)
    {
        LOCK(cs_vecPayments);

        BOOST_FOREACH(CStormnodePayee& p, vecPayments){
            if(p.nVotes >= nVotesReq && p.scriptPubKey == payee) return true;
        }

        return false;
    }

    bool IsTransactionValid(const CTransaction& txNew);
    std::string GetRequiredPaymentsString();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(nBlockHeight);
        READWRITE(vecPayments);
    }
};

// for storing the winning payments
class CStormnodePaymentWinner
{
public:
    CTxIn vinStormnode;

    int nBlockHeight;
    CScript payee;
    std::vector<unsigned char> vchSig;

    CStormnodePaymentWinner() {
        nBlockHeight = 0;
        vinStormnode = CTxIn();
        payee = CScript();
    }

    CStormnodePaymentWinner(CTxIn vinIn) {
        nBlockHeight = 0;
        vinStormnode = vinIn;
        payee = CScript();
    }

    uint256 GetHash(){
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << payee;
        ss << nBlockHeight;
        ss << vinStormnode.prevout;

        return ss.GetHash();
    }

    bool Sign(CKey& keyStormnode, CPubKey& pubKeyStormnode);
    bool IsValid(CNode* pnode, std::string& strError);
    bool SignatureValid();
    void Relay();

    void AddPayee(CScript payeeIn){
        payee = payeeIn;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(vinStormnode);
        READWRITE(nBlockHeight);
        READWRITE(payee);
        READWRITE(vchSig);
    }

    std::string ToString()
    {
        std::string ret = "";
        ret += vinStormnode.ToString();
        ret += ", " + boost::lexical_cast<std::string>(nBlockHeight);
        ret += ", " + payee.ToString();
        ret += ", " + boost::lexical_cast<std::string>((int)vchSig.size());
        return ret;
    }
};

//
// Stormnode Payments Class
// Keeps track of who should get paid for which blocks
//

class CStormnodePayments
{
private:
    int nSyncedFromPeer;
    int nLastBlockHeight;

public:
    std::map<uint256, CStormnodePaymentWinner> mapStormnodePayeeVotes;
    std::map<int, CStormnodeBlockPayees> mapStormnodeBlocks;
    std::map<uint256, int> mapStormnodesLastVote; //prevout.hash + prevout.n, nBlockHeight

    CStormnodePayments() {
        nSyncedFromPeer = 0;
        nLastBlockHeight = 0;
    }

    void Clear() {
        LOCK2(cs_mapStormnodeBlocks, cs_mapStormnodePayeeVotes);
        mapStormnodeBlocks.clear();
        mapStormnodePayeeVotes.clear();
    }

    bool AddWinningStormnode(CStormnodePaymentWinner& winner);
    bool ProcessBlock(int nBlockHeight);

    void Sync(CNode* node, int nCountNeeded);
    void CleanPaymentList();
    int LastPayment(CStormnode& sn);

    bool GetBlockPayee(int nBlockHeight, CScript& payee);
    bool IsTransactionValid(const CTransaction& txNew, int nBlockHeight);
    bool IsScheduled(CStormnode& sn, int nNotBlockHeight);

    bool CanVote(COutPoint outStormnode, int nBlockHeight) {
        LOCK(cs_mapStormnodePayeeVotes);

        if(mapStormnodesLastVote.count(outStormnode.hash + outStormnode.n)) {
            if(mapStormnodesLastVote[outStormnode.hash + outStormnode.n] == nBlockHeight) {
                return false;
            }
        }

        //record this stormnode voted
        mapStormnodesLastVote[outStormnode.hash + outStormnode.n] = nBlockHeight;
        return true;
    }

    int GetMinStormnodePaymentsProto();
    void ProcessMessageStormnodePayments(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);
    std::string GetRequiredPaymentsString(int nBlockHeight);
    void FillBlockPayee(CTransaction& txNew, CAmount nFees);
    std::string ToString() const;
    int GetOldestBlock();
    int GetNewestBlock();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(mapStormnodePayeeVotes);
        READWRITE(mapStormnodeBlocks);
    }
};



#endif
