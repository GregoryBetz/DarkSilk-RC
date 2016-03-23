// Copyright (c) 2014-2016 The Dash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef STORMNODEMAN_H
#define STORMNODEMAN_H

#include "sync.h"
#include "net.h"
#include "key.h"
#include "util.h"
#include "base58.h"
#include "main.h"
#include "anon/stormnode/stormnode.h"

static const unsigned int STORMNODES_DUMP_SECONDS = (15*60);// 15 Minutes
static const unsigned int STORMNODES_SSEG_SECONDS = (1*60*60);// 1 Hour

using namespace std;

class CStormnodeMan;

extern CStormnodeMan snodeman;
void DumpStormnodes();

/** Access to the SN database (sncache.dat)
 */
class CStormnodeDB
{
private:
    boost::filesystem::path pathSN;
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

    CStormnodeDB();
    bool Write(const CStormnodeMan &snodemanToSave);
    ReadResult Read(CStormnodeMan& snodemanToLoad, bool fDryRun = false);
};

class CStormnodeMan
{
private:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

    // critical section to protect the inner data structures specifically on messaging
    mutable CCriticalSection cs_process_message;

    // map to hold all SNs
    std::vector<CStormnode> vStormnodes;
    // who's asked for the Stormnode list and the last time
    std::map<CNetAddr, int64_t> mAskedUsForStormnodeList;
    // who we asked for the Stormnode list and the last time
    std::map<CNetAddr, int64_t> mWeAskedForStormnodeList;
    // which Stormnodes we've asked for
    std::map<COutPoint, int64_t> mWeAskedForStormnodeListEntry;

public:
    // Keep track of all broadcasts I've seen
    map<uint256, CStormnodeBroadcast> mapSeenStormnodeBroadcast;
    // Keep track of all pings I've seen
    map<uint256, CStormnodePing> mapSeenStormnodePing;

    // keep track of ssq count to prevent stormnodes from gaining sandstorm queue
    int64_t nSsqCount;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        LOCK(cs);
        READWRITE(vStormnodes);
        READWRITE(mAskedUsForStormnodeList);
        READWRITE(mWeAskedForStormnodeList);
        READWRITE(mWeAskedForStormnodeListEntry);
        READWRITE(nSsqCount);

        READWRITE(mapSeenStormnodeBroadcast);
        READWRITE(mapSeenStormnodePing);
    }

    CStormnodeMan();
    CStormnodeMan(CStormnodeMan& other);

    /// Add an entry
    bool Add(CStormnode &sn);

    /// Ask (source) node for snb
    void AskForSN(CNode *pnode, CTxIn &vin);

    /// Check all Stormnodes
    void Check();

    /// Check all Stormnodes and remove inactive
    void CheckAndRemove(bool forceExpiredRemoval = false);

    /// Clear Stormnode vector
    void Clear();

    int CountEnabled(int protocolVersion = -1);

    void SsegUpdate(CNode* pnode);

    /// Find an entry
    CStormnode* Find(const CScript &payee);
    CStormnode* Find(const CTxIn& vin);
    CStormnode* Find(const CPubKey& pubKeyStormnode);

    /// Find an entry in the stormnode list that is next to be paid
    CStormnode* GetNextStormnodeInQueueForPayment(int nBlockHeight, bool fFilterSigTime, int& nCount);

    /// Find a random entry
    CStormnode* FindRandomNotInVec(std::vector<CTxIn> &vecToExclude, int protocolVersion = -1);

    /// Get the current winner for this block
    CStormnode* GetCurrentStormNode(int mod=1, int64_t nBlockHeight=0, int minProtocol=0);

    std::vector<CStormnode> GetFullStormnodeVector() { Check(); return vStormnodes; }

    std::vector<pair<int, CStormnode> > GetStormnodeRanks(int64_t nBlockHeight, int minProtocol=0);
    int GetStormnodeRank(const CTxIn &vin, int64_t nBlockHeight, int minProtocol=0, bool fOnlyActive=true);
    CStormnode* GetStormnodeByRank(int nRank, int64_t nBlockHeight, int minProtocol=0, bool fOnlyActive=true);

    void ProcessStormnodeConnections();

    void ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);

    /// Return the number of (unique) Stormnodes
    int size() { return vStormnodes.size(); }

    std::string ToString() const;

    void Remove(CTxIn vin);

};

#endif
