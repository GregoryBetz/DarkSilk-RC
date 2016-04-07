// Copyright (c) 2014-2016 The Dash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef STORMNODE_H
#define STORMNODE_H

#include "sync.h"
#include "networking/net.h"
#include "key.h"
#include "elements/util/util.h"
#include "base58.h"
#include "main.h"
#include "reward.h"
#include "timedata.h"

static const int STORMNODE_MIN_CONFIRMATIONS = 10;
static const int STORMNODE_MIN_SNP_SECONDS = (10*60);
static const int STORMNODE_MIN_SNB_SECONDS = (5*60);
static const int STORMNODE_PING_SECONDS = (1*60);
static const int STORMNODE_EXPIRATION_SECONDS = (65*60);
static const int STORMNODE_REMOVAL_SECONDS = (75*60);
static const int STORMNODE_CHECK_SECONDS = 5;

using namespace std;

class CStormnode;
class CStormnodeBroadcast;
class CStormnodePing;
extern map<int64_t, uint256> mapCacheBlockHashes;

bool GetBlockHash(uint256& hash, int nBlockHeight);


//
// The Stormnode Ping Class : Contains a different serialize method for sending pings from stormnodes throughout the network
//

class CStormnodePing
{
public:

    CTxIn vin;
    uint256 blockHash;
    int64_t sigTime; //snb message times
    std::vector<unsigned char> vchSig;
    //removed stop

    CStormnodePing();
    CStormnodePing(CTxIn& newVin);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(vin);
        READWRITE(blockHash);
        READWRITE(sigTime);
        READWRITE(vchSig);
    }

    bool CheckAndUpdate(int& nDos, bool fRequireEnabled = true);
    bool Sign(CKey& keyStormnode, CPubKey& pubKeyStormnode);
    void Relay();

    uint256 GetHash(){
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << vin;
        ss << sigTime;
        return ss.GetHash();
    }

    void swap(CStormnodePing& first, CStormnodePing& second) // nothrow
    {
        // enable ADL (not necessary in our case, but good practice)
        using std::swap;

        // by swapping the members of two classes,
        // the two classes are effectively swapped
        swap(first.vin, second.vin);
        swap(first.blockHash, second.blockHash);
        swap(first.sigTime, second.sigTime);
        swap(first.vchSig, second.vchSig);
    }

    CStormnodePing& operator=(CStormnodePing from)
    {
        swap(*this, from);
        return *this;
    }
    friend bool operator==(const CStormnodePing& a, const CStormnodePing& b)
    {
        return a.vin == b.vin && a.blockHash == b.blockHash;
    }
    friend bool operator!=(const CStormnodePing& a, const CStormnodePing& b)
    {
        return !(a == b);
    }

};


//
// The Stormnode Class. For managing the Sandstorm process. It contains the input of the 10000DRKSLK, signature to prove
// it's the one who own that ip address and code for calculating the payment election.
//
class CStormnode
{
private:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;
    int64_t lastTimeChecked;
public:
    enum state {
        STORMNODE_PRE_ENABLED,
        STORMNODE_ENABLED,
        STORMNODE_EXPIRED,
        STORMNODE_VIN_SPENT,
        STORMNODE_REMOVE,
        STORMNODE_POS_ERROR
    };

    CTxIn vin;
    CService addr;
    CPubKey pubkey;
    CPubKey pubkey2;
    std::vector<unsigned char> sig;
    int activeState;
    int64_t sigTime; //snb message time
    int cacheInputAge;
    int cacheInputAgeBlock;
    bool unitTest;
    bool allowFreeTx;
    int protocolVersion;
    int64_t nLastSsq; //the ssq count from the last ssq broadcast of this node
    int nScanningErrorCount;
    int nLastScanningErrorBlockHeight;
    CStormnodePing lastPing;

    CStormnode();
    CStormnode(const CStormnode& other);
    CStormnode(const CStormnodeBroadcast& snb);


    void swap(CStormnode& first, CStormnode& second) // nothrow
    {
        // enable ADL (not necessary in our case, but good practice)
        using std::swap;

        // by swapping the members of two classes,
        // the two classes are effectively swapped
        swap(first.vin, second.vin);
        swap(first.addr, second.addr);
        swap(first.pubkey, second.pubkey);
        swap(first.pubkey2, second.pubkey2);
        swap(first.sig, second.sig);
        swap(first.activeState, second.activeState);
        swap(first.sigTime, second.sigTime);
        swap(first.lastPing, second.lastPing);
        swap(first.cacheInputAge, second.cacheInputAge);
        swap(first.cacheInputAgeBlock, second.cacheInputAgeBlock);
        swap(first.unitTest, second.unitTest);
        swap(first.allowFreeTx, second.allowFreeTx);
        swap(first.protocolVersion, second.protocolVersion);
        swap(first.nLastSsq, second.nLastSsq);
        swap(first.nScanningErrorCount, second.nScanningErrorCount);
        swap(first.nLastScanningErrorBlockHeight, second.nLastScanningErrorBlockHeight);
    }

    CStormnode& operator=(CStormnode from)
    {
        swap(*this, from);
        return *this;
    }
    friend bool operator==(const CStormnode& a, const CStormnode& b)
    {
        return a.vin == b.vin;
    }
    friend bool operator!=(const CStormnode& a, const CStormnode& b)
    {
        return !(a.vin == b.vin);
    }

    uint256 CalculateScore(int mod=1, int64_t nBlockHeight=0);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        LOCK(cs);

        READWRITE(vin);
        READWRITE(addr);
        READWRITE(pubkey);
        READWRITE(pubkey2);
        READWRITE(sig);
        READWRITE(sigTime);
        READWRITE(protocolVersion);
        READWRITE(activeState);
        READWRITE(lastPing);
        READWRITE(cacheInputAge);
        READWRITE(cacheInputAgeBlock);
        READWRITE(unitTest);
        READWRITE(allowFreeTx);
        READWRITE(nLastSsq);
        READWRITE(nScanningErrorCount);
        READWRITE(nLastScanningErrorBlockHeight);
    }

    int64_t SecondsSincePayment();

    bool UpdateFromNewBroadcast(CStormnodeBroadcast& snb);

    inline uint64_t SliceHash(uint256& hash, int slice)
    {
        uint64_t n = 0;
        memcpy(&n, &hash+slice*64, 64);
        return n;
    }

    void Check(bool forceCheck = false);

    bool IsBroadcastedWithin(int seconds)
    {
        return (GetAdjustedTime() - sigTime) < seconds;
    }

    bool IsPingedWithin(int seconds, int64_t now = -1)
    {
        now == -1 ? now = GetAdjustedTime() : now;

        return (lastPing == CStormnodePing())
                ? false
                : now - lastPing.sigTime < seconds;
    }

    void Disable()
    {
        sigTime = 0;
        lastPing = CStormnodePing();
    }

    bool IsEnabled()
    {
        return activeState == STORMNODE_ENABLED;
    }

    bool IsPreEnabled()
    {
        return activeState == STORMNODE_PRE_ENABLED;
    }

    int GetStormnodeInputAge()
    {   
        LOCK(cs_main);
        if(pindexBest == NULL) return 0;

        if(cacheInputAge == 0){
            cacheInputAge = GetInputAge(vin);
            cacheInputAgeBlock = pindexBest->nHeight;
        }

        return cacheInputAge + (pindexBest->nHeight - cacheInputAgeBlock);
    }

    std::string Status() {
        std::string strStatus = "unknown";

        if(activeState == CStormnode::STORMNODE_PRE_ENABLED) strStatus = "PRE_ENABLED";
        if(activeState == CStormnode::STORMNODE_ENABLED) strStatus     = "ENABLED";
        if(activeState == CStormnode::STORMNODE_EXPIRED) strStatus     = "EXPIRED";
        if(activeState == CStormnode::STORMNODE_VIN_SPENT) strStatus   = "VIN_SPENT";
        if(activeState == CStormnode::STORMNODE_REMOVE) strStatus      = "REMOVE";
        if(activeState == CStormnode::STORMNODE_POS_ERROR) strStatus   = "POS_ERROR";

        return strStatus;
    }

    int64_t GetLastPaid();

};


//
// The Stormnode Broadcast Class : Contains a different serialize method for sending stormnodes through the network
//

class CStormnodeBroadcast : public CStormnode
{
public:
    CStormnodeBroadcast();
    CStormnodeBroadcast(CService newAddr, CTxIn newVin, CPubKey newPubkey, CPubKey newPubkey2, int protocolVersionIn);
    CStormnodeBroadcast(const CStormnode& sn);

    bool CheckAndUpdate(int& nDoS);
    bool CheckInputsAndAdd(int& nDos);
    bool Sign(CKey& keyCollateralAddress);
    void Relay();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(vin);
        READWRITE(addr);
        READWRITE(pubkey);
        READWRITE(pubkey2);
        READWRITE(sig);
        READWRITE(sigTime);
        READWRITE(protocolVersion);
        READWRITE(lastPing);
        READWRITE(nLastSsq);
    }

    uint256 GetHash(){
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << sigTime;
        ss << pubkey;
        return ss.GetHash();
    }

};

#endif
