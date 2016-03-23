// Copyright (c) 2014-2016 The Dash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SANDSTORM_H
#define SANDSTORM_H

#include "sync.h"
#include "anon/stormnode/activestormnode.h"
#include "anon/stormnode/stormnodeman.h"

class CTxIn;
class CSandstormPool;
class CSandStormSigner;
class CSandstormQueue;
class CSandstormBroadcastTx;

static const int64_t DENOMS_COUNT_MAX = 100;

// pool states for mixing
#define POOL_STATUS_UNKNOWN                    0 // waiting for update
#define POOL_STATUS_IDLE                       1 // waiting for update
#define POOL_STATUS_QUEUE                      2 // waiting in a queue
#define POOL_STATUS_ACCEPTING_ENTRIES          3 // accepting entries
#define POOL_STATUS_FINALIZE_TRANSACTION       4 // storm node will broadcast what it accepted
#define POOL_STATUS_SIGNING                    5 // check inputs/outputs, sign final tx
#define POOL_STATUS_TRANSMISSION               6 // transmit transaction
#define POOL_STATUS_ERROR                      7 // error
#define POOL_STATUS_SUCCESS                    8 // success

// status update message constants
#define STORMNODE_ACCEPTED                    1
#define STORMNODE_REJECTED                    0
#define STORMNODE_RESET                       -1

#define SANDSTORM_QUEUE_TIMEOUT                 30
#define SANDSTORM_SIGNING_TIMEOUT               15

// used for anonymous relaying of inputs/outputs/sigs
#define SANDSTORM_RELAY_IN                 1
#define SANDSTORM_RELAY_OUT                2
#define SANDSTORM_RELAY_SIG                3

extern CSandstormPool sandStormPool;
extern CSandStormSigner sandStormSigner;
extern std::vector<CSandstormQueue> vecSandstormQueue;
extern std::string strStormNodePrivKey;
extern map<uint256, CSandstormBroadcastTx> mapSandstormBroadcastTxes;
extern CActiveStormnode activeStormnode;

/** Holds an Sandstorm input
 */
class CTxSSIn : public CTxIn
{
public:
    bool fHasSig; // flag to indicate if signed
    int nSentTimes; //times we've sent this anonymously

    CTxSSIn(const CTxIn& in)
    {
        prevout = in.prevout;
        scriptSig = in.scriptSig;
        prevPubKey = in.prevPubKey;
        nSequence = in.nSequence;
        nSentTimes = 0;
        fHasSig = false;
    }
};

/** Holds an Sandstorm output
 */
class CTxSSOut : public CTxOut
{
public:
    int nSentTimes; //times we've sent this anonymously

    CTxSSOut(const CTxOut& out)
    {
        nValue = out.nValue;
        nRounds = out.nRounds;
        scriptPubKey = out.scriptPubKey;
        nSentTimes = 0;
    }
};

// A clients transaction in the sandstorm pool
class CSandStormEntry
{
public:
    bool isSet;
    std::vector<CTxSSIn> sev;
    std::vector<CTxSSOut> vout;
    CAmount amount;
    CTransaction collateral;
    CTransaction txSupporting;
    int64_t addedTime; // time in UTC milliseconds

    CSandStormEntry()
    {
        isSet = false;
        collateral = CTransaction();
        amount = 0;
    }

    /// Add entries to use for Sandstorm
    bool Add(const std::vector<CTxIn> vinIn, CAmount amountIn, const CTransaction collateralIn, const std::vector<CTxOut> voutIn)
    {
        if(isSet){return false;}

        BOOST_FOREACH(const CTxIn& in, vinIn)
            sev.push_back(in);

        BOOST_FOREACH(const CTxOut& out, voutIn)
            vout.push_back(out);

        amount = amountIn;
        collateral = collateralIn;
        isSet = true;
        addedTime = GetTime();

        return true;
    }

    bool AddSig(const CTxIn& vin)
    {
        BOOST_FOREACH(CTxSSIn& s, sev) {
            if(s.prevout == vin.prevout && s.nSequence == vin.nSequence){
                if(s.fHasSig){return false;}
                s.scriptSig = vin.scriptSig;
                s.prevPubKey = vin.prevPubKey;
                s.fHasSig = true;

                return true;
            }
        }

        return false;
    }

    bool IsExpired()
    {
        return (GetTime() - addedTime) > SANDSTORM_QUEUE_TIMEOUT;// 120 seconds
    }
};


/**
 * A currently inprogress Sandstorm merge and denomination information
 */
class CSandstormQueue
{
public:
    CTxIn vin;
    int64_t time;
    int nDenom;
    bool ready; //ready for submit
    std::vector<unsigned char> vchSig;

    CSandstormQueue()
    {
        nDenom = 0;
        vin = CTxIn();
        time = 0;
        vchSig.clear();
        ready = false;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(nDenom);
        READWRITE(vin);
        READWRITE(time);
        READWRITE(ready);
        READWRITE(vchSig);
    }

    bool GetAddress(CService &addr)
    {
        CStormnode* psn = snodeman.Find(vin);
        if(psn != NULL)
        {
            addr = psn->addr;
            return true;
        }
        return false;
    }

    /// Get the protocol version
    bool GetProtocolVersion(int &protocolVersion)
    {
        CStormnode* psn = snodeman.Find(vin);
        if(psn != NULL)
        {
            protocolVersion = psn->protocolVersion;
            return true;
        }
        return false;
    }

    /** Sign this Sandstorm transaction
     *  \return true if all conditions are met:
     *     1) we have an active Stormnode,
     *     2) we have a valid Stormnode private key,
     *     3) we signed the message successfully, and
     *     4) we verified the message successfully
     */
    bool Sign();

    bool Relay();

    /// Is this Sandstorm expired?
    bool IsExpired()
    {
        return (GetTime() - time) > SANDSTORM_QUEUE_TIMEOUT;// 120 seconds
    }

    /// Check if we have a valid Stormnode address
    bool CheckSignature();

};

/** Helper class to store Sandstorm transaction (tx) information.
 */
class CSandstormBroadcastTx
{
public:
    CTransaction tx;
    CTxIn vin;
    vector<unsigned char> vchSig;
    int64_t sigTime;
};

/** Helper object for signing and checking signatures
 */
class CSandStormSigner
{
public:
    /// Is the inputs associated with this public key? (and there is 10000 DARKSILK - checking if valid stormnode)
    bool IsVinAssociatedWithPubkey(CTxIn& vin, CPubKey& pubkey);
    /// Set the private/public key values, returns true if successful
    bool SetKey(std::string strSecret, std::string& errorMessage, CKey& key, CPubKey& pubkey);
    /// Sign the message, returns true if successful
    bool SignMessage(std::string strMessage, std::string& errorMessage, std::vector<unsigned char>& vchSig, CKey key);
    /// Verify the message, returns true if succcessful
    bool VerifyMessage(CPubKey pubkey, std::vector<unsigned char>& vchSig, std::string strMessage, std::string& errorMessage);
};

/** Used to keep track of current status of Sandstorm pool
 */
class CSandstormPool
{
private:
    mutable CCriticalSection cs_sandstorm;

    std::vector<CSandStormEntry> entries; // Stormnode/clients entries
    CMutableTransaction finalTransaction; // the finalized transaction ready for signing

    int64_t lastTimeChanged; // last time the 'state' changed, in UTC milliseconds
    unsigned int state; // should be one of the POOL_STATUS_XXX values
    unsigned int entriesCount;

    unsigned int countEntriesAccepted;

    std::vector<CTxIn> lockedCoins;
    bool unitTest;
    int sessionID;
    int sessionUsers; //N Users have said they'll join
    bool sessionFoundStormnode; //If we've found a compatible Stormnode
    std::vector<CTransaction> vecSessionCollateral;

    CMutableTransaction txCollateral;
    int64_t lastNewBlock;
    std::vector<int64_t> sandStormDenominationsSkipped;

public:
    std::string lastMessage;
    unsigned int lastEntryAccepted;
    int cachedLastSuccess;
    int minBlockSpacing; //required blocks between mixes
    //debugging data
    std::string strAutoDenomResult;
    enum messages {
        ERR_ALREADY_HAVE,
        ERR_DENOM,
        ERR_ENTRIES_FULL,
        ERR_EXISTING_TX,
        ERR_FEES,
        ERR_INVALID_COLLATERAL,
        ERR_INVALID_INPUT,
        ERR_INVALID_SCRIPT,
        ERR_INVALID_TX,
        ERR_MAXIMUM,
        ERR_SN_LIST,
        ERR_MODE,
        ERR_NON_STANDARD_PUBKEY,
        ERR_NOT_A_SN,
        ERR_QUEUE_FULL,
        ERR_RECENT,
        ERR_SESSION,
        ERR_MISSING_TX,
        ERR_VERSION,
        MSG_NOERR,
        MSG_SUCCESS,
        MSG_ENTRIES_ADDED
    };

    // where collateral should be made out to
    CScript collateralPubKey;

    CStormnode* pSubmittedToStormnode;
    int sessionDenom; //Users must submit an denom matching this
    int cachedNumBlocks; //used for the overview screen

    CSandstormPool()
    {
        /* Sandstorm uses collateral addresses to trust parties entering the pool
            to behave themselves. If they don't it takes their money. */

        cachedLastSuccess = 0;
        cachedNumBlocks = std::numeric_limits<int>::max();
        unitTest = false;
        txCollateral = CMutableTransaction();
        minBlockSpacing = 0;
        lastNewBlock = 0;

        SetNull();
    }

    /** Process a Sandstorm message using the Sandstorm protocol
     * \param pfrom
     * \param strCommand lower case command string; valid values are:
     *        Command  | Description
     *        -------- | -----------------
     *        ssa      | Sandstorm Acceptable
     *        ssc      | Sandstorm Complete
     *        ssf      | Sandstorm Final tx
     *        ssi      | Sandstorm vIn
     *        ssq      | Sandstorm Queue
     *        sss      | Sandstorm Signal Final Tx
     *        sssu     | Sandstorm status update
     *        sssub    | Sandstorm Subscribe To
     * \param vRecv
     */
    void ProcessMessageSandstorm(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);

    void InitCollateralAddress(){
        SetCollateralAddress(Params().SandstormPoolDummyAddress());
    }

    void ClearSkippedDenominations() {
        sandStormDenominationsSkipped.clear();
    }

    bool IsDenomSkipped(int64_t denom) {
        BOOST_FOREACH(int64_t d, sandStormDenominationsSkipped) {
            if (d == denom) {
                return true;
            }
        }
        return false;
    }

    void InitDenominations() {
        sandStormDenominations.clear();
    /* Denominations
       A note about convertability. Within Sandstorm pools, each denomination
       is convertable to another.
       For example:
       1DRK+1000 == (.1DRK+100)*10
       10DRK+10000 == (1DRK+1000)*10
    */
    sandStormDenominations.push_back( (10000       * COIN)+10000000 );
    sandStormDenominations.push_back( (1000        * COIN)+1000000 );
    sandStormDenominations.push_back( (100         * COIN)+100000 );
    sandStormDenominations.push_back( (10          * COIN)+10000 );
    sandStormDenominations.push_back( (1           * COIN)+1000 );
    sandStormDenominations.push_back( (.1          * COIN)+100 );
    /* Disabled till we need them
    sandStormDenominations.push_back( (.01      * COIN)+10 );
    sandStormDenominations.push_back( (.001     * COIN)+1 );
    */
    }


    void SetMinBlockSpacing(int minBlockSpacingIn){
        minBlockSpacing = minBlockSpacingIn;
    }

    bool SetCollateralAddress(std::string strAddress);
    void Reset();
    void SetNull();

    void UnlockCoins();

    bool IsNull() const
    {
        return state == POOL_STATUS_ACCEPTING_ENTRIES && entries.empty();
    }

    int GetState() const
    {
        return state;
    }

    std::string GetStatus();

    int GetEntriesCount() const
    {
        return entries.size();
    }

    /// Get the time the last entry was accepted (time in UTC milliseconds)
    int GetLastEntryAccepted() const
    {
        return lastEntryAccepted;
    }

    /// Get the count of the accepted entries
    int GetCountEntriesAccepted() const
    {
        return countEntriesAccepted;
    }

    // Set the 'state' value, with some logging and capturing when the state changed
    void UpdateState(unsigned int newState)
    {
        if (fStormNode && (newState == POOL_STATUS_ERROR || newState == POOL_STATUS_SUCCESS)){
            LogPrint("sandstorm", "CSandstormPool::UpdateState() - Can't set state to ERROR or SUCCESS as a Stormnode. \n");
            return;
        }

        LogPrintf("CSandstormPool::UpdateState() == %d | %d \n", state, newState);
        if(state != newState){
            lastTimeChanged = GetTimeMillis();
            if(fStormNode) {
                RelayStatus(sandStormPool.sessionID, sandStormPool.GetState(), sandStormPool.GetEntriesCount(), STORMNODE_RESET);
            }
        }
        state = newState;
    }

    /// Get the maximum number of transactions for the pool
    int GetMaxPoolTransactions()
    {
        return Params().PoolMaxTransactions();
    }

    /// Do we have enough users to take entries?
    bool IsSessionReady(){
        return sessionUsers >= GetMaxPoolTransactions();
    }

    /// Are these outputs compatible with other client in the pool?
    bool IsCompatibleWithEntries(std::vector<CTxOut>& vout);

    /// Is this amount compatible with other client in the pool?
    bool IsCompatibleWithSession(CAmount nAmount, CTransaction txCollateral, int &errorID);

    /// Passively run Sandstorm in the background according to the configuration in settings (only for QT)
    bool DoAutomaticDenominating(bool fDryRun=false);
    bool PrepareSandstormDenominate();

    /// Check for process in Sandstorm
    void Check();
    void CheckFinalTransaction();
    /// Charge fees to bad actors (Charge clients a fee if they're abusive)
    void ChargeFees();
    /// Rarely charge fees to pay miners
    void ChargeRandomFees();
    void CheckTimeout();
    void CheckForCompleteQueue();
    /// Check to make sure a signature matches an input in the pool
    bool SignatureValid(const CScript& newSig, const CTxIn& newVin);
    /// If the collateral is valid given by a client
    bool IsCollateralValid(const CTransaction& txCollateral);
    /// Add a clients entry to the pool
    bool AddEntry(const std::vector<CTxIn>& newInput, const CAmount& nAmount, const CTransaction& txCollateral, const std::vector<CTxOut>& newOutput, int& errorID);
    /// Add signature to a vin
    bool AddScriptSig(const CTxIn& newVin);
    /// Check that all inputs are signed. (Are all inputs signed?)
    bool SignaturesComplete();
    /// As a client, send a transaction to a Stormnode to start the denomination process
    void SendSandstormDenominate(std::vector<CTxIn>& vin, std::vector<CTxOut>& vout, CAmount amount);
    /// Get Stormnode updates about the progress of Sandstorm
    bool StatusUpdate(int newState, int newEntriesCount, int newAccepted, int &errorID, int newSessionID=0);

    /// As a client, check and sign the final transaction
    bool SignFinalTransaction(CTransaction& finalTransactionNew, CNode* node);

    /// Get the last valid block hash for a given modulus
    bool GetLastValidBlockHash(uint256& hash, int mod=1, int nBlockHeight=0);
    /// Process a new block
    void NewBlock();
    void CompletedTransaction(bool error, int errorID);
    void ClearLastMessage();

    /// Split up large inputs or make fee sized inputs
    bool MakeCollateralAmounts();
    bool CreateDenominated(CAmount nTotalValue);

    /// Get the denominations for a list of outputs (returns a bitshifted integer)
    int GetDenominations(const std::vector<CTxOut>& vout, bool fSingleRandomDenom = false);
    int GetDenominations(const std::vector<CTxSSOut>& vout);

    void GetDenominationsToString(int nDenom, std::string& strDenom);

    /// Get the denominations for a specific amount of DarkSilks.
    int GetDenominationsByAmount(CAmount nAmount, int nDenomTarget=0); // is not used anymore?
    int GetDenominationsByAmounts(std::vector<CAmount>& vecAmount);

    std::string GetMessageByID(int messageID);

    //
    // Relay Sandstorm Messages
    //

    void RelayFinalTransaction(const int sessionID, const CTransaction& txNew);
    void RelaySignaturesAnon(std::vector<CTxIn>& vin);
    void RelayInAnon(std::vector<CTxIn>& vin, std::vector<CTxOut>& vout);
    void RelayIn(const std::vector<CTxSSIn>& vin, const CAmount& nAmount, const CTransaction& txCollateral, const std::vector<CTxSSOut>& vout);
    void RelayStatus(const int sessionID, const int newState, const int newEntriesCount, const int newAccepted, const int errorID=MSG_NOERR);
    void RelayCompletedTransaction(const int sessionID, const bool error, const int errorID);
};

void ThreadCheckSandStormPool();

#endif
