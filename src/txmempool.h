// Copyright (c) 2009-2016 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Developers
// Copyright (c) 2015-2016 Silk Network
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef DARKSILK_TXMEMPOOL_H
#define DARKSILK_TXMEMPOOL_H

#include <boost/circular_buffer.hpp>
#include "boost/multi_index_container.hpp"
#include "boost/multi_index/ordered_index.hpp"

#include "amount.h"
#include "coins.h"
#include "primitives/transaction.h"
#include "consensus/validation.h"
#include "sync.h"

inline double AllowFreeThreshold()
{
    return COIN * 576 / 250;
}

inline bool AllowFree(double dPriority)
{
    // Large (in bytes) low-priority (new, small-coin) transactions
    // need a fee.
    return dPriority > AllowFreeThreshold();
}

///! CTxMemPool stores these:
class CTxMemPoolEntry
{
private:
    CTransaction tx;
    CAmount nFee; //! Cached to avoid expensive parent-transaction lookups
    size_t nTxSize; //! ... and avoid recomputing tx size
    size_t nModSize; //! ... and modified size for priority
    int64_t nTime; //! Local time when entering the mempool
    double dPriority; //! Priority when entering the mempool
    unsigned int nHeight; //! Chain height when entering the mempool
    // Information about descendants of this transaction that are in the
    // mempool; if we remove this transaction we must remove all of these
    // descendants as well.  if nCountWithDescendants is 0, treat this entry as
    // dirty, and nSizeWithDescendants and nModFeesWithDescendants will not be
    // correct.
    uint64_t nCountWithDescendants; //! number of descendant transactions
    uint64_t nSizeWithDescendants;  //! ... and size
    CAmount nModFeesWithDescendants;  //! ... and total fees (all including us)
    CAmount feeDelta; //! Used for determining the priority of the transaction for mining in a block

public:
    CTxMemPoolEntry(const CTransaction& _tx, const CAmount& _nFee,
                    int64_t _nTime, double _dPriority, unsigned int _nHeight);
    CTxMemPoolEntry();
    CTxMemPoolEntry(const CTxMemPoolEntry& other);

    const CTransaction& GetTx() const { return this->tx; }
    double GetPriority(unsigned int currentHeight) const;
    CAmount GetFee() const { return nFee; }
    size_t GetTxSize() const { return nTxSize; }
    int64_t GetTime() const { return nTime; }
    unsigned int GetHeight() const { return nHeight; }

    uint64_t GetCountWithDescendants() const { return nCountWithDescendants; }
    uint64_t GetSizeWithDescendants() const { return nSizeWithDescendants; }
    CAmount GetModFeesWithDescendants() const { return nModFeesWithDescendants; }

    CAmount GetModifiedFee() const { return nFee + feeDelta; }

    // Updates the fee delta used for mining priority score, and the
    // modified fees with descendants.
    void UpdateFeeDelta(CAmount feeDelta);

};

struct update_fee_delta
{
    update_fee_delta(CAmount _feeDelta) : feeDelta(_feeDelta) { }

    void operator() (CTxMemPoolEntry &e) { e.UpdateFeeDelta(feeDelta); }

private:
    CAmount feeDelta;
};

///! Keep track of fee/priority for transactions confirmed within N blocks
class CBlockAverage
{
private:
    boost::circular_buffer<CFeeRate> feeSamples;
    boost::circular_buffer<double> prioritySamples;

    template<typename T> std::vector<T> buf2vec(boost::circular_buffer<T> buf) const
    {
        std::vector<T> vec(buf.begin(), buf.end());
        return vec;
    }

public:
    CBlockAverage() : feeSamples(100), prioritySamples(100) { }

    void RecordFee(const CFeeRate& feeRate) {
        feeSamples.push_back(feeRate);
    }

    void RecordPriority(double priority) {
        prioritySamples.push_back(priority);
    }

    size_t FeeSamples() const { return feeSamples.size(); }
    size_t GetFeeSamples(std::vector<CFeeRate>& insertInto) const
    {
        BOOST_FOREACH(const CFeeRate& f, feeSamples)
            insertInto.push_back(f);
        return feeSamples.size();
    }
    size_t PrioritySamples() const { return prioritySamples.size(); }
    size_t GetPrioritySamples(std::vector<double>& insertInto) const
    {
        BOOST_FOREACH(double d, prioritySamples)
            insertInto.push_back(d);
        return prioritySamples.size();
    }

    /**
     * Used as belt-and-suspenders check when reading to detect
     * file corruption
     */
    static bool AreSane(const CFeeRate fee, const CFeeRate& minRelayFee)
    {
        if (fee < CFeeRate(0))
            return false;
        if (fee.GetFeePerK() > minRelayFee.GetFeePerK() * 10000)
            return false;
        return true;
    }
    static bool AreSane(const std::vector<CFeeRate>& vecFee, const CFeeRate& minRelayFee)
    {
        BOOST_FOREACH(CFeeRate fee, vecFee)
        {
            if (!AreSane(fee, minRelayFee))
                return false;
        }
        return true;
    }
    static bool AreSane(const double priority)
    {
        return priority >= 0;
    }
    static bool AreSane(const std::vector<double> vecPriority)
    {
        BOOST_FOREACH(double priority, vecPriority)
        {
            if (!AreSane(priority))
                return false;
        }
        return true;
    }

    void Write(CAutoFile& fileout) const
    {
        std::vector<CFeeRate> vecFee = buf2vec(feeSamples);
        fileout << vecFee;
        std::vector<double> vecPriority = buf2vec(prioritySamples);
        fileout << vecPriority;
    }

    void Read(CAutoFile& filein, const CFeeRate& minRelayFee) {
        std::vector<CFeeRate> vecFee;
        filein >> vecFee;
        if (AreSane(vecFee, minRelayFee))
            feeSamples.insert(feeSamples.end(), vecFee.begin(), vecFee.end());
        else
            throw runtime_error("Corrupt fee value in estimates file.");
        std::vector<double> vecPriority;
        filein >> vecPriority;
        if (AreSane(vecPriority))
            prioritySamples.insert(prioritySamples.end(), vecPriority.begin(), vecPriority.end());
        else
            throw runtime_error("Corrupt priority value in estimates file.");
        if (feeSamples.size() + prioritySamples.size() > 0)
            LogPrint("estimatefee", "Read %d fee samples and %d priority samples\n",
                     feeSamples.size(), prioritySamples.size());
    }
};

class CMinerPolicyEstimator
{
private:
    /**
     * Records observed averages transactions that confirmed within one block, two blocks,
     * three blocks etc.
     */
    std::vector<CBlockAverage> history;
    std::vector<CFeeRate> sortedFeeSamples;
    std::vector<double> sortedPrioritySamples;

    int nBestSeenHeight;

    /**
     * nBlocksAgo is 0 based, i.e. transactions that confirmed in the highest seen block are
     * nBlocksAgo == 0, transactions in the block before that are nBlocksAgo == 1 etc.
     */
    void seenTxConfirm(const CFeeRate& feeRate, const CFeeRate& minRelayFee, double dPriority, int nBlocksAgo)
    {
        // Last entry records "everything else".
        int nBlocksTruncated = min(nBlocksAgo, (int) history.size() - 1);
        assert(nBlocksTruncated >= 0);

        // We need to guess why the transaction was included in a block-- either
        // because it is high-priority or because it has sufficient fees.
        bool sufficientFee = (feeRate > minRelayFee);
        bool sufficientPriority = AllowFree(dPriority);
        const char* assignedTo = "unassigned";
        if (sufficientFee && !sufficientPriority && CBlockAverage::AreSane(feeRate, minRelayFee))
        {
            history[nBlocksTruncated].RecordFee(feeRate);
            assignedTo = "fee";
        }
        else if (sufficientPriority && !sufficientFee && CBlockAverage::AreSane(dPriority))
        {
            history[nBlocksTruncated].RecordPriority(dPriority);
            assignedTo = "priority";
        }
        else
        {
            // Neither or both fee and priority sufficient to get confirmed:
            // don't know why they got confirmed.
        }
        LogPrint("estimatefee", "Seen TX confirm: %s : %s fee/%g priority, took %d blocks\n",
                 assignedTo, feeRate.ToString(), dPriority, nBlocksAgo);
    }

public:
    CMinerPolicyEstimator(int nEntries) : nBestSeenHeight(0)
    {
        history.resize(nEntries);
    }

    void seenBlock(const std::vector<CTxMemPoolEntry>& entries, int nBlockHeight, const CFeeRate minRelayFee)
    {
        if (nBlockHeight <= nBestSeenHeight)
        {
            // Ignore side chains and re-orgs; assuming they are random
            // they don't affect the estimate.
            // And if an attacker can re-org the chain at will, then
            // you've got much bigger problems than "attacker can influence
            // transaction fees."
            return;
        }
        nBestSeenHeight = nBlockHeight;

        // Fill up the history buckets based on how long transactions took
        // to confirm.
        std::vector<std::vector<const CTxMemPoolEntry*> > entriesByConfirmations;
        entriesByConfirmations.resize(history.size());
        BOOST_FOREACH(const CTxMemPoolEntry& entry, entries)
        {
            // How many blocks did it take for miners to include this transaction?
            int delta = nBlockHeight - entry.GetHeight();
            if (delta <= 0)
            {
                // Re-org made us lose height, this should only happen if we happen
                // to re-org on a difficulty transition point: very rare!
                continue;
            }
            if ((delta-1) >= (int)history.size())
                delta = history.size(); // Last bucket is catch-all
            entriesByConfirmations.at(delta-1).push_back(&entry);
        }
        for (size_t i = 0; i < entriesByConfirmations.size(); i++)
        {
            std::vector<const CTxMemPoolEntry*> &e = entriesByConfirmations.at(i);
            // Insert at most 10 random entries per bucket, otherwise a single block
            // can dominate an estimate:
            if (e.size() > 10) {
                std::random_shuffle(e.begin(), e.end());
                e.resize(10);
            }
            BOOST_FOREACH(const CTxMemPoolEntry* entry, e)
            {
                // Fees are stored and reported as DRKSLK-per-kb:
                CFeeRate feeRate(entry->GetFee(), entry->GetTxSize());
                double dPriority = entry->GetPriority(entry->GetHeight()); // Want priority when it went IN
                seenTxConfirm(feeRate, minRelayFee, dPriority, i);
            }
        }

        //After new samples are added, we have to clear the sorted lists,
        //so they'll be resorted the next time someone asks for an estimate
        sortedFeeSamples.clear();
        sortedPrioritySamples.clear();

        for (size_t i = 0; i < history.size(); i++) {
            if (history[i].FeeSamples() + history[i].PrioritySamples() > 0)
                LogPrint("estimatefee", "estimates: for confirming within %d blocks based on %d/%d samples, fee=%s, prio=%g\n",
                         i,
                         history[i].FeeSamples(), history[i].PrioritySamples(),
                         estimateFee(i+1).ToString(), estimatePriority(i+1));
        }
    }

    /**
     * Can return CFeeRate(0) if we don't have any data for that many blocks back. nBlocksToConfirm is 1 based.
     */
    CFeeRate estimateFee(int nBlocksToConfirm)
    {
        nBlocksToConfirm--;

        if (nBlocksToConfirm < 0 || nBlocksToConfirm >= (int)history.size())
            return CFeeRate(0);

        if (sortedFeeSamples.size() == 0)
        {
            for (size_t i = 0; i < history.size(); i++)
                history.at(i).GetFeeSamples(sortedFeeSamples);
            std::sort(sortedFeeSamples.begin(), sortedFeeSamples.end(),
                      std::greater<CFeeRate>());
        }
        if (sortedFeeSamples.size() < 11)
        {
            // Eleven is Gavin's Favorite Number
            // ... but we also take a maximum of 10 samples per block so eleven means
            // we're getting samples from at least two different blocks
            return CFeeRate(0);
        }

        int nBucketSize = history.at(nBlocksToConfirm).FeeSamples();

        // Estimates should not increase as number of confirmations goes up,
        // but the estimates are noisy because confirmations happen discretely
        // in blocks. To smooth out the estimates, use all samples in the history
        // and use the nth highest where n is (number of samples in previous bucket +
        // half the samples in nBlocksToConfirm bucket):
        size_t nPrevSize = 0;
        for (int i = 0; i < nBlocksToConfirm; i++)
            nPrevSize += history.at(i).FeeSamples();
        size_t index = min(nPrevSize + nBucketSize/2, sortedFeeSamples.size()-1);
        return sortedFeeSamples[index];
    }
    double estimatePriority(int nBlocksToConfirm)
    {
        nBlocksToConfirm--;

        if (nBlocksToConfirm < 0 || nBlocksToConfirm >= (int)history.size())
            return -1;

        if (sortedPrioritySamples.size() == 0)
        {
            for (size_t i = 0; i < history.size(); i++)
                history.at(i).GetPrioritySamples(sortedPrioritySamples);
            std::sort(sortedPrioritySamples.begin(), sortedPrioritySamples.end(),
                      std::greater<double>());
        }
        if (sortedPrioritySamples.size() < 11)
            return -1.0;

        int nBucketSize = history.at(nBlocksToConfirm).PrioritySamples();

        // Estimates should not increase as number of confirmations needed goes up,
        // but the estimates are noisy because confirmations happen discretely
        // in blocks. To smooth out the estimates, use all samples in the history
        // and use the nth highest where n is (number of samples in previous buckets +
        // half the samples in nBlocksToConfirm bucket).
        size_t nPrevSize = 0;
        for (int i = 0; i < nBlocksToConfirm; i++)
            nPrevSize += history.at(i).PrioritySamples();
        size_t index = min(nPrevSize + nBucketSize/2, sortedPrioritySamples.size()-1);
        return sortedPrioritySamples[index];
    }

    void Write(CAutoFile& fileout) const
    {
        fileout << nBestSeenHeight;
        fileout << history.size();
        BOOST_FOREACH(const CBlockAverage& entry, history)
        {
            entry.Write(fileout);
        }
    }

    void Read(CAutoFile& filein, const CFeeRate& minRelayFee)
    {
        int nFileBestSeenHeight;
        filein >> nFileBestSeenHeight;
        size_t numEntries;
        filein >> numEntries;
        if (numEntries <= 0 || numEntries > 10000)
            throw runtime_error("Corrupt estimates file. Must have between 1 and 10k entries.");

        std::vector<CBlockAverage> fileHistory;

        for (size_t i = 0; i < numEntries; i++)
        {
            CBlockAverage entry;
            entry.Read(filein, minRelayFee);
            fileHistory.push_back(entry);
        }

        // Now that we've processed the entire fee estimate data file and not
        // thrown any errors, we can copy it to our history
        nBestSeenHeight = nFileBestSeenHeight;
        history = fileHistory;
        assert(history.size() > 0);
    }
};
class CCoinsViewCache;

// extracts a TxMemPoolEntry's transaction hash
struct mempoolentry_txid
{
    typedef uint256 result_type;
    result_type operator() (const CTxMemPoolEntry &entry) const
    {
        return entry.GetTx().GetHash();
    }
};

/** \class CompareTxMemPoolEntryByDescendantScore
 *
 *  Sort an entry by max(score/size of entry's tx, score/size with all descendants).
 */
class CompareTxMemPoolEntryByDescendantScore
{
public:
    bool operator()(const CTxMemPoolEntry& a, const CTxMemPoolEntry& b)
    {
        bool fUseADescendants = UseDescendantScore(a);
        bool fUseBDescendants = UseDescendantScore(b);

        double aModFee = fUseADescendants ? a.GetModFeesWithDescendants() : a.GetModifiedFee();
        double aSize = fUseADescendants ? a.GetSizeWithDescendants() : a.GetTxSize();

        double bModFee = fUseBDescendants ? b.GetModFeesWithDescendants() : b.GetModifiedFee();
        double bSize = fUseBDescendants ? b.GetSizeWithDescendants() : b.GetTxSize();

        // Avoid division by rewriting (a/b > c/d) as (a*d > c*b).
        double f1 = aModFee * bSize;
        double f2 = aSize * bModFee;

        if (f1 == f2) {
            return a.GetTime() >= b.GetTime();
        }
        return f1 < f2;
    }

    // Calculate which score to use for an entry (avoiding division).
    bool UseDescendantScore(const CTxMemPoolEntry &a)
    {
        double f1 = (double)a.GetModifiedFee() * a.GetSizeWithDescendants();
        double f2 = (double)a.GetModFeesWithDescendants() * a.GetTxSize();
        return f2 > f1;
    }
};

/** \class CompareTxMemPoolEntryByScore
 *
 *  Sort by score of entry ((fee+delta)/size) in descending order
 */
class CompareTxMemPoolEntryByScore
{
public:
    bool operator()(const CTxMemPoolEntry& a, const CTxMemPoolEntry& b)
    {
        double f1 = (double)a.GetModifiedFee() * b.GetTxSize();
        double f2 = (double)b.GetModifiedFee() * a.GetTxSize();
        if (f1 == f2) {
            return b.GetTx().GetHash() < a.GetTx().GetHash();
        }
        return f1 > f2;
    }
};

class CompareTxMemPoolEntryByEntryTime
{
public:
    bool operator()(const CTxMemPoolEntry& a, const CTxMemPoolEntry& b)
    {
        return a.GetTime() < b.GetTime();
    }
};

/**
 * CTxMemPool stores valid-according-to-the-current-best-chain
 * transactions that may be included in the next block.
 *
 * Transactions are added when they are seen on the network
 * (or created by the local node), but not all transactions seen
 * are added to the pool: if a new transaction double-spends
 * an input of a transaction in the pool, it is dropped,
 * as are non-standard transactions.
 *
 * CTxMemPool::mapTx, and CTxMemPoolEntry bookkeeping:
 *
 * mapTx is a boost::multi_index that sorts the mempool on 4 criteria:
 * - transaction hash
 * - feerate [we use max(feerate of tx, feerate of tx with all descendants)]
 * - time in mempool
 * - mining score (feerate modified by any fee deltas from PrioritiseTransaction)
 *
 * Note: the term "descendant" refers to in-mempool transactions that depend on
 * this one, while "ancestor" refers to in-mempool transactions that a given
 * transaction depends on.
 *
 * In order for the feerate sort to remain correct, we must update transactions
 * in the mempool when new descendants arrive.  To facilitate this, we track
 * the set of in-mempool direct parents and direct children in mapLinks.  Within
 * each CTxMemPoolEntry, we track the size and fees of all descendants.
 *
 * Usually when a new transaction is added to the mempool, it has no in-mempool
 * children (because any such children would be an orphan).  So in
 * addUnchecked(), we:
 * - update a new entry's setMemPoolParents to include all in-mempool parents
 * - update the new entry's direct parents to include the new tx as a child
 * - update all ancestors of the transaction to include the new tx's size/fee
 *
 * When a transaction is removed from the mempool, we must:
 * - update all in-mempool parents to not track the tx in setMemPoolChildren
 * - update all ancestors to not include the tx's size/fees in descendant state
 * - update all in-mempool children to not include it as a parent
 *
 * These happen in UpdateForRemoveFromMempool().  (Note that when removing a
 * transaction along with its descendants, we must calculate that set of
 * transactions to be removed before doing the removal, or else the mempool can
 * be in an inconsistent state where it's impossible to walk the ancestors of
 * a transaction.)
 *
 * In the event of a reorg, the assumption that a newly added tx has no
 * in-mempool children is false.  In particular, the mempool is in an
 * inconsistent state while new transactions are being added, because there may
 * be descendant transactions of a tx coming from a disconnected block that are
 * unreachable from just looking at transactions in the mempool (the linking
 * transactions may also be in the disconnected block, waiting to be added).
 * Because of this, there's not much benefit in trying to search for in-mempool
 * children in addUnchecked().  Instead, in the special case of transactions
 * being added from a disconnected block, we require the caller to clean up the
 * state, to account for in-mempool, out-of-block descendants for all the
 * in-block transactions by calling UpdateTransactionsFromBlock().  Note that
 * until this is called, the mempool state is not consistent, and in particular
 * mapLinks may not be correct (and therefore functions like
 * CalculateMemPoolAncestors() and CalculateDescendants() that rely
 * on them to walk the mempool are not generally safe to use).
 *
 * Computational limits:
 *
 * Updating all in-mempool ancestors of a newly added transaction can be slow,
 * if no bound exists on how many in-mempool ancestors there may be.
 * CalculateMemPoolAncestors() takes configurable limits that are designed to
 * prevent these calculations from being too CPU intensive.
 *
 * Adding transactions from a disconnected block can be very time consuming,
 * because we don't have a way to limit the number of in-mempool descendants.
 * To bound CPU processing, we limit the amount of work we're willing to do
 * to properly update the descendant information for a tx being added from
 * a disconnected block.  If we would exceed the limit, then we instead mark
 * the entry as "dirty", and set the feerate for sorting purposes to be equal
 * the feerate of the transaction without any descendants.
 *
 */
class CTxMemPool
{
private:
    bool fSanityCheck;
    unsigned int nTransactionsUpdated;
    CFeeRate minRelayFee; //! Passed to constructor to avoid dependency on main
    uint64_t cachedInnerUsage; //! sum of dynamic memory usage of all the map elements (NOT the maps themselves)

public:
    mutable CCriticalSection cs;
    std::map<uint256, CTransaction> mapTx;
    std::map<uint256, CTxMemPoolEntry> mapTxNew;
    std::map<COutPoint, CInPoint> mapNextTx;
    CMinerPolicyEstimator* minerPolicyEstimator;
    uint64_t totalTxSize; //! sum of all mempool tx' byte sizes
    std::map<uint256, std::pair<double, CAmount> > mapDeltas;

    //CTxMemPool();
    CTxMemPool(const CFeeRate& _minRelayFee);
    ~CTxMemPool();

    ///! If sanity-checking is turned on, check makes sure the pool is
    ///! consistent (does not contain two transactions that spend the same inputs,
    ///! all inputs are in the mapNextTx array). If sanity-checking is turned off,
    ///! check does nothing.
    void check(const CCoinsViewCache *pcoins) const;

    bool addUnchecked(const uint256& hash, const CTxMemPoolEntry &entry);
    bool addUnchecked(const uint256& hash, CTransaction &tx);

    void setSanityCheck(bool _fSanityCheck) { fSanityCheck = _fSanityCheck; }



    bool remove(const CTransaction &tx, bool fRecursive = false);
    bool removeConflicts(const CTransaction &tx);
    void remove(const CTransaction &tx, std::list<CTransaction>& removed, bool fRecursive = false);
    void removeConflicts(const CTransaction &tx, std::list<CTransaction>& removed);
    void removeCoinbaseSpends(const CCoinsViewCache *pcoins, unsigned int nMemPoolHeight);
    void removeForBlock(const std::vector<CTransaction>& vtx, unsigned int nBlockHeight,
                        std::list<CTransaction>& conflicts);

    void clear();
    void queryHashes(std::vector<uint256>& vtxid);
    unsigned int GetTransactionsUpdated() const;
    void AddTransactionsUpdated(unsigned int n);
    bool ReadFeeEstimates(CAutoFile& filein);
    bool WriteFeeEstimates(CAutoFile& fileout) const;
    void ClearPrioritisation(const uint256 hash);

    size_t DynamicMemoryUsage() const;

    /** When adding transactions from a disconnected block back to the mempool,
     *  new mempool entries may have children in the mempool (which is generally
     *  not the case when otherwise adding transactions).
     *  UpdateTransactionsFromBlock() will find child transactions and update the
     *  descendant state for each transaction in hashesToUpdate (excluding any
     *  child transactions present in hashesToUpdate, which are already accounted
     *  for).  Note: hashesToUpdate should be the set of transactions from the
     *  disconnected block that have been accepted back into the mempool.
     */
    void UpdateTransactionsFromBlock(const std::vector<uint256> &hashesToUpdate);

    unsigned long size() const
    {
        LOCK(cs);
        return mapTx.size();
    }

    uint64_t GetTotalTxSize()
    {
        LOCK(cs);
        return totalTxSize;
    }

    bool exists(uint256 hash) const
    {
        LOCK(cs);
        return (mapTx.count(hash) != 0);
    }

    bool lookup(uint256 hash, CTransaction& result) const;

    typedef boost::multi_index_container<
        CTxMemPoolEntry,
        boost::multi_index::indexed_by<
            // sorted by txid
            boost::multi_index::ordered_unique<mempoolentry_txid>,
            // sorted by fee rate
            boost::multi_index::ordered_non_unique<
                boost::multi_index::identity<CTxMemPoolEntry>,
                CompareTxMemPoolEntryByDescendantScore
            >,
            // sorted by entry time
            boost::multi_index::ordered_non_unique<
                boost::multi_index::identity<CTxMemPoolEntry>,
                CompareTxMemPoolEntryByEntryTime
                >,
            // sorted by score (for mining prioritization)
            boost::multi_index::ordered_unique<
                boost::multi_index::identity<CTxMemPoolEntry>,
                CompareTxMemPoolEntryByScore
            >
        >
    > indexed_transaction_set;

    typedef indexed_transaction_set::nth_index<0>::type::iterator txiter;
    struct CompareIteratorByHash {
        bool operator()(const txiter &a, const txiter &b) const {
            return a->GetTx().GetHash() < b->GetTx().GetHash();
        }
    };
    typedef std::set<txiter, CompareIteratorByHash> setEntries;
private:
    typedef std::map<txiter, setEntries, CompareIteratorByHash> cacheMap;

};


/// Fake height value used in CCoins to signify they are only in the memory pool (since 0.8)
static const unsigned int MEMPOOL_HEIGHT = 0x7FFFFFFF;

#endif /* DARKSILK_TXMEMPOOL_H */
