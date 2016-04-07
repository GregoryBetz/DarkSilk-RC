// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLETINTERFACE_H
#define BITCOIN_WALLETINTERFACE_H

#include <boost/signals2/signal.hpp>

class CBlock;
class CBlockLocator;
class CTransaction;
class CValidationInterface;
class CValidationState;
class uint256;

/** Register a wallet to receive updates from core */
void RegisterWallet(CWalletInterface* pwalletIn);
/** Unregister a wallet from core */
void UnregisterWallet(CWalletInterface* pwalletIn);
/** Unregister all wallets from core */
void UnregisterAllValidationInterfaces();
/** Push an updated transaction to all registered wallets old function*/
void SyncWithWallets(const CTransaction& tx, const CBlock* pblock = NULL, bool fConnect = true);
/** Push an updated transaction to all registered wallets new function*/
void SyncWithWallets(const CTransaction& tx, const CBlockIndex *pindex, const CBlock* pblock = NULL);
/** Ask wallets to resend their transactions */
void ResendWalletTransactions(bool fForce = false);

class CWalletInterface {
protected:
    virtual void SyncTransaction(const CTransaction &tx, const CBlock *pblock, bool fConnect) =0;
    virtual void EraseFromWallet(const uint256 &hash) =0;
    virtual void SetBestChain(const CBlockLocator &locator) =0;
    virtual bool UpdatedTransaction(const uint256 &hash) =0;
    virtual void Inventory(const uint256 &hash) =0;
    virtual void ResendWalletTransactions(bool fForce) =0;
    friend void ::RegisterWallet(CWalletInterface*);
    friend void ::UnregisterWallet(CWalletInterface*);
    friend void ::UnregisterAllValidationInterfaces();
};

struct CMainSignals {
        // Notifies listeners of updated transaction data (passing hash, transaction, and optionally the block it is found in.
        boost::signals2::signal<void (const CTransaction &, const CBlock *, bool)> SyncTransaction;
        // Notifies listeners of updated transaction data (transaction, and optionally the block it is found in.
        boost::signals2::signal<void (const CTransaction &, const CBlockIndex *pindex, const CBlock *)> SyncTransactionNew;
        // Notifies listeners of an erased transaction (currently disabled, requires transaction replacement).
        boost::signals2::signal<void (const uint256 &)> EraseTransaction;
        // Notifies listeners of an updated transaction without new data (for now: a coinbase potentially becoming visible).
        boost::signals2::signal<void (const uint256 &)> UpdatedTransaction;
        // Notifies listeners of a new active block chain.
        boost::signals2::signal<void (const CBlockLocator &)> SetBestChain;
        // Notifies listeners about an inventory item being seen on the network.
        boost::signals2::signal<void (const uint256 &)> Inventory;
        // Tells listeners to broadcast their data.
        boost::signals2::signal<void (bool)> Broadcast;
} g_signals;

CMainSignals& GetMainSignals();

#endif
