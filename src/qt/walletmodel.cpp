#include <QSet>
#include <QTimer>
#include <QDebug>

#include "walletmodel.h"
#include "guiconstants.h"
#include "optionsmodel.h"
#include "addresstablemodel.h"
#include "transactiontablemodel.h"
#include "ui_interface.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h" // for BackupWallet
#include "base58.h"
#include "anon/stormnode/spork.h"
#include "smessage.h"

WalletModel::WalletModel(CWallet *wallet, OptionsModel *optionsModel, QObject *parent) :
    QObject(parent), wallet(wallet), optionsModel(optionsModel), addressTableModel(0),
    transactionTableModel(0),
    cachedBalance(0), cachedStake(0), cachedUnconfirmedBalance(0), cachedImmatureBalance(0),
    cachedEncryptionStatus(Unencrypted),
    cachedNumBlocks(0)
{
    fForceCheckBalanceChanged = false;
    addressTableModel = new AddressTableModel(wallet, this);
    transactionTableModel = new TransactionTableModel(wallet, this);

    // This timer will be fired repeatedly to update the balance
    pollTimer = new QTimer(this);
    connect(pollTimer, SIGNAL(timeout()), this, SLOT(pollBalanceChanged()));
    pollTimer->start(MODEL_UPDATE_DELAY);

    subscribeToCoreSignals();
}

WalletModel::~WalletModel()
{
    unsubscribeFromCoreSignals();
}

CAmount WalletModel::getBalance(const CCoinControl *coinControl) const
{
    if (coinControl)
    {
        CAmount nBalance = 0;
        std::vector<COutput> vCoins;
        wallet->AvailableCoins(vCoins, true, coinControl);
        BOOST_FOREACH(const COutput& out, vCoins)
	    if(out.fSpendable)
                nBalance += out.tx->vout[out.i].nValue;

        return nBalance;
    }

    return wallet->GetBalance();
}

CAmount WalletModel::getUnconfirmedBalance() const
{
    return wallet->GetUnconfirmedBalance();
}

CAmount WalletModel::getStake() const
{
    return wallet->GetStake();
}

CAmount WalletModel::getImmatureBalance() const
{
    return wallet->GetImmatureBalance();
}

CAmount WalletModel::getAnonymizedBalance() const
{
    CAmount ret = wallet->GetAnonymizedBalance();
    return ret;
}

bool WalletModel::haveWatchOnly() const
{
    return fHaveWatchOnly;
}

CAmount WalletModel::getWatchBalance() const
{
    return wallet->GetWatchOnlyBalance();
}

CAmount WalletModel::getWatchStake() const
{
    return wallet->GetWatchOnlyStake();
}

CAmount WalletModel::getWatchUnconfirmedBalance() const
{
    return wallet->GetUnconfirmedWatchOnlyBalance();
}

CAmount WalletModel::getWatchImmatureBalance() const
{
    return wallet->GetImmatureWatchOnlyBalance();
}

void WalletModel::updateStatus()
{
    EncryptionStatus newEncryptionStatus = getEncryptionStatus();

    if(cachedEncryptionStatus != newEncryptionStatus)
        emit encryptionStatusChanged(newEncryptionStatus);
}

void WalletModel::pollBalanceChanged()
{
    // Get required locks upfront. This avoids the GUI from getting stuck on
    // periodical polls if the core is holding the locks for a longer time -
    // for example, during a wallet rescan.
    TRY_LOCK(cs_main, lockMain);
    if(!lockMain)
        return;
    TRY_LOCK(wallet->cs_wallet, lockWallet);
    if(!lockWallet)
        return;

    if(fForceCheckBalanceChanged || nBestHeight != cachedNumBlocks || nSandstormRounds != cachedSandstormRounds || cachedTxLocks != nCompleteTXLocks)
    {
        fForceCheckBalanceChanged = false;

        // Balance and number of transactions might have changed
        cachedNumBlocks = nBestHeight;
        cachedSandstormRounds = nSandstormRounds;

        fForceCheckBalanceChanged = true;
        if(transactionTableModel)
            transactionTableModel->updateConfirmations();
    }
}

void WalletModel::checkBalanceChanged()
{
    CAmount newBalance = getBalance();
    CAmount newStake = getStake();
    CAmount newUnconfirmedBalance = getUnconfirmedBalance();
    CAmount newImmatureBalance = getImmatureBalance();
    CAmount newAnonymizedBalance = getAnonymizedBalance();
    CAmount newWatchOnlyBalance = 0;
    CAmount newWatchOnlyStake = 0;
    CAmount newWatchUnconfBalance = 0;
    CAmount newWatchImmatureBalance = 0;
    if (haveWatchOnly())
    {
        newWatchOnlyBalance = getWatchBalance();
        newWatchOnlyStake = getWatchStake();
        newWatchUnconfBalance = getWatchUnconfirmedBalance();
        newWatchImmatureBalance = getWatchImmatureBalance();
    }

    if(cachedBalance != newBalance || cachedStake != newStake || cachedUnconfirmedBalance != newUnconfirmedBalance || cachedImmatureBalance != newImmatureBalance || cachedAnonymizedBalance != newAnonymizedBalance ||
        cachedTxLocks != nCompleteTXLocks || cachedWatchOnlyBalance != newWatchOnlyBalance || cachedWatchOnlyStake != newWatchOnlyStake || cachedWatchUnconfBalance != newWatchUnconfBalance || cachedWatchImmatureBalance != newWatchImmatureBalance)
    {
        cachedBalance = newBalance;
        cachedStake = newStake;
        cachedUnconfirmedBalance = newUnconfirmedBalance;
        cachedImmatureBalance = newImmatureBalance;
        cachedAnonymizedBalance = newAnonymizedBalance;
        cachedTxLocks = nCompleteTXLocks;
        cachedWatchOnlyBalance = newWatchOnlyBalance;
        cachedWatchUnconfBalance = newWatchUnconfBalance;
        cachedWatchImmatureBalance = newWatchImmatureBalance;
        emit balanceChanged(newBalance, newStake, newUnconfirmedBalance, newImmatureBalance, newAnonymizedBalance,
            newWatchOnlyBalance, newWatchOnlyStake, newWatchUnconfBalance, newWatchImmatureBalance);
    }
}

void WalletModel::updateTransaction(const QString &hash, int status)
{
    if(transactionTableModel)
        transactionTableModel->updateTransaction(hash, status);

    // Balance and number of transactions might have changed
    checkBalanceChanged();
}

void WalletModel::updateAddressBook(const QString &address, const QString &label, bool isMine, int status)
{
    if(addressTableModel)
        addressTableModel->updateEntry(address, label, isMine, status);
}

bool WalletModel::validateAddress(const QString &address)
{
    std::string sAddr = address.toStdString();
    
    if (sAddr.length() > 75)
    {
        if (IsStealthAddress(sAddr))
            return true;
    };
    
    CDarkSilkAddress addressParsed(sAddr);
    return addressParsed.IsValid();
}

void WalletModel::updateWatchOnlyFlag(bool fHaveWatchonly)
{
    fHaveWatchOnly = fHaveWatchonly;
    emit notifyWatchonlyChanged(fHaveWatchonly);
}

WalletModel::SendCoinsReturn WalletModel::sendCoins(const QList<SendCoinsRecipient> &recipients, const CCoinControl *coinControl)
{
    CAmount total = 0;
    QSet<QString> setAddress;
    QString hex;

    if(recipients.empty())
    {
        return OK;
    }

    if(isAnonymizeOnlyUnlocked())
    {
        return AnonymizeOnlyUnlocked;
    }

    // Pre-check input data for validity
    foreach(const SendCoinsRecipient &rcp, recipients)
    {
        if(!validateAddress(rcp.address))
        {
            return InvalidAddress;
        }
        setAddress.insert(rcp.address);

        if(rcp.amount <= 0)
        {
            return InvalidAmount;
        }
        total += rcp.amount;
    }

    if(recipients.size() > setAddress.size())
    {
        return DuplicateAddress;
    }

    CAmount nBalance = getBalance(coinControl);

    if(total > nBalance)
    {
        return AmountExceedsBalance;
    }

    if((total + nTransactionFee) > nBalance)
    {
        return SendCoinsReturn(AmountWithFeeExceedsBalance, nTransactionFee);
    }

    std::map<int, std::string> mapStealthNarr;

    {
        LOCK2(cs_main, wallet->cs_wallet);

        // Sendmany
        std::vector<std::pair<CScript, CAmount> > vecSend;
        foreach(const SendCoinsRecipient &rcp, recipients)
        {
            std::string sAddr = rcp.address.toStdString();
            
            if (rcp.typeInd == AddressTableModel::AT_Stealth)
            {
                CStealthAddress sxAddr;
                if (sxAddr.SetEncoded(sAddr))
                {
                    ec_secret ephem_secret;
                    ec_secret secretShared;
                    ec_point pkSendTo;
                    ec_point ephem_pubkey;
                    
                    
                    if (GenerateRandomSecret(ephem_secret) != 0)
                    {
                        printf("GenerateRandomSecret failed.\n");
                        return Aborted;
                    };
                    
                    if (StealthSecret(ephem_secret, sxAddr.scan_pubkey, sxAddr.spend_pubkey, secretShared, pkSendTo) != 0)
                    {
                        printf("Could not generate receiving public key.\n");
                        return Aborted;
                    };
                    
                    CPubKey cpkTo(pkSendTo);
                    if (!cpkTo.IsValid())
                    {
                        printf("Invalid public key generated.\n");
                        return Aborted;
                    };
                    
                    CKeyID ckidTo = cpkTo.GetID();
                    
                    CDarkSilkAddress addrTo(ckidTo);
                    
                    if (SecretToPublicKey(ephem_secret, ephem_pubkey) != 0)
                    {
                        printf("Could not generate ephem public key.\n");
                        return Aborted;
                    };
                    
                    if (fDebug)
                    {
                        printf("Stealth send to generated pubkey %"PRIszu": %s\n", pkSendTo.size(), HexStr(pkSendTo).c_str());
                        printf("hash %s\n", addrTo.ToString().c_str());
                        printf("ephem_pubkey %"PRIszu": %s\n", ephem_pubkey.size(), HexStr(ephem_pubkey).c_str());
                    };
                    
                    CScript scriptPubKey;
                    scriptPubKey.SetDestination(addrTo.Get());
                    
                    vecSend.push_back(make_pair(scriptPubKey, rcp.amount));
                    
                    CScript scriptP = CScript() << OP_RETURN << ephem_pubkey;
                    
                    if (rcp.narration.length() > 0)
                    {
                        std::string sNarr = rcp.narration.toStdString();
                        
                        if (sNarr.length() > 24)
                        {
                            printf("Narration is too long.\n");
                            return NarrationTooLong;
                        };
                        
                        std::vector<unsigned char> vchNarr;
                        
                        SecMsgCrypter crypter;
                        crypter.SetKey(&secretShared.e[0], &ephem_pubkey[0]);
                        
                        if (!crypter.Encrypt((uint8_t*)&sNarr[0], sNarr.length(), vchNarr))
                        {
                            printf("Narration encryption failed.\n");
                            return Aborted;
                        };
                        
                        if (vchNarr.size() > 48)
                        {
                            printf("Encrypted narration is too long.\n");
                            return Aborted;
                        };
                        
                        if (vchNarr.size() > 0)
                            scriptP = scriptP << OP_RETURN << vchNarr;
                        
                        int pos = vecSend.size()-1;
                        mapStealthNarr[pos] = sNarr;
                    };
                    
                    vecSend.push_back(make_pair(scriptP, 0));
                    

                    continue;
                }
		else
		{
		    printf("Couldn't parse stealth address!\n");
		    return Aborted;
		} // else drop through to normal
            }
           
            CScript scriptPubKey;
            scriptPubKey.SetDestination(CDarkSilkAddress(sAddr).Get());
            vecSend.push_back(make_pair(scriptPubKey, rcp.amount));
   	            
            
            
            
            if (rcp.narration.length() > 0)
            {
                std::string sNarr = rcp.narration.toStdString();
                
                if (sNarr.length() > 24)
                {
                    printf("Narration is too long.\n");
                    return NarrationTooLong;
                };
                
                std::vector<uint8_t> vNarr(sNarr.c_str(), sNarr.c_str() + sNarr.length());
                std::vector<uint8_t> vNDesc;
                
                vNDesc.resize(2);
                vNDesc[0] = 'n';
                vNDesc[1] = 'p';
                
                CScript scriptN = CScript() << OP_RETURN << vNDesc << OP_RETURN << vNarr;
                
                vecSend.push_back(make_pair(scriptN, 1));
            }
        }

        //TODO
        /*if(recipients[0].useInstantX && total > GetSporkValue(SPORK_5_MAX_VALUE)*COIN){
            emit message(tr("Send Coins"), tr("InstantX doesn't support sending values that high yet. Transactions are currently limited to %1 DRKSLK.").arg(GetSporkValue(SPORK_5_MAX_VALUE)),
                        CClientUIInterface::MSG_ERROR);
            return TransactionCreationFailed;
        }*/

        CWalletTx wtx;
        CReserveKey keyChange(wallet);
        CAmount nFeeRequired = 0;
        int nChangePos = -1;
        std::string strFailReason;

        bool fCreated = wallet->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, nChangePos, strFailReason, coinControl);

        //TODO
        /*if(recipients[0].useInstantX && newTx->GetValueOut() > GetSporkValue(SPORK_5_MAX_VALUE)*COIN){
            emit message(tr("Send Coins"), tr("InstantX doesn't support sending values that high yet. Transactions are currently limited to %1 DRKSLK.").arg(GetSporkValue(SPORK_5_MAX_VALUE)),
                         CClientUIInterface::MSG_ERROR);
            return TransactionCreationFailed;
        }*/

        std::map<int, std::string>::iterator it;
        for (it = mapStealthNarr.begin(); it != mapStealthNarr.end(); ++it)
        {
            int pos = it->first;
            if (nChangePos > -1 && it->first >= nChangePos)
                pos++;
            
            char key[64];
            if (snprintf(key, sizeof(key), "n_%u", pos) < 1)
            {
                printf("CreateStealthTransaction(): Error creating narration key.");
                continue;
            };
            wtx.mapValue[key] = it->second;
        };

        if(!fCreated)
        {
            if((total + nFeeRequired) > nBalance) // FIXME: could cause collisions in the future
            {
                return SendCoinsReturn(AmountWithFeeExceedsBalance, nFeeRequired);
            }
            return TransactionCreationFailed;
        }
        if(!uiInterface.ThreadSafeAskFee(nFeeRequired, tr("Sending...").toStdString()))
        {
            return Aborted;
        }
        if(!wallet->CommitTransaction(wtx, keyChange, (recipients[0].useInstantX) ? "txlreq" : "tx"))
        {
            return TransactionCommitFailed;
        }
        hex = QString::fromStdString(wtx.GetHash().GetHex());
    }

    // Add addresses / update labels that we've sent to to the address book
    foreach(const SendCoinsRecipient &rcp, recipients)
    {
        std::string strAddress = rcp.address.toStdString();
        CTxDestination dest = CDarkSilkAddress(strAddress).Get();
        std::string strLabel = rcp.label.toStdString();
        {
            LOCK(wallet->cs_wallet);

            if (rcp.typeInd == AddressTableModel::AT_Stealth)
            {
                wallet->UpdateStealthAddress(strAddress, strLabel, true);
            } else
            {
                std::map<CTxDestination, std::string>::iterator mi = wallet->mapAddressBook.find(dest);
                
                // Check if we have a new address or an updated label
                if (mi == wallet->mapAddressBook.end() || mi->second != strLabel)
                {
                    wallet->SetAddressBookName(dest, strLabel);
                };
            };
        }
    }

    checkBalanceChanged(); // update balance immediately, otherwise there could be a short noticeable delay until pollBalanceChanged hits

    return SendCoinsReturn(OK, 0, hex);
}

OptionsModel *WalletModel::getOptionsModel()
{
    return optionsModel;
}

AddressTableModel *WalletModel::getAddressTableModel()
{
    return addressTableModel;
}

TransactionTableModel *WalletModel::getTransactionTableModel()
{
    return transactionTableModel;
}

WalletModel::EncryptionStatus WalletModel::getEncryptionStatus() const
{
    if(!wallet->IsCrypted())
    {
        return Unencrypted;
    }
    else if(wallet->IsLocked())
    {
        return Locked;
    }
    else if(fWalletUnlockStakingOnly)
    {
	return Locked;
    }
    else if (wallet->fWalletUnlockAnonymizeOnly)
    {
        return UnlockedForAnonymizationOnly;
    }
    else
    {
        return Unlocked;
    }
}

bool WalletModel::setWalletEncrypted(bool encrypted, const SecureString &passphrase)
{
    if(encrypted)
    {
        // Encrypt
        return wallet->EncryptWallet(passphrase);
    }
    else
    {
        // Decrypt -- TODO; not supported yet
        return false;
    }
}

bool WalletModel::setWalletLocked(bool locked, const SecureString &passPhrase, bool anonymizeOnly)
{
    if(locked)
    {
        // Lock
        return wallet->Lock();
    }
    else
    {
        // Unlock
        return wallet->Unlock(passPhrase, anonymizeOnly);
    }
}

bool WalletModel::isAnonymizeOnlyUnlocked()
{
    return wallet->fWalletUnlockAnonymizeOnly;
}

bool WalletModel::changePassphrase(const SecureString &oldPass, const SecureString &newPass)
{
    bool retval;
    {
        LOCK(wallet->cs_wallet);
        wallet->Lock(); // Make sure wallet is locked before attempting pass change
        retval = wallet->ChangeWalletPassphrase(oldPass, newPass);
    }
    return retval;
}

bool WalletModel::backupWallet(const QString &filename)
{
    return BackupWallet(*wallet, filename.toLocal8Bit().data());
}

// Handlers for core signals
static void NotifyKeyStoreStatusChanged(WalletModel *walletmodel, CCryptoKeyStore *wallet)
{
    qDebug() << "NotifyKeyStoreStatusChanged";
    QMetaObject::invokeMethod(walletmodel, "updateStatus", Qt::QueuedConnection);
}

static void NotifyAddressBookChanged(WalletModel *walletmodel, CWallet *wallet, const CTxDestination &address, const std::string &label, bool isMine, ChangeType status)
{
    if (address.type() == typeid(CStealthAddress))
    {
        CStealthAddress sxAddr = boost::get<CStealthAddress>(address);
        std::string enc = sxAddr.Encoded();
        LogPrintf("NotifyAddressBookChanged %s %s isMine=%i status=%i\n", enc.c_str(), label.c_str(), isMine, status);
        QMetaObject::invokeMethod(walletmodel, "updateAddressBook", Qt::QueuedConnection,
                                  Q_ARG(QString, QString::fromStdString(enc)),
                                  Q_ARG(QString, QString::fromStdString(label)),
                                  Q_ARG(bool, isMine),
                                  Q_ARG(int, status));
    } else
    {
        LogPrintf("NotifyAddressBookChanged %s %s isMine=%i status=%i\n", CDarkSilkAddress(address).ToString().c_str(), label.c_str(), isMine, status);
        QMetaObject::invokeMethod(walletmodel, "updateAddressBook", Qt::QueuedConnection,
                                  Q_ARG(QString, QString::fromStdString(CDarkSilkAddress(address).ToString())),
                                  Q_ARG(QString, QString::fromStdString(label)),
                                  Q_ARG(bool, isMine),
                                  Q_ARG(int, status));
    }
}

static void NotifyTransactionChanged(WalletModel *walletmodel, CWallet *wallet, const uint256 &hash, ChangeType status)
{
    QString strHash = QString::fromStdString(hash.GetHex());

    qDebug() << "NotifyTransactionChanged : " + strHash + " status= " + QString::number(status);
    QMetaObject::invokeMethod(walletmodel, "updateTransaction", Qt::QueuedConnection,
                              Q_ARG(QString, strHash),
                              Q_ARG(int, status));
}

void WalletModel::subscribeToCoreSignals()
{
    // Connect signals to wallet
    wallet->NotifyStatusChanged.connect(boost::bind(&NotifyKeyStoreStatusChanged, this, _1));
    wallet->NotifyAddressBookChanged.connect(boost::bind(NotifyAddressBookChanged, this, _1, _2, _3, _4, _5));
    wallet->NotifyTransactionChanged.connect(boost::bind(NotifyTransactionChanged, this, _1, _2, _3));
}

void WalletModel::unsubscribeFromCoreSignals()
{
    // Disconnect signals from wallet
    wallet->NotifyStatusChanged.disconnect(boost::bind(&NotifyKeyStoreStatusChanged, this, _1));
    wallet->NotifyAddressBookChanged.disconnect(boost::bind(NotifyAddressBookChanged, this, _1, _2, _3, _4, _5));
    wallet->NotifyTransactionChanged.disconnect(boost::bind(NotifyTransactionChanged, this, _1, _2, _3));
}

// WalletModel::UnlockContext implementation
WalletModel::UnlockContext WalletModel::requestUnlock()
{
    bool was_locked = getEncryptionStatus() == Locked;
    
    if ((!was_locked) && fWalletUnlockStakingOnly && isAnonymizeOnlyUnlocked())
    {
       setWalletLocked(true);
       was_locked = getEncryptionStatus() == Locked;

    }
    if(was_locked)
    {
        // Request UI to unlock wallet
        emit requireUnlock();
    }
    // If wallet is still locked, unlock was failed or cancelled, mark context as invalid
    bool valid = getEncryptionStatus() != Locked;

    return UnlockContext(this, valid, was_locked && !fWalletUnlockStakingOnly);
}

WalletModel::UnlockContext::UnlockContext(WalletModel *wallet, bool valid, bool relock):
        wallet(wallet),
        valid(valid),
        relock(relock)
{
}

WalletModel::UnlockContext::~UnlockContext()
{
    if(valid && relock)
    {
        wallet->setWalletLocked(true);
    }
}

void WalletModel::UnlockContext::CopyFrom(const UnlockContext& rhs)
{
    // Transfer context; old object no longer relocks wallet
    *this = rhs;
    rhs.relock = false;
}

bool WalletModel::getPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const
{
    return wallet->GetPubKey(address, vchPubKeyOut);   
}

// returns a list of COutputs from COutPoints
void WalletModel::getOutputs(const std::vector<COutPoint>& vOutpoints, std::vector<COutput>& vOutputs)
{
    LOCK2(cs_main, wallet->cs_wallet);
    BOOST_FOREACH(const COutPoint& outpoint, vOutpoints)
    {
        if (!wallet->mapWallet.count(outpoint.hash)) continue;
        int nDepth = wallet->mapWallet[outpoint.hash].GetDepthInMainChain();
        if (nDepth < 0) continue;
        COutput out(&wallet->mapWallet[outpoint.hash], outpoint.n, nDepth, true);
        vOutputs.push_back(out);
    }
}

// AvailableCoins + LockedCoins grouped by wallet address (put change in one group with wallet address) 
void WalletModel::listCoins(std::map<QString, std::vector<COutput> >& mapCoins) const
{
    LOCK2(cs_main, wallet->cs_wallet); // ListLockedCoins, mapWallet
    std::vector<COutput> vCoins;
    wallet->AvailableCoins(vCoins);

    std::vector<COutPoint> vLockedCoins;

    // add locked coins
    BOOST_FOREACH(const COutPoint& outpoint, vLockedCoins)
    {
        if (!wallet->mapWallet.count(outpoint.hash)) continue;
        int nDepth = wallet->mapWallet[outpoint.hash].GetDepthInMainChain();
        if (nDepth < 0) continue;
        COutput out(&wallet->mapWallet[outpoint.hash], outpoint.n, nDepth, true);
        vCoins.push_back(out);
    }

    BOOST_FOREACH(const COutput& out, vCoins)
    {
        COutput cout = out;

        while (wallet->IsChange(cout.tx->vout[cout.i]) && cout.tx->vin.size() > 0 && wallet->IsMine(cout.tx->vin[0]))
        {
            if (!wallet->mapWallet.count(cout.tx->vin[0].prevout.hash)) break;
            cout = COutput(&wallet->mapWallet[cout.tx->vin[0].prevout.hash], cout.tx->vin[0].prevout.n, 0, true);
        }

        CTxDestination address;
        if(!out.fSpendable || !ExtractDestination(cout.tx->vout[cout.i].scriptPubKey, address)) 
            continue;
        mapCoins[CDarkSilkAddress(address).ToString().c_str()].push_back(out);
    }
}

bool WalletModel::isLockedCoin(uint256 hash, unsigned int n) const
{
    LOCK2(cs_main, wallet->cs_wallet);
    return wallet->IsLockedCoin(hash, n);
}

void WalletModel::lockCoin(COutPoint& output)
{
    LOCK2(cs_main, wallet->cs_wallet);
    wallet->LockCoin(output);
}

void WalletModel::unlockCoin(COutPoint& output)
{
    LOCK2(cs_main, wallet->cs_wallet);
    wallet->UnlockCoin(output);
}

void WalletModel::listLockedCoins(std::vector<COutPoint>& vOutpts)
{
    LOCK2(cs_main, wallet->cs_wallet);
    wallet->ListLockedCoins(vOutpts);
}

CWallet* WalletModel::getWallet()
{
    return wallet;
}
