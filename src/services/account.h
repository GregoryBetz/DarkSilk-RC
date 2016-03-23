// Copyright (c) 2014-2016 Syscoin Developers
// Copyright (c) 2015-2016 Silk Network
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
//

#ifndef ACCOUNT_H
#define ACCOUNT_H

#include "rpc/rpcserver.h"
#include "leveldbwrapper.h"
#include "script/script.h"
#include "serialize.h"
#include "consensus/params.h"

class CWalletTx;
class CTransaction;
class CTxOut;
class COutPoint;
class CReserveKey;
class CCoinsViewCache;
class CCoins;
class CBlock;
struct CRecipient;
class CDarkSilkAddress;

static const unsigned int MAX_NAME_LENGTH = 255;
static const unsigned int MAX_VALUE_LENGTH = 1023;
static const unsigned int MAX_ID_LENGTH = 20;
static const unsigned int MAX_ENCRYPTED_VALUE_LENGTH = 1108;

class CAccountIndex {
public:
    uint256 txHash;
    int64_t nHeight;
    std::vector<unsigned char> vchPublicValue;
	std::vector<unsigned char> vchPrivateValue;
	std::vector<unsigned char> vchPubKey;
    CAccountIndex() { 
        SetNull();
    }
    CAccountIndex(const CTransaction &tx) {
        SetNull();
        UnserializeFromTx(tx);
    }
	void ClearAccount()
	{
		vchPublicValue.clear();
		vchPrivateValue.clear();
	}
	ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {        
		READWRITE(txHash);
        READWRITE(VARINT(nHeight));
    	READWRITE(vchPublicValue);
		READWRITE(vchPrivateValue);
		READWRITE(vchPubKey);
	}

    friend bool operator==(const CAccountIndex &a, const CAccountIndex &b) {
		return (a.nHeight == b.nHeight && a.txHash == b.txHash && a.vchPublicValue == b.vchPrivateValue && a.vchPubKey == b.vchPubKey);
    }

    friend bool operator!=(const CAccountIndex &a, const CAccountIndex &b) {
        return !(a == b);
    }
    CAccountIndex operator=(const CAccountIndex &b) {
        txHash = b.txHash;
        nHeight = b.nHeight;
        vchPublicValue = b.vchPublicValue;
        vchPrivateValue = b.vchPrivateValue;
        vchPubKey = b.vchPubKey;
        return *this;
    }   
    void SetNull() { txHash.SetNull(); nHeight = 0; vchPublicValue.clear(); vchPrivateValue.clear(); vchPubKey.clear(); }
    bool IsNull() const { return (nHeight == 0 && txHash.IsNull() && vchPublicValue.empty() && vchPrivateValue.empty() && vchPubKey.empty()); }
	bool UnserializeFromTx(const CTransaction &tx);
	const std::vector<unsigned char> Serialize();
};

class CAccountDB : public CDBWrapper {
public:
    CAccountDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "accountes", nCacheSize, fMemory, fWipe) {
    }

	bool WriteAccount(const std::vector<unsigned char>& name, const std::vector<unsigned char>& address, std::vector<CAccountIndex>& vtxPos) {
		return Write(make_pair(std::string("namei"), name), vtxPos) && Write(make_pair(std::string("namea"), address), name);
	}

	bool EraseAccount(const std::vector<unsigned char>& name) {
	    return Erase(make_pair(std::string("namei"), name));
	}
	bool ReadAccount(const std::vector<unsigned char>& name, std::vector<CAccountIndex>& vtxPos) {
		return Read(make_pair(std::string("namei"), name), vtxPos);
	}
	bool ReadAddress(const std::vector<unsigned char>& address, std::vector<unsigned char>& name) {
		return Read(make_pair(std::string("namea"), address), name);
	}
	bool ExistsAccount(const std::vector<unsigned char>& name) {
	    return Exists(make_pair(std::string("namei"), name));
	}
	bool ExistsAddress(const std::vector<unsigned char>& address) {
	    return Exists(make_pair(std::string("namea"), address));
	}
    bool ScanNames(
            const std::vector<unsigned char>& vchName,
            unsigned int nMax,
            std::vector<std::pair<std::vector<unsigned char>, CAccountIndex> >& nameScan);

    bool ReconstructAccountIndex(CBlockIndex *pindexRescan);
};

class COfferDB;
class CCertDB;
class CEscrowDB;
class CMessageDB;
extern CAccountDB *paccountdb;
extern COfferDB *pofferdb;
extern CCertDB *pcertdb;
extern CEscrowDB *pescrowdb;
extern CMessageDB *pmessagedb;



std::string stringFromVch(const std::vector<unsigned char> &vch);
std::vector<unsigned char> vchFromValue(const UniValue& value);
std::vector<unsigned char> vchFromString(const std::string &str);
std::string stringFromValue(const UniValue& value);
bool IsCompressedOrUncompressedPubKey(const std::vector<unsigned char> &vchPubKey);
int GetDarkSilkTxVersion();
const int DARKSILK_TX_VERSION = 0x7400;
bool CheckAccountInputs(const CTransaction &tx, int op, int nOut, const std::vector<std::vector<unsigned char> > &vvchArgs, const CCoinsViewCache &inputs, bool fJustCheck, int nHeight, const CBlock *block = NULL);
void CreateRecipient(const CScript& scriptPubKey, CRecipient& recipient);
void CreateFeeRecipient(const CScript& scriptPubKey, const std::vector<unsigned char>& data, CRecipient& recipient);
bool IsDarkSilkTxMine(const CTransaction& tx,const std::string &type);
bool IsAccountOp(int op);


bool GetTxOfAccount(const std::vector<unsigned char> &vchName, CAccountIndex& account, CTransaction& tx);
int IndexOfAccountOutput(const CTransaction& tx);
bool GetAccountOfTx(const CTransaction& tx, std::vector<unsigned char>& name);
bool DecodeAccountTx(const CTransaction& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch);
bool DecodeAndParseAccountTx(const CTransaction& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch);
bool DecodeAndParseDarkSilkTx(const CTransaction& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch);
bool DecodeAccountScript(const CScript& script, int& op,
		std::vector<std::vector<unsigned char> > &vvch);
void GetAddressFromAccount(const std::string& strAccount, std::string& strAddress);
void GetAccountFromAddress(const std::string& strAddress, std::string& strAccount);
CAmount convertCurrencyCodeToDarkSilk(const std::vector<unsigned char> &vchCurrencyCode, const float &nPrice, const unsigned int &nHeight, int &precision);
bool ExistsInMempool(const std::vector<unsigned char> &vchToFind, opcodetype type);
unsigned int QtyOfPendingAcceptsInMempool(const std::vector<unsigned char>& vchToFind);
std::string getCurrencyToDRKSLKFromAccount(const std::vector<unsigned char> &vchCurrency, CAmount &nFee, const unsigned int &nHeightToFind, std::vector<std::string>& rateList, int &precision);
std::string accountFromOp(int op);
bool IsAccountOp(int op);
int GetAccountExpirationDepth();
CScript RemoveAccountScriptPrefix(const CScript& scriptIn);
int GetDarkSilkDataOutput(const CTransaction& tx);
bool IsDarkSilkDataOutput(const CTxOut& out);
bool GetDarkSilkData(const CTransaction &tx, std::vector<unsigned char> &vchData);
bool GetDarkSilkTransaction(int nHeight, const uint256 &hash, CTransaction &txOut, const Consensus::Params& consensusParams);
bool IsDarkSilkScript(const CScript& scriptPubKey, int &op, std::vector<std::vector<unsigned char> > &vvchArgs);
void RemoveDarkSilkScript(const CScript& scriptPubKeyIn, CScript& scriptPubKeyOut);
bool GetPreviousInput(const COutPoint * outpoint, int &op, std::vector<std::vector<unsigned char> > &vvchArgs);
#endif // ACCOUNT_H
