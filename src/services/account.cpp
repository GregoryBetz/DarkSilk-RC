// Copyright (c) 2014-2016 Syscoin Developers
// Copyright (c) 2015-2016 Silk Network
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
//

#include "services/account.h"
#include "services/offer.h"
#include "services/escrow.h"
#include "services/message.h"
#include "services/cert.h"
#include "services/offer.h"
#include "init.h"
#include "main.h"
#include "util.h"
#include "random.h"
#include "wallet/wallet.h"
#include "rpc/rpcserver.h"
#include "base58.h"
#include "txmempool.h"
#include "txdb.h"
#include "chainparams.h"
#include "policy/policy.h"

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/xpressive/xpressive_dynamic.hpp>
#include <boost/foreach.hpp>
#include <boost/thread.hpp>
#include <boost/algorithm/hex.hpp>

using namespace std;

CAccountDB *paccountdb = NULL;
COfferDB *pofferdb = NULL;
CCertDB *pcertdb = NULL;
CEscrowDB *pescrowdb = NULL;
CMessageDB *pmessagedb = NULL;

extern void SendMoneyDarkSilk(const vector<CRecipient> &vecSend, CAmount nValue, bool fSubtractFeeFromAmount, CWalletTx& wtxNew, const CWalletTx* wtxInOffer=NULL, const CWalletTx* wtxInCert=NULL, const CWalletTx* wtxInAccount=NULL, const CWalletTx* wtxInEscrow=NULL, bool darksilkTx=true);

bool IsCompressedOrUncompressedPubKey(const vector<unsigned char> &vchPubKey) {
    if (vchPubKey.size() < 33) {
        //  Non-canonical public key: too short
        return false;
    }
    if (vchPubKey[0] == 0x04) {
        if (vchPubKey.size() != 65) {
            //  Non-canonical public key: invalid length for uncompressed key
            return false;
        }
    } else if (vchPubKey[0] == 0x02 || vchPubKey[0] == 0x03) {
        if (vchPubKey.size() != 33) {
            //  Non-canonical public key: invalid length for compressed key
            return false;
        }
    } else {
          //  Non-canonical public key: neither compressed nor uncompressed
          return false;
    }
    return true;
}
bool GetPreviousInput(const COutPoint * outpoint, int &op, vector<vector<unsigned char> > &vvchArgs)
{
	if(!pwalletMain || !outpoint)
		return false;
    map<uint256, CWalletTx>::const_iterator it = pwalletMain->mapWallet.find(outpoint->hash);
    if (it != pwalletMain->mapWallet.end())
    {
        const CWalletTx* pcoin = &it->second;
		if(IsDarkSilkScript(pcoin->vout[outpoint->n].scriptPubKey, op, vvchArgs))
			return true;

    } else
       return false;
    return false;
}
bool GetDarkSilkTransaction(int nHeight, const uint256 &hash, CTransaction &txOut, const Consensus::Params& consensusParams)
{
	CBlockIndex *pindexSlow = NULL; 
	LOCK(cs_main);
	pindexSlow = chainActive[nHeight];
    if (pindexSlow) {
        CBlock block;
        if (ReadBlockFromDisk(block, pindexSlow, consensusParams)) {
            BOOST_FOREACH(const CTransaction &tx, block.vtx) {
                if (tx.GetHash() == hash) {
                    txOut = tx;
                    return true;
                }
            }
        }
    }
	return false;
}
bool IsDarkSilkScript(const CScript& scriptPubKey, int &op, vector<vector<unsigned char> > &vvchArgs)
{
	if (DecodeAccountScript(scriptPubKey, op, vvchArgs))
		return true;
	else if(DecodeOfferScript(scriptPubKey, op, vvchArgs))
		return true;
	else if(DecodeCertScript(scriptPubKey, op, vvchArgs))
		return true;
	else if(DecodeMessageScript(scriptPubKey, op, vvchArgs))
		return true;
	else if(DecodeEscrowScript(scriptPubKey, op, vvchArgs))
		return true;
	return false;
}
void RemoveDarkSilkScript(const CScript& scriptPubKeyIn, CScript& scriptPubKeyOut)
{
	vector<vector<unsigned char> > vvch;
	int op;
	if (DecodeAccountScript(scriptPubKeyIn, op, vvch))
		scriptPubKeyOut = RemoveAccountScriptPrefix(scriptPubKeyIn);
	else if (DecodeOfferScript(scriptPubKeyIn, op, vvch))
		scriptPubKeyOut = RemoveOfferScriptPrefix(scriptPubKeyIn);
	else if (DecodeCertScript(scriptPubKeyIn, op, vvch))
		scriptPubKeyOut = RemoveCertScriptPrefix(scriptPubKeyIn);
	else if (DecodeEscrowScript(scriptPubKeyIn, op, vvch))
		scriptPubKeyOut = RemoveEscrowScriptPrefix(scriptPubKeyIn);
	else if (DecodeMessageScript(scriptPubKeyIn, op, vvch))
		scriptPubKeyOut = RemoveMessageScriptPrefix(scriptPubKeyIn);
}

unsigned int QtyOfPendingAcceptsInMempool(const vector<unsigned char>& vchToFind)
{
	LOCK(mempool.cs);
	unsigned int nQty = 0;
	for (CTxMemPool::indexed_transaction_set::iterator mi = mempool.mapTx.begin();
             mi != mempool.mapTx.end(); ++mi)
        {
        const CTransaction& tx = mi->GetTx();
		if (tx.IsCoinBase() || !CheckFinalTx(tx))
			continue;
		vector<vector<unsigned char> > vvch;
		int op, nOut;
		
		if(DecodeOfferTx(tx, op, nOut, vvch)) {
			if(op == OP_OFFER_ACCEPT)
			{
				if(vvch.size() >= 1 && vvch[0] == vchToFind)
				{
					COffer theOffer(tx);
					COfferAccept theOfferAccept = theOffer.accept;
					if (theOffer.IsNull() || theOfferAccept.IsNull())
						continue;
					if(theOfferAccept.vchAcceptRand == vvch[1])
					{
						nQty += theOfferAccept.nQty;
					}
				}
			}
		}		
	}
	return nQty;

}
bool ExistsInMempool(const std::vector<unsigned char> &vchToFind, opcodetype type)
{
	LOCK(mempool.cs);
	for (CTxMemPool::indexed_transaction_set::iterator mi = mempool.mapTx.begin();
             mi != mempool.mapTx.end(); ++mi)
        {
        const CTransaction& tx = mi->GetTx();
		if (tx.IsCoinBase() || !CheckFinalTx(tx))
			continue;
		vector<vector<unsigned char> > vvch;
		int op, nOut;
		if(IsAccountOp(type))
		{
			if(DecodeAccountTx(tx, op, nOut, vvch))
			{
				if(op == type)
				{
					if(vvch.size() >= 1 && vchToFind == vvch[0])
					{
						return true;
					}
				}
			}
		}
		else if(IsOfferOp(type))
		{
			if(DecodeOfferTx(tx, op, nOut, vvch))
			{
				if(op == type)
				{
					if(vvch.size() >= 1 && vchToFind == vvch[0])
					{
						return true;
					}
				}
			}
		}
		else if(IsCertOp(type))
		{
			if(DecodeCertTx(tx, op, nOut, vvch))
			{
				if(op == type)
				{
					if(vvch.size() >= 1 && vchToFind == vvch[0])
					{
						return true;
					}
				}
			}
		}
		else if(IsEscrowOp(type))
		{
			if(DecodeEscrowTx(tx, op, nOut, vvch))
			{
				if(op == type)
				{
					if(vvch.size() >= 1 && vchToFind == vvch[0])
					{
						return true;
					}
				}
			}
		}
		else if(IsMessageOp(type))
		{
			if(DecodeMessageTx(tx, op, nOut, vvch))
			{
				if(op == type)
				{
					if(vvch.size() >= 1 && vchToFind == vvch[0])
					{
						return true;
					}
				}
			}
		}
	}
	return false;

}

CAmount convertCurrencyCodeToDarkSilk(const vector<unsigned char> &vchCurrencyCode, const float &nPrice, const unsigned int &nHeight, int &precision)
{
	CAmount sysPrice = 0;
	CAmount nRate;
	vector<string> rateList;
	if(getCurrencyToDRKSLKFromAccount(vchCurrencyCode, nRate, nHeight, rateList, precision) == "")
	{
		float price = nPrice*(float)nRate;
		sysPrice = CAmount(price);
	}
	return sysPrice;
}
string getCurrencyToDRKSLKFromAccount(const vector<unsigned char> &vchCurrency, CAmount &nFee, const unsigned int &nHeightToFind, vector<string>& rateList, int &precision)
{
	vector<unsigned char> vchName = vchFromString("DRKSLK_RATES");
	string currencyCodeToFind = stringFromVch(vchCurrency);
	// check for account existence in DB
	vector<CAccountIndex> vtxPos;
	if (!paccountdb->ReadAccount(vchName, vtxPos) || vtxPos.empty())
	{
		if(fDebug)
			LogPrintf("getCurrencyToDRKSLKFromAccount() Could not find DRKSLK_RATES account\n");
		return "1";
	}
	if (vtxPos.size() < 1)
	{
		if(fDebug)
			LogPrintf("getCurrencyToDRKSLKFromAccount() Could not find DRKSLK_RATES account (vtxPos.size() == 0)\n");
		return "1";
	}
	CAccountIndex foundAccount;
	for(unsigned int i=0;i<vtxPos.size();i++) {
        CAccountIndex a = vtxPos[i];
        if(a.nHeight <= nHeightToFind) {
            foundAccount = a;
        }
		else
			break;
    }
	if(foundAccount.IsNull())
		foundAccount = vtxPos.back();


	bool found = false;
	string value = stringFromVch(foundAccount.vchPublicValue);
	
	UniValue outerValue(UniValue::VSTR);
	bool read = outerValue.read(value);
	if (read)
	{
		UniValue outerObj = outerValue.get_obj();
		UniValue ratesValue = find_value(outerObj, "rates");
		if (ratesValue.isArray())
		{
			UniValue codes = ratesValue.get_array();
			for (unsigned int idx = 0; idx < codes.size(); idx++) {
				const UniValue& code = codes[idx];					
				UniValue codeObj = code.get_obj();					
				UniValue currencyNameValue = find_value(codeObj, "currency");
				UniValue currencyAmountValue = find_value(codeObj, "rate");
				if (currencyNameValue.isStr())
				{		
					string currencyCode = currencyNameValue.get_str();
					rateList.push_back(currencyCode);
					if(currencyCodeToFind == currencyCode)
					{
						UniValue precisionValue = find_value(codeObj, "precision");
						if(precisionValue.isNum())
						{
							precision = precisionValue.get_int();
						}
						if(currencyAmountValue.isNum())
						{
							found = true;
							try{
								nFee = AmountFromValue(currencyAmountValue.get_real());
							}
							catch(std::runtime_error& err)
							{
								nFee = currencyAmountValue.get_int()*COIN;
							}								
						}
					}
				}
			}
		}
		
	}
	else
	{
		if(fDebug)
			printf("getCurrencyToDRKSLKFromAccount() Failed to get value from account\n");
		return "1";
	}
	if(!found)
	{
		if(fDebug)
			LogPrintf("getCurrencyToDRKSLKFromAccount() currency %s not found in DRKSLK_RATES account\n", stringFromVch(vchCurrency).c_str());
		return "0";
	}
	return "";

}
void PutToAccountList(std::vector<CAccountIndex> &accountList, CAccountIndex& index) {
	int i = accountList.size() - 1;
	BOOST_REVERSE_FOREACH(CAccountIndex &o, accountList) {
        if(index.nHeight != 0 && o.nHeight == index.nHeight) {
        	accountList[i] = index;
            return;
        }
        else if(!o.txHash.IsNull() && o.txHash == index.txHash) {
        	accountList[i] = index;
            return;
        }
        i--;
	}
    accountList.push_back(index);
}

bool IsAccountOp(int op) {
	return op == OP_ACCOUNT_ACTIVATE
			|| op == OP_ACCOUNT_UPDATE;
}
string accountFromOp(int op) {
	switch (op) {
	case OP_ACCOUNT_UPDATE:
		return "accountupdate";
	case OP_ACCOUNT_ACTIVATE:
		return "accountactivate";
	default:
		return "<unknown account op>";
	}
}
int GetDarkSilkDataOutput(const CTransaction& tx) {
   for(unsigned int i = 0; i<tx.vout.size();i++) {
	   if(IsDarkSilkDataOutput(tx.vout[i]))
		   return i;
	}
   return -1;
}
bool IsDarkSilkDataOutput(const CTxOut& out) {
   txnouttype whichType;
	if (!IsStandard(out.scriptPubKey, whichType))
		return false;
	if (whichType == TX_NULL_DATA)
		return true;
   return false;
}
int GetDarkSilkTxVersion()
{
	return DARKSILK_TX_VERSION;
}

/**
 * [IsDarkSilkTxMine check if this transaction is mine or not, must contain a darksilk service vout]
 * @param  tx [darksilk based transaction]
 * @param  type [the type of darksilk service you expect in this transaction]
 * @return    [if darksilk transaction is yours based on type passed in]
 */
bool IsDarkSilkTxMine(const CTransaction& tx, const string &type) {
	if (tx.nVersion != DARKSILK_TX_VERSION)
		return false;
	int op, nOut, myNout;
	vector<vector<unsigned char> > vvch;
	if ((type == "account" || type == "any") && DecodeAccountTx(tx, op, nOut, vvch))
		myNout = nOut;
	else if ((type == "offer" || type == "any") && DecodeOfferTx(tx, op, nOut, vvch))
		myNout = nOut;
	else if ((type == "cert" || type == "any") && DecodeCertTx(tx, op, nOut, vvch))
		myNout = nOut;
	else if ((type == "message" || type == "any") && DecodeMessageTx(tx, op, nOut, vvch))
		myNout = nOut;
	else if ((type == "escrow" || type == "any") && DecodeEscrowTx(tx, op, nOut, vvch))
		myNout = nOut;
	else
		return false;

	CScript scriptPubKey;
	RemoveDarkSilkScript(tx.vout[myNout].scriptPubKey, scriptPubKey);
	CTxDestination dest;
	ExtractDestination(scriptPubKey, dest);
	CDarkSilkAddress address(dest);
	return IsMine(*pwalletMain, address.Get());
}
bool IsDarkSilkTxMine(const CTransaction& tx, const string &type, CDarkSilkAddress& myAddress) {
	if (tx.nVersion != DARKSILK_TX_VERSION)
		return false;
	int op, nOut, myNout;
	vector<vector<unsigned char> > vvch;
	if ((type == "account" || type == "any") && DecodeAccountTx(tx, op, nOut, vvch))
		myNout = nOut;
	else if ((type == "offer" || type == "any") && DecodeOfferTx(tx, op, nOut, vvch))
		myNout = nOut;
	else if ((type == "cert" || type == "any") && DecodeCertTx(tx, op, nOut, vvch))
		myNout = nOut;
	else if ((type == "message" || type == "any") && DecodeMessageTx(tx, op, nOut, vvch))
		myNout = nOut;
	else if ((type == "escrow" || type == "any") && DecodeEscrowTx(tx, op, nOut, vvch))
		myNout = nOut;
	else
		return false;

	CScript scriptPubKey;
	RemoveDarkSilkScript(tx.vout[myNout].scriptPubKey, scriptPubKey);
	CTxDestination dest;
	ExtractDestination(scriptPubKey, dest);
	CDarkSilkAddress address(dest);
	myAddress = address;
	return IsMine(*pwalletMain, address.Get());
}
bool CheckAccountInputs(const CTransaction &tx, int op, int nOut, const vector<vector<unsigned char> > &vvchArgs, const CCoinsViewCache &inputs, bool fJustCheck, int nHeight, const CBlock* block) {
	
	if (tx.IsCoinBase())
		return true;
	if (fDebug)
		LogPrintf("*** %d %d %s %s\n", nHeight, chainActive.Tip()->nHeight, tx.GetHash().ToString().c_str(), fJustCheck ? "JUSTCHECK" : "BLOCK");
	const COutPoint *prevOutput = NULL;
	CCoins prevCoins;
	int prevOp = 0;
	vector<vector<unsigned char> > vvchPrevArgs;
	if(fJustCheck)
	{
		// Strict check - bug disallowed
		for (unsigned int i = 0; i < tx.vin.size(); i++) {
			vector<vector<unsigned char> > vvch;
			int pop;
			prevOutput = &tx.vin[i].prevout;
			if(!prevOutput)
				continue;
			// ensure inputs are unspent when doing consensus check to add to block
			if(!inputs.GetCoins(prevOutput->hash, prevCoins))
				continue;
			if(!IsDarkSilkScript(prevCoins.vout[prevOutput->n].scriptPubKey, pop, vvch))
				continue;

			if (IsAccountOp(pop)) {
				prevOp = pop;
				vvchPrevArgs = vvch;
				break;
			}
		}
	}
	// Make sure account outputs are not spent by a regular transaction, or the account would be lost
	if (tx.nVersion != DARKSILK_TX_VERSION) {
		LogPrintf("CheckAccountInputs() : non-darksilk transaction\n");
		return true;
	}
	// unserialize account from txn, check for valid
	CAccountIndex theAccount(tx);
	// we need to check for cert update specially because an account update without data is sent along with offers linked with the account
	if (theAccount.IsNull() && op != OP_ACCOUNT_UPDATE)
		return error("CheckAccountInputs() : null account");
	if(theAccount.vchPublicValue.size() > MAX_VALUE_LENGTH)
	{
		return error("account pub value too big");
	}
	if(theAccount.vchPrivateValue.size() > MAX_VALUE_LENGTH)
	{
		return error("account priv value too big");
	}
	if(!theAccount.vchPubKey.empty() && !IsCompressedOrUncompressedPubKey(theAccount.vchPubKey))
	{
		return error("account pub key invalid length");
	}
	if (vvchArgs[0].size() > MAX_NAME_LENGTH)
		return error("account hex guid too long");
	vector<CAccountIndex> vtxPos;
	if(fJustCheck)
	{
		switch (op) {
			case OP_ACCOUNT_ACTIVATE:
				break;
			case OP_ACCOUNT_UPDATE:
				if (!IsAccountOp(prevOp))
					return error("accountupdate previous tx not found");
				// Check name
				if (vvchPrevArgs[0] != vvchArgs[0])
					return error("CheckAccountInputs() : accountupdate account mismatch");
				// get the account from the DB
				if (paccountdb->ExistsAccount(vvchArgs[0])) {
					if (!paccountdb->ReadAccount(vvchArgs[0], vtxPos))
						return error(
								"CheckAccountInputs() : failed to read from account DB");
				}
				if(vtxPos.empty())
					return error("CheckAccountInputs() : No account found to update");
				// if transfer
				if(vtxPos.back().vchPubKey != theAccount.vchPubKey)
				{
					CPubKey xferKey  = CPubKey(theAccount.vchPubKey);	
					CDarkSilkAddress myAddress = CDarkSilkAddress(xferKey.GetID());
					// make sure xfer to pubkey doesn't point to an account already 
					if (paccountdb->ExistsAddress(vchFromString(myAddress.ToString())))
						return error("CheckAccountInputs() : Cannot transfer an account that points to another account");
				}
				break;
		default:
			return error(
					"CheckAccountInputs() : account transaction has unknown op");
		}
	}
	
	if (!fJustCheck ) {
		// get the account from the DB
		if (paccountdb->ExistsAccount(vvchArgs[0])) {
			if (!paccountdb->ReadAccount(vvchArgs[0], vtxPos))
				return error(
						"CheckAccountInputs() : failed to read from account DB");
		}
		if(!vtxPos.empty())
		{
			if(theAccount.IsNull())
				theAccount = vtxPos.back();
			else
			{
				const CAccountIndex& dbAccount = vtxPos.back();
				if(theAccount.vchPublicValue.empty())
					theAccount.vchPublicValue = dbAccount.vchPublicValue;	
				if(theAccount.vchPrivateValue.empty())
					theAccount.vchPrivateValue = dbAccount.vchPrivateValue;	
			}
		}
	

		theAccount.nHeight = nHeight;
		theAccount.txHash = tx.GetHash();

		PutToAccountList(vtxPos, theAccount);
		CPubKey PubKey(theAccount.vchPubKey);
		CDarkSilkAddress address(PubKey.GetID());
		if (!paccountdb->WriteAccount(vvchArgs[0], vchFromString(address.ToString()), vtxPos))
			return error( "CheckAccountInputs() :  failed to write to account DB");
		if(fDebug)
			LogPrintf(
				"CONNECTED ACCOUNT: name=%s  op=%s  hash=%s  height=%d\n",
				stringFromVch(vvchArgs[0]).c_str(),
				accountFromOp(op).c_str(),
				tx.GetHash().ToString().c_str(), nHeight);
	}

	return true;
}

string stringFromValue(const UniValue& value) {
	string strName = value.get_str();
	return strName;
}

vector<unsigned char> vchFromValue(const UniValue& value) {
	string strName = value.get_str();
	unsigned char *strbeg = (unsigned char*) strName.c_str();
	return vector<unsigned char>(strbeg, strbeg + strName.size());
}

std::vector<unsigned char> vchFromString(const std::string &str) {
	unsigned char *strbeg = (unsigned char*) str.c_str();
	return vector<unsigned char>(strbeg, strbeg + str.size());
}

string stringFromVch(const vector<unsigned char> &vch) {
	string res;
	vector<unsigned char>::const_iterator vi = vch.begin();
	while (vi != vch.end()) {
		res += (char) (*vi);
		vi++;
	}
	return res;
}
bool GetDarkSilkData(const CTransaction &tx, vector<unsigned char> &vchData)
{
	int nOut = GetDarkSilkDataOutput(tx);
    if(nOut == -1)
	   return false;

	const CScript &scriptPubKey = tx.vout[nOut].scriptPubKey;
	CScript::const_iterator pc = scriptPubKey.begin();
	opcodetype opcode;
	if (!scriptPubKey.GetOp(pc, opcode))
		return false;
	if(opcode != OP_RETURN)
		return false;
	if (!scriptPubKey.GetOp(pc, opcode, vchData))
		return false;
	return true;
}
bool CAccountIndex::UnserializeFromTx(const CTransaction &tx) {
	vector<unsigned char> vchData;
	if(!GetDarkSilkData(tx, vchData))
	{
		SetNull();
		return false;
	}
    try {
        CDataStream dsAccount(vchData, SER_NETWORK, PROTOCOL_VERSION);
        dsAccount >> *this;
    } catch (std::exception &e) {
		SetNull();
        return false;
    }
	// extra check to ensure data was parsed correctly
	if(!IsCompressedOrUncompressedPubKey(vchPubKey))
	{
		SetNull();
		return false;
	}
    return true;
}
const vector<unsigned char> CAccountIndex::Serialize() {
    CDataStream dsAccount(SER_NETWORK, PROTOCOL_VERSION);
    dsAccount << *this;
    const vector<unsigned char> vchData(dsAccount.begin(), dsAccount.end());
    return vchData;

}
bool CAccountDB::ScanNames(const std::vector<unsigned char>& vchName,
		unsigned int nMax,
		vector<pair<vector<unsigned char>, CAccountIndex> >& nameScan) {

	boost::scoped_ptr<CDBIterator> pcursor(NewIterator());
	pcursor->Seek(make_pair(string("namei"), vchName));
	while (pcursor->Valid()) {
		boost::this_thread::interruption_point();
		pair<string, vector<unsigned char> > key;
		try {
			if (pcursor->GetKey(key) && key.first == "namei") {
				vector<unsigned char> vchName = key.second;
				vector<CAccountIndex> vtxPos;
				pcursor->GetValue(vtxPos);
				CAccountIndex txPos;
				if (!vtxPos.empty())
					txPos = vtxPos.back();
				nameScan.push_back(make_pair(vchName, txPos));
			}
			if (nameScan.size() >= nMax)
				break;

			pcursor->Next();
		} catch (std::exception &e) {
			return error("%s() : deserialize error", __PRETTY_FUNCTION__);
		}
	}
	return true;
}

int GetAccountExpirationDepth() {
	return 525600;
}
bool GetTxOfAccount(const vector<unsigned char> &vchName, 
				  CAccountIndex& txPos, CTransaction& tx) {
	vector<CAccountIndex> vtxPos;
	if (!paccountdb->ReadAccount(vchName, vtxPos) || vtxPos.empty())
		return false;
	txPos = vtxPos.back();
	int nHeight = txPos.nHeight;
	if (nHeight + GetAccountExpirationDepth()
			< chainActive.Tip()->nHeight) {
		string name = stringFromVch(vchName);
		LogPrintf("GetTxOfAccount(%s) : expired", name.c_str());
		return false;
	}

	if (!GetDarkSilkTransaction(nHeight, txPos.txHash, tx, Params().GetConsensus()))
		return error("GetTxOfAccount() : could not read tx from disk");

	return true;
}

void GetAddressFromAccount(const std::string& strAccount, std::string& strAddress) {
	try
	{
		const vector<unsigned char> &vchAccount = vchFromValue(strAccount);
		if (paccountdb && !paccountdb->ExistsAccount(vchAccount))
			throw runtime_error("Account not found");

		// check for account existence in DB
		vector<CAccountIndex> vtxPos;
		if (paccountdb && !paccountdb->ReadAccount(vchAccount, vtxPos))
			throw runtime_error("failed to read from account DB");
		if (vtxPos.size() < 1)
			throw runtime_error("no account result returned");

		// get transaction pointed to by account
		CTransaction tx;
		const CAccountIndex &account = vtxPos.back();
		uint256 txHash = account.txHash;
		if (!GetDarkSilkTransaction(account.nHeight, txHash, tx, Params().GetConsensus()))
			throw runtime_error("failed to read transaction from disk");

		CPubKey PubKey(account.vchPubKey);
		CDarkSilkAddress address(PubKey.GetID());
		if(!address.IsValid())
			throw runtime_error("account address is invalid");
		strAddress = address.ToString();
	}
	catch(...)
	{
		throw runtime_error("could not read account");
	}
}

void GetAccountFromAddress(const std::string& strAddress, std::string& strAccount) {
	try
	{
		const vector<unsigned char> &vchAddress = vchFromValue(strAddress);
		if (paccountdb && !paccountdb->ExistsAddress(vchAddress))
			throw runtime_error("Account address mapping not found");

		// check for account address mapping existence in DB
		vector<unsigned char> vchAccount;
		if (paccountdb && !paccountdb->ReadAddress(vchAddress, vchAccount))
			throw runtime_error("failed to read from account DB");
		if (vchAccount.empty())
			throw runtime_error("no account address mapping result returned");
		strAccount = stringFromVch(vchAccount);
	}
	catch(...)
	{
		throw runtime_error("could not read account address mapping");
	}
}
int IndexOfAccountOutput(const CTransaction& tx) {
	vector<vector<unsigned char> > vvch;
	if (tx.nVersion != DARKSILK_TX_VERSION)
		return -1;
	int op;
	int nOut;
	bool good = DecodeAccountTx(tx, op, nOut, vvch);
	if (!good)
		return -1;
	return nOut;
}

bool GetAccountOfTx(const CTransaction& tx, vector<unsigned char>& name) {
	if (tx.nVersion != DARKSILK_TX_VERSION)
		return false;
	vector<vector<unsigned char> > vvchArgs;
	int op;
	int nOut;

	bool good = DecodeAccountTx(tx, op, nOut, vvchArgs);
	if (!good)
		return error("GetAccountOfTx() : could not decode a darksilk tx");

	switch (op) {
	case OP_ACCOUNT_ACTIVATE:
	case OP_ACCOUNT_UPDATE:
		name = vvchArgs[0];
		return true;
	}
	return false;
}
bool DecodeAndParseDarkSilkTx(const CTransaction& tx, int& op, int& nOut,
		vector<vector<unsigned char> >& vvch)
{
	return DecodeAndParseAccountTx(tx, op, nOut, vvch) 
		|| DecodeAndParseCertTx(tx, op, nOut, vvch)
		|| DecodeAndParseOfferTx(tx, op, nOut, vvch)
		|| DecodeAndParseEscrowTx(tx, op, nOut, vvch)
		|| DecodeAndParseMessageTx(tx, op, nOut, vvch);
}
bool DecodeAndParseAccountTx(const CTransaction& tx, int& op, int& nOut,
		vector<vector<unsigned char> >& vvch)
{
	CAccountIndex account;
	bool decode = DecodeAccountTx(tx, op, nOut, vvch);
	bool parse = account.UnserializeFromTx(tx);
	return decode && parse;
}
bool DecodeAccountTx(const CTransaction& tx, int& op, int& nOut,
		vector<vector<unsigned char> >& vvch) {
	bool found = false;


	// Strict check - bug disallowed
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		vector<vector<unsigned char> > vvchRead;
		if (DecodeAccountScript(out.scriptPubKey, op, vvchRead)) {
			nOut = i;
			found = true;
			vvch = vvchRead;
			break;
		}
	}
	if (!found)
		vvch.clear();

	return found && IsAccountOp(op);
}


bool DecodeAccountScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch, CScript::const_iterator& pc) {
	opcodetype opcode;
	vvch.clear();
	if (!script.GetOp(pc, opcode))
		return false;
	if (opcode < OP_1 || opcode > OP_16)
		return false;

	op = CScript::DecodeOP_N(opcode);

	for (;;) {
		vector<unsigned char> vch;
		if (!script.GetOp(pc, opcode, vch))
			return false;
		if (opcode == OP_DROP || opcode == OP_2DROP || opcode == OP_NOP)
			break;
		if (!(opcode >= 0 && opcode <= OP_PUSHDATA4))
			return false;
		vvch.push_back(vch);
	}

	// move the pc to after any DROP or NOP
	while (opcode == OP_DROP || opcode == OP_2DROP || opcode == OP_NOP) {
		if (!script.GetOp(pc, opcode))
			break;
	}

	pc--;

	if ((op == OP_ACCOUNT_ACTIVATE && vvch.size() == 1)
			|| (op == OP_ACCOUNT_UPDATE && vvch.size() == 1))
		return true;
	return false;
}
bool DecodeAccountScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch) {
	CScript::const_iterator pc = script.begin();
	return DecodeAccountScript(script, op, vvch, pc);
}
CScript RemoveAccountScriptPrefix(const CScript& scriptIn) {
	int op;
	vector<vector<unsigned char> > vvch;
	CScript::const_iterator pc = scriptIn.begin();

	if (!DecodeAccountScript(scriptIn, op, vvch, pc))
		throw runtime_error(
				"RemoveAccountScriptPrefix() : could not decode name script");
	return CScript(pc, scriptIn.end());
}
void CreateRecipient(const CScript& scriptPubKey, CRecipient& recipient)
{
	CAmount defaultamt = 0;
	CRecipient recipienttmp = {scriptPubKey, defaultamt, false};
	CTxOut txout(recipienttmp.nAmount,	recipienttmp.scriptPubKey);
	recipienttmp.nAmount = txout.GetDustThreshold(::minRelayTxFee);
	recipient = recipienttmp;
}
void CreateFeeRecipient(const CScript& scriptPubKey, const vector<unsigned char>& data, CRecipient& recipient)
{
	CAmount defaultamt = 0;
	CScript script;
	script += CScript() << data;
	CTxOut txout(defaultamt,script);
	CRecipient recipienttmp = {scriptPubKey, defaultamt, false};
	recipienttmp.nAmount = txout.GetDustThreshold(::minRelayTxFee);
	recipient = recipienttmp;
}
UniValue accountnew(const UniValue& params, bool fHelp) {
	if (fHelp || 2 > params.size() || 3 < params.size())
		throw runtime_error(
		"accountnew <accountname> <public value> [private value]\n"
						"<accountname> account name.\n"
						"<public value> account public profile data, 1023 chars max.\n"
						"<private value> account private profile data, 1023 chars max. Will be private and readable by owner only.\n"
						+ HelpRequiringPassphrase());

	vector<unsigned char> vchName = vchFromString(params[0].get_str());
	vector<unsigned char> vchPublicValue;
	vector<unsigned char> vchPrivateValue;
	string strPublicValue = params[1].get_str();
	vchPublicValue = vchFromString(strPublicValue);

	string strPrivateValue = params.size()>=3?params[2].get_str():"";
	vchPrivateValue = vchFromString(strPrivateValue);
	if (vchPublicValue.size() > MAX_VALUE_LENGTH)
		throw runtime_error("account public value cannot exceed 1023 bytes!");
	if (vchPrivateValue.size() > MAX_VALUE_LENGTH)
		throw runtime_error("account private value cannot exceed 1023 bytes!");
	if (vchName.size() > MAX_NAME_LENGTH)
		throw runtime_error("account name cannot exceed 255 bytes!");


	CDarkSilkAddress myAddress = CDarkSilkAddress(stringFromVch(vchName));
	if(myAddress.IsValid() && !myAddress.isAccount)
		throw runtime_error("account name cannot be a darksilk address!");

	CWalletTx wtx;

	CTransaction tx;
	CAccountIndex theAccount;
	if (GetTxOfAccount(vchName, theAccount, tx)) {
		error("accountactivate() : this account is already active with tx %s",
				tx.GetHash().GetHex().c_str());
		throw runtime_error("this account is already active");
	}

	EnsureWalletIsUnlocked();

	// check for existing pending accountes
	if (ExistsInMempool(vchName, OP_ACCOUNT_ACTIVATE)) {
		throw runtime_error("there are pending operations on that account");
	}
	

	CPubKey newDefaultKey;
	pwalletMain->GetKeyFromPool(newDefaultKey);
	CScript scriptPubKeyOrig;
	scriptPubKeyOrig = GetScriptForDestination(newDefaultKey.GetID());
	CScript scriptPubKey;
	scriptPubKey << CScript::EncodeOP_N(OP_ACCOUNT_ACTIVATE) << vchName << OP_2DROP;
	scriptPubKey += scriptPubKeyOrig;
	std::vector<unsigned char> vchPubKey(newDefaultKey.begin(), newDefaultKey.end());

	if(vchPrivateValue.size() > 0)
	{
		string strCipherText;
		if(!EncryptMessage(vchPubKey, vchPrivateValue, strCipherText))
		{
			throw runtime_error("Could not encrypt private account value!");
		}
		if (strCipherText.size() > MAX_ENCRYPTED_VALUE_LENGTH)
			throw runtime_error("private data length cannot exceed 1023 bytes!");
		vchPrivateValue = vchFromString(strCipherText);
	}

    // build account
    CAccountIndex newAccount;
	newAccount.nHeight = chainActive.Tip()->nHeight;
	newAccount.vchPubKey = vchPubKey;
	newAccount.vchPublicValue = vchPublicValue;
	newAccount.vchPrivateValue = vchPrivateValue;

    vector<CRecipient> vecSend;
	CRecipient recipient;
	CreateRecipient(scriptPubKey, recipient);
	vecSend.push_back(recipient);
	CScript scriptData;
	const vector<unsigned char> &data = newAccount.Serialize();
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, data, fee);
	vecSend.push_back(fee);
	// send the tranasction
	SendMoneyDarkSilk(vecSend, recipient.nAmount + fee.nAmount, false, wtx);
	UniValue res(UniValue::VARR);
	res.push_back(wtx.GetHash().GetHex());
	res.push_back(HexStr(vchPubKey));
	return res;
}
UniValue accountupdate(const UniValue& params, bool fHelp) {
	if (fHelp || 2 > params.size() || 4 < params.size())
		throw runtime_error(
		"accountupdate <accountname> <public value> [private value] [<toaccount_pubkey>]\n"
						"Update and possibly transfer an account.\n"
						"<accountname> account name.\n"
						"<public value> account public profile data, 1023 chars max.\n"
						"<private value> account private profile data, 1023 chars max. Will be private and readable by owner only.\n"
						"<toaccount_pubkey> receiver darksilk account pub key, if transferring account.\n"
						+ HelpRequiringPassphrase());

	vector<unsigned char> vchName = vchFromString(params[0].get_str());
	vector<unsigned char> vchPublicValue;
	vector<unsigned char> vchPrivateValue;
	string strPublicValue = params[1].get_str();
	vchPublicValue = vchFromString(strPublicValue);
	string strPrivateValue = params.size()>=3?params[2].get_str():"";
	vchPrivateValue = vchFromString(strPrivateValue);
	if (vchPublicValue.size() > MAX_VALUE_LENGTH)
		throw runtime_error("account public value cannot exceed 1023 bytes!");
	if (vchPrivateValue.size() > MAX_VALUE_LENGTH)
		throw runtime_error("account public value cannot exceed 1023 bytes!");
	vector<unsigned char> vchPubKeyByte;

	CWalletTx wtx;
	CAccountIndex updateAccount;
	const CWalletTx* wtxIn;
	CScript scriptPubKeyOrig;
	string strPubKey;
    if (params.size() >= 4) {
		vector<unsigned char> vchPubKey;
		vchPubKey = vchFromString(params[3].get_str());
		boost::algorithm::unhex(vchPubKey.begin(), vchPubKey.end(), std::back_inserter(vchPubKeyByte));
		CPubKey xferKey  = CPubKey(vchPubKeyByte);
		if(!xferKey.IsValid())
			throw runtime_error("Invalid public key");
		CDarkSilkAddress myAddress = CDarkSilkAddress(xferKey.GetID());
		if (paccountdb->ExistsAddress(vchFromString(myAddress.ToString())))
			throw runtime_error("You must transfer to a public key that's not associated with any other account");
	}

	EnsureWalletIsUnlocked();
	CTransaction tx;
	CAccountIndex theAccount;
	if (!GetTxOfAccount(vchName, theAccount, tx))
		throw runtime_error("could not find an account with this name");

    if(!IsDarkSilkTxMine(tx, "account")) {
		throw runtime_error("This account is not yours, you cannot update it.");
    }
	wtxIn = pwalletMain->GetWalletTx(tx.GetHash());
	if (wtxIn == NULL)
		throw runtime_error("this account is not in your wallet");
	// check for existing pending accountes
	if (ExistsInMempool(vchName, OP_ACCOUNT_ACTIVATE) || ExistsInMempool(vchName, OP_ACCOUNT_UPDATE)) {
		throw runtime_error("there are pending operations on that account");
	}

	if(vchPubKeyByte.empty())
		vchPubKeyByte = theAccount.vchPubKey;
	if(vchPrivateValue.size() > 0)
	{
		string strCipherText;
		
		// encrypt using new key
		if(!EncryptMessage(vchPubKeyByte, vchPrivateValue, strCipherText))
		{
			throw runtime_error("Could not encrypt account private data!");
		}
		if (strCipherText.size() > MAX_ENCRYPTED_VALUE_LENGTH)
			throw runtime_error("data length cannot exceed 1023 bytes!");
		vchPrivateValue = vchFromString(strCipherText);
	}

	CAccountIndex copyAccount = theAccount;
	theAccount.ClearAccount();

	theAccount.nHeight = chainActive.Tip()->nHeight;
	if(copyAccount.vchPublicValue != vchPublicValue)
		theAccount.vchPublicValue = vchPublicValue;
	if(copyAccount.vchPrivateValue != vchPrivateValue)
		theAccount.vchPrivateValue = vchPrivateValue;

	theAccount.vchPubKey = vchPubKeyByte;
	CPubKey currentKey(vchPubKeyByte);
	scriptPubKeyOrig = GetScriptForDestination(currentKey.GetID());
	CScript scriptPubKey;
	scriptPubKey << CScript::EncodeOP_N(OP_ACCOUNT_UPDATE) << vchName << OP_2DROP;
	scriptPubKey += scriptPubKeyOrig;

    vector<CRecipient> vecSend;
	CRecipient recipient;
	CreateRecipient(scriptPubKey, recipient);
	vecSend.push_back(recipient);
	const vector<unsigned char> &data = theAccount.Serialize();
	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, data, fee);
	vecSend.push_back(fee);
	const CWalletTx * wtxInOffer=NULL;
	const CWalletTx * wtxInCert=NULL;
	const CWalletTx * wtxInEscrow=NULL;
	SendMoneyDarkSilk(vecSend, recipient.nAmount+fee.nAmount, false, wtx, wtxInOffer, wtxInCert, wtxIn, wtxInEscrow);
	UniValue res(UniValue::VARR);
	res.push_back(wtx.GetHash().GetHex());
	return res;
}

UniValue accountlist(const UniValue& params, bool fHelp) {
	if (fHelp || 1 < params.size())
		throw runtime_error("accountlist [<accountname>]\n"
				"list my own accountes.\n"
				"<accountname> account name to use as filter.\n");
	
	vector<unsigned char> vchName;

	if (params.size() == 1)
		vchName = vchFromValue(params[0]);

	vector<unsigned char> vchNameUniq;
	if (params.size() == 1)
		vchNameUniq = vchFromValue(params[0]);
	UniValue oRes(UniValue::VARR);
	map<vector<unsigned char>, int> vNamesI;
	map<vector<unsigned char>, UniValue> vNamesO;

	{
		uint256 hash;
		CTransaction tx;
		int pending = 0;
		uint64_t nHeight;
		BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, pwalletMain->mapWallet) {
			pending = 0;
			// get txn hash, read txn index
			hash = item.second.GetHash();
			const CWalletTx &wtx = item.second;
			// skip non-darksilk txns
			if (wtx.nVersion != DARKSILK_TX_VERSION)
				continue;

			// decode txn, skip non-account txns
			vector<vector<unsigned char> > vvch;
			int op, nOut;
			if (!DecodeAccountTx(wtx, op, nOut, vvch) || !IsAccountOp(op))
				continue;

			// get the txn account name
			if (!GetAccountOfTx(wtx, vchName))
				continue;

			// skip this account if it doesn't match the given filter value
			if (vchNameUniq.size() > 0 && vchNameUniq != vchName)
				continue;
			vector<CAccountIndex> vtxPos;
			CAccountIndex account;
			if (!paccountdb->ReadAccount(vchName, vtxPos) || vtxPos.empty())
			{
				pending = 1;
				account = CAccountIndex(wtx);
				if(!IsDarkSilkTxMine(wtx, "account"))
					continue;
			}
			else
			{
				account = vtxPos.back();
				CTransaction tx;
				if (!GetDarkSilkTransaction(account.nHeight, account.txHash, tx, Params().GetConsensus()))
					continue;
				if (!DecodeAccountTx(tx, op, nOut, vvch) || !IsAccountOp(op))
					continue;
				if(!IsDarkSilkTxMine(tx, "account"))
					continue;
			}

			nHeight = account.nHeight;
			// get last active name only
			if (vNamesI.find(vchName) != vNamesI.end() && (nHeight < vNamesI[vchName] || vNamesI[vchName] < 0))
				continue;	
			int expired = 0;
			int expires_in = 0;
			int expired_block = 0;
			// build the output UniValue
			UniValue oName(UniValue::VOBJ);
			oName.push_back(Pair("name", stringFromVch(vchName)));
			oName.push_back(Pair("value", stringFromVch(account.vchPublicValue)));
			string strPrivateValue = "";
			if(account.vchPrivateValue.size() > 0)
				strPrivateValue = "Encrypted for account owner";
			string strDecrypted = "";
			if(DecryptMessage(account.vchPubKey, account.vchPrivateValue, strDecrypted))
				strPrivateValue = strDecrypted;		
			oName.push_back(Pair("privatevalue", strPrivateValue));
			expired_block = nHeight + GetAccountExpirationDepth();
			if(pending == 0 && (nHeight + GetAccountExpirationDepth() - chainActive.Tip()->nHeight <= 0))
			{
				expired = 1;
			}  
			if(pending == 0 && expired == 0)
			{
				expires_in = nHeight + GetAccountExpirationDepth() - chainActive.Tip()->nHeight;
			}
			oName.push_back(Pair("expires_in", expires_in));
			oName.push_back(Pair("expires_on", expired_block));
			oName.push_back(Pair("expired", expired));
			oName.push_back(Pair("pending", pending));
			vNamesI[vchName] = nHeight;
			vNamesO[vchName] = oName;					

		}
	}

	BOOST_FOREACH(const PAIRTYPE(vector<unsigned char>, UniValue)& item, vNamesO)
		oRes.push_back(item.second);

	return oRes;
}
UniValue accountaffiliates(const UniValue& params, bool fHelp) {
	if (fHelp || 1 < params.size())
		throw runtime_error("accountaffiliates \n"
				"list my own affiliations with merchant offers.\n");
	

	vector<unsigned char> vchOffer;
	UniValue oRes(UniValue::VARR);
	map<vector<unsigned char>, int> vOfferI;
	map<vector<unsigned char>, UniValue> vOfferO;
	{
		uint256 hash;
		CTransaction tx;
		int pending = 0;
		uint64_t nHeight;
		BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, pwalletMain->mapWallet) {
			pending = 0;
			// get txn hash, read txn index
			hash = item.second.GetHash();
			const CWalletTx &wtx = item.second;
			// skip non-darksilk txns
			if (wtx.nVersion != DARKSILK_TX_VERSION)
				continue;

			// decode txn, skip non-account txns
            vector<vector<unsigned char> > vvch;
            int op, nOut;
            if (!DecodeOfferTx(wtx, op, nOut, vvch) 
            	|| !IsOfferOp(op) 
            	|| (op == OP_OFFER_ACCEPT))
                continue;
			if(!IsDarkSilkTxMine(wtx, "offer"))
					continue;
            vchOffer = vvch[0];

			vector<COffer> vtxPos;
			COffer theOffer;
			if (!pofferdb->ReadOffer(vchOffer, vtxPos) || vtxPos.empty())
				continue;
			
			theOffer = vtxPos.back();
			nHeight = theOffer.nHeight;
			// get last active name only
			if (vOfferI.find(vchOffer) != vOfferI.end() && (nHeight < vOfferI[vchOffer] || vOfferI[vchOffer] < 0))
				continue;
			vOfferI[vchOffer] = nHeight;
			// if this is my offer and it is linked go through else skip
			if(theOffer.vchLinkOffer.empty())
				continue;
			// get parent offer
			CTransaction tx;
			COffer linkOffer;
			if (!GetTxOfOffer( theOffer.vchLinkOffer, linkOffer, tx))
				continue;

			for(unsigned int i=0;i<linkOffer.linkWhitelist.entries.size();i++) {
				CTransaction txAccount;
				CAccountIndex theAccount;
				COfferLinkWhitelistEntry& entry = linkOffer.linkWhitelist.entries[i];
				if (GetTxOfAccount(entry.accountLinkVchRand, theAccount, txAccount))
				{
					if (!IsDarkSilkTxMine(txAccount, "account"))
						continue;
					UniValue oList(UniValue::VOBJ);
					oList.push_back(Pair("offer", stringFromVch(vchOffer)));
					oList.push_back(Pair("account", stringFromVch(entry.accountLinkVchRand)));
					int expires_in = 0;
					if(nHeight + GetAccountExpirationDepth() - chainActive.Tip()->nHeight > 0)
					{
						expires_in = nHeight + GetAccountExpirationDepth() - chainActive.Tip()->nHeight;
					}  
					oList.push_back(Pair("expiresin",expires_in));
					oList.push_back(Pair("offer_discount_percentage", strprintf("%d%%", entry.nDiscountPct)));
					vOfferO[vchOffer] = oList;	
				}  
			}
		}
	}

	BOOST_FOREACH(const PAIRTYPE(vector<unsigned char>, UniValue)& item, vOfferO)
		oRes.push_back(item.second);

	return oRes;
}
/**
 * [accountinfo description]
 * @param  params [description]
 * @param  fHelp  [description]
 * @return        [description]
 */
UniValue accountinfo(const UniValue& params, bool fHelp) {
	if (fHelp || 1 != params.size())
		throw runtime_error("accountinfo <accountname>\n"
				"Show values of an account.\n");
	vector<unsigned char> vchName = vchFromValue(params[0]);
	CTransaction tx;
	UniValue oShowResult(UniValue::VOBJ);

	{

		// check for account existence in DB
		vector<CAccountIndex> vtxPos;
		if (!paccountdb->ReadAccount(vchName, vtxPos))
			throw runtime_error("failed to read from account DB");
		if (vtxPos.size() < 1)
			throw runtime_error("no result returned");

		// get transaction pointed to by account
		uint256 txHash = vtxPos.back().txHash;
		if (!GetDarkSilkTransaction(vtxPos.back().nHeight, txHash, tx, Params().GetConsensus()))
			throw runtime_error("failed to read transaction from disk");

		UniValue oName(UniValue::VOBJ);
		uint64_t nHeight;
		int expired = 0;
		int expires_in = 0;
		int expired_block = 0;
		nHeight = vtxPos.back().nHeight;
		oName.push_back(Pair("name", stringFromVch(vchName)));
		const CAccountIndex &account= vtxPos.back();
		oName.push_back(Pair("value", stringFromVch(account.vchPublicValue)));
		string strPrivateValue = "";
		if(account.vchPrivateValue.size() > 0)
			strPrivateValue = "Encrypted for account owner";
		string strDecrypted = "";
		if(DecryptMessage(account.vchPubKey, account.vchPrivateValue, strDecrypted))
			strPrivateValue = strDecrypted;		
		oName.push_back(Pair("privatevalue", strPrivateValue));
		oName.push_back(Pair("txid", tx.GetHash().GetHex()));
		CPubKey PubKey(account.vchPubKey);
		CDarkSilkAddress address(PubKey.GetID());
		if(!address.IsValid())
			throw runtime_error("Invalid account address");
		oName.push_back(Pair("address", address.ToString()));
		bool fAccountMine = IsDarkSilkTxMine(tx, "account")? true:  false;
		oName.push_back(Pair("ismine", fAccountMine));
        oName.push_back(Pair("lastupdate_height", nHeight));
		expired_block = nHeight + GetAccountExpirationDepth();
		if(nHeight + GetAccountExpirationDepth() - chainActive.Tip()->nHeight <= 0)
		{
			expired = 1;
		}  
		if(expired == 0)
		{
			expires_in = nHeight + GetAccountExpirationDepth() - chainActive.Tip()->nHeight;
		}
		oName.push_back(Pair("expires_in", expires_in));
		oName.push_back(Pair("expires_on", expired_block));
		oName.push_back(Pair("expired", expired));
		oShowResult = oName;
	}
	return oShowResult;
}

/**
 * [accounthistory description]
 * @param  params [description]
 * @param  fHelp  [description]
 * @return        [description]
 */
UniValue accounthistory(const UniValue& params, bool fHelp) {
	if (fHelp || 1 != params.size())
		throw runtime_error("accounthistory <accountname>\n"
				"List all stored values of an account.\n");
	UniValue oRes(UniValue::VARR);
	vector<unsigned char> vchName = vchFromValue(params[0]);
	string name = stringFromVch(vchName);

	{
		vector<CAccountIndex> vtxPos;
		if (!paccountdb->ReadAccount(vchName, vtxPos) || vtxPos.empty())
			throw runtime_error("failed to read from account DB");

		CAccountIndex txPos2;
		uint256 txHash;
		BOOST_FOREACH(txPos2, vtxPos) {
			txHash = txPos2.txHash;
			CTransaction tx;
			if (!GetDarkSilkTransaction(txPos2.nHeight, txHash, tx, Params().GetConsensus()))
			{
				error("could not read txpos");
				continue;
			}
            // decode txn, skip non-account txns
            vector<vector<unsigned char> > vvch;
            int op, nOut;
            if (!DecodeAccountTx(tx, op, nOut, vvch) 
            	|| !IsAccountOp(op) )
                continue;
			int expired = 0;
			int expires_in = 0;
			int expired_block = 0;
			UniValue oName(UniValue::VOBJ);
			uint64_t nHeight;
			nHeight = txPos2.nHeight;
			oName.push_back(Pair("name", name));
			string opName = accountFromOp(op);
			oName.push_back(Pair("accounttype", opName));
			oName.push_back(Pair("value", stringFromVch(txPos2.vchPublicValue)));
			string strPrivateValue = "";
			if(txPos2.vchPrivateValue.size() > 0)
				strPrivateValue = "Encrypted for account owner";
			string strDecrypted = "";
			if(DecryptMessage(txPos2.vchPubKey, txPos2.vchPrivateValue, strDecrypted))
				strPrivateValue = strDecrypted;		
			oName.push_back(Pair("privatevalue", strPrivateValue));
			oName.push_back(Pair("txid", tx.GetHash().GetHex()));
			CPubKey PubKey(txPos2.vchPubKey);
			CDarkSilkAddress address(PubKey.GetID());
			oName.push_back(Pair("address", address.ToString()));
            oName.push_back(Pair("lastupdate_height", nHeight));
			expired_block = nHeight + GetAccountExpirationDepth();
			if(nHeight + GetAccountExpirationDepth() - chainActive.Tip()->nHeight <= 0)
			{
				expired = 1;
			}  
			if(expired == 0)
			{
				expires_in = nHeight + GetAccountExpirationDepth() - chainActive.Tip()->nHeight;
			}
			oName.push_back(Pair("expires_in", expires_in));
			oName.push_back(Pair("expires_on", expired_block));
			oName.push_back(Pair("expired", expired));
			oRes.push_back(oName);
		}
	}
	return oRes;
}
UniValue generatepublickey(const UniValue& params, bool fHelp) {
	if(!pwalletMain)
		throw runtime_error("No wallet defined!");
	CPubKey PubKey = pwalletMain->GenerateNewKey();
	std::vector<unsigned char> vchPubKey(PubKey.begin(), PubKey.end());
	UniValue res(UniValue::VARR);
	res.push_back(HexStr(vchPubKey));
	return res;
}
/**
 * [accountfilter description]
 * @param  params [description]
 * @param  fHelp  [description]
 * @return        [description]
 */
UniValue accountfilter(const UniValue& params, bool fHelp) {
	if (fHelp || params.size() > 5)
		throw runtime_error(
				"accountfilter [[[[[regexp] maxage=36000] from=0] nb=0] stat]\n"
						"scan and filter accountes\n"
						"[regexp] : apply [regexp] on accountes, empty means all accountes\n"
						"[maxage] : look in last [maxage] blocks\n"
						"[from] : show results from number [from]\n"
						"[nb] : show [nb] results, 0 means all\n"
						"[stat] : show some stats instead of results\n"
						"accountfilter \"\" 5 # list accountes updated in last 5 blocks\n"
						"accountfilter \"^name\" # list all accountes starting with \"name\"\n"
						"accountfilter 36000 0 0 stat # display stats (number of names) on active accountes\n");

	string strRegexp;
	int nFrom = 0;
	int nNb = 0;
	int nMaxAge = GetAccountExpirationDepth();
	bool fStat = false;
	int nCountFrom = 0;
	int nCountNb = 0;
	/* when changing this to match help, review bitcoinrpc.cpp RPCConvertValues() */
	if (params.size() > 0)
		strRegexp = params[0].get_str();

	if (params.size() > 1)
		nMaxAge = params[1].get_int();

	if (params.size() > 2)
		nFrom = params[2].get_int();

	if (params.size() > 3)
		nNb = params[3].get_int();

	if (params.size() > 4)
		fStat = (params[4].get_str() == "stat" ? true : false);

	UniValue oRes(UniValue::VARR);

	vector<unsigned char> vchName;
	vector<pair<vector<unsigned char>, CAccountIndex> > nameScan;
	if (!paccountdb->ScanNames(vchName, GetAccountExpirationDepth(), nameScan))
		throw runtime_error("scan failed");
	// regexp
	using namespace boost::xpressive;
	smatch nameparts;
	string strRegexpLower = strRegexp;
	boost::algorithm::to_lower(strRegexpLower);
	sregex cregex = sregex::compile(strRegexpLower);
	pair<vector<unsigned char>, CAccountIndex> pairScan;
	BOOST_FOREACH(pairScan, nameScan) {
		const CAccountIndex &account = pairScan.second;
		CPubKey PubKey(account.vchPubKey);
		CDarkSilkAddress address(PubKey.GetID());
		string name = stringFromVch(pairScan.first);
		boost::algorithm::to_lower(name);
		if (strRegexp != "" && !regex_search(name, nameparts, cregex) && strRegexp != address.ToString())
			continue;

		CAccountIndex txName = pairScan.second;
		int nHeight = txName.nHeight;

		// max age
		if (nMaxAge != 0 && chainActive.Tip()->nHeight - nHeight >= nMaxAge)
			continue;

		// from limits
		nCountFrom++;
		if (nCountFrom < nFrom + 1)
			continue;


		int expired = 0;
		int expires_in = 0;
		int expired_block = 0;
		UniValue oName(UniValue::VOBJ);
		oName.push_back(Pair("name", stringFromVch(pairScan.first)));
		CTransaction tx;
		uint256 txHash = txName.txHash;
		if (!GetDarkSilkTransaction(txName.nHeight, txHash, tx, Params().GetConsensus()))
			continue;

		oName.push_back(Pair("value", stringFromVch(txName.vchPublicValue)));
		string strPrivateValue = "";
		if(account.vchPrivateValue.size() > 0)
			strPrivateValue = "Encrypted for account owner";
		string strDecrypted = "";
		if(DecryptMessage(txName.vchPubKey, account.vchPrivateValue, strDecrypted))
			strPrivateValue = strDecrypted;		
		oName.push_back(Pair("privatevalue", strPrivateValue));
		oName.push_back(Pair("txid", txHash.GetHex()));
        oName.push_back(Pair("lastupdate_height", nHeight));
		expired_block = nHeight + GetAccountExpirationDepth();
        if(nHeight + GetAccountExpirationDepth() - chainActive.Tip()->nHeight <= 0)
		{
			expired = 1;
		}  
		if(expired == 0)
		{
			expires_in = nHeight + GetAccountExpirationDepth() - chainActive.Tip()->nHeight;
		}
		oName.push_back(Pair("expires_in", expires_in));
		oName.push_back(Pair("expires_on", expired_block));
		oName.push_back(Pair("expired", expired));

		
		oRes.push_back(oName);

		nCountNb++;
		// nb limits
		if (nNb > 0 && nCountNb >= nNb)
			break;
	}

	if (fStat) {
		UniValue oStat(UniValue::VOBJ);
		oStat.push_back(Pair("blocks", (int) chainActive.Tip()->nHeight));
		oStat.push_back(Pair("count", (int) oRes.size()));
		return oStat;
	}

	return oRes;
}

/**
 * [accountscan description]
 * @param  params [description]
 * @param  fHelp  [description]
 * @return        [description]
 */
UniValue accountscan(const UniValue& params, bool fHelp) {
	if (fHelp || 2 > params.size())
		throw runtime_error(
				"accountscan [<start-name>] [<max-returned>]\n"
						"scan all accountes, starting at start-name and returning a maximum number of entries (default 500)\n");

	vector<unsigned char> vchName;
	int nMax = 500;
	if (params.size() > 0)
		vchName = vchFromValue(params[0]);
	if (params.size() > 1) {
		nMax = params[1].get_int();
	}

	UniValue oRes(UniValue::VARR);

	vector<pair<vector<unsigned char>, CAccountIndex> > nameScan;
	if (!paccountdb->ScanNames(vchName, nMax, nameScan))
		throw runtime_error("scan failed");

	pair<vector<unsigned char>, CAccountIndex> pairScan;
	BOOST_FOREACH(pairScan, nameScan) {
		UniValue oName(UniValue::VOBJ);
		string name = stringFromVch(pairScan.first);
		oName.push_back(Pair("name", name));
		CTransaction tx;
		CAccountIndex txName = pairScan.second;
		uint256 blockHash;
		int expired = 0;
		int expires_in = 0;
		int expired_block = 0;
		int nHeight = txName.nHeight;
		if (!GetDarkSilkTransaction(nHeight, txName.txHash, tx, Params().GetConsensus()))
			continue;

		oName.push_back(Pair("txid", txName.txHash.GetHex()));
		oName.push_back(Pair("value", stringFromVch(txName.vchPublicValue)));
		string strPrivateValue = "";
		if(txName.vchPrivateValue.size() > 0)
			strPrivateValue = "Encrypted for account owner";
		string strDecrypted = "";
		if(DecryptMessage(txName.vchPubKey, txName.vchPrivateValue, strDecrypted))
			strPrivateValue = strDecrypted;		
		oName.push_back(Pair("privatevalue", strPrivateValue));
        oName.push_back(Pair("lastupdate_height", nHeight));
		expired_block = nHeight + GetAccountExpirationDepth();
		if(nHeight + GetAccountExpirationDepth() - chainActive.Tip()->nHeight <= 0)
		{
			expired = 1;
		}  
		if(expired == 0)
		{
			expires_in = nHeight + GetAccountExpirationDepth() - chainActive.Tip()->nHeight;
		}
		oName.push_back(Pair("expires_in", expires_in));
		oName.push_back(Pair("expires_on", expired_block));
		oName.push_back(Pair("expired", expired));
		
		oRes.push_back(oName);
	}

	return oRes;
}