// Copyright (c) 2009-2016 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Developers
// Copyright (c) 2015-2016 Silk Network
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp>

#include "json/json_spirit_utils.h"
#include "json/json_spirit_value.h"

#include <stdint.h>

#include "rpc/rpcserver.h"
#include "base58.h"
#include "clientversion.h"
#include "init.h"
#include "main.h"
#include "net.h"
#include "netbase.h"
#include "timedata.h"
#include "util.h"
#include "utilstrencodings.h"
#include "anon/stealth/stealth.h"
#include "anon/stormnode/spork.h"
#include "anon/stormnode/stormnode-sync.h"

#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#endif

using namespace std;
using namespace boost;
using namespace boost::assign;
using namespace json_spirit;

Value getinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getinfo\n"
            "Returns an object containing various state info.");

    proxyType proxy;
    GetProxy(NET_IPV4, proxy);

    Object obj, diff;
    obj.push_back(Pair("version",       FormatFullVersion()));
    obj.push_back(Pair("protocolversion",(int)PROTOCOL_VERSION));
#ifdef ENABLE_WALLET
    if (pwalletMain) {
        obj.push_back(Pair("walletversion", pwalletMain->GetVersion()));
        obj.push_back(Pair("balance",       ValueFromAmount(pwalletMain->GetBalance())));
        obj.push_back(Pair("newmint",       ValueFromAmount(pwalletMain->GetNewMint())));
        obj.push_back(Pair("stake",         ValueFromAmount(pwalletMain->GetStake())));
        if(!fLiteMode)
            obj.push_back(Pair("sandstorm_balance",       ValueFromAmount(pwalletMain->GetAnonymizedBalance())));
    }
#endif
    obj.push_back(Pair("blocks",        (int)nBestHeight));
    obj.push_back(Pair("timeoffset",    (int64_t)GetTimeOffset()));
    obj.push_back(Pair("moneysupply",   ValueFromAmount(pindexBest->nMoneySupply)));
    obj.push_back(Pair("connections",   (int)vNodes.size()));
    obj.push_back(Pair("proxy",         (proxy.IsValid() ? proxy.ToStringIPPort() : string())));
    obj.push_back(Pair("ip",            GetLocalAddress(NULL).ToStringIP()));
    diff.push_back(Pair("proof-of-work",  GetDifficulty()));
    diff.push_back(Pair("proof-of-stake", GetDifficulty(GetLastBlockIndex(pindexBest, true))));
    obj.push_back(Pair("difficulty",    diff));
    obj.push_back(Pair("testnet",       TestNet()));
#ifdef ENABLE_WALLET
    if (pwalletMain) {
        obj.push_back(Pair("keypoololdest", (int64_t)pwalletMain->GetOldestKeyPoolTime()));
        obj.push_back(Pair("keypoolsize",   (int)pwalletMain->GetKeyPoolSize()));
    }
    obj.push_back(Pair("paytxfee",      ValueFromAmount(nTransactionFee)));
    obj.push_back(Pair("mininput",      ValueFromAmount(nMinimumInputValue)));
    if (pwalletMain && pwalletMain->IsCrypted())
        obj.push_back(Pair("unlocked_until", (int64_t)nWalletUnlockTime));
#endif
    obj.push_back(Pair("errors",        GetWarnings("statusbar")));
    return obj;
}

Value snsync(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "snsync [status|reset]\n"
            "Returns the sync status or resets sync.\n"
        );

    std::string strMode = params[0].get_str();

    if(strMode == "status") {
        Object obj;

        obj.push_back(Pair("IsBlockchainSynced", stormnodeSync.IsBlockchainSynced()));
        obj.push_back(Pair("lastStormnodeList", stormnodeSync.lastStormnodeList));
        obj.push_back(Pair("lastStormnodeWinner", stormnodeSync.lastStormnodeWinner));
        obj.push_back(Pair("lastBudgetItem", stormnodeSync.lastBudgetItem));
        obj.push_back(Pair("lastFailure", stormnodeSync.lastFailure));
        obj.push_back(Pair("nCountFailures", stormnodeSync.nCountFailures));
        obj.push_back(Pair("sumStormnodeList", stormnodeSync.sumStormnodeList));
        obj.push_back(Pair("sumStormnodeWinner", stormnodeSync.sumStormnodeWinner));
        obj.push_back(Pair("sumBudgetItemProp", stormnodeSync.sumBudgetItemProp));
        obj.push_back(Pair("sumBudgetItemFin", stormnodeSync.sumBudgetItemFin));
        obj.push_back(Pair("countStormnodeList", stormnodeSync.countStormnodeList));
        obj.push_back(Pair("countStormnodeWinner", stormnodeSync.countStormnodeWinner));
        obj.push_back(Pair("countBudgetItemProp", stormnodeSync.countBudgetItemProp));
        obj.push_back(Pair("countBudgetItemFin", stormnodeSync.countBudgetItemFin));
        obj.push_back(Pair("RequestedStormnodeAssets", stormnodeSync.RequestedStormnodeAssets));
        obj.push_back(Pair("RequestedStormnodeAttempt", stormnodeSync.RequestedStormnodeAttempt));


        return obj;
    }

    if(strMode == "reset")
    {
        stormnodeSync.Reset();
        return "success";
    }
    return "failure";
}

#ifdef ENABLE_WALLET
class DescribeAddressVisitor : public boost::static_visitor<Object>
{
private:
    isminetype mine;
public:
    DescribeAddressVisitor(isminetype mineIn) : mine(mineIn) {}

    Object operator()(const CNoDestination &dest) const { return Object(); }

    Object operator()(const CKeyID &keyID) const {
        Object obj;
        CPubKey vchPubKey;
        obj.push_back(Pair("isscript", false));
        if (mine == ISMINE_SPENDABLE) {
            if (pwalletMain && pwalletMain->GetPubKey(keyID, vchPubKey)) {
                obj.push_back(Pair("pubkey", HexStr(vchPubKey)));
                obj.push_back(Pair("iscompressed", vchPubKey.IsCompressed()));
            }       
        }
        return obj;
    }

    Object operator()(const CScriptID &scriptID) const {
        Object obj;
        obj.push_back(Pair("isscript", true));
        if (mine != ISMINE_NO) {
            CScript subscript;
            if (pwalletMain && pwalletMain->GetCScript(scriptID, subscript)){
                std::vector<CTxDestination> addresses;
                txnouttype whichType;
                int nRequired;
                ExtractDestinations(subscript, whichType, addresses, nRequired);
                obj.push_back(Pair("script", GetTxnOutputType(whichType)));
                obj.push_back(Pair("hex", HexStr(subscript.begin(), subscript.end())));
                Array a;
                BOOST_FOREACH(const CTxDestination& addr, addresses)
                    a.push_back(CDarkSilkAddress(addr).ToString());
                obj.push_back(Pair("addresses", a));
                if (whichType == TX_MULTISIG)
                    obj.push_back(Pair("sigsrequired", nRequired));
            }
        }
        return obj;
    }

    Object operator()(const CStealthAddress &stxAddr) const {
        Object obj;
        obj.push_back(Pair("todo", true));
        return obj;
    }
};
#endif

/*
    Used for updating/reading spork settings on the network
*/
Value spork(const Array& params, bool fHelp)
{
    if(params.size() == 1 && params[0].get_str() == "show"){
        Object ret;
        for(unsigned int nSporkID = SPORK_START; nSporkID <= SPORK_END; nSporkID++){
            if(sporkManager.GetSporkNameByID(nSporkID) != "Unknown")
                ret.push_back(Pair(sporkManager.GetSporkNameByID(nSporkID), GetSporkValue(nSporkID)));
        }
        return ret;
    } else if(params.size() == 1 && params[0].get_str() == "active"){
        Object ret;
        for(unsigned int nSporkID = SPORK_START; nSporkID <= SPORK_END; nSporkID++){
            if(sporkManager.GetSporkNameByID(nSporkID) != "Unknown")
                ret.push_back(Pair(sporkManager.GetSporkNameByID(nSporkID), IsSporkActive(nSporkID)));
        }
        return ret;
    } else if (params.size() == 2){
        int nSporkID = sporkManager.GetSporkIDByName(params[0].get_str());
        if(nSporkID == -1){
            return "Invalid spork name";
        }

        // SPORK VALUE
        int64_t nValue = params[1].get_int();

        //broadcast new spork
        if(sporkManager.UpdateSpork(nSporkID, nValue)){
            ExecuteSpork(nSporkID, nValue);
            return "success";
        } else {
            return "failure";
        }

    }

    throw runtime_error(
        "spork <name> [<value>]\n"
        "<name> is the corresponding spork name, or 'show' to show all current spork settings, active to show which sporks are active"
        "<value> is a epoch datetime to enable or disable spork"
        + HelpRequiringPassphrase());
}

Value validateaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "validateaddress \"darksilkaddress\"\n"
            "\nReturn information about the given DarkSilk address.\n"
            "\nArguments:\n"
            "1. \"darksilkaddress\"     (string, required) The DarkSilk address to validate\n"
            "\nResult:\n"
            "{\n"
            "  \"isvalid\" : true|false,         (boolean) If the address is valid or not. If not, this is the only property returned.\n"
            "  \"address\" : \"darksilkaddress\", (string) The DarkSilk address validated\n"
            "  \"ismine\" : true|false,          (boolean) If the address is yours or not\n"
            "  \"isscript\" : true|false,        (boolean) If the key is a script\n"
            "  \"pubkey\" : \"publickeyhex\",    (string) The hex value of the raw public key\n"
            "  \"iscompressed\" : true|false,    (boolean) If the address is compressed\n"
            "  \"account\" : \"account\"         (string) The account associated with the address, \"\" is the default account\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("validateaddress", "\"DPSSGeFHDnKNxiEyFrD1wcEaHr9hrQDDWc\"")
            + HelpExampleRpc("validateaddress", "\"DPSSGeFHDnKNxiEyFrD1wcEaHr9hrQDDWc\"")
        );

    CDarkSilkAddress address(params[0].get_str());
    bool isValid = address.IsValid();

    Object ret;
    ret.push_back(Pair("isvalid", isValid));
    if (isValid)
    {
        CTxDestination dest = address.Get();
        string currentAddress = address.ToString();
        ret.push_back(Pair("address", currentAddress));
#ifdef ENABLE_WALLET
        isminetype mine = pwalletMain ? IsMine(*pwalletMain, dest) : ISMINE_NO;
        ret.push_back(Pair("ismine", (mine & ISMINE_SPENDABLE) ? true : false));
        if (mine != ISMINE_NO) {
            ret.push_back(Pair("iswatchonly", (mine & ISMINE_WATCH_ONLY) ? true: false));
            Object detail = boost::apply_visitor(DescribeAddressVisitor(mine), dest);
            ret.insert(ret.end(), detail.begin(), detail.end());
        }
        if (pwalletMain && pwalletMain->mapAddressBook.count(dest))
            ret.push_back(Pair("account", pwalletMain->mapAddressBook[dest]));
#endif
    }
    return ret;
}

Value validatepubkey(const Array& params, bool fHelp)
{
    if (fHelp || !params.size() || params.size() > 2)
        throw runtime_error(
            "validatepubkey <darksilkpubkey>\n"
            "Return information about <darksilkpubkey>.");

    std::vector<unsigned char> vchPubKey = ParseHex(params[0].get_str());
    CPubKey pubKey(vchPubKey);

    bool isValid = pubKey.IsValid();
    bool isCompressed = pubKey.IsCompressed();
    CKeyID keyID = pubKey.GetID();

    CDarkSilkAddress address;
    address.Set(keyID);

    Object ret;
    ret.push_back(Pair("isvalid", isValid));
    if (isValid)
    {
        CTxDestination dest = address.Get();
        string currentAddress = address.ToString();
        ret.push_back(Pair("address", currentAddress));
        ret.push_back(Pair("iscompressed", isCompressed));
#ifdef ENABLE_WALLET
        isminetype mine = pwalletMain ? IsMine(*pwalletMain, dest) : ISMINE_NO;
        ret.push_back(Pair("ismine", (mine & ISMINE_SPENDABLE) ? true : false));
        if (mine != ISMINE_NO) {
           ret.push_back(Pair("iswatchonly", (mine & ISMINE_WATCH_ONLY) ? true: false));
           Object detail = boost::apply_visitor(DescribeAddressVisitor(mine), dest);
            ret.insert(ret.end(), detail.begin(), detail.end());
        }
        if (pwalletMain && pwalletMain->mapAddressBook.count(dest))
            ret.push_back(Pair("account", pwalletMain->mapAddressBook[dest]));
#endif
    }
    return ret;
}

Value verifymessage(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "verifymessage <darksilkaddress> <signature> <message>\n"
            "Verify a signed message");

    string strAddress  = params[0].get_str();
    string strSign     = params[1].get_str();
    string strMessage  = params[2].get_str();

    CDarkSilkAddress addr(strAddress);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

    bool fInvalid = false;
    vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

    if (fInvalid)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CPubKey pubkey;
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig))
        return false;

    return (pubkey.GetID() == keyID);
}
