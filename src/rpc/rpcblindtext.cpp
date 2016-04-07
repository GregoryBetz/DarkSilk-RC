// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp>

#include <string>
#include <sstream>

#include "base58.h"
#include "rpc/rpcserver.h"
#include "wallet/db.h"
#include "init.h"
#include "main.h"
#include "reward.h"
#include "net.h"
#include "wallet/wallet.h"
#include "blindtext.h"

using namespace std;
using namespace boost;
using namespace boost::assign;
using namespace json_spirit;

// Externally constructed transactions have a 640 second window
const int MaxTxnTimeDrift = 10 * 64;

string sendtoaddresswithtime(string sAddress, int64_t nAmount, unsigned int nTime) {

    CDarkSilkAddress address(sAddress);
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid DarkSilk address");

    if (nAmount < (1*COIN))
        throw JSONRPCError(-101, "Send amount too small");

    CWalletTx wtx;
    wtx.nTime = nTime;

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                "Error: Please enter the wallet passphrase with walletpassphrase first.");

    std::string sNarr;
    string strError = pwalletMain->SendMoneyToDestination(address.Get(), nAmount, sNarr, wtx);
    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    return wtx.GetHash().GetHex();
}



Value decryptsend(const Array& params, bool fHelp)
{
    // Not Synced, No Pin, No Secret, Replay, Bad Timestamp, Bad Format
    if (fHelp || params.size() < 1 || params.size() > 1) {
        throw runtime_error(
            "decryptsend <text string>\n"
            "The text is comma separated [uid,msg64].\n"
            "Decrypts send transaction (serialized, hex-encoded) and\n"
            "broadcasts to local node and network. \n"
            "Can not send if not synced, if a replay of a previous\n"
            "transaction, or if the timestamp is too divergent.\n"
            "To use, init with both -stealthsecret and -stealthpin.\n");
    }

    if (IsInitialBlockDownload()) {
         return string("<<Not Synced>>");
    }

    string sSecret = GetArg("-stealthsecret", "");
    if (sSecret == "") {
         return string("<<No Secret>>");
    }

    string sPin = GetArg("-stealthpin", "");
    if (sPin == "") {
         return string("<<No Pin>>");
    }

    string twofa = sSecret + sPin;

    // save the clientid, which is substr(0, found)
    string ciphertext;
    string blindtext = params[0].get_str();
    unsigned int found = blindtext.find_last_of(",");
    ciphertext = blindtext.substr(found+1);
    
    // txdescr: addr, amt, timestamp;
    vector<string> txdescr(3);
    if (!decryptblindtxt(ciphertext, twofa, txdescr)) {
      return string("<<Bad Format>>");
    }

    string sAddress = txdescr[0];
    int64_t nAmount = roundint(atof(txdescr[1].c_str()) * COIN);

    // want seconds, not milliseconds (better than int division)
    string sTimeStamp = txdescr[2].substr(0, txdescr[2].size() - 3);
    unsigned int nTime = atoi(sTimeStamp.c_str());

    cout << "Time is: " << nTime << endl;
    cout << "Amount is: " << nAmount << endl;

    // make sure external transaction is within time window
    unsigned int adjtime = GetAdjustedTime();
    if (((nTime < adjtime) && ((adjtime - nTime) > MaxTxnTimeDrift)) ||
        ((nTime > adjtime) && ((nTime - adjtime) > MaxTxnTimeDrift))) {
            return string("<<Bad Timestamp>>");
    }

    Array ret;
      
    // look for existing matching timestamps in wallet (ghetto uid)
    // should handle replay with scriptsig in future (version 2)
    LOCK(pwalletMain->cs_wallet);
    for (map<uint256, CWalletTx>::const_iterator it = pwalletMain->mapWallet.begin();
         it != pwalletMain->mapWallet.end(); ++it) {
             const CWalletTx* pcoin = &(*it).second;
             // Object entry;
             // WalletTxToJSON(pcoin, entry);
             std::stringstream repr;
             repr << pcoin->nTime;
             ret.push_back(repr.str());
             if (pcoin->nTime == nTime) {
                   return string("<<Replay>>");
             }
    }
    return sendtoaddresswithtime(sAddress, nAmount, nTime);
}
