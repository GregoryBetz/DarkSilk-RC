// Copyright (c) 2009-2016 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Developers
// Copyright (c) 2015-2016 Silk Network
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp>

#include <assert.h>

#include "chainparams.h"
#include "chainparamsseeds.h"
#include "main.h"
#include "net.h"
#include "random.h"
#include "utilstrencodings.h"

using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

//
// Main network
//

// Convert the pnSeeds array into usable address objects.
static void convertSeeds(std::vector<CAddress> &vSeedsOut, const unsigned int *data, unsigned int count, int port)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int k = 0; k < count; ++k)
    {
        struct in_addr ip;
        unsigned int i = data[k], t;
        
        // -- convert to big endian
        t =   (i & 0x000000ff) << 24u
            | (i & 0x0000ff00) << 8u
            | (i & 0x00ff0000) >> 8u
            | (i & 0xff000000) >> 24u;
        
        memcpy(&ip, &t, sizeof(ip));
        
        CAddress addr(CService(ip, port));
        addr.nTime = GetTime()-GetRand(nOneWeek)-nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

class CMainParams : public CChainParams {
public:
    CMainParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0x1f;
        pchMessageStart[1] = 0x22;
        pchMessageStart[2] = 0x05;
        pchMessageStart[3] = 0x31;
        vAlertPubKey = ParseHex("0450e0acc669231cfe2d0a8f0d164c341547487adff89f09e1e78a5299d204bd1c9f05897cb916365c56a31377d872abddb551a12d8d8163149abfc851be7f88ba");
        nDefaultPort = 31000;
        nRPCPort = 31500;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 2); // PoW starting difficulty = 0.0002441

        // Build the genesis block. Note that the output of the genesis coinbase cannot
        // be spent as it did not originally exist in the database.
        
        const char* pszTimestamp = "2015 DarkSilk is Born";
        std::vector<CTxIn> vin;
        vin.resize(1);
        vin[0].scriptSig = CScript() << 0 << CBigNum(42) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        std::vector<CTxOut> vout;
        vout.resize(1);
        vout[0].SetEmpty();
        CMutableTransaction txNew(1, 1444948732, vin, vout, 0);
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1444948732; //Change to current UNIX Time of generated genesis
        genesis.nBits    = 0x1e0ffff0;
        genesis.nNonce   = 763220;

        hashGenesisBlock = genesis.GetHash();

        //// debug print
        //printf("hashGenesisBlock: %s\n", hashGenesisBlock.ToString().c_str());
        //printf("Gensis Hash: %s\n", genesis.GetHash().ToString().c_str());
        //printf("Gensis Hash Merkle: %s\n", genesis.hashMerkleRoot.ToString().c_str());
        //printf("Gensis nTime: %u\n", genesis.nTime);
        //printf("Gensis nBits: %08x\n", genesis.nBits);
        //printf("Gensis Nonce: %u\n\n", genesis.nNonce);

        assert(hashGenesisBlock == uint256("0xc22606c50d13f59b98220efa9822ff2b5ae48815dd702b796f21378b70d9c853"));
        assert(genesis.hashMerkleRoot == uint256("0x77a9ada8f10cd4fb7f05dadc582ec1880fcd2af4414ed664a07fb230a4da390d"));

        vSeeds.push_back(CDNSSeedData("darksilk.org", "ds1.darksilk.org"));
        vSeeds.push_back(CDNSSeedData("", ""));
        
        base58Prefixes[PUBKEY_ADDRESS] = list_of(30);                     //DarkSilk addresses start with 'D'
        base58Prefixes[SCRIPT_ADDRESS] = list_of(10);                     //DarkSilk script addresses start with '5'
        base58Prefixes[SECRET_KEY]     = list_of(140);                    //DarkSilk private keys start with 'y'
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x02)(0xFE)(0x52)(0x7D); //DarkSilk BIP32 pubkeys start with 'drks'
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x02)(0xFE)(0x52)(0x8C); //DarkSilk BIP32 prvkeys start with 'drky'

        convertSeeds(vFixedSeeds, pnSeed, ARRAYLEN(pnSeed), nDefaultPort);

        //TODO(AA)
        nPoolMaxTransactions = 3;
        strSandstormPoolDummyAddress = "DDCxTmWLPytjnEAMd3TCGaryJStEx5caSm"; //private key = MpBeYuuA7c47bqa6ubmBnP8P7hkpmJTSUgwejC8AehSPwsXmkZHD
        strStormnodePaymentsPubKey = "";
        nFirstPOSBlock = 101;
        nStartStormnodePayments = 1446335999; //Wed, 31 Oct 2015 23:59:59 GMT
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


//
// Testnet
//

class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0x1f;
        pchMessageStart[1] = 0x22;
        pchMessageStart[2] = 0x05;
        pchMessageStart[3] = 0x30;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 2); // PoW starting difficulty = 0.0002441
        vAlertPubKey = ParseHex("");
        nDefaultPort = 31750;
        nRPCPort = 31800;
        strDataDir = "testnet";

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1438578972;
        genesis.nBits  = 0; 
        genesis.nNonce = 0;
        hashGenesisBlock = genesis.GetHash(); 

        //// debug print
        //printf("Test hashGenesisBlock: %s\n", hashGenesisBlock.ToString().c_str());
        //printf("Test Gensis Has: %s\n", genesis.GetHash().ToString().c_str());
        //printf("Test Gensis Hash Merkle: %s\n", genesis.hashMerkleRoot.ToString().c_str());
        //printf("Test Gensis nTime: %u\n", genesis.nTime);
        //printf("Test Gensis nBits: %08x\n", genesis.nBits);
        //printf("Test Gensis Nonce: %u\n\n\n", genesis.nNonce);

        assert(genesis.GetHash() == uint256("0x236d17365d9336ab02561840c9b2828064c44316b5fdb7d35f2ce376545a8528"));

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = list_of(30);                     //DarkSilk addresses start with 'D'
        base58Prefixes[SCRIPT_ADDRESS] = list_of(10);                     //DarkSilk script addresses start with '5'
        base58Prefixes[SECRET_KEY] =     list_of(140);                    //DarkSilk private keys start with 'y'              
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x02)(0xFE)(0x52)(0x7D); //DarkSilk BIP32 pubkeys start with 'drks'
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x02)(0xFE)(0x52)(0x8C); //DarkSilk BIP32 prvkeys start with 'drky'

        convertSeeds(vFixedSeeds, pnTestnetSeed, ARRAYLEN(pnTestnetSeed), nDefaultPort);

        //TODO(Amir): Change pub key and dummy address
        nPoolMaxTransactions = 3;
        strStormnodePaymentsPubKey = "";
        strSandstormPoolDummyAddress = "DDCxTmWLPytjnEAMd3TCGaryJStEx5caSm"; //private key = MpBeYuuA7c47bqa6ubmBnP8P7hkpmJTSUgwejC8AehSPwsXmkZHD
        nFirstPOSBlock = 101;
        nStartStormnodePayments = 1446335999; //Wed, 31 Oct 2015 23:59:59 GMT
    }

    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;

static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

void SelectParams(CChainParams::Network network) {
    switch (network) {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {
    
    bool fTestNet = GetBoolArg("-testnet", false);
    
    if (fTestNet) {
        SelectParams(CChainParams::TESTNET);
    } else {
        SelectParams(CChainParams::MAIN);
    }
    return true;
}
