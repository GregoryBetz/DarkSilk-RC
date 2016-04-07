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
#include "reward.h"
#include "net.h"
#include "random.h"
#include "utilstrencodings.h"

using namespace boost::assign;

bool newChain = false;

void CreateGenesis(CBlock genesis){
    // This will figure out a valid hash and Nonce if you're creating a different genesis block:
    uint256 hashTarget = CBigNum().SetCompact(Params().ProofOfWorkLimit().GetCompact()).getuint256();
    printf("Target: %s\n", hashTarget.GetHex().c_str());
    uint256 newhash = genesis.GetHash();
    uint256 besthash;
    memset(&besthash,0xFF,32);
    while (newhash > hashTarget) {
    	++genesis.nNonce;
        if (genesis.nNonce == 0){
            printf("NONCE WRAPPED, incrementing time");
            ++genesis.nTime;
        }
	newhash = genesis.GetHash();
	if(newhash < besthash){
	    besthash=newhash;
	    printf("New best: %s\n", newhash.GetHex().c_str());
	}
    }
    LogPrintf("Found Genesis, Nonce: %ld, Hash: %s\n", genesis.nNonce, genesis.GetHash().GetHex().c_str());
    exit(0);
}

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
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 20); // PoW starting difficulty = 0.0002441

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
		
	nPoWTargetSpacing = 60;
	nPoSTargetSpacing = 64;
		
	if (newChain == true) {CreateGenesis(genesis);}
		
        assert(hashGenesisBlock == uint256("0xdcc5e22e275eff273799a4c06493f8364316d032813c22845602f05ff13d7ec7"));
        assert(genesis.hashMerkleRoot == uint256("0xfed7550a453e532c460fac58d438740235c380f9908cae2d602b705ca2c2f0a6"));

        vSeeds.push_back(CDNSSeedData("darksilk.org", "ds1.darksilk.org"));
        vSeeds.push_back(CDNSSeedData("", ""));
        
        base58Prefixes[PUBKEY_ADDRESS] = list_of(30);                     //DarkSilk addresses start with 'D'
        base58Prefixes[SCRIPT_ADDRESS] = list_of(10);                     //DarkSilk script addresses start with '5'
        base58Prefixes[SECRET_KEY] =     list_of(140);                    //DarkSilk private keys start with 'y'              
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x02)(0xFE)(0x52)(0x7D); //DarkSilk BIP32 pubkeys start with 'drks'
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x02)(0xFE)(0x52)(0x8C); //DarkSilk BIP32 prvkeys start with 'drky'

        convertSeeds(vFixedSeeds, pnSeed, ARRAYLEN(pnSeed), nDefaultPort);

        //TODO(AA)
        nPoolMaxTransactions = 3;
        strSandstormPoolDummyAddress = "DDCxTmWLPytjnEAMd3TCGaryJStEx5caSm"; //private key = MpBeYuuA7c47bqa6ubmBnP8P7hkpmJTSUgwejC8AehSPwsXmkZHD
        strStormnodePaymentsPubKey = "";
        
        nFirstPOSBlock = 101;
        nStakingReward = (0.01*COIN); // 0.01 DRKSLK
	nMiningReward = (1.25*COIN); // 1.25 DRKSLK
        nMinFee = 0.00001; // DRKSLK
        nStartStormnodePayments = 1446335999; // Wed, 31 Oct 2015 23:59:59 GMT
        nStormnodeCollateral = 10000; // DRKSLK
        nStormnodePaymentStart = 420; // 100 for Testnet
        nSandstormCollateral = (0.01*COIN);
        nSandstormPoolMax = (9999.99*COIN);
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
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 20); // PoW starting difficulty = 0.0002441
        vAlertPubKey = ParseHex("");
        nDefaultPort = 31750;
        nRPCPort = 31800;
        strDataDir = "testnet";
        
	nPoWTargetSpacing = 60;
	nPoSTargetSpacing = 64;
		
	if (newChain == true) {CreateGenesis(genesis);}
	
        // Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1438578972;
        genesis.nBits  = 0; 
        genesis.nNonce = 0;
        hashGenesisBlock = genesis.GetHash(); 

        //printf("Test Genesis Hash: %s\n", genesis.GetHash().ToString().c_str());
        assert(hashGenesisBlock == uint256("0xf788ac4ae46429468897b4b9758651cb8a642a6e01f16968134a75078905e24d"));

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
        nStakingReward = (0.01*COIN); // 0.01 DRKSLK
        nMiningReward = (1.25*COIN); // 1.25 DRKSLK
        nMinFee = 0.00001; // DRKSLK
        nStartStormnodePayments = 1446335999; // Wed, 31 Oct 2015 23:59:59 GMT
        nStormnodeCollateral = 10000; // DRKSLK
        nStormnodePaymentStart = 100; // Block
        nSandstormCollateral = (0.01*COIN);
        nSandstormPoolMax = (9999.99*COIN);
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
