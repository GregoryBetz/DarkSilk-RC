// Copyright (c) 2009-2016 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Developers
// Copyright (c) 2015-2016 Silk Network
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DARKSILK_CHAINPARAMS_H
#define DARKSILK_CHAINPARAMS_H

#include <vector>

#include "bignum.h"
#include "uint256.h"
#include "amount.h"

#include "consensus/params.h"

using namespace std;

#define MESSAGE_START_SIZE 4
typedef unsigned char MessageStartChars[MESSAGE_START_SIZE];

class CAddress;
class CBlock;

struct CDNSSeedData {
    string name, host;
    CDNSSeedData(const string &strName, const string &strHost) : name(strName), host(strHost) {}
};

typedef std::map<int, uint256> MapCheckpoints;

struct CCheckpointData {
    MapCheckpoints mapCheckpoints;
    int64_t nTimeLastCheckpoint;
    int64_t nTransactionsLastCheckpoint;
    double fTransactionsPerDay;
};

/**
 * CChainParams defines various tweakable parameters of a given instance of the
 * DarkSilk system. There are three: the main network on which people trade goods
 * and services, the public test network which gets reset from time to time and
 * a regression test mode which is intended for private networks only. It has
 * minimal difficulty to ensure that blocks can be found instantly.
 */
class CChainParams
{
public:
    enum Network {
        MAIN,
        TESTNET,

        MAX_NETWORK_TYPES
    };

    enum Base58Type {
        PUBKEY_ADDRESS,
        SCRIPT_ADDRESS,
        SECRET_KEY,
        EXT_PUBLIC_KEY,
        EXT_SECRET_KEY,

        MAX_BASE58_TYPES
    };
	
	const Consensus::Params& GetConsensus() const { return consensus; }
    const uint256& HashGenesisBlock() const { return hashGenesisBlock; }
    const MessageStartChars& MessageStart() const { return pchMessageStart; }
    const vector<unsigned char>& AlertKey() const { return vAlertPubKey; }
    int GetDefaultPort() const { return nDefaultPort; }
    const CBigNum& ProofOfWorkLimit() const { return bnProofOfWorkLimit; }
    int SubsidyHalvingInterval() const { return nSubsidyHalvingInterval; }
    virtual const CBlock& GenesisBlock() const = 0;
    virtual bool RequireRPCPassword() const { return true; }
    const string& DataDir() const { return strDataDir; }
    virtual Network NetworkID() const = 0;
    const vector<CDNSSeedData>& DNSSeeds() const { return vSeeds; }
    const std::vector<unsigned char> &Base58Prefix(Base58Type type) const { return base58Prefixes[type]; }
    virtual const vector<CAddress>& FixedSeeds() const = 0;
    const CCheckpointData& Checkpoints() const { return checkpointData; }
    int RPCPort() const { return nRPCPort; }
    int FirstPOSBlock() const { return nFirstPOSBlock; }
    std::string StormnodePaymentPubKey() const { return strStormnodePaymentsPubKey; }
    int64_t StartStormnodePayments() const { return nStartStormnodePayments; }
    int PoolMaxTransactions() const { return nPoolMaxTransactions; }
    std::string SandstormPoolDummyAddress() const { return strSandstormPoolDummyAddress; }
    int ProofOfWorkSpacing() const { return nPoWTargetSpacing; }
    int ProofOfStakeSpacing() const { return nPoSTargetSpacing; }
    CAmount StakingReward() const { return nStakingReward; }
	double MinimumFee() const { return nMinFee; }
	CAmount StormnodeCollateral() const { return nStormnodeCollateral; }
	CAmount SandstormCollateral() const { return nSandstormCollateral; }
	int StormnodePaymentStart() const { return nStormnodePaymentStart; }
	CAmount SandstormPoolMax() const { return nSandstormPoolMax; }
	int MiningReward() const { return nMiningReward; }

protected:
    CChainParams() {};

	Consensus::Params consensus;

	int nPoWTargetSpacing;
	int nPoSTargetSpacing;
	CAmount nStakingReward;
	CAmount nMiningReward;
	double nMinFee;
	CAmount nStormnodeCollateral;
	int nStormnodePaymentStart;
	CAmount nSandstormCollateral;
	int nSandstormPoolMax;
    uint256 hashGenesisBlock;
    MessageStartChars pchMessageStart;
    // Raw pub key bytes for the broadcast alert signing key.
    vector<unsigned char> vAlertPubKey;
    int nDefaultPort;
    int nRPCPort;
    CBigNum bnProofOfWorkLimit;
    int nSubsidyHalvingInterval;
    string strDataDir;
    vector<CDNSSeedData> vSeeds;
    std::vector<unsigned char> base58Prefixes[MAX_BASE58_TYPES];
    std::string strStormnodePaymentsPubKey;
    int64_t nStartStormnodePayments;
    int nFirstPOSBlock;
    int nPoolMaxTransactions;
    std::string strSandstormPoolDummyAddress;
    CCheckpointData checkpointData;
};

/**
 * Return the currently selected parameters. This won't change after app startup
 * outside of the unit tests.
 */
const CChainParams &Params();

/** Sets the params returned by Params() to those for the given network. */
void SelectParams(CChainParams::Network network);

/**
 * Looks for -testnet and then calls SelectParams as appropriate.
 * Returns false if an invalid combination is given.
 */
bool SelectParamsFromCommandLine();

inline bool TestNet() {
    // Note: it's deliberate that this returns "false" for regression test mode.
    return Params().NetworkID() == CChainParams::TESTNET;
}

#endif
