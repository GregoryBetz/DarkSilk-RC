// Copyright (c) 2009-2016 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/foreach.hpp>

#include "primitives/block.h"
#include "chainparams.h"
#include "pow.h"

bool CBlock::CheckBlockSignature() const
{
    if (IsProofOfWork())
        return vchBlockSig.empty();

    if (vchBlockSig.empty())
        return false;

    vector<valtype> vSolutions;
    txnouttype whichType;

    const CTxOut& txout = vtx[1].vout[1];

    if (!Solver(txout.scriptPubKey, whichType, vSolutions))
        return false;

    if (whichType == TX_PUBKEY)
    {
        valtype& vchPubKey = vSolutions[0];
        return CPubKey(vchPubKey).Verify(GetHash(), vchBlockSig);
    }

    // Block signing key also can be encoded in the nonspendable output
    // This allows to not pollute UTXO set with useless outputs e.g. in case of multisig staking
    const CScript& script = txout.scriptPubKey;
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    valtype vchPushValue;

    if (!script.GetOp(pc, opcode, vchPushValue))
        return false;
    if (opcode != OP_RETURN)
        return false;
    if (!script.GetOp(pc, opcode, vchPushValue))
        return false;
    if (!IsCompressedOrUncompressedPubKey(vchPushValue))
        return false;
    return CPubKey(vchPushValue).Verify(GetHash(), vchBlockSig);

    return false;
}

void CBlock::UpdateTime(const CBlockIndex* pindexPrev)
{
    nTime = max(GetBlockTime(), GetAdjustedTime());
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u, vchBlockSig=%s)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size(),
        HexStr(vchBlockSig.begin(), vchBlockSig.end()));
    for (unsigned int i = 0; i < vtx.size(); i++)
    {
        s << "  " << vtx[i].ToString() << "\n";
    }
    s << "  vMerkleTree: ";
    for (unsigned int i = 0; i < vMerkleTree.size(); i++)
        s << " " << vMerkleTree[i].ToString();
    s << "\n";
    return s.str();
}
