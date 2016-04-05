// Copyright (c) 2009-2016 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Developers
// Copyright (c) 2015-2016 Silk Network
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef __cplusplus
# error This header can only be compiled as C++.
#endif

#ifndef INCLUDED_PROTOCOL_H
#define INCLUDED_PROTOCOL_H

#include <string>

#include <stdint.h>

#include "chainparams.h"
#include "serialize.h"
#include "netbase.h"

/** Message header.
 * (4) message start.
 * (12) command.
 * (4) size.
 * (4) checksum.
 */
class CMessageHeader
{
public:
    typedef unsigned char MessageStartChars[MESSAGE_START_SIZE];

    CMessageHeader();
    CMessageHeader(const char* pszCommand, unsigned int nMessageSizeIn);

    std::string GetCommand() const;
    bool IsValid() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(FLATDATA(pchMessageStart));
        READWRITE(FLATDATA(pchCommand));
        READWRITE(nMessageSize);
        READWRITE(nChecksum);
    }

// TODO: make private (improves encapsulation)
public:
    enum {
        COMMAND_SIZE=12,
        MESSAGE_SIZE_SIZE=sizeof(int),
        CHECKSUM_SIZE=sizeof(int),

        MESSAGE_SIZE_OFFSET=MESSAGE_START_SIZE+COMMAND_SIZE,
        CHECKSUM_OFFSET=MESSAGE_SIZE_OFFSET+MESSAGE_SIZE_SIZE,
        HEADER_SIZE=MESSAGE_START_SIZE+COMMAND_SIZE+MESSAGE_SIZE_SIZE+CHECKSUM_SIZE
    };
    char pchMessageStart[MESSAGE_START_SIZE];
    char pchCommand[COMMAND_SIZE];
    unsigned int nMessageSize;
    unsigned int nChecksum;
};

/** nServices flags */
enum
{
    NODE_NETWORK = (1 << 0),
#ifdef USE_NATIVE_I2P
    NODE_I2P     = (1 << 7),
#endif
};

/** A CService with information about it as peer */
class CAddress : public CService
{
    public:
        CAddress();
        explicit CAddress(CService ipIn, uint64_t nServicesIn=NODE_NETWORK);

        void Init();

        ADD_SERIALIZE_METHODS;

        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
            CAddress* pthis = const_cast<CAddress*>(this);
            CService* pip = (CService*)pthis;
            if (ser_action.ForRead())
                pthis->Init();
            if (nType & SER_DISK)
                READWRITE(nVersion);
            if ((nType & SER_DISK) ||
                (nVersion >= CADDR_TIME_VERSION && !(nType & SER_GETHASH)))
                READWRITE(nTime);
            READWRITE(nServices);
            READWRITE(*pip);
        }

        void print() const;

    // TODO: make private (improves encapsulation)
    public:
        uint64_t nServices;

        // disk and network only
        unsigned int nTime;

        // memory only
        int64_t nLastTry;
};

/** inv message data */
class CInv
{
    public:
        CInv();
        CInv(int typeIn, const uint256& hashIn);
        CInv(const std::string& strType, const uint256& hashIn);

        ADD_SERIALIZE_METHODS;

        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
            READWRITE(type);
            READWRITE(hash);
        }

        friend bool operator<(const CInv& a, const CInv& b);

        bool IsKnownType() const;
        const char* GetCommand() const;
        std::string ToString() const;
        void print() const;

    // TODO: make private (improves encapsulation)
    public:
        int type;
        uint256 hash;
};

enum {
    MSG_TX = 1,
    MSG_BLOCK,
    // Nodes may always request a MSG_FILTERED_BLOCK in a getdata, however,
    // MSG_FILTERED_BLOCK should not appear in any invs except as a part of getdata.
    MSG_FILTERED_BLOCK,
    MSG_TXLOCK_REQUEST,
    MSG_TXLOCK_VOTE,
    MSG_SPORK,
    MSG_STORMNODE_WINNER,
    MSG_STORMNODE_SCANNING_ERROR,
    MSG_BUDGET_VOTE,
    MSG_BUDGET_PROPOSAL,
    MSG_BUDGET_FINALIZED,
    MSG_BUDGET_FINALIZED_VOTE,
    MSG_STORMNODE_QUORUM,
    MSG_STORMNODE_ANNOUNCE,
    MSG_STORMNODE_PING,
    MSG_SSTX
};


#endif // INCLUDED_PROTOCOL_H
