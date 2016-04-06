// Copyright (c) 2012-2016 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef DARKSILK_VERSION_H
#define DARKSILK_VERSION_H

#include <string>

#include "clientversion.h"

//
// client versioning
//

static const int CLIENT_VERSION =
                           1000000 * CLIENT_VERSION_MAJOR
                         +   10000 * CLIENT_VERSION_MINOR
                         +     100 * CLIENT_VERSION_REVISION
                         +       1 * CLIENT_VERSION_BUILD;

extern const std::string CLIENT_NAME;
extern const std::string CLIENT_BUILD;
extern const std::string CLIENT_DATE;

#ifdef USE_NATIVE_I2P
extern const std::string I2P_NATIVE_BUILD;
extern const std::string I2P_NATIVE_DATE;
#endif

//
// database format versioning

static const int DATABASE_VERSION = 70510;

//
// network protocol versioning
//

static const int PROTOCOL_VERSION = 60711;

// intial proto version, to be increased after version/verack negotiation
static const int INIT_PROTO_VERSION = 209;

// disconnect from peers older than this proto version
static const int MIN_SANDSTORM_PROTO_VERSION = 60711;

/// minimum peer version for stormnode budgets
static const int MIN_BUDGET_PEER_PROTO_VERSION = 60711;

/// minimum peer version for stormnode winner broadcasts
static const int MIN_SNW_PEER_PROTO_VERSION = 60711;

//! minimum peer version that can receive stormnode payments
// V1 - Last protocol version before update
// V2 - Newest protocol version
static const int MIN_STORMNODE_PAYMENT_PROTO_VERSION_1 = 60711;
static const int MIN_STORMNODE_PAYMENT_PROTO_VERSION_2 = 60711;

// disconnect from peers older than this proto version
static const int MIN_PEER_PROTO_VERSION = 60711;

// disconnect from peers older than this proto version
static const int MIN_POOL_PEER_PROTO_VERSION = 60711;

/// minimum peer version accepted by SandstormPool
static const int MIN_INSTANTX_PROTO_VERSION = 60711;

//disconnect from Stormnodes older than this proto version
static const int MIN_SN_PROTO_VERSION = 60711;

// nTime field added to CAddress, starting with this version;
// if possible, avoid requesting addresses nodes older than this
static const int CADDR_TIME_VERSION = 31402;

// only request blocks from nodes outside this range of versions
static const int NOBLKS_VERSION_START = 60200;
static const int NOBLKS_VERSION_END = 60600;

// "mempool" command, enhanced "getdata" behavior starts with this version:
static const int MEMPOOL_GD_VERSION = 60200;

// reject blocks with non-canonical signatures starting from this version
static const int CANONICAL_BLOCK_SIG_VERSION = 60711;

#endif
