// Copyright (c) 2009-2016 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Developers
// Copyright (c) 2015-2016 Silk Network
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef DARKSILK_INIT_H
#define DARKSILK_INIT_H

#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

namespace boost 
{
    class thread_group;
} // namespace boost

extern CWallet* pwalletMain;

void StartShutdown();
bool ShutdownRequested();
void Shutdown();
void PrepareShutdown();
bool AppInit2(boost::thread_group& threadGroup);

std::string HelpMessage();
/** Returns licensing information (for -version) */
std::string LicenseInfo();

extern bool fOnlyTor;

/* The help message mode determines what help message to show */
enum HelpMessageMode
{
    HMM_DARKSILK,
    HMM_DARKSILK_QT,
    HMM_DARKSILK_CLI
};

std::string HelpMessage(HelpMessageMode mode);

#endif
