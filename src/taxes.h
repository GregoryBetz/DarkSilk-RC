// Copyright (c) 2009-2016 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Developers
// Copyright (c) 2015-2016 Silk Network
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DARKSILK_TAXES_H
#define DARKSILK_TAXES_H

#include <stdlib.h>
#include <string>
#include <limits>

#include "amounts.h"
#include "main.h"
#include "miner.h"
#include "util.h"
#include "taxes.h"
#include "serialize.h"

CAmount CalculateTaxationAmt()
void CheckForTax()
void SetTransactionAmt()
void ExecuteTax()

#endif //  DARKSILK_TAXES_H
