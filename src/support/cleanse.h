// Copyright (c) 2009-2016 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DARKSILK_SUPPORT_CLEANSE_H
#define DARKSILK_SUPPORT_CLEANSE_H

#include <stdlib.h>

void memory_cleanse(void *ptr, size_t len);

#endif // DARKSILK_SUPPORT_CLEANSE_H