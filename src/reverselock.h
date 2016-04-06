// Copyright (c) 2015 The Bitcoin Core developers
// Copyright {c} 2015-2016 Silk Network
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DARKSILK_REVERSELOCK_H
#define DARKSILK_REVERSELOCK_H

/**
 * An RAII-style reverse lock. Unlocks on construction and locks on destruction.
 */
template<typename Lock>
class reverse_lock
{
public:

    explicit reverse_lock(Lock& lock) : lock(lock) {
        lock.unlock();
    }

   ~reverse_lock() {
        lock.lock();
   }

private:
    reverse_lock(reverse_lock const&);
    reverse_lock& operator=(reverse_lock const&);

    Lock& lock;
};

#endif // DARKSILK_REVERSELOCK_H

