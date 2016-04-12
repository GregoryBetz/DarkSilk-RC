// Copyright (c) 2009-2016 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef DARKSILK_CRYPTKEY_H
#define DARKSILK_CRYPTKEY_H

#include <map>

#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/ssl.h>
#include <openssl/ecdh.h> 

#include "key.h"
#include "pubkey.h"
#include "crypto/common.h"
#include "crypto/hmac_sha512.h"
#include "elements/util/util.h"

#include "cryptogram/ies.h"

#include <vector>

// CPrivKey is a serialized private key, with all parameters included (279 bytes)
typedef std::vector<unsigned char, secure_allocator<unsigned char> > CPrivKey;
// CSecret is a serialization of just the secret parameter (32 bytes)
typedef std::vector<unsigned char, secure_allocator<unsigned char> > CSecret;
/*
class CCryptPubKey
{
	public:
		// Encrypt data
		void EncryptData(const std::vector<unsigned char>& data, std::vector<unsigned char>& encrypted);
};
*/
class CCryptKey : public CPubKey
{
	protected:
		EC_KEY* pkey;
		void SetCompressedPubKey();
		bool fCompressedPubKey;
		bool fSet;
		
	public:
		
		void Reset();
		
		// Encrypt data
		void EncryptData(const std::vector<unsigned char>& data, std::vector<unsigned char>& encrypted);

		// Decrypt data
		void DecryptData(const std::vector<unsigned char>& encrypted, std::vector<unsigned char>& data);
		
		// Set public key
		bool SetPubKey(const CPubKey& vchPubKey);
};

class key_error : public std::runtime_error
{
	public:
		explicit key_error(const std::string& str) : std::runtime_error(str) {}
};

#endif // DARKSILK_KEY_H
