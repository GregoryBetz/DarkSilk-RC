// Copyright (c) 2009-2016 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "cryptkey.h"

#include <map>

#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/ssl.h>
#include <openssl/ecdh.h>

void CCryptKey::EncryptData(const std::vector<unsigned char>& data, std::vector<unsigned char>& encrypted)
{
    ies_ctx_t *ctx;
    char error[1024] = "Unknown error";
    cryptogram_t *cryptogram;

    ctx = create_context(pkey);
    if (!EC_KEY_get0_public_key(ctx->user_key))
        throw key_error("Given EC key is not public key");

    cryptogram = ecies_encrypt(ctx, (unsigned char*)&data[0], data.size(), error);
    if (cryptogram == NULL) {
        free(ctx);
        ctx = NULL;
        throw key_error(std::string("Error in encryption: %s") + error);
    }

    encrypted.resize(cryptogram_data_sum_length(cryptogram));
    unsigned char *key_data = cryptogram_key_data(cryptogram);
    memcpy(&encrypted[0], key_data, encrypted.size());
    cryptogram_free(cryptogram);
    free(ctx);
}

void CCryptKey::DecryptData(const std::vector<unsigned char>& encrypted, std::vector<unsigned char>& data)
{
    ies_ctx_t *ctx;
    char error[1024] = "Unknown error";
    cryptogram_t *cryptogram;
    size_t length;
    unsigned char *decrypted;

    ctx = create_context(pkey);
    if (!EC_KEY_get0_private_key(ctx->user_key))
        throw key_error("Given EC key is not private key");

    size_t key_length = ctx->stored_key_length;
    size_t mac_length = EVP_MD_size(ctx->md);
    cryptogram = cryptogram_alloc(key_length, mac_length, encrypted.size() - key_length - mac_length);

    memcpy(cryptogram_key_data(cryptogram), &encrypted[0], encrypted.size());

    decrypted = ecies_decrypt(ctx, cryptogram, &length, error);
    cryptogram_free(cryptogram);
    free(ctx);

    if (decrypted == NULL) {
        throw key_error(std::string("Error in decryption: %s") + error);
    }

    data.resize(length);
    memcpy(&data[0], decrypted, length);
    free(decrypted);
}

void CCryptKey::SetCompressedPubKey()
{
    EC_KEY_set_conv_form(pkey, POINT_CONVERSION_COMPRESSED);
    fCompressedPubKey = true;
}

void CCryptKey::Reset()
{
    fCompressedPubKey = false;
    if (pkey != NULL)
        EC_KEY_free(pkey);
    pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (pkey == NULL)
        throw key_error("CKey::CKey() : EC_KEY_new_by_curve_name failed");
    fSet = false;
}

bool CCryptKey::SetPubKey(const CPubKey& vchPubKey)
{
    const unsigned char* pbegin = &vchPubKey.vchPubKey[0];
    if (o2i_ECPublicKey(&pkey, &pbegin, vchPubKey.vchPubKey.size()))
    {
        fSet = true;
        if (vchPubKey.vchPubKey.size() == 33)
            SetCompressedPubKey();
        return true;
    }
    pkey = NULL;
    Reset();
    return false;
}
