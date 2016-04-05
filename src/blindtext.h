#ifndef DARKSILK_BLINDTEXT_H
#define DARKSILK_BLINDTEXT_H

#include "cryptopp/cryptlib.h"
#include "cryptopp/aes.h"

#include <iostream>
#include <string>
#include <vector>

using std::cout;
using std::cerr;
using std::endl;
using CryptoPP::AES;

const int TAG_SIZE = 16;  // BouncyCastle default
const int KEY_SIZE = 32;  // SHA256 for key deriv
const int IV_SIZE = AES::BLOCKSIZE;


void SHAKD(std::string twofa, std::string iv_str, byte key[KEY_SIZE]);
bool decryptblindtxt(std::string msg64,
                     std::string twofa,
                     std::vector<std::string> &txdescr);


#endif // DARKSILK_BLINDTEXT_H
