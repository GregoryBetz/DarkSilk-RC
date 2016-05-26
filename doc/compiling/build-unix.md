# DarkSilk
*Version 1.0*

> Distributed under the MIT/X11 software license, see the accompanying
> http://www.opensource.org/licenses/mit-license.php.
>
> This product includes software developed by the OpenSSL Project for use in
> the OpenSSL Toolkit (http://www.openssl.org/).  This product includes
> cryptographic software written by Eric Young (eay@cryptsoft.com) and UPnP
> software written by Thomas Bernard.


DarkSilk Is a Digital Virtual Currency that employs the latest technologies for anonymous, safe transactions
  - Copyright (c) 2015-2016 Silk Network
  - Copyright (c) 2011-2016 PPCoin Developers
  - Copyright (c) 2009-2016 The BitCoin Developers
  - Copyright (c) 2010-2016 The DashPay Developers
  
> DarkSilk is based on BlackCoin and uses the Argon2d Algorithm for Proof
> of Work Mining and Blake2b for Proof of Stake Mining. DarkSilk also has
> Stormnodes and employs InstantX and Sandstorm for anonymity. DarkSilk
> also has native I2P Support


# How to compile on Debain Based Enviroments

Install dependencies:

    $ sudo apt-get update && sudo apt-get upgrade
    $ sudo apt-get install git build-essential libssl-dev libdb5.3++-dev libminiupnpc-dev dh-autoreconf zip unzip libboost-all-dev make libgmp3-dev libcrypto++-dev

build darksilkd from git:

    $ git clone https://github.com/SCDeveloper/DarkSilk-Release-Candidate.git darksilk
    $ cd darksilk/src/secp256k1 && ./autogen.sh && ./configure --disable-shared --with-pic --with-bignum=no --enable-module-recovery && make && cd .. && sudo make -f makefile.unix USE_UPNP=1
   
install and run darksilkd daemon:

    $ sudo strip darksilkd && sudo cp ~/darksilk/src/darksilkd /usr/bin && cd ~/
    $ darksilkd

here are a few commands, google for more.

    $ ./darksilkd getinfo
    $ ./darksilkd getpeerinfo
    $ ./darksilkd getmininginfo
    $ ./darksilkd getstakinginfo
    $ ./darksilkd getnewaddresss
	
