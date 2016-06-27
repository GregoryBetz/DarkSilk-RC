# **DarkSilk (DRKSLK) Release Candidate**

[![Deploy](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy)


[![Stories in Ready](https://badge.waffle.io/SCDeveloper/DarkSilk-Release-Candidate.png?label=ready&title=Ready)](http://waffle.io/SCDeveloper/DarkSilk-Release-Candidate)
[![Build Status](https://travis-ci.org/SCDeveloper/DarkSilk-Release-Candidate.png?branch=master)](https://travis-ci.org/SCDeveloper/DarkSilk-Release-Candidate)


Graph on Pull Request History
====================================

[![Throughput Graph](https://graphs.waffle.io/SCDeveloper/DarkSilk-Release-Candidate/throughput.svg)](https://waffle.io/SCDeveloper/DarkSilk-Release-Candidate/metrics/throughput)

DarkSilk Integration/Staging Tree
================================
[](src/qt/res/icons/darksilk-80.png)

**Copyright (c) 2015-2016 Silk Network**

What is DarkSilk?
----------------
* Coin Suffix: DRKSLK
* PoW Algorithm: Argon2d
* PoW Period: Unlimited
* PoW Target Spacing: 60 Seconds
* PoW Difficulty Retarget: 10 Blocks
* PoW Reward per Block: 1 DRKSLK
* Full Confirmation: 10 Blocks
* PoS Algorithm: Blake2B
* PoS Target Spacing: 64 Seconds
* PoS Difficulty Retarget: 10 Blocks 
* PoS Reward: 0.01 DRKSLK Static PoS Reward
* PoS Stake Split Combined Threshold: 500 DRKSLK
* Maturity: 100 Blocks (~100 minutes)
* Minimum Confirmations for Stake: 2830 Blocks (~1 day)
* PoS Min: 1 Hour
* PoS Max: Unlimited
* PoW/PoS Blocks: ~2790 per day
* Stormnode Collateral Amount: 10000 DRKSLK
* Stormnode Min Confirmation: 10 Blocks
* Stormnode Reward: 0.25 DRKSLK Static Reward
* Budget Reward: 10,000 DRKSLK Static Reward Every 41,091 blocks (~30 days)
* Budget Proposal Fee: 100 DRKSLK, 20 confirmations (~20 minutes)
* Total Coins: 90,000,000 DRKSLK (~105 years)
* Min TX Fee: 0.00001 DRKSLK
* Block Size: TBA


DarkSilk is a new digital currency that enables instant payments to anyone, anywhere in the world. DarkSilk uses peer-to-peer technology over I2P/Tor/ClearNet to operate securly with no central authority (centralisation): managing transactions and issuing currency (DRKSLK) are carried out collectively by the DarkSilk network. DarkSilk is the name of open source software which enables the use of the currency DRKSLK.

DarkSilk utilises Stormnodes, Sandstorm and InstantX to provide anonymous and near instant transaction confirmations.

DarkSilk implements Gavin Andresens signature cache optimisation from Bitcoin for significantly faster transaction validation.

DarkSilk uses ShadowChat from Shadowcash based upon Bitmessage for encrypted, anonymous and secure messaging via the DarkSilk wallet network.

Darksilk includes a completely decentralised marketplace, providing anonymity and escrow services for safe and fast trades.

DarkSilk includes an Address Index feature, based on the address index API (searchrawtransactions RPC command) implemented in Bitcoin Core but modified implementation to work with the DarkSilk codebase (PoS coins maintain a txindex by default for instance). Initialize the Address Index by running the -reindexaddr command line argument, it may take 10-15 minutes to build the initial index.




**Stormnode/Sandstorm Network Information**
Ported Masternodes from Dash, rebranded as Stormnodes and modified to use stealth addresses.
Darksend ported and rebranded as Sandstorm.
Utilisation of InstantX for instant transaction confirmation.

**MainNet Parameters**
P2P Port/Stormnodes = 31000
RPC Port = 31500
Magic Bytes: 0x42 0x04 0x20 0x24


**TestNet Parameters**
P2P Port/Stormnodes = 31750
RPC Port = 31800
Magic Bytes: 0x24 0x20 0x04 0x42


Debian/Ubuntu Linux Daemon Build Instructions
================================================

install dependencies:

    $ sudo apt-get update && sudo apt-get upgrade
    $ sudo apt-get install git build-essential libssl-dev libdb5.3++-dev libminiupnpc-dev dh-autoreconf zip unzip libboost-all-dev make libgmp3-dev libcrypto++-dev

build darksilkd from git:

    $ git clone https://github.com/SilkNetwork/DarkSilk.git darksilk
    $ cd darksilk/src/univalue && ./autogen.sh && ./configure && make && cd ../../..
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
	

Debian/Ubuntu Linux Qt5 Wallet Build Instructions
================================================

update and install dependencies:

    $ sudo apt-get update && sudo apt-get upgrade
    $ sudo apt-get install make libqt5webkit5-dev libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools qtcreator zip unzip dh-autoreconf libboost-thread-dev libssl-dev libdb++-dev libstdc++6 libminiupnpc-dev libevent-dev libcurl4-openssl-dev git libpng-dev qrencode libqrencode-dev build-essential libboost-dev libboost-all-dev libboost-system-dev libboost-filesystem-dev libboost-program-options-dev libgmp3-dev libcrypto++-dev

build darksilk-qt from git:

    $ git clone https://github.com/SilkNetwork/DarkSilk-Core.git darksilk
    $ cd darksilk && qmake -qt=qt5 "USE_QRCODE=1" "USE_NATIVE_I2P=1" && make
 
running the darksilk Qt wallet:

    $ sudo ./DarkSilk
    
This will compile and build the Qt Wallet which takes a little while, please be patient.  When finished you will have a file called DarkSilk - Simply Double Click


Example stormnode.conf Configuration
===================================================

	rpcallowip=127.0.0.1
	rpcuser=MAKEUPYOUROWNUSERNAME
	rpcpassword=MAKEUPYOUROWNPASSWORD
	rpcport=31500
	server=1
	daemon=1
	listen=1
	staking=0
	port=31000
	stormnodeaddr=YOUR_IP:31000
	stormnode=1
	stormnodeprivkey=KEY GENERATED BY COMMAND
	snconflock=1 // Stormnodes can be locked via the configuration file 

> Set the stormnodeprivkey (KEY GENERATED BY COMMAND) to the result of running:

	stormnode genkey // From the RPC console in the local wallet.

> If you are running your stormnode as a hidden service, replace YOUR_IP with your onion hostname (typically found in /var/lib/tor/YOURHIDDENSERVICENAME/hostname).

> Port 31000 must be open.

> If you are using the hot/cold system where you are remotely activating your stormnode from your local wallet, you will also put these entries in your local (cold) wallet .conf:

	stormnodeaddr=YOUR_IP:31000
	stormnode=1
	stormnodeprivkey=KEY GENERATED BY COMMAND

> Then, start the daemon on your remote stormnode, start your local wallet, and then you can start your stormnode from the RPC console:

	stormnode start
