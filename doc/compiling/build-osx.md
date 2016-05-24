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


# How to compile on OS X Enviroments

* See readme-qt.rst for instructions on building DarkSilk QT, the graphical user interface.

* Tested on 10.5 and 10.6 intel.  PPC is not supported because it's big-endian.

* All of the commands should be executed in Terminal.app.. it's in /Applications/Utilities

> You need to install XCode with all the options checked so that the compiler and
> everything is available in /usr not just /Developer I think it comes on the DVD
> but you can get the current version from http://developer.apple.com


1.  Clone the github tree to get the source code:

        git clone git@github.com:SilkNetwork/DarkSilk-Core.git darksilk

2.  Download and install MacPorts from http://www.macports.org/

3.  Install dependencies from MacPorts

        sudo port install boost db48 openssl miniupnpc

Optionally install qrencode (and set USE_QRCODE=1):

        sudo port install qrencode

4.  Now you should be able to build darksilkd:

        cd darksilk/src
        make -f makefile.osx

Run:

         ./darksilkd --help  # for a list of command-line options.


Run

        ./darksilkd -daemon # to start the darksilk daemon.

Run

         ./darksilkd help # When the daemon is running, to get a list of RPC commands
