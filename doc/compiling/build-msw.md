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


# How to compile on Windows Enviroments

* See readme-qt.rst for instructions on building DarkSilk QT, the graphical user interface.

WINDOWS BUILD NOTES
===================

* Prepare Compile Enviroment
* Download MSYS Shell
  
    i) Download http://sourceforge.net/projects/mingw/files/Installer/mingw-get-setup.exe/download
    
    ii) From MinGW installation manager -> All packages -> MSYS mark the following for installation:
    
      a) msys-base-bin
      
      b) msys-autoconf-bin
      
      c) msys-automake-bin
      
      d) msys-libtool-bin
      
    iii) Click on Installation -> Apply changes
    
      a) Note: Make sure no mingw packages are checked for installation or present from a previous install. Only the above msys packages should be installed. Also make sure that msys-gcc and msys-w32api packages are not installed.

* Download MingGW Toolkit (http://sourceforge.net/projects/mingw-w64/files/Toolchains%20targetting%20Win32/Personal%20Builds/mingw-builds/4.9.2/threads-posix/dwarf/i686-4.9.2-release-posix-dwarf-rt_v3-rev1.7z/download)

NOTE: Ensure that mingw-builds bin folder is set in your PATH environment variable:

* Download the dependancies (place them in C:/deps)


| Dependancy  | Version        | Download Link                                                                                            |
|-------------|----------------|----------------------------------------------------------------------------------------------------------|
| OpenSSL     | 1.0.1l         | http://www.openssl.org/source/openssl-1.0.1l.tar.gz                                                      |
| Berkeley DB | 4.8.30 NC      | http://download.oracle.com/berkeley-db/db-4.8.30.NC.tar.gz                                               |
| Boost       | 1.57           | http://sourceforge.net/projects/boost/files/boost/1.57.0/                                                |
| MiniUPNPc   | 1.9.20150206   | http://miniupnp.free.fr/files/download.php?file=miniupnpc-1.9.20150206.tar.gz                            |
| LibEvent    | Latest Version | https://github.com/libevent/libevent                                                                     |
| Qt Base     | 5.3.2          | http://download.qt-project.org/official_releases/qt/5.3/5.3.2/submodules/qtbase-opensource-src-5.3.2.7z  |
| Qt Tools    | 5.3.2          | http://download.qt-project.org/official_releases/qt/5.3/5.3.2/submodules/qttools-opensource-src-5.3.2.7z |

Install OpenSSL
=======================

Open MinGW32 Shell (C:\MinGW\msys\1.0\msys.bat)

    cd /c/deps/
    tar xvfz openssl-1.0.1l.tar.gz
    cd openssl-1.0.1l
    ./Configure no-zlib no-shared no-dso no-krb5 no-camellia no-capieng no-cast no-cms no-dtls1 no-gost no-gmp no-heartbeats no-idea no-jpake no-md2 no-mdc2 no-rc5 no-rdrand no-rfc3779 no-rsax no-sctp no-seed no-sha0 no-static_engine no-whirlpool no-rc2 no-rc4 no-ssl2 no-ssl3 mingw
    make

Install BerkleyDB
=========================

Open MinGW32 Shell (C:\MinGW\msys\1.0\msys.bat)

    cd /c/deps/
    tar xvfz db-4.8.30.NC.tar.gz
    cd db-4.8.30.NC/build_unix
    ../dist/configure --enable-mingw --enable-cxx --disable-shared --disable-replication
    make

Install Boost
=========================

Open Command Prompt (cmd.exe), extract the boost archive file and continue

    cd C:\deps\boost_1_57_0\
    bootstrap.bat mingw
    b2 --build-type=complete --with-chrono --with-filesystem --with-program_options --with-system --with-thread toolset=gcc variant=release link=static threading=multi runtime-link=static stage
    
Install MiniUPNPc
==========================

Open Command Prompt (cmd.exe), extract the miniupnpc archive and rename it to 'miniupnpc'

    cd C:\deps\miniupnpc
    mingw32-make -f Makefile.mingw init upnpc-static

Install Qt and It's Tools
============================

Open Command Prompt (cmd.exe), extract Qt and QtTools Respectfully and continue

NOTE: The following assumes qtbase has been unpacked to 'C:\Qt\5.3.2' and qttools have been unpacked to 'C:\Qt\qttools-opensource-src-5.3.2'

    set INCLUDE=C:\deps\libpng-1.6.16;C:\deps\openssl-1.0.1l\include
    set LIB=C:\deps\libpng-1.6.16\.libs;C:\deps\openssl-1.0.1l
    
    cd C:\Qt\5.3.2
    configure.bat -release -opensource -confirm-license -static -make libs -no-sql-sqlite -no-opengl -system-zlib -qt-pcre -no-icu -no-gif -system-libpng -no-libjpeg -no-freetype -no-angle -no-vcproj -openssl -no-dbus -no-audio-backend -no-wmf-backend -no-qml-debug
    
    mingw32-make
    
    set PATH=%PATH%;C:\Qt\5.3.2\bin
    
    cd C:\Qt\qttools-opensource-src-5.3.2
    qmake qttools.pro
    mingw32-make


* Modify the makefile to suit the location of your dependances
* Then run
    make -f makefile.msw
