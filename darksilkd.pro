TEMPLATE = app
TARGET = darksilkd
VERSION = 1.0.0.0
INCLUDEPATH += src src/json
QT += network widgets
DEFINES += ENABLE_WALLET BOOST_THREAD_USE_LIB BOOST_SPIRIT_THREADSAFE USE_NATIVE_I2P
CONFIG += static no_include_pwd thread
QMAKE_CXXFLAGS = -fpermissive

# for boost 1.37, add -mt to the boost libraries
# use: qmake BOOST_LIB_SUFFIX=-mt
# for boost thread win32 with _win32 sufix
# use: BOOST_THREAD_LIB_SUFFIX=_win32-...
# or when linking against a specific BerkelyDB version: BDB_LIB_SUFFIX=-4.8

# Dependency library locations can be customized with:
#    BOOST_INCLUDE_PATH, BOOST_LIB_PATH, BDB_INCLUDE_PATH,
#    BDB_LIB_PATH, OPENSSL_INCLUDE_PATH and OPENSSL_LIB_PATH respectively

# workaround for boost 1.58
DEFINES += BOOST_VARIANT_USE_RELAXED_GET_BY_DEFAULT

OBJECTS_DIR = build
MOC_DIR = build
UI_DIR = build

# use: qmake "RELEASE=1"
contains(RELEASE, 1) {
    macx:QMAKE_CXXFLAGS += -mmacosx-version-min=10.7 -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.7.sdk
    macx:QMAKE_CFLAGS += -mmacosx-version-min=10.7 -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.7.sdk
    macx:QMAKE_LFLAGS += -mmacosx-version-min=10.7 -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.7.sdk
    macx:QMAKE_OBJECTIVE_CFLAGS += -mmacosx-version-min=10.7 -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.7.sdk

    !windows:!macx {
        # Linux: static link
        # LIBS += -Wl,-Bstatic
    }
}

!win32 {
# for extra security against potential buffer overflows: enable GCCs Stack Smashing Protection
QMAKE_CXXFLAGS *= -fstack-protector-all --param ssp-buffer-size=1
QMAKE_LFLAGS   *= -fstack-protector-all --param ssp-buffer-size=1
# We need to exclude this for Windows cross compile with MinGW 4.2.x, as it will result in a non-working executable!
# This can be enabled for Windows, when we switch to MinGW >= 4.4.x.
}
# for extra security on Windows: enable ASLR and DEP via GCC linker flags
win32:QMAKE_LFLAGS *= -Wl,--dynamicbase -Wl,--nxcompat -static
win32:QMAKE_LFLAGS *= -static-libgcc -static-libstdc++

# use: qmake "USE_QRCODE=1"
# libqrencode (http://fukuchi.org/works/qrencode/index.en.html) must be installed for support
contains(USE_QRCODE, 1) {
    message(Building with QRCode support)
    DEFINES += USE_QRCODE
    LIBS += -lqrencode
}

# use: qmake "USE_UPNP=1" ( enabled by default; default)
#  or: qmake "USE_UPNP=0" (disabled by default)
#  or: qmake "USE_UPNP=-" (not supported)
# miniupnpc (http://miniupnp.free.fr/files/) must be installed for support
contains(USE_UPNP, -) {
    message(Building without UPNP support)
} else {
    message(Building with UPNP support)
    count(USE_UPNP, 0) {
        USE_UPNP=1
    }
    DEFINES += USE_UPNP=$$USE_UPNP MINIUPNP_STATICLIB STATICLIB
    INCLUDEPATH += $$MINIUPNPC_INCLUDE_PATH
    LIBS += $$join(MINIUPNPC_LIB_PATH,,-L,) -lminiupnpc
    win32:LIBS += -liphlpapi
}

# use: qmake "USE_DBUS=1" or qmake "USE_DBUS=0"
linux:count(USE_DBUS, 0) {
    USE_DBUS=1
}
contains(USE_DBUS, 1) {
    message(Building with DBUS (Freedesktop notifications) support)
    DEFINES += USE_DBUS
    QT += dbus
}

contains(DARKSILK_NEED_QT_PLUGINS, 1) {
    DEFINES += DARKSILK_NEED_QT_PLUGINS
    QTPLUGIN += qcncodecs qjpcodecs qtwcodecs qkrcodecs qtaccessiblewidgets
}

#Build Secp256k1
INCLUDEPATH += src/secp256k1/include
LIBS += $$PWD/src/secp256k1/src/libsecp256k1_la-secp256k1.o
!win32 {
    # we use QMAKE_CXXFLAGS_RELEASE even without RELEASE=1 because we use RELEASE to indicate linking preferences not -O preferences
    gensecp256k1.commands = cd $$PWD/src/secp256k1 && ./autogen.sh && ./configure --disable-shared --with-pic --with-bignum=no --enable-module-recovery && CC=$$QMAKE_CC CXX=$$QMAKE_CXX $(MAKE) OPT=\"$$QMAKE_CXXFLAGS $$QMAKE_CXXFLAGS_RELEASE\"
} else {
    #Windows ???
}
gensecp256k1.target = $$PWD/src/secp256k1/src/libsecp256k1_la-secp256k1.o
gensecp256k1.depends = FORCE
PRE_TARGETDEPS += $$PWD/src/secp256k1/src/libsecp256k1_la-secp256k1.o
QMAKE_EXTRA_TARGETS += gensecp256k1
QMAKE_CLEAN += $$PWD/src/secp256k1/src/libsecp256k1_la-secp256k1.o; cd $$PWD/src/secp256k1 ; $(MAKE) clean


#Build LevelDB
INCLUDEPATH += src/leveldb/include src/leveldb/helpers src/leveldb/helpers/memenv
LIBS += $$PWD/src/leveldb/libleveldb.a $$PWD/src/leveldb/libmemenv.a
SOURCES += src/elements/txdb/txdb-leveldb.cpp
!win32 {
    # we use QMAKE_CXXFLAGS_RELEASE even without RELEASE=1 because we use RELEASE to indicate linking preferences not -O preferences
    genleveldb.commands = cd $$PWD/src/leveldb && CC=$$QMAKE_CC CXX=$$QMAKE_CXX $(MAKE) OPT=\"$$QMAKE_CXXFLAGS $$QMAKE_CXXFLAGS_RELEASE\" libleveldb.a libmemenv.a
} else {
    # make an educated guess about what the ranlib command is called
    isEmpty(QMAKE_RANLIB) {
        QMAKE_RANLIB = $$replace(QMAKE_STRIP, strip, ranlib)
    }
    LIBS += -lshlwapi
    genleveldb.commands = cd $$PWD/src/leveldb && CC=$$QMAKE_CC CXX=$$QMAKE_CXX TARGET_OS=OS_WINDOWS_CROSSCOMPILE $(MAKE) OPT=\"$$QMAKE_CXXFLAGS $$QMAKE_CXXFLAGS_RELEASE\" libleveldb.a libmemenv.a && $$QMAKE_RANLIB $$PWD/src/leveldb/libleveldb.a && $$QMAKE_RANLIB $$PWD/src/leveldb/libmemenv.a
}
genleveldb.target = $$PWD/src/leveldb/libleveldb.a
genleveldb.depends = FORCE
PRE_TARGETDEPS += $$PWD/src/leveldb/libleveldb.a
QMAKE_EXTRA_TARGETS += genleveldb
# Gross ugly hack that depends on qmake internals, unfortunately there is no other way to do it.
QMAKE_CLEAN += $$PWD/src/leveldb/libleveldb.a; cd $$PWD/src/leveldb ; $(MAKE) clean

# regenerate src/build.h
!windows|contains(USE_BUILD_INFO, 1) {
    genbuild.depends = FORCE
    genbuild.commands = cd $$PWD; /bin/sh share/genbuild.sh $$OUT_PWD/build/build.h
    genbuild.target = $$OUT_PWD/build/build.h
    PRE_TARGETDEPS += $$OUT_PWD/build/build.h
    QMAKE_EXTRA_TARGETS += genbuild
    DEFINES += HAVE_BUILD_INFO
}

#contains(DEFINES, USE_NATIVE_I2P) {
#    geni2pbuild.depends = FORCE
#    geni2pbuild.commands = cd $$PWD; /bin/sh share/inc_build_number.sh src/networking/i2p/i2pbuild.h darksilk-core-build-number
#    geni2pbuild.target = src/networking/i2p/i2pbuild.h
#    PRE_TARGETDEPS += src/networking/i2p/i2pbuild.h
#    QMAKE_EXTRA_TARGETS += geni2pbuild
#}

contains(USE_O3, 1) {
    message(Building O3 optimization flag)
    QMAKE_CXXFLAGS_RELEASE -= -O2
    QMAKE_CFLAGS_RELEASE -= -O2
    QMAKE_CXXFLAGS += -O3
    QMAKE_CFLAGS += -O3
}

*-g++-32 {
    message("32 platform, adding -msse2 flag")

    QMAKE_CXXFLAGS += -msse2
    QMAKE_CFLAGS += -msse2
}

QMAKE_CXXFLAGS_WARN_ON = -fdiagnostics-show-option -Wall -Wextra -Wno-ignored-qualifiers -Wformat -Wformat-security -Wno-unused-parameter -Wstack-protector

INCLUDEPATH +=  src/crypto/argon2 \
                src/crypto/argon2/blake2

# Input
DEPENDPATH += . \
              src \
              src/compat \
              src/crypto \
              src/json \
              src/obj \
              src/primitives \
              src/leveldb/db \
              src/leveldb/issues \
              src/leveldb/port \
              src/leveldb/table \
              src/leveldb/elements/util/util \
              src/secp256k1/include \
              src/secp256k1/src \
              src/test/data \
              src/leveldb/doc/bench \
              src/leveldb/helpers/memenv \
              src/leveldb/include/leveldb \
              src/leveldb/port/win \
              src/secp256k1/src/java

HEADERS +=  \
            src/support/allocators/pagelocker.h \
            src/support/allocators/secure.h \
            src/support/allocators/zeroafterfee.h \
            src/httpserver.h \
            src/memusage.h \
			src/walletinterface.h \
			src/prevector.h \
    	    src/scheduler.h \
            src/cryptkey.h \
            src/proofs.h \
            src/reward.h \
            src/stormnode/activestormnode.h \
            src/cryptogram/ies.h \
            src/blindtext.h \
			src/alert.h \
            src/addrman.h \
            src/base58.h \
            src/bignum.h \
            src/bloom.h \
            src/chainparams.h \
            src/chainparamsseeds.h \
            src/checkpoints.h \
            src/support/cleanse.h \
            src/compat/compat.h \
            src/coincontrol.h \
            src/elements/core/core_io.h \
            src/sync.h \
            src/random.h \
            src/elements/util/util.h \
            src/elements/util/utilstrencodings.h \
            src/elements/util/utilmoneystr.h \
            src/hash.h \
            src/uint256.h \
            src/kernel.h \
            src/crypto/scrypt/scrypt.h \
            src/pbkdf2.h \
            src/serialize.h \
            src/limitedmap.h \
            src/main.h \
            src/miner.h \
            src/networking/net.h \
            src/key.h \
            src/ecwrapper.h \
            src/pubkey.h \
            src/wallet/db.h \
            src/elements/txdb/txdb.h \
            src/txmempool.h \
            src/univalue.h \
            src/univalue_escapes.h \
            src/wallet/walletdb.h \
            src/script/script.h \
            src/script/script_error.h \
            src/init.h \
            src/mruset.h \
            src/consensus/validation.h \
            src/json/json_spirit_writer_template.h \
            src/json/json_spirit_writer.h \
            src/json/json_spirit_value.h \
            src/json/json_spirit_utils.h \
            src/json/json_spirit_stream_reader.h \
            src/json/json_spirit_reader_template.h \
            src/json/json_spirit_reader.h \
            src/json/json_spirit_error_position.h \
            src/json/json_spirit.h \
            src/wallet/wallet.h \
            src/keystore.h \
            src/rpc/rpcclient.h \
            src/rpc/rpcprotocol.h \
            src/rpc/rpcserver.h \
            src/timedata.h \
            src/crypter.h \
            src/protocol.h \
            src/ui_interface.h \
            src/version.h \
            src/networking/netbase.h \
            src/clientversion.h \
            src/threadsafety.h \
            src/tinyformat.h \
            src/stealth/stealth.h \
            src/stormnode/stormnode.h \ 
            src/stormnode/stormnode-budget.h \
            src/stormnode/stormnode-payments.h \
            src/sandstorm/sandstorm.h \    
            src/sandstorm/sandstorm-relay.h \
            src/instantx/instantx.h \
            src/stormnode/stormnodeman.h \
            src/stormnode/spork.h \
            src/crypto/common.h \
            src/crypto/hmac_sha256.h \
            src/crypto/hmac_sha512.h \
            src/crypto/ripemd160.h \
            src/crypto/sha1.h \
            src/crypto/sha256.h \
            src/crypto/sha512.h \
            src/smessage.h \
            src/primitives/block.h \
            src/primitives/transaction.h \
            src/stormnode/stormnode-sync.h \
            src/chain.h \
            src/coins.h \
			src/networking/tor/torcontrol.h \
            src/script/compressor.h \
            src/undo.h \
            src/leveldbwrapper.h \
            src/streams.h \
            src/elements/txdb/txdb-leveldb.h \
            src/amount.h \
            src/sanity.h \
            src/crypto/argon2/argon2.h \
            src/crypto/argon2/core.h \
            src/crypto/argon2/encoding.h \
            src/crypto/argon2/thread.h \
            src/crypto/argon2/blake2/blake2-impl.h \
            src/crypto/argon2/blake2/blake2.h \
            src/crypto/argon2/blake2/blamka-round-opt.h \
            src/crypto/argon2/blake2/blamka-round-ref.h \
            src/crypto/argon2/opt.h \
            src/consensus/params.h

SOURCES +=  src/darksilkd.cpp \
            src/walletinterface.cpp \
			src/blindtext.cpp \
			src/networking/tor/torcontrol.cpp \
            src/rest.cpp \
			src/scheduler.cpp \
            src/cryptkey.cpp \
            src/proofs.cpp \
            src/reward.cpp \
            src/stormnode/activestormnode.cpp \
            src/cryptogram/cryptogram.cpp \
            src/cryptogram/ecies.cpp \
            src/alert.cpp \
            src/support/allocators/pagelocker.cpp \
            src/bloom.cpp \
            src/elements/core/core_read.cpp \
            src/elements/core/core_write.cpp \
            src/chainparams.cpp \
            src/support/cleanse.cpp \
            src/version.cpp \
            src/sync.cpp \
            src/txmempool.cpp \
            src/gen.cpp \
            src/univalue.cpp \
            src/univalue_read.cpp \
            src/univalue_write.cpp \
            src/random.cpp \
            src/elements/util/util.cpp \
            src/elements/util/utilstrencodings.cpp \
            src/elements/util/utilmoneystr.cpp \
            src/hash.cpp \
            src/networking/netbase.cpp \
            src/key.cpp \
            src/ecwrapper.cpp \
            src/pubkey.cpp \
            src/script/script.cpp \
            src/script/script_error.cpp \
            src/main.cpp \
            src/miner.cpp \
            src/init.cpp \
            src/networking/net.cpp \
            src/checkpoints.cpp \
            src/addrman.cpp \
            src/base58.cpp \
            src/wallet/db.cpp \
            src/wallet/walletdb.cpp \
            src/wallet/wallet.cpp \
            src/keystore.cpp \
            src/rpc/rpcclient.cpp \
            src/rpc/rpccrypt.cpp \
            src/rpc/rpcprotocol.cpp \
            src/rpc/rpcserver.cpp \
            src/wallet/rpcdump.cpp \
            src/rpc/rpcmisc.cpp \
            src/rpc/rpcnet.cpp \
            src/rpc/rpcmining.cpp \
            src/wallet/rpcwallet.cpp \
            src/rpc/rpcblockchain.cpp \
            src/rpc/rpcrawtransaction.cpp \
            src/timedata.cpp \
            src/crypter.cpp \
            src/protocol.cpp \
            src/noui.cpp \
            src/kernel.cpp \
            src/crypto/scrypt/scrypt-arm.S \
            src/crypto/scrypt/scrypt-x86.S \
            src/crypto/scrypt/scrypt-x86_64.S \
            src/crypto/scrypt/scrypt.cpp \
            src/pbkdf2.cpp \
            src/stealth/stealth.cpp \
            src/stormnode/stormnode.cpp \
            src/stormnode/stormnode-budget.cpp \
            src/stormnode/stormnode-payments.cpp \
            src/sandstorm/sandstorm.cpp \
            src/sandstorm/sandstorm-relay.cpp \
            src/rpc/rpcstormnode.cpp \
            src/rpc/rpcstormnode-budget.cpp \
            src/instantx/instantx.cpp \
            src/stormnode/spork.cpp \
            src/stormnode/stormnodeconfig.cpp \
            src/stormnode/stormnodeman.cpp \
            src/crypto/hmac_sha256.cpp \
            src/crypto/hmac_sha512.cpp \
            src/crypto/ripemd160.cpp \
            src/crypto/sha1.cpp \
            src/crypto/sha256.cpp \
            src/crypto/sha512.cpp \
            src/smessage.cpp \
            src/rpc/rpcsmessage.cpp \
            src/primitives/block.cpp \
            src/primitives/transaction.cpp \
            src/stormnode/stormnode-sync.cpp \
            src/chain.cpp \
            src/uint256.cpp \
            src/coins.cpp \
            src/script/compressor.cpp \
            src/leveldbwrapper.cpp \
            src/httpserver.cpp \
            src/elements/txdb/txdb.cpp \
            src/amount.cpp \
            src/undo.cpp \
            src/rpc/rpcblindtext.cpp \
            src/compat/glibc_sanity.cpp \
            src/compat/glibcxx_sanity.cpp \
            src/crypto/argon2/argon2.c \
            src/crypto/argon2/core.c \
            src/crypto/argon2/encoding.c \
            src/crypto/argon2/thread.c \
            src/crypto/argon2/blake2/blake2b.c \
            src/crypto/argon2/opt.c 

contains(DEFINES, USE_NATIVE_I2P) {
HEADERS +=  src/networking/i2p/i2p.h \
            src/networking/i2p/i2psam.h
            
SOURCES +=  src/networking/i2p/i2p.cpp \
            src/networking/i2p/i2psam.cpp
}

CODECFORTR = UTF-8

# for lrelease/lupdate
# also add new translations to src/qt/darksilk.qrc under translations/
TRANSLATIONS = $$files(src/qt/locale/darksilk_*.ts)

isEmpty(QMAKE_LRELEASE) {
    win32:QMAKE_LRELEASE = $$[QT_INSTALL_BINS]\\lrelease.exe
    else:QMAKE_LRELEASE = $$[QT_INSTALL_BINS]/lrelease
}
isEmpty(QM_DIR):QM_DIR = $$PWD/src/qt/locale
# automatically build translations, so they can be included in resource file
TSQM.name = lrelease ${QMAKE_FILE_IN}
TSQM.input = TRANSLATIONS
TSQM.output = $$QM_DIR/${QMAKE_FILE_BASE}.qm
TSQM.commands = $$QMAKE_LRELEASE ${QMAKE_FILE_IN} -qm ${QMAKE_FILE_OUT}
TSQM.CONFIG = no_link
QMAKE_EXTRA_COMPILERS += TSQM

# "Other files" to show in Qt Creator
OTHER_FILES += \
    doc/*.rst doc/*.txt doc/README README.md res/darksilk-core.rc

# platform specific defaults, if not overridden on command line
isEmpty(BOOST_LIB_SUFFIX) {
    macx:BOOST_LIB_SUFFIX = -mt
    win32:BOOST_LIB_SUFFIX = -mgw49-mt-s-1_59
}

isEmpty(BOOST_THREAD_LIB_SUFFIX) {
    BOOST_THREAD_LIB_SUFFIX = $$BOOST_LIB_SUFFIX
}

isEmpty(BDB_LIB_PATH) {
    macx:BDB_LIB_PATH = /usr/local/Cellar/berkeley-db4/4.8.30/lib
}

isEmpty(BDB_LIB_SUFFIX) {
    macx:BDB_LIB_SUFFIX = -4.8
}

isEmpty(BDB_INCLUDE_PATH) {
    macx:BDB_INCLUDE_PATH = /usr/local/Cellar/berkeley-db4/4.8.30/include
}

isEmpty(BOOST_LIB_PATH) {
    macx:BOOST_LIB_PATH = /usr/local/Cellar/boost/1.58.0/lib
}

isEmpty(BOOST_INCLUDE_PATH) {
    macx:BOOST_INCLUDE_PATH = /usr/local/Cellar/boost/1.58.0/include
}

isEmpty(QRENCODE_LIB_PATH) {
    macx:QRENCODE_LIB_PATH = /usr/local/lib
}

isEmpty(QRENCODE_INCLUDE_PATH) {
    macx:QRENCODE_INCLUDE_PATH = /usr/local/include
}

windows:DEFINES += WIN32
windows:RC_FILE = src/qt/res/darksilk-core.rc

windows:!contains(MINGW_THREAD_BUGFIX, 0) {
    # At least qmake's win32-g++-cross profile is missing the -lmingwthrd
    # thread-safety flag. GCC has -mthreads to enable this, but it doesn't
    # work with static linking. -lmingwthrd must come BEFORE -lmingw, so
    # it is prepended to QMAKE_LIBS_QT_ENTRY.
    # It can be turned off with MINGW_THREAD_BUGFIX=0, just in case it causes
    # any problems on some untested qmake profile now or in the future.
    DEFINES += _MT BOOST_THREAD_PROVIDES_GENERIC_SHARED_MUTEX_ON_WIN
    QMAKE_LIBS_QT_ENTRY = -lmingwthrd $$QMAKE_LIBS_QT_ENTRY
}

# Set libraries and includes at end, to use platform-defined defaults if not overridden
INCLUDEPATH += $$BOOST_INCLUDE_PATH $$BDB_INCLUDE_PATH $$OPENSSL_INCLUDE_PATH $$QRENCODE_INCLUDE_PATH
LIBS += $$join(BOOST_LIB_PATH,,-L,) $$join(BDB_LIB_PATH,,-L,) $$join(OPENSSL_LIB_PATH,,-L,) $$join(QRENCODE_LIB_PATH,,-L,)
LIBS += -lssl -lcrypto -ldb_cxx$$BDB_LIB_SUFFIX -lcryptopp -levent
# -lgdi32 has to happen after -lcrypto (see  #681)
windows:LIBS += -lws2_32 -lshlwapi -lmswsock -lole32 -loleaut32 -luuid -lgdi32
LIBS += -lboost_system$$BOOST_LIB_SUFFIX -lboost_filesystem$$BOOST_LIB_SUFFIX -lboost_program_options$$BOOST_LIB_SUFFIX -lboost_thread$$BOOST_THREAD_LIB_SUFFIX
LIBS += -lboost_chrono$$BOOST_LIB_SUFFIX

contains(RELEASE, 1) {
    !windows:!macx {
        # Linux: turn dynamic linking back on for c/c++ runtime libraries
        LIBS += -Wl,-Bdynamic
    }
}

# Set GMP
!windows: {
    LIBS += -lgmp
}

!windows:!macx {
    DEFINES += LINUX
    LIBS += -lrt -ldl
}

system($$QMAKE_LRELEASE -silent $$_PRO_FILE_)

DISTFILES += \
            src/makefile.bsd \
            src/makefile.linux-mingw \
            src/makefile.mingw \
            src/makefile.osx \
            src/makefile.unix
