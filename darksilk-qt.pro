TEMPLATE = app
TARGET = DarkSilk
VERSION = 1.0.0.0

greaterThan(QT_MAJOR_VERSION, 5) {
    INCLUDEPATH += src src/json src/qt src/qt/plugins/mrichtexteditor
    QT += network widgets
    DEFINES += ENABLE_WALLET
    DEFINES += BOOST_THREAD_USE_LIB BOOST_SPIRIT_THREADSAFE 
    DEFINES += USE_NATIVE_I2P
    CONFIG += static
    CONFIG += no_include_pwd
    CONFIG += thread
    QMAKE_CXXFLAGS = -fpermissive
}

greaterThan(QT_MAJOR_VERSION, 4) {
    INCLUDEPATH += src src/json src/qt src/qt/plugins/mrichtexteditor
    QT += network widgets
    DEFINES += ENABLE_WALLET
    DEFINES += BOOST_THREAD_USE_LIB BOOST_SPIRIT_THREADSAFE 
    DEFINES += USE_NATIVE_I2P
    DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0
    CONFIG += static
    CONFIG += no_include_pwd
    CONFIG += thread
    QMAKE_CXXFLAGS = -fpermissive
}

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
    gensecp256k1.commands = if [ -f $$PWD/src/secp256k1/src/libsecp256k1_la-secp256k1.o ]; then echo "Secp256k1 already built"; else cd $$PWD/src/secp256k1 && ./autogen.sh && ./configure --disable-shared --with-pic --with-bignum=no --enable-module-recovery && CC=$$QMAKE_CC CXX=$$QMAKE_CXX $(MAKE) OPT=\"$$QMAKE_CXXFLAGS $$QMAKE_CXXFLAGS_RELEASE\"; fi
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
SOURCES += src/txdb-leveldb.cpp
!win32 {
    # we use QMAKE_CXXFLAGS_RELEASE even without RELEASE=1 because we use RELEASE to indicate linking preferences not -O preferences
    genleveldb.commands = if [ -f $$PWD/src/leveldb/libleveldb.a ]; then echo "Level DB already built"; else cd $$PWD/src/leveldb && CC=$$QMAKE_CC CXX=$$QMAKE_CXX $(MAKE) OPT=\"$$QMAKE_CXXFLAGS $$QMAKE_CXXFLAGS_RELEASE\" libleveldb.a libmemenv.a; fi
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

#Build Univalue
INCLUDEPATH += src/univalue/include
LIBS += $$PWD/src/univalue/lib/libunivalue_la-univalue.o
LIBS += $$PWD/src/univalue/lib/libunivalue_la-univalue_read.o
LIBS += $$PWD/src/univalue/lib/libunivalue_la-univalue_write.o
!win32 {
    # we use QMAKE_CXXFLAGS_RELEASE even without RELEASE=1 because we use RELEASE to indicate linking preferences not -O preferences
    genUnivalue.commands =if [ -f $$PWD/src/univalue/lib/libunivalue_la-univalue.o ]; then echo "Univalue already built"; else cd $$PWD/src/univalue && ./autogen.sh && ./configure && CC=$$QMAKE_CC CXX=$$QMAKE_CXX $(MAKE) OPT=\"$$QMAKE_CXXFLAGS $$QMAKE_CXXFLAGS_RELEASE\"; fi
} else {
    #Windows ???
}
genUnivalue.target = $$PWD/src/univalue/lib/libunivalue_la-univalue.o
genUnivalue.depends = FORCE
PRE_TARGETDEPS += $$PWD/src/univalue/lib/libunivalue_la-univalue.o
QMAKE_EXTRA_TARGETS += genUnivalue
QMAKE_CLEAN += $$PWD/src/univalue/lib/libunivalue_la-univalue.o; cd $$PWD/src/univalue ; $(MAKE) clean

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
#    geni2pbuild.commands = cd $$PWD; /bin/sh share/inc_build_number.sh src/i2p/i2pbuild.h darksilk-core-build-number
#    geni2pbuild.target = src/i2p/i2pbuild.h
#    PRE_TARGETDEPS += src/i2p/i2pbuild.h
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
              src/qt \
              src/leveldb/db \
              src/leveldb/issues \
              src/leveldb/port \
              src/leveldb/table \
              src/leveldb/util \
              src/qt/forms \
              src/qt/locale \
              src/qt/test \
              src/secp256k1/include \
              src/secp256k1/src \
              src/test/data \
              src/leveldb/doc/bench \
              src/leveldb/helpers/memenv \
              src/leveldb/include/leveldb \
              src/leveldb/port/win \
              src/secp256k1/src/java

HEADERS +=  src/qt/darksilkgui.h \
            src/cryptkey.h \
            src/anon/stormnode/activestormnode.h \
            src/cryptogram/ies.h \
            src/qt/transactiontablemodel.h \
            src/qt/addresstablemodel.h \
            src/qt/optionsdialog.h \
            src/qt/coincontroldialog.h \
            src/qt/coincontroltreewidget.h \
            src/qt/sendcoinsdialog.h \
            src/qt/addressbookpage.h \
            src/qt/signverifymessagedialog.h \
            src/qt/aboutdialog.h \
            src/qt/editaddressdialog.h \
            src/qt/darksilkaddressvalidator.h \
            src/blindtext.h \
            src/alert.h \
            src/allocators.h \
            src/addrman.h \
            src/base58.h \
            src/bignum.h \
            src/bloom.h \
            src/chainparams.h \
            src/chainparamsseeds.h \
            src/checkpoints.h \
            src/cleanse.h \
            src/compat/compat.h \
            src/coincontrol.h \
            src/core_io.h \
            src/sync.h \
            src/random.h \
            src/util.h \
            src/utiltime.h \
            src/utilstrencodings.h \
            src/utilmoneystr.h \
            src/hash.h \
            src/uint256.h \
            src/kernel.h \
            src/scrypt.h \
            src/pbkdf2.h \
            src/serialize.h \
            src/limitedmap.h \
            src/main.h \
            src/miner.h \
            src/net.h \
            src/key.h \
            src/ecwrapper.h \
            src/pubkey.h \
            src/wallet/db.h \
            src/txdb.h \
            src/txmempool.h \
            src/wallet/walletdb.h \
            src/wallet/wallet_ismine.h \
            src/script/script.h \
            src/script/script_error.h \
            src/init.h \
            src/mruset.h \
            src/consensus/consensus.h \
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
            src/qt/clientmodel.h \
            src/qt/guiutil.h \
            src/qt/transactionrecord.h \
            src/qt/guiconstants.h \
            src/qt/optionsmodel.h \
            src/qt/monitoreddatamapper.h \
            src/qt/trafficgraphwidget.h \
            src/qt/transactiondesc.h \
            src/qt/transactiondescdialog.h \
            src/qt/darksilkamountfield.h \
            src/wallet/wallet.h \
            src/keystore.h \
            src/qt/transactionfilterproxy.h \
            src/qt/transactionview.h \
            src/qt/walletmodel.h \
            src/rpc/rpcclient.h \
            src/rpc/rpcprotocol.h \
            src/rpc/rpcserver.h \
            src/timedata.h \
            src/qt/overviewpage.h \
            src/qt/csvmodelwriter.h \
            src/crypter.h \
            src/qt/sendcoinsentry.h \
            src/qt/qvalidatedlineedit.h \
            src/qt/darksilkunits.h \
            src/qt/qvaluecombobox.h \
            src/qt/askpassphrasedialog.h \
            src/protocol.h \
            src/qt/notificator.h \
            src/qt/paymentserver.h \
            src/ui_interface.h \
            src/qt/debugconsole.h \
            src/version.h \
            src/netbase.h \
            src/clientversion.h \
            src/threadsafety.h \
            src/tinyformat.h \
            src/anon/stealth/stealth.h \
            src/qt/flowlayout.h \
            src/qt/sandstormconfig.h \
            src/anon/stormnode/stormnode.h \ 
            src/anon/stormnode/stormnode-budget.h \
            src/anon/stormnode/stormnode-payments.h \
            src/anon/sandstorm/sandstorm.h \    
            src/anon/sandstorm/sandstorm-relay.h \
            src/anon/instantx/instantx.h \
            src/anon/stormnode/stormnodeman.h \
            src/anon/stormnode/spork.h \
            src/crypto/common.h \
            src/crypto/hmac_sha256.h \
            src/crypto/hmac_sha512.h \
            src/crypto/ripemd160.h \
            src/crypto/sha1.h \
            src/crypto/sha256.h \
            src/crypto/sha512.h \
            src/qt/stormnodemanager.h \
            src/qt/addeditstormnode.h \
            src/qt/stormnodeconfigdialog.h \
            src/qt/winshutdownmonitor.h \
            src/smessage.h \
            src/qt/messagepage.h \
            src/qt/messagemodel.h \
            src/qt/sendmessagesdialog.h \
            src/qt/sendmessagesentry.h \
            src/qt/plugins/mrichtexteditor/mrichtextedit.h \
            src/qt/qvalidatedtextedit.h \
            src/qt/peertablemodel.h \
            src/qt/bantablemodel.h \
            src/primitives/block.h \
            src/primitives/transaction.h \
            src/anon/stormnode/stormnode-sync.h \
            src/chain.h \
            src/coins.h \
            src/script/compressor.h \
            src/undo.h \
            src/leveldbwrapper.h \
            src/streams.h \
            src/txdb-leveldb.h \
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
            src/qt/multisiginputentry.h \
            src/qt/multisigaddressentry.h \
            src/qt/multisigdialog.h \
            src/memusage.h \
            src/consensus/params.h \
            src/prevector.h

SOURCES +=  src/qt/darksilk.cpp src/qt/darksilkgui.cpp src/rest.cpp \
            src/blindtext.cpp \
            src/cryptkey.cpp \
            src/anon/stormnode/activestormnode.cpp \
            src/qt/transactiontablemodel.cpp \
            src/qt/addresstablemodel.cpp \
            src/qt/optionsdialog.cpp \
            src/qt/sendcoinsdialog.cpp \
            src/qt/coincontroldialog.cpp \
            src/qt/coincontroltreewidget.cpp \
            src/cryptogram/cryptogram.cpp \
            src/cryptogram/ecies.cpp \
            src/qt/addressbookpage.cpp \
            src/qt/signverifymessagedialog.cpp \
            src/qt/aboutdialog.cpp \
            src/qt/editaddressdialog.cpp \
            src/qt/darksilkaddressvalidator.cpp \
            src/qt/peertablemodel.cpp \
            src/qt/bantablemodel.cpp \
            src/alert.cpp \
            src/allocators.cpp \
            src/bloom.cpp \
            src/core_read.cpp \
            src/core_write.cpp \
            src/chainparams.cpp \
            src/cleanse.cpp \
            src/version.cpp \
            src/sync.cpp \
            src/txmempool.cpp \
            src/random.cpp \
            src/util.cpp \
            src/utiltime.cpp \
            src/utilstrencodings.cpp \
            src/utilmoneystr.cpp \
            src/hash.cpp \
            src/netbase.cpp \
            src/key.cpp \
            src/ecwrapper.cpp \
            src/pubkey.cpp \
            src/script/script.cpp \
            src/script/script_error.cpp \
            src/main.cpp \
            src/miner.cpp \
            src/init.cpp \
            src/net.cpp \
            src/checkpoints.cpp \
            src/qt/multisiginputentry.cpp \
            src/qt/multisigaddressentry.cpp \
            src/qt/multisigdialog.cpp \
            src/addrman.cpp \
            src/base58.cpp \
            src/wallet/db.cpp \
            src/wallet/walletdb.cpp \
            src/wallet/wallet_ismine.cpp \
            src/qt/clientmodel.cpp \
            src/qt/guiutil.cpp \
            src/qt/transactionrecord.cpp \
            src/qt/optionsmodel.cpp \
            src/qt/monitoreddatamapper.cpp \
            src/qt/trafficgraphwidget.cpp \
            src/qt/transactiondesc.cpp \
            src/qt/transactiondescdialog.cpp \
            src/qt/darksilkstrings.cpp \
            src/qt/darksilkamountfield.cpp \
            src/wallet/wallet.cpp \
            src/keystore.cpp \
            src/qt/transactionfilterproxy.cpp \
            src/qt/transactionview.cpp \
            src/qt/walletmodel.cpp \
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
            src/qt/overviewpage.cpp \
            src/qt/csvmodelwriter.cpp \
            src/crypter.cpp \
            src/qt/sendcoinsentry.cpp \
            src/qt/qvalidatedlineedit.cpp \
            src/qt/darksilkunits.cpp \
            src/qt/qvaluecombobox.cpp \
            src/qt/askpassphrasedialog.cpp \
            src/protocol.cpp \
            src/qt/notificator.cpp \
            src/qt/paymentserver.cpp \
            src/ui_interface.cpp \
            src/qt/debugconsole.cpp \
            src/noui.cpp \
            src/kernel.cpp \
            src/scrypt-arm.S \
            src/scrypt-x86.S \
            src/scrypt-x86_64.S \
            src/scrypt.cpp \
            src/pbkdf2.cpp \
            src/anon/stealth/stealth.cpp \
            src/qt/flowlayout.cpp \
            src/qt/sandstormconfig.cpp \
            src/anon/stormnode/stormnode.cpp \
            src/anon/stormnode/stormnode-budget.cpp \
            src/anon/stormnode/stormnode-payments.cpp \
            src/anon/sandstorm/sandstorm.cpp \
            src/anon/sandstorm/sandstorm-relay.cpp \
            src/rpc/rpcstormnode.cpp \
            src/rpc/rpcstormnode-budget.cpp \
            src/anon/instantx/instantx.cpp \
            src/anon/stormnode/spork.cpp \
            src/anon/stormnode/stormnodeconfig.cpp \
            src/anon/stormnode/stormnodeman.cpp \
            src/crypto/hmac_sha256.cpp \
            src/crypto/hmac_sha512.cpp \
            src/crypto/ripemd160.cpp \
            src/crypto/sha1.cpp \
            src/crypto/sha256.cpp \
            src/crypto/sha512.cpp \
            src/qt/stormnodemanager.cpp \
            src/qt/addeditstormnode.cpp \
            src/qt/stormnodeconfigdialog.cpp \
            src/qt/winshutdownmonitor.cpp \
            src/smessage.cpp \
            src/qt/messagepage.cpp \
            src/qt/messagemodel.cpp \
            src/qt/sendmessagesdialog.cpp \
            src/qt/sendmessagesentry.cpp \
            src/qt/qvalidatedtextedit.cpp \
            src/qt/plugins/mrichtexteditor/mrichtextedit.cpp \
            src/rpc/rpcsmessage.cpp \
            src/primitives/block.cpp \
            src/primitives/transaction.cpp \
            src/anon/stormnode/stormnode-sync.cpp \
            src/chain.cpp \
            src/uint256.cpp \
            src/coins.cpp \
            src/script/compressor.cpp \
            src/leveldbwrapper.cpp \
            src/txdb.cpp \
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

RESOURCES += \
            src/qt/darksilk.qrc

FORMS += \
            src/qt/forms/coincontroldialog.ui \
            src/qt/forms/sendcoinsdialog.ui \
            src/qt/forms/addressbookpage.ui \
            src/qt/forms/signverifymessagedialog.ui \
            src/qt/forms/aboutdialog.ui \
            src/qt/forms/editaddressdialog.ui \  
            src/qt/forms/multisiginputentry.ui \
            src/qt/forms/multisigaddressentry.ui \
            src/qt/forms/multisigdialog.ui \
            src/qt/forms/transactiondescdialog.ui \
            src/qt/forms/overviewpage.ui \
            src/qt/forms/sendcoinsentry.ui \
            src/qt/forms/askpassphrasedialog.ui \
            src/qt/forms/debugconsole.ui \
            src/qt/forms/optionsdialog.ui \
            src/qt/forms/sandstormconfig.ui \
            src/qt/forms/stormnodemanager.ui \
            src/qt/forms/addeditstormnode.ui \
            src/qt/forms/stormnodeconfigdialog.ui \
            src/qt/forms/messagepage.ui \
            src/qt/forms/sendmessagesentry.ui \
            src/qt/forms/sendmessagesdialog.ui \
            src/qt/plugins/mrichtexteditor/mrichtextedit.ui

contains(DEFINES, USE_NATIVE_I2P) {
HEADERS +=  src/i2p/i2p.h \
            src/i2p/i2psam.h \
            src/qt/showi2paddresses.h \
            src/qt/i2poptionswidget.h

SOURCES +=  src/i2p/i2p.cpp \
            src/i2p/i2psam.cpp \
            src/qt/showi2paddresses.cpp \
            src/qt/i2poptionswidget.cpp

FORMS +=    src/qt/forms/showi2paddresses.ui \
            src/qt/forms/i2poptionswidget.ui
}

contains(USE_QRCODE, 1) {
HEADERS +=  src/qt/qrcodedialog.h
SOURCES +=  src/qt/qrcodedialog.cpp
FORMS   +=  src/qt/forms/qrcodedialog.ui
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

macx:HEADERS += src/qt/macdockiconhandler.h src/qt/macnotificationhandler.h
macx:OBJECTIVE_SOURCES += src/qt/macdockiconhandler.mm src/qt/macnotificationhandler.mm
macx:LIBS += -framework Foundation -framework ApplicationServices -framework AppKit -framework CoreServices
macx:DEFINES += MAC_OSX MSG_NOSIGNAL=0
macx:ICON = src/qt/res/icons/darksilk.icns
macx:TARGET = "DarkSilk-Qt"
macx:QMAKE_CFLAGS_THREAD += -pthread
macx:QMAKE_LFLAGS_THREAD += -pthread
macx:QMAKE_CXXFLAGS_THREAD += -pthread
macx:QMAKE_INFO_PLIST = share/qt/Info.plist

# Set libraries and includes at end, to use platform-defined defaults if not overridden
INCLUDEPATH += $$BOOST_INCLUDE_PATH $$BDB_INCLUDE_PATH $$OPENSSL_INCLUDE_PATH $$QRENCODE_INCLUDE_PATH
LIBS += $$join(BOOST_LIB_PATH,,-L,) $$join(BDB_LIB_PATH,,-L,) $$join(OPENSSL_LIB_PATH,,-L,) $$join(QRENCODE_LIB_PATH,,-L,)
LIBS += -lssl -lcrypto -ldb_cxx$$BDB_LIB_SUFFIX -lcryptopp
# -lgdi32 has to happen after -lcrypto (see  #681)
windows:LIBS += -lws2_32 -lshlwapi -lmswsock -lole32 -loleaut32 -luuid -lgdi32
LIBS += -lboost_system$$BOOST_LIB_SUFFIX -lboost_filesystem$$BOOST_LIB_SUFFIX -lboost_program_options$$BOOST_LIB_SUFFIX -lboost_thread$$BOOST_THREAD_LIB_SUFFIX
windows:LIBS += -lboost_chrono$$BOOST_LIB_SUFFIX

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
            src/makefile.unix \
            .travis.yml
