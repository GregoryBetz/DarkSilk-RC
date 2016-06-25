
#include <QDateTime>
#include <QTimer>
#include <QDebug>

#include "clientmodel.h"
#include "guiconstants.h"
#include "bantablemodel.h"
#include "peertablemodel.h"
#include "optionsmodel.h"
#include "addresstablemodel.h"
#include "transactiontablemodel.h"
#include "chainparams.h"
#include "alert.h"
#include "main.h"
#include "ui_interface.h"
#include "anon/stormnode/stormnodeman.h"
#include "anon/stormnode/stormnode-sync.h"

#ifdef USE_NATIVE_I2P
#include "i2p/i2p.h"
#endif

static const int64_t nClientStartupTime = GetTime();

ClientModel::ClientModel(OptionsModel *optionsModel, QObject *parent) :
    QObject(parent),
    optionsModel(optionsModel),
    peerTableModel(0),
    banTableModel(0),
    cachedNumBlocks(0),
    cachedStormnodeCountString(""),
    numBlocksAtStartup(-1),
    pollTimer(0)
{
    peerTableModel = new PeerTableModel(this);
    banTableModel = new BanTableModel(this);
    pollTimer = new QTimer(this);
    connect(pollTimer, SIGNAL(timeout()), this, SLOT(updateTimer()));
    pollTimer->start(MODEL_UPDATE_DELAY);

    pollSnTimer = new QTimer(this);
    connect(pollSnTimer, SIGNAL(timeout()), this, SLOT(updateSnTimer()));
    // no need to update as frequent as data for balances/txes/blocks
    pollSnTimer->start(MODEL_UPDATE_DELAY * 4);

    subscribeToCoreSignals();
}

ClientModel::~ClientModel()
{
    unsubscribeFromCoreSignals();
}

int ClientModel::getNumConnections() const
{
    return vNodes.size();
}

QString ClientModel::getStormnodeCountString() const
{
    return QString::number((int)snodeman.CountEnabled()) + " / " + QString::number((int)snodeman.size());
}

int ClientModel::getNumBlocks() const
{
    LOCK(cs_main);
    return nBestHeight;
}

int ClientModel::getNumBlocksAtStartup()
{
    if (numBlocksAtStartup == -1) numBlocksAtStartup = getNumBlocks();
    return numBlocksAtStartup;
}

quint64 ClientModel::getTotalBytesRecv() const
{
    return CNode::GetTotalBytesRecv();
}

quint64 ClientModel::getTotalBytesSent() const
{
    return CNode::GetTotalBytesSent();
}

QDateTime ClientModel::getLastBlockDate() const
{
    LOCK(cs_main);
    if (pindexBest)
        return QDateTime::fromTime_t(pindexBest->GetBlockTime());
    else
        return QDateTime::fromTime_t(Params().GenesisBlock().nTime); // Genesis block's time of current network
}

long ClientModel::getMempoolSize() const
{
    return mempool.size();
}

size_t ClientModel::getMempoolDynamicUsage() const
{
    return mempool.DynamicMemoryUsage();
}

void ClientModel::updateTimer()
{
    // Get required lock upfront. This avoids the GUI from getting stuck on
    // periodical polls if the core is holding the locks for a longer time -
    // for example, during a wallet rescan.
    TRY_LOCK(cs_main, lockMain);
    if(!lockMain)
        return;
    // Some quantities (such as number of blocks) change so fast that we don't want to be notified for each change.
    // Periodically check and update with a timer.
    int newNumBlocks = getNumBlocks();

    if(cachedNumBlocks != newNumBlocks)
    {
        cachedNumBlocks = newNumBlocks;

        emit numBlocksChanged(newNumBlocks);
    }

    emit bytesChanged(getTotalBytesRecv(), getTotalBytesSent());

    emit mempoolSizeChanged(getMempoolSize(), getMempoolDynamicUsage());
}

void ClientModel::updateSnTimer()
{
    // Get required lock upfront. This avoids the GUI from getting stuck on
    // periodical polls if the core is holding the locks for a longer time -
    // for example, during a wallet rescan.
    TRY_LOCK(cs_main, lockMain);
    if(!lockMain)
        return;
    QString newStormnodeCountString = getStormnodeCountString();

    if (cachedStormnodeCountString != newStormnodeCountString)
    {
        cachedStormnodeCountString = newStormnodeCountString;

        emit strStormnodesChanged(cachedStormnodeCountString);
    }
}

void ClientModel::updateNumConnections(int numConnections)
{
    emit numConnectionsChanged(numConnections);
}

void ClientModel::updateAlert(const QString &hash, int status)
{
    // Show error message notification for new alert
    if(status == CT_NEW)
    {
        uint256 hash_256;
        hash_256.SetHex(hash.toStdString());
        CAlert alert = CAlert::getAlertByHash(hash_256);
        if(!alert.IsNull())
        {
            emit message(tr("Network Alert"), QString::fromStdString(alert.strStatusBar), false, CClientUIInterface::ICON_ERROR);
        }
    }

    emit alertsChanged(getStatusBarWarnings());
}

bool ClientModel::isTestNet() const
{
    return TestNet();
}

bool ClientModel::inInitialBlockDownload() const
{
    return IsInitialBlockDownload();
}

bool ClientModel::isImporting() const
{
    return fImporting;
}

QString ClientModel::getStatusBarWarnings() const
{
    return QString::fromStdString(GetWarnings("statusbar"));
}

OptionsModel *ClientModel::getOptionsModel()
{
    return optionsModel;
}

PeerTableModel *ClientModel::getPeerTableModel()
{
    return peerTableModel;
}

#ifdef USE_NATIVE_I2P
QString ClientModel::formatI2PNativeFullVersion() const
{
    return QString::fromStdString(FormatI2PNativeFullVersion());
}

void ClientModel::updateNumI2PConnections(int numI2PConnections)
{
    emit numI2PConnectionsChanged(numI2PConnections);
}

int ClientModel::getNumI2PConnections() const
{
    return nI2PNodeCount;
}

QString ClientModel::getPublicI2PKey() const
{
    return QString::fromStdString(I2PSession::Instance().getMyDestination().pub);
}

QString ClientModel::getPrivateI2PKey() const
{
    return QString::fromStdString(I2PSession::Instance().getMyDestination().priv);
}

bool ClientModel::isI2PAddressGenerated() const
{
    return I2PSession::Instance().getMyDestination().isGenerated;
}

bool ClientModel::isI2POnly() const
{
    return IsI2POnly();
}

QString ClientModel::getB32Address(const QString& destination) const
{
    return QString::fromStdString(I2PSession::GenerateB32AddressFromDestination(destination.toStdString()));
}

void ClientModel::generateI2PDestination(QString& pub, QString& priv) const
{
    const SAM::FullDestination generatedDest = I2PSession::Instance().destGenerate();
    pub = QString::fromStdString(generatedDest.pub);
    priv = QString::fromStdString(generatedDest.priv);
}

#endif

QString ClientModel::formatFullVersion() const
{
    return QString::fromStdString(FormatFullVersion());
}

BanTableModel *ClientModel::getBanTableModel()
{
    return banTableModel;
}

QString ClientModel::formatBuildDate() const
{
    return QString::fromStdString(CLIENT_DATE);
}

bool ClientModel::isReleaseVersion() const
{
    return CLIENT_VERSION_IS_RELEASE;
}

QString ClientModel::clientName() const
{
    return QString::fromStdString(CLIENT_NAME);
}

QString ClientModel::formatClientStartupTime() const
{
    return QDateTime::fromTime_t(nClientStartupTime).toString();
}

// Handlers for core signals
static void ShowProgress(ClientModel *clientmodel, const std::string &title, int nProgress)
{
    // emits signal "showProgress"
    QMetaObject::invokeMethod(clientmodel, "showProgress", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(title)),
                              Q_ARG(int, nProgress));
}

static void NotifyNumConnectionsChanged(ClientModel *clientmodel, int newNumConnections)
{
    // Too noisy: qDebug() << "NotifyNumConnectionsChanged : " + QString::number(newNumConnections);
    QMetaObject::invokeMethod(clientmodel, "updateNumConnections", Qt::QueuedConnection,
                              Q_ARG(int, newNumConnections));
}

#ifdef USE_NATIVE_I2P
static void NotifyNumI2PConnectionsChanged(ClientModel *clientmodel, int newNumI2PConnections)
{
    QMetaObject::invokeMethod(clientmodel, "updateNumI2PConnections", Qt::QueuedConnection,
                              Q_ARG(int, newNumI2PConnections));
}
#endif

static void NotifyAlertChanged(ClientModel *clientmodel, const uint256 &hash, ChangeType status)
{
    qDebug() << "NotifyAlertChanged : " + QString::fromStdString(hash.GetHex()) + " status=" + QString::number(status);
    QMetaObject::invokeMethod(clientmodel, "updateAlert", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(hash.GetHex())),
                              Q_ARG(int, status));
}

static void BannedListChanged(ClientModel *clientmodel)
{
    qDebug() << QString("%1: Requesting update for peer banlist").arg(__func__);
    QMetaObject::invokeMethod(clientmodel, "updateBanlist", Qt::QueuedConnection);
}


void ClientModel::subscribeToCoreSignals()
{
    // Connect signals to client
    uiInterface.ShowProgress.connect(boost::bind(ShowProgress, this, _1, _2));
    uiInterface.NotifyNumConnectionsChanged.connect(boost::bind(NotifyNumConnectionsChanged, this, _1));
    uiInterface.NotifyAlertChanged.connect(boost::bind(NotifyAlertChanged, this, _1, _2));
    uiInterface.BannedListChanged.connect(boost::bind(BannedListChanged, this));
#ifdef USE_NATIVE_I2P
    uiInterface.NotifyNumI2PConnectionsChanged.connect(boost::bind(NotifyNumI2PConnectionsChanged, this, _1));
#endif
}

void ClientModel::unsubscribeFromCoreSignals()
{
    // Disconnect signals from client
    uiInterface.ShowProgress.disconnect(boost::bind(ShowProgress, this, _1, _2));
    uiInterface.NotifyNumConnectionsChanged.disconnect(boost::bind(NotifyNumConnectionsChanged, this, _1));
    uiInterface.NotifyAlertChanged.disconnect(boost::bind(NotifyAlertChanged, this, _1, _2));
    uiInterface.BannedListChanged.disconnect(boost::bind(BannedListChanged, this));
#ifdef USE_NATIVE_I2P
    uiInterface.NotifyNumI2PConnectionsChanged.disconnect(boost::bind(NotifyNumI2PConnectionsChanged, this, _1));
#endif
}
