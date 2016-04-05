#ifndef CLIENTMODEL_H
#define CLIENTMODEL_H

#include <QObject>

class OptionsModel;
class AddressTableModel;
class PeerTableModel;
class BanTableModel;
class TransactionTableModel;
class CWallet;

QT_BEGIN_NAMESPACE
class QDateTime;
class QTimer;
QT_END_NAMESPACE

/** Model for DarkSilk network client. */
class ClientModel : public QObject
{
    Q_OBJECT

public:
    explicit ClientModel(OptionsModel *optionsModel, QObject *parent = 0);
    ~ClientModel();

    OptionsModel *getOptionsModel();
    PeerTableModel *getPeerTableModel();
    BanTableModel *getBanTableModel();

    int getNumConnections() const;
    QString getStormnodeCountString() const;
    int getNumBlocks() const;
    int getNumBlocksAtStartup();

    //! Return number of transactions in the mempool
    long getMempoolSize() const;
    //! Return the dynamic memory usage of the mempool
    size_t getMempoolDynamicUsage() const;

    quint64 getTotalBytesRecv() const;
    quint64 getTotalBytesSent() const;

    QDateTime getLastBlockDate() const;

    //! Return true if client connected to testnet
    bool isTestNet() const;
    //! Return true if core is doing initial block download
    bool inInitialBlockDownload() const;
    //! Return true if core is importing blocks
    bool isImporting() const;
    //! Return warnings to be displayed in status bar
    QString getStatusBarWarnings() const;

    QString formatFullVersion() const;
    QString formatBuildDate() const;
    bool isReleaseVersion() const;
    QString clientName() const;
    QString formatClientStartupTime() const;
#ifdef USE_NATIVE_I2P
    QString formatI2PNativeFullVersion() const;
    int getNumI2PConnections() const;

    QString getPublicI2PKey() const;
    QString getPrivateI2PKey() const;
    bool isI2PAddressGenerated() const;
    bool isI2POnly() const;
    QString getB32Address(const QString& destination) const;
    void generateI2PDestination(QString& pub, QString& priv) const;
#endif

private:
    OptionsModel *optionsModel;
    PeerTableModel *peerTableModel;
    BanTableModel *banTableModel;

    int cachedNumBlocks;

    QString cachedStormnodeCountString;

    int numBlocksAtStartup;

    QTimer *pollTimer;

    QTimer *pollSnTimer;

    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();

signals:
    void numConnectionsChanged(int count);
#ifdef USE_NATIVE_I2P
    void numI2PConnectionsChanged(int count);
#endif
    void numBlocksChanged(int count);
    void strStormnodesChanged(const QString &strStormnodes);
    void alertsChanged(const QString &warnings);
    void bytesChanged(quint64 totalBytesIn, quint64 totalBytesOut);

    //! Asynchronous message notification
    void message(const QString &title, const QString &message, bool modal, unsigned int style);

    // Show progress dialog e.g. for verifychain
    void showProgress(const QString &title, int nProgress);
    // Updates the memory usage stats on debug page.
    void mempoolSizeChanged(long count, size_t mempoolSizeInBytes);

public slots:
    void updateTimer();
    void updateSnTimer();
    void updateNumConnections(int numConnections);
    void updateAlert(const QString &hash, int status);
#ifdef USE_NATIVE_I2P
    void updateNumI2PConnections(int numI2PConnections);
#endif
};

#endif // CLIENTMODEL_H
