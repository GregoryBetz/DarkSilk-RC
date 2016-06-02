#ifndef DEBUGCONSOLE_H
#define DEBUGCONSOLE_H

#include <QDialog>
#include <QCompleter>

#include "peertablemodel.h"

namespace Ui {
    class DEBUGConsole;
}

QT_BEGIN_NAMESPACE
class QMenu;
class QItemSelection;
QT_END_NAMESPACE

class ClientModel;

QString GetBoostVersion();

/** Local DarkSilk RPC console. */
class DEBUGConsole: public QDialog
{
    Q_OBJECT

public:
    explicit DEBUGConsole(QWidget *parent = 0);
    ~DEBUGConsole();

    void setClientModel(ClientModel *model);

    enum MessageClass {
        MC_ERROR,
        MC_DEBUG,
        CMD_REQUEST,
        CMD_REPLY,
        CMD_ERROR
    };

    enum TabTypes {
        TAB_INFO = 0,
        TAB_CONSOLE = 1,
        TAB_GRAPH = 2,
        TAB_PEERS = 3
    };

protected:
    virtual bool eventFilter(QObject* obj, QEvent *event);

private slots:
    void on_lineEdit_returnPressed();
    void on_tabWidget_currentChanged(int index);
    /** open the debug.log from the current datadir */
    void on_openDebugLogfileButton_clicked();
    /** display messagebox with program parameters (same as darksilk-core --help) */
    void on_showCLOptionsButton_clicked();
    /** change the time range of the network traffic graph */
    void on_sldGraphRange_valueChanged(int value);
    /** update traffic statistics */
    void updateTrafficStats(quint64 totalBytesIn, quint64 totalBytesOut);
    /** clear traffic graph */
    void on_btnClearTrafficGraph_clicked();
    /** updates peer info */
    void resizeEvent(QResizeEvent *event);
    void showEvent(QShowEvent *event);
    void hideEvent(QHideEvent *event);
    /** Show custom context menu on Peers tab */
    void showPeersTableContextMenu(const QPoint& point);
    /** Show custom context menu on Bans tab */
    void showBanTableContextMenu(const QPoint& point);
    /** Hides ban table if no bans are present */
    void showOrHideBanTableIfRequired();
    /** clear the selected node */
    void clearSelectedNode();

public slots:
    void clear();
    void message(int category, const QString &message, bool html = false);
    /** Set number of connections shown in the UI */
    void setNumConnections(int count);
    /** Set number of blocks shown in the UI */
    void setNumBlocks(int count);
    /** Set number of stormnodes shown in the UI */
    void setStormnodeCount(const QString &strStormnodes);
    /** Switch to peers tab and show */
    void showPeers();
    /** Go forward or back in history */
    void browseHistory(int offset);
    /** Scroll console view to end */
    void scrollToEnd();
    /** Handle selection of peer in peers list */
    void peerSelected(const QItemSelection &selected, const QItemSelection &deselected);
    /** Handle updated peer information */
    void peerLayoutChanged();
    /** Set size (number of transactions and memory usage) of the mempool in the UI */
    void setMempoolSize(long numberOfTxs, size_t dynUsage);
    /** Disconnect a selected node on the Peers tab */
    void disconnectSelectedNode();
    /** Ban a selected node on the Peers tab */
    void banSelectedNode(int bantime);
    /** Unban a selected node on the Bans tab */
    void unbanSelectedNode();
    /** set which tab has the focus (is visible) */
    void setTabFocus(enum TabTypes tabType);
signals:
    // For RPC command executor
    void stopExecutor();
    void cmdRequest(const QString &command);

private:
    static QString FormatBytes(quint64 bytes);
    void setTrafficGraphRange(int mins);

    void updateNodeDetail(const CNodeCombinedStats *stats);

    enum ColumnWidths
    {
        ADDRESS_COLUMN_WIDTH = 170,
        SUBVERSION_COLUMN_WIDTH = 140,
        PING_COLUMN_WIDTH = 70,
        BANSUBNET_COLUMN_WIDTH = 200,
        BANTIME_COLUMN_WIDTH = 250
    };

    Ui::DEBUGConsole *ui;
    ClientModel *clientModel;
    QStringList history;
    int historyPtr;

    void startExecutor();
    NodeId cachedNodeid;
    QMenu *peersTableContextMenu;
    QMenu *banTableContextMenu;
    QCompleter *autoCompleter;
};

#endif // DEBUGCONSOLE_H
