#ifndef STORMNODEMANAGER_H
#define STORMNODEMANAGER_H

#include <QWidget>
#include <QTimer>

#include "util.h"
#include "sync.h"

namespace Ui {
    class StormnodeManager;
}

class ClientModel;
class WalletModel;

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

/** Stormnode Manager page widget */
class StormnodeManager : public QWidget
{
    Q_OBJECT

public:
    explicit StormnodeManager(QWidget *parent = 0);
    ~StormnodeManager();

    void setClientModel(ClientModel *clientModel);
    void setWalletModel(WalletModel *walletModel);


public slots:
    void updateNodeList();
    void updateStormNode(QString alias, QString addr, QString privkey, QString txHash, QString txIndex, QString status);
    void on_UpdateButton_clicked();

signals:

private:
    QTimer *timer;
    Ui::StormnodeManager *ui;
    ClientModel *clientModel;
    WalletModel *walletModel;
    CCriticalSection cs_storm;

private slots:
    void on_createButton_clicked();
    void on_startButton_clicked();
    void on_startAllButton_clicked();
    void on_tableWidget_2_itemSelectionChanged();
};
#endif // STORMNODEMANAGER_H
