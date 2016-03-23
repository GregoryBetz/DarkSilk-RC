#include <boost/lexical_cast.hpp>
#include <fstream>

#include <QAbstractItemDelegate>
#include <QPainter>
#include <QTimer>
#include <QDebug>
#include <QScrollArea>
#include <QScroller>
#include <QDateTime>
#include <QApplication>
#include <QClipboard>
#include <QMessageBox>

#include "stormnodemanager.h"
#include "ui_stormnodemanager.h"
#include "addeditstormnode.h"
#include "stormnodeconfigdialog.h"
#include "sync.h"
#include "clientmodel.h"
#include "walletmodel.h"
#include "anon/stormnode/activestormnode.h"
#include "anon/stormnode/stormnodeconfig.h"
#include "anon/stormnode/stormnode.h"
#include "anon/stormnode/stormnodeman.h"
#include "wallet/walletdb.h"
#include "wallet/wallet.h"
#include "init.h"
#include "rpc/rpcserver.h"
#include "anon/sandstorm/sandstorm.h"

using namespace json_spirit;
using namespace std;

StormnodeManager::StormnodeManager(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::StormnodeManager),
    clientModel(0),
    walletModel(0)
{
    ui->setupUi(this);

    ui->editButton->setEnabled(false);
    ui->startButton->setEnabled(false);

    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->tableWidget_2->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);

    timer = new QTimer(this);
    connect(timer, SIGNAL(timeout()), this, SLOT(updateNodeList()));
    timer->start(30000);

    updateNodeList();
}

StormnodeManager::~StormnodeManager()
{
    delete ui;
}

void StormnodeManager::on_tableWidget_2_itemSelectionChanged()
{
    if(ui->tableWidget_2->selectedItems().count() > 0)
    {
        ui->editButton->setEnabled(true);
        ui->startButton->setEnabled(true);
    }
}

void StormnodeManager::updateStormNode(QString alias, QString addr, QString privkey, QString txHash, QString txIndex, QString status)
{
    LOCK(cs_storm);
    bool bFound = false;
    int nodeRow = 0;
    for(int i=0; i < ui->tableWidget_2->rowCount(); i++)
    {
        if(ui->tableWidget_2->item(i, 0)->text() == alias)
        {
            bFound = true;
            nodeRow = i;
            break;
        }
    }

    if(nodeRow == 0 && !bFound)
        ui->tableWidget_2->insertRow(0);

    QTableWidgetItem *aliasItem = new QTableWidgetItem(alias);
    QTableWidgetItem *addrItem = new QTableWidgetItem(addr);
    QTableWidgetItem *statusItem = new QTableWidgetItem(status);

    ui->tableWidget_2->setItem(nodeRow, 0, aliasItem);
    ui->tableWidget_2->setItem(nodeRow, 1, addrItem);
    ui->tableWidget_2->setItem(nodeRow, 2, statusItem);
}

void StormnodeManager::updateNodeList()
{
    //TODO
    /*TRY_LOCK(cs_stormnodes, lockStormnodes);
    if(!lockStormnodes)
        return;

    ui->countLabel->setText("Updating...");
    ui->tableWidget->clearContents();
    ui->tableWidget->setRowCount(0);
    
    std::vector<CStormnode> vStormnodes = snodeman.GetFullStormnodeVector();
    BOOST_FOREACH(CStormnode& sn, vStormnodes)
    {
        int snRow = 0;
        ui->tableWidget->insertRow(0);

 	// populate list
	// Address, Rank, Active, Active Seconds, Last Seen, Pub Key
	QTableWidgetItem *activeItem = new QTableWidgetItem(QString::number(sn.IsEnabled()));
	QTableWidgetItem *addressItem = new QTableWidgetItem(QString::fromStdString(sn.addr.ToString()));
	QTableWidgetItem *rankItem = new QTableWidgetItem(QString::number(snodeman.GetStormnodeRank(sn.vin, pindexBest->nHeight)));
	QTableWidgetItem *activeSecondsItem = new QTableWidgetItem(seconds_to_DHMS((qint64)(sn.lastTimeSeen - sn.sigTime)));
	QTableWidgetItem *lastSeenItem = new QTableWidgetItem(QString::fromStdString(DateTimeStrFormat(sn.lastTimeSeen)));
	
	CScript pubkey;
    pubkey = GetScriptForDestination(sn.pubkey.GetID());
    CTxDestination address1;
    ExtractDestination(pubkey, address1);
    CDarkSilkAddress address2(address1);
	QTableWidgetItem *pubkeyItem = new QTableWidgetItem(QString::fromStdString(address2.ToString()));
	
	ui->tableWidget->setItem(snRow, 0, addressItem);
	ui->tableWidget->setItem(snRow, 1, rankItem);
	ui->tableWidget->setItem(snRow, 2, activeItem);
	ui->tableWidget->setItem(snRow, 3, activeSecondsItem);
	ui->tableWidget->setItem(snRow, 4, lastSeenItem);
	ui->tableWidget->setItem(snRow, 5, pubkeyItem);
    }

    ui->countLabel->setText(QString::number(ui->tableWidget->rowCount()));
    
    on_UpdateButton_clicked();*/
}

void StormnodeManager::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if(model)
    {
    }
}

void StormnodeManager::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
    if(model && model->getOptionsModel())
    {
    }

}

void StormnodeManager::on_createButton_clicked()
{
    AddEditStormNode* aenode = new AddEditStormNode();
    aenode->exec();
}

void StormnodeManager::on_startButton_clicked()
{
    // start the node
    QItemSelectionModel* selectionModel = ui->tableWidget_2->selectionModel();
    QModelIndexList selected = selectionModel->selectedRows();
    if(selected.count() == 0)
        return;

    QModelIndex index = selected.at(0);
    int r = index.row();
    std::string sAlias = ui->tableWidget_2->item(r, 0)->text().toStdString();

    if(pwalletMain->IsLocked()) {
    }

    std::string statusObj;
    statusObj += "<center>Alias: " + sAlias;

    BOOST_FOREACH(CStormnodeConfig::CStormnodeEntry sne, stormnodeConfig.getEntries()) {
        if(sne.getAlias() == sAlias) {
            std::string errorMessage;

            bool result = activeStormnode.Register(sne.getIp(), sne.getPrivKey(), sne.getTxHash(), sne.getOutputIndex(), errorMessage);
 
            if(result) {
                statusObj += "<br>Successfully started Stormnode." ;
            } else {
                statusObj += "<br>Failed to start Stormnode.<br>Error: " + errorMessage;
            }
            break;
        }
    }
    statusObj += "</center>";
    pwalletMain->Lock();

    QMessageBox msg;
    msg.setText(QString::fromStdString(statusObj));
    msg.exec();
}

void StormnodeManager::on_startAllButton_clicked()
{
    if(pwalletMain->IsLocked()) {
    }

    std::vector<CStormnodeConfig::CStormnodeEntry> snEntries;

    int total = 0;
    int successful = 0;
    int fail = 0;
    std::string statusObj;

    BOOST_FOREACH(CStormnodeConfig::CStormnodeEntry sne, stormnodeConfig.getEntries()) {
        total++;

        std::string errorMessage;
        //std::string strDonateAddress = sne.getDonationAddress();
        //std::string strDonationPercentage = sne.getDonationPercentage();

        bool result = activeStormnode.Register(sne.getIp(), sne.getPrivKey(), sne.getTxHash(), sne.getOutputIndex(), errorMessage);

        if(result) {
            successful++;
        } else {
            fail++;
            statusObj += "\nFailed to start " + sne.getAlias() + ". Error: " + errorMessage;
        }
    }
    pwalletMain->Lock();

    std::string returnObj;
    returnObj = "Successfully started " + boost::lexical_cast<std::string>(successful) + " Stormnodes, failed to start " +
            boost::lexical_cast<std::string>(fail) + ", total " + boost::lexical_cast<std::string>(total);
    if (fail > 0)
        returnObj += statusObj;

    QMessageBox msg;
    msg.setText(QString::fromStdString(returnObj));
    msg.exec();
}

void StormnodeManager::on_UpdateButton_clicked()
{
    BOOST_FOREACH(CStormnodeConfig::CStormnodeEntry sne, stormnodeConfig.getEntries()) {
        std::string errorMessage;

        std::vector<CStormnode> vStormnodes = snodeman.GetFullStormnodeVector();
        if (errorMessage == ""){
            updateStormNode(QString::fromStdString(sne.getAlias()), QString::fromStdString(sne.getIp()), QString::fromStdString(sne.getPrivKey()), QString::fromStdString(sne.getTxHash()),
                QString::fromStdString(sne.getOutputIndex()), QString::fromStdString("Not in the Stormnode list."));
        }
        else {
            updateStormNode(QString::fromStdString(sne.getAlias()), QString::fromStdString(sne.getIp()), QString::fromStdString(sne.getPrivKey()), QString::fromStdString(sne.getTxHash()),
                QString::fromStdString(sne.getOutputIndex()), QString::fromStdString(errorMessage));
        }

        BOOST_FOREACH(CStormnode& sn, vStormnodes) {
            if (sn.addr.ToString().c_str() == sne.getIp()){
                updateStormNode(QString::fromStdString(sne.getAlias()), QString::fromStdString(sne.getIp()), QString::fromStdString(sne.getPrivKey()), QString::fromStdString(sne.getTxHash()),
                QString::fromStdString(sne.getOutputIndex()), QString::fromStdString("Stormnode is Running."));
            }
        }
    }
}
