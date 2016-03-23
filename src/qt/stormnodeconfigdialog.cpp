#include <QModelIndex>

#include "stormnodeconfigdialog.h"
#include "ui_stormnodeconfigdialog.h"

StormNodeConfigDialog::StormNodeConfigDialog(QWidget *parent, QString nodeAddress, QString privkey) :
    QDialog(parent),
    ui(new Ui::StormNodeConfigDialog)
{
    ui->setupUi(this);
    QString desc = "rpcallowip=127.0.0.1<br>rpcuser=REPLACEME<br>rpcpassword=REPLACEME<br>server=1<br>listen=1<br>port=REPLACEMEWITHYOURPORT<br>stormnode=1<br>stormnodeaddr=" + nodeAddress + "<br>stormnodeprivkey=" + privkey + "<br>";
    ui->detailText->setHtml(desc);
}

StormNodeConfigDialog::~StormNodeConfigDialog()
{
    delete ui;
}
