
#include <QMessageBox>

#include "addeditstormnode.h"
#include "ui_addeditstormnode.h"
#include "anon/stormnode/stormnodeconfig.h"
#include "stormnodemanager.h"
#include "ui_stormnodemanager.h"
#include "wallet/walletdb.h"
#include "wallet/wallet.h"
#include "ui_interface.h"
#include "util.h"
#include "key.h"
#include "script/script.h"
#include "init.h"
#include "base58.h"


AddEditStormNode::AddEditStormNode(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AddEditStormNode)
{
    ui->setupUi(this);

}

AddEditStormNode::~AddEditStormNode()
{
    delete ui;
}


void AddEditStormNode::on_okButton_clicked()
{
    if(ui->aliasLineEdit->text() == "")
    {
	QMessageBox msg;
        msg.setText("Please enter an alias.");
	msg.exec();
	return;
    }
    else if(ui->addressLineEdit->text() == "")
    {
          QMessageBox msg;
        msg.setText("Please enter an ip address and port. (123.45.67.89:31000)");
        msg.exec();
        return;
    }
    else if(ui->privkeyLineEdit->text() == "")
    {
        QMessageBox msg;
        msg.setText("Please enter a Stormnode private key. This can be found using the \"Stormnode genkey\" command in the console.");
        msg.exec();
        return;
    }
    else if(ui->txhashLineEdit->text() == "")
    {
        QMessageBox msg;
        msg.setText("Please enter the transaction hash for the transaction that has 10000 coins");
        msg.exec();
        return;
    }
    else if(ui->outputindexLineEdit->text() == "")
    {
        QMessageBox msg;
        msg.setText("Please enter a transaction output index. This can be found using the \"Stormnode outputs\" command in the console.");
        msg.exec();
        return;
    }
    else
    {
        std::string sAlias = ui->aliasLineEdit->text().toStdString();
        std::string sAddress = ui->addressLineEdit->text().toStdString();
        std::string sStormnodePrivKey = ui->privkeyLineEdit->text().toStdString();
        std::string sTxHash = ui->txhashLineEdit->text().toStdString();
        std::string sOutputIndex = ui->outputindexLineEdit->text().toStdString();
        std::string sDonationAddress = "";
        std::string sDonationPercentage = "";

        boost::filesystem::path pathConfigFile = GetDataDir() / "stormnode.conf";
        boost::filesystem::ofstream stream (pathConfigFile.string(), ios::out | ios::app);
        if (stream.is_open())
        {
            stream << sAlias << " " << sAddress << " " << sStormnodePrivKey << " " << sTxHash << " " << sOutputIndex;
            if (sDonationAddress != "" && sDonationPercentage != ""){
                stream << " " << sDonationAddress << " " << sDonationPercentage << std::endl;
            } else {
                stream << std::endl;
            }
            stream.close();
        }

        stormnodeConfig.add(sAlias, sAddress, sStormnodePrivKey, sTxHash, sOutputIndex, sDonationAddress, sDonationPercentage);

        accept();
    }
}

void AddEditStormNode::on_cancelButton_clicked()
{
    reject();
}

