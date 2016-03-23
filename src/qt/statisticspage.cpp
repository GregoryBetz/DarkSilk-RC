#include <sstream>
#include <string>

#include "statisticspage.h"
#include "ui_statisticspage.h"
#include "main.h"
#include "wallet/wallet.h"
#include "init.h"
#include "base58.h"
#include "clientmodel.h"
#include "rpc/rpcblockchain.cpp"

using namespace json_spirit;

StatisticsPage::StatisticsPage(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::StatisticsPage) {
    ui->setupUi(this);
    setFixedSize(400, 420);

    connect(ui->startButton, SIGNAL(pressed()), this, SLOT(updateStatistics()));
}

int heightPrevious = -1;
int connectionPrevious = -1;
int volumePrevious = -1;
double rewardPrevious = -1;
double netPawratePrevious = -1;
double pawratePrevious = -1;
double hardnessPrevious = -1;
double hardnessPrevious2 = -1;
QString stakecPrevious = "";


void StatisticsPage::updateStatistics() {
    double pHardness = GetDifficulty();
    double pHardness2 = GetDifficulty(GetLastBlockIndex(pindexBest, true));
    int pPawrate = GetPoWMHashPS();
    double pPawrate2 = 0.000;
    int nHeight = pindexBest->nHeight;
    double nSubsidy = 42;
    int64_t volume = ((pindexBest->nMoneySupply) / 100000000);
    int peers = this->model->getNumConnections();
    pPawrate2 = (double)pPawrate;
    ui->progressBar->setValue(nHeight);
    QString height = QString::number(nHeight);
    QString phase = "";

    if (pindexBest->nHeight < 42001) {
        phase = "<p align=\"center\">PoW/PoS</p>";
        ui->progressBar->setMaximum(42001);
    } else {
        ui->progressBar->hide();
        phase = "<p align=\"center\">PoS</p>";
    }

    QString subsidy = QString::number(nSubsidy, 'f', 6);
    QString hardness = QString::number(pHardness, 'f', 6);
    QString hardness2 = QString::number(pHardness2, 'f', 6);
    QString pawrate = QString::number(pPawrate2, 'f', 3);
    QString Qlpawrate = model->getLastBlockDate().toString();

    QString QPeers = QString::number(peers);
    QString qVolume = QLocale(QLocale::English).toString((qlonglong)volume);

    if (nHeight > heightPrevious) {
        ui->progressBar->setValue(nHeight);
        ui->heightBox->setText("<font color=\"green\">" + height + "</font>");
    } else {
        ui->heightBox->setText(height);
    }

    if (phase != stakecPrevious) {
        ui->cBox->setText("<font color=\"green\">" + phase + "</font>");
    } else {
        ui->cBox->setText(phase);
    }

    if (pHardness2 > hardnessPrevious2) {
        ui->diffBox2->setText("<font color=\"green\">" + hardness2 + "</font>");
    } else if (pHardness2 < hardnessPrevious2) {
        ui->diffBox2->setText("<font color=\"red\">" + hardness2 + "</font>");
    } else {
        ui->diffBox2->setText(hardness2);
    }

    if (Qlpawrate != pawratePrevious) {
        ui->localBox->setText("<font color=\"green\">" + Qlpawrate + "</font>");
    } else {
        ui->localBox->setText(Qlpawrate);
    }

    if (peers > connectionPrevious) {
        ui->connectionBox->setText("<font color=\"green\">" + QPeers + "</font>");
    } else if (peers < connectionPrevious) {
        ui->connectionBox->setText("<font color=\"red\">" + QPeers + "</font>");
    } else {
        ui->connectionBox->setText(QPeers);
    }

    if (volume > volumePrevious) {
        ui->volumeBox->setText("<font color=\"green\">" + qVolume + " DRKSLK" + "</font>");
    } else if (volume < volumePrevious) {
        ui->volumeBox->setText("<font color=\"red\">" + qVolume + " DRKSLK" + "</font>");
    } else {
        ui->volumeBox->setText(qVolume + " DRKSLK");
    }

    updatePrevious(nHeight, phase, nSubsidy, pHardness, pHardness2, pPawrate2, Qlpawrate, peers, volume);
}

void StatisticsPage::updatePrevious(int nHeight, QString phase, double nSubsidy, double pHardness, double pHardness2, double pPawrate2, QString Qlpawrate, int peers, int volume) {
    heightPrevious = nHeight;
    stakecPrevious = phase;
    rewardPrevious = nSubsidy;
    hardnessPrevious = pHardness;
    hardnessPrevious2 = pHardness2;
    netPawratePrevious = pPawrate2;
    pawratePrevious = Qlpawrate;
    connectionPrevious = peers;
    volumePrevious = volume;
}

void StatisticsPage::setModel(ClientModel *model) {
    updateStatistics();
    this->model = model;
}


StatisticsPage::~StatisticsPage() {
    delete ui;
}
