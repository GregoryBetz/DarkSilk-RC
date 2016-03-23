#include <QMessageBox>
#include <QPushButton>
#include <QKeyEvent>
#include <QSettings>

#include "sandstormconfig.h"
#include "ui_sandstormconfig.h"
#include "darksilkunits.h"
#include "guiconstants.h"
#include "optionsmodel.h"
#include "walletmodel.h"
#include "init.h"

SandstormConfig::SandstormConfig(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SandstormConfig),
    model(0)
{
    ui->setupUi(this);

    connect(ui->buttonBasic, SIGNAL(clicked()), this, SLOT(clickBasic()));
    connect(ui->buttonHigh, SIGNAL(clicked()), this, SLOT(clickHigh()));
    connect(ui->buttonMax, SIGNAL(clicked()), this, SLOT(clickMax()));
}

SandstormConfig::~SandstormConfig()
{
    delete ui;
}

void SandstormConfig::setModel(WalletModel *model)
{
    this->model = model;
}

void SandstormConfig::clickBasic()
{
    configure(true, 1000, 2);

    QString strAmount(DarkSilkUnits::formatWithUnit(
        model->getOptionsModel()->getDisplayUnit(), 1000 * COIN));
    QMessageBox::information(this, tr("Sandstorm Configuration"),
        tr(
            "Sandstorm was successfully set to basic (%1 and 2 rounds). You can change this at any time by opening DarkSilk's configuration screen."
        ).arg(strAmount)
    );

    close();
}

void SandstormConfig::clickHigh()
{
    configure(true, 1000, 50);

    QString strAmount(DarkSilkUnits::formatWithUnit(
        model->getOptionsModel()->getDisplayUnit(), 1000 * COIN));
    QMessageBox::information(this, tr("Sandstorm Configuration"),
        tr(
            "Sandstorm was successfully set to high (%1 and 50 rounds). You can change this at any time by opening DarkSilk's configuration screen."
        ).arg(strAmount)
    );

    close();
}

void SandstormConfig::clickMax()
{
    configure(true, 1000, 100);

    QString strAmount(DarkSilkUnits::formatWithUnit(
        model->getOptionsModel()->getDisplayUnit(), 1000 * COIN));
    QMessageBox::information(this, tr("Sandstorm Configuration"),
        tr(
            "Sandstorm was successfully set to maximum (%1 and 100 rounds). You can change this at any time by opening DarkSilk's configuration screen."
        ).arg(strAmount)
    );

    close();
}

void SandstormConfig::configure(bool enabled, int coins, int rounds) {

    QSettings settings;

    settings.setValue("nSandstormRounds", rounds);
    settings.setValue("nAnonymizeDarkSilkAmount", coins);

    nSandstormRounds = rounds;
    nAnonymizeDarkSilkAmount = coins;
}
