#ifndef STATISTICSPAGE_H
#define STATISTICSPAGE_H

#include <QDir>
#include <QFile>
#include <QProcess>
#include <QTime>
#include <QTimer>
#include <QStringList>
#include <QMap>
#include <QSettings>
#include <QSlider>
#include <QWidget>

#include "clientmodel.h"
#include "main.h"
#include "wallet/wallet.h"
#include "base58.h"

namespace Ui {
class StatisticsPage;
}
class ClientModel;

class StatisticsPage : public QWidget {
    Q_OBJECT

  public:
    explicit StatisticsPage(QWidget *parent = 0);
    ~StatisticsPage();

    void setModel(ClientModel *model);

    int heightPrevious;
    int connectionPrevious;
    int volumePrevious;
    double rewardPrevious;
    double netPawratePrevious;
    QString pawratePrevious;
    double hardnessPrevious;
    double hardnessPrevious2;

  public slots:

    void updateStatistics();
    void updatePrevious(int, QString, double, double, double, double, QString, int, int);

  private slots:

  private:
    Ui::StatisticsPage *ui;
    ClientModel *model;

};

#endif // STATISTICSPAGE_H
