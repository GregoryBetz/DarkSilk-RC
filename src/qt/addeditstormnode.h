#ifndef ADDEDITSTORMNODE_H
#define ADDEDITSTORMNODE_H

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#include <QDialog>

namespace Ui {
class AddEditStormNode;
}


class AddEditStormNode : public QDialog
{
    Q_OBJECT

public:
    explicit AddEditStormNode(QWidget *parent = 0);
    ~AddEditStormNode();

protected:

private slots:
    void on_okButton_clicked();
    void on_cancelButton_clicked();

signals:

private:
    Ui::AddEditStormNode *ui;
};

#endif // ADDEDITSTORMNODE_H
