// Copyright (c) 2011-2016 The Bitcoin developers
// Copyright (c) 2014-2016 Silk Network
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <QStringList>
#include <QSettings>

#include "darksilkunits.h"
#include "primitives/transaction.h"

DarkSilkUnits::DarkSilkUnits(QObject *parent):
        QAbstractListModel(parent),
        unitlist(availableUnits())
{
}

QList<DarkSilkUnits::Unit> DarkSilkUnits::availableUnits()
{
    QList<DarkSilkUnits::Unit> unitlist;
    unitlist.append(DRKSLK);
    unitlist.append(mDRKSLK);
    unitlist.append(uDRKSLK);
    return unitlist;
}

bool DarkSilkUnits::valid(int unit)
{
    switch(unit)
    {
    case DRKSLK:
    case mDRKSLK:
    case uDRKSLK:
        return true;
    default:
        return false;
    }
}

QString DarkSilkUnits::name(int unit)
{
    switch(unit)
    {
    case DRKSLK: return QString("DRKSLK");
    case mDRKSLK: return QString("mDRKSLK");
    case uDRKSLK: return QString::fromUtf8("μDRKSLK");
    default: return QString("???");
    }
}

QString DarkSilkUnits::description(int unit)
{
    switch(unit)
    {
    case DRKSLK: return QString("DarkSilks");
    case mDRKSLK: return QString("Milli-DarkSilks (1 / 1,000)");
    case uDRKSLK: return QString("Micro-DarkSilkss (1 / 1,000,000)");
    default: return QString("???");
    }
}

qint64 DarkSilkUnits::factor(int unit)
{
    switch(unit)
    {
    case DRKSLK:  return 100000000;
    case mDRKSLK: return 100000;
    case uDRKSLK: return 100;
    default:   return 100000000;
    }
}

int DarkSilkUnits::amountDigits(int unit)
{
    switch(unit)
    {
    case DRKSLK: return 8; // 21,000,000 (# digits, without commas)
    case mDRKSLK: return 11; // 21,000,000,000
    case uDRKSLK: return 14; // 21,000,000,000,000
    default: return 0;
    }
}

int DarkSilkUnits::decimals(int unit)
{
    switch(unit)
    {
    case DRKSLK: return 8;
    case mDRKSLK: return 5;
    case uDRKSLK: return 2;
    default: return 0;
    }
}

QString DarkSilkUnits::format(int unit, const CAmount& nIn, bool fPlus)
{
    // Note: not using straight sprintf here because we do NOT want
    // localized number formatting.
    if(!valid(unit))
        return QString(); // Refuse to format invalid unit
    qint64 n = (qint64)nIn;
    qint64 coin = factor(unit);
    int num_decimals = decimals(unit);
    qint64 n_abs = (n > 0 ? n : -n);
    qint64 quotient = n_abs / coin;
    qint64 remainder = n_abs % coin;
    QString quotient_str = QString::number(quotient);
    QString remainder_str = QString::number(remainder).rightJustified(num_decimals, '0');

    // Right-trim excess zeros after the decimal point
    int nTrim = 0;
    for (int i = remainder_str.size()-1; i>=2 && (remainder_str.at(i) == '0'); --i)
        ++nTrim;
    remainder_str.chop(nTrim);

    if (n < 0)
        quotient_str.insert(0, '-');
    else if (fPlus && n > 0)
        quotient_str.insert(0, '+');
    return quotient_str + QString(".") + remainder_str;
}

QString DarkSilkUnits::formatWithUnit(int unit, const CAmount& amount, bool plussign)
{
    return format(unit, amount, plussign) + QString(" ") + name(unit);
}

QString DarkSilkUnits::floorWithUnit(int unit, const CAmount& amount, bool plussign, SeparatorStyle separators)
{
    QSettings settings;
    int digits = settings.value("digits").toInt();

    QString result = format(unit, amount, plussign, separators);
    if(decimals(unit) > digits) result.chop(decimals(unit) - digits);

    return result + QString(" ") + name(unit);
}

QString DarkSilkUnits::floorHtmlWithUnit(int unit, const CAmount& amount, bool plussign, SeparatorStyle separators)
{
    QString str(floorWithUnit(unit, amount, plussign, separators));
    str.replace(QChar(THIN_SP_CP), QString(THIN_SP_HTML));
    return QString("<span style='white-space: nowrap;'>%1</span>").arg(str);
}

QString DarkSilkUnits::format(int unit, const CAmount& nIn, bool fPlus, SeparatorStyle separators)
{
    // Note: not using straight sprintf here because we do NOT want
    // localized number formatting.
    if(!valid(unit))
        return QString(); // Refuse to format invalid unit
    qint64 n = (qint64)nIn;
    qint64 coin = factor(unit);
    int num_decimals = decimals(unit);
    qint64 n_abs = (n > 0 ? n : -n);
    qint64 quotient = n_abs / coin;
    qint64 remainder = n_abs % coin;
    QString quotient_str = QString::number(quotient);
    QString remainder_str = QString::number(remainder).rightJustified(num_decimals, '0');

    // Right-trim excess zeros after the decimal point
    int nTrim = 0;
    for (int i = remainder_str.size()-1; i>=2 && (remainder_str.at(i) == '0'); --i)
        ++nTrim;
    remainder_str.chop(nTrim);

    if (n < 0)
        quotient_str.insert(0, '-');
    else if (fPlus && n > 0)
        quotient_str.insert(0, '+');
    return quotient_str + QString(".") + remainder_str;
}

bool DarkSilkUnits::parse(int unit, const QString &value, CAmount *val_out)
{
    if(!valid(unit) || value.isEmpty())
        return false; // Refuse to parse invalid unit or empty string
    int num_decimals = decimals(unit);
    QStringList parts = value.split(".");

    if(parts.size() > 2)
    {
        return false; // More than one dot
    }
    QString whole = parts[0];
    QString decimals;

    if(parts.size() > 1)
    {
        decimals = parts[1];
    }
    if(decimals.size() > num_decimals)
    {
        return false; // Exceeds max precision
    }
    bool ok = false;
    QString str = whole + decimals.leftJustified(num_decimals, '0');

    if(str.size() > 18)
    {
        return false; // Longer numbers will exceed 63 bits
    }
    CAmount retvalue = str.toLongLong(&ok);
    if(val_out)
    {
        *val_out = retvalue;
    }
    return ok;
}

int DarkSilkUnits::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return unitlist.size();
}

QVariant DarkSilkUnits::data(const QModelIndex &index, int role) const
{
    int row = index.row();
    if(row >= 0 && row < unitlist.size())
    {
        Unit unit = unitlist.at(row);
        switch(role)
        {
        case Qt::EditRole:
        case Qt::DisplayRole:
            return QVariant(name(unit));
        case Qt::ToolTipRole:
            return QVariant(description(unit));
        case UnitRole:
            return QVariant(static_cast<int>(unit));
        }
    }
    return QVariant();
}

CAmount DarkSilkUnits::maxMoney()
{
    return MAX_MONEY;
}

QString DarkSilkUnits::getAmountColumnTitle(int unit)
{
    QString amountTitle = QObject::tr("Amount");
    if (DarkSilkUnits::valid(unit))
    {
        amountTitle += " ("+DarkSilkUnits::name(unit) + ")";
    }
    return amountTitle;
}

