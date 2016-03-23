// Copyright (c) 2011-2016 The Bitcoin developers
// Copyright (c) 2014-2016 Silk Network
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DARKSILKUNITS_H
#define DARKSILKUNITS_H

#include <QString>
#include <QAbstractListModel>

#include "amount.h"

// U+2009 THIN SPACE = UTF-8 E2 80 89
#define REAL_THIN_SP_CP 0x2009
#define REAL_THIN_SP_UTF8 "\xE2\x80\x89"
#define REAL_THIN_SP_HTML "&thinsp;"

// QMessageBox seems to have a bug whereby it doesn't display thin/hair spaces
// correctly.  Workaround is to display a space in a small font.  If you
// change this, please test that it doesn't cause the parent span to start
// wrapping.
#define HTML_HACK_SP "<span style='white-space: nowrap; font-size: 6pt'> </span>"

// Define THIN_SP_* variables to be our preferred type of thin space
#define THIN_SP_CP   REAL_THIN_SP_CP
#define THIN_SP_UTF8 REAL_THIN_SP_UTF8
#define THIN_SP_HTML HTML_HACK_SP

/** DarkSilk unit definitions. Encapsulates parsing and formatting
   and serves as list model for drop-down selection boxes.
*/
class DarkSilkUnits: public QAbstractListModel
{
    Q_OBJECT

public:
    explicit DarkSilkUnits(QObject *parent);

    /** DarkSilk units.
      @note Source: https://en.darksilk.it/wiki/Units . Please add only sensible ones
     */
    enum Unit
    {
        DRKSLK,
        mDRKSLK,
        uDRKSLK
    };

    enum SeparatorStyle
    {
        separatorNever,
        separatorStandard,
        separatorAlways
    };

    //! @name Static API
    //! Unit conversion and formatting
    ///@{

    //! Get list of units, for drop-down box
    static QList<Unit> availableUnits();
    //! Is unit ID valid?
    static bool valid(int unit);
    //! Short name
    static QString name(int unit);
    //! Longer description
    static QString description(int unit);
    //! Number of Satoshis (1e-8) per unit
    static qint64 factor(int unit);
    //! Number of amount digits (to represent max number of coins)
    static int amountDigits(int unit);
    //! Number of decimals left
    static int decimals(int unit);
    //! Format as string
    static QString format(int unit, const CAmount& nIn, bool plussign=false);
    //! Format as string (with unit)
    static QString formatWithUnit(int unit, const CAmount& amount, bool plussign=false);
    //! Parse string to coin amount
    static bool parse(int unit, const QString &value, CAmount *val_out);
    //! Gets title for amount column including current display unit if optionsModel reference available */
    static QString getAmountColumnTitle(int unit);

    //! Format as string (with unit) but floor value up to "digits" settings
    static QString floorWithUnit(int unit, const CAmount& amount, bool plussign=false, SeparatorStyle separators=separatorStandard);
    static QString floorHtmlWithUnit(int unit, const CAmount& amount, bool plussign=false, SeparatorStyle separators=separatorStandard);

    static QString format(int unit, const CAmount& nIn, bool fPlus, SeparatorStyle separators);

    //! @name AbstractListModel implementation
    //! List model for unit drop-down selection box.
    ///@{
    enum RoleIndex {
        /** Unit identifier */
        UnitRole = Qt::UserRole
    };

    int rowCount(const QModelIndex &parent) const;
    QVariant data(const QModelIndex &index, int role) const;
    ///@}

    //! Return maximum number of base units (Satoshis)
    static CAmount maxMoney();

private:
    QList<DarkSilkUnits::Unit> unitlist;
};
typedef DarkSilkUnits::Unit DarkSilkUnit;

#endif // DARKSILKUNITS_H
