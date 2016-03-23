#include <QSettings>

#include "optionsmodel.h"
#include "darksilkunits.h"
#include "init.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#include "guiutil.h"

#ifdef USE_NATIVE_I2P
#include "i2p/i2p.h"
#include <sstream>

#define I2P_OPTIONS_SECTION_NAME    "I2P"

class ScopeGroupHelper
{
public:
    ScopeGroupHelper(QSettings& settings, const QString& groupName)
        : settings_(settings)
    {
        settings_.beginGroup(groupName);
    }
    ~ScopeGroupHelper()
    {
        settings_.endGroup();
    }

private:
    QSettings& settings_;
};

#endif

bool fUseBlackTheme;

OptionsModel::OptionsModel(QObject *parent, bool resetSettings) :
    QAbstractListModel(parent)
{
    Init(resetSettings);
}

void OptionsModel::addOverriddenOption(const std::string &option)
{
    strOverriddenByCommandLine += QString::fromStdString(option) + "=" + QString::fromStdString(mapArgs[option]) + " ";
}

bool static ApplyProxySettings()
{
    QSettings settings;
    CService addrProxy(settings.value("addrProxy", "127.0.0.1:9050").toString().toStdString());
    if (!settings.value("fUseProxy", false).toBool()) {
        addrProxy = CService();
        return false;
    }
    if (!addrProxy.IsValid())
        return false;
    if (!IsLimited(NET_IPV4))
        SetProxy(NET_IPV4, addrProxy);
    if (!IsLimited(NET_IPV6))
        SetProxy(NET_IPV6, addrProxy);
    SetNameProxy(addrProxy);
    return true;
}

#ifdef USE_NATIVE_I2P
std::string& FormatI2POptionsString(
        std::string& options,
        const std::string& name,
        const std::pair<bool, std::string>& value)
{
    if (value.first)
    {
        if (!options.empty())
            options += " ";
        options += name + "=" + value.second;
    }
    return options;
}

std::string& FormatI2POptionsString(
        std::string& options,
        const std::string& name,
        const std::pair<bool, bool>& value)
{
    if (value.first)
    {
        if (!options.empty())
            options += " ";
        options += name + "=" + (value.second ? "true" : "false");
    }
    return options;
}

std::string& FormatI2POptionsString(
        std::string& options,
        const std::string& name,
        const std::pair<bool, int>& value)
{
    if (value.first)
    {
        if (!options.empty())
            options += " ";
        std::ostringstream oss;
        oss << value.second;
        options += name + "=" + oss.str();
    }
    return options;
}
#endif

void OptionsModel::Init(bool resetSettings)
{
    if (resetSettings)
        Reset();

    this->resetSettings = resetSettings;

    QSettings settings;

    // Ensure restart flag is unset on client startup
    setRestartRequired(false);

    // These are Qt-only settings:
    nDisplayUnit = settings.value("nDisplayUnit", DarkSilkUnits::DRKSLK).toInt();
    fMinimizeToTray = settings.value("fMinimizeToTray", false).toBool();
    fMinimizeOnClose = settings.value("fMinimizeOnClose", false).toBool();
    fCoinControlFeatures = settings.value("fCoinControlFeatures", false).toBool();
    nTransactionFee = settings.value("nTransactionFee").toLongLong();
    nReserveBalance = settings.value("nReserveBalance").toLongLong();
    language = settings.value("language", "").toString();
    fUseBlackTheme = settings.value("fUseBlackTheme", true).toBool();

    if (!settings.contains("digits"))
        settings.setValue("digits", "2");
    if (!settings.contains("theme"))
        settings.setValue("theme", "");

    // Sandstorm
    if (!settings.contains("nSandstormRounds"))
        settings.setValue("nSandstormRounds", 2);
    if (!SoftSetArg("-sandstormrounds", settings.value("nSandstormRounds").toString().toStdString()))
        addOverriddenOption("-sandstormrounds");
    nSandstormRounds = settings.value("nSandstormRounds").toInt();

    if (!settings.contains("nAnonymizeDarkSilkAmount")) {
        // for migration from old settings
        if (!settings.contains("nAnonymizeDarkSilkAmount"))
            settings.setValue("nAnonymizeDarkSilkAmount", 1000);
        else
            settings.setValue("nAnonymizeDarkSilkAmount", settings.value("nAnonymizeDarkSilkAmount").toInt());
    }
    if (!SoftSetArg("-anonymizedarksilkamount", settings.value("nAnonymizeDarkSilkAmount").toString().toStdString()))
        addOverriddenOption("-anonymizedarksilkamount");
    nAnonymizeDarkSilkAmount = settings.value("nAnonymizeDarkSilkAmount").toInt();

    // Network
    if (!settings.contains("fUseUPnP"))
        settings.setValue("fUseUPnP", DEFAULT_UPNP);
    if (!SoftSetBoolArg("-upnp", settings.value("fUseUPnP").toBool()))
        addOverriddenOption("-upnp");

    if (!settings.contains("fListen"))
        settings.setValue("fListen", DEFAULT_LISTEN);
    if (!SoftSetBoolArg("-listen", settings.value("fListen").toBool()))
        addOverriddenOption("-listen");

    if (!settings.contains("fUseProxy"))
        settings.setValue("fUseProxy", false);
    if (!settings.contains("addrProxy"))
        settings.setValue("addrProxy", "127.0.0.1:9050");
    // Only try to set -proxy, if user has enabled fUseProxy
    if (settings.value("fUseProxy").toBool() && !SoftSetArg("-proxy", settings.value("addrProxy").toString().toStdString()))
        addOverriddenOption("-proxy");
    else if(!settings.value("fUseProxy").toBool() && !GetArg("-proxy", "").empty())
        addOverriddenOption("-proxy");

#ifdef USE_NATIVE_I2P
    ScopeGroupHelper s(settings, I2P_OPTIONS_SECTION_NAME);

    if (settings.value("useI2POnly", false).toBool())
    {
        mapArgs["-onlynet"] = NATIVE_I2P_NET_STRING;
        std::vector<std::string>& onlyNets = mapMultiArgs["-onlynet"];
        if (std::find(onlyNets.begin(), onlyNets.end(), NATIVE_I2P_NET_STRING) == onlyNets.end())
            onlyNets.push_back(NATIVE_I2P_NET_STRING);
    }

    if (settings.contains("samhost"))
        SoftSetArg(I2P_SAM_HOST_PARAM, settings.value("samhost").toString().toStdString());

    if (settings.contains("samport"))
        SoftSetArg(I2P_SAM_PORT_PARAM, settings.value("samport").toString().toStdString());

    if (settings.contains("sessionName"))
        SoftSetArg(I2P_SESSION_NAME_PARAM, settings.value("sessionName").toString().toStdString());

    i2pInboundQuantity        = settings.value(SAM_NAME_INBOUND_QUANTITY       , SAM_DEFAULT_INBOUND_QUANTITY       ).toInt();
    i2pInboundLength          = settings.value(SAM_NAME_INBOUND_LENGTH         , SAM_DEFAULT_INBOUND_LENGTH         ).toInt();
    i2pInboundLengthVariance  = settings.value(SAM_NAME_INBOUND_LENGTHVARIANCE , SAM_DEFAULT_INBOUND_LENGTHVARIANCE ).toInt();
    i2pInboundBackupQuantity  = settings.value(SAM_NAME_INBOUND_BACKUPQUANTITY , SAM_DEFAULT_INBOUND_BACKUPQUANTITY ).toInt();
    i2pInboundAllowZeroHop    = settings.value(SAM_NAME_INBOUND_ALLOWZEROHOP   , SAM_DEFAULT_INBOUND_ALLOWZEROHOP   ).toBool();
    i2pInboundIPRestriction   = settings.value(SAM_NAME_INBOUND_IPRESTRICTION  , SAM_DEFAULT_INBOUND_IPRESTRICTION  ).toInt();
    i2pOutboundQuantity       = settings.value(SAM_NAME_OUTBOUND_QUANTITY      , SAM_DEFAULT_OUTBOUND_QUANTITY      ).toInt();
    i2pOutboundLength         = settings.value(SAM_NAME_OUTBOUND_LENGTH        , SAM_DEFAULT_OUTBOUND_LENGTH        ).toInt();
    i2pOutboundLengthVariance = settings.value(SAM_NAME_OUTBOUND_LENGTHVARIANCE, SAM_DEFAULT_OUTBOUND_LENGTHVARIANCE).toInt();
    i2pOutboundBackupQuantity = settings.value(SAM_NAME_OUTBOUND_BACKUPQUANTITY, SAM_DEFAULT_OUTBOUND_BACKUPQUANTITY).toInt();
    i2pOutboundAllowZeroHop   = settings.value(SAM_NAME_OUTBOUND_ALLOWZEROHOP  , SAM_DEFAULT_OUTBOUND_ALLOWZEROHOP  ).toBool();
    i2pOutboundIPRestriction  = settings.value(SAM_NAME_OUTBOUND_IPRESTRICTION , SAM_DEFAULT_OUTBOUND_IPRESTRICTION ).toInt();
    i2pOutboundPriority       = settings.value(SAM_NAME_OUTBOUND_PRIORITY      , SAM_DEFAULT_OUTBOUND_PRIORITY      ).toInt();

    std::string i2pOptionsTemp;
    FormatI2POptionsString(i2pOptionsTemp, SAM_NAME_INBOUND_QUANTITY       , std::make_pair(settings.contains(SAM_NAME_INBOUND_QUANTITY       ), i2pInboundQuantity));
    FormatI2POptionsString(i2pOptionsTemp, SAM_NAME_INBOUND_LENGTH         , std::make_pair(settings.contains(SAM_NAME_INBOUND_LENGTH         ), i2pInboundLength));
    FormatI2POptionsString(i2pOptionsTemp, SAM_NAME_INBOUND_LENGTHVARIANCE , std::make_pair(settings.contains(SAM_NAME_INBOUND_LENGTHVARIANCE ), i2pInboundLengthVariance));
    FormatI2POptionsString(i2pOptionsTemp, SAM_NAME_INBOUND_BACKUPQUANTITY , std::make_pair(settings.contains(SAM_NAME_INBOUND_BACKUPQUANTITY ), i2pInboundBackupQuantity));
    FormatI2POptionsString(i2pOptionsTemp, SAM_NAME_INBOUND_ALLOWZEROHOP   , std::make_pair(settings.contains(SAM_NAME_INBOUND_ALLOWZEROHOP   ), i2pInboundAllowZeroHop));
    FormatI2POptionsString(i2pOptionsTemp, SAM_NAME_INBOUND_IPRESTRICTION  , std::make_pair(settings.contains(SAM_NAME_INBOUND_IPRESTRICTION  ), i2pInboundIPRestriction));
    FormatI2POptionsString(i2pOptionsTemp, SAM_NAME_OUTBOUND_QUANTITY      , std::make_pair(settings.contains(SAM_NAME_OUTBOUND_QUANTITY      ), i2pOutboundQuantity));
    FormatI2POptionsString(i2pOptionsTemp, SAM_NAME_OUTBOUND_LENGTH        , std::make_pair(settings.contains(SAM_NAME_OUTBOUND_LENGTH        ), i2pOutboundLength));
    FormatI2POptionsString(i2pOptionsTemp, SAM_NAME_OUTBOUND_LENGTHVARIANCE, std::make_pair(settings.contains(SAM_NAME_OUTBOUND_LENGTHVARIANCE), i2pOutboundLengthVariance));
    FormatI2POptionsString(i2pOptionsTemp, SAM_NAME_OUTBOUND_BACKUPQUANTITY, std::make_pair(settings.contains(SAM_NAME_OUTBOUND_BACKUPQUANTITY), i2pOutboundBackupQuantity));
    FormatI2POptionsString(i2pOptionsTemp, SAM_NAME_OUTBOUND_ALLOWZEROHOP  , std::make_pair(settings.contains(SAM_NAME_OUTBOUND_ALLOWZEROHOP  ), i2pOutboundAllowZeroHop));
    FormatI2POptionsString(i2pOptionsTemp, SAM_NAME_OUTBOUND_IPRESTRICTION , std::make_pair(settings.contains(SAM_NAME_OUTBOUND_IPRESTRICTION ), i2pOutboundIPRestriction));
    FormatI2POptionsString(i2pOptionsTemp, SAM_NAME_OUTBOUND_PRIORITY      , std::make_pair(settings.contains(SAM_NAME_OUTBOUND_PRIORITY      ), i2pOutboundPriority));

    if (!i2pOptionsTemp.empty())
        SoftSetArg(I2P_SAM_I2P_OPTIONS_PARAM, i2pOptionsTemp);

    i2pOptions = QString::fromStdString(i2pOptionsTemp);
#endif
}

void OptionsModel::Reset()
{
    QSettings settings;

    // Remove all entries from our QSettings object
    settings.clear();
    resetSettings = true; // Needed in dash.cpp during shotdown to also remove the window positions

    // default setting for OptionsModel::StartAtStartup - disabled
    if (GUIUtil::GetStartOnSystemStartup())
        GUIUtil::SetStartOnSystemStartup(false);
}

int OptionsModel::rowCount(const QModelIndex & parent) const
{
    return OptionIDRowCount;
}

QVariant OptionsModel::data(const QModelIndex & index, int role) const
{
    if(role == Qt::EditRole)
    {
        QSettings settings;
        switch(index.row())
        {
        case StartAtStartup:
            return QVariant(GUIUtil::GetStartOnSystemStartup());
        case MinimizeToTray:
            return QVariant(fMinimizeToTray);
        case MapPortUPnP:
#ifdef USE_UPNP
            return settings.value("fUseUPnP");
#else
            return false;
#endif
        case MinimizeOnClose:
            return QVariant(fMinimizeOnClose);
        case ProxyUse:
            return settings.value("fUseProxy", false);
        case ProxyIP: {
            proxyType proxy;
            if (GetProxy(NET_IPV4, proxy))
                return QVariant(QString::fromStdString(proxy.ToStringIP()));
            else
                return QVariant(QString::fromStdString("127.0.0.1"));
        }
        case ProxyPort: {
            proxyType proxy;
            if (GetProxy(NET_IPV4, proxy))
                return QVariant(proxy.GetPort());
            else
                return QVariant(9050);
        }
        case Fee:
            return QVariant((qint64) nTransactionFee);
        case ReserveBalance:
            return QVariant((qint64) nReserveBalance);
        case SandstormRounds:
            return settings.value("nSandstormRounds");
        case AnonymizeDarkSilkAmount:
            return settings.value("nAnonymizeDarkSilkAmount");
        case Listen:
            return settings.value("fListen");
         case DisplayUnit:
            return QVariant(nDisplayUnit);
        case Language:
            return settings.value("language", "");
        case CoinControlFeatures:
            return QVariant(fCoinControlFeatures);
        case UseBlackTheme:
            return QVariant(fUseBlackTheme);
#ifdef USE_NATIVE_I2P
        case I2PUseI2POnly:
        {
            ScopeGroupHelper s(settings, I2P_OPTIONS_SECTION_NAME);
            bool useI2POnly = false;
            if (mapArgs.count("-onlynet"))
            {
                const std::vector<std::string>& onlyNets = mapMultiArgs["-onlynet"];
                if (std::find(onlyNets.begin(), onlyNets.end(), NATIVE_I2P_NET_STRING) != onlyNets.end())
                    useI2POnly = true;
            }
            return settings.value("useI2POnly", useI2POnly);
        }
        case I2PSAMHost:
        {
            ScopeGroupHelper s(settings, I2P_OPTIONS_SECTION_NAME);
            return settings.value("samhost", QString::fromStdString(GetArg(I2P_SAM_HOST_PARAM, I2P_SAM_HOST_DEFAULT)));
        }
        case I2PSAMPort:
        {
            ScopeGroupHelper s(settings, I2P_OPTIONS_SECTION_NAME);
            return settings.value("samport", QString::number((qint64)GetArg(I2P_SAM_PORT_PARAM, I2P_SAM_PORT_DEFAULT)));
        }
        case I2PSessionName:
        {
            ScopeGroupHelper s(settings, I2P_OPTIONS_SECTION_NAME);
            return settings.value("sessionName", QString::fromStdString(GetArg(I2P_SESSION_NAME_PARAM, I2P_SESSION_NAME_DEFAULT)));
        }
        case I2PInboundQuantity:
            return QVariant(i2pInboundQuantity);
        case I2PInboundLength:
            return QVariant(i2pInboundLength);
        case I2PInboundLengthVariance:
            return QVariant(i2pInboundLengthVariance);
        case I2PInboundBackupQuantity:
            return QVariant(i2pInboundBackupQuantity);
        case I2PInboundAllowZeroHop:
            return QVariant(i2pInboundAllowZeroHop);
        case I2PInboundIPRestriction:
            return QVariant(i2pInboundIPRestriction);
        case I2POutboundQuantity:
            return QVariant(i2pOutboundQuantity);
        case I2POutboundLength:
            return QVariant(i2pOutboundLength);
        case I2POutboundLengthVariance:
            return QVariant(i2pOutboundLengthVariance);
        case I2POutboundBackupQuantity:
            return QVariant(i2pOutboundBackupQuantity);
        case I2POutboundAllowZeroHop:
            return QVariant(i2pOutboundAllowZeroHop);
        case I2POutboundIPRestriction:
            return QVariant(i2pOutboundIPRestriction);
        case I2POutboundPriority:
            return QVariant(i2pOutboundPriority);
#endif
        default:
            return QVariant();
        }
    }
    return QVariant();
}

bool OptionsModel::setData(const QModelIndex & index, const QVariant & value, int role)
{
    bool successful = true; /* set to false on parse error */
    if(role == Qt::EditRole)
    {
        QSettings settings;
        switch(index.row())
        {
        case StartAtStartup:
            successful = GUIUtil::SetStartOnSystemStartup(value.toBool());
            break;
        case MinimizeToTray:
            fMinimizeToTray = value.toBool();
            settings.setValue("fMinimizeToTray", fMinimizeToTray);
            break;
        case MapPortUPnP:
            settings.setValue("fUseUPnP", value.toBool());
            MapPort(value.toBool());
            break;
        case MinimizeOnClose:
            fMinimizeOnClose = value.toBool();
            settings.setValue("fMinimizeOnClose", fMinimizeOnClose);
            break;
        case ProxyUse:
            settings.setValue("fUseProxy", value.toBool());
            ApplyProxySettings();
            break;
        case ProxyIP: {
            proxyType proxy;
            proxy = CService("127.0.0.1", 9050);
            GetProxy(NET_IPV4, proxy);

            CNetAddr addr(value.toString().toStdString());
            proxy.SetIP(addr);
            settings.setValue("addrProxy", proxy.ToStringIPPort().c_str());
            successful = ApplyProxySettings();
        }
        break;
        case ProxyPort: {
            proxyType proxy;
            proxy = CService("127.0.0.1", 9050);
            GetProxy(NET_IPV4, proxy);

            proxy.SetPort(value.toInt());
            settings.setValue("addrProxy", proxy.ToStringIPPort().c_str());
            successful = ApplyProxySettings();
        }
        break;
        case Fee:
            nTransactionFee = value.toLongLong();
            settings.setValue("nTransactionFee", (qint64) nTransactionFee);
            emit transactionFeeChanged(nTransactionFee);
            break;
        case ReserveBalance:
            nReserveBalance = value.toLongLong();
            settings.setValue("nReserveBalance", (qint64) nReserveBalance);
            emit reserveBalanceChanged(nReserveBalance);
            break;
        case DisplayUnit:
            nDisplayUnit = value.toInt();
            settings.setValue("nDisplayUnit", nDisplayUnit);
            emit displayUnitChanged(nDisplayUnit);
            break;
        case Digits:
            if (settings.value("digits") != value) {
                settings.setValue("digits", value);
                setRestartRequired(true);
            }
            break; 
        case Language:
            settings.setValue("language", value);
            break;
        case CoinControlFeatures: {
            fCoinControlFeatures = value.toBool();
            settings.setValue("fCoinControlFeatures", fCoinControlFeatures);
            emit coinControlFeaturesChanged(fCoinControlFeatures);
            }
            break;
        case UseBlackTheme:
            fUseBlackTheme = value.toBool();
            settings.setValue("fUseBlackTheme", fUseBlackTheme);
            break;
        case SandstormRounds:
            if (settings.value("nSandstormRounds") != value)
            {
                nSandstormRounds = value.toInt();
                settings.setValue("nSandstormRounds", nSandstormRounds);
                emit sandstormRoundsChanged();
            }
            break;
        case AnonymizeDarkSilkAmount:
            if (settings.value("nAnonymizeDarkSilkAmount") != value)
            {
                nAnonymizeDarkSilkAmount = value.toInt();
                settings.setValue("nAnonymizeDarkSilkAmount", nAnonymizeDarkSilkAmount);
                emit anonymizeDarkSilkAmountChanged();
            }
            break;
        case Listen:
            if (settings.value("fListen") != value) {
                settings.setValue("fListen", value);
                setRestartRequired(true);
            }
            break;
#ifdef USE_NATIVE_I2P
        case I2PUseI2POnly:
        {
            ScopeGroupHelper s(settings, I2P_OPTIONS_SECTION_NAME);
            settings.setValue("useI2POnly", value.toBool());
            break;
        }
        case I2PSAMHost:
        {
            ScopeGroupHelper s(settings, I2P_OPTIONS_SECTION_NAME);
            settings.setValue("samhost", value.toString());
            break;
        }
        case I2PSAMPort:
        {
            ScopeGroupHelper s(settings, I2P_OPTIONS_SECTION_NAME);
            settings.setValue("samport", value.toString());
            break;
        }
        case I2PSessionName:
        {
            ScopeGroupHelper s(settings, I2P_OPTIONS_SECTION_NAME);
            settings.setValue("sessionName", value.toString());
            break;
        }
        case I2PInboundQuantity:
        {
            ScopeGroupHelper s(settings, I2P_OPTIONS_SECTION_NAME);
            i2pInboundQuantity = value.toInt();
            settings.setValue(SAM_NAME_INBOUND_QUANTITY, i2pInboundQuantity);
            break;
        }
        case I2PInboundLength:
        {
            ScopeGroupHelper s(settings, I2P_OPTIONS_SECTION_NAME);
            i2pInboundLength = value.toInt();
            settings.setValue(SAM_NAME_INBOUND_LENGTH, i2pInboundLength);
            break;
        }
        case I2PInboundLengthVariance:
        {
            ScopeGroupHelper s(settings, I2P_OPTIONS_SECTION_NAME);
            i2pInboundLengthVariance = value.toInt();
            settings.setValue(SAM_NAME_INBOUND_LENGTHVARIANCE, i2pInboundLengthVariance);
            break;
        }
        case I2PInboundBackupQuantity:
        {
            ScopeGroupHelper s(settings, I2P_OPTIONS_SECTION_NAME);
            i2pInboundBackupQuantity = value.toInt();
            settings.setValue(SAM_NAME_INBOUND_BACKUPQUANTITY, i2pInboundBackupQuantity);
            break;
        }
        case I2PInboundAllowZeroHop:
        {
            ScopeGroupHelper s(settings, I2P_OPTIONS_SECTION_NAME);
            i2pInboundAllowZeroHop = value.toBool();
            settings.setValue(SAM_NAME_INBOUND_ALLOWZEROHOP, i2pInboundAllowZeroHop);
            break;
        }
        case I2PInboundIPRestriction:
        {
            ScopeGroupHelper s(settings, I2P_OPTIONS_SECTION_NAME);
            i2pInboundIPRestriction = value.toInt();
            settings.setValue(SAM_NAME_INBOUND_IPRESTRICTION, i2pInboundIPRestriction);
            break;
        }
        case I2POutboundQuantity:
        {
            ScopeGroupHelper s(settings, I2P_OPTIONS_SECTION_NAME);
            i2pOutboundQuantity = value.toInt();
            settings.setValue(SAM_NAME_OUTBOUND_QUANTITY, i2pOutboundQuantity);
            break;
        }
        case I2POutboundLength:
        {
            ScopeGroupHelper s(settings, I2P_OPTIONS_SECTION_NAME);
            i2pOutboundLength = value.toInt();
            settings.setValue(SAM_NAME_OUTBOUND_LENGTH, i2pOutboundLength);
            break;
        }
        case I2POutboundLengthVariance:
        {
            ScopeGroupHelper s(settings, I2P_OPTIONS_SECTION_NAME);
            i2pOutboundLengthVariance = value.toInt();
            settings.setValue(SAM_NAME_OUTBOUND_LENGTHVARIANCE, i2pOutboundLengthVariance);
            break;
        }
        case I2POutboundBackupQuantity:
        {
            ScopeGroupHelper s(settings, I2P_OPTIONS_SECTION_NAME);
            i2pOutboundBackupQuantity = value.toInt();
            settings.setValue(SAM_NAME_OUTBOUND_BACKUPQUANTITY, i2pOutboundBackupQuantity);
            break;
        }
        case I2POutboundAllowZeroHop:
        {
            ScopeGroupHelper s(settings, I2P_OPTIONS_SECTION_NAME);
            i2pOutboundAllowZeroHop = value.toBool();
            settings.setValue(SAM_NAME_OUTBOUND_ALLOWZEROHOP, i2pOutboundAllowZeroHop);
            break;
        }
        case I2POutboundIPRestriction:
        {
            ScopeGroupHelper s(settings, I2P_OPTIONS_SECTION_NAME);
            i2pOutboundIPRestriction = value.toInt();
            settings.setValue(SAM_NAME_OUTBOUND_IPRESTRICTION, i2pOutboundIPRestriction);
            break;
        }
        case I2POutboundPriority:
        {
            ScopeGroupHelper s(settings, I2P_OPTIONS_SECTION_NAME);
            i2pOutboundPriority = value.toInt();
            settings.setValue(SAM_NAME_OUTBOUND_PRIORITY, i2pOutboundPriority);
            break;
        }

#endif
        default:
            break;
        }
    }
    emit dataChanged(index, index);

    return successful;
}

/** Updates current unit in memory, settings and emits displayUnitChanged(newUnit) signal */
void OptionsModel::setDisplayUnit(const QVariant &value)
{
    if (!value.isNull())
    {
        QSettings settings;
        nDisplayUnit = value.toInt();
        settings.setValue("nDisplayUnit", nDisplayUnit);
        emit displayUnitChanged(nDisplayUnit);
    }
}

qint64 OptionsModel::getTransactionFee()
{
    return nTransactionFee;
}

qint64 OptionsModel::getReserveBalance()
{
    return nReserveBalance;
}

bool OptionsModel::getCoinControlFeatures()
{
    return fCoinControlFeatures;
}

bool OptionsModel::getMinimizeToTray()
{
    return fMinimizeToTray;
}

bool OptionsModel::getMinimizeOnClose()
{
    return fMinimizeOnClose;
}

int OptionsModel::getDisplayUnit()
{
    return nDisplayUnit;
}

void OptionsModel::setRestartRequired(bool fRequired)
{
    QSettings settings;
    return settings.setValue("fRestartRequired", fRequired);
}

bool OptionsModel::isRestartRequired()
{
    QSettings settings;
    return settings.value("fRestartRequired", false).toBool();
}
