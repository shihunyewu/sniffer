#include <QtGui>
#include "findqqdialog.h"
#include "ui_findqqdialog.h"
#include "findqqthread.h"
#include "sniffer.h"
#include "mainwindow.h"

FindQQDialog::FindQQDialog(QWidget *parent) : QDialog(parent)
{
    setupUi(this);

    findQQThread = NULL;

    // 固定对话框大小，不允许调整
    this->setFixedSize(this->width(),this->height());

    connect(infoPushButton, SIGNAL(clicked()), this, SLOT(showHelpInfo()));
    connect(beginPushButton, SIGNAL(clicked()), this, SLOT(beginFind()));
    connect(endPushButton, SIGNAL(clicked()), this, SLOT(endFind()));
    endPushButton->setEnabled(false);

    setWindowIcon(QIcon(":/res/images/findqq.png"));
}

FindQQDialog::FindQQDialog(QWidget *parent, MainWindow *window, Sniffer *sni) : QDialog(parent)
{
    setupUi(this);

    mainwindow   = window;
    findQQThread = NULL;
    sniffer      = sni;

    // 固定对话框大小，不允许调整
    this->setFixedSize(this->width(),this->height());

    connect(infoPushButton, SIGNAL(clicked()), this, SLOT(showHelpInfo()));
    connect(beginPushButton, SIGNAL(clicked()), this, SLOT(beginFind()));
    connect(endPushButton, SIGNAL(clicked()), this, SLOT(endFind()));
    endPushButton->setEnabled(false);

    setWindowIcon(QIcon(":/res/images/findqq.png"));
}

void FindQQDialog::closeEvent(QCloseEvent *event)
{
    if (findQQThread != NULL) {
        endFind();
    }
    event->accept();
}

void FindQQDialog::beginFind()
{
    if (findQQThread != NULL) {
        delete findQQThread;
    }

    findQQThread = new FindQQThread(this, sniffer);

    bool bOpenSucceed = false;
    if (mainwindow->settingInfo->bPromiscuous == true) {
        bOpenSucceed = sniffer->openNetDev(mainwindow->settingInfo->iOpenDevNum,
                                        PCAP_OPENFLAG_PROMISCUOUS, mainwindow->settingInfo->iDataLimit);
    } else {
        bOpenSucceed = sniffer->openNetDev(mainwindow->settingInfo->iOpenDevNum,
                                         PCAP_OPENFLAG_NOCAPTURE_LOCAL, mainwindow->settingInfo->iDataLimit);
    }
    if (bOpenSucceed == true) {
        sniffer->setDevsFilter("ip and udp");
        findQQThread->start();
        beginPushButton->setEnabled(false);
        endPushButton->setEnabled(true);
    } else {
        QMessageBox::warning(this, tr("Sniffer"),
                        tr("<H3>无法在您的机器上打开网络适配器接口。</H3>"
                            "<p>很遗憾出现这样的结果，可能出现的原因有：\n"
                            "<p>1. 不支持您的网卡，请到 <a href=\"http://winpcap.org\">"
                            "http://winpcap.org</a> 查阅支持的硬件列表\n"
                            "<p>2. 您的杀毒软件或者HIPS程序阻止本程序运行"), QMessageBox::Ok);
    }
}

void FindQQDialog::endFind()
{
    findQQThread->stop();
    endPushButton->setEnabled(false);
    beginPushButton->setEnabled(true);
}

void FindQQDialog::addOneFindInfo(const char *szFirstTime, const char *szLastTime, const char *szSIP,
                                     const char *szDIP, const char *szQQ, const char *szSum)
{
    QTreeWidgetItem *elem = new QTreeWidgetItem(QStringList() << szFirstTime << szLastTime
                                                            << szSIP << szDIP << szQQ << szSum);

    elem->setIcon(2, QIcon(":/res/images/computer.png"));
    elem->setIcon(3, QIcon(":/res/images/computer.png"));
    elem->setIcon(4, QIcon(":/res/images/qq.png"));

    findTreeWidget->addTopLevelItem(elem);

    itemMap.insert(ItemMaptype::value_type(std::string(szQQ), elem));
}

void FindQQDialog::changeOneInfoNum(const char *szLastTime, const char *szQQ, const char *szSum)
{
    for (ItemMaptype::iterator index = itemMap.begin(); index != itemMap.end(); ++index) {
        if (index->first == szQQ) {
            index->second->setText(1, szLastTime);
            index->second->setText(5, szSum);
            break;
        }
    }
}

void FindQQDialog::showHelpInfo()
{
    QMessageBox::information(this, tr("关于捕获QQ号码"),
                tr("<p><span style=\" font-size:12pt;\">"
                    "工具简介：</span></p><p><span style=\" font-size:10pt;\">"
                    "这个小工具可以发现局域网内进行通信的QQ号码。但由于受到通"
                    "信方式的限制，现代网络常常采用交换机作为网络连接设备"
                    "枢纽，在通常情况下，交换机不会让网络中每一台主机侦听"
                    "到其他主机的通讯，因此Sniffer技术在这时必须结合网络端"
                    "口镜像技术或者进行ARP欺骗等方式获取数据包。</span></p>"
                    "<p><span style=\" font-size:10pt; color:#ff0000;\">* 因为实现"
                    "ARP欺骗容易被杀毒软件识别为病毒，故在此不予实现，"
                    "仅仅演示捕获，无线局域网一般可以嗅探全网段数据包。</span>"
                    "</p>"));
}
