#include "prototreeview.h"
#include <QtGui>

#ifndef WIN32

#else
    #include <pcap.h>
    #define WPCAP
    #define HAVE_REMOTE
    #include <remote-ext.h>
    #pragma warning(disable:4996)
#endif
ProtoTreeView::ProtoTreeView()
{
    mainModel = new QStandardItemModel;

    mainModel->setColumnCount(1);
    mainModel->setHeaderData(0, Qt::Horizontal, tr("捕获数据分析："));

    this->setModel(mainModel);
}

ProtoTreeView::~ProtoTreeView()
{

}

void ProtoTreeView::ShowTreeAnalyseInfo(const SnifferData *snifferData)
{
    rebuildInfo();

    QStandardItem *item, *itemChild,*itemGrandChild;
    QModelIndex index;


    item = new QStandardItem(snifferData->protoInfo.strEthTitle);
    mainModel->setItem(0, item);
    index = mainModel->item(0)->index();
    setExpanded(index, true);

    //数据链路层
    itemChild = new QStandardItem(snifferData->protoInfo.strDMac);
    item->appendRow(itemChild);
    itemChild = new QStandardItem(snifferData->protoInfo.strSMac);
    item->appendRow(itemChild);
    itemChild = new QStandardItem(snifferData->protoInfo.strType);
    item->appendRow(itemChild);

    //网络层
    item = new QStandardItem(snifferData->protoInfo.strIPTitle);
    mainModel->setItem(1, item);
    index = mainModel->item(1)->index();
    setExpanded(index, true);

    itemChild = new QStandardItem(snifferData->protoInfo.strVersion);
    item->appendRow(itemChild);
    itemChild = new QStandardItem(snifferData->protoInfo.strHeadLength);
    item->appendRow(itemChild);
    itemChild = new QStandardItem(snifferData->protoInfo.strLength);
    item->appendRow(itemChild);
    itemChild = new QStandardItem(snifferData->protoInfo.strNextProto);
    item->appendRow(itemChild);
    itemChild = new QStandardItem(snifferData->protoInfo.strSIP);
    item->appendRow(itemChild);
    itemChild = new QStandardItem(snifferData->protoInfo.strDIP);
    item->appendRow(itemChild);

    //传输层
    item = new QStandardItem(snifferData->protoInfo.strTranProto);
    mainModel->setItem(2, item);
    index = mainModel->item(2)->index();
    setExpanded(index, true);

    itemChild = new QStandardItem(snifferData->protoInfo.strSPort);
    item->appendRow(itemChild);
    itemChild = new QStandardItem(snifferData->protoInfo.strDPort);
    item->appendRow(itemChild);

    if(snifferData->protoInfo.strTranProto.endsWith("TCP 协议 (Transmission Control Protocol)")){
        itemChild = new QStandardItem(snifferData->protoInfo.seq_no);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData->protoInfo.ack_no);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData->protoInfo.wnd_size);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData->protoInfo.flag);
        item->appendRow(itemChild);
            itemGrandChild = new QStandardItem(snifferData->protoInfo.urg);
            itemChild->appendRow(itemGrandChild);
            itemGrandChild = new QStandardItem(snifferData->protoInfo.ack);
            itemChild->appendRow(itemGrandChild);
            itemGrandChild = new QStandardItem(snifferData->protoInfo.psh);
            itemChild->appendRow(itemGrandChild);
            itemGrandChild = new QStandardItem(snifferData->protoInfo.rst);
            itemChild->appendRow(itemGrandChild);
            itemGrandChild = new QStandardItem(snifferData->protoInfo.syn);
            itemChild->appendRow(itemGrandChild);
            itemGrandChild = new QStandardItem(snifferData->protoInfo.fin);
            itemChild->appendRow(itemGrandChild);

            index = item->child(5)->index();
            setExpanded(index,true);

    }

    item = new QStandardItem(snifferData->protoInfo.strAppProto);
    mainModel->setItem(3, item);
    if(snifferData->protoInfo.strAppProto.endsWith("OICQ(protocol for QQ)"))
    {
        itemChild = new QStandardItem(snifferData->protoInfo.oicq.qq_version);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData->protoInfo.oicq.qq_command);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData->protoInfo.oicq.qq_sequence);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData->protoInfo.oicq.qq_number);
        item->appendRow(itemChild);
    }

    index = mainModel->item(3)->index();
    setExpanded(index, true);
}

void ProtoTreeView::rebuildInfo()
{
    mainModel->clear();

    mainModel->setColumnCount(1);
    mainModel->setHeaderData(0, Qt::Horizontal, tr("捕获数据分析："));
}
