#include "listtreeview.h"

ListTreeView::ListTreeView()
{
    iPosition = 0;
    mainModel = new QStandardItemModel;

    mainModel->setColumnCount(6);
    mainModel->setHeaderData(0,Qt::Horizontal,tr("序号"));
    mainModel->setHeaderData(1,Qt::Horizontal,tr("时间"));
    mainModel->setHeaderData(2,Qt::Horizontal,tr("来源IP地址"));
    mainModel->setHeaderData(3,Qt::Horizontal,tr("目标IP地址"));
    mainModel->setHeaderData(4,Qt::Horizontal,tr("协议"));
    mainModel->setHeaderData(5,Qt::Horizontal,tr("发送长度"));

    this->setModel(mainModel);
}

/**
 * @brief ListTreeView::reBulidInfo
 * @desc  删除已有数据
 */
void ListTreeView::reBulidInfo()
{
    mainModel->clear();
    iPosition =0;

    mainModel->setColumnCount(6);
    mainModel->setHeaderData(0,Qt::Horizontal,tr("序号"));
    mainModel->setHeaderData(1,Qt::Horizontal,tr("时间"));
    mainModel->setHeaderData(2,Qt::Horizontal,tr("来源IP地址"));
    mainModel->setHeaderData(3,Qt::Horizontal,tr("目标IP地址"));
    mainModel->setHeaderData(4,Qt::Horizontal,tr("协议"));
    mainModel->setHeaderData(5,Qt::Horizontal,tr("发送长度"));

    this->setModel(mainModel);
}


/**
 * @brief ListTreeView::addOneCaptureItem
 * @param strNum
 * @param strTime
 * @param strSIP
 * @param strDIP
 * @param strProto
 * @param strLength
 * @desc  添加一条信息
 */
void ListTreeView::addOneCaptureItem(QString strNum, QString strTime, QString strSIP,
                                        QString strDIP, QString strProto, QString strLength)
{
    QStandardItem *item;

    item = new QStandardItem(QString(strNum));
    mainModel->setItem(iPosition, 0, item);
    item = new QStandardItem(QString(strTime));
    mainModel->setItem(iPosition, 1, item);
    item = new QStandardItem(QString(strSIP));
    mainModel->setItem(iPosition, 2, item);
    item = new QStandardItem(QString(strDIP));
    mainModel->setItem(iPosition, 3, item);
    item = new QStandardItem(QString(strProto));
    mainModel->setItem(iPosition, 4, item);
    item = new QStandardItem(QString(strLength));
    mainModel->setItem(iPosition, 5, item);

    iPosition++;
}

/**
 * @brief ListTreeView::getOrderNumber
 * @param index
 * @param strNumber
 * @desc  ？？
 */
void ListTreeView::getOrderNumber(QModelIndex &index, QString &strNumber)
{
    strNumber = mainModel->data(index, 0).toString();
}

/**
 * @brief ListTreeView::isChanged
 * @return
 * @desc  判断ListTreeView中是否有数据
 */
bool ListTreeView::isChanged()
{
    //获取和正则表达式 "*" 相符的Item，即查看表中是否有Item
    QList<QStandardItem *>tmp = mainModel->findItems("*",Qt::MatchWildcard|Qt::MatchRecursive);

    if(tmp.size()!=0)
        return true;
    return false;
}



