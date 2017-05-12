#pragma once
#ifndef LISTTREEVIEW_H
#define LISTTREEVIEW_H

#include <QTreeView>
#include <QStandardItemModel>
#include <QStandardItem>
#include <QModelIndex>
#include <QString>
#include <QList>

class ListTreeView : public QTreeView
{
    Q_OBJECT
public:
    ListTreeView();

    void reBulidInfo();
    bool isChanged();
    void addOneCaptureItem(QString strNum, QString strTime, QString strSIP,
                                QString strDIP, QString strProto, QString strLength);
    void getOrderNumber(QModelIndex &index, QString &strNumber);
signals:

public slots:
private:
    QStandardItemModel *mainModel;
    int iPosition;

};

#endif // LISTTREEVIEW_H
