#pragma once
#ifndef PROTOTREEVIEW_H
#define PROTOTREEVIEW_H

#include <QString>
#include <QTreeView>
#include <QByteArray>
#include <QStandardItemModel>

#include "sniffertype.h"
#include "sniffer.h"

class ProtoTreeView : public QTreeView
{
    Q_OBJECT

public:
    ProtoTreeView();
    ~ProtoTreeView();

    void rebuildInfo();
    void ShowTreeAnalyseInfo(const SnifferData *snifferData);

private:
    QStandardItemModel *mainModel;
};

#endif // PROTOTREEVIEW_H
