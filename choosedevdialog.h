#pragma once
#ifndef CHOOSEDEVDIALOG_H
#define CHOOSEDEVDIALOG_H

#include <QtGui>
#include <vector>
#include <QDialog>
#include <string>
#include <QListWidgetItem>

class  Sniffer;
struct SettingInfo;
#include "ui_choosedevdialog.h"

class ChooseDevDialog : public QDialog,public Ui::ChooseDevDialog
{
    Q_OBJECT
public:
    ChooseDevDialog(QWidget *parent = 0);
    ChooseDevDialog(Sniffer *sni, QWidget *parent = 0);

    void GetUserSet(SettingInfo *settingInfo);

    void addNetDevInfo();

    int 		iOpenDevNum;
    bool 		bPromiscuous;
    bool 		bAutoBegin;
    int	 		iDataLimit;
    std::string	filterString;

private slots:
    void helpDialog();
    void setChoose(QListWidgetItem *changedElem);
    void setPromiscuousFlag(int flag);
    void setAutoBeginFlag(int flag);
    void setDataLimitValue(int iValue);
    void setFilterString(int index);

private:
    std::vector<QListWidgetItem *> devItemVector;
    Sniffer 	*sniffer;

};

#endif // CHOOSEDEVDIALOG_H
