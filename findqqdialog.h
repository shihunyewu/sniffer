#pragma once
#ifndef FINDQQDIALOG_H
#define FINDQQDIALOG_H

#include <QDialog>
#include <QWidget>
#include <QTreeWidgetItem>
#include <string>
#include <map>
#include <QCloseEvent>

class FindQQThread;
class MainWindow;
class Sniffer;

#include "ui_findqqdialog.h"

class FindQQDialog :public QDialog, public Ui::FindQQDialog
{
    Q_OBJECT

public:
    FindQQDialog(QWidget *parent, MainWindow *window, Sniffer *sni);
    FindQQDialog(QWidget *parent = 0);


    void addOneFindInfo(const char *szFirstTime, const char *szLastTime, const char *szSIP,
                                     const char *szDIP, const char *szQQ, const char *szSum);

    void changeOneInfoNum(const char *szLastTime, const char *szQQ, const char *szSum);

protected:
    void closeEvent(QCloseEvent *event);

private slots:
    void beginFind();
    void endFind();
    void showHelpInfo();

private:
    FindQQThread  *findQQThread;
    MainWindow    *mainwindow;
    Sniffer 	  *sniffer;

    typedef std::map<std::string, QTreeWidgetItem *> ItemMaptype;
    ItemMaptype	  itemMap;
};

#endif // FINDQQDIALOG_H
