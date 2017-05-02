#ifndef MAINWINDOW_H
#define MAINWINDOW_H


#include <QTime>
#include <QSettings>
#include <QSplitter>
#include <QFileDialog>
#include <QMessageBox>
#include <QMainWindow>
#include <QCloseEvent>
#include <QCoreApplication>

#include "listtreeview.h"
#include "settinginfo.h"
class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    MainWindow();

    void sleep(int msec);

    SettingInfo *settingInfo;   //程序全局设置
signals:
protected:
    void closeEvent(QCloseEvent *);

public slots:

private:
    int isToContinue();
    void save();
    void writeSettings();
    bool saveFile(const QString &fileName);
    void setCurrentFile(const QString &fileName);

    QString curFile;
    QSplitter *rightSplitter;		// 右边的切分窗口
    QSplitter *mainSplitter;		// 总体的切分窗口

    ListTreeView *mainTreeView;		// 捕获的数据包列表

};

#endif // MAINWINDOW_H
