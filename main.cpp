#include <QApplication>
#include <QtGui>
#include <QSplashScreen>
#include "mainwindow.h"

int main(int argc,char *argv[])
{
    QApplication app(argc,argv);

    //设置中文编码
    //windows上也是设置成utf-8
    QTextCodec *tc = QTextCodec::codecForName("utf-8");
    QTextCodec::setCodecForCStrings(tc);
    QTextCodec::setCodecForLocale(tc);
    QTextCodec::setCodecForTr(tc);

    //加载汉化文件
    QTranslator translator;
    translator.load(":/res/language/qt_zh_CN.qm");
    app.installTranslator(&translator);
    QSplashScreen *splash = new QSplashScreen;

    splash->setPixmap(QPixmap(":/res/images/startlogo.png"));
    splash->show();

    MainWindow *mw = new MainWindow;
    mw->sleep(1000);
    mw->showMaximized();

    splash->finish(mw);
    delete splash;
    return app.exec();

}

