#-------------------------------------------------
#
# Project created by QtCreator 2017-05-02T18:00:40
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = copySniffer
TEMPLATE = app

LIBS += -LD:/project/Qt/WpdPack/Lib/ -lwpcap
LIBS += -LD:/project/Qt/WpdPack/Lib/ -lPacket
LIBS += -LC:/QT/MinGw/mingw32/i686-w64-mingw32/lib/libws2_32
SOURCES += \
    mainwindow.cpp \
    main.cpp \
    listtreeview.cpp \
    capturethread.cpp \
    csniffer.cpp \
    sniffer.cpp \
    choosedevdialog.cpp \
    findqqdialog.cpp \
    findqqthread.cpp \
    prototreeview.cpp

HEADERS  += \
    sniffertype.h \
    mainwindow.h \
    settinginfo.h \
    listtreeview.h \
    capturethread.h \
    csniffer.h \
    sniffer.h \
    choosedevdialog.h \
    findqqdialog.h \
    findqqthread.h \
    prototreeview.h

FORMS    += \
    choosedevdialog.ui \
    findqqdialog.ui

RESOURCES += \
    sniffer.qrc
