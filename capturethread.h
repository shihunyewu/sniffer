#pragma once
#ifndef CAPTURETHREAD_H
#define CAPTURETHREAD_H

#include <QThread>
#include <QString>


class ListTreeView;
class Sniffer;

class  CaptureThread : public QThread
{
    Q_OBJECT

public:
    CaptureThread();
    CaptureThread(ListTreeView *pTree, Sniffer *pSniffer, QString tmpFileName = "");

    void stop();

protected:
    void run();

private:
    QString _char_to_char(unsigned short,int index);//从flag中取第index位的值
    volatile bool bStopped;
    ListTreeView  *mainTree;
    Sniffer       *sniffer;
    QString		  tmpFile;
};

#endif // CAPTURETHREAD_H
