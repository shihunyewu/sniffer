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
    volatile bool bStopped;
    ListTreeView  *mainTree;
    Sniffer       *sniffer;
    QString		  tmpFile;
};

#endif // CAPTURETHREAD_H
