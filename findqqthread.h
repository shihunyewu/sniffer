#pragma once
#ifndef FINDQQTHREAD_H
#define FINDQQTHREAD_H

#include <QThread>
#include <QtEndian>
#include <map>


class FindQQDialog;
class Sniffer;

class  FindQQThread : public QThread
{
    Q_OBJECT

public:
    FindQQThread();
    FindQQThread(FindQQDialog *findQQ, Sniffer *sni);
    void stop();
protected:
    void run();

private:
    volatile bool bStopped;
    FindQQDialog  *findQQDialog;
    Sniffer 	  *sniffer;
};


#endif // FINDQQTHREAD_H
