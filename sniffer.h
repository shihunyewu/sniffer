#pragma once
#ifndef SNIFFER_H
#define SNIFFER_H
#include <vector>
#include <iostream>

#include "csniffer.h"
#include "sniffertype.h"

class Sniffer : public CSniffer
{
public:
    Sniffer();
    ~Sniffer();

    bool getNetDevInfo();		// 构建网络设备的信息结构
    int	 captureOnce();			// 捕获一次网络数据包
    void consolePrint();		// 控制台打印的函数


    bool OpenSaveCaptureFile(const char *szFileName);

    std::vector<NetDevInfo>  netDevInfo;
    std::vector<SnifferData> snifferDataVector;
};

#endif // SNIFFER_H
