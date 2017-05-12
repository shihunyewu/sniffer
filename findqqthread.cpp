#include "findqqthread.h"
#include "sniffertype.h"
#include "sniffer.h"
#include "findqqdialog.h"

#ifdef WIN32
    #pragma warning(disable:4996)
#endif

FindQQThread::FindQQThread()
{
    bStopped = false;
    sniffer  = NULL;
}

FindQQThread::FindQQThread(FindQQDialog *findQQ, Sniffer *sni)
{
    bStopped     = false;
    findQQDialog = findQQ;
    sniffer      = sni;
}

void FindQQThread::run()
{
    int 		res;
    struct tm 	*ltime;
    char 		timestr[16];
    time_t 		local_tv_sec;

    std::map<int, int> mapQQ;

    while (bStopped != true && (res = sniffer->captureOnce()) >= 0) {
        if (res == 0) {
            continue;
        }

        local_tv_sec = sniffer->header->ts.tv_sec;
        ltime = localtime(&local_tv_sec);
        strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);

        ip_header		*ih;
        udp_header		*uh;
        unsigned int	ip_len;
        unsigned short	sport, dport;

        // 获得 IP 协议头
        ih = (ip_header *)(sniffer->pkt_data + 14);

        // 获得 IP 头的大小
        ip_len = (ih->ver_ihl & 0xF) * 4;

        // 判断是否为 UDP 协议
        if (ih->proto == UDP_SIG) {
            // 获得 UDP 协议头
            uh = (udp_header *)((u_char *)ih + ip_len);

            // 获得源端口和目的端口
            sport = qFromLittleEndian(uh->sport);
            dport = qFromLittleEndian(uh->dport);

            // 得到 UDP 协议头后的数据
            unsigned char *pByte = (unsigned char *)ih + ip_len + sizeof(udp_header);

            unsigned int QQNumber;

            // 判断是否为 QQ 协议
            if (*pByte == QQ_SIGN && (sport == QQ_SER_PORT || dport == QQ_SER_PORT)) {
                // 获取 QQ 号码
                QQNumber = *(int *)(pByte + QQ_NUM_OFFSET);
            } else {
                continue;
            }

            // 转换字节序
            QQNumber = qFromLittleEndian(QQNumber);
//ntohl
            if (QQNumber == 0) {
                continue;
            }

            char szQQNumber[12], szSaddr[24], szDaddr[24];

            sprintf(szQQNumber, "%u", QQNumber);
            sprintf(szSaddr, "%d.%d.%d.%d : %d", ih->saddr[0], ih->saddr[1], ih->saddr[2], ih->saddr[3], sport);
            sprintf(szDaddr, "%d.%d.%d.%d : %d", ih->daddr[0], ih->daddr[1], ih->daddr[2], ih->daddr[3], dport);

            if (bStopped == true) {
                return;
            }

            char szSum[10];
            bool bChange = false;
            for (std::map<int, int>::iterator index = mapQQ.begin(); index != mapQQ.end(); ++index) {
                if (index->first == QQNumber) {
                    mapQQ[index->first] = index->second + 1;
                    sprintf(szSum, "%d", index->second);
                    findQQDialog->changeOneInfoNum(timestr, szQQNumber, szSum);
                    bChange = true;
                    break;
                }
            }
            if (bChange == false) {
                mapQQ.insert(std::map<int, int>::value_type(QQNumber, 1));
                findQQDialog->addOneFindInfo(timestr, timestr, szSaddr, szDaddr, szQQNumber, "1");
            }
        }
    }
}

void FindQQThread::stop()
{
    bStopped = true;
}
