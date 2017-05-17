#include "capturethread.h"
#include "listtreeview.h"
#include "sniffer.h"
#include <QtEndian>
#include <winuser.h>
#include <QMessageBox>

//#include "sniffertype.h"

#ifdef WIN32
#pragma warning(disable:4996)
#endif


CaptureThread::CaptureThread()
{
    bStopped = false;
    sniffer  = NULL;
    mainTree = NULL;
}

CaptureThread::CaptureThread(ListTreeView *pTree, Sniffer *pSniffer, QString tmpFileName)
{
    bStopped = false;

    mainTree = pTree;
    sniffer  = pSniffer;
    tmpFile  = tmpFileName;
}

void CaptureThread::run()
{
    int             res;
    struct  tm      *ltime;
    char            szNum[10];
    char            szLength[6];
    char            timestr[16];
    time_t          local_tv_sec;
    QByteArray      rawByteData;

    int num = 1;
    SnifferData tmpSnifferData;

    if (!tmpFile.isEmpty()) {
        sniffer->openDumpFile((const char *)tmpFile.toLocal8Bit());
    }

    // 清理遗留数据
    sniffer->snifferDataVector.clear();

    while (bStopped != true && (res = sniffer->captureOnce()) >= 0)
    {
        if (res == 0) {
            continue;
        }

        sniffer->saveCaptureData();

        tmpSnifferData.protoInfo.init();

        rawByteData.clear();
        rawByteData.setRawData((const char *)sniffer->pkt_data, sniffer->header->caplen);

        tmpSnifferData.strData = "原始捕获数据：" + rawByteData.toHex().toUpper();

        sprintf(szNum, "%d", num);
        tmpSnifferData.strNum = szNum;
        num++;

        local_tv_sec = sniffer->header->ts.tv_sec;
        ltime = localtime(&local_tv_sec);
        strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);

        tmpSnifferData.strTime = timestr;

        sprintf(szLength, "%d", sniffer->header->len);
        tmpSnifferData.strLength = szLength;

        eth_header      *eh;
        ip_header       *ih;
        udp_header      *uh;
        tcp_header      *th;
        unsigned short   sport, dport;
        unsigned int     ip_len, ip_all_len;
        unsigned char   *pByte;

        //获取tcp应答号之类


        // 获得 Mac 头，pkt_data直接就是 Mac 数据包
        eh = (eth_header *)sniffer->pkt_data;

        QByteArray DMac, SMac;

        DMac.setRawData((const char *)eh->dstmac, 6);
        SMac.setRawData((const char *)eh->srcmac, 6);
        DMac = DMac.toHex().toUpper();
        SMac = SMac.toHex().toUpper();

        tmpSnifferData.protoInfo.strDMac = tmpSnifferData.protoInfo.strDMac
                                           + DMac[0] + DMac[1] + "-" + DMac[2] + DMac[3] + "-" + DMac[4]  + DMac[5] + "-"
                                           + DMac[6] + DMac[7] + "-" + DMac[8] + DMac[9] + "-" + DMac[10] + DMac[11] ;
        tmpSnifferData.protoInfo.strSMac = tmpSnifferData.protoInfo.strSMac
                                           + SMac[0] + SMac[1] + "-" + SMac[2] + SMac[3] + "-" + SMac[4]  + SMac[5] + "-"
                                           + SMac[6] + SMac[7] + "-" + SMac[8] + SMac[9] + "-" + SMac[10] + SMac[11] ;
        // 获得 IP 协议头，IP包就是偏移十四个字节
        ih = (ip_header *)(sniffer->pkt_data + 14);

        // 获得 IP 头的大小
        ip_len = (ih->ver_ihl & 0xF) * 4;

        char szSize[6];
        sprintf(szSize, "%u", ip_len);
        tmpSnifferData.protoInfo.strHeadLength += szSize;
        tmpSnifferData.protoInfo.strHeadLength += " bytes";

        ip_all_len = (ih->tlen);
        sprintf(szSize, "%u", ip_all_len);
        tmpSnifferData.protoInfo.strLength += szSize;
        tmpSnifferData.protoInfo.strLength += " bytes";

        char szSaddr[24], szDaddr[24];

        sprintf(szSaddr, "%d.%d.%d.%d", ih->saddr[0], ih->saddr[1], ih->saddr[2], ih->saddr[3]);
        sprintf(szDaddr, "%d.%d.%d.%d", ih->daddr[0], ih->daddr[1], ih->daddr[2], ih->daddr[3]);

        switch (ih->proto) {
        case TCP_SIG:
            tmpSnifferData.strProto = "TCP";
            tmpSnifferData.protoInfo.strNextProto += "TCP (Transmission Control Protocol)";
            tmpSnifferData.protoInfo.strTranProto += "TCP 协议 (Transmission Control Protocol)";
            th = (tcp_header *)((unsigned char *)ih + ip_len);      // 获得 TCP 协议头

            //做大小端转换
            sport = qFromBigEndian(th->sport);                               // 获得源端口和目的端口
            dport = qFromBigEndian(th->dport);


            /*
             * @desc :填充tcp的序列号，应答号，以及窗口值
             * */
            tmpSnifferData.protoInfo.seq_no += QString("%1").arg(qFromBigEndian(th->seq_no),0,10);
            tmpSnifferData.protoInfo.ack_no += QString("%1").arg(qFromBigEndian(th->ack_no),0,10);
            tmpSnifferData.protoInfo.wnd_size += QString("%1").arg(qFromBigEndian(th->wnd_size),0,10);


            tmpSnifferData.protoInfo.flag += QString("%1").arg(qFromBigEndian(th->flag),0,10);


            tmpSnifferData.protoInfo.urg += _char_to_char(th->flag,TCP_URG);
            tmpSnifferData.protoInfo.ack += _char_to_char(th->flag,TCP_ACK);
            tmpSnifferData.protoInfo.psh += _char_to_char(th->flag,TCP_PSH);
            tmpSnifferData.protoInfo.rst += _char_to_char(th->flag,TCP_RST);
            tmpSnifferData.protoInfo.syn += _char_to_char(th->flag,TCP_SYN);
            tmpSnifferData.protoInfo.fin += _char_to_char(th->flag,TCP_FIN);



            if (sport == FTP_PORT || dport == FTP_PORT) {
                tmpSnifferData.strProto += " (FTP)";
                tmpSnifferData.protoInfo.strAppProto += "FTP (File Transfer Protocol)";
            } else if (sport == TELNET_PORT || dport == TELNET_PORT) {
                tmpSnifferData.strProto += " (TELNET)";
                tmpSnifferData.protoInfo.strAppProto += "TELNET";
            } else if (sport == SMTP_PORT || dport == SMTP_PORT) {
                tmpSnifferData.strProto += " (SMTP)";
                tmpSnifferData.protoInfo.strAppProto += "SMTP (Simple Message Transfer Protocol)";
            } else if (sport == POP3_PORT || dport == POP3_PORT) {
                tmpSnifferData.strProto += " (POP3)";
                tmpSnifferData.protoInfo.strAppProto += "POP3 (Post Office Protocol 3)";
            } else if (sport == HTTPS_PORT || dport == HTTPS_PORT) {
                tmpSnifferData.strProto = "HTTPS";
                tmpSnifferData.protoInfo.strAppProto += "HTTPS (Hypertext Transfer "
                                                        "Protocol over Secure Socket Layer)";
            } else if (sport == HTTP_PORT || dport == HTTP_PORT ||
                     sport == HTTP2_PORT || dport == HTTP2_PORT) {
                tmpSnifferData.strProto = "HTTP";
                tmpSnifferData.protoInfo.strAppProto += "HTTP (Hyper Text Transport Protocol)";
                tmpSnifferData.protoInfo.strSendInfo = rawByteData.remove(0, 54);
            }else
            {
                tmpSnifferData.protoInfo.strAppProto+="Unknown protocol";
            }
            break;
        case UDP_SIG:
            tmpSnifferData.strProto = "UDP";
            tmpSnifferData.protoInfo.strNextProto += "UDP (User Datagram Protocol)";
            tmpSnifferData.protoInfo.strTranProto += "UDP 协议 (User Datagram Protocol)";
            uh = (udp_header *)((unsigned char *)ih + ip_len);      // 获得 UDP 协议头
            sport = qFromBigEndian(uh->sport);                             // 获得源端口和目的端口
            dport = qFromBigEndian(uh->dport);
            pByte = (unsigned char *)ih + ip_len + sizeof(udp_header);

            if (sport == DNS_PORT || dport == DNS_PORT) {
                tmpSnifferData.strProto += " (DNS)";
                tmpSnifferData.protoInfo.strAppProto += "DNS (Domain Name Server)";
            } else if (sport == SNMP_PORT || dport == SNMP_PORT) {
                tmpSnifferData.strProto += " (SNMP)";
                tmpSnifferData.protoInfo.strAppProto += "SNMP (Simple Network Management Protocol)";
            } else if (*pByte == QQ_SIGN && (sport == QQ_SER_PORT || dport == QQ_SER_PORT)) {
                tmpSnifferData.strProto = "OICQ";
                tmpSnifferData.protoInfo.strAppProto += "OICQ(protocol for QQ)";


                unsigned short qq_version = *(short *)(pByte + 1);
                qq_version = qFromBigEndian(qq_version);
                char qq_ver_char[10];
                sprintf(qq_ver_char,"%x",qq_version);
                tmpSnifferData.protoInfo.oicq.qq_version += QString("%1").arg(qq_version,0,16);

                unsigned short qq_command = *(short *)(pByte + 3);
                qq_command = qFromBigEndian(qq_command);
                tmpSnifferData.protoInfo.oicq.getCommand(qq_command);

                unsigned short qq_sequence = *(short *)(pByte + 5);
                qq_sequence = qFromBigEndian(qq_sequence);
                tmpSnifferData.protoInfo.oicq.qq_sequence +=QString("%1").arg(qq_sequence);

                unsigned int qq_no = *(int *)(pByte + QQ_NUM_OFFSET);
                qq_no = qFromBigEndian(qq_no);
                tmpSnifferData.protoInfo.oicq.qq_number += QString("%1").arg(qq_no);

//                char text[60];
//                sprintf(text,"version:%x\ncommand:%u\nsequence:%u\nqq:%u",qq_version,qq_command,qq_sequence,qq_no);
//                MessageBoxA(0,text,0,0);

            } else if (sport == DHCP_PORT || dport == DHCP_PORT) {
                tmpSnifferData.strProto = "DHCP";
                tmpSnifferData.protoInfo.strAppProto += "DHCP(Dynamic Host Configuration Protocol)";
            }else if (sport == NBNS_PORT || dport == NBNS_PORT) {
                tmpSnifferData.strProto = "NBNS";
                tmpSnifferData.protoInfo.strAppProto += "NBNS(NetBIOS Name Service)";
            }else {
                tmpSnifferData.protoInfo.strAppProto += "Unknown Proto";
            }
            break;
        default:
            continue;
        }

        char szSPort[6], szDPort[6];
        sprintf(szSPort, "%d", sport);
        sprintf(szDPort, "%d", dport);

        tmpSnifferData.strSIP = szSaddr;
        tmpSnifferData.strSIP = tmpSnifferData.strSIP + " : " + szSPort;
        tmpSnifferData.strDIP = szDaddr;
        tmpSnifferData.strDIP = tmpSnifferData.strDIP + " : " + szDPort;

        tmpSnifferData.protoInfo.strSIP   += szSaddr;
        tmpSnifferData.protoInfo.strDIP   += szDaddr;
        tmpSnifferData.protoInfo.strSPort += szSPort;
        tmpSnifferData.protoInfo.strDPort += szDPort;



        sniffer->snifferDataVector.push_back(tmpSnifferData);

        mainTree->addOneCaptureItem(tmpSnifferData.strNum, tmpSnifferData.strTime,
                                    tmpSnifferData.strSIP, tmpSnifferData.strDIP,
                                    tmpSnifferData.strProto, tmpSnifferData.strLength);

    }
}


QString CaptureThread::_char_to_char(unsigned short value,int index)
{

    char reValue[6];
    value = qFromBigEndian(value);
    value = value<<index;
    value = value>>15;
    sprintf(reValue,"%u",value);

    return QString(reValue);
}

void CaptureThread::stop()
{
    bStopped = true;
}
