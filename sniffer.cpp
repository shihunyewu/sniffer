#include "sniffer.h"
#ifndef WIN32
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <pcap.h>
#else
    #include <pcap.h>
    #define WPCAP
    #define HAVE_REMOTE
    #include <remote-ext.h>
    #pragma comment(lib, "wpcap.lib")
    #pragma comment(lib, "Packet.lib")
    #pragma comment(lib, "ws2_32.lib")
    #pragma warning(disable:4996)
    #include <winsock.h>
#endif


Sniffer::Sniffer()
{

}

Sniffer::~Sniffer()
{
}

bool Sniffer::getNetDevInfo()
{
    if (pAllNetDevs == NULL) {
        if (findAllNetDevs() == false) {
            return false;
        }
    }

    pcap_if_t	*index;
    pcap_addr_t *pAddr;
    NetDevInfo	tmpNetDevInfo;
    char ip6str[128];

    for (index = pAllNetDevs; index != NULL; index = index->next) {
        tmpNetDevInfo.strNetDevname = index->name;

        if (index->description) {
            tmpNetDevInfo.strNetDevDescribe = "             ";
            tmpNetDevInfo.strNetDevDescribe += index->description;
        } else {
            tmpNetDevInfo.strNetDevDescribe = "             (No description available)";
        }

        for (pAddr = index->addresses; pAddr != NULL; pAddr = pAddr->next) {
            switch(pAddr->addr->sa_family) {
            case AF_INET:
                tmpNetDevInfo.strIPV4FamilyName = "                  Address Family Name : ";
                tmpNetDevInfo.strIPV4FamilyName += "AF_INET (IPV4)";
                if (pAddr->addr) {
                    tmpNetDevInfo.strIPV4Addr = "                  IPV4 Address : ";
                    tmpNetDevInfo.strIPV4Addr += iptos(((struct sockaddr_in *)pAddr->addr)->sin_addr.s_addr);
                }
                break;
            case AF_INET6:
                tmpNetDevInfo.strIPV6FamilyName = "                  Address Family Name : ";
                tmpNetDevInfo.strIPV6FamilyName += "AF_INET6 (IPV6)";
                if (pAddr->addr) {
                    tmpNetDevInfo.strIPV6Addr = "                  IPV6 Address : ";
                    //tmpNetDevInfo.strIPV6Addr += ip6tos(pAddr->addr, ip6str, sizeof(ip6str));
                }
                break;
            default:
                break;
            }
        }
        netDevInfo.push_back(tmpNetDevInfo);
    }

    return true;
}

int Sniffer::captureOnce()
{
    if (adHandle == NULL) {
        return -2;
    }

    return pcap_next_ex( adHandle, &header, &pkt_data);
}

#ifdef WIN32

bool Sniffer::OpenSaveCaptureFile(const char *szFileName)
{
    char source[PCAP_BUF_SIZE];

    if (createDevsStr(source, szFileName) == 0) {
        if (openNetDev(source) == true) {
            return true;
        }
    }

    return false;
}

#endif

void Sniffer::consolePrint()
{
    for (std::vector<NetDevInfo>::iterator index = netDevInfo.begin();
            index < netDevInfo.end(); ++index) {
        std::cout << index->strNetDevname << "\n" << index->strNetDevDescribe << "\n"
                << index->strIPV4FamilyName << "\n" << index->strIPV4Addr << "\n"
                << index->strIPV6FamilyName << "\n" << index->strIPV6Addr << std::endl;
    }
}

