#pragma once
#ifndef SNIFFERTYPE_H
#define SNIFFERTYPE_H

#endif // SNIFFERTYPE_H


#define QQ_SIGN         ('\x02')    //OICQ协议标识
#define QQ_SER_PORT     (8000)      //QQ服务器所用端口号
#define QQ_NUM_OFFSET   (7)         //QQ号码信息在QQ协议头中的偏移量

//Mac头部（14字节）

typedef struct _eth_header
{
    unsigned char dstmac[6];    //目标mac地址
    unsigned char srcmac[6];    //来源mac地址
    unsigned short eth_type;    //以太网类型
}eth_header;

// ARP 头部（28字节）
typedef struct _arp_header
{
    unsigned short arp_hrd;		// 硬件类型
    unsigned short arp_pro;		// 协议类型
    unsigned char arp_hln;		// 硬件地址长度
    unsigned char arp_pln;		// 协议地址长度
    unsigned short arp_op;		// ARP操作类型
    unsigned char arp_sha[6];	// 发送者的硬件地址
    unsigned long arp_spa;		// 发送者的协议地址
    unsigned char arp_tha[6];	// 目标的硬件地址
    unsigned long arp_tpa;		// 目标的协议地址
}arp_header;

// IP 协议头 协议(Protocol) 字段标识含义
//      协议      协议号

#define IP_SIG			(0)
#define ICMP_SIG		(1)
#define IGMP_SIG		(2)
#define GGP_SIG			(3)
#define IP_ENCAP_SIG	(4)
#define ST_SIG			(5)
#define TCP_SIG			(6)
#define EGP_SIG			(8)
#define PUP_SIG			(12)
#define UDP_SIG			(17)
#define HMP_SIG			(20)
#define XNS_IDP_SIG		(22)
#define RDP_SIG			(27)
#define TP4_SIG			(29)
#define XTP_SIG			(36)
#define DDP_SIG			(37)
#define IDPR_CMTP_SIG	(39)
#define RSPF_SIG		(73)
#define VMTP_SIG		(81)
#define OSPFIGP_SIG		(89)
#define IPIP_SIG		(94)
#define ENCAP_SIG		(98)

// IPv4头部（20字节）
typedef struct _ip_header
{
    unsigned char		ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
    unsigned char		tos;            // 服务类型(Type of service)
    unsigned short		tlen;           // 总长(Total length)
    unsigned short		identification; // 标识(Identification)
    unsigned short		flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
    unsigned char		ttl;            // 存活时间(Time to live)
    unsigned char		proto;          // 协议(Protocol)
    unsigned short		crc;			// 首部校验和(Header checksum)
    unsigned char		saddr[4];		// 源地址(Source address)
    unsigned char		daddr[4];		// 目标地址(Destination address)
}ip_header;

// TCP头部（20字节）
typedef struct _tcp_header
{
    unsigned short	sport;				// 源端口号
    unsigned short	dport;				// 目的端口号
    unsigned int	seq_no;				// 序列号
    unsigned int	ack_no;				// 确认号
    unsigned char	thl:4;				// tcp头部长度
    unsigned char	reserved_1:4;		// 保留6位中的4位首部长度
    unsigned char	reseverd_2:2;		// 保留6位中的2位
    unsigned char	flag:6;				// 6位标志
    unsigned short	wnd_size;			// 16位窗口大小
    unsigned short	chk_sum;			// 16位TCP检验和
    unsigned short	urgt_p;				// 16为紧急指针
}tcp_header;

// UDP头部（8字节）
typedef struct _udp_header
{
    unsigned short	sport;		// 源端口(Source port)
    unsigned short	dport;		// 目的端口(Destination port)
    unsigned short	len;		// UDP数据包长度(Datagram length)
    unsigned short	crc;		// 校验和(Checksum)
}udp_header;

// 定义一些应用层协议使用的端口号

// TCP 协议
#define FTP_PORT 		(21)
#define TELNET_PORT 	(23)
#define SMTP_PORT 		(25)
#define HTTP_PORT  		(80)
#define HTTPS_PORT		(443)
#define HTTP2_PORT 		(8080)
#define POP3_PORT 		(110)

// UDP 协议
#define DNS_PORT		(53)
#define SNMP_PORT		(161)

// 网络设备信息结构
struct NetDevInfo
{
    std::string strNetDevname;
    std::string strNetDevDescribe;
    std::string strIPV4FamilyName;
    std::string strIPV4Addr;
    std::string strIPV6FamilyName;
    std::string strIPV6Addr;
};

#include <QString>

// 树形显示结果的数据结构
struct AnalyseProtoType
{
    QString 	strEthTitle;		// 数据链路层
    QString 	strDMac;
    QString 	strSMac;
    QString 	strType;

    QString 	strIPTitle;			// 网络层
    QString 	strVersion;
    QString 	strHeadLength;
    QString 	strLength;
    QString 	strNextProto;
    QString 	strSIP;
    QString 	strDIP;

    QString 	strTranProto;		// 传输层
    QString 	strSPort;
    QString 	strDPort;

    QString 	strAppProto;		// 应用层
    QByteArray  strSendInfo;

    void init()
    {
        strEthTitle   = "数据链路层 - Ethrmet II";
        strDMac       = "目标MAC地址：";
        strSMac       = "来源MAC地址：";
        strType       = "以太网类型：Internet Protocol (0x0800)";

        strIPTitle    = "网络层 - IP 协议 (Internet Protocol)";
        strVersion    = "版本：IPv4";
        strHeadLength = "协议头长度：";
        strLength     = "总长：";
        strNextProto  = "高层协议类型：";
        strSIP        = "来源IP地址：";
        strDIP        = "目标IP地址：";

        strTranProto  = "传输层 - ";
        strSPort      = "来源端口号：";
        strDPort      = "目标端口号：";

        strAppProto   = "应用层 - ";
    }
};

// 捕获的数据结构
struct SnifferData
{
    QString				strNum;			// 序号
    QString 			strTime;		// 时间
    QString 			strSIP;			// 来源 IP 地址，格式 IP:port
    QString 			strDIP;			// 目标 IP 地址，格式 IP:port
    QString 			strProto;		// 使用的协议
    QString				strLength;		// 数据长度
    QByteArray  		strData;		// 原始数据
    AnalyseProtoType	protoInfo;		// 树形显示结果的数据结构
};
