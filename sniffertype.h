#pragma once
#ifndef SNIFFERTYPE_H
#define SNIFFERTYPE_H

#endif // SNIFFERTYPE_H


#define QQ_SIGN         ('\x02')    //OICQ协议标识
#define QQ_SER_PORT     (8000)      //QQ服务器所用端口号
#define QQ_VER_OFFSET   (1)         //QQ版本偏移
#define QQ_COM_OFFSET   (3)         //QQ命令偏移
#define QQ_SEQ_OFFSET   (5)         //QQ序列号偏移
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


#define TCP_URG         (10)
#define TCP_ACK         (11)
#define TCP_PSH         (12)
#define TCP_RST         (13)
#define TCP_SYN         (14)
#define TCP_FIN         (15)

// TCP头部（20字节）
typedef struct _tcp_header
{
    unsigned short	sport;				// 源端口号
    unsigned short	dport;				// 目的端口号
    unsigned int	seq_no;				// 序列号
    unsigned int	ack_no;				// 确认号

    unsigned short  flag;               //16位标志

//    unsigned char	thl:4;				// tcp头部长度
//    unsigned char	reserved_1:4;		// 保留6位中的4位首部长度
//    unsigned char	reseverd_2:2;		// 保留6位中的2位
//    unsigned char	flag:6;				// 6位标志
//    unsigned char  urg ;
//    unsigned char ack;
//    unsigned char psh;
//    unsigned char rst;
//    unsigned char syn;
//    unsigned char fin;


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
#define DHCP_PORT       (67)
#define NBNS_PORT       (137)

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

struct OicqType
{
    //qq协议包中的具体信息
    QString     qq_version;
    QString     qq_command;
    QString     qq_sequence;
    QString     qq_number;

    void init()
    {
        qq_version    ="OICQ版本：";
        qq_command    ="OICQ命令：";
        qq_sequence   ="OICQ序列号：";
        qq_number     ="QQ号码：";
    }

    void getCommand(unsigned short commandno)
    {
        QString com;
        switch(commandno)
        {
        case 1:
            com = "注销登录(1)";
            break;
        case 2:
            com = "心跳信息(2)";
            break;
        case 4:
            com = "更换用户信息(4)";
            break;
        case 5:
            com = "搜索用户(5)";
            break;
        case 6:
            com = "获取用户信息(6)";
            break;
        case 9:
            com = "不需认证方式添加好友(9)";
            break;
        case 10:
            com = "删除好友(10)";
            break;
        case 11:
            com = "设置隐身、示忙等状态(11)";
            break;
        case 13:
            com = "需要认证的方式添加好友(12)";
            break;
        case 18:
            com = "确认收到系统消息(18)";
            break;
        case 22:
            com = "发送消息(22)";
            break;
        case 23:
            com = "收到消息，由服务器发起(23)";
            break;
        case 26:
            com = "未知作用(26)";
            break;
        case 28:
            com = "在对方好友列表上删除自己(28)";
            break;
        case 29:
            com = "请求秘钥(29)";
            break;
        case 34:
            com = "登录(34)";
            break;
        case 38:
            com = "获取好友清单(38)";
            break;
        case 39:
            com = "获取在线好友(39)";
            break;
        case 48:
            com = "群操作指令(48)";
            break;
        case 60:
            com = "群名操作(60)";
            break;
        case 63:
            com = "MEMO操作，加载图片等资源时(62)";
            break;
        case 88:
            com = "下载群好友(88)";
            break;
        case 92:
            com = "获取层次(92)";
            break;
        case 98:
            com = "请求登录(98)";
            break;
        case 101:
            com = "请求额外信息(101)";
            break;
        case 103:
            com = "签名操作(103)";
            break;
        case 128:
            com = "收到系统消息(128)";
            break;
        case 129:
            com = "收到好友状态改变信息(129)";
            break;
        case 181:
            com = "获取群好友的状态信息(181)";
            break;
        default:
            com = "未知作用"+QString("(%1)").arg(commandno);
        }
        qq_command += com;
    }
};


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

    //tcp具体信息
    QString     seq_no;//序列号
    QString     ack_no;//确认号
    QString     wnd_size;//窗口大小

    QString     flag;
    QString     urg;//紧急
    QString     ack;//确认
    QString     psh;//推送
    QString     rst;//复位
    QString     syn;//同步
    QString     fin;//终止

    QString 	strAppProto;		// 应用层
    OicqType    oicq;


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

        seq_no        ="序列号：";
        ack_no        ="确认号：";
        wnd_size      ="窗口大小：";
        flag          ="标志：";//标志
        urg           ="紧急URG：";//紧急
        ack           ="确认ACK：";//确认
        psh           ="推送PSH：";//推送
        rst           ="复位RST：";//复位
        syn           ="同步SYN：";//同步
        fin           ="终止FIN：";//终止

        strAppProto   = "应用层 - ";
        oicq.init();

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
