/*******************************************************************************************************************************************
* 文件名：tcpclient.h
* 文件描述：973智慧协同网络SAR系统TestBed套件——长字符串请求端，下端连接数据请求端（Data Subscriber）
* 声明：本模板代码作者王兆旭，为北京交通大学下一代互联网互联设备国家工程实验室新生基础工程技术培训专用。作者王兆旭在此郑重声明，此文件及其它用于培训的模板代码均为本人精力与经验的产物，本资源的传播方式均为作者本人向他人进行一对一传授，任何个人不得向第三方转交或展示该资源内容。任何有需求的学员，均须向王兆旭本人直接索要，亦无向他人索要或传授之权利和义务。因有些资源内容涉及实验室项目秘密，暂不考虑申请专利保护或软件著作权等事宜，故个别资源仅限实验室内部一对一发放，如发现有辜负作者本人的一片好意的行为，作者将保留就其原创性进行追查、举证、申诉和问责的权利。本资源的发放权归作者本人所有，其整理和总结过程浸透无偿贡献的热忱和为诸君学业尽绵薄之力的真诚，愿学员尊重作者的劳动成果，谢谢合作！
* 作者：王兆旭
* 身份：北京交通大学下一代互联网互联设备国家工程实验室 2013级硕博连读研究生
* E-mail. hellozxwang@foxmail.com
* Mobile. 18811774990
* QQ    . 535667240
* Addr  . 北京市海淀区西直门外北京交通大学机械楼D706室, 100044
*******************************************************************************************************************************************/
/*******************************************************************************************************************************************
*****功能说明：1.CLI方式编辑SID并发送
**************2.接收SID对应的DATA并显示
*******************************************************************************************************************************************/
/*
快速配置步骤：
1、宏定义修改
DEFAULTDIR指通过网页访问文件系统的根路径，注意系统中是否有/home，没有的话可以自行决定修改为某个路径，对正常运行没有太大影响
PhysicalPort指CoLoR协议发出Get包和接收Data包的网卡端口，注意网卡的默认有线端口名称是否为eth0，而Fedora20系统中的默认名称为em1，请注意识别
2、系统设置
在Fedora系统中因需要使用原始套接字发送自定义格式的数据包，须关闭Fedora的防火墙，命令：
sudo systemctl stop firewalld.service
在Ubuntu系统中无需任何操作
3、编译命令
gcc tcpclient.c -o tcpclient -lpthread
4、运行（因涉及原始套接字的使用，须root权限）
sudo ./tcpclient
*/

#include"transportlayerdefine.h"
#include"subscriber.h"

/*******************************************************************************************************************************************
*************************************宏定义配置数据************全局变量定义******************************************************************
*******************************************************************************************************************************************/
#ifndef _TCPCLI_
#define _TCPCLI_

//TCP任务线程控制参数组
//Tip.信号量的声明不能处在奇地址上，在结构体中，多个变量的存储采用字节对齐的方式，才会存在奇地址的问题
struct TCPCliPara
{
	uint8_t SID[SIDLEN];//任务所服务的SID
	int SIDLen;//SID的实际长度
	
	uint8_t * BUF;//发送缓冲区开头
	uint8_t * BUFEnd;//发送缓冲区结尾
	uint8_t * BUFFileEnd;//读取文件结束时，缓冲区内文件末尾所在地址

	int BUFRenewCount;//缓冲区更新次数
	unsigned long BUFLength;//发送缓冲长度

	unsigned long FileWritePoint;//文件写入进度
	unsigned long FileLength;//文件总长度

	unsigned long PacketDataLength;//单包数据段长度
	unsigned long LastPacketDataLength;//整个传输任务的最后一个数据包实际长度	

	unsigned long OffsetConfirmDATA;//在整个文件中确认收到的字节顶端
	unsigned long OffsetPacket;//在整个文件中当前封包字节数（暂时没用）
	unsigned long OffsetWaitDATA;//在整个文件中等待确认收到的字节数（发送ACK数据包偏移量字段的填写依据）

	uint8_t * AddrConfirmDATA;//在缓冲区中已确认偏移量所在地址
	uint8_t * AddrPacket;//在缓冲区中当前封包偏移量所在地址（暂时没用）
	uint8_t * AddrWaitDATA;//在缓冲区中待确认偏移量所在地址（暂时没用）

	unsigned long RTOs;//往返容忍时延（RTO大于1秒部分，单位秒）
	unsigned long RTOus;//往返容忍时延（RTO小于1秒部分，单位微秒）
	unsigned long RTOns;//往返容忍时延（RTO小于1秒部分，单位纳秒）

	int FlagInputBUF;//是否将收到的数据写入缓冲

	int TimingState;//计时状态，0按时，1超时
	int ThreadState;//任务状态（用于结束过程的控制）

	//内部线程触发用UDP通信变量
	int CountTCPClientTimingBegin_Triggering;
	int CountTCPClientTimingBegin_Waiting;
	int CountTCPClientTimingBegin_Triggered;

	int SENDTCPClientTimingBegin;
	int RECVTCPClientTimingBegin;
	struct sockaddr_in SENDAddrToTCPClientTimingBegin;
	struct sockaddr_in RECVAddrToTCPClientTimingBegin;

	int CountTCPClientTimingEnd_Triggering;
	int CountTCPClientTimingEnd_Waiting;
	int CountTCPClientTimingEnd_Triggered;

	int SENDTCPClientTimingEnd;
	int RECVTCPClientTimingEnd;
	struct sockaddr_in SENDAddrToTCPClientTimingEnd;
	struct sockaddr_in RECVAddrToTCPClientTimingEnd;

	int CountTCPClientTimingRespond_Triggering;
	int CountTCPClientTimingRespond_Waiting;
	int CountTCPClientTimingRespond_Triggered;

	int SENDTCPClientTimingRespond;
	int RECVTCPClientTimingRespond;
	struct sockaddr_in SENDAddrToTCPClientTimingRespond;
	struct sockaddr_in RECVAddrToTCPClientTimingRespond;

	int CountTCPClientBufReady_Triggering;
	int CountTCPClientBufReady_Waiting;
	int CountTCPClientBufReady_Triggered;

	int SENDTCPClientBufReady;
	int RECVTCPClientBufReady;
	struct sockaddr_in SENDAddrToTCPClientBufReady;
	struct sockaddr_in RECVAddrToTCPClientBufReady;

	int CountTCPClientMoreData_Triggering;
	int CountTCPClientMoreData_Waiting;
	int CountTCPClientMoreData_Triggered;

	int SENDTCPClientMoreData;
	int RECVTCPClientMoreData;
	struct sockaddr_in SENDAddrToTCPClientMoreData;
	struct sockaddr_in RECVAddrToTCPClientMoreData;

	int CountTCPClientWriteData_Triggering;
	int CountTCPClientWriteData_Waiting;
	int CountTCPClientWriteData_Triggered;

	int SENDTCPClientWriteData;
	int RECVTCPClientWriteData;
	struct sockaddr_in SENDAddrToTCPClientWriteData;
	struct sockaddr_in RECVAddrToTCPClientWriteData;

	int CountTCPClientFileClose_Triggering;
	int CountTCPClientFileClose_Waiting;
	int CountTCPClientFileClose_Triggered;

	int SENDTCPClientFileClose;
	int RECVTCPClientFileClose;
	struct sockaddr_in SENDAddrToTCPClientFileClose;
	struct sockaddr_in RECVAddrToTCPClientFileClose;

	int CountTCPClientStartOrder1_Triggering;
	int CountTCPClientStartOrder1_Waiting;
	int CountTCPClientStartOrder1_Triggered;

	int SENDTCPClientStartOrder1;
	int RECVTCPClientStartOrder1;
	struct sockaddr_in SENDAddrToTCPClientStartOrder1;
	struct sockaddr_in RECVAddrToTCPClientStartOrder1;

	int CountTCPClientStartOrder2_Triggering;
	int CountTCPClientStartOrder2_Waiting;
	int CountTCPClientStartOrder2_Triggered;

	int SENDTCPClientStartOrder2;
	int RECVTCPClientStartOrder2;
	struct sockaddr_in SENDAddrToTCPClientStartOrder2;
	struct sockaddr_in RECVAddrToTCPClientStartOrder2;

	int CountTCPClientStartOrder3_Triggering;
	int CountTCPClientStartOrder3_Waiting;
	int CountTCPClientStartOrder3_Triggered;

	int SENDTCPClientStartOrder3;
	int RECVTCPClientStartOrder3;
	struct sockaddr_in SENDAddrToTCPClientStartOrder3;
	struct sockaddr_in RECVAddrToTCPClientStartOrder3;

	int CountTCPClientStartOrder4_Triggering;
	int CountTCPClientStartOrder4_Waiting;
	int CountTCPClientStartOrder4_Triggered;

	int SENDTCPClientStartOrder4;
	int RECVTCPClientStartOrder4;
	struct sockaddr_in SENDAddrToTCPClientStartOrder4;
	struct sockaddr_in RECVAddrToTCPClientStartOrder4;
};
struct TCPCliPara TCPCliParaList;

/*

	sendto(SENDTCPClientTimingBegin,"",0,0,(struct sockaddr *)&AddrToTCPClientTimingBegin,sizeof(AddrToTCPClientTimingBegin));
	recvfrom(RECVTCPClientTimingBegin,Trigger,20,0,(struct sockaddr *)&AddrToTCPClientTimingBegin,&SockAddrLength);

	sendto(SENDTCPClientTimingEnd,"",0,0,(struct sockaddr *)&AddrToTCPClientTimingEnd,sizeof(AddrToTCPClientTimingEnd));
	recvfrom(RECVTCPClientTimingEnd,Trigger,20,0,(struct sockaddr *)&AddrToTCPClientTimingEnd,&SockAddrLength);

	sendto(SENDTCPClientTimingRespond,"",0,0,(struct sockaddr *)&AddrToTCPClientTimingRespond,sizeof(AddrToTCPClientTimingRespond));
	recvfrom(RECVTCPClientTimingRespond,Trigger,20,0,(struct sockaddr *)&AddrToTCPClientTimingRespond,&SockAddrLength);

	sendto(SENDTCPClientBufReady,"",0,0,(struct sockaddr *)&AddrToTCPClientBufReady,sizeof(AddrToTCPClientBufReady));
	recvfrom(RECVTCPClientBufReady,Trigger,20,0,(struct sockaddr *)&AddrToTCPClientBufReady,&SockAddrLength);

	sendto(SENDTCPClientMoreData,"",0,0,(struct sockaddr *)&AddrToTCPClientMoreData,sizeof(AddrToTCPClientMoreData));
	recvfrom(RECVTCPClientMoreData,Trigger,20,0,(struct sockaddr *)&AddrToTCPClientMoreData,&SockAddrLength);

	sendto(SENDTCPClientWriteData,"",0,0,(struct sockaddr *)&AddrToTCPClientWriteData,sizeof(AddrToTCPClientWriteData));
	recvfrom(RECVTCPClientWriteData,Trigger,20,0,(struct sockaddr *)&AddrToTCPClientWriteData,&SockAddrLength);

	sendto(SENDTCPClientFileClose,"",0,0,(struct sockaddr *)&AddrToTCPClientFileClose,sizeof(AddrToTCPClientFileClose));
	recvfrom(RECVTCPClientFileClose,Trigger,20,0,(struct sockaddr *)&AddrToTCPClientFileClose,&SockAddrLength);

	sendto(SENDTCPClientStartOrder1,"",0,0,(struct sockaddr *)&AddrToTCPClientStartOrder1,sizeof(AddrToTCPClientStartOrder1));
	recvfrom(RECVTCPClientStartOrder1,Trigger,20,0,(struct sockaddr *)&AddrToTCPClientStartOrder1,&SockAddrLength);

	sendto(SENDTCPClientStartOrder2,"",0,0,(struct sockaddr *)&AddrToTCPClientStartOrder2,sizeof(AddrToTCPClientStartOrder2));
	recvfrom(RECVTCPClientStartOrder2,Trigger,20,0,(struct sockaddr *)&AddrToTCPClientStartOrder2,&SockAddrLength);

	sendto(SENDTCPClientStartOrder3,"",0,0,(struct sockaddr *)&AddrToTCPClientStartOrder3,sizeof(AddrToTCPClientStartOrder3));
	recvfrom(RECVTCPClientStartOrder3,Trigger,20,0,(struct sockaddr *)&AddrToTCPClientStartOrder3,&SockAddrLength);

	sendto(SENDTCPClientStartOrder4,"",0,0,(struct sockaddr *)&AddrToTCPClientStartOrder4,sizeof(AddrToTCPClientStartOrder4));
	recvfrom(RECVTCPClientStartOrder4,Trigger,20,0,(struct sockaddr *)&AddrToTCPClientStartOrder4,&SockAddrLength);

*/


/*******************************************************************************************************************************************
*******************************************初始化参数配置相关********************************************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：TCPClient_Parameterinit
* 功能描述：TCPClient模块全局变量赋初值
* 参数列表：
* 返回结果：
*****************************************/
void
TCPClient_Parameterinit();

/*******************************************************************************************************************************************
*******************************************应用层TCPClient服务器（通过CLI控制）**************************************************************
*******************************************************************************************************************************************/

/*******************************************************************************************************************************************
*******************************************上行通道 - From.数据请求端   To.应用服务器********************************************************
*******************************************************************************************************************************************/

/*******************************************************************************************************************************************
*******************************************下行通道 - From.应用服务器 To.数据请求端**********************************************************
*******************************************************************************************************************************************/

/*******************************************************************************************************************************************
**********************************************************多线程主干程序********************************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：TCPClient_thread_timer
* 功能描述：为各线程提供计时信号
* 参数列表：
* 返回结果：
*****************************************/
void *
TCPClient_thread_timer
(
	void * fd
);

/*****************************************
* 函数名称：TCPClient_thread_TCP
* 功能描述：上行通道 - TCP客户端任务控制主子线程
* 参数列表：
* 返回结果：
*****************************************/
void *
TCPClient_thread_TCP
(
	void * fd
);

/*****************************************
* 函数名称：TCPClient_thread_FTP
* 功能描述：读取文件线程（FTP前身），负责读取文件并维持发送缓冲的更新
* 参数列表：
* 返回结果：
*****************************************/
void *
TCPClient_thread_FTP
(
	void * fd
);

/*****************************************
* 函数名称：TCPClient_thread_NetworkLayertoTransportLayer
* 功能描述：上行通道 - From.数据请求端   To.应用服务器
* 参数列表：
* 返回结果：
*****************************************/
void *
TCPClient_thread_NetworkLayertoTransportLayer
(
	void * fd
);

/*****************************************
* 函数名称：TCPClient_thread_TransportLayertoNetworkLayer
* 功能描述：下行通道 - From.应用服务器 To.数据请求端
* 参数列表：
* 返回结果：
*****************************************/
void *
TCPClient_thread_TransportLayertoNetworkLayer
(
	void * fd
);

/*****************************************
* 函数名称：TCPClient_main
* 功能描述：TCPClient模块主函数，启动ForwardingPlane转发平面线程。自身主循环执行简单HTTP服务器功能。
* 参数列表：
eg: ./sub d1sub1 d1sub1-eth1
第二参数使用char**argv的方式声明报错，不知是不是语法问题
* 返回结果：
*****************************************/
int
TCPClient_main
(
	int argc,
	char argv[][30]
);

#endif
