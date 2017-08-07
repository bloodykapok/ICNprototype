/*******************************************************************************************************************************************
* 文件名：cnfclient.h
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
gcc cnfclient.c -o cnfclient -lpthread
4、运行（因涉及原始套接字的使用，须root权限）
sudo ./cnfclient
*/

#include"library.h"
#include"packet.h"
#include"basic.h"

#include"cnf.h"

/*******************************************************************************************************************************************
*************************************宏定义配置数据************全局变量定义******************************************************************
*******************************************************************************************************************************************/
#ifndef _CNFCLI_
#define _CNFCLI_

//软件状态，即是否需要输出各阶段运行的数据，输出多少：
//开发阶段 == 0
//测试阶段 == 1
//残包阶段 == 2
//微调阶段 == 3
//二次开发阶段 == 4
//部署阶段 == 5
//CNF测试 == 6
//CNF输出参数 == 7
#define cnfcliDEVETESTIMPL cnfDEVETESTIMPL

//是否输出AIMD机制的每一步触发提示
#define CNFclientTRIGGERTEST CNFTRIGGERTEST

#define CNFBUFSIZE       1000000    //CNF单任务发送缓冲大小（1MB）

//CNF任务线程控制参数组
//Tip.信号量的声明不能处在奇地址上，在结构体中，多个变量的存储采用字节对齐的方式，才会存在奇地址的问题
struct CNFCliPara
{
	//内部线程触发用SEM通信变量
	sem_t semCNFClientTimingBegin;
	sem_t semCNFClientTimingEnd;
	sem_t semCNFClientTimingRespond;
	sem_t semCNFClientBufReady;
	sem_t semCNFClientMoreData;//无用
	sem_t semCNFClientWriteData;
	sem_t semCNFClientFileClose;//无用
	sem_t semCNFClientStartOrder1;
	sem_t semCNFClientStartOrder2;
	sem_t semCNFClientStartOrder3;
	sem_t semCNFClientStartOrder4;
/*
	if(cnfINTRACOMMUNICATION == 0)
	{
		
	}
	else if(cnfINTRACOMMUNICATION == 1)
	{
		sem_post(&semCNFClientStartOrder);
	}
*/


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

	//CNF任务线程组句柄	
	pthread_t pthread_timer;
	pthread_t pthread_CNF;
	pthread_t pthread_FTP;
	pthread_t pthread_NetworkLayertoTransportLayer;
	pthread_t pthread_TransportLayertoNetworkLayer;

	//对外收发接口用UDP通信变量
	int SENDCNFClientACK;
	struct sockaddr_in SENDAddrToCNFClientACK;
	int RECVCNFClientSEG;
	struct sockaddr_in RECVAddrToCNFClientSEG;

	//内部线程触发用UDP通信变量
	int CountCNFClientTimingBegin_Triggering;
	int CountCNFClientTimingBegin_Waiting;
	int CountCNFClientTimingBegin_Triggered;

	int SENDCNFClientTimingBegin;
	int RECVCNFClientTimingBegin;
	struct sockaddr_in SENDAddrToCNFClientTimingBegin;
	struct sockaddr_in RECVAddrToCNFClientTimingBegin;

	int CountCNFClientTimingEnd_Triggering;
	int CountCNFClientTimingEnd_Waiting;
	int CountCNFClientTimingEnd_Triggered;

	int SENDCNFClientTimingEnd;
	int RECVCNFClientTimingEnd;
	struct sockaddr_in SENDAddrToCNFClientTimingEnd;
	struct sockaddr_in RECVAddrToCNFClientTimingEnd;

	int CountCNFClientTimingRespond_Triggering;
	int CountCNFClientTimingRespond_Waiting;
	int CountCNFClientTimingRespond_Triggered;

	int SENDCNFClientTimingRespond;
	int RECVCNFClientTimingRespond;
	struct sockaddr_in SENDAddrToCNFClientTimingRespond;
	struct sockaddr_in RECVAddrToCNFClientTimingRespond;

	int CountCNFClientBufReady_Triggering;
	int CountCNFClientBufReady_Waiting;
	int CountCNFClientBufReady_Triggered;

	int SENDCNFClientBufReady;
	int RECVCNFClientBufReady;
	struct sockaddr_in SENDAddrToCNFClientBufReady;
	struct sockaddr_in RECVAddrToCNFClientBufReady;

	int CountCNFClientMoreData_Triggering;
	int CountCNFClientMoreData_Waiting;
	int CountCNFClientMoreData_Triggered;

	int SENDCNFClientMoreData;
	int RECVCNFClientMoreData;
	struct sockaddr_in SENDAddrToCNFClientMoreData;
	struct sockaddr_in RECVAddrToCNFClientMoreData;

	int CountCNFClientWriteData_Triggering;
	int CountCNFClientWriteData_Waiting;
	int CountCNFClientWriteData_Triggered;

	int SENDCNFClientWriteData;
	int RECVCNFClientWriteData;
	struct sockaddr_in SENDAddrToCNFClientWriteData;
	struct sockaddr_in RECVAddrToCNFClientWriteData;

	int CountCNFClientFileClose_Triggering;
	int CountCNFClientFileClose_Waiting;
	int CountCNFClientFileClose_Triggered;

	int SENDCNFClientFileClose;
	int RECVCNFClientFileClose;
	struct sockaddr_in SENDAddrToCNFClientFileClose;
	struct sockaddr_in RECVAddrToCNFClientFileClose;

	int CountCNFClientStartOrder1_Triggering;
	int CountCNFClientStartOrder1_Waiting;
	int CountCNFClientStartOrder1_Triggered;

	int SENDCNFClientStartOrder1;
	int RECVCNFClientStartOrder1;
	struct sockaddr_in SENDAddrToCNFClientStartOrder1;
	struct sockaddr_in RECVAddrToCNFClientStartOrder1;

	int CountCNFClientStartOrder2_Triggering;
	int CountCNFClientStartOrder2_Waiting;
	int CountCNFClientStartOrder2_Triggered;

	int SENDCNFClientStartOrder2;
	int RECVCNFClientStartOrder2;
	struct sockaddr_in SENDAddrToCNFClientStartOrder2;
	struct sockaddr_in RECVAddrToCNFClientStartOrder2;

	int CountCNFClientStartOrder3_Triggering;
	int CountCNFClientStartOrder3_Waiting;
	int CountCNFClientStartOrder3_Triggered;

	int SENDCNFClientStartOrder3;
	int RECVCNFClientStartOrder3;
	struct sockaddr_in SENDAddrToCNFClientStartOrder3;
	struct sockaddr_in RECVAddrToCNFClientStartOrder3;

	int CountCNFClientStartOrder4_Triggering;
	int CountCNFClientStartOrder4_Waiting;
	int CountCNFClientStartOrder4_Triggered;

	int SENDCNFClientStartOrder4;
	int RECVCNFClientStartOrder4;
	struct sockaddr_in SENDAddrToCNFClientStartOrder4;
	struct sockaddr_in RECVAddrToCNFClientStartOrder4;
};
struct CNFCliPara CNFCliParaList[THREADNUM];

/*

	sendto(SENDCNFClientTimingBegin,"",0,0,(struct sockaddr *)&AddrToCNFClientTimingBegin,sizeof(AddrToCNFClientTimingBegin));
	recvfrom(RECVCNFClientTimingBegin,Trigger,20,0,(struct sockaddr *)&AddrToCNFClientTimingBegin,&SockAddrLength);

	sendto(SENDCNFClientTimingEnd,"",0,0,(struct sockaddr *)&AddrToCNFClientTimingEnd,sizeof(AddrToCNFClientTimingEnd));
	recvfrom(RECVCNFClientTimingEnd,Trigger,20,0,(struct sockaddr *)&AddrToCNFClientTimingEnd,&SockAddrLength);

	sendto(SENDCNFClientTimingRespond,"",0,0,(struct sockaddr *)&AddrToCNFClientTimingRespond,sizeof(AddrToCNFClientTimingRespond));
	recvfrom(RECVCNFClientTimingRespond,Trigger,20,0,(struct sockaddr *)&AddrToCNFClientTimingRespond,&SockAddrLength);

	sendto(SENDCNFClientBufReady,"",0,0,(struct sockaddr *)&AddrToCNFClientBufReady,sizeof(AddrToCNFClientBufReady));
	recvfrom(RECVCNFClientBufReady,Trigger,20,0,(struct sockaddr *)&AddrToCNFClientBufReady,&SockAddrLength);

	sendto(SENDCNFClientMoreData,"",0,0,(struct sockaddr *)&AddrToCNFClientMoreData,sizeof(AddrToCNFClientMoreData));
	recvfrom(RECVCNFClientMoreData,Trigger,20,0,(struct sockaddr *)&AddrToCNFClientMoreData,&SockAddrLength);

	sendto(SENDCNFClientWriteData,"",0,0,(struct sockaddr *)&AddrToCNFClientWriteData,sizeof(AddrToCNFClientWriteData));
	recvfrom(RECVCNFClientWriteData,Trigger,20,0,(struct sockaddr *)&AddrToCNFClientWriteData,&SockAddrLength);

	sendto(SENDCNFClientFileClose,"",0,0,(struct sockaddr *)&AddrToCNFClientFileClose,sizeof(AddrToCNFClientFileClose));
	recvfrom(RECVCNFClientFileClose,Trigger,20,0,(struct sockaddr *)&AddrToCNFClientFileClose,&SockAddrLength);

	sendto(SENDCNFClientStartOrder1,"",0,0,(struct sockaddr *)&AddrToCNFClientStartOrder1,sizeof(AddrToCNFClientStartOrder1));
	recvfrom(RECVCNFClientStartOrder1,Trigger,20,0,(struct sockaddr *)&AddrToCNFClientStartOrder1,&SockAddrLength);

	sendto(SENDCNFClientStartOrder2,"",0,0,(struct sockaddr *)&AddrToCNFClientStartOrder2,sizeof(AddrToCNFClientStartOrder2));
	recvfrom(RECVCNFClientStartOrder2,Trigger,20,0,(struct sockaddr *)&AddrToCNFClientStartOrder2,&SockAddrLength);

	sendto(SENDCNFClientStartOrder3,"",0,0,(struct sockaddr *)&AddrToCNFClientStartOrder3,sizeof(AddrToCNFClientStartOrder3));
	recvfrom(RECVCNFClientStartOrder3,Trigger,20,0,(struct sockaddr *)&AddrToCNFClientStartOrder3,&SockAddrLength);

	sendto(SENDCNFClientStartOrder4,"",0,0,(struct sockaddr *)&AddrToCNFClientStartOrder4,sizeof(AddrToCNFClientStartOrder4));
	recvfrom(RECVCNFClientStartOrder4,Trigger,20,0,(struct sockaddr *)&AddrToCNFClientStartOrder4,&SockAddrLength);

*/

/*******************************************************************************************************************************************
*******************************************初始化参数配置相关********************************************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：CNFClient_Parameterinit
* 功能描述：CNFClient模块全局变量赋初值
* 参数列表：
* 返回结果：
*****************************************/
void
CNFClient_Parameterinit
(
	int threadnum
);

/*******************************************************************************************************************************************
*******************************************应用层CNFClient服务器（通过CLI控制）**************************************************************
*******************************************************************************************************************************************/

/*******************************************************************************************************************************************
*******************************************上行通道 - From.数据请求端   To.应用服务器********************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：CNFClient_UDP_SendData
* 功能描述：向上层转发平面发送UDP封装的DATA包内容/同时终止该CNF整个任务并回收的所有资源
* 参数列表：
* 返回结果：
*****************************************/
void
CNFClient_UDP_SendData
(
	int threadnum
);

/*****************************************
* 函数名称：CNFClient_SEM_SendData
* 功能描述：向上层转发平面发送UDP封装的DATA包内容/同时终止该CNF整个任务并回收的所有资源
* 参数列表：
* 返回结果：
*****************************************/
void
CNFClient_SEM_SendData
(
	int threadnum
);

/*******************************************************************************************************************************************
*******************************************下行通道 - From.应用服务器 To.数据请求端**********************************************************
*******************************************************************************************************************************************/

/*******************************************************************************************************************************************
**********************************************************多线程主干程序********************************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：CNFClient_thread_timer
* 功能描述：为各线程提供计时信号
* 参数列表：
* 返回结果：
*****************************************/
void *
CNFClient_thread_timer
(
	void * fd
);

/*****************************************
* 函数名称：CNFClient_thread_CNF
* 功能描述：上行通道 - CNF客户端任务控制主子线程
* 参数列表：
* 返回结果：
*****************************************/
void *
CNFClient_thread_CNF
(
	void * fd
);

/*****************************************
* 函数名称：CNFClient_thread_FTP
* 功能描述：读取文件线程（FTP前身），负责读取文件并维持发送缓冲的更新
* 参数列表：
* 返回结果：
*****************************************/
void *
CNFClient_thread_FTP
(
	void * fd
);

/*****************************************
* 函数名称：CNFClient_thread_NetworkLayertoTransportLayer
* 功能描述：上行通道 - From.数据请求端   To.应用服务器
* 参数列表：
* 返回结果：
*****************************************/
void *
CNFClient_thread_NetworkLayertoTransportLayer
(
	void * fd
);

/*****************************************
* 函数名称：CNFClient_thread_TransportLayertoNetworkLayer
* 功能描述：下行通道 - From.应用服务器 To.数据请求端
* 参数列表：
* 返回结果：
*****************************************/
void *
CNFClient_thread_TransportLayertoNetworkLayer
(
	void * fd
);

/*****************************************
* 函数名称：CNFClient_main
* 功能描述：CNFClient模块主函数，启动ForwardingPlane转发平面线程。自身主循环执行简单HTTP服务器功能。

* 参数列表：
eg: ./sub d1sub1 d1sub1-eth1
第二参数使用char**argv的方式声明报错，不知是不是语法问题
* 返回结果：

*****************************************/
int
CNFClient_main
(
	void * fd
);

/*****************************************
* 函数名称：CNFClientStart_main
* 功能描述：CNFClient总起函数，启动CNFClient的TCP传输模块，和下层Subscriber协议栈模块
* 参数列表：
第二参数使用char**argv的方式声明报错，不知是不是语法问题
* 返回结果：
*****************************************/
int
CNFClientStart_main
(
	int argc,
	char argv[][30]
);

#endif
