/*******************************************************************************************************************************************
* 文件名：cnfclient.c
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

#include"cnfclient.h"

/*******************************************************************************************************************************************
*************************************宏定义配置数据************全局变量定义******************************************************************
*******************************************************************************************************************************************/

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
)
{
	//
	int i;
	for(i=0;i<CACHENUM;i++)
	{
		CacheList[i].cachetop = 0;
	}
	

	SockAddrLength = sizeof(struct sockaddr_in);

	//ACK发送socket
	bzero(&CNFCliParaList[threadnum].SENDAddrToCNFClientACK,SockAddrLength);
	CNFCliParaList[threadnum].SENDAddrToCNFClientACK.sin_family=AF_INET;
	CNFCliParaList[threadnum].SENDAddrToCNFClientACK.sin_addr.s_addr=inet_addr(CNFThreadList[threadnum].physicalportIP);
	CNFCliParaList[threadnum].SENDAddrToCNFClientACK.sin_port=htons(PhysicalportInterPORT);

	CNFCliParaList[threadnum].SENDCNFClientACK = socket(AF_INET,SOCK_DGRAM,0);

	//SEG监听socket
	bzero(&CNFCliParaList[threadnum].RECVAddrToCNFClientSEG,SockAddrLength);
	CNFCliParaList[threadnum].RECVAddrToCNFClientSEG.sin_family=AF_INET;
	CNFCliParaList[threadnum].RECVAddrToCNFClientSEG.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFCliParaList[threadnum].RECVAddrToCNFClientSEG.sin_port=htons(PhysicalportInterPORT + threadnum * CNFPORTRANGE);

	CNFCliParaList[threadnum].RECVCNFClientSEG = socket(AF_INET,SOCK_DGRAM,0);

	bind(CNFCliParaList[threadnum].RECVCNFClientSEG,(struct sockaddr *)&CNFCliParaList[threadnum].RECVAddrToCNFClientSEG,SockAddrLength);
	
	//计时开始
	CNFCliParaList[threadnum].CountCNFClientTimingBegin_Triggering = 1;
	CNFCliParaList[threadnum].CountCNFClientTimingBegin_Waiting = 1;
	CNFCliParaList[threadnum].CountCNFClientTimingBegin_Triggered = 1;

	bzero(&CNFCliParaList[threadnum].SENDAddrToCNFClientTimingBegin,SockAddrLength);
	CNFCliParaList[threadnum].SENDAddrToCNFClientTimingBegin.sin_family=AF_INET;
	CNFCliParaList[threadnum].SENDAddrToCNFClientTimingBegin.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFCliParaList[threadnum].SENDAddrToCNFClientTimingBegin.sin_port=htons(CNFClientTimingBegin + threadnum * CNFPORTRANGE);

	bzero(&CNFCliParaList[threadnum].RECVAddrToCNFClientTimingBegin,SockAddrLength);
	CNFCliParaList[threadnum].RECVAddrToCNFClientTimingBegin.sin_family=AF_INET;
	CNFCliParaList[threadnum].RECVAddrToCNFClientTimingBegin.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFCliParaList[threadnum].RECVAddrToCNFClientTimingBegin.sin_port=htons(CNFClientTimingBegin + threadnum * CNFPORTRANGE);

	CNFCliParaList[threadnum].SENDCNFClientTimingBegin = socket(AF_INET,SOCK_DGRAM,0);
	CNFCliParaList[threadnum].RECVCNFClientTimingBegin = socket(AF_INET,SOCK_DGRAM,0);

	bind(CNFCliParaList[threadnum].RECVCNFClientTimingBegin,(struct sockaddr *)&CNFCliParaList[threadnum].RECVAddrToCNFClientTimingBegin,SockAddrLength);

	//计时结束
	CNFCliParaList[threadnum].CountCNFClientTimingEnd_Triggering = 1;
	CNFCliParaList[threadnum].CountCNFClientTimingEnd_Waiting = 1;
	CNFCliParaList[threadnum].CountCNFClientTimingEnd_Triggered = 1;

	bzero(&CNFCliParaList[threadnum].SENDAddrToCNFClientTimingEnd,SockAddrLength);
	CNFCliParaList[threadnum].SENDAddrToCNFClientTimingEnd.sin_family=AF_INET;
	CNFCliParaList[threadnum].SENDAddrToCNFClientTimingEnd.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFCliParaList[threadnum].SENDAddrToCNFClientTimingEnd.sin_port=htons(CNFClientTimingEnd + threadnum * CNFPORTRANGE);

	bzero(&CNFCliParaList[threadnum].RECVAddrToCNFClientTimingEnd,SockAddrLength);
	CNFCliParaList[threadnum].RECVAddrToCNFClientTimingEnd.sin_family=AF_INET;
	CNFCliParaList[threadnum].RECVAddrToCNFClientTimingEnd.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFCliParaList[threadnum].RECVAddrToCNFClientTimingEnd.sin_port=htons(CNFClientTimingEnd + threadnum * CNFPORTRANGE);

	CNFCliParaList[threadnum].SENDCNFClientTimingEnd = socket(AF_INET,SOCK_DGRAM,0);
	CNFCliParaList[threadnum].RECVCNFClientTimingEnd = socket(AF_INET,SOCK_DGRAM,0);

	bind(CNFCliParaList[threadnum].RECVCNFClientTimingEnd,(struct sockaddr *)&CNFCliParaList[threadnum].RECVAddrToCNFClientTimingEnd,SockAddrLength);

	//反馈计时结果
	CNFCliParaList[threadnum].CountCNFClientTimingRespond_Triggering = 1;
	CNFCliParaList[threadnum].CountCNFClientTimingRespond_Waiting = 1;
	CNFCliParaList[threadnum].CountCNFClientTimingRespond_Triggered = 1;

	bzero(&CNFCliParaList[threadnum].SENDAddrToCNFClientTimingRespond,SockAddrLength);
	CNFCliParaList[threadnum].SENDAddrToCNFClientTimingRespond.sin_family=AF_INET;
	CNFCliParaList[threadnum].SENDAddrToCNFClientTimingRespond.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFCliParaList[threadnum].SENDAddrToCNFClientTimingRespond.sin_port=htons(CNFClientTimingRespond + threadnum * CNFPORTRANGE);

	bzero(&CNFCliParaList[threadnum].RECVAddrToCNFClientTimingRespond,SockAddrLength);
	CNFCliParaList[threadnum].RECVAddrToCNFClientTimingRespond.sin_family=AF_INET;
	CNFCliParaList[threadnum].RECVAddrToCNFClientTimingRespond.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFCliParaList[threadnum].RECVAddrToCNFClientTimingRespond.sin_port=htons(CNFClientTimingRespond + threadnum * CNFPORTRANGE);

	CNFCliParaList[threadnum].SENDCNFClientTimingRespond = socket(AF_INET,SOCK_DGRAM,0);
	CNFCliParaList[threadnum].RECVCNFClientTimingRespond = socket(AF_INET,SOCK_DGRAM,0);

	bind(CNFCliParaList[threadnum].RECVCNFClientTimingRespond,(struct sockaddr *)&CNFCliParaList[threadnum].RECVAddrToCNFClientTimingRespond,SockAddrLength);

	//接收缓冲启动
	CNFCliParaList[threadnum].CountCNFClientBufReady_Triggering = 1;
	CNFCliParaList[threadnum].CountCNFClientBufReady_Waiting = 1;
	CNFCliParaList[threadnum].CountCNFClientBufReady_Triggered = 1;

	bzero(&CNFCliParaList[threadnum].SENDAddrToCNFClientBufReady,SockAddrLength);
	CNFCliParaList[threadnum].SENDAddrToCNFClientBufReady.sin_family=AF_INET;
	CNFCliParaList[threadnum].SENDAddrToCNFClientBufReady.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFCliParaList[threadnum].SENDAddrToCNFClientBufReady.sin_port=htons(CNFClientBufReady + threadnum * CNFPORTRANGE);

	bzero(&CNFCliParaList[threadnum].RECVAddrToCNFClientBufReady,SockAddrLength);
	CNFCliParaList[threadnum].RECVAddrToCNFClientBufReady.sin_family=AF_INET;
	CNFCliParaList[threadnum].RECVAddrToCNFClientBufReady.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFCliParaList[threadnum].RECVAddrToCNFClientBufReady.sin_port=htons(CNFClientBufReady + threadnum * CNFPORTRANGE);

	CNFCliParaList[threadnum].SENDCNFClientBufReady = socket(AF_INET,SOCK_DGRAM,0);
	CNFCliParaList[threadnum].RECVCNFClientBufReady = socket(AF_INET,SOCK_DGRAM,0);

	bind(CNFCliParaList[threadnum].RECVCNFClientBufReady,(struct sockaddr *)&CNFCliParaList[threadnum].RECVAddrToCNFClientBufReady,SockAddrLength);

	//接收后续数据
	CNFCliParaList[threadnum].CountCNFClientMoreData_Triggering = 1;
	CNFCliParaList[threadnum].CountCNFClientMoreData_Waiting = 1;
	CNFCliParaList[threadnum].CountCNFClientMoreData_Triggered = 1;
	
	bzero(&CNFCliParaList[threadnum].SENDAddrToCNFClientMoreData,SockAddrLength);
	CNFCliParaList[threadnum].SENDAddrToCNFClientMoreData.sin_family=AF_INET;
	CNFCliParaList[threadnum].SENDAddrToCNFClientMoreData.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFCliParaList[threadnum].SENDAddrToCNFClientMoreData.sin_port=htons(CNFClientMoreData + threadnum * CNFPORTRANGE);

	bzero(&CNFCliParaList[threadnum].RECVAddrToCNFClientMoreData,SockAddrLength);
	CNFCliParaList[threadnum].RECVAddrToCNFClientMoreData.sin_family=AF_INET;
	CNFCliParaList[threadnum].RECVAddrToCNFClientMoreData.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFCliParaList[threadnum].RECVAddrToCNFClientMoreData.sin_port=htons(CNFClientMoreData + threadnum * CNFPORTRANGE);

	CNFCliParaList[threadnum].SENDCNFClientMoreData = socket(AF_INET,SOCK_DGRAM,0);
	CNFCliParaList[threadnum].RECVCNFClientMoreData = socket(AF_INET,SOCK_DGRAM,0);

	bind(CNFCliParaList[threadnum].RECVCNFClientMoreData,(struct sockaddr *)&CNFCliParaList[threadnum].RECVAddrToCNFClientMoreData,SockAddrLength);

	//通知将数据写入缓冲
	CNFCliParaList[threadnum].CountCNFClientWriteData_Triggering = 1;
	CNFCliParaList[threadnum].CountCNFClientWriteData_Waiting = 1;
	CNFCliParaList[threadnum].CountCNFClientWriteData_Triggered = 1;

	bzero(&CNFCliParaList[threadnum].SENDAddrToCNFClientWriteData,SockAddrLength);
	CNFCliParaList[threadnum].SENDAddrToCNFClientWriteData.sin_family=AF_INET;
	CNFCliParaList[threadnum].SENDAddrToCNFClientWriteData.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFCliParaList[threadnum].SENDAddrToCNFClientWriteData.sin_port=htons(CNFClientWriteData + threadnum * CNFPORTRANGE);

	bzero(&CNFCliParaList[threadnum].RECVAddrToCNFClientWriteData,SockAddrLength);
	CNFCliParaList[threadnum].RECVAddrToCNFClientWriteData.sin_family=AF_INET;
	CNFCliParaList[threadnum].RECVAddrToCNFClientWriteData.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFCliParaList[threadnum].RECVAddrToCNFClientWriteData.sin_port=htons(CNFClientWriteData + threadnum * CNFPORTRANGE);

	CNFCliParaList[threadnum].SENDCNFClientWriteData = socket(AF_INET,SOCK_DGRAM,0);
	CNFCliParaList[threadnum].RECVCNFClientWriteData = socket(AF_INET,SOCK_DGRAM,0);

	bind(CNFCliParaList[threadnum].RECVCNFClientWriteData,(struct sockaddr *)&CNFCliParaList[threadnum].RECVAddrToCNFClientWriteData,SockAddrLength);

	//文件写入结束
	CNFCliParaList[threadnum].CountCNFClientFileClose_Triggering = 1;
	CNFCliParaList[threadnum].CountCNFClientFileClose_Waiting = 1;
	CNFCliParaList[threadnum].CountCNFClientFileClose_Triggered = 1;

	bzero(&CNFCliParaList[threadnum].SENDAddrToCNFClientFileClose,SockAddrLength);
	CNFCliParaList[threadnum].SENDAddrToCNFClientFileClose.sin_family=AF_INET;
	CNFCliParaList[threadnum].SENDAddrToCNFClientFileClose.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFCliParaList[threadnum].SENDAddrToCNFClientFileClose.sin_port=htons(CNFClientFileClose + threadnum * CNFPORTRANGE);

	bzero(&CNFCliParaList[threadnum].RECVAddrToCNFClientFileClose,SockAddrLength);
	CNFCliParaList[threadnum].RECVAddrToCNFClientFileClose.sin_family=AF_INET;
	CNFCliParaList[threadnum].RECVAddrToCNFClientFileClose.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFCliParaList[threadnum].RECVAddrToCNFClientFileClose.sin_port=htons(CNFClientFileClose + threadnum * CNFPORTRANGE);

	CNFCliParaList[threadnum].SENDCNFClientFileClose = socket(AF_INET,SOCK_DGRAM,0);
	CNFCliParaList[threadnum].RECVCNFClientFileClose = socket(AF_INET,SOCK_DGRAM,0);

	bind(CNFCliParaList[threadnum].RECVCNFClientFileClose,(struct sockaddr *)&CNFCliParaList[threadnum].RECVAddrToCNFClientFileClose,SockAddrLength);

	//启动顺序1
	CNFCliParaList[threadnum].CountCNFClientStartOrder1_Triggering = 1;
	CNFCliParaList[threadnum].CountCNFClientStartOrder1_Waiting = 1;
	CNFCliParaList[threadnum].CountCNFClientStartOrder1_Triggered = 1;
	
	bzero(&CNFCliParaList[threadnum].SENDAddrToCNFClientStartOrder1,SockAddrLength);
	CNFCliParaList[threadnum].SENDAddrToCNFClientStartOrder1.sin_family=AF_INET;
	CNFCliParaList[threadnum].SENDAddrToCNFClientStartOrder1.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFCliParaList[threadnum].SENDAddrToCNFClientStartOrder1.sin_port=htons(CNFClientStartOrder1 + threadnum * CNFPORTRANGE);

	bzero(&CNFCliParaList[threadnum].RECVAddrToCNFClientStartOrder1,SockAddrLength);
	CNFCliParaList[threadnum].RECVAddrToCNFClientStartOrder1.sin_family=AF_INET;
	CNFCliParaList[threadnum].RECVAddrToCNFClientStartOrder1.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFCliParaList[threadnum].RECVAddrToCNFClientStartOrder1.sin_port=htons(CNFClientStartOrder1 + threadnum * CNFPORTRANGE);

	CNFCliParaList[threadnum].SENDCNFClientStartOrder1 = socket(AF_INET,SOCK_DGRAM,0);
	CNFCliParaList[threadnum].RECVCNFClientStartOrder1 = socket(AF_INET,SOCK_DGRAM,0);

	bind(CNFCliParaList[threadnum].RECVCNFClientStartOrder1,(struct sockaddr *)&CNFCliParaList[threadnum].RECVAddrToCNFClientStartOrder1,SockAddrLength);

	//启动顺序2
	CNFCliParaList[threadnum].CountCNFClientStartOrder2_Triggering = 1;
	CNFCliParaList[threadnum].CountCNFClientStartOrder2_Waiting = 1;
	CNFCliParaList[threadnum].CountCNFClientStartOrder2_Triggered = 1;
	
	bzero(&CNFCliParaList[threadnum].SENDAddrToCNFClientStartOrder2,SockAddrLength);
	CNFCliParaList[threadnum].SENDAddrToCNFClientStartOrder2.sin_family=AF_INET;
	CNFCliParaList[threadnum].SENDAddrToCNFClientStartOrder2.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFCliParaList[threadnum].SENDAddrToCNFClientStartOrder2.sin_port=htons(CNFClientStartOrder2 + threadnum * CNFPORTRANGE);

	bzero(&CNFCliParaList[threadnum].RECVAddrToCNFClientStartOrder2,SockAddrLength);
	CNFCliParaList[threadnum].RECVAddrToCNFClientStartOrder2.sin_family=AF_INET;
	CNFCliParaList[threadnum].RECVAddrToCNFClientStartOrder2.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFCliParaList[threadnum].RECVAddrToCNFClientStartOrder2.sin_port=htons(CNFClientStartOrder2 + threadnum * CNFPORTRANGE);

	CNFCliParaList[threadnum].SENDCNFClientStartOrder2 = socket(AF_INET,SOCK_DGRAM,0);
	CNFCliParaList[threadnum].RECVCNFClientStartOrder2 = socket(AF_INET,SOCK_DGRAM,0);

	bind(CNFCliParaList[threadnum].RECVCNFClientStartOrder2,(struct sockaddr *)&CNFCliParaList[threadnum].RECVAddrToCNFClientStartOrder2,SockAddrLength);

	//启动顺序3
	CNFCliParaList[threadnum].CountCNFClientStartOrder3_Triggering = 1;
	CNFCliParaList[threadnum].CountCNFClientStartOrder3_Waiting = 1;
	CNFCliParaList[threadnum].CountCNFClientStartOrder3_Triggered = 1;
	
	bzero(&CNFCliParaList[threadnum].SENDAddrToCNFClientStartOrder3,SockAddrLength);
	CNFCliParaList[threadnum].SENDAddrToCNFClientStartOrder3.sin_family=AF_INET;
	CNFCliParaList[threadnum].SENDAddrToCNFClientStartOrder3.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFCliParaList[threadnum].SENDAddrToCNFClientStartOrder3.sin_port=htons(CNFClientStartOrder3 + threadnum * CNFPORTRANGE);

	bzero(&CNFCliParaList[threadnum].RECVAddrToCNFClientStartOrder3,SockAddrLength);
	CNFCliParaList[threadnum].RECVAddrToCNFClientStartOrder3.sin_family=AF_INET;
	CNFCliParaList[threadnum].RECVAddrToCNFClientStartOrder3.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFCliParaList[threadnum].RECVAddrToCNFClientStartOrder3.sin_port=htons(CNFClientStartOrder3 + threadnum * CNFPORTRANGE);

	CNFCliParaList[threadnum].SENDCNFClientStartOrder3 = socket(AF_INET,SOCK_DGRAM,0);
	CNFCliParaList[threadnum].RECVCNFClientStartOrder3 = socket(AF_INET,SOCK_DGRAM,0);

	bind(CNFCliParaList[threadnum].RECVCNFClientStartOrder3,(struct sockaddr *)&CNFCliParaList[threadnum].RECVAddrToCNFClientStartOrder3,SockAddrLength);

	//启动顺序4
	CNFCliParaList[threadnum].CountCNFClientStartOrder4_Triggering = 1;
	CNFCliParaList[threadnum].CountCNFClientStartOrder4_Waiting = 1;
	CNFCliParaList[threadnum].CountCNFClientStartOrder4_Triggered = 1;
	
	bzero(&CNFCliParaList[threadnum].SENDAddrToCNFClientStartOrder4,SockAddrLength);
	CNFCliParaList[threadnum].SENDAddrToCNFClientStartOrder4.sin_family=AF_INET;
	CNFCliParaList[threadnum].SENDAddrToCNFClientStartOrder4.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFCliParaList[threadnum].SENDAddrToCNFClientStartOrder4.sin_port=htons(CNFClientStartOrder4 + threadnum * CNFPORTRANGE);

	bzero(&CNFCliParaList[threadnum].RECVAddrToCNFClientStartOrder4,SockAddrLength);
	CNFCliParaList[threadnum].RECVAddrToCNFClientStartOrder4.sin_family=AF_INET;
	CNFCliParaList[threadnum].RECVAddrToCNFClientStartOrder4.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFCliParaList[threadnum].RECVAddrToCNFClientStartOrder4.sin_port=htons(CNFClientStartOrder4 + threadnum * CNFPORTRANGE);

	CNFCliParaList[threadnum].SENDCNFClientStartOrder4 = socket(AF_INET,SOCK_DGRAM,0);
	CNFCliParaList[threadnum].RECVCNFClientStartOrder4 = socket(AF_INET,SOCK_DGRAM,0);

	bind(CNFCliParaList[threadnum].RECVCNFClientStartOrder4,(struct sockaddr *)&CNFCliParaList[threadnum].RECVAddrToCNFClientStartOrder4,SockAddrLength);

}

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
)
{
	//根据CNF任务号提取DATA包缓存位置
	int DATALocation = CNFThreadList[threadnum].datapkglocation;
	
	//从DATA包缓存位置提取相关参数
	int pkglength = datapkglist[DATALocation].pkglength;
	uint8_t local_ip[16];
	memcpy(local_ip,datapkglist[DATALocation].local_ip,16);

	//UDP发包代码

	char pkg[BUFSIZE];
	
	int socket_sender;
	socket_sender=socket(AF_INET,SOCK_DGRAM,0);
	
	struct sockaddr_in addrFrom;
	bzero(&addrFrom,sizeof(addrFrom));
	addrFrom.sin_family=AF_INET;
	//addrFrom.sin_addr.s_addr=htonl(INADDR_ANY);
	addrFrom.sin_addr.s_addr=inet_addr(local_ip);
	addrFrom.sin_port=htons(0);

	int error = bind(socket_sender,(struct sockaddr *)&addrFrom,sizeof(addrFrom));
	if(error != 0)
	{
		printf("bind() error!\n");
	}

	memcpy(pkg,"NET",3);
	memcpy(pkg+3,datapkglist[DATALocation].datapkg+14,pkglength);
	
	struct sockaddr_in addrTo;
	bzero(&addrTo,sizeof(addrTo));
	addrTo.sin_family=AF_INET;
	addrTo.sin_port=htons(PhysicalportInterPORT);
	addrTo.sin_addr.s_addr=inet_addr("127.1.1.1");
	
	if(cnfcliDEVETESTIMPL <= 6)
	{
		//printf("[%s] UDP Message has been sent out:%s\n",datapkglist[DATALocation].physicalport,pkg);
		printf("[%s] UDP Message has been sent out.\n",datapkglist[DATALocation].physicalport);
		printf("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n\n");
	}

	sendto(socket_sender,pkg,pkglength+3,0,(struct sockaddr *)&addrTo,sizeof(addrTo));
	close(socket_sender);

	//释放该CNF任务所有内部通信句柄
	close(CNFCliParaList[threadnum].SENDCNFClientACK);
	close(CNFCliParaList[threadnum].RECVCNFClientSEG);
	close(CNFCliParaList[threadnum].SENDCNFClientTimingBegin);
	close(CNFCliParaList[threadnum].RECVCNFClientTimingBegin);
	close(CNFCliParaList[threadnum].SENDCNFClientTimingEnd);
	close(CNFCliParaList[threadnum].RECVCNFClientTimingEnd);
	close(CNFCliParaList[threadnum].SENDCNFClientTimingRespond);
	close(CNFCliParaList[threadnum].RECVCNFClientTimingRespond);
	close(CNFCliParaList[threadnum].SENDCNFClientBufReady);
	close(CNFCliParaList[threadnum].RECVCNFClientBufReady);
	close(CNFCliParaList[threadnum].SENDCNFClientMoreData);
	close(CNFCliParaList[threadnum].RECVCNFClientMoreData);
	close(CNFCliParaList[threadnum].SENDCNFClientWriteData);
	close(CNFCliParaList[threadnum].RECVCNFClientWriteData);
	close(CNFCliParaList[threadnum].SENDCNFClientFileClose);
	close(CNFCliParaList[threadnum].RECVCNFClientFileClose);
	close(CNFCliParaList[threadnum].SENDCNFClientStartOrder1);
	close(CNFCliParaList[threadnum].RECVCNFClientStartOrder1);
	close(CNFCliParaList[threadnum].SENDCNFClientStartOrder2);
	close(CNFCliParaList[threadnum].RECVCNFClientStartOrder2);
	close(CNFCliParaList[threadnum].SENDCNFClientStartOrder3);
	close(CNFCliParaList[threadnum].RECVCNFClientStartOrder3);
	close(CNFCliParaList[threadnum].SENDCNFClientStartOrder4);
	close(CNFCliParaList[threadnum].RECVCNFClientStartOrder4);

	//释放该CNF任务所有变量
	//（在任务开始时有初始化代码）
	
	//释放DATA缓存位置
	datapkglist[DATALocation].pkglength = 0;
	memset(datapkglist[DATALocation].physicalport,0,30);
	memset(datapkglist[DATALocation].local_ip,0,16);
	memset(datapkglist[DATALocation].sid,0,SIDLEN);
	memset(datapkglist[DATALocation].offset,0,OFFLEN);
	memset(datapkglist[DATALocation].datapkg,0,pkglength);
	
	//释放CNF任务序号
	CNFThreadList[threadnum].flag_IO = -1;
	CNFThreadList[threadnum].datapkglocation = -1;
	CNFThreadList[threadnum].cachelocation = -1;
	memset(CNFThreadList[threadnum].physicalport,0,30);
	memset(CNFThreadList[threadnum].physicalportIP,0,16);
	memset(CNFThreadList[threadnum].sid,0,SIDLEN);
	memset(CNFThreadList[threadnum].offset,0,OFFLEN);
	
	//对任务解除占用
	datapkglist[DATALocation].flag_occupied = 0;
	CNFThreadList[threadnum].flag_occupied = 0;
	
	if(cnfcliDEVETESTIMPL <= 6)
		printf("threadnum %d released.\n",threadnum);
}

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
)
{
	//根据CNF任务号提取DATA包缓存位置
	int DATALocation = CNFThreadList[threadnum].datapkglocation;
	
	//从DATA包缓存位置提取相关参数
	int pkglength = datapkglist[DATALocation].pkglength;
	uint8_t local_ip[16];
	memcpy(local_ip,datapkglist[DATALocation].local_ip,16);

	//清空转发缓存中一切包（因data(161)包与残留的ACK(164)包经常搞混，故此为假定仅有单条链路的权益之技，并不能解决问题）
	int i;
	for(i=0;i<10;i++)
	{
		PkgBUF[i].flag_occupied = 0;
	}

	//数据包进入转发缓冲队列（此处需要线程锁）
	//printf("[CNF Client Stopping] Locking...\n");
	pthread_mutex_lock(&lockPkgBUF);
	//printf("[CNF Client Stopping] Locked.\n");
	int LocalPkgBUFHead;
	if(PkgBUF[PkgBUFHead].flag_occupied == 0)
	{
		LocalPkgBUFHead = PkgBUFHead;
		PkgBUFHead++;
		if(PkgBUFHead >=10)
			PkgBUFHead -= 10;
		
		PkgBUF[LocalPkgBUFHead].flag_occupied = 1;
		PkgBUF[LocalPkgBUFHead].pkglength = pkglength;
		strcpy(PkgBUF[LocalPkgBUFHead].sourcepp,datapkglist[DATALocation].physicalport);
		memcpy(PkgBUF[LocalPkgBUFHead].pkg,datapkglist[DATALocation].datapkg+14,pkglength);
		
		//触发网络层信号量
		sem_post(&semPacketRECV);

		if(cnfcliDEVETESTIMPL <= 6)
		{
			printf("[%s] SEM Message has been sent to NetworkLayer:\n",datapkglist[DATALocation].physicalport);
			printf("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n\n");
		}
	}
	else
	{
		if(cnfcliDEVETESTIMPL <= 6)
		{
			printf("[%s] SEM Message failed to be sent to NetworkLayer:\n",datapkglist[DATALocation].physicalport);
			printf("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n\n");
		}
	}

	//关闭整个任务

	//释放该CNF任务所有内部通信句柄
	close(CNFCliParaList[threadnum].SENDCNFClientACK);
	close(CNFCliParaList[threadnum].RECVCNFClientSEG);
	close(CNFCliParaList[threadnum].SENDCNFClientTimingBegin);
	close(CNFCliParaList[threadnum].RECVCNFClientTimingBegin);
	close(CNFCliParaList[threadnum].SENDCNFClientTimingEnd);
	close(CNFCliParaList[threadnum].RECVCNFClientTimingEnd);
	close(CNFCliParaList[threadnum].SENDCNFClientTimingRespond);
	close(CNFCliParaList[threadnum].RECVCNFClientTimingRespond);
	close(CNFCliParaList[threadnum].SENDCNFClientBufReady);
	close(CNFCliParaList[threadnum].RECVCNFClientBufReady);
	close(CNFCliParaList[threadnum].SENDCNFClientMoreData);
	close(CNFCliParaList[threadnum].RECVCNFClientMoreData);
	close(CNFCliParaList[threadnum].SENDCNFClientWriteData);
	close(CNFCliParaList[threadnum].RECVCNFClientWriteData);
	close(CNFCliParaList[threadnum].SENDCNFClientFileClose);
	close(CNFCliParaList[threadnum].RECVCNFClientFileClose);
	close(CNFCliParaList[threadnum].SENDCNFClientStartOrder1);
	close(CNFCliParaList[threadnum].RECVCNFClientStartOrder1);
	close(CNFCliParaList[threadnum].SENDCNFClientStartOrder2);
	close(CNFCliParaList[threadnum].RECVCNFClientStartOrder2);
	close(CNFCliParaList[threadnum].SENDCNFClientStartOrder3);
	close(CNFCliParaList[threadnum].RECVCNFClientStartOrder3);
	close(CNFCliParaList[threadnum].SENDCNFClientStartOrder4);
	close(CNFCliParaList[threadnum].RECVCNFClientStartOrder4);

	//释放该CNF任务所有变量
	//（在任务开始时有初始化代码）
	
	//释放DATA缓存位置
	datapkglist[DATALocation].pkglength = 0;
	memset(datapkglist[DATALocation].physicalport,0,30);
	memset(datapkglist[DATALocation].local_ip,0,16);
	memset(datapkglist[DATALocation].sid,0,SIDLEN);
	memset(datapkglist[DATALocation].offset,0,OFFLEN);
	memset(datapkglist[DATALocation].datapkg,0,pkglength);
	
	//释放CNF任务序号
	CNFThreadList[threadnum].flag_IO = -1;
	CNFThreadList[threadnum].datapkglocation = -1;
	CNFThreadList[threadnum].cachelocation = -1;
	memset(CNFThreadList[threadnum].physicalport,0,30);
	memset(CNFThreadList[threadnum].physicalportIP,0,16);
	memset(CNFThreadList[threadnum].sid,0,SIDLEN);
	memset(CNFThreadList[threadnum].offset,0,OFFLEN);
	
	//对任务解除占用
	datapkglist[DATALocation].flag_occupied = 0;
	CNFThreadList[threadnum].flag_occupied = 0;
	
	if(cnfcliDEVETESTIMPL <= 6)
		printf("threadnum %d released.\n",threadnum);
	
	pthread_mutex_unlock(&lockPkgBUF);
	//printf("[CNF Client Stopping] Lock Released.\n");
}

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
)
{
	//对CNFClient模块进行线程调用的参数拷贝接口
	struct cnfcliinput * cnfinput;
	cnfinput = (struct cnfcliinput *)fd;
	
	int threadnum = cnfinput->threadnum;

	if(cnfcliDEVETESTIMPL <= 6)
		printf("CNF threadnum == %d (CNFClient_thread_timer)\n",threadnum);

	int timer_XX = 0;
/*
	while(1)
	{
		sleep(SLEEP);
		
		time(&GMT);//读取GMT，赋值给GMT
		UTC = localtime(&GMT);//GMT-UTC转换
		printf("GMT(long)   %ld\n",GMT);//[GMT]输出1970.1.1.00:00:00至今秒数
		printf("UTC(human)  %s",asctime(UTC));//[UTC]输出字符化人类可读时间
	}
*/

	time(&GMT);//读取GMT，赋值给GMT
	StartTime = GMT;

	sleep(10000);
	//关闭线程
	//free(fd);
	//pthread_exit(NULL);
}

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
)
{
	//对CNFClient模块进行线程调用的参数拷贝接口
	struct cnfcliinput * cnfinput;
	cnfinput = (struct cnfcliinput *)fd;
	
	int threadnum = cnfinput->threadnum;
	
	if(cnfcliDEVETESTIMPL <= 6)
		printf("CNF threadnum == %d (CNFClient_thread_CNF)\n",threadnum);

	uint8_t PhysicalportIP[16];
	memcpy(PhysicalportIP,cnfinput->physicalportIP,16);

	//usleep(ProgramWaitingPeriod);//等待physicalport启动——在CNF程序中，用不到
	
	int i,j;

	uint8_t message[DATALENst+SIDLENst+OFFLEN+20];
	memset(message,0,DATALENst+SIDLENst+OFFLEN+20);

	uint8_t SID[SIDLEN];
	memset(SID,0,SIDLEN);
	int SIDlen=0;
	
	uint8_t DATA[DATALEN];
	memset(DATA,0,DATALEN);
	int DATAlen;

	uint8_t REQoffset[OFFLEN];
	memset(REQoffset,0,OFFLEN);
	unsigned long REQoffsetlong;

	uint8_t RESoffset[OFFLEN];
	memset(RESoffset,0,OFFLEN);
	unsigned long RESoffsetlong;

	//参数初始化
	memset(CNFCliParaList[threadnum].SID,0,SIDLEN);//任务所服务的SID
	CNFCliParaList[threadnum].SIDLen = 0;//SID的实际长度

	CNFCliParaList[threadnum].BUF = NULL;//发送缓冲区开头
	CNFCliParaList[threadnum].BUFEnd = NULL;//发送缓冲区结尾
	CNFCliParaList[threadnum].BUFFileEnd = NULL;//读取文件结束时，缓冲区内文件末尾所在地址

	CNFCliParaList[threadnum].BUFRenewCount = 0;//缓冲区更新次数
	CNFCliParaList[threadnum].BUFLength = CNFBUFSIZE;//发送缓冲长度

	CNFCliParaList[threadnum].FileWritePoint = 0;//文件写入进度
	CNFCliParaList[threadnum].FileLength = 0;//文件总长度

	CNFCliParaList[threadnum].PacketDataLength = PKTDATALEN;//单包数据段长度
	CNFCliParaList[threadnum].LastPacketDataLength = 0;//整个传输任务的最后一个数据包实际长度

	CNFCliParaList[threadnum].OffsetConfirmDATA = 0;//在整个文件中确认收到的字节顶端
	CNFCliParaList[threadnum].OffsetPacket = 0;//在整个文件中当前封包字节数
	CNFCliParaList[threadnum].OffsetWaitDATA = PKTDATALEN;//在整个文件中等待确认收到的字节数（发送ACK数据包偏移量字段的填写依据）

	CNFCliParaList[threadnum].AddrConfirmDATA = NULL;//在缓冲区中已确认偏移量所在地址
	CNFCliParaList[threadnum].AddrPacket = NULL;//在缓冲区中当前封包偏移量所在地址
	CNFCliParaList[threadnum].AddrWaitDATA = NULL;//在缓冲区中待确认偏移量所在地址

	CNFCliParaList[threadnum].RTOs = 0;//往返容忍时延（RTO大于1秒部分，单位秒）
	CNFCliParaList[threadnum].RTOus = 0;//往返容忍时延（RTO小于1秒部分，单位微秒）
	CNFCliParaList[threadnum].RTOns = 0;//往返容忍时延（RTO小于1秒部分，单位纳秒）

	CNFCliParaList[threadnum].FlagInputBUF = 0;//是否将收到的数据写入缓冲

	CNFCliParaList[threadnum].TimingState = 0;//计时状态，0按时，1超时
	CNFCliParaList[threadnum].ThreadState = 0;//任务状态（用于结束过程的控制）

	if(cnfcliDEVETESTIMPL <= 6)
	{
		printf("xxx waiting...\n");
		printf("xxx triggering...\n");
		printf("xxx triggered!\n");
	}

	//触发FTP线程开始
	if(cnfINTRACOMMUNICATION == 0)
	{
		sendto(CNFCliParaList[threadnum].SENDCNFClientStartOrder1,"StartOrder1",20,0,(struct sockaddr *)&CNFCliParaList[threadnum].SENDAddrToCNFClientStartOrder1,SockAddrLength);
	}
	else if(cnfINTRACOMMUNICATION == 1)
	{
		sem_post(&CNFCliParaList[threadnum].semCNFClientStartOrder1);
	}
	
	if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
		printf("[%d] StartOrder1 triggering...\n",CNFCliParaList[threadnum].CountCNFClientStartOrder1_Triggering);
	CNFCliParaList[threadnum].CountCNFClientStartOrder1_Triggering++;

	//触发CNF主子线程开始
	if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
		printf("[%d] StartOrder3 waiting...\n",CNFCliParaList[threadnum].CountCNFClientStartOrder3_Waiting);
	CNFCliParaList[threadnum].CountCNFClientStartOrder3_Waiting++;
	
	if(cnfINTRACOMMUNICATION == 0)
	{
		recvfrom(CNFCliParaList[threadnum].RECVCNFClientStartOrder3,Trigger,20,0,(struct sockaddr *)&CNFCliParaList[threadnum].RECVAddrToCNFClientStartOrder3,&SockAddrLength);
	}
	else if(cnfINTRACOMMUNICATION == 1)
	{
		sem_wait(&CNFCliParaList[threadnum].semCNFClientStartOrder3);
	}
	
	if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
		printf("[%d] StartOrder3 triggered!\n",CNFCliParaList[threadnum].CountCNFClientStartOrder3_Triggered);
	CNFCliParaList[threadnum].CountCNFClientStartOrder3_Triggered++;

	//触发下行线程开始
	if(cnfINTRACOMMUNICATION == 0)
	{
		sendto(CNFCliParaList[threadnum].SENDCNFClientStartOrder4,"StartOrder4",20,0,(struct sockaddr *)&CNFCliParaList[threadnum].SENDAddrToCNFClientStartOrder4,SockAddrLength);
	}
	else if(cnfINTRACOMMUNICATION == 1)
	{
		sem_post(&CNFCliParaList[threadnum].semCNFClientStartOrder4);
	}
	
	if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
		printf("[%d] StartOrder4 triggering...\n",CNFCliParaList[threadnum].CountCNFClientStartOrder4_Triggering);
	CNFCliParaList[threadnum].CountCNFClientStartOrder4_Triggering++;

	//循环监听回送资源成功的信令的变量准备
	int flag_sidgot = 0;
	int counter_sidget = 0;

	if(cnfcliDEVETESTIMPL <= 1)
		printf("[Transport Layer] CNFClient responce listening start...\n");
	
	uint8_t recvpkg[sizeof(CoLoR_seg)];
	CoLoR_seg * precvpkg;
	precvpkg = (CoLoR_seg *)recvpkg;

	int FoundSIDNum = -1;
	
	//循环监听回送资源成功的信令
	while(1)
	{
		i=0;
		j=0;

		//清空缓冲，为接收数据做准备
		DATAlen = 0;
		REQoffsetlong = 0;
		RESoffsetlong = 0;
		memset(DATA,0,DATALEN);
		memset(recvpkg,0,sizeof(CoLoR_seg));

		FoundSIDNum = -1;

		//接收
		recvfrom(CNFCliParaList[threadnum].RECVCNFClientSEG,recvpkg,sizeof(CoLoR_seg),0,(struct sockaddr *)&CNFCliParaList[threadnum].RECVAddrToCNFClientSEG,&SockAddrLength);
		
		if(cnfcliDEVETESTIMPL <= 1)
			printf("[Transport Layer] CNFClient responce listener received a new UDP message.\n");
		
		//提取DATA与offset
		memcpy(DATA,precvpkg->data,DATALEN);
		memcpy(RESoffset,precvpkg->offset,OFFLEN);
		DATAlen = DATALEN;

		//收到的数据长度累积大于预知文件长度（容错机制，并非结束机制，所以出错判断条件需要大于结束条件）
		if((long)CNFCliParaList[threadnum].OffsetConfirmDATA - (long)DATALEN >= CACHESIZE)//强制long型转换是避免做差反向溢出导致误判
		{
			if(cnfcliDEVETESTIMPL <= 6)
			{
				printf("Received File Length   = %ld\n",(long)CNFCliParaList[threadnum].OffsetConfirmDATA - (long)DATALEN);
				printf("File Length Ever known = %ld\n",(unsigned long)CACHESIZE);
				printf("[Deadly Error] Received File Length is Bigger Than the File Length Ever known.\n");
			}
			
			CNFCliParaList[threadnum].FlagInputBUF = 0;
			sendto(CNFCliParaList[threadnum].SENDCNFClientTimingEnd,"TimingEnd",20,0,(struct sockaddr *)&CNFCliParaList[threadnum].SENDAddrToCNFClientTimingEnd,SockAddrLength);

			if(cnfcliDEVETESTIMPL <= 6 || CNFTRIGGERTEST == 1)
				printf("[%d] TimingEnd triggering...\n",CNFCliParaList[threadnum].CountCNFClientTimingEnd_Triggering);

			CNFCliParaList[threadnum].CountCNFClientTimingEnd_Triggering++;
		}
	
		if(cnfcliDEVETESTIMPL <= 5)
		{
			printf("[DATAlen]\n%d\n",DATAlen);
			//printf("[DATA]\n%s\n",DATA);
			printf("[DATA-END]\n");
		}

		//至此CNF网络层上行接口做好，接口消息格式GOTdataOFFoffset
		//此处缺少对数据正确性的校验
		
		//判断OFFSET的合法性，进入主要处理程序
		if(RESoffset[0] >= 0 && RESoffset[1] >= 0 && RESoffset[2] >= 0 && RESoffset[3] >= 0)
		{
			RESoffsetlong = (unsigned long)RESoffset[0] * 256 * 256 * 256 + 
					(unsigned long)RESoffset[1] * 256 * 256 + 
					(unsigned long)RESoffset[2] * 256 + 
					(unsigned long)RESoffset[3];
			
			//查找与SID对应的任务线程编号
			if(strncmp(CNFCliParaList[threadnum].SID,SID,SIDLEN) == 0)
			{
				FoundSIDNum = 0;
			}
			if(FoundSIDNum == -1)
			{
				printf("An unknown ACK Packet received, SID not found.\n");
				exit(0);
			}

			CNFCliParaList[threadnum].SIDLen = SIDlen;
			//if(RESoffsetlong >= 10000)exit(0);
			
			if(cnfcliDEVETESTIMPL <= 5)
			{
				printf("[RECV]RESoffsetlong  = %ld\n",RESoffsetlong);
				printf("[RECV]OffsetWaitDATA = %ld\n",CNFCliParaList[threadnum].OffsetWaitDATA);
			}
			
			if(RESoffsetlong == CNFCliParaList[threadnum].OffsetWaitDATA)//收到当前所请求的偏移量，写入接收缓冲，更新确认偏移量值
			{
				//printf("New Data Input!\n");
				//向缓冲区拷贝刚刚收到的数据字段
				
				//收到数据段长度大于本地CNF规定的标准单包数据段长度，
				//意味着文件尚未结束（文件大小恰为PacketDataLength的整数倍情况除外）
				if(DATAlen == CNFCliParaList[threadnum].PacketDataLength)
				{
					//将收到的数据拷贝进缓存
					memcpy(CNFCliParaList[threadnum].AddrConfirmDATA,DATA,CNFCliParaList[threadnum].PacketDataLength);

					//移动各类定位标识
					CNFCliParaList[threadnum].OffsetConfirmDATA = RESoffsetlong;
					CNFCliParaList[threadnum].OffsetWaitDATA    = RESoffsetlong + DATAlen;
					CNFCliParaList[threadnum].AddrConfirmDATA  += CNFCliParaList[threadnum].PacketDataLength;

					//缓冲区回环处理
					if(CNFCliParaList[threadnum].AddrConfirmDATA >= CNFCliParaList[threadnum].BUFEnd)
					{
						CNFCliParaList[threadnum].AddrConfirmDATA = CNFCliParaList[threadnum].BUF + ( CNFCliParaList[threadnum].AddrConfirmDATA - CNFCliParaList[threadnum].BUFEnd );
					}
				}
				//收到数据段长度小于本地CNF规定的标准单包数据段长度，
				//意味着这是文件的最后一个包，应当触发对文件生成和结束传输的处理
				/*
				else if(DATAlen < CNFCliParaList[threadnum].PacketDataLength)
				{
					//将收到的数据拷贝进缓存
					memcpy(CNFCliParaList[threadnum].AddrConfirmDATA,DATA,DATAlen);
					
					//移动各类定位标识
					CNFCliParaList[threadnum].OffsetWaitDATA = RESoffsetlong + DATAlen;
					CNFCliParaList[threadnum].AddrConfirmDATA += CNFCliParaList[threadnum].PacketDataLength;

					//通知向文件写入数据
					sendto(CNFCliParaList[threadnum].SENDCNFClientWriteData,"WriteData",20,0,(struct sockaddr *)&CNFCliParaList[threadnum].SENDAddrToCNFClientWriteData,SockAddrLength);

					if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
						printf("[%d] WriteData triggering...\n",CNFCliParaList[threadnum].CountCNFClientWriteData_Triggering);
					CNFCliParaList[threadnum].CountCNFClientWriteData_Triggering++;
				}
				*/
				//收到数据段长度不等于本地CNF规定的标准单包数据段长度，
				//属于两端协议参数不匹配，需要修改设置
				else
				{
					printf("Deadly error!(DATAlen == %d > CNFCliParaList[threadnum].PacketDataLength)\n",DATAlen);
					exit(0);
				}

				CNFCliParaList[threadnum].FlagInputBUF = 1;
				
				//通知结束计时
				sendto(CNFCliParaList[threadnum].SENDCNFClientTimingEnd,"TimingEnd",20,0,(struct sockaddr *)&CNFCliParaList[threadnum].SENDAddrToCNFClientTimingEnd,SockAddrLength);

				if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
					printf("[%d] TimingEnd triggering...\n",CNFCliParaList[threadnum].CountCNFClientTimingEnd_Triggering);
				CNFCliParaList[threadnum].CountCNFClientTimingEnd_Triggering++;
			}
			else if(RESoffsetlong != CNFCliParaList[threadnum].OffsetWaitDATA)//收到非当前所请求的偏移量，重复发送当前所请求的偏移量
			{
				CNFCliParaList[threadnum].FlagInputBUF = 0;

				sendto(CNFCliParaList[threadnum].SENDCNFClientTimingEnd,"TimingEnd",20,0,(struct sockaddr *)&CNFCliParaList[threadnum].SENDAddrToCNFClientTimingEnd,SockAddrLength);

				if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
					printf("[%d] TimingEnd triggering...\n",CNFCliParaList[threadnum].CountCNFClientTimingEnd_Triggering);
				CNFCliParaList[threadnum].CountCNFClientTimingEnd_Triggering++;
			}
		}
		else//offset值非法
		{
			//触发ACK重传
			CNFCliParaList[threadnum].FlagInputBUF = 0;

			sendto(CNFCliParaList[threadnum].SENDCNFClientTimingEnd,"TimingEnd",20,0,(struct sockaddr *)&CNFCliParaList[threadnum].SENDAddrToCNFClientTimingEnd,SockAddrLength);

			if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
				printf("[%d] TimingEnd triggering...\n",CNFCliParaList[threadnum].CountCNFClientTimingEnd_Triggering);
			CNFCliParaList[threadnum].CountCNFClientTimingEnd_Triggering++;
		}
	}

	sleep(10000);
	//关闭线程
	//exit(0);
	//free(fd);
	//pthread_exit(NULL);	
}

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
)
{
	//对CNFClient模块进行线程调用的参数拷贝接口
	struct cnfcliinput * cnfinput;
	cnfinput = (struct cnfcliinput *)fd;
	
	int threadnum = cnfinput->threadnum;

	if(cnfcliDEVETESTIMPL <= 6)
		printf("CNF threadnum     == %d (CNFClient_thread_FTP)\n",threadnum);

	int CacheLocation = CNFThreadList[cnfinput->threadnum].cachelocation;

	if(cnfcliDEVETESTIMPL <= 6)
		printf("CNF CacheLocation == %d (CNFClient_thread_FTP)\n",CacheLocation);

	//提取任务编号
	//int ThreadNum = *((int *)fd);printf("[FTP]ThreadNum = %d\n",ThreadNum);
	
	//触发FTP线程开始
	if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
		printf("[%d] StartOrder1 waiting...\n",CNFCliParaList[threadnum].CountCNFClientStartOrder1_Waiting);
	CNFCliParaList[threadnum].CountCNFClientStartOrder1_Waiting++;

	if(cnfINTRACOMMUNICATION == 0)
	{
		recvfrom(CNFCliParaList[threadnum].RECVCNFClientStartOrder1,Trigger,20,0,(struct sockaddr *)&CNFCliParaList[threadnum].RECVAddrToCNFClientStartOrder1,&SockAddrLength);
	}
	else if(cnfINTRACOMMUNICATION == 1)
	{
		sem_wait(&CNFCliParaList[threadnum].semCNFClientStartOrder1);
	}

	if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
		printf("[%d] StartOrder1 triggered!\n",CNFCliParaList[threadnum].CountCNFClientStartOrder1_Triggered);
	CNFCliParaList[threadnum].CountCNFClientStartOrder1_Triggered++;

	//为任务申请接收缓冲内存
	CNFCliParaList[threadnum].BUF = (uint8_t *)malloc(CNFBUFSIZE);
	memset(CNFCliParaList[threadnum].BUF,0,CNFBUFSIZE);
	
	//更新相关控制参数
	CNFCliParaList[threadnum].BUFEnd = CNFCliParaList[threadnum].BUF + CNFBUFSIZE;//发送缓冲区结尾

	CNFCliParaList[threadnum].BUFRenewCount = 0;//缓冲区更新次数
	CNFCliParaList[threadnum].BUFLength = CNFBUFSIZE;//发送缓冲长度

	CNFCliParaList[threadnum].FileWritePoint = 0;//文件写入进度
	CNFCliParaList[threadnum].FileLength = 0;//文件总长度

	CNFCliParaList[threadnum].PacketDataLength = PKTDATALEN;//单包数据段长度
	CNFCliParaList[threadnum].LastPacketDataLength = 0;//整个传输任务的最后一个数据包实际长度
	
	CNFCliParaList[threadnum].AddrConfirmDATA = CNFCliParaList[threadnum].BUF;//在缓冲区中已确认偏移量所在地址
	CNFCliParaList[threadnum].AddrPacket = CNFCliParaList[threadnum].BUF;//在缓冲区中当前封包偏移量所在地址
	CNFCliParaList[threadnum].AddrWaitDATA = CNFCliParaList[threadnum].BUF;//在缓冲区中待确认偏移量所在地址

	//依照任务编号对应的参数组SID寻找对应的文件
	
	
	//打开文件并获取所需参数
	/*
	int fp;
	unsigned long filelen = FILELEN;//debuglog.txt的文件大小
	*/

	unsigned long cachelen = CACHESIZE;
	
	//创建并打开客户端接收文件
	/*
	fp = open(FTPClientPath,O_RDWR | O_CREAT | O_APPEND | O_TRUNC);
	if(fp == -1)
	{
		printf("[Deadly Error] The Client File \"%s\" opening failed.\n",FTPClientPath);
		exit(0);
	}
	*/
	
	//通知传输层，发送缓冲已经准备就绪（暂时无用）
	if(cnfINTRACOMMUNICATION == 0)
	{
		sendto(CNFCliParaList[threadnum].SENDCNFClientBufReady,"BufReady",20,0,(struct sockaddr *)&CNFCliParaList[threadnum].SENDAddrToCNFClientBufReady,SockAddrLength);
	}
	else if(cnfINTRACOMMUNICATION == 1)
	{
		sem_post(&CNFCliParaList[threadnum].semCNFClientBufReady);
	}

	if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
		printf("[%d] BufReady triggering...\n",CNFCliParaList[threadnum].CountCNFClientBufReady_Triggering);
	CNFCliParaList[threadnum].CountCNFClientBufReady_Triggering++;

	//触发上行计时线程开始
	//sendto(CNFCliParaList[threadnum].SENDCNFClientStartOrder2,"StartOrder2",20,0,(struct sockaddr *)&CNFCliParaList[threadnum].SENDAddrToCNFClientStartOrder2,SockAddrLength);

	//printf("[%d] StartOrder2 triggering...\n",CNFCliParaList[threadnum].CountCNFClientStartOrder2_Triggering);
	
	//计算时间节点（微秒）		
	gettimeofday(&utime,NULL);
	printf("==================Time==================\nClient Transmission Start %ld us\n========================================\n",1000000 * utime.tv_sec + utime.tv_usec);

	//开始持续为传输层供应数据
	while(1)
	{
		if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
			printf("[%d] WriteData waiting...\n",CNFCliParaList[threadnum].CountCNFClientWriteData_Waiting);
		CNFCliParaList[threadnum].CountCNFClientWriteData_Waiting++;

		//阻塞等待传输层触发对上传数据的要求
		if(cnfINTRACOMMUNICATION == 0)
		{
			recvfrom(CNFCliParaList[threadnum].RECVCNFClientWriteData,Trigger,20,0,(struct sockaddr *)&CNFCliParaList[threadnum].RECVAddrToCNFClientWriteData,&SockAddrLength);
		}
		else if(cnfINTRACOMMUNICATION == 1)
		{
			sem_wait(&CNFCliParaList[threadnum].semCNFClientWriteData);
		}
		
		if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
			printf("[%d] WriteData triggered!\n",CNFCliParaList[threadnum].CountCNFClientWriteData_Triggered);
		CNFCliParaList[threadnum].CountCNFClientWriteData_Triggered++;

		CNFCliParaList[threadnum].BUFRenewCount++;
		
		//一次上传接收缓冲中一半的内容，前半段和后半段交替上传
		if(CNFCliParaList[threadnum].BUFRenewCount % 2 == 1)//判断上传前半段
		{
			//检查缓存剩余长度是否足够一次上传
			if(CNFCliParaList[threadnum].FileWritePoint + CNFCliParaList[threadnum].BUFLength/2 > cachelen)//不足一次上传，则记录尾部标识，上传有限数据
			{
				//write(fp,CNFCliParaList[threadnum].BUF,filelen - CNFCliParaList[threadnum].FileWritePoint);
				memcpy(CacheList[CacheLocation].cache + CacheList[CacheLocation].cachetop,
					CNFCliParaList[threadnum].BUF,
					cachelen - CNFCliParaList[threadnum].FileWritePoint);
				CacheList[CacheLocation].cachetop += cachelen - CNFCliParaList[threadnum].FileWritePoint;
				
				CNFCliParaList[threadnum].BUFFileEnd = CNFCliParaList[threadnum].BUF + ( cachelen - CNFCliParaList[threadnum].FileWritePoint );
				CNFCliParaList[threadnum].ThreadState = 1;
				break;
			}
			else//足够一次上传，则上传
			{
				//write(fp,CNFCliParaList[threadnum].BUF,CNFCliParaList[threadnum].BUFLength/2);
				memcpy(CacheList[CacheLocation].cache + CacheList[CacheLocation].cachetop,
					CNFCliParaList[threadnum].BUF,
					CNFCliParaList[threadnum].BUFLength/2);
				CacheList[CacheLocation].cachetop += CNFCliParaList[threadnum].BUFLength/2;
				
				CNFCliParaList[threadnum].FileWritePoint += CNFCliParaList[threadnum].BUFLength/2;
				//printf("CNFCliParaList[threadnum].FileWritePoint = %ld\n",CNFCliParaList[threadnum].FileWritePoint);
			}
		}
		else if(CNFCliParaList[threadnum].BUFRenewCount % 2 == 0)//判断上传后半段
		{
			//检查文件剩余长度是否足够一次上传
			if(CNFCliParaList[threadnum].FileWritePoint + CNFCliParaList[threadnum].BUFLength/2 > cachelen)//不足一次上传，则记录尾部标识，上传有限数据
			{
				//write(fp,CNFCliParaList[threadnum].BUF + CNFCliParaList[threadnum].BUFLength/2,filelen - CNFCliParaList[threadnum].FileWritePoint);
				//write(fp,CNFCliParaList[threadnum].BUF + CNFCliParaList[threadnum].BUFLength/2,filelen - CNFCliParaList[threadnum].FileWritePoint);
				memcpy(CacheList[CacheLocation].cache + CacheList[CacheLocation].cachetop,
					CNFCliParaList[threadnum].BUF + CNFCliParaList[threadnum].BUFLength/2,
					cachelen - CNFCliParaList[threadnum].FileWritePoint);
				CacheList[CacheLocation].cachetop += cachelen - CNFCliParaList[threadnum].FileWritePoint;
				
				CNFCliParaList[threadnum].BUFFileEnd = CNFCliParaList[threadnum].BUF + CNFCliParaList[threadnum].BUFLength/2 + ( cachelen - CNFCliParaList[threadnum].FileWritePoint );
				CNFCliParaList[threadnum].ThreadState = 1;
				break;
			}
			else//足够一次上传，则上传
			{
				//write(fp,CNFCliParaList[threadnum].BUF + CNFCliParaList[threadnum].BUFLength/2,CNFCliParaList[threadnum].BUFLength/2);
				memcpy(CacheList[CacheLocation].cache + CacheList[CacheLocation].cachetop,
					CNFCliParaList[threadnum].BUF + CNFCliParaList[threadnum].BUFLength/2,
					CNFCliParaList[threadnum].BUFLength/2);
				CacheList[CacheLocation].cachetop += CNFCliParaList[threadnum].BUFLength/2;
				
				CNFCliParaList[threadnum].FileWritePoint += CNFCliParaList[threadnum].BUFLength/2;
				//printf("CNFCliParaList[threadnum].FileWritePoint = %ld\n",CNFCliParaList[threadnum].FileWritePoint);
			}
		}

		if(cnfcliDEVETESTIMPL <= 6)
			printf("Data already received: %ld Byte\n",CNFCliParaList[threadnum].FileWritePoint);
	}

	//向下行通道通知文件写入结束
	if(cnfINTRACOMMUNICATION == 0)
	{
		sendto(CNFCliParaList[threadnum].SENDCNFClientFileClose,"FileClose",20,0,(struct sockaddr *)&CNFCliParaList[threadnum].SENDAddrToCNFClientFileClose,SockAddrLength);
	}
	else if(cnfINTRACOMMUNICATION == 1)
	{
		sem_post(&CNFCliParaList[threadnum].semCNFClientFileClose);
	}

	if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
		printf("[%d] FileClose triggering...\n",CNFCliParaList[threadnum].CountCNFClientFileClose_Triggering);
	CNFCliParaList[threadnum].CountCNFClientFileClose_Triggering++;
	
	if(cnfcliDEVETESTIMPL <= 6)
		printf("[FTP]File Transport End.\n");

	if(cnfcliDEVETESTIMPL <= 7)
	{
/*
		printf("==========DATA Results==========\n");
		//计算整个传输总共消耗秒数
		time(&GMT);//读取GMT，赋值给GMT
		EndTime = GMT;
		UsedTime = EndTime - StartTime;
		printf("Total Time  %ld\n",UsedTime);//输出整个传输总共消耗秒数
*/
		//计算时间节点（微秒）		
		gettimeofday(&utime,NULL);
		printf("==================Time==================\nClient Transmission End   %ld us\n========================================\n",1000000 * utime.tv_sec + utime.tv_usec);
/*
		//计算时间节点（秒）
		time(&GMT);//读取GMT，赋值给GMT
		UTC = localtime(&GMT);//GMT-UTC转换
		printf("GMT(long)   %ld s\n",GMT);//[GMT]输出1970.1.1.00:00:00至今秒数
		printf("UTC(human)  %s\n",asctime(UTC));//[UTC]输出字符化人类可读时间
		printf("================================\n");
*/
	}
	
	//printf("BUF = \n%s\n",CacheList[CacheLocation].cache);//检查整个数据块的输出
	
	CNFThreadList[threadnum].flag_close = 1;

	int closethread1,closethread2,closethread3,closethread4;
	closethread1 = pthread_cancel(CNFCliParaList[threadnum].pthread_NetworkLayertoTransportLayer);
	closethread2 = pthread_cancel(CNFCliParaList[threadnum].pthread_TransportLayertoNetworkLayer);
	closethread3 = pthread_cancel(CNFCliParaList[threadnum].pthread_CNF);
	closethread4 = pthread_cancel(CNFCliParaList[threadnum].pthread_timer);
	
	if(closethread1 == 0 && closethread2 == 0 && closethread3 == 0 && closethread4 == 0)
	{
		if(cnfcliDEVETESTIMPL <= 7)
		{
			printf("Client Threads Close Success.\n");
			printf("<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<\n");
		}
	}
	else
	{
		printf("Client Threads Close Failed.\n");
		printf("closethread1 = %d\n",closethread1);
		printf("closethread2 = %d\n",closethread2);
		printf("closethread3 = %d\n",closethread3);
		printf("closethread4 = %d\n",closethread4);
	}

	//CNF上游阶段传输完毕，将缓存的DATA包上传转发平面，以便向下一跳转发
	if(INTRACOMMUNICATION == 0)
		CNFClient_UDP_SendData(threadnum);
	else if(INTRACOMMUNICATION == 1)
		CNFClient_SEM_SendData(threadnum);
	
	//结束该线程
	pthread_exit(NULL);
	//exit(0);
	//close(fp);
}

/*****************************************
* 函数名称：CNFClient_thread_NetworkLayertoTransportLayer
* 功能描述：上行通道 - From.数据请求端   To.应用服务器  提供定时
* 参数列表：
* 返回结果：
*****************************************/
void *
CNFClient_thread_NetworkLayertoTransportLayer
(
	void * fd
)
{
	//对CNFClient模块进行线程调用的参数拷贝接口
	struct cnfcliinput * cnfinput;
	cnfinput = (struct cnfcliinput *)fd;
	
	int threadnum = cnfinput->threadnum;
	
	if(cnfcliDEVETESTIMPL <= 6)
		printf("CNF threadnum == %d\n (CNFClient_thread_NetworkLayertoTransportLayer)\n",threadnum);

	//提取任务编号
	//int ThreadNum = *((int *)fd);printf("[UP]ThreadNum = %d\n",ThreadNum);

	//触发上行计时线程开始
	if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
		printf("[%d] BufReady waiting...\n",CNFCliParaList[threadnum].CountCNFClientBufReady_Waiting);
	CNFCliParaList[threadnum].CountCNFClientBufReady_Waiting++;
	
	if(cnfINTRACOMMUNICATION == 0)
	{
		recvfrom(CNFCliParaList[threadnum].RECVCNFClientBufReady,Trigger,20,0,(struct sockaddr *)&CNFCliParaList[threadnum].RECVAddrToCNFClientBufReady,&SockAddrLength);
	}
	else if(cnfINTRACOMMUNICATION == 1)
	{
		sem_wait(&CNFCliParaList[threadnum].semCNFClientBufReady);
	}

	if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
		printf("[%d] BufReady triggered!\n",CNFCliParaList[threadnum].CountCNFClientBufReady_Triggered);
	CNFCliParaList[threadnum].CountCNFClientBufReady_Triggered++;
	
	//printf("[%d] StartOrder2 waiting...\n",CNFCliParaList[threadnum].CountCNFClientStartOrder2_Waiting);
	//CNFCliParaList[threadnum].CountCNFClientStartOrder2_Waiting++;
	
	//recvfrom(CNFCliParaList[threadnum].RECVCNFClientStartOrder2,Trigger,20,0,(struct sockaddr *)&CNFCliParaList[threadnum].RECVAddrToCNFClientStartOrder2,&SockAddrLength);
	
	//printf("[%d] StartOrder2 triggered!\n",CNFCliParaList[threadnum].CountCNFClientStartOrder2_Triggered);
	//CNFCliParaList[threadnum].CountCNFClientStartOrder2_Triggered++;
	
	//计时器相关参数初始化
	CNFCliParaList[threadnum].RTOs = RTOS;//往返容忍时延（RTO大于1秒部分，单位秒）
	CNFCliParaList[threadnum].RTOus = RTOUS;//往返容忍时延（RTO小于1秒部分，单位微秒）
	CNFCliParaList[threadnum].RTOns = RTONS;//往返容忍时延（RTO小于1秒部分，单位纳秒）
	time_t GMT;//国际标准时间，实例化time_t结构(typedef long time_t;)
	struct timespec delaytime;

	//触发CNF主子线程开始
	if(cnfINTRACOMMUNICATION == 0)
	{
		sendto(CNFCliParaList[threadnum].SENDCNFClientStartOrder3,"StartOrder3",20,0,(struct sockaddr *)&CNFCliParaList[threadnum].SENDAddrToCNFClientStartOrder3,SockAddrLength);
	}
	else if(cnfINTRACOMMUNICATION == 1)
	{
		sem_post(&CNFCliParaList[threadnum].semCNFClientStartOrder3);
	}

	if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
		printf("[%d] StartOrder3 triggering...\n",CNFCliParaList[threadnum].CountCNFClientStartOrder3_Triggering);
	CNFCliParaList[threadnum].CountCNFClientStartOrder3_Triggering++;

	while(1)
	{
		//变量清零
		CNFCliParaList[threadnum].TimingState = 0;

		if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
			printf("[%d] TimingBegin waiting...\n",CNFCliParaList[threadnum].CountCNFClientTimingBegin_Waiting);
		CNFCliParaList[threadnum].CountCNFClientTimingBegin_Waiting++;
		
		//阻塞等待定时任务
		if(cnfINTRACOMMUNICATION == 0)
		{
			recvfrom(CNFCliParaList[threadnum].RECVCNFClientTimingBegin,Trigger,20,0,(struct sockaddr *)&CNFCliParaList[threadnum].RECVAddrToCNFClientTimingBegin,&SockAddrLength);
		}
		else if(cnfINTRACOMMUNICATION == 1)
		{
			sem_wait(&CNFCliParaList[threadnum].semCNFClientTimingBegin);
		}

		if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
			printf("[%d] TimingBegin triggered!\n",CNFCliParaList[threadnum].CountCNFClientTimingBegin_Triggered);
		CNFCliParaList[threadnum].CountCNFClientTimingBegin_Triggered++;
		
		//定时阻塞窗口传输上行通道结束计时提示
		if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
			printf("[%d] TimingEnd waiting...\n",CNFCliParaList[threadnum].CountCNFClientTimingEnd_Waiting);
		CNFCliParaList[threadnum].CountCNFClientTimingEnd_Waiting++;

		//带超时的UDP消息接收
		//设置超时
		struct timeval delaytime;
		delaytime.tv_sec=CNFCliParaList[threadnum].RTOs;
		delaytime.tv_usec=CNFCliParaList[threadnum].RTOus;

		//记录sockfd
		fd_set readfds;//已改用函数输入外部变量指针
		FD_ZERO(&readfds);
		FD_SET(CNFCliParaList[threadnum].RECVCNFClientTimingEnd,&readfds);

		select(CNFCliParaList[threadnum].RECVCNFClientTimingEnd+1,&readfds,NULL,NULL,&delaytime);
		
		//限时接收
		if(FD_ISSET(CNFCliParaList[threadnum].RECVCNFClientTimingEnd,&readfds))
		{
			if(0 <= recvfrom(CNFCliParaList[threadnum].RECVCNFClientTimingEnd,Trigger,20,0,(struct sockaddr *)&CNFCliParaList[threadnum].RECVAddrToCNFClientTimingEnd,&SockAddrLength))
			{
				if(cnfcliDEVETESTIMPL <= 0)
					printf("[TimingEndDelay]  %.3f ms\n",(double)(CNFCliParaList[threadnum].RTOus - (int)delaytime.tv_usec)/(double)1000);
			}
		}
		else
		{
			if(cnfcliDEVETESTIMPL <= 0)
				printf("[TimingEndDelay]  %.3f ms   (Timeout)\n",(double)(CNFCliParaList[threadnum].RTOus - (int)delaytime.tv_usec)/(double)1000);
		}

		if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
			printf("[%d] TimingEnd triggered!\n",CNFCliParaList[threadnum].CountCNFClientTimingEnd_Triggered);
		CNFCliParaList[threadnum].CountCNFClientTimingEnd_Triggered++;

		//通知下行通道，反馈本次反馈计时已得出结果
		if(cnfINTRACOMMUNICATION == 0)
		{
			sendto(CNFCliParaList[threadnum].SENDCNFClientTimingRespond,"TimingRespond",20,0,(struct sockaddr *)&CNFCliParaList[threadnum].SENDAddrToCNFClientTimingRespond,SockAddrLength);
		}
		else if(cnfINTRACOMMUNICATION == 1)
		{
			sem_post(&CNFCliParaList[threadnum].semCNFClientTimingRespond);
		}
		if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
			printf("[%d] TimingRespond triggering...\n",CNFCliParaList[threadnum].CountCNFClientTimingRespond_Triggering);
		CNFCliParaList[threadnum].CountCNFClientTimingRespond_Triggering++;
	}
	
	sleep(10000);
	//关闭线程
	//exit(0);
	//free(fd);
	//pthread_exit(NULL);
}

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
)
{
	int i;

	//对CNFClient模块进行线程调用的参数拷贝接口
	struct cnfcliinput * cnfinput;
	cnfinput = (struct cnfcliinput *)fd;
	
	int threadnum = cnfinput->threadnum;

	if(cnfcliDEVETESTIMPL <= 6)
		printf("CNF threadnum == %d (CNFClient_thread_TransportLayertoNetworkLayer)\n",threadnum);

	uint8_t PhysicalportIP[16];
	memcpy(PhysicalportIP,cnfinput->physicalportIP,16);
	
	int portnum;
	for(i=15;i>=0;i--)
	{
		if(CNFThreadList[threadnum].physicalportIP[i] == '.')
		{
			portnum = CNFThreadList[threadnum].physicalportIP[i+2] - '0';
			break;
		}
	}

	//提取任务编号
	//int ThreadNum = *((int *)fd);printf("[DOWN]ThreadNum = %d\n",ThreadNum);

	//触发下行线程开始
	if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
		printf("[%d] StartOrder4 waiting...\n",CNFCliParaList[threadnum].CountCNFClientStartOrder4_Waiting);
	CNFCliParaList[threadnum].CountCNFClientStartOrder4_Waiting++;

	if(cnfINTRACOMMUNICATION == 0)
	{
		recvfrom(CNFCliParaList[threadnum].RECVCNFClientStartOrder4,Trigger,20,0,(struct sockaddr *)&CNFCliParaList[threadnum].RECVAddrToCNFClientStartOrder4,&SockAddrLength);
	}
	else if(cnfINTRACOMMUNICATION == 1)
	{
		sem_wait(&CNFCliParaList[threadnum].semCNFClientStartOrder4);
	}

	if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
		printf("[%d] StartOrder4 triggered!\n",CNFCliParaList[threadnum].CountCNFClientStartOrder4_Triggered);
	CNFCliParaList[threadnum].CountCNFClientStartOrder4_Triggered++;

	//向网络请求一个SID文件
	/*
	在此处添加SID转接代码
	变量realPath即为SID
	输出接口：SID
	输出对象：CoLoR协议GET包封装程序
	输出方式：1、文件存取（因延迟较大并不建议）；2、socket发送本地回环消息
	*/
	
	//赋值SID
	uint8_t SID[SIDLEN];
	memset(SID,0,SIDLEN);
	strcpy(SID,"wangzhaoxu");
	if(cnfcliDEVETESTIMPL <= 0)
		printf("\n[SID  ]  %s\n",SID);
	
	uint8_t offset[OFFLEN];
	/*
	unsigned long filelen = FILELEN;//接收的文件大小
	*/
	unsigned long cachelen = CACHESIZE;

	uint8_t sendpkg[sizeof(CoLoR_ack)+3];
	CoLoR_ack * psendpkg;
	psendpkg = (CoLoR_ack *)(sendpkg+3);

	int LocalPkgBUFHead;
	while(CNFCliParaList[threadnum].OffsetConfirmDATA <= cachelen)
	{
		memset(sendpkg,0,sizeof(CoLoR_ack)+3);
		memcpy(sendpkg,"FOR",3);

		if(CNFCliParaList[threadnum].TimingState == 0)//未超时
		{
			CNFCliParaList[threadnum].OffsetWaitDATA += 0;
		}
		else if(CNFCliParaList[threadnum].TimingState == 1)//超时
		{
		}
		//printf("[Down]OffsetWaitDATA = %ld\n",CNFCliParaList[threadnum].OffsetWaitDATA);
		
		//计算待确认的偏移量值
		offset[3] = CNFCliParaList[threadnum].OffsetWaitDATA % 256;
		offset[2] = CNFCliParaList[threadnum].OffsetWaitDATA / 256 % 256;
		offset[1] = CNFCliParaList[threadnum].OffsetWaitDATA / 256 / 256 % 256;
		offset[0] = CNFCliParaList[threadnum].OffsetWaitDATA / 256 / 256 / 256 % 256;
		
		//封装传输层ACK包
		CNFClient_PacketACK(psendpkg,SID,offset);
		//strcpy(psendpkg->sid,SID);
		//memcpy(psendpkg->offset,offset,OFFLEN);

				//发送ACK传输包
				if(INTRACOMMUNICATION == 0)
				{
					sendto(CNFCliParaList[threadnum].SENDCNFClientACK,sendpkg,sizeof(CoLoR_ack)+3,0,(struct sockaddr *)&CNFCliParaList[threadnum].SENDAddrToCNFClientACK,SockAddrLength);
				}
				else if(INTRACOMMUNICATION == 1)
				{
					//数据包进入转发缓冲队列（此处需要线程锁）
					pthread_mutex_lock(&lockPkgBUF);
					if(PkgBUF[PkgBUFHead].flag_occupied == 0)
					{
						LocalPkgBUFHead = PkgBUFHead;
						PkgBUFHead++;
						if(PkgBUFHead >=10)
							PkgBUFHead -= 10;
		
						PkgBUF[LocalPkgBUFHead].flag_occupied = 1;
						PkgBUF[LocalPkgBUFHead].destppnum = portnum;
						PkgBUF[LocalPkgBUFHead].pkglength = sizeof(CoLoR_ack);
						strcpy(PkgBUF[LocalPkgBUFHead].sourcepp,CNFThreadList[threadnum].physicalport);
						memcpy(PkgBUF[LocalPkgBUFHead].pkg,sendpkg+3,sizeof(CoLoR_ack));
		
						//触发网络层信号量
						sem_post(&semPacketSEND[portnum]);

						if(cnfcliDEVETESTIMPL <= 1)
						{
							printf("[%s] SEQ Message has been sent\n",CNFThreadList[threadnum].physicalport);
							printf("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n\n");
						}
					}
					else
					{
						if(cnfcliDEVETESTIMPL <= 1)
						{
							printf("[%s] SEQ Message failed to be sent\n",CNFThreadList[threadnum].physicalport);
							printf("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n\n");
						}
					}
					pthread_mutex_unlock(&lockPkgBUF);
				}

		if(cnfcliDEVETESTIMPL <= 1)
			printf("[Transport Layer] The CNFClient asked for Data whitch match the SID: %s\n",SID);

		//触发反馈计时
		if(cnfINTRACOMMUNICATION == 0)
		{
			sendto(CNFCliParaList[threadnum].SENDCNFClientTimingBegin,"TimingBegin",20,0,(struct sockaddr *)&CNFCliParaList[threadnum].SENDAddrToCNFClientTimingBegin,SockAddrLength);
		}
		else if(cnfINTRACOMMUNICATION == 1)
		{
			sem_post(&CNFCliParaList[threadnum].semCNFClientTimingBegin);
		}

		if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
			printf("[%d] TimingBegin triggering...\n",CNFCliParaList[threadnum].CountCNFClientTimingBegin_Triggering);
		CNFCliParaList[threadnum].CountCNFClientTimingBegin_Triggering++;

		if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
			printf("[%d] TimingRespond waiting...\n",CNFCliParaList[threadnum].CountCNFClientTimingRespond_Waiting);
		CNFCliParaList[threadnum].CountCNFClientTimingRespond_Waiting++;

		//等待触发回送ACK
		if(cnfINTRACOMMUNICATION == 0)
		{
			recvfrom(CNFCliParaList[threadnum].RECVCNFClientTimingRespond,Trigger,20,0,(struct sockaddr *)&CNFCliParaList[threadnum].RECVAddrToCNFClientTimingRespond,&SockAddrLength);
		}
		else if(cnfINTRACOMMUNICATION == 1)
		{
			sem_wait(&CNFCliParaList[threadnum].semCNFClientTimingRespond);
		}
		if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
			printf("[%d] TimingRespond triggered!\n",CNFCliParaList[threadnum].CountCNFClientTimingRespond_Triggered);
		CNFCliParaList[threadnum].CountCNFClientTimingRespond_Triggered++;
		
		//结束判断：收到的数据长度累积超过预知文件长度的逻辑容忍范围（逻辑容忍范围是文件长度+单包长度）
		if(CNFCliParaList[threadnum].OffsetConfirmDATA >= cachelen)
		{
			if(cnfcliDEVETESTIMPL <= 6)
				printf("[END message]Received File Length is Bigger Than the File Length Ever known.\n");
			
			CNFCliParaList[threadnum].FlagInputBUF = 0;

			//通知向文件写入数据
			if(cnfINTRACOMMUNICATION == 0)
			{
				sendto(CNFCliParaList[threadnum].SENDCNFClientWriteData,"WriteData",20,0,(struct sockaddr *)&CNFCliParaList[threadnum].SENDAddrToCNFClientWriteData,SockAddrLength);
			}
			else if(cnfINTRACOMMUNICATION == 1)
			{
				sem_post(&CNFCliParaList[threadnum].semCNFClientWriteData);
			}
			if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
				printf("[%d] WriteData triggering...\n",CNFCliParaList[threadnum].CountCNFClientWriteData_Triggering);
			CNFCliParaList[threadnum].CountCNFClientWriteData_Triggering++;
		}
		//写入文件判断
		else if(CNFCliParaList[threadnum].OffsetConfirmDATA / ( CNFCliParaList[threadnum].BUFLength / 2 ) >= CNFCliParaList[threadnum].BUFRenewCount + 1)
		{
			//通知向文件写入数据
			if(cnfINTRACOMMUNICATION == 0)
			{
				sendto(CNFCliParaList[threadnum].SENDCNFClientWriteData,"WriteData",20,0,(struct sockaddr *)&CNFCliParaList[threadnum].SENDAddrToCNFClientWriteData,SockAddrLength);
			}
			else if(cnfINTRACOMMUNICATION == 1)
			{
				sem_post(&CNFCliParaList[threadnum].semCNFClientWriteData);
			}

			if(cnfcliDEVETESTIMPL <= 1 || CNFclientTRIGGERTEST == 1)
				printf("[%d] WriteData triggering...\n",CNFCliParaList[threadnum].CountCNFClientWriteData_Triggering);
			CNFCliParaList[threadnum].CountCNFClientWriteData_Triggering++;
		}
	}
	
	if(cnfcliDEVETESTIMPL <= 6)
		printf("[Down]File transport end.\n");
	
	sleep(10000);
	//关闭线程
	//exit(0);
	//free(fd);
	//pthread_exit(NULL);
}

/*****************************************
* 函数名称：CNFClient_PacketACK
* 功能描述：组装不含mac层的Get包
* 参数列表：
* 返回结果：
*****************************************/
int
CNFClient_PacketACK
(
	uint8_t * pkg,
	uint8_t * SID,
	uint8_t * OFF
)
{
	CoLoR_ack * getpkg;
	getpkg = (CoLoR_ack *)pkg;
	
	//填充CoLoR-Get包文
	getpkg->version_type = 164;//版本4位，类型4位，此为设置成CoLoR_ack包
	getpkg->ttl = 255;//生存时间
	//getpkg->data_len = htons(4);
	getpkg->total_len = 16 + 16 + SIDLEN + NIDLEN + DATALEN + PUBKEYLEN + PIDN*4;//总长度
	
	getpkg->port_no = 0;//端口号
	getpkg->checksum = 0;//检验和
	
	getpkg->sid_len = SIDLEN;//SID长度
	getpkg->nid_len = NIDLEN;//NID长度
	getpkg->pid_n = PIDN;//PID长度
	getpkg->options_static = 0;//固定首部选项

	memset(getpkg->offset,0,OFFLEN);
	memcpy(getpkg->offset,OFF,OFFLEN);
	
	memcpy(getpkg->sid, SID, SIDLEN);//SID

	char nid[NIDLEN] = {'d','1','s','u','b','1',0,0,'d','1','r','m',0,0,0,0};
	memcpy(getpkg->nid, sendnid, NIDLEN);//NID
	
	getpkg->publickey_len = PUBKEYLEN;
	getpkg->mtu = MTU;
	
	char data[DATALEN] = {'I',' ','a','m',' ','t','h','e',' ','d','a','t','a','~','~','~','~','~','~','!'};
	memcpy(getpkg->data, data, DATALEN);//Data
	
	char publickey[PUBKEYLEN] = {'I',' ','a','m',' ','t','h','e',' ','p','u','b','k','e','y','!'};
	memcpy(getpkg->publickey, publickey, PUBKEYLEN);//公钥

	return 1;
}

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
)
{
	//printf("BUF = \n%s\n",CacheList[0].cache);//检查整个数据块的输出
	
	//对CNFClient模块进行线程调用的参数拷贝接口
	struct cnfcliinput * cnfinput;
	cnfinput = (struct cnfcliinput *)fd;
	
	int threadnum = cnfinput->threadnum;
	
	if(cnfcliDEVETESTIMPL <= 6)
		printf("CNF threadnum == %d (CNFClient_main)\n",threadnum);
	
	CNFClient_Parameterinit(threadnum);

	//创建发送计时器子线程
	if(pthread_create(&CNFCliParaList[threadnum].pthread_timer, NULL, CNFClient_thread_timer, fd)!=0)
	{
		perror("Creation of timer thread failed.");
	}
	
	//创建CNF主子线程
	if(pthread_create(&CNFCliParaList[threadnum].pthread_CNF, NULL, CNFClient_thread_CNF, fd)!=0)
	{
		perror("Creation of CNF thread failed.");
	}

	//创建thread_FTP子线程
	if(pthread_create(&CNFCliParaList[threadnum].pthread_FTP, NULL, CNFClient_thread_FTP, fd)!=0)
	{
		perror("Creation of FTP thread failed.");
	}
	
	//创建thread_NetworkLayertoTransportLayer上行子线程
	if(pthread_create(&CNFCliParaList[threadnum].pthread_NetworkLayertoTransportLayer, NULL, CNFClient_thread_NetworkLayertoTransportLayer, fd)!=0)
	{
		perror("Creation of NetworkLayertoTransportLayer thread failed.");
	}
	
	//创建thread_TransportLayertoNetworkLayer下行子线程
	if(pthread_create(&CNFCliParaList[threadnum].pthread_TransportLayertoNetworkLayer, NULL, CNFClient_thread_TransportLayertoNetworkLayer, fd)!=0)
	{
		perror("Creation of TransportLayertoNetworkLayer thread failed.");
	}

	//主循环——客户端代码
	while (!CNFThreadList[threadnum].flag_close)
	{
		sleep(1);
	}
}

/*****************************************
* 函数名称：CNFClientStart_main
* 功能描述：CNFClient总起函数，启动CNFClient的TCP传输模块，和下层Subscriber协议栈模块
* 参数列表：
eg: ./sub d1sub1 d1sub1-eth1
第二参数使用char**argv的方式声明报错，不知是不是语法问题
* 返回结果：
*****************************************/
int
CNFClientStart_main
(
	int argc,
	char argv[][30]
)
{
	int i;

	for(i=0;i<CACHESIZE;i++)
		printf("%d",CacheList[TESTCACHENO].cache[i]);
	printf("\n");

	//创建CNFClient模块主子线程
	struct cnfcliinput cnfinput;
	cnfinput.threadnum = TESTNO;
	memset(cnfinput.sid,0,SIDLEN);
	
	pthread_t pthread_cnfclient;
	
	//创建子线程
	if(pthread_create(&pthread_cnfclient, NULL, CNFClient_main, (void *)&cnfinput)!=0)
	{
		perror("Creation of CNF Client main thread failed.");
	}

	//主循环——客户端代码
	while (1)
	{
		sleep(10000);
	}
}
