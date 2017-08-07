/*******************************************************************************************************************************************
* 文件名：cnfserver.c
* 文件描述：973智慧协同网络SAR系统TestBed套件——最简化通用服务端程序，下端连接数据发布端（Data Publisher）
* 声明：本模板代码作者王兆旭，为北京交通大学下一代互联网互联设备国家工程实验室新生基础工程技术培训专用。作者王兆旭在此郑重声明，此文件及其它用于培训的模板代码均为本人精力与经验的产物，本资源的传播方式均为作者本人向他人进行一对一传授，任何个人不得向第三方转交或展示该资源内容。任何有需求的学员，均须向王兆旭本人直接索要，亦无向他人索要或传授之权利和义务。因有些资源内容涉及实验室项目秘密，暂不考虑申请专利保护或软件著作权等事宜，故个别资源仅限实验室内部一对一发放，如发现有辜负作者本人的一片好意的行为，作者将保留就其原创性进行追查、举证、申诉和问责的权利。本资源的发放权归作者本人所有，其整理和总结过程浸透无偿贡献的热忱和为诸君学业尽绵薄之力的真诚，愿学员尊重作者的劳动成果，谢谢合作！
* 作者：王兆旭
* 身份：北京交通大学下一代互联网互联设备国家工程实验室 2013级硕博连读研究生
* E-mail. hellozxwang@foxmail.com
* Mobile. 18811774990
* QQ    . 535667240
* Addr  . 北京市海淀区西直门外北京交通大学机械楼D706室, 100044
*******************************************************************************************************************************************/
/*******************************************************************************************************************************************
*****功能说明：1.向物理网口发送包含请求SID对应Data的DATA类型包
**************2.接收由物理网口监听的SAR/CoLoR类型数据包；
**************3.从接收到的GET包中提取SID
**************4.本地查询缓存内容，找到SID匹配的Data内容
*******************************************************************************************************************************************/
/*
快速配置步骤：
1、宏定义修改
CACHEPATH指存储SID与Data匹配关系的文件，默认文件名cache.log，路径需要运行该程序的人员自行决定，能与该文件实际存在的位置对上号就行了
PhysicalPort指CoLoR协议发出Get包和接收Data包的网卡端口，注意网卡的默认有线端口名称是否为eth0，而Fedora20系统中的默认名称为em1，请注意识别
2、系统设置
在Fedora系统中因需要使用原始套接字发送自定义格式的数据包，须关闭Fedora的防火墙，命令：
sudo systemctl stop firewalld.service
在Ubuntu系统中无需任何操作
3、编译命令
gcc cnfserver.c -o cnfserver -lpthread
4、运行（因涉及原始套接字的使用，须root权限）
sudo ./cnfserver
*/

#include"cnfserver.h"

/*******************************************************************************************************************************************
*************************************宏定义配置数据************全局变量定义******************************************************************
*******************************************************************************************************************************************/

/*******************************************************************************************************************************************
*******************************************初始化参数配置相关********************************************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：CNFServer_Parameterinit
* 功能描述：CNFServer模块全局变量赋初值
* 参数列表：
* 返回结果：
*****************************************/
void
CNFServer_Parameterinit
(
	int threadnum
)
{
	CNFSerParaList[threadnum].LostPacketCount=0;
	CNFSerParaList[threadnum].InputCount=0;
	CNFSerParaList[threadnum].TotalWindowLength=0;

	//创建并打开客户端接收文件
	CNFSerParaList[threadnum].LogFilePoint = open(LOGFilePath,O_RDWR | O_CREAT | O_APPEND | O_TRUNC);
	/*
	if(CNFSerParaList[threadnum].LogFilePoint == -1)
	{
		printf("[Deadly Error] The Log File \"%s\" opening failed.\n",FTPClientPath);
		exit(0);
	}
	*/

	//初始化测试用缓存内容
	/*
	int i;	
	for(i=0;i<CACHENUM;i++)
	{
		memset(CacheList[i].cache,'A',CACHESIZE);
		CacheList[i].cachetop = 0;
	}
	*/


	SockAddrLength = sizeof(struct sockaddr_in);

	//SEG发送socket
	bzero(&CNFSerParaList[threadnum].SENDAddrToCNFServerSEG,SockAddrLength);
	CNFSerParaList[threadnum].SENDAddrToCNFServerSEG.sin_family=AF_INET;
	CNFSerParaList[threadnum].SENDAddrToCNFServerSEG.sin_addr.s_addr=inet_addr(CNFThreadList[threadnum].physicalportIP);
	CNFSerParaList[threadnum].SENDAddrToCNFServerSEG.sin_port=htons(PhysicalportInterPORT);

	CNFSerParaList[threadnum].SENDCNFServerSEG = socket(AF_INET,SOCK_DGRAM,0);

	//ACK监听socket
	bzero(&CNFSerParaList[threadnum].RECVAddrToCNFServerACK,SockAddrLength);
	CNFSerParaList[threadnum].RECVAddrToCNFServerACK.sin_family=AF_INET;
	CNFSerParaList[threadnum].RECVAddrToCNFServerACK.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFSerParaList[threadnum].RECVAddrToCNFServerACK.sin_port=htons(PhysicalportInterPORT + threadnum * CNFPORTRANGE);

	CNFSerParaList[threadnum].RECVCNFServerACK = socket(AF_INET,SOCK_DGRAM,0);

	bind(CNFSerParaList[threadnum].RECVCNFServerACK,(struct sockaddr *)&CNFSerParaList[threadnum].RECVAddrToCNFServerACK,SockAddrLength);

	//窗口传输开始
	CNFSerParaList[threadnum].CountCNFServerWindowBegin_Triggering = 1;
	CNFSerParaList[threadnum].CountCNFServerWindowBegin_Waiting = 1;
	CNFSerParaList[threadnum].CountCNFServerWindowBegin_Triggered = 1;
/*
	printf("[%d] WindowBegin triggering...\n",CNFSerParaList[threadnum].CountCNFServerWindowBegin_Triggering);
	CNFSerParaList[threadnum].CountCNFServerWindowBegin_Triggering++;
	printf("[%d] WindowBegin waiting...\n",CNFSerParaList[threadnum].CountCNFServerWindowBegin_Waiting);
	CNFSerParaList[threadnum].CountCNFServerWindowBegin_Waiting++;
	printf("[%d] WindowBegin triggered!\n",CNFSerParaList[threadnum].CountCNFServerWindowBegin_Triggered);
	CNFSerParaList[threadnum].CountCNFServerWindowBegin_Triggered++;
*/
	bzero(&CNFSerParaList[threadnum].SENDAddrToCNFServerWindowBegin,SockAddrLength);
	CNFSerParaList[threadnum].SENDAddrToCNFServerWindowBegin.sin_family=AF_INET;
	CNFSerParaList[threadnum].SENDAddrToCNFServerWindowBegin.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFSerParaList[threadnum].SENDAddrToCNFServerWindowBegin.sin_port=htons(CNFServerWindowBegin + threadnum * CNFPORTRANGE);

	bzero(&CNFSerParaList[threadnum].RECVAddrToCNFServerWindowBegin,SockAddrLength);
	CNFSerParaList[threadnum].RECVAddrToCNFServerWindowBegin.sin_family=AF_INET;
	CNFSerParaList[threadnum].RECVAddrToCNFServerWindowBegin.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFSerParaList[threadnum].RECVAddrToCNFServerWindowBegin.sin_port=htons(CNFServerWindowBegin + threadnum * CNFPORTRANGE);

	CNFSerParaList[threadnum].SENDCNFServerWindowBegin = socket(AF_INET,SOCK_DGRAM,0);
	CNFSerParaList[threadnum].RECVCNFServerWindowBegin = socket(AF_INET,SOCK_DGRAM,0);

	bind(CNFSerParaList[threadnum].RECVCNFServerWindowBegin,(struct sockaddr *)&CNFSerParaList[threadnum].RECVAddrToCNFServerWindowBegin,SockAddrLength);

	//窗口传输上行通道结束计时
	CNFSerParaList[threadnum].CountCNFServerWindowTimingEnd_Triggering = 1;
	CNFSerParaList[threadnum].CountCNFServerWindowTimingEnd_Waiting = 1;
	CNFSerParaList[threadnum].CountCNFServerWindowTimingEnd_Triggered = 1;
/*
	printf("[%d] WindowTimingEnd triggering...\n",CNFSerParaList[threadnum].CountCNFServerWindowTimingEnd_Triggering);
	CNFSerParaList[threadnum].CountCNFServerWindowTimingEnd_Triggering++;
	printf("[%d] WindowTimingEnd waiting...\n",CNFSerParaList[threadnum].CountCNFServerWindowTimingEnd_Waiting);
	CNFSerParaList[threadnum].CountCNFServerWindowTimingEnd_Waiting++;
	printf("[%d] WindowTimingEnd triggered!\n",CNFSerParaList[threadnum].CountCNFServerWindowTimingEnd_Triggered);
	CNFSerParaList[threadnum].CountCNFServerWindowTimingEnd_Triggered++;
*/
	bzero(&CNFSerParaList[threadnum].SENDAddrToCNFServerWindowTimingEnd,SockAddrLength);
	CNFSerParaList[threadnum].SENDAddrToCNFServerWindowTimingEnd.sin_family=AF_INET;
	CNFSerParaList[threadnum].SENDAddrToCNFServerWindowTimingEnd.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFSerParaList[threadnum].SENDAddrToCNFServerWindowTimingEnd.sin_port=htons(CNFServerWindowTimingEnd + threadnum * CNFPORTRANGE);

	bzero(&CNFSerParaList[threadnum].RECVAddrToCNFServerWindowTimingEnd,SockAddrLength);
	CNFSerParaList[threadnum].RECVAddrToCNFServerWindowTimingEnd.sin_family=AF_INET;
	CNFSerParaList[threadnum].RECVAddrToCNFServerWindowTimingEnd.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFSerParaList[threadnum].RECVAddrToCNFServerWindowTimingEnd.sin_port=htons(CNFServerWindowTimingEnd + threadnum * CNFPORTRANGE);

	CNFSerParaList[threadnum].SENDCNFServerWindowTimingEnd = socket(AF_INET,SOCK_DGRAM,0);
	CNFSerParaList[threadnum].RECVCNFServerWindowTimingEnd = socket(AF_INET,SOCK_DGRAM,0);

	bind(CNFSerParaList[threadnum].RECVCNFServerWindowTimingEnd,(struct sockaddr *)&CNFSerParaList[threadnum].RECVAddrToCNFServerWindowTimingEnd,SockAddrLength);

	//窗口传输下行通道反馈结果
	CNFSerParaList[threadnum].CountCNFServerWindowRespond_Triggering = 1;
	CNFSerParaList[threadnum].CountCNFServerWindowRespond_Waiting = 1;
	CNFSerParaList[threadnum].CountCNFServerWindowRespond_Triggered = 1;
/*
	printf("[%d] WindowRespond triggering...\n",CNFSerParaList[threadnum].CountCNFServerWindowRespond_Triggering);
	CNFSerParaList[threadnum].CountCNFServerWindowRespond_Triggering++;
	printf("[%d] WindowRespond waiting...\n",CNFSerParaList[threadnum].CountCNFServerWindowRespond_Waiting);
	CNFSerParaList[threadnum].CountCNFServerWindowRespond_Waiting++;
	printf("[%d] WindowRespond triggered!\n",CNFSerParaList[threadnum].CountCNFServerWindowRespond_Triggered);
	CNFSerParaList[threadnum].CountCNFServerWindowRespond_Triggered++;
*/
	bzero(&CNFSerParaList[threadnum].SENDAddrToCNFServerWindowRespond,SockAddrLength);
	CNFSerParaList[threadnum].SENDAddrToCNFServerWindowRespond.sin_family=AF_INET;
	CNFSerParaList[threadnum].SENDAddrToCNFServerWindowRespond.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFSerParaList[threadnum].SENDAddrToCNFServerWindowRespond.sin_port=htons(CNFServerWindowRespond + threadnum * CNFPORTRANGE);

	bzero(&CNFSerParaList[threadnum].RECVAddrToCNFServerWindowRespond,SockAddrLength);
	CNFSerParaList[threadnum].RECVAddrToCNFServerWindowRespond.sin_family=AF_INET;
	CNFSerParaList[threadnum].RECVAddrToCNFServerWindowRespond.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFSerParaList[threadnum].RECVAddrToCNFServerWindowRespond.sin_port=htons(CNFServerWindowRespond + threadnum * CNFPORTRANGE);

	CNFSerParaList[threadnum].SENDCNFServerWindowRespond = socket(AF_INET,SOCK_DGRAM,0);
	CNFSerParaList[threadnum].RECVCNFServerWindowRespond = socket(AF_INET,SOCK_DGRAM,0);

	bind(CNFSerParaList[threadnum].RECVCNFServerWindowRespond,(struct sockaddr *)&CNFSerParaList[threadnum].RECVAddrToCNFServerWindowRespond,SockAddrLength);

	//发送缓冲启动
	CNFSerParaList[threadnum].CountCNFServerBufReady_Triggering = 1;
	CNFSerParaList[threadnum].CountCNFServerBufReady_Waiting = 1;
	CNFSerParaList[threadnum].CountCNFServerBufReady_Triggered = 1;
/*
	printf("[%d] BufReady triggering...\n",CNFSerParaList[threadnum].CountCNFServerBufReady_Triggering);
	CNFSerParaList[threadnum].CountCNFServerBufReady_Triggering++;
	printf("[%d] BufReady waiting...\n",CNFSerParaList[threadnum].CountCNFServerBufReady_Waiting);
	CNFSerParaList[threadnum].CountCNFServerBufReady_Waiting++;
	printf("[%d] BufReady triggered!\n",CNFSerParaList[threadnum].CountCNFServerBufReady_Triggered);
	CNFSerParaList[threadnum].CountCNFServerBufReady_Triggered++;
*/
	bzero(&CNFSerParaList[threadnum].SENDAddrToCNFServerBufReady,SockAddrLength);
	CNFSerParaList[threadnum].SENDAddrToCNFServerBufReady.sin_family=AF_INET;
	CNFSerParaList[threadnum].SENDAddrToCNFServerBufReady.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFSerParaList[threadnum].SENDAddrToCNFServerBufReady.sin_port=htons(CNFServerBufReady + threadnum * CNFPORTRANGE);

	bzero(&CNFSerParaList[threadnum].RECVAddrToCNFServerBufReady,SockAddrLength);
	CNFSerParaList[threadnum].RECVAddrToCNFServerBufReady.sin_family=AF_INET;
	CNFSerParaList[threadnum].RECVAddrToCNFServerBufReady.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFSerParaList[threadnum].RECVAddrToCNFServerBufReady.sin_port=htons(CNFServerBufReady + threadnum * CNFPORTRANGE);

	CNFSerParaList[threadnum].SENDCNFServerBufReady = socket(AF_INET,SOCK_DGRAM,0);
	CNFSerParaList[threadnum].RECVCNFServerBufReady = socket(AF_INET,SOCK_DGRAM,0);

	bind(CNFSerParaList[threadnum].RECVCNFServerBufReady,(struct sockaddr *)&CNFSerParaList[threadnum].RECVAddrToCNFServerBufReady,SockAddrLength);

	//供应后续数据
	CNFSerParaList[threadnum].CountCNFServerMoreData_Triggering = 1;
	CNFSerParaList[threadnum].CountCNFServerMoreData_Waiting = 1;
	CNFSerParaList[threadnum].CountCNFServerMoreData_Triggered = 1;
/*
	printf("[%d] MoreData triggering...\n",CNFSerParaList[threadnum].CountCNFServerMoreData_Triggering);
	CNFSerParaList[threadnum].CountCNFServerMoreData_Triggering++;
	printf("[%d] MoreData waiting...\n",CNFSerParaList[threadnum].CountCNFServerMoreData_Waiting);
	CNFSerParaList[threadnum].CountCNFServerMoreData_Waiting++;
	printf("[%d] MoreData triggered!\n",CNFSerParaList[threadnum].CountCNFServerMoreData_Triggered);
	CNFSerParaList[threadnum].CountCNFServerMoreData_Triggered++;
*/
	bzero(&CNFSerParaList[threadnum].SENDAddrToCNFServerMoreData,SockAddrLength);
	CNFSerParaList[threadnum].SENDAddrToCNFServerMoreData.sin_family=AF_INET;
	CNFSerParaList[threadnum].SENDAddrToCNFServerMoreData.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFSerParaList[threadnum].SENDAddrToCNFServerMoreData.sin_port=htons(CNFServerMoreData + threadnum * CNFPORTRANGE);

	bzero(&CNFSerParaList[threadnum].RECVAddrToCNFServerMoreData,SockAddrLength);
	CNFSerParaList[threadnum].RECVAddrToCNFServerMoreData.sin_family=AF_INET;
	CNFSerParaList[threadnum].RECVAddrToCNFServerMoreData.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFSerParaList[threadnum].RECVAddrToCNFServerMoreData.sin_port=htons(CNFServerMoreData + threadnum * CNFPORTRANGE);

	CNFSerParaList[threadnum].SENDCNFServerMoreData = socket(AF_INET,SOCK_DGRAM,0);
	CNFSerParaList[threadnum].RECVCNFServerMoreData = socket(AF_INET,SOCK_DGRAM,0);

	bind(CNFSerParaList[threadnum].RECVCNFServerMoreData,(struct sockaddr *)&CNFSerParaList[threadnum].RECVAddrToCNFServerMoreData,SockAddrLength);

	//文件读取结束
	CNFSerParaList[threadnum].CountCNFServerFileClose_Triggering = 1;
	CNFSerParaList[threadnum].CountCNFServerFileClose_Waiting = 1;
	CNFSerParaList[threadnum].CountCNFServerFileClose_Triggered = 1;
/*
	printf("[%d] FileClose triggering...\n",CNFSerParaList[threadnum].CountCNFServerFileClose_Triggering);
	CNFSerParaList[threadnum].CountCNFServerFileClose_Triggering++;
	printf("[%d] FileClose waiting...\n",CNFSerParaList[threadnum].CountCNFServerFileClose_Waiting);
	CNFSerParaList[threadnum].CountCNFServerFileClose_Waiting++;
	printf("[%d] FileClose triggered!\n",CNFSerParaList[threadnum].CountCNFServerFileClose_Triggered);
	CNFSerParaList[threadnum].CountCNFServerFileClose_Triggered++;
*/
	bzero(&CNFSerParaList[threadnum].SENDAddrToCNFServerFileClose,SockAddrLength);
	CNFSerParaList[threadnum].SENDAddrToCNFServerFileClose.sin_family=AF_INET;
	CNFSerParaList[threadnum].SENDAddrToCNFServerFileClose.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFSerParaList[threadnum].SENDAddrToCNFServerFileClose.sin_port=htons(CNFServerFileClose + threadnum * CNFPORTRANGE);

	bzero(&CNFSerParaList[threadnum].RECVAddrToCNFServerFileClose,SockAddrLength);
	CNFSerParaList[threadnum].RECVAddrToCNFServerFileClose.sin_family=AF_INET;
	CNFSerParaList[threadnum].RECVAddrToCNFServerFileClose.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFSerParaList[threadnum].RECVAddrToCNFServerFileClose.sin_port=htons(CNFServerFileClose + threadnum * CNFPORTRANGE);

	CNFSerParaList[threadnum].SENDCNFServerFileClose = socket(AF_INET,SOCK_DGRAM,0);
	CNFSerParaList[threadnum].RECVCNFServerFileClose = socket(AF_INET,SOCK_DGRAM,0);

	bind(CNFSerParaList[threadnum].RECVCNFServerFileClose,(struct sockaddr *)&CNFSerParaList[threadnum].RECVAddrToCNFServerFileClose,SockAddrLength);

	//上行通道继续收包
	CNFSerParaList[threadnum].CountCNFServerContinueRECV_Triggering = 1;
	CNFSerParaList[threadnum].CountCNFServerContinueRECV_Waiting = 1;
	CNFSerParaList[threadnum].CountCNFServerContinueRECV_Triggered = 1;
/*
	printf("[%d] ContinueRECV triggering...\n",CNFSerParaList[threadnum].CountCNFServerContinueRECV_Triggering);
	CNFSerParaList[threadnum].CountCNFServerContinueRECV_Triggering++;
	printf("[%d] ContinueRECV waiting...\n",CNFSerParaList[threadnum].CountCNFServerContinueRECV_Waiting);
	CNFSerParaList[threadnum].CountCNFServerContinueRECV_Waiting++;
	printf("[%d] ContinueRECV triggered!\n",CNFSerParaList[threadnum].CountCNFServerContinueRECV_Triggered);
	CNFSerParaList[threadnum].CountCNFServerContinueRECV_Triggered++;
*/
	bzero(&CNFSerParaList[threadnum].SENDAddrToCNFServerContinueRECV,SockAddrLength);
	CNFSerParaList[threadnum].SENDAddrToCNFServerContinueRECV.sin_family=AF_INET;
	CNFSerParaList[threadnum].SENDAddrToCNFServerContinueRECV.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFSerParaList[threadnum].SENDAddrToCNFServerContinueRECV.sin_port=htons(CNFServerContinueRECV + threadnum * CNFPORTRANGE);

	bzero(&CNFSerParaList[threadnum].RECVAddrToCNFServerContinueRECV,SockAddrLength);
	CNFSerParaList[threadnum].RECVAddrToCNFServerContinueRECV.sin_family=AF_INET;
	CNFSerParaList[threadnum].RECVAddrToCNFServerContinueRECV.sin_addr.s_addr=inet_addr(LOOPIP);
	CNFSerParaList[threadnum].RECVAddrToCNFServerContinueRECV.sin_port=htons(CNFServerContinueRECV + threadnum * CNFPORTRANGE);

	CNFSerParaList[threadnum].SENDCNFServerContinueRECV = socket(AF_INET,SOCK_DGRAM,0);
	CNFSerParaList[threadnum].RECVCNFServerContinueRECV = socket(AF_INET,SOCK_DGRAM,0);

	bind(CNFSerParaList[threadnum].RECVCNFServerContinueRECV,(struct sockaddr *)&CNFSerParaList[threadnum].RECVAddrToCNFServerContinueRECV,SockAddrLength);

}

/*****************************************
* 函数名称：CNFServer_Parametershut
* 功能描述：终止该CNF整个任务并回收的所有资源
* 参数列表：
* 返回结果：
*****************************************/
void
CNFServer_Parametershut
(
	int threadnum
)
{
	//释放该CNF任务所有内部通信句柄
	close(CNFSerParaList[threadnum].SENDCNFServerSEG);
	close(CNFSerParaList[threadnum].RECVCNFServerACK);
	close(CNFSerParaList[threadnum].SENDCNFServerWindowBegin);
	close(CNFSerParaList[threadnum].RECVCNFServerWindowBegin);
	close(CNFSerParaList[threadnum].SENDCNFServerWindowTimingEnd);
	close(CNFSerParaList[threadnum].RECVCNFServerWindowTimingEnd);
	close(CNFSerParaList[threadnum].SENDCNFServerWindowRespond);
	close(CNFSerParaList[threadnum].RECVCNFServerWindowRespond);
	close(CNFSerParaList[threadnum].SENDCNFServerBufReady);
	close(CNFSerParaList[threadnum].RECVCNFServerBufReady);
	close(CNFSerParaList[threadnum].SENDCNFServerMoreData);
	close(CNFSerParaList[threadnum].RECVCNFServerMoreData);
	close(CNFSerParaList[threadnum].SENDCNFServerFileClose);
	close(CNFSerParaList[threadnum].RECVCNFServerFileClose);
	close(CNFSerParaList[threadnum].SENDCNFServerContinueRECV);
	close(CNFSerParaList[threadnum].RECVCNFServerContinueRECV);

	//释放该CNF任务所有变量
	//(在任务开始时有初始化代码)
	
	//释放CacheList缓存位置
	int CacheLocation = CNFThreadList[threadnum].cachelocation;
	memset(CacheList[CacheLocation].physicalport,0,30);
	memset(CacheList[CacheLocation].sid,0,SIDLEN);
	memset(CacheList[CacheLocation].sbd,0,SBDLEN);
	memset(CacheList[CacheLocation].offset,0,OFFLEN);
	memset(CacheList[CacheLocation].cache,0,CACHESIZE);
	CacheList[CacheLocation].cachetop = 0;
	CacheList[CacheLocation].datapkglocation = -1;
	CacheList[CacheLocation].flag_ack = 0;

	//释放CNF任务序号
	CNFThreadList[threadnum].flag_IO = -1;
	CNFThreadList[threadnum].datapkglocation = -1;
	CNFThreadList[threadnum].cachelocation = -1;
	memset(CNFThreadList[threadnum].physicalport,0,30);
	memset(CNFThreadList[threadnum].physicalportIP,0,16);
	memset(CNFThreadList[threadnum].sid,0,SIDLEN);
	memset(CNFThreadList[threadnum].offset,0,OFFLEN);
	
	//对任务解除占用
	CacheList[CacheLocation].flag_occupied = 0;
	CNFThreadList[threadnum].flag_occupied = 0;
	
	if(cnfserDEVETESTIMPL <= 6)
		printf("threadnum %d released.\n",threadnum);
}

/*******************************************************************************************************************************************
*******************************************应用层CNFServer服务器（通过CLI控制）******************************************************************
*******************************************************************************************************************************************/

/*******************************************************************************************************************************************
*******************************************上行通道 - From.数据响应端   To.应用服务器*********************************************************
*******************************************************************************************************************************************/

/*******************************************************************************************************************************************
*******************************************下行通道 - From.应用服务器 To.数据响应端***********************************************************
*******************************************************************************************************************************************/

/*******************************************************************************************************************************************
**********************************************************多线程主干程序********************************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：CNFServer_thread_timer
* 功能描述：为各线程提供计时信号
* 参数列表：
* 返回结果：
*****************************************/
void *
CNFServer_thread_timer
(
	void * fd
)
{
	//对CNFServer模块进行线程调用的参数拷贝接口
	struct cnfserinput * cnfinput;
	cnfinput = (struct cnfserinput *)fd;
	
	int threadnum = cnfinput->threadnum;
	
	if(cnfserDEVETESTIMPL <= 6)
		printf("CNF threadnum == %d (CNFServer_thread_timer)\n",threadnum);

	CNFSerParaList[threadnum].timer_XX = 0;
	
	while(1)
	{
		//sleep(10000);
		sleep(SLEEP);
		CNFSerParaList[threadnum].timer_XX++;
		
		//time(&GMT);//读取GMT，赋值给GMT
		//UTC = localtime(&GMT);//GMT-UTC转换
		//printf("GMT(long)   %ld\n",GMT);//[GMT]输出1970.1.1.00:00:00至今秒数
		//printf("UTC(human)  %s",asctime(UTC));//[UTC]输出字符化人类可读时间
	}

	sleep(10000);
	//关闭线程
	//exit(0);
	//free(fd);
	//pthread_exit(NULL);
}

/*****************************************
* 函数名称：CNFServer_thread_CNF
* 功能描述：上行通道 - CNF服务端任务控制主子线程
* 参数列表：
* 返回结果：
*****************************************/
void *
CNFServer_thread_CNF
(
	void * fd
)
{
	//对CNFServer模块进行线程调用的参数拷贝接口
	struct cnfserinput * cnfinput;
	cnfinput = (struct cnfserinput *)fd;
	
	int threadnum = cnfinput->threadnum;
	
	if(cnfserDEVETESTIMPL <= 6)
		printf("CNF threadnum == %d (CNFServer_thread_CNF)\n",threadnum);

	uint8_t PhysicalportIP[16];
	memcpy(PhysicalportIP,cnfinput->physicalportIP,16);

	int i,j;
	
	//用作接收SID请求的处理存储变量
	uint8_t SID[SIDLEN];
	uint8_t OFFSET[OFFLEN];
	unsigned long offsetlong;
	uint8_t DATA[DATALEN];
	int SIDlen=0,DATAlen=0;
	
	uint8_t recvpkg[sizeof(CoLoR_ack)];
	CoLoR_ack * precvpkg;
	precvpkg = (CoLoR_ack *)recvpkg;

	int SingleThreadAlreadyStart = 0;
	int FoundSIDNum;
	while(1)
	{
		i=0;
		j=0;

		offsetlong = 0;
		SIDlen = 0;
		DATAlen = 0;
		memset(SID,0,SIDLEN);
		memset(OFFSET,0,OFFLEN);
		memset(DATA,0,DATALEN);
		memset(recvpkg,0,sizeof(CoLoR_ack));

		FoundSIDNum=-1;

		recvfrom(CNFSerParaList[threadnum].RECVCNFServerACK,recvpkg,sizeof(CoLoR_ack),0,(struct sockaddr *)&CNFSerParaList[threadnum].RECVAddrToCNFServerACK,&SockAddrLength);

		//提取SID与offset
		memcpy(SID,precvpkg->sid,SIDLEN);
		memcpy(OFFSET,precvpkg->offset,OFFLEN);
		SIDlen = 10;

		if(cnfserDEVETESTIMPL <= 4)
		{
			printf("[NetworkLayer to TransportLayer]SID = %s\n",SID);
			printf("[NetworkLayer to TransportLayer]OFF = %d %d %d %d\n",OFFSET[0],OFFSET[1],OFFSET[2],OFFSET[3]);
		}

		//至此CNF网络层上行接口做好
		
		//判断OFFSET是0还是大于0，借此判定收到的GET消息是 新任务请求消息 还是 某已有任务的ACK
		if(OFFSET[0] == 0 && OFFSET[1] == 0 && OFFSET[2] == 3 && OFFSET[3] == 232 && SingleThreadAlreadyStart == 0)//这是新任务请求（暂时将任务数量定为1）
		{
			if(cnfserDEVETESTIMPL <= 6)
				printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>A New Service Started.\n");

			SingleThreadAlreadyStart = 1;
			
			//初始化任务线程控制参数组
			memset(CNFSerParaList[threadnum].SID,0,SIDLEN);
			memcpy(CNFSerParaList[threadnum].SID,SID,SIDlen);
			CNFSerParaList[threadnum].SIDLen = SIDlen;
	
			CNFSerParaList[threadnum].BUF = NULL;//发送缓冲区开头
			CNFSerParaList[threadnum].BUFEnd = NULL;//发送缓冲区结尾
			CNFSerParaList[threadnum].BUFFileEnd = NULL;//读取文件结束时，缓冲区内文件末尾所在地址

			CNFSerParaList[threadnum].BUFRenewCount = 1;//缓冲区更新次数
			CNFSerParaList[threadnum].BUFLength = CNFBUFSIZE;//发送缓冲长度

			CNFSerParaList[threadnum].FileReadPoint = 0;//文件读取进度
			CNFSerParaList[threadnum].FileLength = 0;//文件总长度

			CNFSerParaList[threadnum].PacketDataLength = PKTDATALEN;//单包数据段长度
			CNFSerParaList[threadnum].LastPacketDataLength = PKTDATALEN;//整个传输任务的最后一个数据包实际长度

			CNFSerParaList[threadnum].WindowLength = 1;//窗口长度
			CNFSerParaList[threadnum].WindowThreshold = CNFBUFSIZE;//窗口门限值

			CNFSerParaList[threadnum].OffsetWindowHead = 0;//在整个文件中窗口头部所指的偏移量
			CNFSerParaList[threadnum].OffsetWindowEnd = PKTDATALEN;//在整个文件中窗口尾部所指的偏移量
			CNFSerParaList[threadnum].OffsetConfirmACK = 0;//在整个文件中已确认偏移量所在偏移量
			CNFSerParaList[threadnum].OffsetRequestACK = 0;//在整个文件中接到请求的偏移量
			CNFSerParaList[threadnum].OffsetPacket = PKTDATALEN;//在整个文件中当前封包偏移量（回传数据包偏移量字段的填写依据）
			CNFSerParaList[threadnum].OffsetWaitACK = PKTDATALEN;//在整个文件中等待确认收到的偏移量（下一节）

			CNFSerParaList[threadnum].AddrWindowHead = NULL;//在缓冲区中窗口头部所在地址
			CNFSerParaList[threadnum].AddrWindowEnd = NULL;//在缓冲区中窗口尾部所在地址
			CNFSerParaList[threadnum].AddrConfirmACK = NULL;//在缓冲区中已确认偏移量所在地址
			CNFSerParaList[threadnum].AddrRequestACK = NULL;//在缓冲区中接到请求的所在地址
			CNFSerParaList[threadnum].AddrPacket = NULL;//在缓冲区中当前封包偏移量所在地址
			CNFSerParaList[threadnum].AddrWaitACK = NULL;//在缓冲区中待确认偏移量所在地址

			CNFSerParaList[threadnum].RTOs = 0;//往返容忍时延（RTO大于1秒部分，单位秒）
			CNFSerParaList[threadnum].RTOus = 0;//往返容忍时延（RTO小于1秒部分，单位微秒）
			CNFSerParaList[threadnum].RTOns = 0;//往返容忍时延（RTO小于1秒部分，单位纳秒）

			CNFSerParaList[threadnum].FlagTrebleAck = 0;//计数器，记录收到相同偏移量ACK的个数，用于判断三重ACK丢包状况

			CNFSerParaList[threadnum].WindowState = 0;//窗口状态，1ACK正常更新但未达窗口所要求的上界；2窗口传输成功；3三重ACK；4超时
			CNFSerParaList[threadnum].ThreadState = 0;//任务状态（用于结束过程的控制），0未完成，1文件读取完毕，2窗口录入完毕，3窗口发送完毕，4窗口确认完毕（即可终止）
			
			//创建thread_FTP子线程
			if(pthread_create(&CNFSerParaList[threadnum].pthread_FTP, NULL, CNFServer_thread_FTP, fd)!=0)
			{
				perror("Creation of FTP thread failed.");
			}
			
			//创建thread_NetworkLayertoTransportLayer上行子线程
			if(pthread_create(&CNFSerParaList[threadnum].pthread_NetworkLayertoTransportLayer, NULL, CNFServer_thread_NetworkLayertoTransportLayer, fd)!=0)
			{
				perror("Creation of NetworkLayertoTransportLayer thread failed.");
			}
	
			//创建thread_TransportLayertoNetworkLayer下行子线程
			if(pthread_create(&CNFSerParaList[threadnum].pthread_TransportLayertoNetworkLayer, NULL, CNFServer_thread_TransportLayertoNetworkLayer, fd)!=0)
			{
				perror("Creation of TransportLayertoNetworkLayer thread failed.");
			}
			
			//通知应用层查找SID数据并存入发送缓存
			//（暂时以单任务假设简化开发）
			if(cnfserDEVETESTIMPL <= 6)
			{
				printf("[RECV new]offsetlong = %ld\n",(unsigned long)1000);
				printf("[RECV new]OffsetRequestACK  = %ld\n",CNFSerParaList[threadnum].OffsetRequestACK);
			}
		}
		else//这是已有任务的ACK
		{
			//printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>There is an ACK for a Single Thread which Already Started.\n");

			offsetlong    = (unsigned long)OFFSET[0] * 256 * 256 * 256 + 
					(unsigned long)OFFSET[1] * 256 * 256 + 
					(unsigned long)OFFSET[2] * 256 + 
					(unsigned long)OFFSET[3];

			//匹配SID，查找与SID对应的任务线程编号
			if(strncmp(CNFSerParaList[threadnum].SID,SID,SIDLEN) == 0)
			{
				FoundSIDNum = 0;
			}
			if(FoundSIDNum == -1)
			{
				//printf("An unknown ACK Packet received, SID not found.\n");
				continue;
			}
			
			CNFSerParaList[threadnum].SIDLen = SIDlen;

			if(cnfserDEVETESTIMPL <= 1)
			{
				printf("[RECV]offsetlong       = %ld\n",offsetlong);
				printf("[LAST]OffsetRequestACK = %ld\n",CNFSerParaList[threadnum].OffsetRequestACK);
				printf("[NOW ]OffsetWindowEnd  = %ld\n",CNFSerParaList[threadnum].OffsetWindowEnd);
			}

			if(offsetlong > CNFSerParaList[threadnum].OffsetRequestACK)//新的请求偏移量，更新确认偏移量值
			{//printf("New ACK\n");
				CNFSerParaList[threadnum].OffsetRequestACK = offsetlong;
				CNFSerParaList[threadnum].OffsetConfirmACK = CNFSerParaList[threadnum].OffsetRequestACK - CNFSerParaList[threadnum].PacketDataLength;
				
				CNFSerParaList[threadnum].FlagTrebleAck = 0;
				
				CNFSerParaList[threadnum].WindowState = 1;
				
				if(CNFSerParaList[threadnum].OffsetRequestACK == CNFSerParaList[threadnum].OffsetWindowEnd)//收到ACK到达所等待窗口的上界
				{
					CNFSerParaList[threadnum].WindowState = 2;
				}
			}
			else if(offsetlong == CNFSerParaList[threadnum].OffsetRequestACK)//收到重复偏移量的ACK
			{//printf("Same ACK\n");printf("[RECV]offsetlong       = %ld\n",offsetlong);
				CNFSerParaList[threadnum].FlagTrebleAck++;
				
				if(CNFSerParaList[threadnum].FlagTrebleAck >= 3)//重复ACK达3次
				{
					//printf("TrebleAck Reached!\n");
					CNFSerParaList[threadnum].WindowState = 3;
					CNFSerParaList[threadnum].FlagTrebleAck = 0;
					
					continue;
				}
				else
				{
					continue;
				}
			}
			else//收到请求偏移量小于当前确认偏移量的ACK，在网络中存在乱序的情况下是正常的
			{
				continue;
			}

			sendto(CNFSerParaList[threadnum].SENDCNFServerWindowTimingEnd,"WindowTimingEnd",20,0,(struct sockaddr *)&CNFSerParaList[threadnum].SENDAddrToCNFServerWindowTimingEnd,SockAddrLength);

			if(cnfserDEVETESTIMPL <= 1 || CNFserverTRIGGERTEST == 1)
				printf("[%d] WindowTimingEnd triggering...\n",CNFSerParaList[threadnum].CountCNFServerWindowTimingEnd_Triggering);
			CNFSerParaList[threadnum].CountCNFServerWindowTimingEnd_Triggering++;
			
			//如果是非正常情况（到达窗口上界或三重ACK）的触发WindowTimingEnd，须排除正常ACK更新并等待下行通道回送继续收包的指令

			if(CNFSerParaList[threadnum].WindowState != 1)
			{
				//阻塞等待下行通道回送继续收包的指令
				if(cnfserDEVETESTIMPL <= 1 || CNFserverTRIGGERTEST == 1)
					printf("[%d] ContinueRECV waiting...\n",CNFSerParaList[threadnum].CountCNFServerContinueRECV_Waiting);
				CNFSerParaList[threadnum].CountCNFServerContinueRECV_Waiting++;
				
				if(cnfINTRACOMMUNICATION == 0)
				{
					recvfrom(CNFSerParaList[threadnum].RECVCNFServerContinueRECV,Trigger,20,0,(struct sockaddr *)&CNFSerParaList[threadnum].RECVAddrToCNFServerContinueRECV,&SockAddrLength);
				}
				else if(cnfINTRACOMMUNICATION == 1)
				{
					sem_wait(&CNFSerParaList[threadnum].semCNFServerContinueRECV);
				}


				if(cnfserDEVETESTIMPL <= 1 || CNFserverTRIGGERTEST == 1)
					printf("[%d] ContinueRECV triggered.\n",CNFSerParaList[threadnum].CountCNFServerContinueRECV_Triggered);
				CNFSerParaList[threadnum].CountCNFServerContinueRECV_Triggered++;
			}

		}
	}

	sleep(10000);
	//关闭线程
	//exit(0);
	//free(fd);
	//pthread_exit(NULL);	
}

/*****************************************
* 函数名称：CNFServer_thread_FTP
* 功能描述：读取文件线程（FTP前身），负责读取文件并维持发送缓冲的更新
* 参数列表：
* 返回结果：
*****************************************/
void *
CNFServer_thread_FTP
(
	void * fd
)
{
	//对CNFServer模块进行线程调用的参数拷贝接口
	struct cnfserinput * cnfinput;
	cnfinput = (struct cnfserinput *)fd;
	
	int threadnum = cnfinput->threadnum;

	if(cnfserDEVETESTIMPL <= 6)
		printf("CNF threadnum == %d (CNFServer_thread_FTP)\n",threadnum);
	
	//提取任务编号
	//int ThreadNum = *((int *)fd);printf("[FTP]ThreadNum = %d\n",ThreadNum);
	
	//为任务申请发送缓冲内存
	CNFSerParaList[threadnum].BUF = (uint8_t *)malloc(CNFBUFSIZE);
	memset(CNFSerParaList[threadnum].BUF,0,CNFBUFSIZE);
	
	//依照任务编号对应的参数组SID寻找对应的文件
	
	
	//打开文件并获取所需参数
	/*
	int fp;
	unsigned long filelen;
	
	fp = open(FTPServerPath,O_RDONLY);
	filelen = lseek(fp,0,SEEK_END);
	*/
	//向参数组拷贝文件总长度
	unsigned long cachelen = CACHESIZE;
	//CNFSerParaList[threadnum].FileLength = filelen;
	CNFSerParaList[threadnum].FileLength = CACHESIZE;
	
	if(cnfserDEVETESTIMPL <= 6)
		printf("FileLength = %ld\n",CNFSerParaList[threadnum].FileLength);
	
	CNFSerParaList[threadnum].BUFEnd = CNFSerParaList[threadnum].BUF + CNFSerParaList[threadnum].BUFLength;

	//如果文件总长度小于缓冲区长度（针对小文件）
	int readlength = 0;
	if(CNFSerParaList[threadnum].FileLength <= CNFSerParaList[threadnum].BUFLength)
	{
		if(cnfserDEVETESTIMPL <= 6)
			printf("File is very small, smaller than the BUFFER.\n");

		readlength = CNFSerParaList[threadnum].FileLength;
		CNFSerParaList[threadnum].BUFFileEnd = CNFSerParaList[threadnum].BUF + CNFSerParaList[threadnum].FileLength;
		CNFSerParaList[threadnum].ThreadState = 1;
	}
	else
	{
		readlength = CNFBUFSIZE;
	}

	//读取第一批数据
	//lseek(fp,0,SEEK_SET);
	//read(fp,CNFSerParaList[threadnum].BUF,readlength);
	memcpy(CNFSerParaList[threadnum].BUF,CacheList[TESTCACHENO].cache,readlength);
	//相应地修改文件控制参数
	CNFSerParaList[threadnum].BUFRenewCount = 0;
	CNFSerParaList[threadnum].FileReadPoint = CNFBUFSIZE;
	
	//printf("BUF = %s\n",CNFSerParaList[threadnum].BUF);
	
	//通知传输层，发送缓冲已经准备就绪
	if(cnfINTRACOMMUNICATION == 0)
	{
		sendto(CNFSerParaList[threadnum].SENDCNFServerBufReady,"BufReady",20,0,(struct sockaddr *)&CNFSerParaList[threadnum].SENDAddrToCNFServerBufReady,SockAddrLength);
	}
	else if(cnfINTRACOMMUNICATION == 1)
	{
		sem_post(&CNFSerParaList[threadnum].semCNFServerBufReady);
	}

	if(cnfserDEVETESTIMPL <= 1 || CNFserverTRIGGERTEST == 1)
		printf("[%d] BufReady triggering...\n",CNFSerParaList[threadnum].CountCNFServerBufReady_Triggering);

	CNFSerParaList[threadnum].CountCNFServerBufReady_Triggering++;
	
	if(cnfserDEVETESTIMPL <= 6)
		printf("DATA Reloading...(First for 1M size)\n");
	
		//计算时间节点（微秒）		
		gettimeofday(&utime,NULL);
		printf("==================Time==================\nServer Transmission Start %ld us\n========================================\n",1000000 * utime.tv_sec + utime.tv_usec);

	//开始持续为传输层供应数据
	while(CNFSerParaList[threadnum].ThreadState == 0)
	{
		//阻塞等待传输层触发对供应后续数据的要求
		if(cnfserDEVETESTIMPL <= 1 || CNFserverTRIGGERTEST == 1)
			printf("[%d] MoreData waiting...\n",CNFSerParaList[threadnum].CountCNFServerMoreData_Waiting);
		CNFSerParaList[threadnum].CountCNFServerMoreData_Waiting++;

		if(cnfINTRACOMMUNICATION == 0)
		{
			recvfrom(CNFSerParaList[threadnum].RECVCNFServerMoreData,Trigger,20,0,(struct sockaddr *)&CNFSerParaList[threadnum].RECVAddrToCNFServerMoreData,&SockAddrLength);
		}
		else if(cnfINTRACOMMUNICATION == 1)
		{
			sem_wait(&CNFSerParaList[threadnum].semCNFServerMoreData);
		}


		if(cnfserDEVETESTIMPL <= 1 || CNFserverTRIGGERTEST == 1)
			printf("[%d] MoreData triggered.\n",CNFSerParaList[threadnum].CountCNFServerMoreData_Triggered);
		CNFSerParaList[threadnum].CountCNFServerMoreData_Triggered++;

		CNFSerParaList[threadnum].BUFRenewCount++;

		if(cnfserDEVETESTIMPL <= 6)
			printf("DATA Reloading...(Per BUFLEN/2 for once)\n");

		//一次更新发送缓冲中一半的内容，前半段和后半段交替更新
		if(CNFSerParaList[threadnum].BUFRenewCount % 2 == 1)//指示更新前半段
		{
			//检查文件剩余长度是否足够一次补充
			if(CNFSerParaList[threadnum].FileReadPoint + CNFBUFSIZE/2 > cachelen)//不足一次补充，则补足余下数据，并记录尾部标识
			{
				//lseek(fp,CNFSerParaList[threadnum].FileReadPoint,SEEK_SET);
				//read(fp,CNFSerParaList[threadnum].BUF,filelen - CNFSerParaList[threadnum].FileReadPoint);
				memcpy(CNFSerParaList[threadnum].BUF,
					CacheList[TESTCACHENO].cache + CNFSerParaList[threadnum].FileReadPoint,
					cachelen - CNFSerParaList[threadnum].FileReadPoint);
				
				CNFSerParaList[threadnum].BUFFileEnd = CNFSerParaList[threadnum].BUF + ( cachelen - CNFSerParaList[threadnum].FileReadPoint );
				CNFSerParaList[threadnum].ThreadState = 1;
				break;
			}
			else//足够一次补充，则补充
			{
				//lseek(fp,CNFSerParaList[threadnum].FileReadPoint,SEEK_SET);
				//read(fp,CNFSerParaList[threadnum].BUF,CNFBUFSIZE/2);
				memcpy(CNFSerParaList[threadnum].BUF,
					CacheList[TESTCACHENO].cache + CNFSerParaList[threadnum].FileReadPoint,
					CNFBUFSIZE/2);
			
				CNFSerParaList[threadnum].FileReadPoint += CNFBUFSIZE/2;
			}
		}
		else if(CNFSerParaList[threadnum].BUFRenewCount % 2 == 0)//指示更新后半段
		{
			//检查文件剩余长度是否足够一次补充
			if(CNFSerParaList[threadnum].FileReadPoint + CNFBUFSIZE/2 > cachelen)//不足一次补充，则补足余下数据，并记录尾部标识
			{
				//lseek(fp,CNFSerParaList[threadnum].FileReadPoint,SEEK_SET);
				//read(fp,CNFSerParaList[threadnum].BUF + CNFBUFSIZE/2,filelen - CNFSerParaList[threadnum].FileReadPoint);
				memcpy(CNFSerParaList[threadnum].BUF + CNFBUFSIZE/2,
					CacheList[TESTCACHENO].cache + CNFSerParaList[threadnum].FileReadPoint,
					cachelen - CNFSerParaList[threadnum].FileReadPoint);
				
				CNFSerParaList[threadnum].BUFFileEnd = CNFSerParaList[threadnum].BUF + CNFBUFSIZE/2 + ( cachelen - CNFSerParaList[threadnum].FileReadPoint );
				CNFSerParaList[threadnum].ThreadState = 1;
				break;
			}
			else//足够一次补充，则补充
			{
				//lseek(fp,CNFSerParaList[threadnum].FileReadPoint,SEEK_SET);
				//read(fp,CNFSerParaList[threadnum].BUF + CNFBUFSIZE/2,CNFBUFSIZE/2);
				memcpy(CNFSerParaList[threadnum].BUF + CNFBUFSIZE/2,
					CacheList[TESTCACHENO].cache + CNFSerParaList[threadnum].FileReadPoint,
					CNFBUFSIZE/2);
			
				CNFSerParaList[threadnum].FileReadPoint += CNFBUFSIZE/2;
			}
		}
		
		if(cnfserDEVETESTIMPL <= 6)
			printf("FILE Reloaded. Already loaded: %ld Byte\n",CNFSerParaList[threadnum].FileReadPoint);
	}

	//向下行通道通知文件读取结束
	if(cnfINTRACOMMUNICATION == 0)
	{
		sendto(CNFSerParaList[threadnum].SENDCNFServerFileClose,"FileClose",20,0,(struct sockaddr *)&CNFSerParaList[threadnum].SENDAddrToCNFServerFileClose,SockAddrLength);
	}
	else if(cnfINTRACOMMUNICATION == 1)
	{
		sem_post(&CNFSerParaList[threadnum].semCNFServerFileClose);
	}

	if(cnfserDEVETESTIMPL <= 1 || CNFserverTRIGGERTEST == 1)
		printf("[%d] FileClose triggering...\n",CNFSerParaList[threadnum].CountCNFServerFileClose_Triggering);
	CNFSerParaList[threadnum].CountCNFServerFileClose_Triggering++;
	
	sleep(10000);
	//close(fp);
}

/*****************************************
* 函数名称：CNFServer_thread_NetworkLayertoTransportLayer
* 功能描述：上行通道 - From.数据响应端   To.应用服务器，负责ACK的接收和计时
* 参数列表：
* 返回结果：
*****************************************/
void *
CNFServer_thread_NetworkLayertoTransportLayer
(
	void * fd
)
{
	//对CNFServer模块进行线程调用的参数拷贝接口
	struct cnfserinput * cnfinput;
	cnfinput = (struct cnfserinput *)fd;
	
	int threadnum = cnfinput->threadnum;
	
	if(cnfserDEVETESTIMPL <= 6)
		printf("CNF threadnum == %d (CNFServer_thread_NetworkLayertoTransportLayer)\n",threadnum);

	//提取任务编号
	//int ThreadNum = *((int *)fd);printf("[UP]ThreadNum = %d\n",ThreadNum);
	
	//计时器初始化

	//设置超时
	//struct timespec delaytime;
	struct timeval delaytime;
	
	fd_set readfds;

	int judge = 0;
	int TimingCount = 0;
	while(1)
	{
		//变量清零
		judge = 0;
		TimingCount++;
		//printf("TimingCount = %d\n",TimingCount);
		
		if(CNFSerParaList[threadnum].WindowState != 1)
		{
			//阻塞等待定时任务
			if(cnfserDEVETESTIMPL <= 1 || CNFserverTRIGGERTEST == 1)
				printf("[%d] WindowBegin waiting...\n",CNFSerParaList[threadnum].CountCNFServerWindowBegin_Waiting);
			CNFSerParaList[threadnum].CountCNFServerWindowBegin_Waiting++;

			if(cnfINTRACOMMUNICATION == 0)
			{
				recvfrom(CNFSerParaList[threadnum].RECVCNFServerWindowBegin,Trigger,20,0,(struct sockaddr *)&CNFSerParaList[threadnum].RECVAddrToCNFServerWindowBegin,&SockAddrLength);
			}
			else if(cnfINTRACOMMUNICATION == 1)
			{
				sem_wait(&CNFSerParaList[threadnum].semCNFServerWindowBegin);
			}

			if(cnfserDEVETESTIMPL <= 1 || CNFserverTRIGGERTEST == 1)
				printf("[%d] WindowBegin triggered!\n",CNFSerParaList[threadnum].CountCNFServerWindowBegin_Triggered);
			CNFSerParaList[threadnum].CountCNFServerWindowBegin_Triggered++;
		}
		
		//定时阻塞窗口传输上行通道结束计时提示
		if(cnfserDEVETESTIMPL <= 1 || CNFserverTRIGGERTEST == 1)
			printf("[%d] WindowTimingEnd waiting...\n",CNFSerParaList[threadnum].CountCNFServerWindowTimingEnd_Waiting);
		CNFSerParaList[threadnum].CountCNFServerWindowTimingEnd_Waiting++;

		//带超时的UDP消息接收
		//设置超时
		delaytime.tv_sec=CNFSerParaList[threadnum].RTOs;
		delaytime.tv_usec=CNFSerParaList[threadnum].RTOus;

		//记录sockfd
		FD_ZERO(&readfds);
		FD_SET(CNFSerParaList[threadnum].RECVCNFServerWindowTimingEnd,&readfds);

		select(CNFSerParaList[threadnum].RECVCNFServerWindowTimingEnd+1,&readfds,NULL,NULL,&delaytime);
	
		//限时接收
		if(FD_ISSET(CNFSerParaList[threadnum].RECVCNFServerWindowTimingEnd,&readfds))
		{
			if(0 <= recvfrom(CNFSerParaList[threadnum].RECVCNFServerWindowTimingEnd,Trigger,20,0,(struct sockaddr *)&CNFSerParaList[threadnum].RECVAddrToCNFServerWindowTimingEnd,&SockAddrLength))
			{
				if(cnfserDEVETESTIMPL <= 0)
					printf("[TimingEndDelay]  %.3f ms\n",(double)(RTOUS - (int)delaytime.tv_usec)/(double)1000);
				judge = 1;
			}
		}
		else
		{
			if(cnfserDEVETESTIMPL <= 0)
				printf("[TimingEndDelay]  %.3f ms   (Timeout)\n",(double)(RTOUS - (int)delaytime.tv_usec)/(double)1000);
		}

		if(cnfserDEVETESTIMPL <= 1 || CNFserverTRIGGERTEST == 1)
			printf("[%d] WindowTimingEnd triggered!\n",CNFSerParaList[threadnum].CountCNFServerWindowTimingEnd_Triggered);
		CNFSerParaList[threadnum].CountCNFServerWindowTimingEnd_Triggered++;

		//显示结果
		if(judge > 0)//按时完成
		{
			//printf("On Time!\n");
			
			//按时接收到新的ACK但整个窗口尚未传输成功，属于可正常等待的情况，故重置定时器
			if(CNFSerParaList[threadnum].WindowState == 1)
			{
				continue;
			}
			//其它情况（2窗口按时传输成功 3三重ACK）均需要重新做窗口传输处理
		}
		else//超时
		{
			//printf("Time Out!\n");
			CNFSerParaList[threadnum].WindowState = 4;
			//printf("WindowState = %d\n",CNFSerParaList[threadnum].WindowState);
		}

		//通知下行通道，反馈本次窗口传输已得出结果
		if(cnfINTRACOMMUNICATION == 0)
		{
			sendto(CNFSerParaList[threadnum].SENDCNFServerWindowRespond,"WindowRespond",20,0,(struct sockaddr *)&CNFSerParaList[threadnum].SENDAddrToCNFServerWindowRespond,SockAddrLength);
		}
		else if(cnfINTRACOMMUNICATION == 1)
		{
			sem_post(&CNFSerParaList[threadnum].semCNFServerWindowRespond);
		}

		if(cnfserDEVETESTIMPL <= 1 || CNFserverTRIGGERTEST == 1)
			printf("[%d] WindowRespond triggering...\n",CNFSerParaList[threadnum].CountCNFServerWindowRespond_Triggering);
		CNFSerParaList[threadnum].CountCNFServerWindowRespond_Triggering++;
	}
	
	sleep(10000);
	//关闭线程
	//exit(0);
	//free(fd);
	//pthread_exit(NULL);
}

/*****************************************
* 函数名称：CNFServer_thread_TransportLayertoNetworkLayer
* 功能描述：下行通道 - From.应用服务器 To.数据响应端，负责窗口的计算与滑动、超时的响应、封装数据并向下递交
* 参数列表：
* 返回结果：
*****************************************/
void *
CNFServer_thread_TransportLayertoNetworkLayer
(
	void * fd
)
{
	int i,j;

	//对CNFServer模块进行线程调用的参数拷贝接口
	struct cnfserinput * cnfinput;
	cnfinput = (struct cnfserinput *)fd;
	
	int threadnum = cnfinput->threadnum;
	
	if(cnfserDEVETESTIMPL <= 6)
		printf("CNF threadnum == %d (CNFServer_thread_TransportLayertoNetworkLayer)\n",threadnum);

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

	if(cnfserDEVETESTIMPL <= 6)
	{
		printf("cnfinput->physicalportIP == %s\n",cnfinput->physicalportIP);
		printf("PhysicalportInterPORT = %d\n",PhysicalportInterPORT);
	}

	//提取任务编号
	//int ThreadNum = *((int *)fd);printf("[DOWN]ThreadNum = %d\n",ThreadNum);
	
	//阻塞，须等待发送缓冲准备就绪

	if(cnfserDEVETESTIMPL <= 1 || CNFserverTRIGGERTEST == 1)
		printf("[%d] BufReady waiting...\n",CNFSerParaList[threadnum].CountCNFServerBufReady_Waiting);

	CNFSerParaList[threadnum].CountCNFServerBufReady_Waiting++;

	if(cnfINTRACOMMUNICATION == 0)
	{
		recvfrom(CNFSerParaList[threadnum].RECVCNFServerBufReady,Trigger,20,0,(struct sockaddr *)&CNFSerParaList[threadnum].RECVAddrToCNFServerBufReady,&SockAddrLength);
	}
	else if(cnfINTRACOMMUNICATION == 1)
	{
		sem_wait(&CNFSerParaList[threadnum].semCNFServerBufReady);
	}

	if(cnfserDEVETESTIMPL <= 1 || CNFserverTRIGGERTEST == 1)
		printf("[%d] BufReady triggered!\n",CNFSerParaList[threadnum].CountCNFServerBufReady_Triggered);

	CNFSerParaList[threadnum].CountCNFServerBufReady_Triggered++;
	
	//参数初始化（任务初始触发到此的时候，已经意味着收到偏移为PKTDATALEN的请求）

	CNFSerParaList[threadnum].BUFLength = CNFBUFSIZE;//发送缓冲长度

	CNFSerParaList[threadnum].PacketDataLength = PKTDATALEN;//单包数据段长度
	CNFSerParaList[threadnum].LastPacketDataLength = PKTDATALEN;//整个传输任务的最后一个数据包实际长度

	CNFSerParaList[threadnum].WindowLength = 2;//窗口长度
	CNFSerParaList[threadnum].WindowThreshold = CNFBUFSIZE;//窗口门限值

	CNFSerParaList[threadnum].OffsetWindowHead = 0;//在整个文件中窗口头部所指的偏移量
	CNFSerParaList[threadnum].OffsetWindowEnd = PKTDATALEN + CNFSerParaList[threadnum].WindowLength * CNFSerParaList[threadnum].PacketDataLength;//在整个文件中窗口尾部所指的偏移量
	CNFSerParaList[threadnum].OffsetConfirmACK = 0;//在整个文件中已确认偏移量所在偏移量
	CNFSerParaList[threadnum].OffsetRequestACK = PKTDATALEN;//在整个文件中接到请求的偏移量
	CNFSerParaList[threadnum].OffsetPacket = PKTDATALEN;//在整个文件中当前封包偏移量（回传数据包偏移量字段的填写依据）
	CNFSerParaList[threadnum].OffsetWaitACK = PKTDATALEN;//在整个文件中等待确认收到的偏移量（下一节）

	CNFSerParaList[threadnum].AddrWindowHead = CNFSerParaList[threadnum].BUF;//在缓冲区中窗口头部所在地址
	CNFSerParaList[threadnum].AddrWindowEnd = CNFSerParaList[threadnum].BUF + CNFSerParaList[threadnum].WindowLength * CNFSerParaList[threadnum].PacketDataLength;//在缓冲区中窗口尾部所在地址
	CNFSerParaList[threadnum].AddrConfirmACK = CNFSerParaList[threadnum].BUF;//在缓冲区中已确认偏移量所在地址
	CNFSerParaList[threadnum].AddrRequestACK = CNFSerParaList[threadnum].BUF;//在缓冲区中接到请求的所在地址
	CNFSerParaList[threadnum].AddrPacket = CNFSerParaList[threadnum].BUF;//在缓冲区中当前封包偏移量所在地址
	CNFSerParaList[threadnum].AddrWaitACK = CNFSerParaList[threadnum].BUF;//在缓冲区中待确认偏移量所在地址

	CNFSerParaList[threadnum].RTOs = RTOS;//往返容忍时延（RTO大于1秒部分，单位秒）
	CNFSerParaList[threadnum].RTOus = RTOUS;//往返容忍时延（RTO小于1秒部分，单位微秒）
	CNFSerParaList[threadnum].RTOns = RTONS;//往返容忍时延（RTO小于1秒部分，单位纳秒）

	CNFSerParaList[threadnum].FlagTrebleAck = 0;//计数器，记录收到相同偏移量ACK的个数，用于判断三重ACK丢包状况

	CNFSerParaList[threadnum].WindowState = 0;//窗口状态，1ACK正常更新但未达窗口所要求的上界；2窗口传输成功；3三重ACK；4超时
	//CNFSerParaList[threadnum].ThreadState = 0;//任务状态此时已经改变（FTP线程中读取小文件时会发生改变，故不能再次初始化）


	//传输过程变量

	uint8_t DATA[DATALEN];
	unsigned long offsetlong;
	uint8_t offset[OFFLEN];
	
	uint8_t sendpkg[sizeof(CoLoR_seg)+3];
	CoLoR_seg * psendpkg;
	psendpkg = (CoLoR_seg *)(sendpkg+3);

	int LocalPkgBUFHead;
	while(1)
	{
		CNFSerParaList[threadnum].FlagTrebleAck = 0;

		//如果文件已经读取完毕，则须检查发送过程是否已经到文件末尾
		//printf("ThreadState == %d\n",CNFSerParaList[threadnum].ThreadState);
		//printf("[SET TAIL]CNFSerParaList[threadnum].AddrWindowEnd   = %d\n",CNFSerParaList[threadnum].AddrWindowEnd - CNFSerParaList[threadnum].BUF);
		//printf("ThreadState = %d\n",CNFSerParaList[threadnum].ThreadState);
		if(CNFSerParaList[threadnum].ThreadState >= 1)
		{
/*
			printf("[CHECK TAIL]OffsetConfirmACK == %ld\n",CNFSerParaList[threadnum].OffsetConfirmACK);
			printf("[CHECK TAIL]OffsetRequestACK == %ld\n",CNFSerParaList[threadnum].OffsetRequestACK);
			printf("[CHECK TAIL]OffsetPacket + WindowLength * PacketDataLength == %ld\n",CNFSerParaList[threadnum].OffsetPacket + CNFSerParaList[threadnum].WindowLength * CNFSerParaList[threadnum].PacketDataLength);
*/
			if( CNFSerParaList[threadnum].OffsetPacket - PKTDATALEN + CNFSerParaList[threadnum].WindowLength * CNFSerParaList[threadnum].PacketDataLength > CNFSerParaList[threadnum].FileLength )
			{
				CNFSerParaList[threadnum].ThreadState = 2;
				
				//根据文件剩余长度重新计算窗口大小
				CNFSerParaList[threadnum].WindowLength = ( CNFSerParaList[threadnum].FileLength - CNFSerParaList[threadnum].OffsetConfirmACK ) / CNFSerParaList[threadnum].PacketDataLength;

				if(cnfserDEVETESTIMPL <= 6)
					printf("WindowLength = %ld\n",CNFSerParaList[threadnum].WindowLength);

				if(( CNFSerParaList[threadnum].FileLength - CNFSerParaList[threadnum].OffsetConfirmACK ) % CNFSerParaList[threadnum].PacketDataLength != 0)
					CNFSerParaList[threadnum].WindowLength++;

				if(cnfserDEVETESTIMPL <= 6)
					printf("WindowLength = %ld\n",CNFSerParaList[threadnum].WindowLength);
				
				//如果重新计算得到的窗口大小为0，说明所有数据均得到了确认，文件已没有剩余长度，退出
				if(CNFSerParaList[threadnum].WindowLength == 0)
				{
					CNFSerParaList[threadnum].ThreadState = 4;
					if(cnfserDEVETESTIMPL <= 6)
						printf("[END] File Transmission Succeed!!(By. WindowLength Zero)\n");
					break;
				}

				//更新窗口尾部
				CNFSerParaList[threadnum].OffsetWindowEnd = CNFSerParaList[threadnum].OffsetWindowHead + CNFSerParaList[threadnum].WindowLength * CNFSerParaList[threadnum].PacketDataLength;
				CNFSerParaList[threadnum].AddrWindowEnd   = CNFSerParaList[threadnum].AddrWindowHead   + CNFSerParaList[threadnum].WindowLength * CNFSerParaList[threadnum].PacketDataLength;

				if(cnfserDEVETESTIMPL <= 6)
				{
					printf("[SET TAIL]CNFSerParaList[threadnum].OffsetWindowEnd = %ld\n",CNFSerParaList[threadnum].OffsetWindowEnd);
					printf("[SET TAIL]CNFSerParaList[threadnum].AddrWindowEnd   = %d\n",CNFSerParaList[threadnum].AddrWindowEnd - CNFSerParaList[threadnum].BUF);
				}
			}
		}
		
		//循环发送窗口内的数据包


		//记录窗口长度变化过程
		CNFSerParaList[threadnum].InputCount++;
		CNFSerParaList[threadnum].TotalWindowLength += CNFSerParaList[threadnum].WindowLength;
		//printf("[%d] ",CNFSerParaList[threadnum].InputCount);
		//printf("WindowLength = %ld\n",CNFSerParaList[threadnum].WindowLength);
		
/*
		itoa((int)CNFSerParaList[threadnum].WindowLength,CNFSerParaList[threadnum].NumStr,10);
		if(CNFSerParaList[threadnum].WindowLength<10)
			write(CNFSerParaList[threadnum].LogFilePoint,CNFSerParaList[threadnum].NumStr,1);
		else if(CNFSerParaList[threadnum].WindowLength<100)
			write(CNFSerParaList[threadnum].LogFilePoint,CNFSerParaList[threadnum].NumStr,2);
		else if(CNFSerParaList[threadnum].WindowLength<1000)
			write(CNFSerParaList[threadnum].LogFilePoint,CNFSerParaList[threadnum].NumStr,3);
		write(CNFSerParaList[threadnum].LogFilePoint," ",1);
*/

		for(i=0;i<CNFSerParaList[threadnum].WindowLength;i++)
		{
			if(cnfserDEVETESTIMPL <= 1)
				printf("WindowLength = %ld\n",CNFSerParaList[threadnum].WindowLength);

			memset(sendpkg,0,sizeof(CoLoR_seg)+3);
			memcpy(sendpkg,"FOR",3);

			//填充CoLoR-SEQ包文
			psendpkg->version_type = 163;//版本4位，类型4位，此为设置成CoLoR_seq包
			psendpkg->ttl = 255;//生存时间
			psendpkg->total_len = sizeof(CoLoR_seg);//总长度
	
			psendpkg->port_no = 1;//端口号
			psendpkg->checksum = 0;//检验和
	
			psendpkg->sid_len = SIDLEN;//SID长度
			psendpkg->nid_len = NIDLEN;//NID长度
			psendpkg->pid_n = PIDN;//PID长度

			//固定首部选项
			if(CNFON == 1)//CNF设定
				psendpkg->options_static = 32;
			else if(CNFON == 0)//CNF设定
				psendpkg->options_static = 0;
	
			psendpkg->signature_algorithm = 1;//签名算法
			psendpkg->if_hash_cache = 255;//是否哈希4位，是否缓存4位
			psendpkg->options_dynamic = 0;//可变首部选项
			
			//读取窗口数据
			if(i == CNFSerParaList[threadnum].WindowLength - 1 && CNFSerParaList[threadnum].ThreadState >= 2)//如果已经录入到达整个传输任务的最后一个包
			{
				if(cnfserDEVETESTIMPL <= 6)
				{
					printf("The last Packet!!!!\n");
					printf("[LAST PACKET]AddrWindowEnd - BUF        = %d\n",CNFSerParaList[threadnum].AddrWindowEnd - CNFSerParaList[threadnum].BUF);
					printf("[LAST PACKET]AddrWindowEnd - AddrPacket = %d\n",CNFSerParaList[threadnum].AddrWindowEnd - CNFSerParaList[threadnum].AddrPacket);
				}

				memcpy(DATA,CNFSerParaList[threadnum].AddrPacket,CNFSerParaList[threadnum].AddrWindowEnd - CNFSerParaList[threadnum].AddrPacket);

				CNFSerParaList[threadnum].LastPacketDataLength = CNFSerParaList[threadnum].AddrWindowEnd - CNFSerParaList[threadnum].AddrPacket;
				
				//换算offset的数据类型
				offsetlong = CNFSerParaList[threadnum].OffsetPacket;
				for(j=OFFLEN-1;j>=0;j--)
				{
					offset[j] = (char)offsetlong%256;
					offsetlong/=256;
				}

				if(cnfserDEVETESTIMPL <= 6)
					printf("Sent Offset = %ld\n",CNFSerParaList[threadnum].OffsetPacket);
					//printf("Sent Offset = %d %d %d %d\n",(int)offset[0],(int)offset[1],(int)offset[2],(int)offset[3]);

				//封装SID、DATA、offset
				memcpy(psendpkg->sid,CNFSerParaList[threadnum].SID,SIDLEN);
				memcpy(psendpkg->data,DATA,CNFSerParaList[threadnum].AddrWindowEnd - CNFSerParaList[threadnum].AddrPacket);
				memcpy(psendpkg->offset,offset,OFFLEN);

				//间隔一定时间发送下一个包
				usleep(FlowSlot);
				
				//发送SEQ传输包
				if(INTRACOMMUNICATION == 0)
				{
					sendto(CNFSerParaList[threadnum].SENDCNFServerSEG,sendpkg,sizeof(CoLoR_seg)+3,0,(struct sockaddr *)&CNFSerParaList[threadnum].SENDAddrToCNFServerSEG,SockAddrLength);
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
						//printf("[C]PkgBUFHead = %d\n",PkgBUFHead);
						//printf("[C]PkgBUF[%d].flag_occupied = %d\n",PkgBUFHead,PkgBUF[PkgBUFHead].flag_occupied);
		
						PkgBUF[LocalPkgBUFHead].flag_occupied = 1;
						PkgBUF[LocalPkgBUFHead].destppnum = portnum;
						PkgBUF[LocalPkgBUFHead].pkglength = sizeof(CoLoR_seg);
						strcpy(PkgBUF[LocalPkgBUFHead].sourcepp,CNFThreadList[threadnum].physicalport);
						memcpy(PkgBUF[LocalPkgBUFHead].pkg,sendpkg+3,sizeof(CoLoR_seg));
		
						//触发网络层信号量
						sem_post(&semPacketSEND[portnum]);

						if(cnfserDEVETESTIMPL <= 1)
						{
							printf("[%s] SEQ Message has been sent\n",CNFThreadList[threadnum].physicalport);
							printf("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n\n");
						}
					}
					else
					{
						if(cnfserDEVETESTIMPL <= 1)
						{
							printf("[%s] SEQ Message failed to be sent\n",CNFThreadList[threadnum].physicalport);
							printf("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n\n");
						}
					}
					pthread_mutex_unlock(&lockPkgBUF);
				}

				if(cnfserDEVETESTIMPL <= 6)
					printf("[CNFServer]The last SEQ packet sent.\n");

				//设置RTO计时器
				if(i == 0)
				{
					if(cnfINTRACOMMUNICATION == 0)
					{
						sendto(CNFSerParaList[threadnum].SENDCNFServerWindowBegin,"WindowBegin",20,0,(struct sockaddr *)&CNFSerParaList[threadnum].SENDAddrToCNFServerWindowBegin,SockAddrLength);
					}
					else if(cnfINTRACOMMUNICATION == 1)
					{
						sem_post(&CNFSerParaList[threadnum].semCNFServerWindowBegin);
					}

					if(cnfserDEVETESTIMPL <= 1 || CNFserverTRIGGERTEST == 1)
						printf("[%d] WindowBegin triggering...\n",CNFSerParaList[threadnum].CountCNFServerWindowBegin_Triggering);
					CNFSerParaList[threadnum].CountCNFServerWindowBegin_Triggering++;
				}
			
				//参数变化
				//CNFSerParaList[threadnum].OffsetPacket += CNFSerParaList[threadnum].PacketDataLength;
				//CNFSerParaList[threadnum].AddrPacket   += CNFSerParaList[threadnum].PacketDataLength;
			
				//缓冲区回环处理
				if(CNFSerParaList[threadnum].AddrPacket >= CNFSerParaList[threadnum].BUFEnd)
				{
					CNFSerParaList[threadnum].AddrPacket = CNFSerParaList[threadnum].BUF + ( CNFSerParaList[threadnum].AddrPacket - CNFSerParaList[threadnum].BUFEnd );
				}

				CNFSerParaList[threadnum].OffsetWaitACK = CNFSerParaList[threadnum].OffsetPacket;
				CNFSerParaList[threadnum].AddrWaitACK   = CNFSerParaList[threadnum].AddrPacket;
				
				//（传输任务末端测试用）校验累加的文件长度是否与实际文件长度相符
				if(CNFSerParaList[threadnum].OffsetWaitACK > CNFSerParaList[threadnum].FileLength + PKTDATALEN)
				{
					printf("Deadly Error! [ OffsetWaitACK > FileLength + PKTDATALEN ] In The End!\n");
					exit(0);
				}
				else
				{
					//printf("File Length Checking passed!.\n");
				}

				CNFSerParaList[threadnum].ThreadState = 3;//修改任务状态为：3窗口发送完毕
			}
			else//发送的数据包尚未到整个任务的最后一个
			{
/*
				printf("[NOT END]AddrWindowEnd - BUF        = %d\n",CNFSerParaList[threadnum].AddrWindowEnd - CNFSerParaList[threadnum].BUF);
				printf("[NOT END]BUFFileEnd    - AddrPacket = %d\n",CNFSerParaList[threadnum].BUFFileEnd - CNFSerParaList[threadnum].AddrPacket);
				printf("[NOT END]AddrWindowEnd - AddrPacket = %d\n",CNFSerParaList[threadnum].AddrWindowEnd - CNFSerParaList[threadnum].AddrPacket);
				printf("[NOT END]OffsetPacket               = %ld\n",CNFSerParaList[threadnum].OffsetPacket);
*/
				memcpy(DATA,CNFSerParaList[threadnum].AddrPacket,CNFSerParaList[threadnum].PacketDataLength);

				//printf("DATA = \n");
				int testnum;
				for(testnum=0;testnum<CNFSerParaList[threadnum].PacketDataLength;testnum++)
				{
					//printf("%c",DATA[testnum]);
				}
				//printf("\n");
				//换算offset的数据类型
				offsetlong = CNFSerParaList[threadnum].OffsetPacket;
				for(j=OFFLEN-1;j>=0;j--)
				{
					offset[j] = (char)offsetlong%256;
					offsetlong/=256;
				}

				if(cnfserDEVETESTIMPL <= 1)
					printf("Sent Offset = %ld\n",CNFSerParaList[threadnum].OffsetPacket);

				//printf("Sent Offset = %d %d %d %d\n",(int)offset[0],(int)offset[1],(int)offset[2],(int)offset[3]);

				//printf("OFFSET = %d %d %d %d\n",offset[0],offset[1],offset[2],offset[3]);
				//printf("PacketDataLength = %ld\n",CNFSerParaList[threadnum].PacketDataLength);
				//printf("SIDLen = %d\n",CNFSerParaList[threadnum].SIDLen);
				
				//封装SID、DATA、offset
				memcpy(psendpkg->sid,CNFSerParaList[threadnum].SID,SIDLEN);
				memcpy(psendpkg->data,DATA,CNFSerParaList[threadnum].PacketDataLength);
				memcpy(psendpkg->offset,offset,OFFLEN);

				//间隔一定时间发送下一个包
				usleep(FlowSlot);

				//发送SEQ传输包
				if(INTRACOMMUNICATION == 0)
				{
					sendto(CNFSerParaList[threadnum].SENDCNFServerSEG,sendpkg,sizeof(CoLoR_seg)+3,0,(struct sockaddr *)&CNFSerParaList[threadnum].SENDAddrToCNFServerSEG,SockAddrLength);
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
						PkgBUF[LocalPkgBUFHead].pkglength = sizeof(CoLoR_seg);
						strcpy(PkgBUF[LocalPkgBUFHead].sourcepp,CNFThreadList[threadnum].physicalport);
						memcpy(PkgBUF[LocalPkgBUFHead].pkg,sendpkg+3,sizeof(CoLoR_seg));
		
						//触发网络层信号量
						sem_post(&semPacketSEND[portnum]);

						if(cnfserDEVETESTIMPL <= 1)
						{
							printf("[%s] ACK Message has been sent\n",CNFThreadList[threadnum].physicalport);
							printf("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n\n");
						}
					}
					else
					{
						if(cnfserDEVETESTIMPL <= 1)
						{
							printf("[%s] ACK Message failed to be sent\n",CNFThreadList[threadnum].physicalport);
							printf("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n\n");
						}
					}
					pthread_mutex_unlock(&lockPkgBUF);
				}
				
				//设置RTO计时器
				if(i == 0)
				{
					if(cnfINTRACOMMUNICATION == 0)
					{
						sendto(CNFSerParaList[threadnum].SENDCNFServerWindowBegin,"WindowBegin",20,0,(struct sockaddr *)&CNFSerParaList[threadnum].SENDAddrToCNFServerWindowBegin,SockAddrLength);
					}
					else if(cnfINTRACOMMUNICATION == 1)
					{
						sem_post(&CNFSerParaList[threadnum].semCNFServerWindowBegin);
					}

					if(cnfserDEVETESTIMPL <= 1 || CNFserverTRIGGERTEST == 1)
						printf("[%d] WindowBegin triggering...\n",CNFSerParaList[threadnum].CountCNFServerWindowBegin_Triggering);
					CNFSerParaList[threadnum].CountCNFServerWindowBegin_Triggering++;
				}
			
				//参数变化
				CNFSerParaList[threadnum].OffsetPacket += CNFSerParaList[threadnum].PacketDataLength;
				CNFSerParaList[threadnum].AddrPacket   += CNFSerParaList[threadnum].PacketDataLength;
			
				//缓冲区回环处理
				if(CNFSerParaList[threadnum].AddrPacket >= CNFSerParaList[threadnum].BUFEnd)
				{
					CNFSerParaList[threadnum].AddrPacket = CNFSerParaList[threadnum].BUF + ( CNFSerParaList[threadnum].AddrPacket - CNFSerParaList[threadnum].BUFEnd );
				}

				CNFSerParaList[threadnum].OffsetWaitACK = CNFSerParaList[threadnum].OffsetPacket;
				CNFSerParaList[threadnum].AddrWaitACK   = CNFSerParaList[threadnum].AddrPacket;
/*
				printf("[PARA CHANGE]OffsetPacket     = %ld\n",CNFSerParaList[threadnum].OffsetPacket);
				printf("[PARA CHANGE]AddrPacket - BUF = %d\n",CNFSerParaList[threadnum].AddrPacket - CNFSerParaList[threadnum].BUF);
				printf("[PARA CHANGE]OffsetWaitACK    = %ld\n",CNFSerParaList[threadnum].OffsetWaitACK);
				printf("[PARA CHANGE]AddrWaitACK- BUF = %d\n",CNFSerParaList[threadnum].AddrWaitACK - CNFSerParaList[threadnum].BUF);
*/
			}
		}
		
		//进入阻塞，等待上行通道信号
		if(cnfserDEVETESTIMPL <= 1 || CNFserverTRIGGERTEST == 1)
			printf("[%d] WindowRespond waiting...\n",CNFSerParaList[threadnum].CountCNFServerWindowRespond_Waiting);
		CNFSerParaList[threadnum].CountCNFServerWindowRespond_Waiting++;

		if(cnfINTRACOMMUNICATION == 0)
		{
			recvfrom(CNFSerParaList[threadnum].RECVCNFServerWindowRespond,Trigger,20,0,(struct sockaddr *)&CNFSerParaList[threadnum].RECVAddrToCNFServerWindowRespond,&SockAddrLength);
		}
		else if(cnfINTRACOMMUNICATION == 1)
		{
			sem_wait(&CNFSerParaList[threadnum].semCNFServerWindowRespond);
		}

		if(cnfserDEVETESTIMPL <= 1 || CNFserverTRIGGERTEST == 1)
			printf("[%d] WindowRespond triggered!\n",CNFSerParaList[threadnum].CountCNFServerWindowRespond_Triggered);
		CNFSerParaList[threadnum].CountCNFServerWindowRespond_Triggered++;
		
		//任务参数计算规则
		
		//窗口大小、窗口滑动、门限值等相关参数计算，依据参数：CNFSerParaList[threadnum].WindowState和CNFSerParaList[threadnum].OffsetRequestACK
		//printf("WindowState = %d\n",CNFSerParaList[threadnum].WindowState);

		if(CNFSerParaList[threadnum].WindowState == 1)//ACK正常更新但未达窗口所要求的上界
		{
			//printf("After WindowRespond, WindowState == 1. Maybe not normal. Check the code.\n");
			CNFSerParaList[threadnum].WindowState = 0;
		}
		else if(CNFSerParaList[threadnum].WindowState == 2)//整个窗口顺利传输完毕
		{
			CNFSerParaList[threadnum].WindowState = 0;
			
			//整个任务传输成功
			if(CNFSerParaList[threadnum].ThreadState >= 3)
			{
				CNFSerParaList[threadnum].ThreadState = 4;
				if(cnfserDEVETESTIMPL <= 6)
					printf("[END] File Transmission Succeed!!(By. Rightpoint)\n");
				break;
			}

			if(CNFSerParaList[threadnum].WindowLength < CNFSerParaList[threadnum].BUFLength / 2 -1)//避免窗口长度大于单次数据传输的缓冲总长
			{
				if(CNFSerParaList[threadnum].WindowLength * 2 <= CNFSerParaList[threadnum].WindowThreshold)//慢启动阶段
					CNFSerParaList[threadnum].WindowLength *= 2;
				else//拥塞避免阶段
					CNFSerParaList[threadnum].WindowLength ++;
			}

			//避免窗口长度超过整个缓冲区长度
			/*
			if(CNFSerParaList[threadnum].WindowLength > CNFSerParaList[threadnum].BUFLength / CNFSerParaList[threadnum].PacketDataLength / 2)
			{
				CNFSerParaList[threadnum].WindowLength = CNFSerParaList[threadnum].BUFLength / CNFSerParaList[threadnum].PacketDataLength / 2;
			}
			*/
			//避免窗口长度超过最大窗口长度
			if(CNFSerParaList[threadnum].WindowLength > MAXWndLen)
			{
				CNFSerParaList[threadnum].WindowLength = MAXWndLen;
			}

			//更新窗口头部
			CNFSerParaList[threadnum].OffsetWindowHead = CNFSerParaList[threadnum].OffsetWindowEnd;
			CNFSerParaList[threadnum].AddrWindowHead   = CNFSerParaList[threadnum].AddrWindowEnd;
			//更新窗口尾部
			CNFSerParaList[threadnum].OffsetWindowEnd += CNFSerParaList[threadnum].WindowLength * CNFSerParaList[threadnum].PacketDataLength;
			CNFSerParaList[threadnum].AddrWindowEnd   += CNFSerParaList[threadnum].WindowLength * CNFSerParaList[threadnum].PacketDataLength;
/*
			printf("[RENEW WND HEAD1]AddrWindowHead - BUF = %d\n",CNFSerParaList[threadnum].AddrWindowHead - CNFSerParaList[threadnum].BUF);
			printf("[RENEW WND TAIL1]OffsetWindowEnd     = %ld\n",CNFSerParaList[threadnum].OffsetWindowEnd);
			printf("[RENEW WND TAIL1]AddrWindowEnd - BUF = %d\n",CNFSerParaList[threadnum].AddrWindowEnd - CNFSerParaList[threadnum].BUF);
*/
			//缓冲区回环处理
			if(CNFSerParaList[threadnum].AddrWindowEnd >= CNFSerParaList[threadnum].BUFEnd)
			{
				CNFSerParaList[threadnum].AddrWindowEnd = CNFSerParaList[threadnum].BUF + ( CNFSerParaList[threadnum].AddrWindowEnd - CNFSerParaList[threadnum].BUFEnd );
			}
		}
/*
		else if(CNFSerParaList[threadnum].WindowState == 3)//三重ACK（轻度丢包）
		{printf("Treble ACK!\n");
			CNFSerParaList[threadnum].WindowState = 0;
			
			//任务状态撤回
			if(CNFSerParaList[threadnum].ThreadState >= 2)
			{
				CNFSerParaList[threadnum].ThreadState = 1;
			}

			CNFSerParaList[threadnum].WindowThreshold = CNFSerParaList[threadnum].WindowLength / 2;//把门限值设置为当前窗口大小的一半
			
			CNFSerParaList[threadnum].WindowLength = CNFSerParaList[threadnum].WindowThreshold;//把窗口值设置为门限值
			
			if(CNFSerParaList[threadnum].WindowThreshold == 0)
				CNFSerParaList[threadnum].WindowThreshold = 1;
			if(CNFSerParaList[threadnum].WindowLength == 0)
				CNFSerParaList[threadnum].WindowLength = 1;
			
			printf("CNFSerParaList[threadnum].WindowThreshold = %ld\n",CNFSerParaList[threadnum].WindowThreshold);

			//更新窗口头部
			CNFSerParaList[threadnum].OffsetWindowHead = CNFSerParaList[threadnum].OffsetRequestACK;
			CNFSerParaList[threadnum].AddrWindowHead   = CNFSerParaList[threadnum].AddrWaitACK - ( CNFSerParaList[threadnum].OffsetWaitACK - CNFSerParaList[threadnum].OffsetRequestACK );

			//缓冲区回环处理
			if(CNFSerParaList[threadnum].AddrWindowHead < CNFSerParaList[threadnum].BUF)
			{
				CNFSerParaList[threadnum].AddrWindowHead = CNFSerParaList[threadnum].BUFEnd - ( CNFSerParaList[threadnum].BUF - CNFSerParaList[threadnum].AddrWindowHead );
			}

			//更新窗口尾部
			CNFSerParaList[threadnum].OffsetWindowEnd = CNFSerParaList[threadnum].OffsetWindowHead + 
							 CNFSerParaList[threadnum].WindowLength * CNFSerParaList[threadnum].PacketDataLength;
			CNFSerParaList[threadnum].AddrWindowEnd   = CNFSerParaList[threadnum].AddrWindowHead   + 
							 CNFSerParaList[threadnum].WindowLength * CNFSerParaList[threadnum].PacketDataLength;

			//printf("[RENEW WND HEAD2]AddrWindowHead - BUF = %d\n",CNFSerParaList[threadnum].AddrWindowHead - CNFSerParaList[threadnum].BUF);
			//printf("[RENEW WND TAIL2]OffsetWindowEnd     = %ld\n",CNFSerParaList[threadnum].OffsetWindowEnd);
			//printf("[RENEW WND TAIL2]AddrWindowEnd - BUF = %d\n",CNFSerParaList[threadnum].AddrWindowEnd - CNFSerParaList[threadnum].BUF);

			//缓冲区回环处理
			if(CNFSerParaList[threadnum].AddrWindowEnd >= CNFSerParaList[threadnum].BUFEnd)
			{
				CNFSerParaList[threadnum].AddrWindowEnd = CNFSerParaList[threadnum].BUF + ( CNFSerParaList[threadnum].AddrWindowEnd - CNFSerParaList[threadnum].BUFEnd );
			}
		}
*/
		else if(CNFSerParaList[threadnum].WindowState == 3 || CNFSerParaList[threadnum].WindowState == 4)//窗口ACK超时（重度拥塞）
		{//printf("Time Out!\n");
			CNFSerParaList[threadnum].LostPacketCount++;//记录丢包次数
			
			CNFSerParaList[threadnum].WindowState = 0;
			
			//整个任务传输成功
			if(CNFSerParaList[threadnum].ThreadState >= 3)
			{
				CNFSerParaList[threadnum].ThreadState = 4;

				if(cnfserDEVETESTIMPL <= 6)
					printf("[END] File Transmission Succeed!!(By. Timeouts)\n");

				break;
			}

			//任务状态撤回
			else if(CNFSerParaList[threadnum].ThreadState >= 2)
			{
				CNFSerParaList[threadnum].ThreadState = 1;
			}

			CNFSerParaList[threadnum].WindowThreshold = CNFSerParaList[threadnum].WindowLength / 2;//把门限值设置为当前窗口大小的一半
			
			CNFSerParaList[threadnum].WindowLength = 1;//把窗口大小重新设置为一个报文段

			if(CNFSerParaList[threadnum].WindowThreshold == 0)
				CNFSerParaList[threadnum].WindowThreshold = 1;

			//printf("CNFSerParaList[threadnum].WindowThreshold = %ld\n",CNFSerParaList[threadnum].WindowThreshold);
			
			//更新窗口头部
			CNFSerParaList[threadnum].OffsetWindowHead = CNFSerParaList[threadnum].OffsetRequestACK;
			CNFSerParaList[threadnum].AddrWindowHead   = CNFSerParaList[threadnum].AddrWaitACK - ( CNFSerParaList[threadnum].OffsetWaitACK - CNFSerParaList[threadnum].OffsetRequestACK );

			//缓冲区回环处理
			if(CNFSerParaList[threadnum].AddrWindowHead < CNFSerParaList[threadnum].BUF)
			{
				CNFSerParaList[threadnum].AddrWindowHead = CNFSerParaList[threadnum].BUFEnd - ( CNFSerParaList[threadnum].BUF - CNFSerParaList[threadnum].AddrWindowHead );
			}

			//更新窗口尾部
			CNFSerParaList[threadnum].OffsetWindowEnd = CNFSerParaList[threadnum].OffsetWindowHead + 
							 CNFSerParaList[threadnum].WindowLength * CNFSerParaList[threadnum].PacketDataLength;
			CNFSerParaList[threadnum].AddrWindowEnd   = CNFSerParaList[threadnum].AddrWindowHead   + 
							 CNFSerParaList[threadnum].WindowLength * CNFSerParaList[threadnum].PacketDataLength;
/*
			printf("[RENEW WND HEAD3]AddrWindowHead - BUF = %d\n",CNFSerParaList[threadnum].AddrWindowHead - CNFSerParaList[threadnum].BUF);
			printf("[RENEW WND TAIL3]OffsetWindowEnd     = %ld\n",CNFSerParaList[threadnum].OffsetWindowEnd);
			printf("[RENEW WND TAIL3]AddrWindowEnd - BUF = %d\n",CNFSerParaList[threadnum].AddrWindowEnd - CNFSerParaList[threadnum].BUF);
*/
			//缓冲区回环处理
			if(CNFSerParaList[threadnum].AddrWindowEnd >= CNFSerParaList[threadnum].BUFEnd)
			{
				CNFSerParaList[threadnum].AddrWindowEnd = CNFSerParaList[threadnum].BUF + ( CNFSerParaList[threadnum].AddrWindowEnd - CNFSerParaList[threadnum].BUFEnd );
			}
		}
		else//致命错误，WindowState窗口状态值异常
		{
			//printf("[Deadly Error] (WindowState == %d)\n",CNFSerParaList[threadnum].WindowState);
			CNFSerParaList[threadnum].LostPacketCount++;
			continue;
			//exit(0);
		}

		CNFSerParaList[threadnum].OffsetPacket = CNFSerParaList[threadnum].OffsetRequestACK;
		CNFSerParaList[threadnum].AddrPacket   = CNFSerParaList[threadnum].AddrWindowHead;
		//printf("[PARA CHANGE]AddrPacket - BUF = %d\n",CNFSerParaList[threadnum].AddrPacket - CNFSerParaList[threadnum].BUF);
		
		//向应用层通知对供应后续数据的要求
		if( CNFSerParaList[threadnum].OffsetRequestACK / ( CNFSerParaList[threadnum].BUFLength / 2 ) == CNFSerParaList[threadnum].BUFRenewCount + 1 )
		{
			if(cnfINTRACOMMUNICATION == 0)
			{
				sendto(CNFSerParaList[threadnum].SENDCNFServerMoreData,"MoreData",20,0,(struct sockaddr *)&CNFSerParaList[threadnum].SENDAddrToCNFServerMoreData,SockAddrLength);
			}
			else if(cnfINTRACOMMUNICATION == 1)
			{
				sem_post(&CNFSerParaList[threadnum].semCNFServerMoreData);
			}

			if(cnfserDEVETESTIMPL <= 1 || CNFserverTRIGGERTEST == 1)
				printf("[%d] MoreData triggering...\n",CNFSerParaList[threadnum].CountCNFServerMoreData_Triggering);
			CNFSerParaList[threadnum].CountCNFServerMoreData_Triggering++;
		}
		else if( CNFSerParaList[threadnum].OffsetRequestACK / ( CNFSerParaList[threadnum].BUFLength / 2 ) > CNFSerParaList[threadnum].BUFRenewCount + 1 )
		{
			if(cnfserDEVETESTIMPL <= 6)
				printf("[Deadly Error]This is not normal. BUFRenewCount has problems to solve.\n1. Maybe a MoreData message has been lost.\n2. WindowLength is larger than BUFLength/2.\n");
			
			//exit(0);
			//break;
		}

		//触发上行通道继续收包的指令
		if(cnfINTRACOMMUNICATION == 0)
		{
			sendto(CNFSerParaList[threadnum].SENDCNFServerContinueRECV,"ContinueRECV",20,0,(struct sockaddr *)&CNFSerParaList[threadnum].SENDAddrToCNFServerContinueRECV,SockAddrLength);
		}
		else if(cnfINTRACOMMUNICATION == 1)
		{
			sem_post(&CNFSerParaList[threadnum].semCNFServerContinueRECV);
		}
		
		if(cnfserDEVETESTIMPL <= 1 || CNFserverTRIGGERTEST == 1)
			printf("[%d] ContinueRECV triggering...\n",CNFSerParaList[threadnum].CountCNFServerContinueRECV_Triggering);
		CNFSerParaList[threadnum].CountCNFServerContinueRECV_Triggering++;

	}

	//输出AIMD传输统计参数
	if(cnfserDEVETESTIMPL <= 7)
	{
		//计算时间节点（微秒）		
		gettimeofday(&utime,NULL);
		printf("==================Time==================\nServer Transmission End   %ld us\n========================================\n",1000000 * utime.tv_sec + utime.tv_usec);

		printf("==============DATA Results==============\n");
		printf("Total Time             %ld seconds\n",CNFSerParaList[threadnum].timer_XX);
		printf("Transport Rate         %.3f Byte/s\n",(double)CACHESIZE / (double)CNFSerParaList[threadnum].timer_XX);
		printf("Average Window Length  %ld\n\n",CNFSerParaList[threadnum].TotalWindowLength / (unsigned long)CNFSerParaList[threadnum].InputCount);
		printf("LostPacketCount        %ld\n",CNFSerParaList[threadnum].LostPacketCount);
		printf("TotalPacketCount       %ld\n",CNFSerParaList[threadnum].FileLength / CNFSerParaList[threadnum].PacketDataLength + 1);
		printf("Lost Rate              %.3f%%\n",((double)CNFSerParaList[threadnum].LostPacketCount / ((double)CNFSerParaList[threadnum].FileLength / (double)CNFSerParaList[threadnum].PacketDataLength)) * (double)100);
		printf("========================================\n");
	}

	//关闭其它线程
	CNFThreadList[threadnum].flag_close = 1;

	int closethread1,closethread2,closethread3,closethread4;
	closethread1 = pthread_cancel(CNFSerParaList[threadnum].pthread_NetworkLayertoTransportLayer);
	closethread2 = pthread_cancel(CNFSerParaList[threadnum].pthread_FTP);
	closethread3 = pthread_cancel(CNFSerParaList[threadnum].pthread_CNF);
	closethread4 = pthread_cancel(CNFSerParaList[threadnum].pthread_timer);
	if(closethread1 == 0 && closethread2 == 0 && closethread3 == 0 && closethread4 == 0)
	{
		if(cnfserDEVETESTIMPL <= 7)
		{
			printf("Server Threads Close Success.\n");
			printf(">->->->->->->->->->->->->->->->->->->->->->->->->->->->->->->->->->\n");
		}
	}
	else
	{
		printf("Server Threads Close Failed.\n");
		printf("closethread1 = %d\n",closethread1);
		printf("closethread2 = %d\n",closethread2);
		printf("closethread3 = %d\n",closethread3);
		printf("closethread4 = %d\n",closethread4);
	}
	
	//同时终止该CNF整个任务并回收的所有资源
	CNFServer_Parametershut(threadnum);

	//结束该线程
	pthread_exit(NULL);
	//exit(0);
	//free(fd);
}

/*****************************************
* 函数名称：CNFServer_main
* 功能描述：CNFServer模块主函数，启动各个线程，自身不提供实际功能
* 参数列表：第二参数使用char**argv的方式声明报错，不知是不是语法问题
* 返回结果：
*****************************************/
//int main(int argc, char *argv[])
int
CNFServer_main
(
	void * fd
)
{
	//对CNFServer模块进行线程调用的参数拷贝接口
	struct cnfserinput * pcnfinput;
	pcnfinput = (struct cnfserinput *)fd;
	
	//因physicalport调用方对线程传参存在等待时间的缘故，实参消失太快，此拷贝代码有时不能得到及时传参引发运行死机，故在单任务threadnum常为0的情况下，暂时抛弃这段代码，替换以直接从全局任务参数组拷贝所需参数
	
	int threadnum = pcnfinput->threadnum;

	struct cnfserinput cnfinput;
	cnfinput.threadnum = pcnfinput->threadnum;
	cnfinput.cachelocation = pcnfinput->cachelocation;
	cnfinput.cachelength = pcnfinput->cachelength;
	memcpy(cnfinput.physicalportIP,pcnfinput->physicalportIP,16);
	memcpy(cnfinput.sid,pcnfinput->sid,SIDLEN);
	memcpy(cnfinput.sbd,pcnfinput->sbd,SBDLEN);
	memcpy(cnfinput.offset,pcnfinput->offset,OFFLEN);

	//结束创建线程的等待
	sem_post(&CNFThreadList[threadnum].StartParaTransEnd);
	
/*
	int threadnum;
	int i;
	for(i=0;i<10;i++)
	{
		if(CNFThreadList[i].flag_occupied == 1 && CNFThreadList[i].flag_IO == 1 && CNFThreadList[i].datapkglocation == -1)
		{
			threadnum = i;
			break;
		}
	}
	
	struct cnfserinput cnfinput;
	cnfinput.threadnum = threadnum;
	cnfinput.cachelocation = CNFThreadList[threadnum].cachelocation;
	cnfinput.cachelength = CNFThreadList[threadnum].cachelength;
	memcpy(cnfinput.physicalportIP,CNFThreadList[threadnum].physicalportIP,16);
	memcpy(cnfinput.sid,CNFThreadList[threadnum].sid,SIDLEN);
	memcpy(cnfinput.sbd,CNFThreadList[threadnum].sbd,SBDLEN);
	memcpy(cnfinput.offset,CNFThreadList[threadnum].offset,OFFLEN);
*/
	if(cnfserDEVETESTIMPL <= 6)
	{
		printf("[CNFServer_main]#cnfinput.physicalportIP = %s\n",cnfinput.physicalportIP);
		printf("[CNFServer_main]CNF threadnum == %d (CNFServer_main)\n",threadnum);
	}
	if(cnfserDEVETESTIMPL <= 6)
	{
		printf("[CNFServer_main]==O==ThreadNum = %d\n",threadnum);
		printf("[CNFServer_main]flag_occupied  = %d\n",CNFThreadList[threadnum].flag_occupied);
		printf("[CNFServer_main]flag_IO        = %d\n",CNFThreadList[threadnum].flag_IO);
		printf("[CNFServer_main]datapkglocation= %d\n",CNFThreadList[threadnum].datapkglocation);
		printf("[CNFServer_main]cachelocation  = %d\n",CNFThreadList[threadnum].cachelocation);
		printf("[CNFServer_main]physicalport   = %s\n",CNFThreadList[threadnum].physicalport);
		printf("[CNFServer_main]physicalportIP = %s\n",CNFThreadList[threadnum].physicalportIP);
		printf("[CNFServer_main]sid            = %s\n",CNFThreadList[threadnum].sid);
		printf("[CNFServer_main]offset         = %s\n",CNFThreadList[threadnum].offset);
		printf("[CNFServer_main]===================\n");
	}

	CNFServer_Parameterinit(threadnum);
	
	//创建发送计时器子线程
	if(pthread_create(&CNFSerParaList[threadnum].pthread_timer, NULL, CNFServer_thread_timer, (void *)&cnfinput)!=0)
	{
		perror("Creation of timer thread failed.");
	}

	//创建CNF主子线程
	if(pthread_create(&CNFSerParaList[threadnum].pthread_CNF, NULL, CNFServer_thread_CNF, (void *)&cnfinput)!=0)
	{
		perror("Creation of CNF thread failed.");
	}
	
	//主循环——保留传参到达各线程的接收终端，取消此主循环后会使传参的实际存储过早消失，各下级线程无法读取可用的参数
	while (!CNFThreadList[threadnum].flag_close)
	{
		sleep(1);
	}
}

/*****************************************
* 函数名称：CNFServerStart_main
* 功能描述：CNFServer总起函数，启动CNFServer的TCP传输模块，和下层Publisher协议栈模块
* 参数列表：第二参数使用char**argv的方式声明报错，不知是不是语法问题
* 返回结果：

*****************************************/
int
CNFServerStart_main
(
	int argc,
	char argv[][30]
)
{
	int i;

	//创建CNFServer模块主子线程
	struct cnfserinput cnfinput;
	cnfinput.threadnum = TESTNO;
	memset(cnfinput.sid,0,SIDLEN);
	
	pthread_t pthread_cnfserver;
	
	//创建子线程
	if(pthread_create(&pthread_cnfserver, NULL, CNFServer_main, (void *)&cnfinput)!=0)
	{
		perror("Creation of CNF Server main thread failed.");
	}


	//主循环——客户端代码
	while (1)
	{
		sleep(10000);
	}
}
