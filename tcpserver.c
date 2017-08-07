/*******************************************************************************************************************************************
* 文件名：tcpserver.c
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
gcc tcpserver.c -o tcpserver -lpthread
4、运行（因涉及原始套接字的使用，须root权限）
sudo ./tcpserver
*/

#include"tcpserver.h"

/*******************************************************************************************************************************************
*************************************宏定义配置数据************全局变量定义******************************************************************
*******************************************************************************************************************************************/

/*******************************************************************************************************************************************
*******************************************初始化参数配置相关********************************************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：TCPServer_Parameterinit
* 功能描述：TCPServer模块全局变量赋初值
* 参数列表：
* 返回结果：
*****************************************/
void
TCPServer_Parameterinit()
{
	SockAddrLength = sizeof(struct sockaddr_in);

	TCPSerParaList.LostPacketCount=0;
	TCPSerParaList.InputCount=0;
	TCPSerParaList.TotalWindowLength=0;



	//窗口传输开始
	TCPSerParaList.CountTCPServerWindowBegin_Triggering = 1;
	TCPSerParaList.CountTCPServerWindowBegin_Waiting = 1;
	TCPSerParaList.CountTCPServerWindowBegin_Triggered = 1;
/*
	printf("[%d] WindowBegin triggering...\n",TCPSerParaList.CountTCPServerWindowBegin_Triggering);
	TCPSerParaList.CountTCPServerWindowBegin_Triggering++;
	printf("[%d] WindowBegin waiting...\n",TCPSerParaList.CountTCPServerWindowBegin_Waiting);
	TCPSerParaList.CountTCPServerWindowBegin_Waiting++;
	printf("[%d] WindowBegin triggered!\n",TCPSerParaList.CountTCPServerWindowBegin_Triggered);
	TCPSerParaList.CountTCPServerWindowBegin_Triggered++;
*/
	bzero(&TCPSerParaList.SENDAddrToTCPServerWindowBegin,SockAddrLength);
	TCPSerParaList.SENDAddrToTCPServerWindowBegin.sin_family=AF_INET;
	TCPSerParaList.SENDAddrToTCPServerWindowBegin.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPSerParaList.SENDAddrToTCPServerWindowBegin.sin_port=htons(TCPServerWindowBegin);

	bzero(&TCPSerParaList.RECVAddrToTCPServerWindowBegin,SockAddrLength);
	TCPSerParaList.RECVAddrToTCPServerWindowBegin.sin_family=AF_INET;
	TCPSerParaList.RECVAddrToTCPServerWindowBegin.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPSerParaList.RECVAddrToTCPServerWindowBegin.sin_port=htons(TCPServerWindowBegin);

	TCPSerParaList.SENDTCPServerWindowBegin = socket(AF_INET,SOCK_DGRAM,0);
	TCPSerParaList.RECVTCPServerWindowBegin = socket(AF_INET,SOCK_DGRAM,0);

	bind(TCPSerParaList.RECVTCPServerWindowBegin,(struct sockaddr *)&TCPSerParaList.RECVAddrToTCPServerWindowBegin,SockAddrLength);

	//窗口传输上行通道结束计时
	TCPSerParaList.CountTCPServerWindowTimingEnd_Triggering = 1;
	TCPSerParaList.CountTCPServerWindowTimingEnd_Waiting = 1;
	TCPSerParaList.CountTCPServerWindowTimingEnd_Triggered = 1;
/*
	printf("[%d] WindowTimingEnd triggering...\n",TCPSerParaList.CountTCPServerWindowTimingEnd_Triggering);
	TCPSerParaList.CountTCPServerWindowTimingEnd_Triggering++;
	printf("[%d] WindowTimingEnd waiting...\n",TCPSerParaList.CountTCPServerWindowTimingEnd_Waiting);
	TCPSerParaList.CountTCPServerWindowTimingEnd_Waiting++;
	printf("[%d] WindowTimingEnd triggered!\n",TCPSerParaList.CountTCPServerWindowTimingEnd_Triggered);
	TCPSerParaList.CountTCPServerWindowTimingEnd_Triggered++;
*/
	bzero(&TCPSerParaList.SENDAddrToTCPServerWindowTimingEnd,SockAddrLength);
	TCPSerParaList.SENDAddrToTCPServerWindowTimingEnd.sin_family=AF_INET;
	TCPSerParaList.SENDAddrToTCPServerWindowTimingEnd.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPSerParaList.SENDAddrToTCPServerWindowTimingEnd.sin_port=htons(TCPServerWindowTimingEnd);

	bzero(&TCPSerParaList.RECVAddrToTCPServerWindowTimingEnd,SockAddrLength);
	TCPSerParaList.RECVAddrToTCPServerWindowTimingEnd.sin_family=AF_INET;
	TCPSerParaList.RECVAddrToTCPServerWindowTimingEnd.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPSerParaList.RECVAddrToTCPServerWindowTimingEnd.sin_port=htons(TCPServerWindowTimingEnd);

	TCPSerParaList.SENDTCPServerWindowTimingEnd = socket(AF_INET,SOCK_DGRAM,0);
	TCPSerParaList.RECVTCPServerWindowTimingEnd = socket(AF_INET,SOCK_DGRAM,0);

	bind(TCPSerParaList.RECVTCPServerWindowTimingEnd,(struct sockaddr *)&TCPSerParaList.RECVAddrToTCPServerWindowTimingEnd,SockAddrLength);

	//窗口传输下行通道反馈结果
	TCPSerParaList.CountTCPServerWindowRespond_Triggering = 1;
	TCPSerParaList.CountTCPServerWindowRespond_Waiting = 1;
	TCPSerParaList.CountTCPServerWindowRespond_Triggered = 1;
/*
	printf("[%d] WindowRespond triggering...\n",TCPSerParaList.CountTCPServerWindowRespond_Triggering);
	TCPSerParaList.CountTCPServerWindowRespond_Triggering++;
	printf("[%d] WindowRespond waiting...\n",TCPSerParaList.CountTCPServerWindowRespond_Waiting);
	TCPSerParaList.CountTCPServerWindowRespond_Waiting++;
	printf("[%d] WindowRespond triggered!\n",TCPSerParaList.CountTCPServerWindowRespond_Triggered);
	TCPSerParaList.CountTCPServerWindowRespond_Triggered++;
*/
	bzero(&TCPSerParaList.SENDAddrToTCPServerWindowRespond,SockAddrLength);
	TCPSerParaList.SENDAddrToTCPServerWindowRespond.sin_family=AF_INET;
	TCPSerParaList.SENDAddrToTCPServerWindowRespond.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPSerParaList.SENDAddrToTCPServerWindowRespond.sin_port=htons(TCPServerWindowRespond);

	bzero(&TCPSerParaList.RECVAddrToTCPServerWindowRespond,SockAddrLength);
	TCPSerParaList.RECVAddrToTCPServerWindowRespond.sin_family=AF_INET;
	TCPSerParaList.RECVAddrToTCPServerWindowRespond.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPSerParaList.RECVAddrToTCPServerWindowRespond.sin_port=htons(TCPServerWindowRespond);

	TCPSerParaList.SENDTCPServerWindowRespond = socket(AF_INET,SOCK_DGRAM,0);
	TCPSerParaList.RECVTCPServerWindowRespond = socket(AF_INET,SOCK_DGRAM,0);

	bind(TCPSerParaList.RECVTCPServerWindowRespond,(struct sockaddr *)&TCPSerParaList.RECVAddrToTCPServerWindowRespond,SockAddrLength);

	//发送缓冲启动
	TCPSerParaList.CountTCPServerBufReady_Triggering = 1;
	TCPSerParaList.CountTCPServerBufReady_Waiting = 1;
	TCPSerParaList.CountTCPServerBufReady_Triggered = 1;
/*
	printf("[%d] BufReady triggering...\n",TCPSerParaList.CountTCPServerBufReady_Triggering);
	TCPSerParaList.CountTCPServerBufReady_Triggering++;
	printf("[%d] BufReady waiting...\n",TCPSerParaList.CountTCPServerBufReady_Waiting);
	TCPSerParaList.CountTCPServerBufReady_Waiting++;
	printf("[%d] BufReady triggered!\n",TCPSerParaList.CountTCPServerBufReady_Triggered);
	TCPSerParaList.CountTCPServerBufReady_Triggered++;
*/
	bzero(&TCPSerParaList.SENDAddrToTCPServerBufReady,SockAddrLength);
	TCPSerParaList.SENDAddrToTCPServerBufReady.sin_family=AF_INET;
	TCPSerParaList.SENDAddrToTCPServerBufReady.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPSerParaList.SENDAddrToTCPServerBufReady.sin_port=htons(TCPServerBufReady);

	bzero(&TCPSerParaList.RECVAddrToTCPServerBufReady,SockAddrLength);
	TCPSerParaList.RECVAddrToTCPServerBufReady.sin_family=AF_INET;
	TCPSerParaList.RECVAddrToTCPServerBufReady.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPSerParaList.RECVAddrToTCPServerBufReady.sin_port=htons(TCPServerBufReady);

	TCPSerParaList.SENDTCPServerBufReady = socket(AF_INET,SOCK_DGRAM,0);
	TCPSerParaList.RECVTCPServerBufReady = socket(AF_INET,SOCK_DGRAM,0);

	bind(TCPSerParaList.RECVTCPServerBufReady,(struct sockaddr *)&TCPSerParaList.RECVAddrToTCPServerBufReady,SockAddrLength);

	//供应后续数据
	TCPSerParaList.CountTCPServerMoreData_Triggering = 1;
	TCPSerParaList.CountTCPServerMoreData_Waiting = 1;
	TCPSerParaList.CountTCPServerMoreData_Triggered = 1;
/*
	printf("[%d] MoreData triggering...\n",TCPSerParaList.CountTCPServerMoreData_Triggering);
	TCPSerParaList.CountTCPServerMoreData_Triggering++;
	printf("[%d] MoreData waiting...\n",TCPSerParaList.CountTCPServerMoreData_Waiting);
	TCPSerParaList.CountTCPServerMoreData_Waiting++;
	printf("[%d] MoreData triggered!\n",TCPSerParaList.CountTCPServerMoreData_Triggered);
	TCPSerParaList.CountTCPServerMoreData_Triggered++;
*/
	bzero(&TCPSerParaList.SENDAddrToTCPServerMoreData,SockAddrLength);
	TCPSerParaList.SENDAddrToTCPServerMoreData.sin_family=AF_INET;
	TCPSerParaList.SENDAddrToTCPServerMoreData.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPSerParaList.SENDAddrToTCPServerMoreData.sin_port=htons(TCPServerMoreData);

	bzero(&TCPSerParaList.RECVAddrToTCPServerMoreData,SockAddrLength);
	TCPSerParaList.RECVAddrToTCPServerMoreData.sin_family=AF_INET;
	TCPSerParaList.RECVAddrToTCPServerMoreData.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPSerParaList.RECVAddrToTCPServerMoreData.sin_port=htons(TCPServerMoreData);

	TCPSerParaList.SENDTCPServerMoreData = socket(AF_INET,SOCK_DGRAM,0);
	TCPSerParaList.RECVTCPServerMoreData = socket(AF_INET,SOCK_DGRAM,0);

	bind(TCPSerParaList.RECVTCPServerMoreData,(struct sockaddr *)&TCPSerParaList.RECVAddrToTCPServerMoreData,SockAddrLength);

	//文件读取结束
	TCPSerParaList.CountTCPServerFileClose_Triggering = 1;
	TCPSerParaList.CountTCPServerFileClose_Waiting = 1;
	TCPSerParaList.CountTCPServerFileClose_Triggered = 1;
/*
	printf("[%d] FileClose triggering...\n",TCPSerParaList.CountTCPServerFileClose_Triggering);
	TCPSerParaList.CountTCPServerFileClose_Triggering++;
	printf("[%d] FileClose waiting...\n",TCPSerParaList.CountTCPServerFileClose_Waiting);
	TCPSerParaList.CountTCPServerFileClose_Waiting++;
	printf("[%d] FileClose triggered!\n",TCPSerParaList.CountTCPServerFileClose_Triggered);
	TCPSerParaList.CountTCPServerFileClose_Triggered++;
*/
	bzero(&TCPSerParaList.SENDAddrToTCPServerFileClose,SockAddrLength);
	TCPSerParaList.SENDAddrToTCPServerFileClose.sin_family=AF_INET;
	TCPSerParaList.SENDAddrToTCPServerFileClose.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPSerParaList.SENDAddrToTCPServerFileClose.sin_port=htons(TCPServerFileClose);

	bzero(&TCPSerParaList.RECVAddrToTCPServerFileClose,SockAddrLength);
	TCPSerParaList.RECVAddrToTCPServerFileClose.sin_family=AF_INET;
	TCPSerParaList.RECVAddrToTCPServerFileClose.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPSerParaList.RECVAddrToTCPServerFileClose.sin_port=htons(TCPServerFileClose);

	TCPSerParaList.SENDTCPServerFileClose = socket(AF_INET,SOCK_DGRAM,0);
	TCPSerParaList.RECVTCPServerFileClose = socket(AF_INET,SOCK_DGRAM,0);

	bind(TCPSerParaList.RECVTCPServerFileClose,(struct sockaddr *)&TCPSerParaList.RECVAddrToTCPServerFileClose,SockAddrLength);

	//上行通道继续收包
	TCPSerParaList.CountTCPServerContinueRECV_Triggering = 1;
	TCPSerParaList.CountTCPServerContinueRECV_Waiting = 1;
	TCPSerParaList.CountTCPServerContinueRECV_Triggered = 1;
/*
	printf("[%d] ContinueRECV triggering...\n",TCPSerParaList.CountTCPServerContinueRECV_Triggering);
	TCPSerParaList.CountTCPServerContinueRECV_Triggering++;
	printf("[%d] ContinueRECV waiting...\n",TCPSerParaList.CountTCPServerContinueRECV_Waiting);
	TCPSerParaList.CountTCPServerContinueRECV_Waiting++;
	printf("[%d] ContinueRECV triggered!\n",TCPSerParaList.CountTCPServerContinueRECV_Triggered);
	TCPSerParaList.CountTCPServerContinueRECV_Triggered++;
*/
	bzero(&TCPSerParaList.SENDAddrToTCPServerContinueRECV,SockAddrLength);
	TCPSerParaList.SENDAddrToTCPServerContinueRECV.sin_family=AF_INET;
	TCPSerParaList.SENDAddrToTCPServerContinueRECV.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPSerParaList.SENDAddrToTCPServerContinueRECV.sin_port=htons(TCPServerContinueRECV);

	bzero(&TCPSerParaList.RECVAddrToTCPServerContinueRECV,SockAddrLength);
	TCPSerParaList.RECVAddrToTCPServerContinueRECV.sin_family=AF_INET;
	TCPSerParaList.RECVAddrToTCPServerContinueRECV.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPSerParaList.RECVAddrToTCPServerContinueRECV.sin_port=htons(TCPServerContinueRECV);

	TCPSerParaList.SENDTCPServerContinueRECV = socket(AF_INET,SOCK_DGRAM,0);
	TCPSerParaList.RECVTCPServerContinueRECV = socket(AF_INET,SOCK_DGRAM,0);

	bind(TCPSerParaList.RECVTCPServerContinueRECV,(struct sockaddr *)&TCPSerParaList.RECVAddrToTCPServerContinueRECV,SockAddrLength);

}

/*******************************************************************************************************************************************
*******************************************应用层TCPServer服务器（通过CLI控制）******************************************************************
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
* 函数名称：TCPServer_thread_timer
* 功能描述：为各线程提供计时信号
* 参数列表：
* 返回结果：
*****************************************/
void *
TCPServer_thread_timer
(
	void * fd
)
{
	TCPSerParaList.timer_XX = 0;
	
	while(1)
	{
		//sleep(10000);
		sleep(SLEEP);
		TCPSerParaList.timer_XX++;
		
		//time(&GMT);//读取GMT，赋值给GMT
		//UTC = localtime(&GMT);//GMT-UTC转换
		//printf("GMT(long)   %ld\n",GMT);//[GMT]输出1970.1.1.00:00:00至今秒数
		//printf("UTC(human)  %s",asctime(UTC));//[UTC]输出字符化人类可读时间
	}
	//关闭线程
	exit(0);
	free(fd);
	pthread_exit(NULL);
}

/*****************************************
* 函数名称：TCPServer_thread_TCP
* 功能描述：上行通道 - TCP服务端任务控制主子线程
* 参数列表：
* 返回结果：
*****************************************/
void *
TCPServer_thread_TCP
(
	void * fd
)
{
	int i,j;

	//用于多任务TCP的线程组
	pthread_t pthread_NetworkLayertoTransportLayer;
	pthread_t pthread_TransportLayertoNetworkLayer;
	pthread_t pthread_FTP;

	//用来接收传输层请求SID的套接字
	int socket_sidreceiver;
	socket_sidreceiver = socket(AF_INET,SOCK_DGRAM,0);

	struct sockaddr_in sin;
	int sockaddr_len=SockAddrLength;
	bzero(&sin,sockaddr_len);
	sin.sin_family=AF_INET;
	//sin.sin_addr.s_addr=htonl(INADDR_ANY);
	sin.sin_addr.s_addr=inet_addr(LOOPIP);
	sin.sin_port=htons(NETLtoTRAL);

	bind(socket_sidreceiver,(struct sockaddr *)&sin,sockaddr_len);

	//用作接收SID请求的处理存储变量
	uint8_t SID[SIDLEN];
	uint8_t OFFSET[OFFLEN];
	unsigned long offsetlong;
	uint8_t DATA[DATALEN];
	int SIDlen=0,DATAlen=0;
	
	uint8_t recvpkg[sizeof(Trans_get)];
	Trans_get * precvpkg;
	precvpkg = (Trans_get *)recvpkg;

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
		memset(recvpkg,0,sizeof(Trans_get));

		FoundSIDNum=-1;

		recvfrom(socket_sidreceiver,recvpkg,sizeof(Trans_get),0,(struct sockaddr *)&sin,&sockaddr_len);

		//提取SID与offset
		memcpy(SID,precvpkg->sid,SIDLEN);
		memcpy(OFFSET,precvpkg->offset,OFFLEN);
		SIDlen = 10;

		if(transDEVETESTIMPL <= 4)
		{
			printf("[NetworkLayer to TransportLayer]SID = %s\n",SID);
			printf("[NetworkLayer to TransportLayer]OFF = %d %d %d %d\n",OFFSET[0],OFFSET[1],OFFSET[2],OFFSET[3]);
		}

		//至此TCP网络层上行接口做好
		
		//判断OFFSET是0还是大于0，借此判定收到的GET消息是 新任务请求消息 还是 某已有任务的ACK
		if(OFFSET[0] == 0 && OFFSET[1] == 0 && OFFSET[2] == 3 && OFFSET[3] == 232 && SingleThreadAlreadyStart == 0)//这是新任务请求（暂时将任务数量定为1）
		{
			printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>A New Service Started.\n");
			SingleThreadAlreadyStart = 1;
			
			//初始化任务线程控制参数组
			memset(TCPSerParaList.SID,0,SIDLEN);
			memcpy(TCPSerParaList.SID,SID,SIDlen);
			TCPSerParaList.SIDLen = SIDlen;
	
			TCPSerParaList.BUF = NULL;//发送缓冲区开头
			TCPSerParaList.BUFEnd = NULL;//发送缓冲区结尾
			TCPSerParaList.BUFFileEnd = NULL;//读取文件结束时，缓冲区内文件末尾所在地址

			TCPSerParaList.BUFRenewCount = 1;//缓冲区更新次数
			TCPSerParaList.BUFLength = TCPBUFSIZE;//发送缓冲长度

			TCPSerParaList.FileReadPoint = 0;//文件读取进度
			TCPSerParaList.FileLength = 0;//文件总长度

			TCPSerParaList.PacketDataLength = PKTDATALEN;//单包数据段长度
			TCPSerParaList.LastPacketDataLength = PKTDATALEN;//整个传输任务的最后一个数据包实际长度

			TCPSerParaList.WindowLength = 1;//窗口长度
			TCPSerParaList.WindowThreshold = TCPBUFSIZE;//窗口门限值

			TCPSerParaList.OffsetWindowHead = 0;//在整个文件中窗口头部所指的偏移量
			TCPSerParaList.OffsetWindowEnd = PKTDATALEN;//在整个文件中窗口尾部所指的偏移量
			TCPSerParaList.OffsetConfirmACK = 0;//在整个文件中已确认偏移量所在偏移量
			TCPSerParaList.OffsetRequestACK = 0;//在整个文件中接到请求的偏移量
			TCPSerParaList.OffsetPacket = PKTDATALEN;//在整个文件中当前封包偏移量（回传数据包偏移量字段的填写依据）
			TCPSerParaList.OffsetWaitACK = PKTDATALEN;//在整个文件中等待确认收到的偏移量（下一节）

			TCPSerParaList.AddrWindowHead = NULL;//在缓冲区中窗口头部所在地址
			TCPSerParaList.AddrWindowEnd = NULL;//在缓冲区中窗口尾部所在地址
			TCPSerParaList.AddrConfirmACK = NULL;//在缓冲区中已确认偏移量所在地址
			TCPSerParaList.AddrRequestACK = NULL;//在缓冲区中接到请求的所在地址
			TCPSerParaList.AddrPacket = NULL;//在缓冲区中当前封包偏移量所在地址
			TCPSerParaList.AddrWaitACK = NULL;//在缓冲区中待确认偏移量所在地址

			TCPSerParaList.RTOs = 0;//往返容忍时延（RTO大于1秒部分，单位秒）
			TCPSerParaList.RTOus = 0;//往返容忍时延（RTO小于1秒部分，单位微秒）
			TCPSerParaList.RTOns = 0;//往返容忍时延（RTO小于1秒部分，单位纳秒）

			TCPSerParaList.FlagTrebleAck = 0;//计数器，记录收到相同偏移量ACK的个数，用于判断三重ACK丢包状况

			TCPSerParaList.WindowState = 0;//窗口状态，1ACK正常更新但未达窗口所要求的上界；2窗口传输成功；3三重ACK；4超时
			TCPSerParaList.ThreadState = 0;//任务状态（用于结束过程的控制），0未完成，1文件读取完毕，2窗口录入完毕，3窗口发送完毕，4窗口确认完毕（即可终止）
			
			//创建thread_FTP子线程
			if(pthread_create(&pthread_FTP, NULL, TCPServer_thread_FTP, NULL)!=0)
			{
				perror("Creation of FTP thread failed.");
			}
			
			//创建thread_NetworkLayertoTransportLayer上行子线程
			if(pthread_create(&pthread_NetworkLayertoTransportLayer, NULL, TCPServer_thread_NetworkLayertoTransportLayer, NULL)!=0)
			{
				perror("Creation of NetworkLayertoTransportLayer thread failed.");
			}
	
			//创建thread_TransportLayertoNetworkLayer下行子线程
			if(pthread_create(&pthread_TransportLayertoNetworkLayer, NULL, TCPServer_thread_TransportLayertoNetworkLayer, NULL)!=0)
			{
				perror("Creation of TransportLayertoNetworkLayer thread failed.");
			}
			
			//通知应用层查找SID数据并存入发送缓存
			//（暂时以单任务假设简化开发）
			printf("[RECV new]offsetlong = %ld\n",(unsigned long)1000);
			printf("[RECV new]OffsetRequestACK  = %ld\n",TCPSerParaList.OffsetRequestACK);
		}
		else//这是已有任务的ACK
		{
			//printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>There is an ACK for a Single Thread which Already Started.\n");

			offsetlong    = (unsigned long)OFFSET[0] * 256 * 256 * 256 + 
					(unsigned long)OFFSET[1] * 256 * 256 + 
					(unsigned long)OFFSET[2] * 256 + 
					(unsigned long)OFFSET[3];

			//匹配SID，查找与SID对应的任务线程编号
			if(strncmp(TCPSerParaList.SID,SID,SIDLEN) == 0)
			{
				FoundSIDNum = 0;
			}
			if(FoundSIDNum == -1)
			{
				//printf("An unknown ACK Packet received, SID not found.\n");
				continue;
			}
			
			TCPSerParaList.SIDLen = SIDlen;

			if(transDEVETESTIMPL <= 5)
			{
				printf("[RECV]offsetlong       = %ld\n",offsetlong);
				printf("[LAST]OffsetRequestACK = %ld\n",TCPSerParaList.OffsetRequestACK);
				printf("[NOW ]OffsetWindowEnd  = %ld\n",TCPSerParaList.OffsetWindowEnd);
			}

			if(offsetlong > TCPSerParaList.OffsetRequestACK)//新的请求偏移量，更新确认偏移量值
			{//printf("New ACK\n");
				TCPSerParaList.OffsetRequestACK = offsetlong;
				TCPSerParaList.OffsetConfirmACK = TCPSerParaList.OffsetRequestACK - TCPSerParaList.PacketDataLength;
				
				TCPSerParaList.FlagTrebleAck = 0;
				
				TCPSerParaList.WindowState = 1;
				
				if(TCPSerParaList.OffsetRequestACK == TCPSerParaList.OffsetWindowEnd)//收到ACK到达所等待窗口的上界
				{
					TCPSerParaList.WindowState = 2;
				}
			}
			else if(offsetlong == TCPSerParaList.OffsetRequestACK)//收到重复偏移量的ACK
			{//printf("Same ACK\n");printf("[RECV]offsetlong       = %ld\n",offsetlong);
				TCPSerParaList.FlagTrebleAck++;
				
				if(TCPSerParaList.FlagTrebleAck >= 3)//重复ACK达3次
				{
					//printf("TrebleAck Reached!\n");
					TCPSerParaList.WindowState = 3;
					TCPSerParaList.FlagTrebleAck = 0;
					
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

			sendto(TCPSerParaList.SENDTCPServerWindowTimingEnd,"WindowTimingEnd",20,0,(struct sockaddr *)&TCPSerParaList.SENDAddrToTCPServerWindowTimingEnd,SockAddrLength);

			//printf("[%d] WindowTimingEnd triggering...\n",TCPSerParaList.CountTCPServerWindowTimingEnd_Triggering);
			TCPSerParaList.CountTCPServerWindowTimingEnd_Triggering++;
			
			//如果是非正常情况（到达窗口上界或三重ACK）的触发WindowTimingEnd，须排除正常ACK更新并等待下行通道回送继续收包的指令

			if(TCPSerParaList.WindowState != 1)
			{
				//阻塞等待下行通道回送继续收包的指令
				//printf("[%d] ContinueRECV waiting...\n",TCPSerParaList.CountTCPServerContinueRECV_Waiting);
				TCPSerParaList.CountTCPServerContinueRECV_Waiting++;

				recvfrom(TCPSerParaList.RECVTCPServerContinueRECV,Trigger,20,0,(struct sockaddr *)&TCPSerParaList.RECVAddrToTCPServerContinueRECV,&SockAddrLength);

				//printf("[%d] ContinueRECV triggered.\n",TCPSerParaList.CountTCPServerContinueRECV_Triggered);
				TCPSerParaList.CountTCPServerContinueRECV_Triggered++;
			}

		}
	}
	
	close(socket_sidreceiver);

	//关闭线程
	exit(0);
	free(fd);
	pthread_exit(NULL);	
}

/*****************************************
* 函数名称：TCPServer_thread_FTP
* 功能描述：读取文件线程（FTP前身），负责读取文件并维持发送缓冲的更新
* 参数列表：
* 返回结果：
*****************************************/
void *
TCPServer_thread_FTP
(
	void * fd
)
{
	//提取任务编号
	//int ThreadNum = *((int *)fd);printf("[FTP]ThreadNum = %d\n",ThreadNum);
	
	//为任务申请发送缓冲内存
	TCPSerParaList.BUF = (uint8_t *)malloc(TCPBUFSIZE);
	memset(TCPSerParaList.BUF,0,TCPBUFSIZE);
	
	//依照任务编号对应的参数组SID寻找对应的文件
	
	
	//打开文件并获取所需参数
	int fp;
	unsigned long filelen;
	
	fp = open(FTPServerPath,O_RDONLY);
	filelen = lseek(fp,0,SEEK_END);
	//向参数组拷贝文件总长度
	TCPSerParaList.FileLength = filelen;
	
	printf("FileLength = %ld\n",TCPSerParaList.FileLength);
	
	TCPSerParaList.BUFEnd = TCPSerParaList.BUF + TCPSerParaList.BUFLength;

	//如果文件总长度小于缓冲区长度（针对小文件）
	int readlength = 0;
	if(TCPSerParaList.FileLength <= TCPSerParaList.BUFLength)
	{
		printf("File is very small, smaller than the BUFFER.\n");
		readlength = TCPSerParaList.FileLength;
		TCPSerParaList.BUFFileEnd = TCPSerParaList.BUF + TCPSerParaList.FileLength;
		TCPSerParaList.ThreadState = 1;
	}
	else
	{
		readlength = TCPBUFSIZE;
	}

	//读取第一批数据
	lseek(fp,0,SEEK_SET);
	read(fp,TCPSerParaList.BUF,readlength);
	//相应地修改文件控制参数
	TCPSerParaList.BUFRenewCount = 0;
	TCPSerParaList.FileReadPoint = TCPBUFSIZE;
	
	//printf("BUF = %s\n",TCPSerParaList.BUF);
	
	//通知传输层，发送缓冲已经准备就绪
	sendto(TCPSerParaList.SENDTCPServerBufReady,"BufReady",20,0,(struct sockaddr *)&TCPSerParaList.SENDAddrToTCPServerBufReady,SockAddrLength);

	printf("[%d] BufReady triggering...\n",TCPSerParaList.CountTCPServerBufReady_Triggering);
	TCPSerParaList.CountTCPServerBufReady_Triggering++;
	
	//开始持续为传输层供应数据
	while(TCPSerParaList.ThreadState == 0)
	{
		//阻塞等待传输层触发对供应后续数据的要求
		//printf("[%d] MoreData waiting...\n",TCPSerParaList.CountTCPServerMoreData_Waiting);
		TCPSerParaList.CountTCPServerMoreData_Waiting++;

		recvfrom(TCPSerParaList.RECVTCPServerMoreData,Trigger,20,0,(struct sockaddr *)&TCPSerParaList.RECVAddrToTCPServerMoreData,&SockAddrLength);

		//printf("[%d] MoreData triggered.\n",TCPSerParaList.CountTCPServerMoreData_Triggered);
		TCPSerParaList.CountTCPServerMoreData_Triggered++;

		TCPSerParaList.BUFRenewCount++;

		printf("FILE Reloading...(Per BUFLEN/2 for once)\n");

		//一次更新发送缓冲中一半的内容，前半段和后半段交替更新
		if(TCPSerParaList.BUFRenewCount % 2 == 1)//指示更新前半段
		{
			//检查文件剩余长度是否足够一次补充
			if(TCPSerParaList.FileReadPoint + TCPBUFSIZE/2 > filelen)//不足一次补充，则补足余下数据，并记录尾部标识
			{
				lseek(fp,TCPSerParaList.FileReadPoint,SEEK_SET);
				read(fp,TCPSerParaList.BUF,filelen - TCPSerParaList.FileReadPoint);
				
				TCPSerParaList.BUFFileEnd = TCPSerParaList.BUF + ( filelen - TCPSerParaList.FileReadPoint );
				TCPSerParaList.ThreadState = 1;
				break;
			}
			else//足够一次补充，则补充
			{
				lseek(fp,TCPSerParaList.FileReadPoint,SEEK_SET);
				read(fp,TCPSerParaList.BUF,TCPBUFSIZE/2);
			
				TCPSerParaList.FileReadPoint += TCPBUFSIZE/2;
			}
		}
		else if(TCPSerParaList.BUFRenewCount % 2 == 0)//指示更新后半段
		{
			//检查文件剩余长度是否足够一次补充
			if(TCPSerParaList.FileReadPoint + TCPBUFSIZE/2 > filelen)//不足一次补充，则补足余下数据，并记录尾部标识
			{
				lseek(fp,TCPSerParaList.FileReadPoint,SEEK_SET);
				read(fp,TCPSerParaList.BUF + TCPBUFSIZE/2,filelen - TCPSerParaList.FileReadPoint);
				
				TCPSerParaList.BUFFileEnd = TCPSerParaList.BUF + TCPBUFSIZE/2 + ( filelen - TCPSerParaList.FileReadPoint );
				TCPSerParaList.ThreadState = 1;
				break;
			}
			else//足够一次补充，则补充
			{
				lseek(fp,TCPSerParaList.FileReadPoint,SEEK_SET);
				read(fp,TCPSerParaList.BUF + TCPBUFSIZE/2,TCPBUFSIZE/2);
			
				TCPSerParaList.FileReadPoint += TCPBUFSIZE/2;
			}
		}
		printf("FILE Reloaded. Already loaded: %ld Byte\n",TCPSerParaList.FileReadPoint);
	}

	//向下行通道通知文件读取结束
	sendto(TCPSerParaList.SENDTCPServerFileClose,"FileClose",20,0,(struct sockaddr *)&TCPSerParaList.SENDAddrToTCPServerFileClose,SockAddrLength);

	//printf("[%d] FileClose triggering...\n",TCPSerParaList.CountTCPServerFileClose_Triggering);
	TCPSerParaList.CountTCPServerFileClose_Triggering++;
	
	close(fp);
}

/*****************************************
* 函数名称：TCPServer_thread_NetworkLayertoTransportLayer
* 功能描述：上行通道 - From.数据响应端   To.应用服务器，负责ACK的接收和计时
* 参数列表：
* 返回结果：
*****************************************/
void *
TCPServer_thread_NetworkLayertoTransportLayer
(
	void * fd
)
{
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
		
		if(TCPSerParaList.WindowState != 1)
		{
			//阻塞等待定时任务

			//printf("[%d] WindowBegin waiting...\n",TCPSerParaList.CountTCPServerWindowBegin_Waiting);
			TCPSerParaList.CountTCPServerWindowBegin_Waiting++;

			recvfrom(TCPSerParaList.RECVTCPServerWindowBegin,Trigger,20,0,(struct sockaddr *)&TCPSerParaList.RECVAddrToTCPServerWindowBegin,&SockAddrLength);

			//printf("[%d] WindowBegin triggered!\n",TCPSerParaList.CountTCPServerWindowBegin_Triggered);
			TCPSerParaList.CountTCPServerWindowBegin_Triggered++;
		}
		
		//定时阻塞窗口传输上行通道结束计时提示

		//printf("[%d] WindowTimingEnd waiting...\n",TCPSerParaList.CountTCPServerWindowTimingEnd_Waiting);
		TCPSerParaList.CountTCPServerWindowTimingEnd_Waiting++;

		//带超时的UDP消息接收
		//设置超时
		delaytime.tv_sec=TCPSerParaList.RTOs;
		delaytime.tv_usec=TCPSerParaList.RTOus;

		//记录sockfd
		FD_ZERO(&readfds);
		FD_SET(TCPSerParaList.RECVTCPServerWindowTimingEnd,&readfds);

		select(TCPSerParaList.RECVTCPServerWindowTimingEnd+1,&readfds,NULL,NULL,&delaytime);
	
		//限时接收
		if(FD_ISSET(TCPSerParaList.RECVTCPServerWindowTimingEnd,&readfds))
		{
			if(0 <= recvfrom(TCPSerParaList.RECVTCPServerWindowTimingEnd,Trigger,20,0,(struct sockaddr *)&TCPSerParaList.RECVAddrToTCPServerWindowTimingEnd,&SockAddrLength))
			{
				if(transDEVETESTIMPL <= 0)
					printf("[TimingEndDelay]  %.3f ms\n",(double)(RTOUS - (int)delaytime.tv_usec)/(double)1000);
				judge = 1;
			}
		}
		else
		{
			if(transDEVETESTIMPL <= 0)
				printf("[TimingEndDelay]  %.3f ms   (Timeout)\n",(double)(RTOUS - (int)delaytime.tv_usec)/(double)1000);
		}

		//printf("[%d] WindowTimingEnd triggered!\n",TCPSerParaList.CountTCPServerWindowTimingEnd_Triggered);
		TCPSerParaList.CountTCPServerWindowTimingEnd_Triggered++;

		//显示结果
		if(judge > 0)//按时完成
		{
			//printf("On Time!\n");
			
			//按时接收到新的ACK但整个窗口尚未传输成功，属于可正常等待的情况，故重置定时器
			if(TCPSerParaList.WindowState == 1)
			{
				continue;
			}
			//其它情况（2窗口按时传输成功 3三重ACK）均需要重新做窗口传输处理
		}
		else//超时
		{
			//printf("Time Out!\n");
			TCPSerParaList.WindowState = 4;
			//printf("WindowState = %d\n",TCPSerParaList.WindowState);
		}

		//通知下行通道，反馈本次窗口传输已得出结果
		sendto(TCPSerParaList.SENDTCPServerWindowRespond,"WindowRespond",20,0,(struct sockaddr *)&TCPSerParaList.SENDAddrToTCPServerWindowRespond,SockAddrLength);

		//printf("[%d] WindowRespond triggering...\n",TCPSerParaList.CountTCPServerWindowRespond_Triggering);
		TCPSerParaList.CountTCPServerWindowRespond_Triggering++;
	}
	
	//关闭线程
	exit(0);
	free(fd);
	pthread_exit(NULL);
}

/*****************************************
* 函数名称：TCPServer_thread_TransportLayertoNetworkLayer
* 功能描述：下行通道 - From.应用服务器 To.数据响应端，负责窗口的计算与滑动、超时的响应、封装数据并向下递交
* 参数列表：
* 返回结果：
*****************************************/
void *
TCPServer_thread_TransportLayertoNetworkLayer
(
	void * fd
)
{
	//提取任务编号
	//int ThreadNum = *((int *)fd);printf("[DOWN]ThreadNum = %d\n",ThreadNum);
	
	//阻塞，须等待发送缓冲准备就绪

	printf("[%d] BufReady waiting...\n",TCPSerParaList.CountTCPServerBufReady_Waiting);
	TCPSerParaList.CountTCPServerBufReady_Waiting++;

	recvfrom(TCPSerParaList.RECVTCPServerBufReady,Trigger,20,0,(struct sockaddr *)&TCPSerParaList.RECVAddrToTCPServerBufReady,&SockAddrLength);

	printf("[%d] BufReady triggered!\n",TCPSerParaList.CountTCPServerBufReady_Triggered);
	TCPSerParaList.CountTCPServerBufReady_Triggered++;

	int i,j;
	
	//参数初始化（任务初始触发到此的时候，已经意味着收到偏移为PKTDATALEN的请求）

	TCPSerParaList.BUFLength = TCPBUFSIZE;//发送缓冲长度

	TCPSerParaList.PacketDataLength = PKTDATALEN;//单包数据段长度
	TCPSerParaList.LastPacketDataLength = PKTDATALEN;//整个传输任务的最后一个数据包实际长度

	TCPSerParaList.WindowLength = 2;//窗口长度
	TCPSerParaList.WindowThreshold = TCPBUFSIZE;//窗口门限值

	TCPSerParaList.OffsetWindowHead = 0;//在整个文件中窗口头部所指的偏移量
	TCPSerParaList.OffsetWindowEnd = PKTDATALEN + TCPSerParaList.WindowLength * TCPSerParaList.PacketDataLength;//在整个文件中窗口尾部所指的偏移量
	TCPSerParaList.OffsetConfirmACK = 0;//在整个文件中已确认偏移量所在偏移量
	TCPSerParaList.OffsetRequestACK = PKTDATALEN;//在整个文件中接到请求的偏移量
	TCPSerParaList.OffsetPacket = PKTDATALEN;//在整个文件中当前封包偏移量（回传数据包偏移量字段的填写依据）
	TCPSerParaList.OffsetWaitACK = PKTDATALEN;//在整个文件中等待确认收到的偏移量（下一节）

	TCPSerParaList.AddrWindowHead = TCPSerParaList.BUF;//在缓冲区中窗口头部所在地址
	TCPSerParaList.AddrWindowEnd = TCPSerParaList.BUF + TCPSerParaList.WindowLength * TCPSerParaList.PacketDataLength;//在缓冲区中窗口尾部所在地址
	TCPSerParaList.AddrConfirmACK = TCPSerParaList.BUF;//在缓冲区中已确认偏移量所在地址
	TCPSerParaList.AddrRequestACK = TCPSerParaList.BUF;//在缓冲区中接到请求的所在地址
	TCPSerParaList.AddrPacket = TCPSerParaList.BUF;//在缓冲区中当前封包偏移量所在地址
	TCPSerParaList.AddrWaitACK = TCPSerParaList.BUF;//在缓冲区中待确认偏移量所在地址

	TCPSerParaList.RTOs = RTOS;//往返容忍时延（RTO大于1秒部分，单位秒）
	TCPSerParaList.RTOus = RTOUS;//往返容忍时延（RTO小于1秒部分，单位微秒）
	TCPSerParaList.RTOns = RTONS;//往返容忍时延（RTO小于1秒部分，单位纳秒）

	TCPSerParaList.FlagTrebleAck = 0;//计数器，记录收到相同偏移量ACK的个数，用于判断三重ACK丢包状况

	TCPSerParaList.WindowState = 0;//窗口状态，1ACK正常更新但未达窗口所要求的上界；2窗口传输成功；3三重ACK；4超时
	//TCPSerParaList.ThreadState = 0;//任务状态此时已经改变（FTP线程中读取小文件时会发生改变，故不能再次初始化）



	//传输过程变量

	uint8_t DATA[DATALEN];
	unsigned long offsetlong;
	uint8_t offset[OFFLEN];
	
	uint8_t sendpkg[sizeof(CoLoR_data)];
	Trans_data * psendpkg;
	psendpkg = (Trans_data *)sendpkg;

	while(1)
	{
		TCPSerParaList.FlagTrebleAck = 0;

		//如果文件已经读取完毕，则须检查发送过程是否已经到文件末尾
		//printf("ThreadState == %d\n",TCPSerParaList.ThreadState);
		//printf("[SET TAIL]TCPSerParaList.AddrWindowEnd   = %d\n",TCPSerParaList.AddrWindowEnd - TCPSerParaList.BUF);
		//printf("ThreadState = %d\n",TCPSerParaList.ThreadState);
		if(TCPSerParaList.ThreadState >= 1)
		{
/*
			printf("[CHECK TAIL]OffsetConfirmACK == %ld\n",TCPSerParaList.OffsetConfirmACK);
			printf("[CHECK TAIL]OffsetRequestACK == %ld\n",TCPSerParaList.OffsetRequestACK);
			printf("[CHECK TAIL]OffsetPacket + WindowLength * PacketDataLength == %ld\n",TCPSerParaList.OffsetPacket + TCPSerParaList.WindowLength * TCPSerParaList.PacketDataLength);
*/
			if( TCPSerParaList.OffsetPacket - PKTDATALEN + TCPSerParaList.WindowLength * TCPSerParaList.PacketDataLength > TCPSerParaList.FileLength )
			{
				TCPSerParaList.ThreadState = 2;
				
				//根据文件剩余长度重新计算窗口大小
				TCPSerParaList.WindowLength = ( TCPSerParaList.FileLength - TCPSerParaList.OffsetConfirmACK ) / TCPSerParaList.PacketDataLength;
				printf("WindowLength = %ld\n",TCPSerParaList.WindowLength);
				if(( TCPSerParaList.FileLength - TCPSerParaList.OffsetConfirmACK ) % TCPSerParaList.PacketDataLength != 0)
					TCPSerParaList.WindowLength++;
				printf("WindowLength = %ld\n",TCPSerParaList.WindowLength);

				//更新窗口尾部
				TCPSerParaList.OffsetWindowEnd = TCPSerParaList.OffsetWindowHead + TCPSerParaList.WindowLength * TCPSerParaList.PacketDataLength;
				TCPSerParaList.AddrWindowEnd   = TCPSerParaList.AddrWindowHead   + TCPSerParaList.WindowLength * TCPSerParaList.PacketDataLength;
				printf("[SET TAIL]TCPSerParaList.OffsetWindowEnd = %ld\n",TCPSerParaList.OffsetWindowEnd);
				printf("[SET TAIL]TCPSerParaList.AddrWindowEnd   = %d\n",TCPSerParaList.AddrWindowEnd - TCPSerParaList.BUF);
			}
		}
		
		//循环发送窗口内的数据包


		//记录窗口长度变化过程
		TCPSerParaList.InputCount++;
		TCPSerParaList.TotalWindowLength += TCPSerParaList.WindowLength;
		//printf("[%d] ",TCPSerParaList.InputCount);
		//printf("WindowLength = %ld\n",TCPSerParaList.WindowLength);
		
/*
		itoa((int)TCPSerParaList.WindowLength,TCPSerParaList.NumStr,10);
		if(TCPSerParaList.WindowLength<10)
			write(TCPSerParaList.LogFilePoint,TCPSerParaList.NumStr,1);
		else if(TCPSerParaList.WindowLength<100)
			write(TCPSerParaList.LogFilePoint,TCPSerParaList.NumStr,2);
		else if(TCPSerParaList.WindowLength<1000)
			write(TCPSerParaList.LogFilePoint,TCPSerParaList.NumStr,3);
		write(TCPSerParaList.LogFilePoint," ",1);
*/

		for(i=0;i<TCPSerParaList.WindowLength;i++)
		{
			if(transDEVETESTIMPL <= 5)
				printf("WindowLength = %ld\n",TCPSerParaList.WindowLength);

			memset(sendpkg,0,sizeof(CoLoR_data));
			
			//读取窗口数据
			if(i == TCPSerParaList.WindowLength - 1 && TCPSerParaList.ThreadState >= 2)//如果已经录入到达整个传输任务的最后一个包
			{printf("The last Packet!!!!\n");

				printf("[LAST PACKET]AddrWindowEnd - BUF        = %d\n",TCPSerParaList.AddrWindowEnd - TCPSerParaList.BUF);
				printf("[LAST PACKET]AddrWindowEnd - AddrPacket = %d\n",TCPSerParaList.AddrWindowEnd - TCPSerParaList.AddrPacket);

				memcpy(DATA,TCPSerParaList.AddrPacket,TCPSerParaList.AddrWindowEnd - TCPSerParaList.AddrPacket);

				TCPSerParaList.LastPacketDataLength = TCPSerParaList.AddrWindowEnd - TCPSerParaList.AddrPacket;
				
				//换算offset的数据类型
				offsetlong = TCPSerParaList.OffsetPacket;
				for(j=OFFLEN-1;j>=0;j--)
				{
					offset[j] = (char)offsetlong%256;
					offsetlong/=256;
				}
				printf("Sent Offset = %ld\n",TCPSerParaList.OffsetPacket);
				//printf("Sent Offset = %d %d %d %d\n",(int)offset[0],(int)offset[1],(int)offset[2],(int)offset[3]);

				//封装SID、DATA、offset
				memcpy(psendpkg->sid,TCPSerParaList.SID,SIDLEN);
				memcpy(psendpkg->data,DATA,TCPSerParaList.AddrWindowEnd - TCPSerParaList.AddrPacket);
				memcpy(psendpkg->offset,offset,OFFLEN);
				/*
				//封装消息
				memcpy(message,"GOT",3);
				memcpy(message + 3,DATA,TCPSerParaList.AddrWindowEnd - TCPSerParaList.AddrPacket);
				memcpy(message + 3 + TCPSerParaList.LastPacketDataLength,"GET",3);
				memcpy(message + 3 + TCPSerParaList.LastPacketDataLength + 3,TCPSerParaList.SID,TCPSerParaList.SIDLen);
				memcpy(message + 3 + TCPSerParaList.LastPacketDataLength + 3 + TCPSerParaList.SIDLen,"OFF",3);
				memcpy(message + 3 + TCPSerParaList.LastPacketDataLength + 3 + TCPSerParaList.SIDLen + 3,offset,OFFLEN);
				*/
			
				//间隔发出
				//创建socket
				//套接口描述字
				int socket_datasender;
				socket_datasender = socket(AF_INET,SOCK_DGRAM,0);
		
				struct sockaddr_in addrTo;
				bzero(&addrTo,SockAddrLength);
				addrTo.sin_family=AF_INET;
				addrTo.sin_port=htons(TRALtoNETL);
				//unsigned long IPto = 2130706433;//回环地址名称 == 2130706433
				//addrTo.sin_addr.s_addr=htonl(IPto);//htonl将主机字节序转换为网络字节序
				addrTo.sin_addr.s_addr=inet_addr(LOOPIP);//htonl将主机字节序转换为网络字节序

				//间隔一定时间发送下一个包
				usleep(FlowSlot);
			
				//发送SID信令
				sendto(socket_datasender,sendpkg,sizeof(Trans_data),0,(struct sockaddr *)&addrTo,SockAddrLength);
				printf("DATAsent\n");
				//设置RTO计时器
				if(i == 0)
				{
					sendto(TCPSerParaList.SENDTCPServerWindowBegin,"WindowBegin",20,0,(struct sockaddr *)&TCPSerParaList.SENDAddrToTCPServerWindowBegin,SockAddrLength);

					//printf("[%d] WindowBegin triggering...\n",TCPSerParaList.CountTCPServerWindowBegin_Triggering);
					TCPSerParaList.CountTCPServerWindowBegin_Triggering++;
				}
			
				close(socket_datasender);
			
				//参数变化
				//TCPSerParaList.OffsetPacket += TCPSerParaList.PacketDataLength;
				//TCPSerParaList.AddrPacket   += TCPSerParaList.PacketDataLength;
			
				//缓冲区回环处理
				if(TCPSerParaList.AddrPacket >= TCPSerParaList.BUFEnd)
				{
					TCPSerParaList.AddrPacket = TCPSerParaList.BUF + ( TCPSerParaList.AddrPacket - TCPSerParaList.BUFEnd );
				}

				TCPSerParaList.OffsetWaitACK = TCPSerParaList.OffsetPacket;
				TCPSerParaList.AddrWaitACK   = TCPSerParaList.AddrPacket;
				
				//（传输任务末端测试用）校验累加的文件长度是否与实际文件长度相符
				if(TCPSerParaList.OffsetWaitACK > TCPSerParaList.FileLength + PKTDATALEN)
				{
					printf("Deadly Error! [ OffsetWaitACK > FileLength + PKTDATALEN ] In The End!\n");
					exit(0);
				}
				else
				{
					//printf("File Length Checking passed!.\n");
				}

				TCPSerParaList.ThreadState = 3;//修改任务状态为：3窗口发送完毕
			}
			else//发送的数据包尚未到整个任务的最后一个
			{
/*
				printf("[NOT END]AddrWindowEnd - BUF        = %d\n",TCPSerParaList.AddrWindowEnd - TCPSerParaList.BUF);
				printf("[NOT END]BUFFileEnd    - AddrPacket = %d\n",TCPSerParaList.BUFFileEnd - TCPSerParaList.AddrPacket);
				printf("[NOT END]AddrWindowEnd - AddrPacket = %d\n",TCPSerParaList.AddrWindowEnd - TCPSerParaList.AddrPacket);
				printf("[NOT END]OffsetPacket               = %ld\n",TCPSerParaList.OffsetPacket);
*/
				memcpy(DATA,TCPSerParaList.AddrPacket,TCPSerParaList.PacketDataLength);

				//printf("DATA = \n");
				int testnum;
				for(testnum=0;testnum<TCPSerParaList.PacketDataLength;testnum++)
				{
					//printf("%c",DATA[testnum]);
				}
				//printf("\n");
				//换算offset的数据类型
				offsetlong = TCPSerParaList.OffsetPacket;
				for(j=OFFLEN-1;j>=0;j--)
				{
					offset[j] = (char)offsetlong%256;
					offsetlong/=256;
				}

				if(transDEVETESTIMPL <= 5)
					printf("Sent Offset = %ld\n",TCPSerParaList.OffsetPacket);

				//printf("Sent Offset = %d %d %d %d\n",(int)offset[0],(int)offset[1],(int)offset[2],(int)offset[3]);

				//printf("OFFSET = %d %d %d %d\n",offset[0],offset[1],offset[2],offset[3]);
				//printf("PacketDataLength = %ld\n",TCPSerParaList.PacketDataLength);
				//printf("SIDLen = %d\n",TCPSerParaList.SIDLen);
				
				//封装SID、DATA、offset
				memcpy(psendpkg->sid,TCPSerParaList.SID,SIDLEN);
				memcpy(psendpkg->data,DATA,TCPSerParaList.PacketDataLength);
				memcpy(psendpkg->offset,offset,OFFLEN);
				
				/*
				//封装消息
				memcpy(message,"GOT",3);
				memcpy(message + 3,DATA,TCPSerParaList.PacketDataLength);
				memcpy(message + 3 + TCPSerParaList.PacketDataLength,"GET",3);
				memcpy(message + 3 + TCPSerParaList.PacketDataLength + 3,TCPSerParaList.SID,TCPSerParaList.SIDLen);
				memcpy(message + 3 + TCPSerParaList.PacketDataLength + 3 + TCPSerParaList.SIDLen,"OFF",3);
				memcpy(message + 3 + TCPSerParaList.PacketDataLength + 3 + TCPSerParaList.SIDLen + 3,offset,OFFLEN);
				*/
			
				//间隔发出
				//创建socket
				//套接口描述字
				int socket_datasender;
				socket_datasender = socket(AF_INET,SOCK_DGRAM,0);
		
				struct sockaddr_in addrTo;
				bzero(&addrTo,SockAddrLength);
				addrTo.sin_family=AF_INET;
				addrTo.sin_port=htons(TRALtoNETL);
				//unsigned long IPto = 2130706433;//回环地址名称 == 2130706433
				//addrTo.sin_addr.s_addr=htonl(IPto);//htonl将主机字节序转换为网络字节序
				addrTo.sin_addr.s_addr=inet_addr(LOOPIP);//htonl将主机字节序转换为网络字节序

				//间隔一定时间发送下一个包
				usleep(FlowSlot);
			
				//发送SID信令
				sendto(socket_datasender,sendpkg,sizeof(Trans_data),0,(struct sockaddr *)&addrTo,SockAddrLength);
				
				//设置RTO计时器
				if(i == 0)
				{
					sendto(TCPSerParaList.SENDTCPServerWindowBegin,"WindowBegin",20,0,(struct sockaddr *)&TCPSerParaList.SENDAddrToTCPServerWindowBegin,SockAddrLength);

					//printf("[%d] WindowBegin triggering...\n",TCPSerParaList.CountTCPServerWindowBegin_Triggering);
					TCPSerParaList.CountTCPServerWindowBegin_Triggering++;
				}
			
				close(socket_datasender);
			
				//参数变化
				TCPSerParaList.OffsetPacket += TCPSerParaList.PacketDataLength;
				TCPSerParaList.AddrPacket   += TCPSerParaList.PacketDataLength;
			
				//缓冲区回环处理
				if(TCPSerParaList.AddrPacket >= TCPSerParaList.BUFEnd)
				{
					TCPSerParaList.AddrPacket = TCPSerParaList.BUF + ( TCPSerParaList.AddrPacket - TCPSerParaList.BUFEnd );
				}

				TCPSerParaList.OffsetWaitACK = TCPSerParaList.OffsetPacket;
				TCPSerParaList.AddrWaitACK   = TCPSerParaList.AddrPacket;
/*
				printf("[PARA CHANGE]OffsetPacket     = %ld\n",TCPSerParaList.OffsetPacket);
				printf("[PARA CHANGE]AddrPacket - BUF = %d\n",TCPSerParaList.AddrPacket - TCPSerParaList.BUF);
				printf("[PARA CHANGE]OffsetWaitACK    = %ld\n",TCPSerParaList.OffsetWaitACK);
				printf("[PARA CHANGE]AddrWaitACK- BUF = %d\n",TCPSerParaList.AddrWaitACK - TCPSerParaList.BUF);
*/
			}
		}
		
		//进入阻塞，等待上行通道信号

		//printf("[%d] WindowRespond waiting...\n",TCPSerParaList.CountTCPServerWindowRespond_Waiting);
		TCPSerParaList.CountTCPServerWindowRespond_Waiting++;

		recvfrom(TCPSerParaList.RECVTCPServerWindowRespond,Trigger,20,0,(struct sockaddr *)&TCPSerParaList.RECVAddrToTCPServerWindowRespond,&SockAddrLength);

		//printf("[%d] WindowRespond triggered!\n",TCPSerParaList.CountTCPServerWindowRespond_Triggered);
		TCPSerParaList.CountTCPServerWindowRespond_Triggered++;
		
		//任务参数计算规则
		
		//窗口大小、窗口滑动、门限值等相关参数计算，依据参数：TCPSerParaList.WindowState和TCPSerParaList.OffsetRequestACK
		//printf("WindowState = %d\n",TCPSerParaList.WindowState);

		if(TCPSerParaList.WindowState == 1)//ACK正常更新但未达窗口所要求的上界
		{
			//printf("After WindowRespond, WindowState == 1. Maybe not normal. Check the code.\n");
			TCPSerParaList.WindowState = 0;
		}
		else if(TCPSerParaList.WindowState == 2)//整个窗口顺利传输完毕
		{
			TCPSerParaList.WindowState = 0;
			
/*尚未设置客户端对最后一个包成功接收的反馈，故此段代码不可能得到执行，暂时放在超时中执行
			//整个任务传输成功
			if(TCPSerParaList.ThreadState >= 3)
			{
				TCPSerParaList.ThreadState = 4;
				printf("[END] File Transmission Succeed!!\n");
				break;
			}
*/
			
			if(TCPSerParaList.WindowLength * 2 <= TCPSerParaList.WindowThreshold)//慢启动阶段
				TCPSerParaList.WindowLength *= 2;
			else//拥塞避免阶段
				TCPSerParaList.WindowLength ++;

			//避免窗口长度超过整个缓冲区长度
			/*
			if(TCPSerParaList.WindowLength > TCPSerParaList.BUFLength / TCPSerParaList.PacketDataLength / 2)
			{
				TCPSerParaList.WindowLength = TCPSerParaList.BUFLength / TCPSerParaList.PacketDataLength / 2;
			}
			*/
			//避免窗口长度超过最大窗口长度
			if(TCPSerParaList.WindowLength > MAXWndLen)
			{
				TCPSerParaList.WindowLength = MAXWndLen;
			}

			//更新窗口头部
			TCPSerParaList.OffsetWindowHead = TCPSerParaList.OffsetWindowEnd;
			TCPSerParaList.AddrWindowHead   = TCPSerParaList.AddrWindowEnd;
			//更新窗口尾部
			TCPSerParaList.OffsetWindowEnd += TCPSerParaList.WindowLength * TCPSerParaList.PacketDataLength;
			TCPSerParaList.AddrWindowEnd   += TCPSerParaList.WindowLength * TCPSerParaList.PacketDataLength;
/*
			printf("[RENEW WND HEAD1]AddrWindowHead - BUF = %d\n",TCPSerParaList.AddrWindowHead - TCPSerParaList.BUF);
			printf("[RENEW WND TAIL1]OffsetWindowEnd     = %ld\n",TCPSerParaList.OffsetWindowEnd);
			printf("[RENEW WND TAIL1]AddrWindowEnd - BUF = %d\n",TCPSerParaList.AddrWindowEnd - TCPSerParaList.BUF);
*/
			//缓冲区回环处理
			if(TCPSerParaList.AddrWindowEnd >= TCPSerParaList.BUFEnd)
			{
				TCPSerParaList.AddrWindowEnd = TCPSerParaList.BUF + ( TCPSerParaList.AddrWindowEnd - TCPSerParaList.BUFEnd );
			}
		}
/*
		else if(TCPSerParaList.WindowState == 3)//三重ACK（轻度丢包）
		{printf("Treble ACK!\n");
			TCPSerParaList.WindowState = 0;
			
			//任务状态撤回
			if(TCPSerParaList.ThreadState >= 2)
			{
				TCPSerParaList.ThreadState = 1;
			}

			TCPSerParaList.WindowThreshold = TCPSerParaList.WindowLength / 2;//把门限值设置为当前窗口大小的一半
			
			TCPSerParaList.WindowLength = TCPSerParaList.WindowThreshold;//把窗口值设置为门限值
			
			if(TCPSerParaList.WindowThreshold == 0)
				TCPSerParaList.WindowThreshold = 1;
			if(TCPSerParaList.WindowLength == 0)
				TCPSerParaList.WindowLength = 1;
			
			printf("TCPSerParaList.WindowThreshold = %ld\n",TCPSerParaList.WindowThreshold);

			//更新窗口头部
			TCPSerParaList.OffsetWindowHead = TCPSerParaList.OffsetRequestACK;
			TCPSerParaList.AddrWindowHead   = TCPSerParaList.AddrWaitACK - ( TCPSerParaList.OffsetWaitACK - TCPSerParaList.OffsetRequestACK );

			//缓冲区回环处理
			if(TCPSerParaList.AddrWindowHead < TCPSerParaList.BUF)
			{
				TCPSerParaList.AddrWindowHead = TCPSerParaList.BUFEnd - ( TCPSerParaList.BUF - TCPSerParaList.AddrWindowHead );
			}

			//更新窗口尾部
			TCPSerParaList.OffsetWindowEnd = TCPSerParaList.OffsetWindowHead + 
							 TCPSerParaList.WindowLength * TCPSerParaList.PacketDataLength;
			TCPSerParaList.AddrWindowEnd   = TCPSerParaList.AddrWindowHead   + 
							 TCPSerParaList.WindowLength * TCPSerParaList.PacketDataLength;

			//printf("[RENEW WND HEAD2]AddrWindowHead - BUF = %d\n",TCPSerParaList.AddrWindowHead - TCPSerParaList.BUF);
			//printf("[RENEW WND TAIL2]OffsetWindowEnd     = %ld\n",TCPSerParaList.OffsetWindowEnd);
			//printf("[RENEW WND TAIL2]AddrWindowEnd - BUF = %d\n",TCPSerParaList.AddrWindowEnd - TCPSerParaList.BUF);

			//缓冲区回环处理
			if(TCPSerParaList.AddrWindowEnd >= TCPSerParaList.BUFEnd)
			{
				TCPSerParaList.AddrWindowEnd = TCPSerParaList.BUF + ( TCPSerParaList.AddrWindowEnd - TCPSerParaList.BUFEnd );
			}
		}
*/
		else if(TCPSerParaList.WindowState == 3 || TCPSerParaList.WindowState == 4)//窗口ACK超时（重度拥塞）
		{//printf("Time Out!\n");
			TCPSerParaList.LostPacketCount++;//记录丢包次数
			
			TCPSerParaList.WindowState = 0;
			
			//整个任务传输成功
			if(TCPSerParaList.ThreadState >= 3)
			{
				TCPSerParaList.ThreadState = 4;
				printf("[END] File Transmission Succeed!!\n");
				break;
			}

			//任务状态撤回
			else if(TCPSerParaList.ThreadState >= 2)
			{
				TCPSerParaList.ThreadState = 1;
			}

			TCPSerParaList.WindowThreshold = TCPSerParaList.WindowLength / 2;//把门限值设置为当前窗口大小的一半
			
			TCPSerParaList.WindowLength = 1;//把窗口大小重新设置为一个报文段

			if(TCPSerParaList.WindowThreshold == 0)
				TCPSerParaList.WindowThreshold = 1;

			//printf("TCPSerParaList.WindowThreshold = %ld\n",TCPSerParaList.WindowThreshold);
			
			//更新窗口头部
			TCPSerParaList.OffsetWindowHead = TCPSerParaList.OffsetRequestACK;
			TCPSerParaList.AddrWindowHead   = TCPSerParaList.AddrWaitACK - ( TCPSerParaList.OffsetWaitACK - TCPSerParaList.OffsetRequestACK );

			//缓冲区回环处理
			if(TCPSerParaList.AddrWindowHead < TCPSerParaList.BUF)
			{
				TCPSerParaList.AddrWindowHead = TCPSerParaList.BUFEnd - ( TCPSerParaList.BUF - TCPSerParaList.AddrWindowHead );
			}

			//更新窗口尾部
			TCPSerParaList.OffsetWindowEnd = TCPSerParaList.OffsetWindowHead + 
							 TCPSerParaList.WindowLength * TCPSerParaList.PacketDataLength;
			TCPSerParaList.AddrWindowEnd   = TCPSerParaList.AddrWindowHead   + 
							 TCPSerParaList.WindowLength * TCPSerParaList.PacketDataLength;
/*
			printf("[RENEW WND HEAD3]AddrWindowHead - BUF = %d\n",TCPSerParaList.AddrWindowHead - TCPSerParaList.BUF);
			printf("[RENEW WND TAIL3]OffsetWindowEnd     = %ld\n",TCPSerParaList.OffsetWindowEnd);
			printf("[RENEW WND TAIL3]AddrWindowEnd - BUF = %d\n",TCPSerParaList.AddrWindowEnd - TCPSerParaList.BUF);
*/
			//缓冲区回环处理
			if(TCPSerParaList.AddrWindowEnd >= TCPSerParaList.BUFEnd)
			{
				TCPSerParaList.AddrWindowEnd = TCPSerParaList.BUF + ( TCPSerParaList.AddrWindowEnd - TCPSerParaList.BUFEnd );
			}
		}
		else//致命错误，WindowState窗口状态值异常
		{
			//printf("[Deadly Error] (WindowState == %d)\n",TCPSerParaList.WindowState);
			TCPSerParaList.LostPacketCount++;
			continue;
			//exit(0);
		}

		TCPSerParaList.OffsetPacket = TCPSerParaList.OffsetRequestACK;
		TCPSerParaList.AddrPacket   = TCPSerParaList.AddrWindowHead;
		//printf("[PARA CHANGE]AddrPacket - BUF = %d\n",TCPSerParaList.AddrPacket - TCPSerParaList.BUF);
		
		//向应用层通知对供应后续数据的要求
		if( TCPSerParaList.OffsetRequestACK / ( TCPSerParaList.BUFLength / 2 ) == TCPSerParaList.BUFRenewCount + 1 )
		{
			sendto(TCPSerParaList.SENDTCPServerMoreData,"MoreData",20,0,(struct sockaddr *)&TCPSerParaList.SENDAddrToTCPServerMoreData,SockAddrLength);

			//printf("[%d] MoreData triggering...\n",TCPSerParaList.CountTCPServerMoreData_Triggering);
			TCPSerParaList.CountTCPServerMoreData_Triggering++;
		}
		else if( TCPSerParaList.OffsetRequestACK / ( TCPSerParaList.BUFLength / 2 ) > TCPSerParaList.BUFRenewCount + 1 )
		{
			printf("[Deadly Error]This is not normal. BUFRenewCount has problems to solve.\n1. Maybe a MoreData message has been lost.\n2. WindowLength is larger than BUFLength/2.\n");
			exit(0);
		}

		//触发上行通道继续收包的指令
		sendto(TCPSerParaList.SENDTCPServerContinueRECV,"ContinueRECV",20,0,(struct sockaddr *)&TCPSerParaList.SENDAddrToTCPServerContinueRECV,SockAddrLength);
		
		//printf("[%d] ContinueRECV triggering...\n",TCPSerParaList.CountTCPServerContinueRECV_Triggering);
		TCPSerParaList.CountTCPServerContinueRECV_Triggering++;

	}

	//sleep(100);
	printf("[DOWN]File Transport End.\n");
	printf("==========DATA Results==========\n");
	printf("Total Time = %ld seconds\n",TCPSerParaList.timer_XX);
	printf("Transport Rate = %.3f Byte/s\n",(double)FILELEN / (double)TCPSerParaList.timer_XX);
	printf("Average Window Length = %ld\n",TCPSerParaList.TotalWindowLength / (unsigned long)TCPSerParaList.InputCount);
	printf("TCPSerParaList.LostPacketCount  = %ld\n",TCPSerParaList.LostPacketCount);
	printf("TotalPacketCount = %ld\n",TCPSerParaList.FileLength / TCPSerParaList.PacketDataLength + 1);
	printf("Lost Rate = %.3f%%\n",((double)TCPSerParaList.LostPacketCount / ((double)TCPSerParaList.FileLength / (double)TCPSerParaList.PacketDataLength)) * (double)100);
	printf("================================\n");

	//关闭线程
	exit(0);
	free(fd);
	pthread_exit(NULL);
}

/*****************************************
* 函数名称：TCPServer_main
* 功能描述：TCPServer模块主函数，启动各个线程，自身不提供实际功能
* 参数列表：第二参数使用char**argv的方式声明报错，不知是不是语法问题
* 返回结果：
*****************************************/
//int main(int argc, char *argv[])
int
TCPServer_main
(
	int argc,
	char argv[][30]
)
{
	int i,j;
	
	TCPServer_Parameterinit();
	
	//创建发送计时器子线程
	pthread_t pthread_timer;
	if(pthread_create(&pthread_timer, NULL, TCPServer_thread_timer, NULL)!=0)
	{
		perror("Creation of timer thread failed.");
	}

	//创建TCP主子线程
	pthread_t pthread_TCP;
	if(pthread_create(&pthread_TCP, NULL, TCPServer_thread_TCP, NULL)!=0)
	{
		perror("Creation of TCP thread failed.");
	}

	//创建为Publisher模块输出的通信参数，并储存
	/*
	struct publisherinput
	{
		int argc;
		char argv[50][30];
	};
	*/
	struct publisherinput pubinput;
	pubinput.argc=0;
	memset(pubinput.argv,0,1500);

	pubinput.argc=argc;
	for(i=0;i<pubinput.argc;i++)
	{
		strcpy(pubinput.argv[i],argv[i]);
	}

	pthread_t pthread_publisher;

	//创建Publisher子线程
	if(pthread_create(&pthread_publisher, NULL, Publisher_main, (void *)&pubinput)!=0)
	{
		perror("Creation of publisher thread failed.");
	}

	//Publisher_main(argc,(char (*)[30])argv);

	//主循环——客户端代码
	while (1)
	{
		sleep(10000);
	}
}
