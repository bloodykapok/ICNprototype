/*******************************************************************************************************************************************
* 文件名：tcpclient.c
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

#include"tcpclient.h"

/*******************************************************************************************************************************************
*************************************宏定义配置数据************全局变量定义******************************************************************
*******************************************************************************************************************************************/

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
TCPClient_Parameterinit()
{
	SockAddrLength = sizeof(struct sockaddr_in);


	//计时开始
	TCPCliParaList.CountTCPClientTimingBegin_Triggering = 1;
	TCPCliParaList.CountTCPClientTimingBegin_Waiting = 1;
	TCPCliParaList.CountTCPClientTimingBegin_Triggered = 1;

	bzero(&TCPCliParaList.SENDAddrToTCPClientTimingBegin,SockAddrLength);
	TCPCliParaList.SENDAddrToTCPClientTimingBegin.sin_family=AF_INET;
	TCPCliParaList.SENDAddrToTCPClientTimingBegin.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPCliParaList.SENDAddrToTCPClientTimingBegin.sin_port=htons(TCPClientTimingBegin);

	bzero(&TCPCliParaList.RECVAddrToTCPClientTimingBegin,SockAddrLength);
	TCPCliParaList.RECVAddrToTCPClientTimingBegin.sin_family=AF_INET;
	TCPCliParaList.RECVAddrToTCPClientTimingBegin.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPCliParaList.RECVAddrToTCPClientTimingBegin.sin_port=htons(TCPClientTimingBegin);

	TCPCliParaList.SENDTCPClientTimingBegin = socket(AF_INET,SOCK_DGRAM,0);
	TCPCliParaList.RECVTCPClientTimingBegin = socket(AF_INET,SOCK_DGRAM,0);

	bind(TCPCliParaList.RECVTCPClientTimingBegin,(struct sockaddr *)&TCPCliParaList.RECVAddrToTCPClientTimingBegin,SockAddrLength);

	//计时结束
	TCPCliParaList.CountTCPClientTimingEnd_Triggering = 1;
	TCPCliParaList.CountTCPClientTimingEnd_Waiting = 1;
	TCPCliParaList.CountTCPClientTimingEnd_Triggered = 1;

	bzero(&TCPCliParaList.SENDAddrToTCPClientTimingEnd,SockAddrLength);
	TCPCliParaList.SENDAddrToTCPClientTimingEnd.sin_family=AF_INET;
	TCPCliParaList.SENDAddrToTCPClientTimingEnd.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPCliParaList.SENDAddrToTCPClientTimingEnd.sin_port=htons(TCPClientTimingEnd);

	bzero(&TCPCliParaList.RECVAddrToTCPClientTimingEnd,SockAddrLength);
	TCPCliParaList.RECVAddrToTCPClientTimingEnd.sin_family=AF_INET;
	TCPCliParaList.RECVAddrToTCPClientTimingEnd.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPCliParaList.RECVAddrToTCPClientTimingEnd.sin_port=htons(TCPClientTimingEnd);

	TCPCliParaList.SENDTCPClientTimingEnd = socket(AF_INET,SOCK_DGRAM,0);
	TCPCliParaList.RECVTCPClientTimingEnd = socket(AF_INET,SOCK_DGRAM,0);

	bind(TCPCliParaList.RECVTCPClientTimingEnd,(struct sockaddr *)&TCPCliParaList.RECVAddrToTCPClientTimingEnd,SockAddrLength);

	//反馈计时结果
	TCPCliParaList.CountTCPClientTimingRespond_Triggering = 1;
	TCPCliParaList.CountTCPClientTimingRespond_Waiting = 1;
	TCPCliParaList.CountTCPClientTimingRespond_Triggered = 1;

	bzero(&TCPCliParaList.SENDAddrToTCPClientTimingRespond,SockAddrLength);
	TCPCliParaList.SENDAddrToTCPClientTimingRespond.sin_family=AF_INET;
	TCPCliParaList.SENDAddrToTCPClientTimingRespond.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPCliParaList.SENDAddrToTCPClientTimingRespond.sin_port=htons(TCPClientTimingRespond);

	bzero(&TCPCliParaList.RECVAddrToTCPClientTimingRespond,SockAddrLength);
	TCPCliParaList.RECVAddrToTCPClientTimingRespond.sin_family=AF_INET;
	TCPCliParaList.RECVAddrToTCPClientTimingRespond.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPCliParaList.RECVAddrToTCPClientTimingRespond.sin_port=htons(TCPClientTimingRespond);

	TCPCliParaList.SENDTCPClientTimingRespond = socket(AF_INET,SOCK_DGRAM,0);
	TCPCliParaList.RECVTCPClientTimingRespond = socket(AF_INET,SOCK_DGRAM,0);

	bind(TCPCliParaList.RECVTCPClientTimingRespond,(struct sockaddr *)&TCPCliParaList.RECVAddrToTCPClientTimingRespond,SockAddrLength);

	//接收缓冲启动
	TCPCliParaList.CountTCPClientBufReady_Triggering = 1;
	TCPCliParaList.CountTCPClientBufReady_Waiting = 1;
	TCPCliParaList.CountTCPClientBufReady_Triggered = 1;

	bzero(&TCPCliParaList.SENDAddrToTCPClientBufReady,SockAddrLength);
	TCPCliParaList.SENDAddrToTCPClientBufReady.sin_family=AF_INET;
	TCPCliParaList.SENDAddrToTCPClientBufReady.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPCliParaList.SENDAddrToTCPClientBufReady.sin_port=htons(TCPClientBufReady);

	bzero(&TCPCliParaList.RECVAddrToTCPClientBufReady,SockAddrLength);
	TCPCliParaList.RECVAddrToTCPClientBufReady.sin_family=AF_INET;
	TCPCliParaList.RECVAddrToTCPClientBufReady.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPCliParaList.RECVAddrToTCPClientBufReady.sin_port=htons(TCPClientBufReady);

	TCPCliParaList.SENDTCPClientBufReady = socket(AF_INET,SOCK_DGRAM,0);
	TCPCliParaList.RECVTCPClientBufReady = socket(AF_INET,SOCK_DGRAM,0);

	bind(TCPCliParaList.RECVTCPClientBufReady,(struct sockaddr *)&TCPCliParaList.RECVAddrToTCPClientBufReady,SockAddrLength);

	//接收后续数据
	TCPCliParaList.CountTCPClientMoreData_Triggering = 1;
	TCPCliParaList.CountTCPClientMoreData_Waiting = 1;
	TCPCliParaList.CountTCPClientMoreData_Triggered = 1;
	
	bzero(&TCPCliParaList.SENDAddrToTCPClientMoreData,SockAddrLength);
	TCPCliParaList.SENDAddrToTCPClientMoreData.sin_family=AF_INET;
	TCPCliParaList.SENDAddrToTCPClientMoreData.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPCliParaList.SENDAddrToTCPClientMoreData.sin_port=htons(TCPClientMoreData);

	bzero(&TCPCliParaList.RECVAddrToTCPClientMoreData,SockAddrLength);
	TCPCliParaList.RECVAddrToTCPClientMoreData.sin_family=AF_INET;
	TCPCliParaList.RECVAddrToTCPClientMoreData.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPCliParaList.RECVAddrToTCPClientMoreData.sin_port=htons(TCPClientMoreData);

	TCPCliParaList.SENDTCPClientMoreData = socket(AF_INET,SOCK_DGRAM,0);
	TCPCliParaList.RECVTCPClientMoreData = socket(AF_INET,SOCK_DGRAM,0);

	bind(TCPCliParaList.RECVTCPClientMoreData,(struct sockaddr *)&TCPCliParaList.RECVAddrToTCPClientMoreData,SockAddrLength);

	//通知将数据写入缓冲
	TCPCliParaList.CountTCPClientWriteData_Triggering = 1;
	TCPCliParaList.CountTCPClientWriteData_Waiting = 1;
	TCPCliParaList.CountTCPClientWriteData_Triggered = 1;

	bzero(&TCPCliParaList.SENDAddrToTCPClientWriteData,SockAddrLength);
	TCPCliParaList.SENDAddrToTCPClientWriteData.sin_family=AF_INET;
	TCPCliParaList.SENDAddrToTCPClientWriteData.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPCliParaList.SENDAddrToTCPClientWriteData.sin_port=htons(TCPClientWriteData);

	bzero(&TCPCliParaList.RECVAddrToTCPClientWriteData,SockAddrLength);
	TCPCliParaList.RECVAddrToTCPClientWriteData.sin_family=AF_INET;
	TCPCliParaList.RECVAddrToTCPClientWriteData.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPCliParaList.RECVAddrToTCPClientWriteData.sin_port=htons(TCPClientWriteData);

	TCPCliParaList.SENDTCPClientWriteData = socket(AF_INET,SOCK_DGRAM,0);
	TCPCliParaList.RECVTCPClientWriteData = socket(AF_INET,SOCK_DGRAM,0);

	bind(TCPCliParaList.RECVTCPClientWriteData,(struct sockaddr *)&TCPCliParaList.RECVAddrToTCPClientWriteData,SockAddrLength);

	//文件写入结束
	TCPCliParaList.CountTCPClientFileClose_Triggering = 1;
	TCPCliParaList.CountTCPClientFileClose_Waiting = 1;
	TCPCliParaList.CountTCPClientFileClose_Triggered = 1;

	bzero(&TCPCliParaList.SENDAddrToTCPClientFileClose,SockAddrLength);
	TCPCliParaList.SENDAddrToTCPClientFileClose.sin_family=AF_INET;
	TCPCliParaList.SENDAddrToTCPClientFileClose.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPCliParaList.SENDAddrToTCPClientFileClose.sin_port=htons(TCPClientFileClose);

	bzero(&TCPCliParaList.RECVAddrToTCPClientFileClose,SockAddrLength);
	TCPCliParaList.RECVAddrToTCPClientFileClose.sin_family=AF_INET;
	TCPCliParaList.RECVAddrToTCPClientFileClose.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPCliParaList.RECVAddrToTCPClientFileClose.sin_port=htons(TCPClientFileClose);

	TCPCliParaList.SENDTCPClientFileClose = socket(AF_INET,SOCK_DGRAM,0);
	TCPCliParaList.RECVTCPClientFileClose = socket(AF_INET,SOCK_DGRAM,0);

	bind(TCPCliParaList.RECVTCPClientFileClose,(struct sockaddr *)&TCPCliParaList.RECVAddrToTCPClientFileClose,SockAddrLength);

	//启动顺序1
	TCPCliParaList.CountTCPClientStartOrder1_Triggering = 1;
	TCPCliParaList.CountTCPClientStartOrder1_Waiting = 1;
	TCPCliParaList.CountTCPClientStartOrder1_Triggered = 1;
	
	bzero(&TCPCliParaList.SENDAddrToTCPClientStartOrder1,SockAddrLength);
	TCPCliParaList.SENDAddrToTCPClientStartOrder1.sin_family=AF_INET;
	TCPCliParaList.SENDAddrToTCPClientStartOrder1.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPCliParaList.SENDAddrToTCPClientStartOrder1.sin_port=htons(TCPClientStartOrder1);

	bzero(&TCPCliParaList.RECVAddrToTCPClientStartOrder1,SockAddrLength);
	TCPCliParaList.RECVAddrToTCPClientStartOrder1.sin_family=AF_INET;
	TCPCliParaList.RECVAddrToTCPClientStartOrder1.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPCliParaList.RECVAddrToTCPClientStartOrder1.sin_port=htons(TCPClientStartOrder1);

	TCPCliParaList.SENDTCPClientStartOrder1 = socket(AF_INET,SOCK_DGRAM,0);
	TCPCliParaList.RECVTCPClientStartOrder1 = socket(AF_INET,SOCK_DGRAM,0);

	bind(TCPCliParaList.RECVTCPClientStartOrder1,(struct sockaddr *)&TCPCliParaList.RECVAddrToTCPClientStartOrder1,SockAddrLength);

	//启动顺序2
	TCPCliParaList.CountTCPClientStartOrder2_Triggering = 1;
	TCPCliParaList.CountTCPClientStartOrder2_Waiting = 1;
	TCPCliParaList.CountTCPClientStartOrder2_Triggered = 1;
	
	bzero(&TCPCliParaList.SENDAddrToTCPClientStartOrder2,SockAddrLength);
	TCPCliParaList.SENDAddrToTCPClientStartOrder2.sin_family=AF_INET;
	TCPCliParaList.SENDAddrToTCPClientStartOrder2.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPCliParaList.SENDAddrToTCPClientStartOrder2.sin_port=htons(TCPClientStartOrder2);

	bzero(&TCPCliParaList.RECVAddrToTCPClientStartOrder2,SockAddrLength);
	TCPCliParaList.RECVAddrToTCPClientStartOrder2.sin_family=AF_INET;
	TCPCliParaList.RECVAddrToTCPClientStartOrder2.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPCliParaList.RECVAddrToTCPClientStartOrder2.sin_port=htons(TCPClientStartOrder2);

	TCPCliParaList.SENDTCPClientStartOrder2 = socket(AF_INET,SOCK_DGRAM,0);
	TCPCliParaList.RECVTCPClientStartOrder2 = socket(AF_INET,SOCK_DGRAM,0);

	bind(TCPCliParaList.RECVTCPClientStartOrder2,(struct sockaddr *)&TCPCliParaList.RECVAddrToTCPClientStartOrder2,SockAddrLength);

	//启动顺序3
	TCPCliParaList.CountTCPClientStartOrder3_Triggering = 1;
	TCPCliParaList.CountTCPClientStartOrder3_Waiting = 1;
	TCPCliParaList.CountTCPClientStartOrder3_Triggered = 1;
	
	bzero(&TCPCliParaList.SENDAddrToTCPClientStartOrder3,SockAddrLength);
	TCPCliParaList.SENDAddrToTCPClientStartOrder3.sin_family=AF_INET;
	TCPCliParaList.SENDAddrToTCPClientStartOrder3.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPCliParaList.SENDAddrToTCPClientStartOrder3.sin_port=htons(TCPClientStartOrder3);

	bzero(&TCPCliParaList.RECVAddrToTCPClientStartOrder3,SockAddrLength);
	TCPCliParaList.RECVAddrToTCPClientStartOrder3.sin_family=AF_INET;
	TCPCliParaList.RECVAddrToTCPClientStartOrder3.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPCliParaList.RECVAddrToTCPClientStartOrder3.sin_port=htons(TCPClientStartOrder3);

	TCPCliParaList.SENDTCPClientStartOrder3 = socket(AF_INET,SOCK_DGRAM,0);
	TCPCliParaList.RECVTCPClientStartOrder3 = socket(AF_INET,SOCK_DGRAM,0);

	bind(TCPCliParaList.RECVTCPClientStartOrder3,(struct sockaddr *)&TCPCliParaList.RECVAddrToTCPClientStartOrder3,SockAddrLength);

	//启动顺序4
	TCPCliParaList.CountTCPClientStartOrder4_Triggering = 1;
	TCPCliParaList.CountTCPClientStartOrder4_Waiting = 1;
	TCPCliParaList.CountTCPClientStartOrder4_Triggered = 1;
	
	bzero(&TCPCliParaList.SENDAddrToTCPClientStartOrder4,SockAddrLength);
	TCPCliParaList.SENDAddrToTCPClientStartOrder4.sin_family=AF_INET;
	TCPCliParaList.SENDAddrToTCPClientStartOrder4.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPCliParaList.SENDAddrToTCPClientStartOrder4.sin_port=htons(TCPClientStartOrder4);

	bzero(&TCPCliParaList.RECVAddrToTCPClientStartOrder4,SockAddrLength);
	TCPCliParaList.RECVAddrToTCPClientStartOrder4.sin_family=AF_INET;
	TCPCliParaList.RECVAddrToTCPClientStartOrder4.sin_addr.s_addr=inet_addr(LOOPIP);
	TCPCliParaList.RECVAddrToTCPClientStartOrder4.sin_port=htons(TCPClientStartOrder4);

	TCPCliParaList.SENDTCPClientStartOrder4 = socket(AF_INET,SOCK_DGRAM,0);
	TCPCliParaList.RECVTCPClientStartOrder4 = socket(AF_INET,SOCK_DGRAM,0);

	bind(TCPCliParaList.RECVTCPClientStartOrder4,(struct sockaddr *)&TCPCliParaList.RECVAddrToTCPClientStartOrder4,SockAddrLength);

}

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
)
{
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

	//关闭线程
	free(fd);
	pthread_exit(NULL);
}

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
)
{
	sleep(1);
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
	memset(TCPCliParaList.SID,0,SIDLEN);//任务所服务的SID
	TCPCliParaList.SIDLen = 0;//SID的实际长度

	TCPCliParaList.BUF = NULL;//发送缓冲区开头
	TCPCliParaList.BUFEnd = NULL;//发送缓冲区结尾
	TCPCliParaList.BUFFileEnd = NULL;//读取文件结束时，缓冲区内文件末尾所在地址

	TCPCliParaList.BUFRenewCount = 0;//缓冲区更新次数
	TCPCliParaList.BUFLength = TCPBUFSIZE;//发送缓冲长度

	TCPCliParaList.FileWritePoint = 0;//文件写入进度
	TCPCliParaList.FileLength = 0;//文件总长度

	TCPCliParaList.PacketDataLength = PKTDATALEN;//单包数据段长度
	TCPCliParaList.LastPacketDataLength = 0;//整个传输任务的最后一个数据包实际长度

	TCPCliParaList.OffsetConfirmDATA = 0;//在整个文件中确认收到的字节顶端
	TCPCliParaList.OffsetPacket = 0;//在整个文件中当前封包字节数
	TCPCliParaList.OffsetWaitDATA = PKTDATALEN;//在整个文件中等待确认收到的字节数（发送ACK数据包偏移量字段的填写依据）

	TCPCliParaList.AddrConfirmDATA = NULL;//在缓冲区中已确认偏移量所在地址
	TCPCliParaList.AddrPacket = NULL;//在缓冲区中当前封包偏移量所在地址
	TCPCliParaList.AddrWaitDATA = NULL;//在缓冲区中待确认偏移量所在地址

	TCPCliParaList.RTOs = 0;//往返容忍时延（RTO大于1秒部分，单位秒）
	TCPCliParaList.RTOus = 0;//往返容忍时延（RTO小于1秒部分，单位微秒）
	TCPCliParaList.RTOns = 0;//往返容忍时延（RTO小于1秒部分，单位纳秒）

	TCPCliParaList.FlagInputBUF = 0;//是否将收到的数据写入缓冲

	TCPCliParaList.TimingState = 0;//计时状态，0按时，1超时
	TCPCliParaList.ThreadState = 0;//任务状态（用于结束过程的控制）

printf("xxx waiting...\n");
printf("xxx triggering...\n");
printf("xxx triggered!\n");

	//触发FTP线程开始
	sendto(TCPCliParaList.SENDTCPClientStartOrder1,"StartOrder1",20,0,(struct sockaddr *)&TCPCliParaList.SENDAddrToTCPClientStartOrder1,SockAddrLength);
	
	//printf("[%d] StartOrder1 triggering...\n",TCPCliParaList.CountTCPClientStartOrder1_Triggering);
	TCPCliParaList.CountTCPClientStartOrder1_Triggering++;

	//触发TCP主子线程开始
	//printf("[%d] StartOrder3 waiting...\n",TCPCliParaList.CountTCPClientStartOrder3_Waiting);
	TCPCliParaList.CountTCPClientStartOrder3_Waiting++;
	
	recvfrom(TCPCliParaList.RECVTCPClientStartOrder3,Trigger,20,0,(struct sockaddr *)&TCPCliParaList.RECVAddrToTCPClientStartOrder3,&SockAddrLength);
	
	//printf("[%d] StartOrder3 triggered!\n",TCPCliParaList.CountTCPClientStartOrder3_Triggered);
	TCPCliParaList.CountTCPClientStartOrder3_Triggered++;

	//触发下行线程开始
	sendto(TCPCliParaList.SENDTCPClientStartOrder4,"StartOrder4",20,0,(struct sockaddr *)&TCPCliParaList.SENDAddrToTCPClientStartOrder4,SockAddrLength);
	
	//printf("[%d] StartOrder4 triggering...\n",TCPCliParaList.CountTCPClientStartOrder4_Triggering);
	TCPCliParaList.CountTCPClientStartOrder4_Triggering++;

	//循环监听回送资源成功的信令
	int socket_datareceiver;
	socket_datareceiver = socket(AF_INET,SOCK_DGRAM,0);

	struct sockaddr_in sin;
	int sockaddr_len=SockAddrLength;
	bzero(&sin,sockaddr_len);
	sin.sin_family=AF_INET;
	//sin.sin_addr.s_addr=htonl(INADDR_ANY);
	sin.sin_addr.s_addr=inet_addr(LOOPIP);
	sin.sin_port=htons(TRALtoAPPL);

	bind(socket_datareceiver,(struct sockaddr *)&sin,sockaddr_len);
		
	int flag_sidgot = 0;
	int counter_sidget = 0;

	if(DEVETESTIMPL <= 1)
		printf("[Transport Layer] TCPClient responce listening start...\n");
	
	uint8_t recvpkg[sizeof(Trans_data)];
	Trans_data * precvpkg;
	precvpkg = (Trans_data *)recvpkg;

	int FoundSIDNum = -1;
	while(1)
	{
		i=0;
		j=0;

		//清空缓冲，为接收数据做准备
		DATAlen = 0;
		REQoffsetlong = 0;
		RESoffsetlong = 0;
		memset(DATA,0,DATALEN);
		memset(recvpkg,0,sizeof(Trans_data));

		FoundSIDNum = -1;

		//接收
		recvfrom(socket_datareceiver,recvpkg,sizeof(Trans_data),0,(struct sockaddr *)&sin,&sockaddr_len);

		if(transDEVETESTIMPL <= 1)
			printf("[Transport Layer] TCPClient responce listener received a new UDP message.\n");
		
		//提取DATA与offset
		memcpy(DATA,precvpkg->data,DATALEN);
		memcpy(RESoffset,precvpkg->offset,OFFLEN);
		DATAlen = DATALEN;

		//收到的数据长度累积大于预知文件长度（容错机制，并非结束机制，所以出错判断条件需要大于结束条件）
		if((long)TCPCliParaList.OffsetConfirmDATA - (long)DATALEN >= FILELEN)//强制long型转换是避免做差反向溢出导致误判
		{
			printf("Received File Length   = %ld\n",(long)TCPCliParaList.OffsetConfirmDATA - (long)DATALEN);
			printf("File Length Ever known = %ld\n",(unsigned long)FILELEN);
			printf("[Deadly Error] Received File Length is Bigger Than the File Length Ever known.\n");
			
			TCPCliParaList.FlagInputBUF = 0;
			sendto(TCPCliParaList.SENDTCPClientTimingEnd,"TimingEnd",20,0,(struct sockaddr *)&TCPCliParaList.SENDAddrToTCPClientTimingEnd,SockAddrLength);

			printf("[%d] TimingEnd triggering...\n",TCPCliParaList.CountTCPClientTimingEnd_Triggering);
			TCPCliParaList.CountTCPClientTimingEnd_Triggering++;
		}
	
		if(transDEVETESTIMPL <= 5)
		{
			printf("[DATAlen]\n%d\n",DATAlen);
			printf("[DATA]\n%s\n",DATA);
			printf("[DATA-END]\n");
		}

		//至此TCP网络层上行接口做好，接口消息格式GOTdataOFFoffset
		//此处缺少对数据正确性的校验
		
		//判断OFFSET的合法性，进入主要处理程序
		if(RESoffset[0] >= 0 && RESoffset[1] >= 0 && RESoffset[2] >= 0 && RESoffset[3] >= 0)
		{
			RESoffsetlong = (unsigned long)RESoffset[0] * 256 * 256 * 256 + 
					(unsigned long)RESoffset[1] * 256 * 256 + 
					(unsigned long)RESoffset[2] * 256 + 
					(unsigned long)RESoffset[3];
			
			//查找与SID对应的任务线程编号
			if(strncmp(TCPCliParaList.SID,SID,SIDLEN) == 0)
			{
				FoundSIDNum = 0;
			}
			if(FoundSIDNum == -1)
			{
				printf("An unknown ACK Packet received, SID not found.\n");
				exit(0);
			}

			TCPCliParaList.SIDLen = SIDlen;
			//if(RESoffsetlong >= 10000)exit(0);
			
			if(transDEVETESTIMPL <= 5)
			{
				printf("[RECV]RESoffsetlong  = %ld\n",RESoffsetlong);
				printf("[RECV]OffsetWaitDATA = %ld\n",TCPCliParaList.OffsetWaitDATA);
			}
			
			if(RESoffsetlong == TCPCliParaList.OffsetWaitDATA)//收到当前所请求的偏移量，写入接收缓冲，更新确认偏移量值
			{
				//printf("New Data Input!\n");
				//向缓冲区拷贝刚刚收到的数据字段
				
				//收到数据段长度大于本地TCP规定的标准单包数据段长度，
				//意味着文件尚未结束（文件大小恰为PacketDataLength的整数倍情况除外）
				if(DATAlen == TCPCliParaList.PacketDataLength)
				{
					//将收到的数据拷贝进缓存
					memcpy(TCPCliParaList.AddrConfirmDATA,DATA,TCPCliParaList.PacketDataLength);

					//移动各类定位标识
					TCPCliParaList.OffsetConfirmDATA = RESoffsetlong;
					TCPCliParaList.OffsetWaitDATA    = RESoffsetlong + DATAlen;
					TCPCliParaList.AddrConfirmDATA  += TCPCliParaList.PacketDataLength;

					//缓冲区回环处理
					if(TCPCliParaList.AddrConfirmDATA >= TCPCliParaList.BUFEnd)
					{
						TCPCliParaList.AddrConfirmDATA = TCPCliParaList.BUF + ( TCPCliParaList.AddrConfirmDATA - TCPCliParaList.BUFEnd );
					}
				}
				//收到数据段长度小于本地TCP规定的标准单包数据段长度，
				//意味着这是文件的最后一个包，应当触发对文件生成和结束传输的处理
				/*
				else if(DATAlen < TCPCliParaList.PacketDataLength)
				{
					//将收到的数据拷贝进缓存
					memcpy(TCPCliParaList.AddrConfirmDATA,DATA,DATAlen);
					
					//移动各类定位标识
					TCPCliParaList.OffsetWaitDATA = RESoffsetlong + DATAlen;
					TCPCliParaList.AddrConfirmDATA += TCPCliParaList.PacketDataLength;

					//通知向文件写入数据
					sendto(TCPCliParaList.SENDTCPClientWriteData,"WriteData",20,0,(struct sockaddr *)&TCPCliParaList.SENDAddrToTCPClientWriteData,SockAddrLength);

					printf("[%d] WriteData triggering...\n",TCPCliParaList.CountTCPClientWriteData_Triggering);
					TCPCliParaList.CountTCPClientWriteData_Triggering++;
				}
				*/
				//收到数据段长度不等于本地TCP规定的标准单包数据段长度，
				//属于两端协议参数不匹配，需要修改设置
				else
				{
					printf("Deadly error!(DATAlen == %d > TCPCliParaList.PacketDataLength)\n",DATAlen);
					exit(0);
				}

				TCPCliParaList.FlagInputBUF = 1;
				
				//通知结束计时
				sendto(TCPCliParaList.SENDTCPClientTimingEnd,"TimingEnd",20,0,(struct sockaddr *)&TCPCliParaList.SENDAddrToTCPClientTimingEnd,SockAddrLength);

				//printf("[%d] TimingEnd triggering...\n",TCPCliParaList.CountTCPClientTimingEnd_Triggering);
				TCPCliParaList.CountTCPClientTimingEnd_Triggering++;
			}
			else if(RESoffsetlong != TCPCliParaList.OffsetWaitDATA)//收到非当前所请求的偏移量，重复发送当前所请求的偏移量
			{
				TCPCliParaList.FlagInputBUF = 0;

				sendto(TCPCliParaList.SENDTCPClientTimingEnd,"TimingEnd",20,0,(struct sockaddr *)&TCPCliParaList.SENDAddrToTCPClientTimingEnd,SockAddrLength);

				//printf("[%d] TimingEnd triggering...\n",TCPCliParaList.CountTCPClientTimingEnd_Triggering);
				TCPCliParaList.CountTCPClientTimingEnd_Triggering++;
			}
		}
		else//offset值非法
		{
			//触发ACK重传
			TCPCliParaList.FlagInputBUF = 0;

			sendto(TCPCliParaList.SENDTCPClientTimingEnd,"TimingEnd",20,0,(struct sockaddr *)&TCPCliParaList.SENDAddrToTCPClientTimingEnd,SockAddrLength);

			//printf("[%d] TimingEnd triggering...\n",TCPCliParaList.CountTCPClientTimingEnd_Triggering);
			TCPCliParaList.CountTCPClientTimingEnd_Triggering++;
		}
	}
	
	close(socket_datareceiver);


	//关闭线程
	exit(0);
	free(fd);
	pthread_exit(NULL);	
}

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
)
{
	//提取任务编号
	//int ThreadNum = *((int *)fd);printf("[FTP]ThreadNum = %d\n",ThreadNum);
	
	//触发FTP线程开始
	//printf("[%d] StartOrder1 waiting...\n",TCPCliParaList.CountTCPClientStartOrder1_Waiting);
	TCPCliParaList.CountTCPClientStartOrder1_Waiting++;

	recvfrom(TCPCliParaList.RECVTCPClientStartOrder1,Trigger,20,0,(struct sockaddr *)&TCPCliParaList.RECVAddrToTCPClientStartOrder1,&SockAddrLength);

	//printf("[%d] StartOrder1 triggered!\n",TCPCliParaList.CountTCPClientStartOrder1_Triggered);
	TCPCliParaList.CountTCPClientStartOrder1_Triggered++;

	//为任务申请接收缓冲内存
	TCPCliParaList.BUF = (uint8_t *)malloc(TCPBUFSIZE);
	memset(TCPCliParaList.BUF,0,TCPBUFSIZE);
	
	//更新相关控制参数
	TCPCliParaList.BUFEnd = TCPCliParaList.BUF + TCPBUFSIZE;//发送缓冲区结尾

	TCPCliParaList.BUFRenewCount = 0;//缓冲区更新次数
	TCPCliParaList.BUFLength = TCPBUFSIZE;//发送缓冲长度

	TCPCliParaList.FileWritePoint = 0;//文件写入进度
	TCPCliParaList.FileLength = 0;//文件总长度

	TCPCliParaList.PacketDataLength = PKTDATALEN;//单包数据段长度
	TCPCliParaList.LastPacketDataLength = 0;//整个传输任务的最后一个数据包实际长度
	
	TCPCliParaList.AddrConfirmDATA = TCPCliParaList.BUF;//在缓冲区中已确认偏移量所在地址
	TCPCliParaList.AddrPacket = TCPCliParaList.BUF;//在缓冲区中当前封包偏移量所在地址
	TCPCliParaList.AddrWaitDATA = TCPCliParaList.BUF;//在缓冲区中待确认偏移量所在地址

	//依照任务编号对应的参数组SID寻找对应的文件
	
	
	//打开文件并获取所需参数
	int fp;
	unsigned long filelen = FILELEN;//debuglog.txt的文件大小
	
	//创建并打开客户端接收文件
	fp = open(FTPClientPath,O_RDWR | O_CREAT | O_APPEND | O_TRUNC);
	if(fp == -1)
	{
		printf("[Deadly Error] The Client File \"%s\" opening failed.\n",FTPClientPath);
		exit(0);
	}
	
	//通知传输层，发送缓冲已经准备就绪（暂时无用）
	sendto(TCPCliParaList.SENDTCPClientBufReady,"BufReady",20,0,(struct sockaddr *)&TCPCliParaList.SENDAddrToTCPClientBufReady,SockAddrLength);

	//printf("[%d] BufReady triggering...\n",TCPCliParaList.CountTCPClientBufReady_Triggering);
	TCPCliParaList.CountTCPClientBufReady_Triggering++;

	//触发上行计时线程开始
	//sendto(TCPCliParaList.SENDTCPClientStartOrder2,"StartOrder2",20,0,(struct sockaddr *)&TCPCliParaList.SENDAddrToTCPClientStartOrder2,SockAddrLength);

	//printf("[%d] StartOrder2 triggering...\n",TCPCliParaList.CountTCPClientStartOrder2_Triggering);
	
	//开始持续为传输层供应数据
	while(1)
	{
		//printf("[%d] WriteData waiting...\n",TCPCliParaList.CountTCPClientWriteData_Waiting);
		TCPCliParaList.CountTCPClientWriteData_Waiting++;

		//阻塞等待传输层触发对上传数据的要求
		recvfrom(TCPCliParaList.RECVTCPClientWriteData,Trigger,20,0,(struct sockaddr *)&TCPCliParaList.RECVAddrToTCPClientWriteData,&SockAddrLength);
		
		//printf("[%d] WriteData triggered!\n",TCPCliParaList.CountTCPClientWriteData_Triggered);
		TCPCliParaList.CountTCPClientWriteData_Triggered++;

		TCPCliParaList.BUFRenewCount++;
		
		//一次上传接收缓冲中一半的内容，前半段和后半段交替上传
		if(TCPCliParaList.BUFRenewCount % 2 == 1)//判断上传前半段
		{
			//检查缓存剩余长度是否足够一次上传
			if(TCPCliParaList.FileWritePoint + TCPCliParaList.BUFLength/2 > filelen)//不足一次上传，则记录尾部标识，上传有限数据
			{
				write(fp,TCPCliParaList.BUF,filelen - TCPCliParaList.FileWritePoint);
				
				TCPCliParaList.BUFFileEnd = TCPCliParaList.BUF + ( filelen - TCPCliParaList.FileWritePoint );
				TCPCliParaList.ThreadState = 1;
				break;
			}
			else//足够一次上传，则上传
			{
				write(fp,TCPCliParaList.BUF,TCPCliParaList.BUFLength/2);
				
				TCPCliParaList.FileWritePoint += TCPCliParaList.BUFLength/2;
				//printf("TCPCliParaList.FileWritePoint = %ld\n",TCPCliParaList.FileWritePoint);
			}
		}
		else if(TCPCliParaList.BUFRenewCount % 2 == 0)//判断上传后半段
		{
			//检查文件剩余长度是否足够一次上传
			if(TCPCliParaList.FileWritePoint + TCPCliParaList.BUFLength/2 > filelen)//不足一次上传，则记录尾部标识，上传有限数据
			{
				//write(fp,TCPCliParaList.BUF + TCPCliParaList.BUFLength/2,filelen - TCPCliParaList.FileWritePoint);
				write(fp,TCPCliParaList.BUF + TCPCliParaList.BUFLength/2,filelen - TCPCliParaList.FileWritePoint);
				
				TCPCliParaList.BUFFileEnd = TCPCliParaList.BUF + TCPCliParaList.BUFLength/2 + ( filelen - TCPCliParaList.FileWritePoint );
				TCPCliParaList.ThreadState = 1;
				break;
			}
			else//足够一次上传，则上传
			{
				write(fp,TCPCliParaList.BUF + TCPCliParaList.BUFLength/2,TCPCliParaList.BUFLength/2);
				
				TCPCliParaList.FileWritePoint += TCPCliParaList.BUFLength/2;
				//printf("TCPCliParaList.FileWritePoint = %ld\n",TCPCliParaList.FileWritePoint);
			}
		}
		printf("Data already received: %ld Byte\n",TCPCliParaList.FileWritePoint);
	}

	//向下行通道通知文件写入结束
	sendto(TCPCliParaList.SENDTCPClientFileClose,"FileClose",20,0,(struct sockaddr *)&TCPCliParaList.SENDAddrToTCPClientFileClose,SockAddrLength);

	//printf("[%d] FileClose triggering...\n",TCPCliParaList.CountTCPClientFileClose_Triggering);
	TCPCliParaList.CountTCPClientFileClose_Triggering++;
	
	printf("[FTP]File Transport End.\n");

	//计算整个传输总共消耗秒数
	time(&GMT);//读取GMT，赋值给GMT
	EndTime = GMT;
	UsedTime = EndTime - StartTime;
	printf("Total Transport Delay   %ld\n",UsedTime);//输出整个传输总共消耗秒数

	exit(0);
	close(fp);
}

/*****************************************
* 函数名称：TCPClient_thread_NetworkLayertoTransportLayer
* 功能描述：上行通道 - From.数据请求端   To.应用服务器  提供定时
* 参数列表：
* 返回结果：
*****************************************/
void *
TCPClient_thread_NetworkLayertoTransportLayer
(
	void * fd
)
{
	//提取任务编号
	//int ThreadNum = *((int *)fd);printf("[UP]ThreadNum = %d\n",ThreadNum);

	//触发上行计时线程开始
	//printf("[%d] BufReady waiting...\n",TCPCliParaList.CountTCPClientBufReady_Waiting);
	TCPCliParaList.CountTCPClientBufReady_Waiting++;
	
	recvfrom(TCPCliParaList.RECVTCPClientBufReady,Trigger,20,0,(struct sockaddr *)&TCPCliParaList.RECVAddrToTCPClientBufReady,&SockAddrLength);
	
	//printf("[%d] BufReady triggered!\n",TCPCliParaList.CountTCPClientBufReady_Triggered);
	TCPCliParaList.CountTCPClientBufReady_Triggered++;
	
	//printf("[%d] StartOrder2 waiting...\n",TCPCliParaList.CountTCPClientStartOrder2_Waiting);
	//TCPCliParaList.CountTCPClientStartOrder2_Waiting++;
	
	//recvfrom(TCPCliParaList.RECVTCPClientStartOrder2,Trigger,20,0,(struct sockaddr *)&TCPCliParaList.RECVAddrToTCPClientStartOrder2,&SockAddrLength);
	
	//printf("[%d] StartOrder2 triggered!\n",TCPCliParaList.CountTCPClientStartOrder2_Triggered);
	//TCPCliParaList.CountTCPClientStartOrder2_Triggered++;
	
	//计时器相关参数初始化
	TCPCliParaList.RTOs = RTOS;//往返容忍时延（RTO大于1秒部分，单位秒）
	TCPCliParaList.RTOus = RTOUS;//往返容忍时延（RTO小于1秒部分，单位微秒）
	TCPCliParaList.RTOns = RTONS;//往返容忍时延（RTO小于1秒部分，单位纳秒）
	time_t GMT;//国际标准时间，实例化time_t结构(typedef long time_t;)
	struct timespec delaytime;

	//触发TCP主子线程开始
	sendto(TCPCliParaList.SENDTCPClientStartOrder3,"StartOrder3",20,0,(struct sockaddr *)&TCPCliParaList.SENDAddrToTCPClientStartOrder3,SockAddrLength);

	//printf("[%d] StartOrder3 triggering...\n",TCPCliParaList.CountTCPClientStartOrder3_Triggering);
	TCPCliParaList.CountTCPClientStartOrder3_Triggering++;

	while(1)
	{
		//变量清零
		TCPCliParaList.TimingState = 0;

		//printf("[%d] TimingBegin waiting...\n",TCPCliParaList.CountTCPClientTimingBegin_Waiting);
		TCPCliParaList.CountTCPClientTimingBegin_Waiting++;
		
		//阻塞等待定时任务
		recvfrom(TCPCliParaList.RECVTCPClientTimingBegin,Trigger,20,0,(struct sockaddr *)&TCPCliParaList.RECVAddrToTCPClientTimingBegin,&SockAddrLength);

		//printf("[%d] TimingBegin triggered!\n",TCPCliParaList.CountTCPClientTimingBegin_Triggered);
		TCPCliParaList.CountTCPClientTimingBegin_Triggered++;
		
		//定时阻塞窗口传输上行通道结束计时提示

		//printf("[%d] TimingEnd waiting...\n",TCPCliParaList.CountTCPClientTimingEnd_Waiting);
		TCPCliParaList.CountTCPClientTimingEnd_Waiting++;

		//带超时的UDP消息接收
		//设置超时
		struct timeval delaytime;
		delaytime.tv_sec=TCPCliParaList.RTOs;
		delaytime.tv_usec=TCPCliParaList.RTOus;

		//记录sockfd
		fd_set readfds;//已改用函数输入外部变量指针
		FD_ZERO(&readfds);
		FD_SET(TCPCliParaList.RECVTCPClientTimingEnd,&readfds);

		select(TCPCliParaList.RECVTCPClientTimingEnd+1,&readfds,NULL,NULL,&delaytime);
	
		//限时接收
		if(FD_ISSET(TCPCliParaList.RECVTCPClientTimingEnd,&readfds))
		{
			if(0 <= recvfrom(TCPCliParaList.RECVTCPClientTimingEnd,Trigger,20,0,(struct sockaddr *)&TCPCliParaList.RECVAddrToTCPClientTimingEnd,&SockAddrLength))
			{
				if(transDEVETESTIMPL <= 0)
					printf("[TimingEndDelay]  %.3f ms\n",(double)(TCPCliParaList.RTOus - (int)delaytime.tv_usec)/(double)1000);
			}
		}
		else
		{
			if(transDEVETESTIMPL <= 0)
				printf("[TimingEndDelay]  %.3f ms   (Timeout)\n",(double)(TCPCliParaList.RTOus - (int)delaytime.tv_usec)/(double)1000);
		}

		//printf("[%d] TimingEnd triggered!\n",TCPCliParaList.CountTCPClientTimingEnd_Triggered);
		TCPCliParaList.CountTCPClientTimingEnd_Triggered++;

		//通知下行通道，反馈本次反馈计时已得出结果
		sendto(TCPCliParaList.SENDTCPClientTimingRespond,"TimingRespond",20,0,(struct sockaddr *)&TCPCliParaList.SENDAddrToTCPClientTimingRespond,SockAddrLength);

		//printf("[%d] TimingRespond triggering...\n",TCPCliParaList.CountTCPClientTimingRespond_Triggering);
		TCPCliParaList.CountTCPClientTimingRespond_Triggering++;
	}
	
	//关闭线程
	exit(0);
	free(fd);
	pthread_exit(NULL);
}

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
)
{
	//提取任务编号
	//int ThreadNum = *((int *)fd);printf("[DOWN]ThreadNum = %d\n",ThreadNum);

	//触发下行线程开始
	//printf("[%d] StartOrder4 waiting...\n",TCPCliParaList.CountTCPClientStartOrder4_Waiting);
	TCPCliParaList.CountTCPClientStartOrder4_Waiting++;

	recvfrom(TCPCliParaList.RECVTCPClientStartOrder4,Trigger,20,0,(struct sockaddr *)&TCPCliParaList.RECVAddrToTCPClientStartOrder4,&SockAddrLength);

	//printf("[%d] StartOrder4 triggered!\n",TCPCliParaList.CountTCPClientStartOrder4_Triggered);
	TCPCliParaList.CountTCPClientStartOrder4_Triggered++;

	//向网络请求一个SID文件
	/*
	在此处添加SID转接代码
	变量realPath即为SID
	输出接口：SID
	输出对象：CoLoR协议GET包封装程序
	输出方式：1、文件存取（因延迟较大并不建议）；2、socket发送本地回环消息
	*/

	//创建socket
	//套接口描述字
	int socket_sidsender;
	socket_sidsender = socket(AF_INET,SOCK_DGRAM,0);
	
	struct sockaddr_in addrTo;
	bzero(&addrTo,SockAddrLength);
	addrTo.sin_family=AF_INET;
	addrTo.sin_port=htons(APPLtoTRAL);
	//unsigned long IPto = 2130706433;//回环地址名称 == 2130706433
	//addrTo.sin_addr.s_addr=htonl(IPto);//htonl将主机字节序转换为网络字节序
	addrTo.sin_addr.s_addr=inet_addr(LOOPIP);//htonl将主机字节序转换为网络字节序
	
	//赋值SID 
	strcpy(SID,"wangzhaoxu");
	if(transDEVETESTIMPL <= 0)
		printf("\n[SID  ]  %s\n",SID);
	
	uint8_t offset[OFFLEN];
	unsigned long filelen = FILELEN;//debuglog.txt的文件大小

	uint8_t sendpkg[sizeof(Trans_get)];
	Trans_get * psendpkg;
	psendpkg = (Trans_get *)sendpkg;

	while(TCPCliParaList.OffsetConfirmDATA <= filelen)
	{
		memset(sendpkg,0,sizeof(Trans_get));

		if(TCPCliParaList.TimingState == 0)//未超时
		{
			TCPCliParaList.OffsetWaitDATA += 0;
		}
		else if(TCPCliParaList.TimingState == 1)//超时
		{
		}
		//printf("[Down]OffsetWaitDATA = %ld\n",TCPCliParaList.OffsetWaitDATA);
		
		//计算待确认的偏移量值
		offset[3] = TCPCliParaList.OffsetWaitDATA % 256;
		offset[2] = TCPCliParaList.OffsetWaitDATA / 256 % 256;
		offset[1] = TCPCliParaList.OffsetWaitDATA / 256 / 256 % 256;
		offset[0] = TCPCliParaList.OffsetWaitDATA / 256 / 256 / 256 % 256;
		
		//封装传输层get包
		strcpy(psendpkg->sid,SID);
		memcpy(psendpkg->offset,offset,OFFLEN);
	
		//发送传输层get包
		sendto(socket_sidsender,sendpkg,sizeof(Trans_get),0,(struct sockaddr *)&addrTo,SockAddrLength);

		if(DEVETESTIMPL <= 1)
			printf("[Transport Layer] The TCPClient asked for Data whitch match the SID: %s\n",SID);

		//触发反馈计时
		sendto(TCPCliParaList.SENDTCPClientTimingBegin,"TimingBegin",20,0,(struct sockaddr *)&TCPCliParaList.SENDAddrToTCPClientTimingBegin,SockAddrLength);

		//printf("[%d] TimingBegin triggering...\n",TCPCliParaList.CountTCPClientTimingBegin_Triggering);
		TCPCliParaList.CountTCPClientTimingBegin_Triggering++;

		//printf("[%d] TimingRespond waiting...\n",TCPCliParaList.CountTCPClientTimingRespond_Waiting);
		TCPCliParaList.CountTCPClientTimingRespond_Waiting++;

		//等待触发回送ACK
		recvfrom(TCPCliParaList.RECVTCPClientTimingRespond,Trigger,20,0,(struct sockaddr *)&TCPCliParaList.RECVAddrToTCPClientTimingRespond,&SockAddrLength);

		//printf("[%d] TimingRespond triggered!\n",TCPCliParaList.CountTCPClientTimingRespond_Triggered);
		TCPCliParaList.CountTCPClientTimingRespond_Triggered++;
		
		//结束判断：收到的数据长度累积超过预知文件长度的逻辑容忍范围（逻辑容忍范围是文件长度+单包长度）
		if(TCPCliParaList.OffsetConfirmDATA >= filelen)
		{
			printf("[END message]Received File Length is Bigger Than the File Length Ever known.\n");
			
			TCPCliParaList.FlagInputBUF = 0;

			//通知向文件写入数据
			sendto(TCPCliParaList.SENDTCPClientWriteData,"WriteData",20,0,(struct sockaddr *)&TCPCliParaList.SENDAddrToTCPClientWriteData,SockAddrLength);

			//printf("[%d] WriteData triggering...\n",TCPCliParaList.CountTCPClientWriteData_Triggering);
			TCPCliParaList.CountTCPClientWriteData_Triggering++;
		}
		//写入文件判断
		else if(TCPCliParaList.OffsetConfirmDATA / ( TCPCliParaList.BUFLength / 2 ) >= TCPCliParaList.BUFRenewCount + 1)
		{
			//通知向文件写入数据
			sendto(TCPCliParaList.SENDTCPClientWriteData,"WriteData",20,0,(struct sockaddr *)&TCPCliParaList.SENDAddrToTCPClientWriteData,SockAddrLength);

			//printf("[%d] WriteData triggering...\n",TCPCliParaList.CountTCPClientWriteData_Triggering);
			TCPCliParaList.CountTCPClientWriteData_Triggering++;
		}
	}
	
	printf("[Down]File transport end.\n");
	sleep(100);//等待一百秒，若仍然未能在写入文件的线程中关闭程序，说明程序出现死机等问题，应当自动关闭

	//关闭线程
	exit(0);
	free(fd);
	pthread_exit(NULL);
}

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
)
{
	int i,j;

	TCPClient_Parameterinit();

	//创建发送计时器子线程
	pthread_t pthread_timer;
	if(pthread_create(&pthread_timer, NULL, TCPClient_thread_timer, NULL)!=0)
	{
		perror("Creation of timer thread failed.");
	}
	
	//创建TCP主子线程
	pthread_t pthread_TCP;
	if(pthread_create(&pthread_TCP, NULL, TCPClient_thread_TCP, NULL)!=0)
	{
		perror("Creation of TCP thread failed.");
	}

	//创建thread_FTP子线程
	pthread_t pthread_FTP;
	if(pthread_create(&pthread_FTP, NULL, TCPClient_thread_FTP, NULL)!=0)
	{
		perror("Creation of FTP thread failed.");
	}
	
	//创建thread_NetworkLayertoTransportLayer上行子线程
	pthread_t pthread_NetworkLayertoTransportLayer;
	if(pthread_create(&pthread_NetworkLayertoTransportLayer, NULL, TCPClient_thread_NetworkLayertoTransportLayer, NULL)!=0)
	{
		perror("Creation of NetworkLayertoTransportLayer thread failed.");
	}
	
	//创建thread_TransportLayertoNetworkLayer下行子线程
	pthread_t pthread_TransportLayertoNetworkLayer;
	if(pthread_create(&pthread_TransportLayertoNetworkLayer, NULL, TCPClient_thread_TransportLayertoNetworkLayer, NULL)!=0)
	{
		perror("Creation of TransportLayertoNetworkLayer thread failed.");
	}

	//创建为Subscriber模块输出的通信参数，并储存
	/*
	struct subscriberinput
	{
		int argc;
		char argv[50][30];
	};
	*/
	struct subscriberinput subinput;
	subinput.argc=0;
	memset(subinput.argv,0,1500);

	subinput.argc=argc;
	for(i=0;i<subinput.argc;i++)
	{
		strcpy(subinput.argv[i],argv[i]);
	}

	pthread_t pthread_subscriber;

	//创建Subscriber子线程
	if(pthread_create(&pthread_subscriber, NULL, Subscriber_main, (void *)&subinput)!=0)
	{
		perror("Creation of subscriber thread failed.");
	}

	//Subscriber_main(argc,(char (*)[30])argv);

	//主循环——客户端代码
	while (1)
	{
		sleep(10000);
	}
}
