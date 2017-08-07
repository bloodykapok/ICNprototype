/*******************************************************************************************************************************************
* 文件名：tcpserver.h
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

#include"library.h"
#include"packet.h"
#include"basic.h"

#include"cnf.h"

/*******************************************************************************************************************************************
*************************************宏定义配置数据************全局变量定义******************************************************************
*******************************************************************************************************************************************/
#ifndef _CNFSER_
#define _CNFSER_

//软件状态，即是否需要输出各阶段运行的数据，输出多少：
//开发阶段 == 0
//测试阶段 == 1
//残包阶段 == 2
//微调阶段 == 3
//二次开发阶段 == 4
//部署阶段 == 5
//CNF测试 == 6
//CNF输出参数 == 7
#define cnfserDEVETESTIMPL cnfDEVETESTIMPL

//是否输出AIMD机制的每一步触发提示
#define CNFserverTRIGGERTEST CNFTRIGGERTEST

#define CNFBUFSIZE       1000000    //CNF单任务发送缓冲大小（1MB）

//CNF任务线程控制参数组
//Tip.信号量的声明不能处在奇地址上，在结构体中，多个变量的存储采用字节对齐的方式，才会存在奇地址的问题
struct CNFSerPara
{
	//内部线程触发用SEM通信变量
	sem_t semCNFServerWindowBegin;
	//sem_t semCNFServerWindowTimingEnd;
	sem_t semCNFServerWindowRespond;
	sem_t semCNFServerBufReady;
	sem_t semCNFServerMoreData;
	sem_t semCNFServerFileClose;
	sem_t semCNFServerContinueRECV;
/*
	if(cnfINTRACOMMUNICATION == 0)
	{
		recvfrom();
	}
	else if(cnfINTRACOMMUNICATION == 1)
	{
		sem_wait(&CNFSerParaList[threadnum].semCNFClientTimingRespond);
	}
*/
/*
	if(cnfINTRACOMMUNICATION == 0)
	{
		sendto();
	}
	else if(cnfINTRACOMMUNICATION == 1)
	{
		sem_post(&CNFSerParaList[threadnum].semCNFClientWriteData);
	}
*/

	uint8_t SID[SIDLEN];//任务所服务的SID
	int SIDLen;//SID的实际长度
	
	uint8_t * BUF;//发送缓冲区开头
	uint8_t * BUFEnd;//发送缓冲区结尾
	uint8_t * BUFFileEnd;//读取文件结束时，缓冲区内文件末尾所在地址

	int BUFRenewCount;//缓冲区更新次数
	unsigned long BUFLength;//发送缓冲长度

	int LogFilePoint;//运行日志文件标识
	unsigned long FileReadPoint;//文件读取进度
	unsigned long FileLength;//文件总长度

	unsigned long PacketDataLength;//单包数据段长度
	unsigned long LastPacketDataLength;//整个传输任务的最后一个数据包实际长度

	unsigned long WindowLength;//窗口长度
	unsigned long WindowThreshold;//窗口门限值

	unsigned long OffsetWindowHead;//在整个文件中窗口头部所指的偏移量
	unsigned long OffsetWindowEnd;//在整个文件中窗口尾部所指的偏移量
	unsigned long OffsetConfirmACK;//在整个文件中已确认偏移量所在偏移量
	unsigned long OffsetRequestACK;//在整个文件中接到请求的偏移量
	unsigned long OffsetPacket;//在整个文件中当前封包偏移量（回传数据包偏移量字段的填写依据）
	unsigned long OffsetWaitACK;//在整个文件中等待确认收到的偏移量（下一节）

	uint8_t * AddrWindowHead;//在缓冲区中窗口头部所在地址
	uint8_t * AddrWindowEnd;//在缓冲区中窗口尾部所在地址
	uint8_t * AddrConfirmACK;//在缓冲区中已确认偏移量所在地址（暂时没用）
	uint8_t * AddrRequestACK;//在缓冲区中接到请求的所在地址（暂时没用）
	uint8_t * AddrPacket;//在缓冲区中当前封包偏移量所在地址
	uint8_t * AddrWaitACK;//在缓冲区中待确认偏移量所在地址

	unsigned long RTOs;//往返容忍时延（RTO大于1秒部分，单位秒）
	unsigned long RTOus;//往返容忍时延（RTO小于1秒部分，单位微秒）
	unsigned long RTOns;//往返容忍时延（RTO小于1秒部分，单位纳秒）

	int FlagTrebleAck;//计数器，记录收到相同偏移量ACK的个数，用于判断三重ACK丢包状况

	int WindowState;//窗口状态，1ACK正常更新但未达窗口所要求的上界；2窗口传输成功；3三重ACK；4超时
	int ThreadState;//任务状态（用于结束过程的控制），0未完成，1文件读取完毕，2窗口录入完毕，3窗口发送完毕，4窗口确认完毕（即可终止）

	char NumStr[100];//字符缓存？

	//CNF任务线程组句柄
	pthread_t pthread_timer;
	pthread_t pthread_CNF;
	pthread_t pthread_NetworkLayertoTransportLayer;
	pthread_t pthread_TransportLayertoNetworkLayer;
	pthread_t pthread_FTP;
	
	//对外收发接口用UDP通信变量
	int SENDCNFServerSEG;
	struct sockaddr_in SENDAddrToCNFServerSEG;
	int RECVCNFServerACK;
	struct sockaddr_in RECVAddrToCNFServerACK;

	//内部线程触发用UDP通信变量
	int CountCNFServerWindowBegin_Triggering;
	int CountCNFServerWindowBegin_Waiting;
	int CountCNFServerWindowBegin_Triggered;

	int SENDCNFServerWindowBegin;
	int RECVCNFServerWindowBegin;
	struct sockaddr_in SENDAddrToCNFServerWindowBegin;
	struct sockaddr_in RECVAddrToCNFServerWindowBegin;

	int CountCNFServerWindowTimingEnd_Triggering;
	int CountCNFServerWindowTimingEnd_Waiting;
	int CountCNFServerWindowTimingEnd_Triggered;

	int SENDCNFServerWindowTimingEnd;
	int RECVCNFServerWindowTimingEnd;
	struct sockaddr_in SENDAddrToCNFServerWindowTimingEnd;
	struct sockaddr_in RECVAddrToCNFServerWindowTimingEnd;

	int CountCNFServerWindowRespond_Triggering;
	int CountCNFServerWindowRespond_Waiting;
	int CountCNFServerWindowRespond_Triggered;

	int SENDCNFServerWindowRespond;
	int RECVCNFServerWindowRespond;
	struct sockaddr_in SENDAddrToCNFServerWindowRespond;
	struct sockaddr_in RECVAddrToCNFServerWindowRespond;

	int CountCNFServerBufReady_Triggering;
	int CountCNFServerBufReady_Waiting;
	int CountCNFServerBufReady_Triggered;

	int SENDCNFServerBufReady;
	int RECVCNFServerBufReady;
	struct sockaddr_in SENDAddrToCNFServerBufReady;
	struct sockaddr_in RECVAddrToCNFServerBufReady;

	int CountCNFServerMoreData_Triggering;
	int CountCNFServerMoreData_Waiting;
	int CountCNFServerMoreData_Triggered;

	int SENDCNFServerMoreData;
	int RECVCNFServerMoreData;
	struct sockaddr_in SENDAddrToCNFServerMoreData;
	struct sockaddr_in RECVAddrToCNFServerMoreData;

	int CountCNFServerFileClose_Triggering;
	int CountCNFServerFileClose_Waiting;
	int CountCNFServerFileClose_Triggered;

	int SENDCNFServerFileClose;
	int RECVCNFServerFileClose;
	struct sockaddr_in SENDAddrToCNFServerFileClose;
	struct sockaddr_in RECVAddrToCNFServerFileClose;

	int CountCNFServerContinueRECV_Triggering;
	int CountCNFServerContinueRECV_Waiting;
	int CountCNFServerContinueRECV_Triggered;

	int SENDCNFServerContinueRECV;
	int RECVCNFServerContinueRECV;
	struct sockaddr_in SENDAddrToCNFServerContinueRECV;
	struct sockaddr_in RECVAddrToCNFServerContinueRECV;

	//统计量
	int InputCount;//窗口写入次数
	unsigned long TotalWindowLength;//累计窗口总长度
	unsigned long LostPacketCount;//总丢包次数
	unsigned long timer_XX;//总运行时间秒数
};
struct CNFSerPara CNFSerParaList[THREADNUM];

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
);

/*****************************************
* 函数名称：CNFServer_SendData
* 功能描述：同时终止该CNF整个任务并回收的所有资源
* 参数列表：
* 返回结果：
*****************************************/
void
CNFServer_Parametershut
(
	int threadnum
);

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
);

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
);

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
);

/*****************************************
* 函数名称：CNFServer_thread_NetworkLayertoTransportLayer
* 功能描述：上行通道 - From.数据响应端   To.应用服务器
* 参数列表：
* 返回结果：
*****************************************/
void *
CNFServer_thread_NetworkLayertoTransportLayer
(
	void * fd
);

/*****************************************
* 函数名称：CNFServer_thread_TransportLayertoNetworkLayer
* 功能描述：下行通道 - From.应用服务器 To.数据响应端
* 参数列表：
* 返回结果：
*****************************************/
void *
CNFServer_thread_TransportLayertoNetworkLayer
(
	void * fd
);

/*****************************************
* 函数名称：CNFServer_main
* 功能描述：CNFServer模块主函数，启动各个线程，自身不提供实际功能
* 参数列表：第二参数使用char**argv的方式声明报错，不知是不是语法问题
* 返回结果：
*****************************************/
int
CNFServer_main
(
	void * fd
);

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
);

#endif
