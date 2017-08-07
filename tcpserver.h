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

#include"transportlayerdefine.h"
#include"publisher.h"

/*******************************************************************************************************************************************
*************************************宏定义配置数据************全局变量定义******************************************************************
*******************************************************************************************************************************************/
#ifndef _TCPSER_
#define _TCPSER_



//TCP任务线程控制参数组
//Tip.信号量的声明不能处在奇地址上，在结构体中，多个变量的存储采用字节对齐的方式，才会存在奇地址的问题
struct TCPSerPara
{
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

	//内部线程触发用UDP通信变量
	int CountTCPServerWindowBegin_Triggering;
	int CountTCPServerWindowBegin_Waiting;
	int CountTCPServerWindowBegin_Triggered;

	int SENDTCPServerWindowBegin;
	int RECVTCPServerWindowBegin;
	struct sockaddr_in SENDAddrToTCPServerWindowBegin;
	struct sockaddr_in RECVAddrToTCPServerWindowBegin;

	int CountTCPServerWindowTimingEnd_Triggering;
	int CountTCPServerWindowTimingEnd_Waiting;
	int CountTCPServerWindowTimingEnd_Triggered;

	int SENDTCPServerWindowTimingEnd;
	int RECVTCPServerWindowTimingEnd;
	struct sockaddr_in SENDAddrToTCPServerWindowTimingEnd;
	struct sockaddr_in RECVAddrToTCPServerWindowTimingEnd;

	int CountTCPServerWindowRespond_Triggering;
	int CountTCPServerWindowRespond_Waiting;
	int CountTCPServerWindowRespond_Triggered;

	int SENDTCPServerWindowRespond;
	int RECVTCPServerWindowRespond;
	struct sockaddr_in SENDAddrToTCPServerWindowRespond;
	struct sockaddr_in RECVAddrToTCPServerWindowRespond;

	int CountTCPServerBufReady_Triggering;
	int CountTCPServerBufReady_Waiting;
	int CountTCPServerBufReady_Triggered;

	int SENDTCPServerBufReady;
	int RECVTCPServerBufReady;
	struct sockaddr_in SENDAddrToTCPServerBufReady;
	struct sockaddr_in RECVAddrToTCPServerBufReady;

	int CountTCPServerMoreData_Triggering;
	int CountTCPServerMoreData_Waiting;
	int CountTCPServerMoreData_Triggered;

	int SENDTCPServerMoreData;
	int RECVTCPServerMoreData;
	struct sockaddr_in SENDAddrToTCPServerMoreData;
	struct sockaddr_in RECVAddrToTCPServerMoreData;

	int CountTCPServerFileClose_Triggering;
	int CountTCPServerFileClose_Waiting;
	int CountTCPServerFileClose_Triggered;

	int SENDTCPServerFileClose;
	int RECVTCPServerFileClose;
	struct sockaddr_in SENDAddrToTCPServerFileClose;
	struct sockaddr_in RECVAddrToTCPServerFileClose;

	int CountTCPServerContinueRECV_Triggering;
	int CountTCPServerContinueRECV_Waiting;
	int CountTCPServerContinueRECV_Triggered;

	int SENDTCPServerContinueRECV;
	int RECVTCPServerContinueRECV;
	struct sockaddr_in SENDAddrToTCPServerContinueRECV;
	struct sockaddr_in RECVAddrToTCPServerContinueRECV;

	//统计量
	int InputCount;//窗口写入次数
	unsigned long TotalWindowLength;//累计窗口总长度
	unsigned long LostPacketCount;//总丢包次数
	unsigned long timer_XX;//总运行时间秒数
};
struct TCPSerPara TCPSerParaList;

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
TCPServer_Parameterinit();

/*******************************************************************************************************************************************
*******************************************应用层TCPServer服务器（通过CLI控制）******************************************************************
*******************************************************************************************************************************************/

/*******************************************************************************************************************************************
*******************************************上行通道 - From.数据响应端   To.应用服务器*********************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：TCPServer_FindData
* 功能描述：查询SID对应的DATA
* 参数列表：
* 返回结果：
*****************************************/
int
TCPServer_FindData
(
	uint8_t * SID,
	uint8_t * DATA
);

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
);

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
);

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
);

/*****************************************
* 函数名称：TCPServer_thread_NetworkLayertoTransportLayer
* 功能描述：上行通道 - From.数据响应端   To.应用服务器
* 参数列表：
* 返回结果：
*****************************************/
void *
TCPServer_thread_NetworkLayertoTransportLayer
(
	void * fd
);

/*****************************************
* 函数名称：TCPServer_thread_TransportLayertoNetworkLayer
* 功能描述：下行通道 - From.应用服务器 To.数据响应端
* 参数列表：
* 返回结果：
*****************************************/
void *
TCPServer_thread_TransportLayertoNetworkLayer
(
	void * fd
);

/*****************************************
* 函数名称：TCPServer_main
* 功能描述：TCPServer模块主函数，启动各个线程，自身不提供实际功能
* 参数列表：第二参数使用char**argv的方式声明报错，不知是不是语法问题
* 返回结果：
*****************************************/
int
TCPServer_main
(
	int argc,
	char argv[][30]
);

#endif
