/*******************************************************************************************************************************************
* 文件名：physicalport.h
* 文件描述：973智慧协同网络SAR系统TestBed套件——【虚拟/真实】两用物理网口
* 声明：本模板代码作者王兆旭，为北京交通大学下一代互联网互联设备国家工程实验室新生基础工程技术培训专用。作者王兆旭在此郑重声明，此文件及其它用于培训的模板代码均为本人精力与经验的产物，本资源的传播方式均为作者本人向他人进行一对一传授，任何个人不得向第三方转交或展示该资源内容。任何有需求的学员，均须向王兆旭本人直接索要，亦无向他人索要或传授之权利和义务。因有些资源内容涉及实验室项目秘密，暂不考虑申请专利保护或软件著作权等事宜，故个别资源仅限实验室内部一对一发放，如发现有辜负作者本人的一片好意的行为，作者将保留就其原创性进行追查、举证、申诉和问责的权利。本资源的发放权归作者本人所有，其整理和总结过程浸透无偿贡献的热忱和为诸君学业尽绵薄之力的真诚，愿学员尊重作者的劳动成果，谢谢合作！
* 作者：王兆旭
* 身份：北京交通大学下一代互联网互联设备国家工程实验室 2013级硕博连读研究生
* E-mail. hellozxwang@foxmail.com
* Mobile. 18811774990
* QQ    . 535667240
* Addr  . 北京市海淀区西直门外北京交通大学机械楼D706室, 100044
*******************************************************************************************************************************************/
/*******************************************************************************************************************************************
*****功能说明：1.物理层监听数据帧，解封MAC层并向路由层上传SAR/CoLoR类数据包；2.从路由层接收待发送数据包，封装MAC层并发送************************
*******************************************************************************************************************************************/
/*
快速配置步骤：
1、宏定义修改

2、系统设置
在Fedora系统中因需要使用原始套接字发送自定义格式的数据包，须关闭Fedora的防火墙，命令：
sudo systemctl stop firewalld.service
在Ubuntu系统中无需任何操作
3、编译命令
make
4、运行
因涉及原始套接字的使用，须root权限
sudo ./xxx（xxx依据上层调用本文件的程序而定）
*/

#include"library.h"
#include"packet.h"
#include"basic.h"

#include"cnfserver.h"
#include"cnfclient.h"

/*******************************************************************************************************************************************
*************************************宏定义配置数据************全局变量定义******************************************************************
*******************************************************************************************************************************************/

//IP模式下地址配置文件
#define FILEIPNODE "./ipnode"
#define FILEIPNODELENTH 5000

//仿真组网虚拟参量配置

//程序调试状态配置

//软件状态，即是否需要输出各阶段运行的数据，输出多少：
//开发阶段 == 0
//测试阶段 == 1
//残包阶段 == 2
//微调阶段 == 3
//二次开发阶段 == 4
//部署阶段 ==5
#define pysicalportDEVETESTIMPL DEVETESTIMPL

//是否为跨实体机测试：
//本地总线型测试          == 0
//基于mininet仿真网络平台 == 1
//物理实体机一对一部署    == 2
#define pysicalportGLOBALTEST GLOBALTEST

//使用的协议栈种类
//MAC-CoLoR        == 0
//MAC-IP-UDP-CoLoR == 1
#define pysicalportPROTOCOL PROTOCOL

//是否测试运行时间
//不测试   0
//框架测试 1
//完整测试 2
#define pysicalportSEETIME SEETIME

#ifndef _MACLAYER_
#define _MACLAYER_

//全局变量

//网口所属的节点NID
char NID[NIDLEN];
//网口各自使用的发包-收包防冲突标识
int selfpacketdonotcatch[48];

uint8_t local_mac[7];//（多线程程序中应做局部传递变量处理）（尚未处理）
uint8_t dest_mac[7]; //（多线程程序中应做局部传递变量处理）（尚未处理）
//uint8_t local_ip[16];（多线程程序中已做局部传递变量处理）
uint8_t dest_ip[16];//程序北向接口
uint8_t broad_mac1[7];
uint8_t broad_mac2[7];

//转发平面与physicalport模块之间传递的参数结构体
struct physicalportinput
{
	char pp[30];//交给physicalport模块所需绑定的网口名称
	char ip[16];//转发平面统一收发数据包内容的回环IP地址
};
int pplistcount;

//physicalport模块内部线程传递的参数结构体
struct pplip
{
	char pp[30];//交给physicalport模块所需绑定的网口名称
	uint8_t lmac[6];//本网口的MAC地址，用于收发包查重
	char ip[16];//physicalport模块自身的UDP回环通信地址
};
int ppliplistcount;

//IP节点网口与IP地址对应关系存储总表
struct ipnode
{
	char nid[NIDLEN];//节点NID
	char pp[30];//IP节点入网网口号
	char ip[16];//网口号登录的IP地址
}ipnodelist[100];
int ipnodelistcount;

#endif

/*******************************************************************************************************************************************
*******************************************初始化参数配置相关********************************************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：PhysicalPort_Parameterinit
* 功能描述：physicalport模块全局变量赋初值
* 参数列表：
* 返回结果：
*****************************************/
void
PhysicalPort_Parameterinit();

/*****************************************
* 函数名称：PhysicalPort_Configure
* 功能描述：PhysicalPort模块初始化配置
* 参数列表：
* 返回结果：
*****************************************/
int
PhysicalPort_Configure
(
	char * PhysicalPort,
	uint8_t * LocalMAC,
	char * local_ip
);

/*******************************************************************************************************************************************
*******************************************下行通道 - From.转发平面 To.物理网口**************************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：PhysicalPort_CoLoR_SeeType
* 功能描述：判断是否为、为何种CoLoR包头
* 参数列表：
* 返回结果：
*****************************************/
int
PhysicalPort_CoLoR_SeeType
(
	const CoLoR_VersionType * pkg
);

/*****************************************
* 函数名称：PhysicalPort_Ethernet_Sendpkg
* 功能描述：向物理网口发送MAC+CoLoR数据包
* 参数列表：
* 返回结果：
*****************************************/
int
PhysicalPort_Ethernet_Sendpkg
(
	char * PhysicalPort,
	int portnum,
	char * mac,
	char * dest_mac,
	char * ip,
	char * dest,
	char * message,
	unsigned int messagelength
);

/*****************************************
* 函数名称：PhysicalPort_UDP_Sendpkg
* 功能描述：向物理网口发送MAC+IP+UDP+CoLoR数据包
* 参数列表：
* 返回结果：
注意：由于Register没有明确的目的NID，为了维护程序可拓展性，要对三种CoLoR包格式进行区别处理
*****************************************/
int
PhysicalPort_UDP_Sendpkg
(
	char * PhysicalPort,
	char * packet,
	int packetlength
);

/*******************************************************************************************************************************************
*******************************************上行通道 - From.物理网口 To.转发平面**************************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：PhysicalPort_Ethernet_SetPromisc
* 功能描述：物理网卡混杂模式属性操作
* 参数列表：
* 返回结果：
*****************************************/
int
PhysicalPort_Ethernet_SetPromisc
(
	const char * pcIfName,
	int fd,
	int iFlags
);

/*****************************************
* 函数名称：PhysicalPort_Ethernet_InitSocket
* 功能描述：创建RAW套接字
* 参数列表：
* 返回结果：
*****************************************/
int
PhysicalPort_Ethernet_InitSocket
(
	char * PhysicalPort
);

/*****************************************
* 函数名称：PhysicalPort_UDP_InitSocket
* 功能描述：创建UDP套接字
* 参数列表：

* 返回结果：
*****************************************/
int
PhysicalPort_UDP_InitSocket
(
	char * PhysicalPort
);

/*****************************************
* 函数名称：PhysicalPort_Ethernet_StartCapture
* 功能描述：RAW套接字捕获网卡数据帧
* 参数列表：
* 返回结果：
*****************************************/
void
PhysicalPort_Ethernet_StartCapture
(
	const int fd,
	char * PhysicalPort,
	int portnum,
	uint8_t * LocalMAC,
	char * local_ip
);

/*****************************************

* 函数名称：PhysicalPort_UDP_StartCapture
* 功能描述：UDP套接字捕获网卡数据帧
* 参数列表：
* 返回结果：
*****************************************/
void
PhysicalPort_UDP_StartCapture
(
	const int fd,
	char * PhysicalPort,
	int portnum,
	char * local_ip
);

/*****************************************
* 函数名称：PhysicalPort_Ethernet_ParseFrame
* 功能描述：数据帧解析函数，处理对象包含MAC层
* 参数列表：
* 返回结果：
*****************************************/
int
PhysicalPort_Ethernet_ParseFrame
(
	uint8_t * EnBUF,
	char * PhysicalPort,
	char * local_ip
);

/*****************************************
* 函数名称：PhysicalPort_Ethernet_SeeType
* 功能描述：判断是否为、为何种以太网包头
* 参数列表：
* 返回结果：
*****************************************/
int
PhysicalPort_Ethernet_SeeType
(
	const Ether_VersionType * pkg
);

/*****************************************
* 函数名称：PhysicalPort_CoLoR_Parsepacket
* 功能描述：解析CoLoR包头
* 参数列表：
* 返回结果：
*****************************************/
int
PhysicalPort_CoLoR_Parsepacket
(
	const char * pkg,
	char * PhysicalPort,
	char * local_ip
);

/*****************************************
* 函数名称：PhysicalPort_CNF_NewClientThread
* 功能描述：创建新的CNF-Client任务实例
* 参数列表：
* 返回结果：
*****************************************/
void
PhysicalPort_CNF_NewClientThread
(
	const uint8_t * originalbuf,
	const unsigned int pkglength,
	char * PhysicalPort,
	char * local_ip
);

/*****************************************
* 函数名称：PhysicalPort_CNF_NewServerThread
* 功能描述：创建新的CNF-Server任务实例
* 参数列表：
* 返回结果：
*****************************************/
void
PhysicalPort_CNF_NewServerThread
(
	const uint8_t * originalbuf,
	const unsigned int pkglength,
	char * PhysicalPort,
	char * local_ip
);

/*****************************************
* 函数名称：PhysicalPort_CNF_SendMessage
* 功能描述：向CNF任务实例发送CNF包内容
* 参数列表：
* 返回结果：
*****************************************/
void
PhysicalPort_CNF_SendMessage
(
	const uint8_t * originalbuf,
	const unsigned int pkglength,
	int versiontype,
	char * PhysicalPort,
	char * local_ip
);

/*****************************************
* 函数名称：PhysicalPort_UDP_SendMessage
* 功能描述：向上层转发平面发送UDP封装的数据包内容
* 参数列表：
* 返回结果：
*****************************************/
void
PhysicalPort_UDP_SendMessage
(
	const uint8_t * originalbuf,
	const unsigned int pkglength,
	char * PhysicalPort,
	char * local_ip
);

/*****************************************
* 函数名称：PhysicalPort_SEM_SendMessage
* 功能描述：向上层转发平面发送SEM封装的数据包内容
* 参数列表：
* 返回结果：
*****************************************/
void
PhysicalPort_SEM_SendMessage
(
	const uint8_t * originalbuf,
	const unsigned int pkglength,
	char * PhysicalPort,
	char * local_ip
);

/*******************************************************************************************************************************************
**********************************************************多线程主干程序********************************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：PhysicalPort_thread_send
* 功能描述：下行通道 - From.转发平面 To.物理网口
* 参数列表：
* 返回结果：
*****************************************/
void *
PhysicalPort_thread_send
(
	void * fd
);

/*****************************************
* 函数名称：PhysicalPort_thread_recv
* 功能描述：上行通道 - From.物理网口 To.转发平面
* 参数列表：
* 返回结果：
*****************************************/
void *
PhysicalPort_thread_recv
(
	void * fd
);

/*****************************************
* 函数名称：thread_physicalport
* 功能描述：PhysicalPort模块主函数
* 参数列表：
* 返回结果：
*****************************************/
//int main(int argc, char *argv[])
//int thread_physicalport(char * SouthboundInterface, char * NorthboundInterface)
void *
thread_physicalport
(
	void * argv
);
