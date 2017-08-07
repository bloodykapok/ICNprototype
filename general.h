/*******************************************************************************************************************************************
* 文件名：general.h
* 文件描述：973智慧协同网络SAR系统TestBed套件——网络层通用调用文件
* 声明：本模板代码作者王兆旭，为北京交通大学下一代互联网互联设备国家工程实验室新生基础工程技术培训专用。作者王兆旭在此郑重声明，此文件及其它用于培训的模板代码均为本人精力与经验的产物，本资源的传播方式均为作者本人向他人进行一对一传授，任何个人不得向第三方转交或展示该资源内容。任何有需求的学员，均须向王兆旭本人直接索要，亦无向他人索要或传授之权利和义务。因有些资源内容涉及实验室项目秘密，暂不考虑申请专利保护或软件著作权等事宜，故个别资源仅限实验室内部一对一发放，如发现有辜负作者本人的一片好意的行为，作者将保留就其原创性进行追查、举证、申诉和问责的权利。本资源的发放权归作者本人所有，其整理和总结过程浸透无偿贡献的热忱和为诸君学业尽绵薄之力的真诚，愿学员尊重作者的劳动成果，谢谢合作！
* 作者：王兆旭
* 身份：北京交通大学下一代互联网互联设备国家工程实验室 2013级硕博连读研究生
* E-mail. hellozxwang@foxmail.com
* Mobile. 18811774990
* QQ    . 535667240
* Addr  . 北京市海淀区西直门外北京交通大学机械楼D706室, 100044
*******************************************************************************************************************************************/
/*******************************************************************************************************************************************
*****功能说明：1.网络层通用调用文件**********************************************************************************************************
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

#include"physicalport.h"

#ifndef _GENERAL_
#define _GENERAL_

//软件状态，即是否需要输出各阶段运行的数据，输出多少：
//开发阶段 == 0
//测试阶段 == 1
//残包阶段 == 2
//微调阶段 == 3
//二次开发阶段 == 4
//部署阶段 == 5
//测试 == 6
//输出参数 == 7
#define netDEVETESTIMPL DEVETESTIMPL

//疑似Subscriber与PhysicalPort的通信设置
#define destPORT  6000
#define localPORT 6000

//读取配置文件的基本路径与大小参数
#define FILEnameL 100

#define FILERT     "./routingtable"
#define RTLENTH     5000
char FILERTname[FILEnameL];

#define FILEinterswitch "./interswitch"
#define INTERSWITCHLENTH 2000
char FILEinterswitchname[FILEnameL];

#define FILEsid "./sid"
#define SIDLENTH 5000
char FILEsidname[FILEnameL];

#define FILEpid "./pid"
#define PIDLENTH 5000
char FILEpidname[FILEnameL];

//节点系统内部通信
#define NETLtoTRAL     6001                 //[UDP端口号]网络层  发往  传输层  （上行）
#define TRALtoNETL     6002                 //[UDP端口号]传输层  发往  网络层  （下行）
#define TRALtoAPPL     6003                 //[UDP端口号]传输层  发往  应用层  （上行）
#define APPLtoTRAL     6004                 //[UDP端口号]应用层  发往  传输层  （下行）

#define NETUtoNETD     6011                 //[UDP端口号][网络层]上行通道  发往  下行通道
#define NETDtoNETU     6012                 //[UDP端口号][网络层]下行通道  发往  上行通道
#define TRAUtoTRAD     6013                 //[UDP端口号][传输层]上行通道  发往  下行通道
#define TRADtoTRAU     6014                 //[UDP端口号][传输层]下行通道  发往  上行通道
#define APPUtoAPPD     6015                 //[UDP端口号][应用层]上行通道  发往  下行通道
#define APPDtoAPPU     6016                 //[UDP端口号][应用层]下行通道  发往  上行通道

//程序调试状态配置
//拓扑配置文件路径前缀
#define configFILEprefix "./973domain/domain"

//本机配置信息
uint8_t SwitchDevice_local_ip[16];//转发平面设备通用的回环通信地址

//计时
struct timeval starttime,forwardingtime;
double timefornow;

//物理端口与其所属内部通信IP的映射表项
typedef struct _PPIP PPIP;
struct _PPIP
{
	uint8_t pp[30];
	uint8_t ip[16];
};
int ppiplistcount;

//路由表项
typedef struct _RoutingTableEvent RoutingTableEvent;
struct _RoutingTableEvent
{
	uint8_t dest[40];
	uint8_t port[30];
};
int routingtablecount;

//域间转发表项
typedef struct _InterSwitchEvent InterSwitchEvent;
struct _InterSwitchEvent
{
	uint8_t pid[4];
	uint8_t port[30];
};
int interswitchtablecount;

//PID表项
typedef struct _PIDEvent PIDEvent;
struct _PIDEvent
{
	uint8_t did[10];
	uint8_t pid[4];
	uint8_t nid[16];
};
int pidlistcount;

//SID表项
typedef struct _SIDEvent SIDEvent;
struct _SIDEvent
{
	uint8_t sid[40];
	uint8_t flag;
	uint8_t xid[10];
};
int sidlistcount;

//运行过程相关的中转及判断变量
//三机通用
char domainID[10];
char deviceNA[30];
char deviceID[30];

//接收缓冲区
int RecvBUFLength;
uint8_t RecvBUF[BUFSIZE];
//发送缓冲区
int SendBUFLength;
uint8_t SendBUF[BUFSIZE];

//杂项
int LocalPkgBUFTail;
int PKGLength;
uint8_t ForPKG[PKGSIZE];
uint8_t UpPKG[PKGSIZE];
uint8_t DownPKG[PKGSIZE];

uint8_t tempNID[NIDLENst];

//br
uint8_t tempPID[4];

//br rm
int pkgType;

//rm
int flagSIDchange;

int tempPIDlocation;

/*****************************************
* 函数名称：configure_RTfilepath
* 功能描述：自动配置节点路由表配置文件的读取路径
* 参数列表：
* 返回结果：
*****************************************/
void
configure_RTfilepath
(
	char * RTfilepath,
	char * domainID,
	char * deviceNA,
	char * deviceID
);

/*****************************************
* 函数名称：configure_InterSwitchfilepath
* 功能描述：自动配置节点边界转发配置文件的读取路径
* 参数列表：
* 返回结果：
*****************************************/
void
configure_InterSwitchfilepath
(
	char * InterSwitchfilepath,
	char * domainID,
	char * deviceNA,
	char * deviceID
);

/*****************************************
* 函数名称：configure_SIDfilepath
* 功能描述：自动配置节点SID注册配置文件的读取路径
* 参数列表：
* 返回结果：
*****************************************/
void
configure_SIDfilepath
(
	char * SIDfilepath,
	char * domainID,
	char * deviceNA,
	char * deviceID
);

/*****************************************
* 函数名称：configure_PIDfilepath
* 功能描述：自动配置节点PID通告表配置文件的读取路径
* 参数列表：
* 返回结果：
*****************************************/
void
configure_PIDfilepath
(
	char * PIDfilepath,
	char * domainID,
	char * deviceNA,
	char * deviceID
);

#endif
