/*******************************************************************************************************************************************
* 文件名：cnf.h
* 文件描述：973智慧协同网络SAR系统TestBed套件——CNF通用变量
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

#ifndef _CNF_
#define _CNF_

//是否启动CNF模式
#define CNFON 0

//CNF模式下的线程间通信端口配置

#define CNFClientTimingBegin       6021     //[UDP端口号][传输层][CNF发送端]计时开始
#define CNFClientTimingEnd         6022     //[UDP端口号][传输层][CNF发送端]计时结束
#define CNFClientTimingRespond     6023     //[UDP端口号][传输层][CNF发送端]反馈计时结果
#define CNFClientBufReady          6024     //[UDP端口号][传输层][CNF发送端]接收缓冲启动
#define CNFClientMoreData          6025     //[UDP端口号][传输层][CNF发送端]接收后续数据
#define CNFClientWriteData         6026     //[UDP端口号][传输层][CNF发送端]通知将数据写入缓冲
#define CNFClientFileClose         6027     //[UDP端口号][传输层][CNF发送端]文件写入结束
#define CNFClientStartOrder1       6028     //[UDP端口号][传输层][CNF发送端]启动顺序1
#define CNFClientStartOrder2       6029     //[UDP端口号][传输层][CNF发送端]启动顺序2
#define CNFClientStartOrder3       6030     //[UDP端口号][传输层][CNF发送端]启动顺序3
#define CNFClientStartOrder4       6031     //[UDP端口号][传输层][CNF发送端]启动顺序4

#define CNFServerWindowBegin       6041     //[UDP端口号][传输层][CNF接收端]窗口传输开始
#define CNFServerWindowTimingEnd   6042     //[UDP端口号][传输层][CNF接收端]窗口传输上行通道结束计时
#define CNFServerWindowRespond     6043     //[UDP端口号][传输层][CNF接收端]窗口传输下行通道反馈结果
#define CNFServerBufReady          6044     //[UDP端口号][传输层][CNF接收端]发送缓冲启动
#define CNFServerMoreData          6045     //[UDP端口号][传输层][CNF接收端]供应后续数据
#define CNFServerFileClose         6046     //[UDP端口号][传输层][CNF接收端]文件读取结束
#define CNFServerContinueRECV      6047     //[UDP端口号][传输层][CNF接收端]继续收包

#define CNFPORTRANGE               50       //以上内部回环通信段口号跨度

//软件状态，即是否需要输出各阶段运行的数据，输出多少：
//开发阶段 == 0
//测试阶段 == 1
//残包阶段 == 2
//微调阶段 == 3
//二次开发阶段 == 4
//部署阶段 == 5
//CNF测试 == 6
//CNF输出参数 == 7
#define cnfDEVETESTIMPL DEVETESTIMPL
//是否输出AIMD机制的每一步触发提示
#define CNFTRIGGERTEST 0

//CNF允许的并发处理实例数
#define THREADNUM 10
//CNF当前试验实例编号
#define TESTNO 9

//带缓存的DATA包缓冲队列
typedef struct _DataPkg DataPkg;
struct _DataPkg
{
	int flag_occupied;
	int pkglength;
	int CNFthreadnum;
	uint8_t physicalport[30];
	uint8_t local_ip[16];
	uint8_t sid[SIDLEN];
	uint8_t offset[OFFLEN];
	uint8_t sbd[SBDLEN];
	uint8_t datapkg[MTU];
}datapkglist[10];

//缓存cache的单元大小
#define CACHESIZE 1000000
#define CACHENUM 10
#define TESTCACHENO 0

//收发缓存列表
typedef struct _CacheUnit CacheUnit;
struct _CacheUnit//尚未在转发平面支持初始化
{
	int flag_occupied;
	int flag_ack;
	int datapkglocation;
	unsigned long cachetop;
	uint8_t physicalport[30];
	uint8_t sid[SIDLEN];
	uint8_t sbd[SBDLEN];
	uint8_t offset[OFFLEN];
	uint8_t cache[CACHESIZE];
};
CacheUnit CacheList[CACHENUM];
int flag_CacheListTop;

//CNF任务序号
typedef struct _CNFThreadEvent CNFThreadEvent;
struct _CNFThreadEvent//尚未在转发平面支持初始化
{
	sem_t StartParaTransEnd;
	int flag_occupied;
	int flag_IO;
	int flag_close;
	int datapkglocation;
	int cachelocation;
	unsigned long cachelength;
	uint8_t physicalport[30];
	uint8_t physicalportIP[16];
	uint8_t sid[SIDLEN];
	uint8_t sbd[SBDLEN];
	uint8_t offset[OFFLEN];
};
CNFThreadEvent CNFThreadList[10];

//CNF客户端主线程启动传参
struct cnfcliinput
{
	int threadnum;
	int cachelocation;
	unsigned long cachelength;
	uint8_t physicalportIP[16];
	uint8_t sid[SIDLEN];
	uint8_t sbd[SBDLEN];
	uint8_t offset[OFFLEN];
};

//CNF服务端主线程启动传参
struct cnfserinput
{
	int threadnum;
	int cachelocation;
	unsigned long cachelength;
	uint8_t physicalportIP[16];
	uint8_t sid[SIDLEN];
	uint8_t sbd[SBDLEN];
	uint8_t offset[OFFLEN];
};

#endif
