/*******************************************************************************************************************************************
* 文件名：basic.h
* 文件描述：973智慧协同网络SAR系统TestBed套件——整个程序通用变量
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

#ifndef _BASIC_
#define _BASIC_

//软件状态，即是否需要输出各阶段运行的数据，输出多少：
//开发阶段 == 0
//测试阶段 == 1
//残包阶段 == 2
//微调阶段 == 3
//二次开发阶段 == 4
//部署阶段 == 5
//CNF测试 == 6
//CNF输出参数 == 7
#define DEVETESTIMPL 8

//是否为跨实体机测试：
//本地总线型测试          == 0
//基于mininet仿真网络平台 == 1
//物理实体机一对一部署    == 2
#define GLOBALTEST 2

//使用的协议栈种类
//MAC-CoLoR        == 0
//MAC-IP-UDP-CoLoR == 1
#define PROTOCOL 0

//内部转发通信使用机制
//内部回环UDP      == 0
//信号量           == 1
#define INTRACOMMUNICATION 0
#define cnfINTRACOMMUNICATION 0

//是否测试运行时间
//不测试   0
//框架测试 1
//完整测试 2
#define SEETIME 0

//运行CNF或TCP实验 0/1
//#define CNFTCP 0

//通用

//在实体物理机中，有些系统无法正常执行physicalport中获取MAC的代码，导致源MAC地址为0，影响收发判断，
//故在实际操作中，在此写死每台机器的源MAC（因使用的都是点到点链路，故一台机器统一一个源MAC即可）
#define PPSMAC "000000"

#define LOGFilePath "/root/sar/log.m"//运行日志文件

#define LOOPIP                "127.0.0.1"   //[IP地址][内部回环IP地址]整个网络层以上系统通用
#define PhysicalportInterPORT 6000          //物理网口与网络层之间的UDP通信端口（端口号相同，IP地址不同）

//接收缓冲区（即接收原始数据）大小
//#define BUFSIZE     1500 * 10
#define BUFSIZE     1500
#define PKGSIZE     1500

#define SLEEP                1     //计时器基本计时单位
#define ProgramWaitingPeriod 0  //其它线程运行等待时间，单位微秒
//CNF/TCP通用
#define RTOS                 0           //往返容忍时延（RTO大于1秒部分，单位秒）
#define RTOUS                50000       //往返容忍时延（RTO小于1秒部分，单位微秒）原50000
#define RTONS                50000000    //往返容忍时延（RTO小于1秒部分，单位纳秒）原50000000

#define MAXWndLen            500    //最大窗口长度
#define FlowSlot             0      //数据流包最小发送间隔（单位微秒）缩小到7000开始出现超时重传

#define PKTDATALEN           DATALEN //CNF/TCP/STR单包数据段长度

uint8_t Trigger[20];                 //CNF/TCP用接收线程间触发信令的承载BUF

int SockAddrLength;                  //通用socket_in结构体长度

struct timeval utime;
struct timeval Startutime;
struct timeval Endutime;
struct timeval Usedutime;
time_t GMT;                          //国际标准时间，实例化time_t结构(typedef long time_t;)
struct tm *UTC;                      //北京时区时间，实例化tm结构指针(tm记录年月日星期时分秒的int型表示)

time_t StartTime;                    //传输开始时间
time_t EndTime;                      //传输结束时间
time_t UsedTime;                     //以上二者差值，即传输总耗时

//遗留未解决
uint8_t SID[SIDLEN];                 //已知用于主函数接收HTTP请求与其调用函数之间的数值传递
uint8_t sendnid[NIDLEN];

//内部通信用信号量
sem_t semPacketRECV;
sem_t semPacketSEND[48];
sem_t semNTOS;

//网络层包转发缓冲队列
typedef struct _PkgCacheUnit PkgCacheUnit;
struct _PkgCacheUnit
{
	int flag_occupied;
	int pkglength;
	int destppnum;
	uint8_t sourcepp[30];
	uint8_t pkg[MTU];
}PkgBUF[10];
int PkgBUFHead;
int PkgBUFTail;
pthread_mutex_t lockPkgBUF; //初始化静态互斥锁

#endif
