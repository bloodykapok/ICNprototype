/*******************************************************************************************************************************************
* 文件名：transportlayerdefine.h
* 文件描述：973智慧协同网络SAR系统TestBed套件——传输层统一调用文件
* 声明：本模板代码作者王兆旭，为北京交通大学下一代互联网互联设备国家工程实验室新生基础工程技术培训专用。作者王兆旭在此郑重声明，此文件及其它用于培训的模板代码均为本人精力与经验的产物，本资源的传播方式均为作者本人向他人进行一对一传授，任何个人不得向第三方转交或展示该资源内容。任何有需求的学员，均须向王兆旭本人直接索要，亦无向他人索要或传授之权利和义务。因有些资源内容涉及实验室项目秘密，暂不考虑申请专利保护或软件著作权等事宜，故个别资源仅限实验室内部一对一发放，如发现有辜负作者本人的一片好意的行为，作者将保留就其原创性进行追查、举证、申诉和问责的权利。本资源的发放权归作者本人所有，其整理和总结过程浸透无偿贡献的热忱和为诸君学业尽绵薄之力的真诚，愿学员尊重作者的劳动成果，谢谢合作！
* 作者：王兆旭
* 身份：北京交通大学下一代互联网互联设备国家工程实验室 2013级硕博连读研究生
* E-mail. hellozxwang@foxmail.com
* Mobile. 18811774990
* QQ    . 535667240
* Addr  . 北京市海淀区西直门外北京交通大学机械楼D706室, 100044
*******************************************************************************************************************************************/
/*******************************************************************************************************************************************
*****功能说明：1.传输层统一调用文件
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

#include"general.h"

#ifndef _TRANSLAYERDEFINE_
#define _TRANSLAYERDEFINE_

//TCP模式下的线程间通信端口配置

#define TCPClientTimingBegin       6021     //[UDP端口号][传输层][TCP客户端]计时开始
#define TCPClientTimingEnd         6022     //[UDP端口号][传输层][TCP客户端]计时结束
#define TCPClientTimingRespond     6023     //[UDP端口号][传输层][TCP客户端]反馈计时结果
#define TCPClientBufReady          6024     //[UDP端口号][传输层][TCP客户端]接收缓冲启动
#define TCPClientMoreData          6025     //[UDP端口号][传输层][TCP客户端]接收后续数据
#define TCPClientWriteData         6026     //[UDP端口号][传输层][TCP客户端]通知将数据写入缓冲
#define TCPClientFileClose         6027     //[UDP端口号][传输层][TCP客户端]文件写入结束
#define TCPClientStartOrder1       6028     //[UDP端口号][传输层][TCP客户端]启动顺序1
#define TCPClientStartOrder2       6029     //[UDP端口号][传输层][TCP客户端]启动顺序2
#define TCPClientStartOrder3       6030     //[UDP端口号][传输层][TCP客户端]启动顺序3
#define TCPClientStartOrder4       6031     //[UDP端口号][传输层][TCP客户端]启动顺序4

#define TCPServerWindowBegin       6041     //[UDP端口号][传输层][TCP服务端]窗口传输开始
#define TCPServerWindowTimingEnd   6042     //[UDP端口号][传输层][TCP服务端]窗口传输上行通道结束计时
#define TCPServerWindowRespond     6043     //[UDP端口号][传输层][TCP服务端]窗口传输下行通道反馈结果
#define TCPServerBufReady          6044     //[UDP端口号][传输层][TCP服务端]发送缓冲启动
#define TCPServerMoreData          6045     //[UDP端口号][传输层][TCP服务端]供应后续数据
#define TCPServerFileClose         6046     //[UDP端口号][传输层][TCP服务端]文件读取结束
#define TCPServerContinueRECV      6047     //[UDP端口号][传输层][TCP服务端]继续收包

#define TCPPORTRANGE               30       //以上内部回环通信段口号跨度

//软件状态，即是否需要输出各阶段运行的数据，输出多少：
//开发阶段 == 0
//测试阶段 == 1
//残包阶段 == 2
//微调阶段 == 3
//部署阶段 == 4
#define transDEVETESTIMPL DEVETESTIMPL


#define ThreadNumLimit   100        //可并发执行的TCP服务任务数量
#define TCPBUFSIZE       1000000    //TCP单任务发送缓冲大小（1MB）

#define FTPServerPath "./sendfile/London.flv" //读取文件线程（FTP前身）搜索文件的根目录
#define FTPClientPath "./recvfile/London.flv" //写入文件线程（FTP前身）写入文件的根目录
#define FILELEN 8819515

#endif

