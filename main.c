/*******************************************************************************************************************************************
* 文件名：main.c
* 文件描述：973智慧协同网络SAR系统TestBed套件——主函数
* 声明：本模板代码作者王兆旭，为北京交通大学下一代互联网互联设备国家工程实验室新生基础工程技术培训专用。作者王兆旭在此郑重声明，此文件及其它用于培训的模板代码均为本人精力与经验的产物，本资源的传播方式均为作者本人向他人进行一对一传授，任何个人不得向第三方转交或展示该资源内容。任何有需求的学员，均须向王兆旭本人直接索要，亦无向他人索要或传授之权利和义务。因有些资源内容涉及实验室项目秘密，暂不考虑申请专利保护或软件著作权等事宜，故个别资源仅限实验室内部一对一发放，如发现有辜负作者本人的一片好意的行为，作者将保留就其原创性进行追查、举证、申诉和问责的权利。本资源的发放权归作者本人所有，其整理和总结过程浸透无偿贡献的热忱和为诸君学业尽绵薄之力的真诚，愿学员尊重作者的劳动成果，谢谢合作！
* 作者：王兆旭
* 身份：北京交通大学下一代互联网互联设备国家工程实验室 2013级硕博连读研究生
* E-mail. hellozxwang@foxmail.com
* Mobile. 18811774990
* QQ    . 535667240
* Addr  . 北京市海淀区西直门外北京交通大学机械楼D706室, 100044
*******************************************************************************************************************************************/
/*******************************************************************************************************************************************
*****功能说明：1.启动起点**********************************************************************************************************
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

#include"cacherouter.h"
#include"borderrouter.h"
#include"resourcemanager.h"
//#include"subscriber.h"
//#include"publisher.h"
#include"client.h"
#include"server.h"
#include"stringclient.h"
#include"stringserver.h"
#include"tcpclient.h"
#include"tcpserver.h"
#include"cnfclient.h"
#include"cnfserver.h"

#include"browserclient.h"

///////////////////////////////////////////////////////////////BUG备忘////////////////////////////////////////////////////////////////
/*
1、同一个客户端计算机不能同时运行两个及以上客户端类程序，包括最简纯客户端、浏览器、文件传输器，否则会造成DATA劫持
可能原因：同源的客户端程序使用的UDP端口相同，造成监听端口冲突
*/

/*****************************************
* 函数名称：pc_main
* 功能描述：实体物理机模式下的主函数
* 参数列表：eg: ./sar cr d1cr1 d1cr1-eth1 d1cr1-eth2 d1cr1-eth3
* 返回结果：
*****************************************/
void
pc_main
(
	int argc,
	char * argv[]
)
{
	int i,ii;

	if(DEVETESTIMPL <= 0)
	{
		printf("argc == %d\n",argc);
		for(i=0;i<argc;i++)
			printf("argv[%d] == %s\n",i,argv[i]);
	}

	int argcx;
	char argvx[50][30];

	argcx=0;
	memset(argvx,0,1500);

	argcx=argc-1;
	strcpy(argvx[0],"./");
	strcpy(argvx[0]+2,argv[1]);

	i=0;
	ii=0;

	for(i=1;i<argcx;i++)
	{
		strcpy(argvx[i],argv[i+1]);
	}
	//至此，输入参数变为了: ./cr d1cr1 d1cr1-eth1 d1cr1-eth2 d1cr1-eth3
	if(DEVETESTIMPL <= 0)
	{
		printf("argcx == %d\n",argcx);
		for(i=0;i<argcx;i++)
			printf("argvx[%d] == %s\n",i,argvx[i]);
	}

	//判定并启动节点角色模块
	int re;

	if(strncmp(argv[1],"hahaha",6)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("SB\n");
	}
	else if(strncmp(argv[1],"cnfcli",6)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("CNF Client Starting...\n");
		re = CNFClientStart_main(argcx,(char (*)[30])argvx);
	}
	else if(strncmp(argv[1],"cnfser",6)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("CNF Server Starting...\n");
		re = CNFServerStart_main(argcx,(char (*)[30])argvx);
	}
	else if(strncmp(argv[1],"tcpcli",6)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("TCP Client Starting...\n");
		re = TCPClient_main(argcx,(char (*)[30])argvx);
	}
	else if(strncmp(argv[1],"tcpser",6)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("TCP Server Starting...\n");
		re = TCPServer_main(argcx,(char (*)[30])argvx);
	}
	else if(strncmp(argv[1],"strcli",6)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("String Client Starting...\n");
		re = StringClient_main(argcx,(char (*)[30])argvx);
	}
	else if(strncmp(argv[1],"strser",6)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("String Server Starting...\n");
		re = StringServer_main(argcx,(char (*)[30])argvx);
	}
	else if(strncmp(argv[1],"http",4)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("HTTP client Starting...\n");
		re = BrowserClient_main(argcx,(char (*)[30])argvx);
	}
	else if(strncmp(argv[1],"cli",3)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("Client Starting...\n");
		re = Client_main(argcx,(char (*)[30])argvx);
	}
	else if(strncmp(argv[1],"ser",3)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("Server Starting...\n");
		re = Server_main(argcx,(char (*)[30])argvx);
	}
	else if(strncmp(argv[1],"sub",3)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("Content Subscriber Starting...\n");
		//re = Subscriber_main(argcx,(char (*)[30])argvx);
	}
	else if(strncmp(argv[1],"pub",3)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("Content Publisher Starting...\n");
		//re = Publisher_main(argcx,(char (*)[30])argvx);
	}
	else if(strncmp(argv[1],"cr",2)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("Cache Router Starting...\n");
		re = CacheRouter_main(argcx,(char (*)[30])argvx);
	}
	else if(strncmp(argv[1],"br",2)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("Border Router Starting...\n");
		re = BorderRouter_main(argcx,(char (*)[30])argvx);
	}
	else if(strncmp(argv[1],"rm",2)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("Resource Manager Starting...\n");
		re = ResourceManager_main(argcx,(char (*)[30])argvx);
	}
	else
	{
		if(DEVETESTIMPL <= 1)
			printf("Unknown device name!\n");
	}
}

/*****************************************
* 函数名称：pc_main
* 功能描述：mininet仿真平台模式下的主函数
* 参数列表：eg: ./sar cr d1cr1 1 2 3
* 返回结果：
*****************************************/
void
mininet_main
(
	int argc,
	char * argv[]
)
{
	int i,ii;

	if(DEVETESTIMPL <= 0)
	{
		printf("argc == %d\n",argc);
		for(i=0;i<argc;i++)
			printf("argv[%d] == %s\n",i,argv[i]);
	}

	int argcx;
	char argvx[50][30];

	argcx=0;
	memset(argvx,0,1500);

	argcx=argc-1;
	strcpy(argvx[0],"./");
	strcpy(argvx[0]+2,argv[1]);
	strcpy(argvx[1],argv[2]);

	i=0;
	ii=0;

	for(i=2;i<argcx;i++)
	{
		strcpy(argvx[i],argvx[1]);
		for(ii=0;ii<30;ii++)
		{
			if(argvx[i][ii]==0)
			{
				strcpy(argvx[i]+ii,"-eth");
				strcpy(argvx[i]+ii+4,argv[i+1]);
				break;
			}
		}
	}
	//至此，输入参数变为了: ./cr d1cr1 d1cr1-eth1 d1cr1-eth2 d1cr1-eth3
	if(DEVETESTIMPL <= 0)
	{
		printf("argcx == %d\n",argcx);
		for(i=0;i<argcx;i++)
			printf("argvx[%d] == %s\n",i,argvx[i]);
	}

	//判定并启动节点角色模块
	int re;
	
	if(strncmp(argv[1],"hahaha",6)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("SB\n");
	}
	else if(strncmp(argv[1],"cnfcli",6)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("CNF Client Starting...\n");
		re = CNFClientStart_main(argcx,(char (*)[30])argvx);
	}
	else if(strncmp(argv[1],"cnfser",6)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("CNF Server Starting...\n");
		re = CNFServerStart_main(argcx,(char (*)[30])argvx);
	}
	else if(strncmp(argv[1],"tcpcli",6)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("TCP Client Starting...\n");
		re = TCPClient_main(argcx,(char (*)[30])argvx);
	}
	else if(strncmp(argv[1],"tcpser",6)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("TCP Server Starting...\n");
		re = TCPServer_main(argcx,(char (*)[30])argvx);
	}
	else if(strncmp(argv[1],"strcli",6)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("String Client Starting...\n");
		re = StringClient_main(argcx,(char (*)[30])argvx);
	}
	else if(strncmp(argv[1],"strser",6)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("String Server Starting...\n");
		re = StringServer_main(argcx,(char (*)[30])argvx);
	}
	else if(strncmp(argv[1],"http",4)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("HTTP client Starting...\n");
		re = BrowserClient_main(argcx,(char (*)[30])argvx);
	}
	else if(strncmp(argv[1],"cli",3)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("Client Starting...\n");
		re = Client_main(argcx,(char (*)[30])argvx);
	}
	else if(strncmp(argv[1],"ser",3)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("Server Starting...\n");
		re = Server_main(argcx,(char (*)[30])argvx);
	}
	else if(strncmp(argv[1],"sub",3)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("Content Subscriber Starting...\n");
		//re = Subscriber_main(argcx,(char (*)[30])argvx);
	}
	else if(strncmp(argv[1],"pub",3)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("Content Publisher Starting...\n");
		//re = Publisher_main(argcx,(char (*)[30])argvx);
	}
	else if(strncmp(argv[1],"cr",2)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("Cache Router Starting...\n");
		re = CacheRouter_main(argcx,(char (*)[30])argvx);
	}
	else if(strncmp(argv[1],"br",2)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("Border Router Starting...\n");
		re = BorderRouter_main(argcx,(char (*)[30])argvx);
	}
	else if(strncmp(argv[1],"rm",2)==0)
	{
		if(DEVETESTIMPL <= 1)
			printf("Resource Manager Starting...\n");
		re = ResourceManager_main(argcx,(char (*)[30])argvx);
	}
	else
	{
		if(DEVETESTIMPL <= 1)
			printf("Unknown device name!\n");
	}
}

/*****************************************
* 函数名称：main
* 功能描述：主函数
* 参数列表：eg: ./sar cr d1cr1 1 2 3
* 返回结果：
*****************************************/
void
main
(
	int argc,
	char * argv[]
)
{
	switch(GLOBALTEST)
	{
		case 0:
			if(DEVETESTIMPL <= 1)
				printf("[main]Do not support the bus network anymore.\n");
			break;
		case 1:
			if(DEVETESTIMPL <= 1)
				printf("[main]Network run on mininet emulator platform.\n");
			mininet_main(argc,(char **)argv);
			break;
		case 2:
			if(DEVETESTIMPL <= 1)
				printf("[main]Network run on real individual physical devices.\n");
			pc_main(argc,(char **)argv);
			break;
		default:
			if(DEVETESTIMPL <= 1)
				printf("[main]GLOBALTEST Configure error.\n");
			break;
	}
}




















//
