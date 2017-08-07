/*******************************************************************************************************************************************
* 文件名：stringclient.c
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
gcc stringclient.c -o stringclient -lpthread
4、运行（因涉及原始套接字的使用，须root权限）
sudo ./stringclient
*/

#include"stringclient.h"

/*******************************************************************************************************************************************
*************************************宏定义配置数据************全局变量定义******************************************************************
*******************************************************************************************************************************************/

/*******************************************************************************************************************************************
*******************************************初始化参数配置相关********************************************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：StringClient_Parameterinit
* 功能描述：StringClient模块全局变量赋初值
* 参数列表：
* 返回结果：
*****************************************/
void
StringClient_Parameterinit()
{
	flag = 0;
}

/*******************************************************************************************************************************************
*******************************************应用层StringClient服务器（通过CLI控制）******************************************************************
*******************************************************************************************************************************************/

/*******************************************************************************************************************************************
*******************************************上行通道 - From.数据请求端   To.应用服务器*********************************************************
*******************************************************************************************************************************************/

/*******************************************************************************************************************************************
*******************************************下行通道 - From.应用服务器 To.数据请求端***********************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：StringClient_StringTransport
* 功能描述：
* 参数列表：
* 返回结果：
*****************************************/
void
StringClient_StringTransport
(
struct timeval * tv,
fd_set * readfds
)
{
	flag = 0;
	
	//读取GMT
	static time_t GMT;                     //国际标准时间，实例化time_t结构(typedef long time_t;)
	time(&GMT);

	//设置超时
	static struct timespec delaytime;
	delaytime.tv_sec = GMT + 2;
	delaytime.tv_nsec = 0;

	//定时阻塞等待信号量变化
	int judge = 0;
	judge = sem_timedwait(&trigger,&delaytime);

	//显示结果
	if(judge > -1)
	{
		printf("Triggered!\n");
	}
	else if(judge == -1)
	{
		printf("Time Out!\n");
	}
}

/*******************************************************************************************************************************************
**********************************************************多线程主干程序********************************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：StringClient_thread_flag
* 功能描述：为各线程提供计时信号

* 参数列表：
* 返回结果：
*****************************************/
void *
StringClient_thread_flag
(
	void * fd
)
{
	while(1)
	{
		getchar();
		sem_post(&trigger);
	}
	//关闭线程
	exit(0);
	free(fd);
	pthread_exit(NULL);
}

/*****************************************
* 函数名称：StringClient_thread_timer
* 功能描述：为各线程提供计时信号
* 参数列表：
* 返回结果：
*****************************************/
void *
StringClient_thread_timer
(
	void * fd
)
{
	int timer_XX = 0;
	
	while(1)
	{
		sleep(10000);
		sleep(SLEEP);
		
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
* 函数名称：StringClient_thread_NetworkLayertoTransportLayer
* 功能描述：上行通道 - From.数据请求端   To.应用服务器
* 参数列表：
* 返回结果：
*****************************************/
void *
StringClient_thread_NetworkLayertoTransportLayer
(
	void * fd
)
{
	while(1)
	{
		sleep(10000);
	}
	
	//关闭线程
	exit(0);
	free(fd);
	pthread_exit(NULL);
}

/*****************************************
* 函数名称：StringClient_thread_TransportLayertoNetworkLayer
* 功能描述：下行通道 - From.应用服务器 To.数据请求端
* 参数列表：
* 返回结果：
*****************************************/
void *
StringClient_thread_TransportLayertoNetworkLayer
(
	void * fd
)
{
	struct timeval tv;
	fd_set readfds;
	while(1)
	{
		StringClient_StringTransport(&tv,&readfds);
	}

	//关闭线程
	exit(0);
	free(fd);
	pthread_exit(NULL);
}

/*****************************************
* 函数名称：StringClient_main
* 功能描述：StringClient模块主函数，启动ForwardingPlane转发平面线程。自身主循环执行简单HTTP服务器功能。
* 参数列表：
eg: ./sub d1sub1 d1sub1-eth1
第二参数使用char**argv的方式声明报错，不知是不是语法问题
* 返回结果：
*****************************************/
int
StringClient_main
(
	int argc,
	char argv[][30]
)
{
	StringClient_Parameterinit();
	
	int i,j;

	//创建发送计时器子线程
	pthread_t pthread_timer;
	if(pthread_create(&pthread_timer, NULL, StringClient_thread_timer, NULL)!=0)
	{
		perror("Creation of timer thread failed.");
	}

	//创建flag输入子线程
	pthread_t pthread_flag;
	if(pthread_create(&pthread_flag, NULL, StringClient_thread_flag, NULL)!=0)
	{
		perror("Creation of flag thread failed.");
	}
	
	//创建thread_NetworkLayertoTransportLayer上行子线程
	pthread_t pthread_NetworkLayertoTransportLayer;
	if(pthread_create(&pthread_NetworkLayertoTransportLayer, NULL, StringClient_thread_NetworkLayertoTransportLayer, NULL)!=0)
	{
		perror("Creation of NetworkLayertoTransportLayer thread failed.");
	}
	
	//创建thread_TransportLayertoNetworkLayer下行子线程
	pthread_t pthread_TransportLayertoNetworkLayer;
	if(pthread_create(&pthread_TransportLayertoNetworkLayer, NULL, StringClient_thread_TransportLayertoNetworkLayer, NULL)!=0)
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
