/*******************************************************************************************************************************************
* 文件名：client.c
* 文件描述：973智慧协同网络SAR系统TestBed套件——最简化通用客户端程序，下端连接数据请求端（Data Subscriber）
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
gcc browser.c -o browser -lpthread
4、运行（因涉及原始套接字的使用，须root权限）
sudo ./browser
*/

#include"client.h"

/*******************************************************************************************************************************************
*************************************宏定义配置数据************全局变量定义******************************************************************
*******************************************************************************************************************************************/

/*******************************************************************************************************************************************
*******************************************初始化参数配置相关********************************************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：Client_Parameterinit
* 功能描述：Client模块全局变量赋初值
* 参数列表：
* 返回结果：
*****************************************/
void
Client_Parameterinit()
{
}

/*******************************************************************************************************************************************
*******************************************应用层Client服务器（通过CLI控制）******************************************************************
*******************************************************************************************************************************************/

/*******************************************************************************************************************************************
*******************************************上行通道 - From.数据请求端   To.应用服务器*********************************************************
*******************************************************************************************************************************************/

/*******************************************************************************************************************************************
*******************************************下行通道 - From.应用服务器 To.数据请求端***********************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：Client_StringTransport
* 功能描述：
* 参数列表：
* 返回结果：
*****************************************/
void
Client_StringTransport
(
)
{
	int i=0;
	char SID[SIDLEN];
	memset(SID,0,SIDLEN);
	char DATA[DATALEN];
	memset(DATA,0,DATALEN);

	printf("[SID ]  ");
	scanf("%s",SID);
	//scanf("%c",SID);
	//strcpy(SID,"wangzhaoxu");
	//printf("%s\n",SID);

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
	bzero(&addrTo,sizeof(addrTo));
	addrTo.sin_family=AF_INET;
	addrTo.sin_port=htons(APPLtoTRAL);
	//unsigned long IPto = 2130706433;//回环地址名称 == 2130706433
	//addrTo.sin_addr.s_addr=htonl(IPto);//htonl将主机字节序转换为网络字节序
	addrTo.sin_addr.s_addr=inet_addr(LOOPIP);//htonl将主机字节序转换为网络字节序

	//发送传输层Get包
	uint8_t sendpkg[sizeof(Trans_get)];
	Trans_get * psendpkg;
	psendpkg = (Trans_get *)sendpkg;

	memset(sendpkg,0,sizeof(Trans_get));
	
	strcpy(psendpkg->sid,SID);
	
	sendto(socket_sidsender,sendpkg,sizeof(Trans_get),0,(struct sockaddr *)&addrTo,sizeof(addrTo));
	close(socket_sidsender);

	gettimeofday(&utime,NULL);
	printf("===============Time===============\nGET  SENT %ld us\n==================================\n",1000000 * utime.tv_sec + utime.tv_usec);
	Startutime.tv_usec = utime.tv_usec;

	if(DEVETESTIMPL <= 1)
		printf("   The Client asked for Data whitch match the SID: %s\n",SID);

	//接收传输层Data包
	int socket_datareceiver;
	socket_datareceiver = socket(AF_INET,SOCK_DGRAM,0);

	struct sockaddr_in sin;
	int sockaddr_len=sizeof(struct sockaddr_in);
	bzero(&sin,sockaddr_len);
	sin.sin_family=AF_INET;
	//sin.sin_addr.s_addr=htonl(INADDR_ANY);
	sin.sin_addr.s_addr=inet_addr(LOOPIP);
	sin.sin_port=htons(TRALtoAPPL);

	bind(socket_datareceiver,(struct sockaddr *)&sin,sockaddr_len);
		
	int flag_sidgot = 0;
	int counter_sidget = 0;

	if(DEVETESTIMPL <= 1)
		printf("Client responce listening start...\n");
	
	uint8_t recvpkg[sizeof(Trans_data)];
	Trans_data * precvpkg;
	precvpkg = (Trans_data *)recvpkg;

	memset(recvpkg,0,sizeof(Trans_data));

	recvfrom(socket_datareceiver,recvpkg,sizeof(Trans_data),0,(struct sockaddr *)&sin,&sockaddr_len);
	close(socket_datareceiver);

	gettimeofday(&utime,NULL);
	printf("===============Time===============\nDATA RECV %ld us\n==================================\n",1000000 * utime.tv_sec + utime.tv_usec);
	Endutime.tv_usec = utime.tv_usec;
	if(Endutime.tv_usec > Startutime.tv_usec)
		Usedutime.tv_usec = Endutime.tv_usec - Startutime.tv_usec;
	else
		Usedutime.tv_usec =-(Endutime.tv_usec - Startutime.tv_usec);
	printf("Total Time: %ld us\n",Usedutime.tv_usec);
	
	if(DEVETESTIMPL <= 1)
		printf("Client responce listener received a new UDP pkg.\n");
	
	memcpy(DATA,precvpkg->data,DATALEN);
	printf("[DATA]  %s\n",DATA);

	//printf("Data \"%s\" has been received and it will be sent to the HTTP Client immediately./n",str);
	/*
	sleep(1);
	counter_sidget++;
	if(counter_sidget >= MAX_GETSIDTIME)//如果提取SID对应资源的请求超过MAX_GETSIDTIME的预设时间没有回复，则认为请求失败
	{
		break;
	}
	*/
		
	/*
	输入接口：直接将取回的文件存入DEFAULTDIR（见代码开头宏定义）所指向的根目录，并由下面的代码调取文件
	输入来源：CoLoR协议取回的文件
	可拓展性：基于文件提取和下载的机制实际上完成了缓存的基础功能，未来还可以在程序中添加缓存索引列表和老化机制
	*/
}

/*******************************************************************************************************************************************
**********************************************************多线程主干程序********************************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：Client_thread_timer
* 功能描述：为各线程提供计时信号
* 参数列表：
* 返回结果：
*****************************************/
void *
Client_thread_timer
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
* 函数名称：Client_thread_NetworkLayertoTransportLayer
* 功能描述：上行通道 - From.数据请求端   To.应用服务器
* 参数列表：
* 返回结果：
*****************************************/
void *
Client_thread_NetworkLayertoTransportLayer
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
* 函数名称：Client_thread_TransportLayertoNetworkLayer
* 功能描述：下行通道 - From.应用服务器 To.数据请求端
* 参数列表：
* 返回结果：
*****************************************/
void *
Client_thread_TransportLayertoNetworkLayer
(
	void * fd
)
{
	sleep(1);
	unsigned long count=1;
	while(1)
	{
		printf("COUNT == %ld\n",count++);
		Client_StringTransport();
	}

	//关闭线程
	exit(0);
	free(fd);
	pthread_exit(NULL);
}

/*****************************************
* 函数名称：Client_main
* 功能描述：Client模块主函数，启动ForwardingPlane转发平面线程。自身主循环执行简单HTTP服务器功能。
* 参数列表：
eg: ./sub d1sub1 d1sub1-eth1
第二参数使用char**argv的方式声明报错，不知是不是语法问题
* 返回结果：
*****************************************/
int
Client_main
(
	int argc,
	char argv[][30]
)
{
	int i,j;

	//创建发送计时器子线程
	pthread_t pthread_timer;
	if(pthread_create(&pthread_timer, NULL, Client_thread_timer, NULL)!=0)
	{
		perror("Creation of timer thread failed.");
	}
	
	//创建thread_NetworkLayertoTransportLayer上行子线程
	pthread_t pthread_NetworkLayertoTransportLayer;
	if(pthread_create(&pthread_NetworkLayertoTransportLayer, NULL, Client_thread_NetworkLayertoTransportLayer, NULL)!=0)
	{
		perror("Creation of NetworkLayertoTransportLayer thread failed.");
	}
	
	//创建thread_TransportLayertoNetworkLayer下行子线程
	pthread_t pthread_TransportLayertoNetworkLayer;
	if(pthread_create(&pthread_TransportLayertoNetworkLayer, NULL, Client_thread_TransportLayertoNetworkLayer, NULL)!=0)
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
