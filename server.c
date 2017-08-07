/*******************************************************************************************************************************************
* 文件名：server.c
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
gcc server.c -o server -lpthread
4、运行（因涉及原始套接字的使用，须root权限）
sudo ./server
*/

#include"server.h"

/*******************************************************************************************************************************************
*************************************宏定义配置数据************全局变量定义******************************************************************
*******************************************************************************************************************************************/

/*******************************************************************************************************************************************
*******************************************初始化参数配置相关********************************************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：Server_Parameterinit
* 功能描述：Server模块全局变量赋初值
* 参数列表：
* 返回结果：
*****************************************/
void
Server_Parameterinit()
{
}

/*******************************************************************************************************************************************
*******************************************应用层Server服务器（通过CLI控制）******************************************************************
*******************************************************************************************************************************************/

/*******************************************************************************************************************************************
*******************************************上行通道 - From.数据响应端   To.应用服务器*********************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：Server_FindData
* 功能描述：查询SID对应的DATA
* 参数列表：
* 返回结果：
*****************************************/
int
Server_FindData
(
	uint8_t * SID,
	uint8_t * DATA
)
{
	int i,j;
	//查询SID缓存列表
	//文件读操作
	FILE *fp;
	
	char ch;
	char buf[SIDLEN/*sid长度*/ + DATALEN/*data长度*/ +1/*中间空格*/];
	int SIDlen=0,DATAlen=0;
	uint8_t tSID[SIDLEN+1];
	uint8_t tDATA[DATALEN+1];
	memset(tSID,0,SIDLEN+1);
	memset(tDATA,0,DATALEN+1);

	strcpy(tSID,SID);//printf("[search]tSID = %s\n",tSID);
	
	int flag_sidfound;
	int file_i;
	
	for(i=0;i<SIDLEN;i++)
	{
		if(tSID[i] == 0)
			break;
	}
	SIDlen = i;
	i=0;
	
	if((fp=fopen(FILEsidname,"r"))==NULL)
	{
		printf("cannot open file!\n");
		exit(0);
	}
	file_i = 0;
	flag_sidfound = 0;
	int runcount = 0;//temp
	while(1)
	{
		if(SIDlen == 0)//如果收到的SID为空
		{	
			if(DEVETESTIMPL <= 1)
				printf("   SID %s not found!(SIDlen == 0)\n",tSID);
			memcpy(tDATA, "xxxx", 4);
			break;
		}
		
		ch=fgetc(fp);
		if(ch==EOF)
		{
			buf[file_i] = 0;
			if(strncmp(buf,tSID,SIDlen) == 0)
			{
				if(buf[SIDlen] != ' ')
				{
					file_i = 0;
					buf[0] = 0;
					continue;
				}

				if(DEVETESTIMPL <= 1)
					printf("   SID %s found! ",tSID);

				for(i=SIDlen+1,j=0;;i++)
				{
					if(buf[i] != 0)
					{
						tDATA[j++] = buf[i];
					}
					else
					{
						tDATA[j] = 0;
						DATAlen = j;
						flag_sidfound = 1;
						break;
					}
				}

				if(DEVETESTIMPL <= 1)
					printf("Data is: %s\n",tDATA);

				break;
			}
			else
			{
				if(DEVETESTIMPL <= 1)
					printf("   SID %s not found!(No SID in the list)\n",tSID);

				memcpy(tDATA, "xxxx", 4);
				DATAlen = 4;
				break;
			}
		}
		else if(ch=='\n')
		{
			buf[file_i] = 0;//printf("[search]buf = %s\n",buf);
			if(strncmp(buf,tSID,SIDlen) == 0)
			{
				if(buf[SIDlen] != ' ')
				{
					file_i = 0;
					buf[0] = 0;
					continue;
				}
				
				if(DEVETESTIMPL <= 1)
					printf("   SID %s found! ",tSID);

				for(i=SIDlen+1,j=0;;i++)
				{
					if(buf[i] != 0)
					{
						tDATA[j++] = buf[i];
					}
					else
					{
						tDATA[j] = 0;
						DATAlen = j;
						flag_sidfound = 1;
						break;
					}
				}

				if(DEVETESTIMPL <= 1)
					printf("Data is: %s\n",tDATA);

				break;
			}
			else
			{
				file_i = 0;
				buf[0] = 0;
				continue;
			}
		}
		else
		{
			buf[file_i++]=ch;
		}
		
		if(flag_sidfound == 1)
			break;
	}

	strcpy(DATA,tDATA);

	fclose(fp);

	return DATAlen;
}

/*******************************************************************************************************************************************
*******************************************下行通道 - From.应用服务器 To.数据响应端***********************************************************
*******************************************************************************************************************************************/

/*******************************************************************************************************************************************
**********************************************************多线程主干程序********************************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：Server_thread_NetworkLayertoTransportLayer
* 功能描述：上行通道 - From.数据响应端   To.应用服务器
* 参数列表：
* 返回结果：
*****************************************/
void *
Server_thread_NetworkLayertoTransportLayer
(
	void * fd
)
{
	int i,j;

	//创建socket：接收传输层请求SID
	int socket_sidreceiver;
	socket_sidreceiver = socket(AF_INET,SOCK_DGRAM,0);

	struct sockaddr_in sin;
	int sockaddr_len=sizeof(struct sockaddr_in);
	bzero(&sin,sockaddr_len);
	sin.sin_family=AF_INET;
	//sin.sin_addr.s_addr=htonl(INADDR_ANY);//htonl将主机字节序转换为网络字节序
	sin.sin_addr.s_addr=inet_addr(LOOPIP);
	sin.sin_port=htons(NETLtoTRAL);

	bind(socket_sidreceiver,(struct sockaddr *)&sin,sockaddr_len);

	//创建socket：向传输层发送DATA
	int socket_datasender;
	socket_datasender = socket(AF_INET,SOCK_DGRAM,0);

	struct sockaddr_in addrTo;
	bzero(&addrTo,sizeof(addrTo));
	addrTo.sin_family=AF_INET;
	addrTo.sin_port=htons(TRALtoNETL);
	addrTo.sin_addr.s_addr=inet_addr(LOOPIP);

	uint8_t SID[SIDLEN];
	uint8_t DATA[DATALEN];
	int SIDlen,DATAlen;

	uint8_t recvpkg[sizeof(Trans_get)];
	Trans_get * precvpkg;
	precvpkg = (Trans_get *)recvpkg;
	uint8_t sendpkg[sizeof(CoLoR_data)];
	Trans_data * psendpkg;
	psendpkg = (Trans_data *)sendpkg;

	while(1)
	{
		i=0;
		j=0;
		SIDlen = 0;
		DATAlen = 0;

		memset(SID,0,SIDLEN);
		memset(DATA,0,DATALEN);
		memset(recvpkg,0,sizeof(Trans_get));
		memset(sendpkg,0,sizeof(CoLoR_data));
		
		//接收传输层包
		recvfrom(socket_sidreceiver,recvpkg,sizeof(Trans_get),0,(struct sockaddr *)&sin,&sockaddr_len);
		
	gettimeofday(&utime,NULL);
	printf("===============Time===============\nGET  RECV %ld us\n==================================\n",1000000 * utime.tv_sec + utime.tv_usec);

		//提取SID
		memcpy(SID,precvpkg->sid,SIDLEN);

		//查询SID对应的DATA
		printf("[SID ]  %s\n",SID);
		DATAlen = Server_FindData(SID,DATA);
		printf("[DATA]  %s\n",DATA);
		
		//封装DATA
		memcpy(psendpkg->sid,SID,SIDLEN);
		memcpy(psendpkg->data,DATA,DATALEN);

		//发送传输层包
		sendto(socket_datasender,sendpkg,sizeof(Trans_data),0,(struct sockaddr *)&addrTo,sizeof(addrTo));

	gettimeofday(&utime,NULL);
	printf("===============Time===============\nDATA SENT %ld us\n==================================\n",1000000 * utime.tv_sec + utime.tv_usec);
	}
	close(socket_sidreceiver);
	close(socket_datasender);

	//关闭线程
	exit(0);
	free(fd);
	pthread_exit(NULL);
}

/*****************************************
* 函数名称：Server_thread_TransportLayertoNetworkLayer
* 功能描述：下行通道 - From.应用服务器 To.数据响应端
* 参数列表：
* 返回结果：
*****************************************/
void *
Server_thread_TransportLayertoNetworkLayer
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
* 函数名称：Server_main
* 功能描述：Server模块主函数，启动各个线程，自身不提供实际功能
* 参数列表：第二参数使用char**argv的方式声明报错，不知是不是语法问题
* 返回结果：
*****************************************/
//int main(int argc, char *argv[])
int
Server_main
(
	int argc,
	char argv[][30]
)
{
	int i,j;
	
	//创建thread_NetworkLayertoTransportLayer上行子线程
	pthread_t pthread_NetworkLayertoTransportLayer;
	if(pthread_create(&pthread_NetworkLayertoTransportLayer, NULL, Server_thread_NetworkLayertoTransportLayer, NULL)!=0)
	{
		perror("Creation of NetworkLayertoTransportLayer thread failed.");
	}
	
	//创建thread_TransportLayertoNetworkLayer下行子线程
	pthread_t pthread_TransportLayertoNetworkLayer;
	if(pthread_create(&pthread_TransportLayertoNetworkLayer, NULL, Server_thread_TransportLayertoNetworkLayer, NULL)!=0)
	{
		perror("Creation of TransportLayertoNetworkLayer thread failed.");
	}

	//创建为Publisher模块输出的通信参数，并储存
	/*
	struct publisherinput
	{
		int argc;
		char argv[50][30];
	};
	*/
	struct publisherinput pubinput;
	pubinput.argc=0;
	memset(pubinput.argv,0,1500);

	pubinput.argc=argc;
	for(i=0;i<pubinput.argc;i++)
	{
		strcpy(pubinput.argv[i],argv[i]);
	}

	pthread_t pthread_publisher;

	//创建Publisher子线程
	if(pthread_create(&pthread_publisher, NULL, Publisher_main, (void *)&pubinput)!=0)
	{
		perror("Creation of publisher thread failed.");
	}

	//Publisher_main(argc,(char (*)[30])argv);

	//主循环——客户端代码
	while (1)
	{
		sleep(10000);
	}
}
