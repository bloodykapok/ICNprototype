/*******************************************************************************************************************************************
* 文件名：physicalport.c
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

#include"physicalport.h"

//Ethernet用于类型判断的字段（截止到固定首部，其中Version/Type字段为IP包、CoLoR包所通用）
Ether_VersionType tempEtherVersionType;

//CoLoR协议用于类型判断的字段（截止到固定首部，其中Version/Type字段为Get包、Data包、Register包所通用）
Ether_CoLoR_VersionType tempCoLoRVersionType;

//CoLoR协议用于类型判断的字段（截止到固定首部，其中Version/Type字段为Get包、Data包、Register包所通用）
CoLoR_VersionType tempCoLoRwithoutMAC;

//CoLoR协议Get包首部（PID之前）字段长度固定，用于封装
//暂未用到

//CoLoR协议Get包首部（PID之前）字段长度可变，用于解析
Ether_CoLoR_get_parse tempGet;

//CoLoR协议Data包首部（PID之前）字段长度固定，用于封装
//暂未用到

//CoLoR协议Data包首部（PID之前）字段长度可变，用于解析
Ether_CoLoR_data_parse tempData;

//CoLoR协议Register包首部（PID之前）
CoLoR_register_parse tempRegister;

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
PhysicalPort_Parameterinit()
{
	int i;
	for(i=0;i<48;i++)
		selfpacketdonotcatch[i] = 0;

	//初始化带缓存的DATA包缓冲队列
	for(i=0;i<10;i++)
	{
		datapkglist[i].flag_occupied = 0;
		datapkglist[i].pkglength = 0;
		datapkglist[i].CNFthreadnum = -1;
		memset(datapkglist[i].physicalport,0,30);
		memset(datapkglist[i].local_ip,0,16);
		memset(datapkglist[i].sid,0,SIDLEN);
		memset(datapkglist[i].offset,0,OFFLEN);
		memset(datapkglist[i].sbd,0,SBDLEN);
		memset(datapkglist[i].datapkg,0,MTU);
	}
	//初始化收发缓存列表
	for(i=0;i<10;i++)
	{
		CacheList[i].flag_occupied = 0;
		CacheList[i].flag_ack = 0;
		CacheList[i].datapkglocation = -1;
		CacheList[i].cachetop = 0;
		memset(CacheList[i].physicalport,0,30);
		memset(CacheList[i].sid,0,SIDLEN);
		memset(CacheList[i].sbd,0,SBDLEN);
		memset(CacheList[i].offset,0,OFFLEN);
		memset(CacheList[i].cache,0,CACHESIZE);
	}
	//初始化CNF任务序号
	for(i=0;i<10;i++)
	{
		CNFThreadList[i].flag_occupied = 0;
		CNFThreadList[i].flag_IO = -1;
		CNFThreadList[i].flag_close = 0;
		CNFThreadList[i].datapkglocation = -1;
		CNFThreadList[i].cachelocation = -1;
		CNFThreadList[i].cachelength = -1;
		memset(CNFThreadList[i].physicalport,0,30);
		memset(CNFThreadList[i].physicalportIP,0,16);
		memset(CNFThreadList[i].sid,0,SIDLEN);
		memset(CNFThreadList[i].sbd,0,SBDLEN);
		memset(CNFThreadList[i].offset,0,OFFLEN);

	}

	if(CacheList[0].flag_occupied == 0)//第一缓存块未被占用，说明该转发节点为传输的始发节点（如果不是始发，则在上一跳接收中，第一缓存块一定会被占用，故未被占用是不可能出现的情形）
	{
		CacheList[0].flag_occupied = 1;
		CacheList[0].flag_ack = 0;
		CacheList[0].datapkglocation = 0;
		CacheList[0].cachetop = CACHESIZE;
		memcpy(CacheList[0].physicalport,"d1pub1-eth0",30);
		memcpy(CacheList[0].sid,"wangzhaoxu",SIDLEN);
		memset(CacheList[0].sbd,0,SBDLEN);
		memset(CacheList[0].offset,0,OFFLEN);
		memset(CacheList[0].cache,'A',CACHESIZE);
	}

	memset(local_mac,0,7);
	memset(dest_mac,0,7);
	memset(dest_ip,0,16);
	
	uint8_t bm1[7]={0xff,0xff,0xff,0xff,0xff,0xff,0x00};
	memcpy(broad_mac1,bm1,7);
	uint8_t bm2[7]={0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	memcpy(broad_mac2,bm2,7);
}

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
)
{
	FILE *fp;
	char ch=0;
	int file_i=0;

	//提取物理网口名称末尾序号
	int i;
	int numfound=0;
	char portnum[3]={0};
	for(i=29;i>=0;i--)
	{
		if(PhysicalPort[i] >= '0' && PhysicalPort[i] <= '9' && numfound == 0)
		{
			numfound=1;
			portnum[1]=PhysicalPort[i];
			continue;
		}
		if(PhysicalPort[i] >= '0' && PhysicalPort[i] <= '9' && numfound == 1)
		{
			numfound=2;
			portnum[0]=PhysicalPort[i];
		}
		else if(numfound == 1)
		{
			portnum[0] = portnum[1];
			portnum[1]=0;
			break;
		}
		if(numfound==2)
			break;
	}

	//获取本地MAC
	struct ifreq ifreq;
	int sock = socket(AF_INET,SOCK_STREAM,0);
	if(0 > sock)
	{
		printf("PhysicalPort MAC getting failed (socket failed).\n");
		exit(0);
	}
	strcpy(ifreq.ifr_name,PhysicalPort);
	if(0 > ioctl(sock,SIOCGIFHWADDR,&ifreq))
	{
		printf("PhysicalPort MAC getting failed (ioctl failed).\n");
		exit(0);
	}
	//拷贝本地MAC
	memcpy(LocalMAC,(uint8_t *)ifreq.ifr_hwaddr.sa_data,6);
	if(GLOBALTEST == 2)//如果是在实体物理机上调试
	memcpy(LocalMAC,PPSMAC,6);

	//设置本地IP
	strcpy(local_ip,dest_ip);
	for(i=0;i<16;i++)
	{
		if(local_ip[i] == 0)
		{
			strcpy(local_ip+i,portnum);
			break;
		}
	}

	//确认输出配置结果
	printf("[Configure]local_ip  == %s\n",local_ip);
	printf("[Configure]dest_ip   == %s\n",dest_ip);

	return 1;
}

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
)
{
	if (NULL == pkg)
	{
		return 0;
	}

	unsigned int type=0;

	if(pkg->version_type>=160 && pkg->version_type<=164)
		return 10;
	
	return 0;
}

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
	char * LocalMAC,
	char * dest_mac,
	char * ip,
	char * dest,
	char * message,
	unsigned int messagelength
)
{
	int i,j;
	char pkg[BUFSIZE]={0};
	struct hostent *host =NULL;
	struct sockaddr sa;
	int sockfd,len;
	uint8_t temp_ip[5];
	memset((char *)&pkg,0,sizeof(pkg));
	
	//填充ethernet包文
	memcpy(pkg,dest_mac,6);
	memcpy(pkg+6,LocalMAC,6);
	pkg[12] = (char)(htons(0x0800)%256);
	pkg[13] = (char)(htons(0x0800)/256);
	memcpy(pkg+14,message,messagelength);

	//实际应该使用PF_PACKET
	if((sockfd = socket(PF_PACKET/*PF_INET*/,SOCK_PACKET,htons(ETH_P_ALL)))==-1)
	{
		fprintf(stderr,"Socket Error:%s\n\a",strerror(errno));
		return 0;
	}
	
	memset(&sa,0,sizeof(sa));
	strcpy(sa.sa_data,PhysicalPort);
	
	selfpacketdonotcatch[portnum]=1;

	if(pysicalportDEVETESTIMPL <= 1)
	{
		printf("[%s] Ethernet pkg length == %d\n",PhysicalPort,messagelength+14);
		printf("[%s] Packet sent out to Physical Port.\n",PhysicalPort);//输出提示
		printf("\n<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n\n");
	}	

	len = sendto(sockfd,&pkg,messagelength+14,0,&sa,sizeof(sa));//发送包至mac层
	close(sockfd);

	if(len != messagelength+14)//如果发送长度与实际包不匹配，发送失败
	{
		fprintf(stderr,"Sendto Error:%s\n\a",strerror(errno));
		return 0;
	}
	return 1;
}

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
)
{
	if(pysicalportDEVETESTIMPL <= 1)
		printf("[%s] PhysicalPort_UDP_Sendpkg()\n",PhysicalPort);

	int i;
	
	CoLoR_VersionType *pkg = NULL;
	char destNID[NIDLEN];
	memset(destNID,0,NIDLEN);
	
	//提取来自转发平面的数据包的目的NID
	pkg = (CoLoR_VersionType * )packet;
	
	if(pkg->version_type == 160)//仅显示IP版本号为10，包类型为0（专属CoLoR-Get包  字段为1010 0000）的包
	{
		if(pysicalportDEVETESTIMPL <= 1)
			printf("[%s] This is a GET pkt from forwarding plane.\n",PhysicalPort);

		memcpy(destNID,packet+16+pkg->sid_len+pkg->nid_len/2,pkg->nid_len/2);

		if(pysicalportDEVETESTIMPL <= 1)
			printf("[%s] destNID == %s\n",PhysicalPort,destNID);
	}
	if(pkg->version_type == 161)//仅显示IP版本号为10，包类型为1（专属CoLoR-Data包 字段为1010 0001）的包
	{
		if(pysicalportDEVETESTIMPL <= 1)
			printf("[%s] This is a DATA pkt from forwarding plane.\n",PhysicalPort);

		memcpy(destNID,packet+16+pkg->sid_len+pkg->nid_len/2,pkg->nid_len/2);

		if(pysicalportDEVETESTIMPL <= 1)
			printf("[%s] destNID == %s\n",PhysicalPort,destNID);
	}
	if(pkg->version_type == 162)//仅显示IP版本号为10，包类型为2（专属CoLoR-Register包 字段为1010 0010）的包
	{
		if(pysicalportDEVETESTIMPL <= 1)
			printf("[%s] This is a REGISTER pkt from forwarding plane.\n",PhysicalPort);

		memcpy(destNID,packet+16+((int)*(packet+1))/2,((int)*(packet+1))/2);

		if(pysicalportDEVETESTIMPL <= 1)
			printf("[%s] destNID == %s\n",PhysicalPort,destNID);
	}

	//根据destNID查找目的IP地址
	char ipaddr[16];
	memset(ipaddr,0,16);
	
	for(i=0;i<=ipnodelistcount;i++)
	{
		if(strncmp(destNID,ipnodelist[i].nid,NIDLEN) == 0)
		{
			strcpy(ipaddr,ipnodelist[i].ip);
			break;
		}
	}
	if(pysicalportDEVETESTIMPL <= 1)
		printf("[%s] ipaddr == %s\n",PhysicalPort,ipaddr);

	//封装并发送MAC+IP+UDP+CoLoR报文
	int udpsender;

	udpsender = socket(AF_INET,SOCK_DGRAM,0);

	struct sockaddr_in addrTo = {0};
	//bzero(&addrTo,sizeof(addrTo));
	
	addrTo.sin_family = AF_INET;
	addrTo.sin_port = htons(6000);
	addrTo.sin_addr.s_addr = inet_addr(ipaddr);

	sendto(udpsender,packet,packetlength,0,(struct sockaddr *)&addrTo,sizeof(addrTo));
	close(udpsender);

	if(pysicalportDEVETESTIMPL <= 1)
	{
		printf("[%s] Packet sent out to the dest IP.\n",PhysicalPort);//输出提示
		printf("\n<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n\n");
	}

	return 1;
}

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
)
{
	int iRet = -1;
	struct ifreq stIfr;
	
	//获取接口属性标志位
	strcpy(stIfr.ifr_name,pcIfName);
	iRet = ioctl(fd,SIOCGIFFLAGS,&stIfr);
	if(0 > iRet)
	{
		perror("[Error]Get Interface Flags");   
		return -1;
	}
	
	if(0 == iFlags)
	{
		//取消混杂模式
		stIfr.ifr_flags &= ~IFF_PROMISC;
	}
	else
	{
		//设置为混杂模式
		stIfr.ifr_flags |= IFF_PROMISC;
	}
	
	//设置接口标志
	iRet = ioctl(fd,SIOCSIFFLAGS,&stIfr);
	if(0 > iRet)
	{
		perror("[Error]Set Interface Flags");
		return -1;
	}
	
	return 0;
}

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
)
{
	int iRet = -1;
	int fd = -1;
	struct ifreq stIf;
	struct sockaddr_ll stLocal = {0};
	
	//创建SOCKET
	fd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	if (0 > fd)
	{
		perror("[Error]Initinate L2 raw socket");
		return -1;
	}
	
	//网卡混杂模式设置
	PhysicalPort_Ethernet_SetPromisc(PhysicalPort,fd,1);
	
	//设置SOCKET选项
	int rawlength = BUFSIZE;
	iRet = setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&rawlength,sizeof(int));
	if (0 > iRet)
	{
		perror("[Error]Set socket option");
		close(fd);
		return -1;
	}
	
	//获取物理网卡接口索引
	strcpy(stIf.ifr_name,PhysicalPort);
	iRet = ioctl(fd,SIOCGIFINDEX,&stIf);
	if (0 > iRet)
	{
		perror("[Error]Ioctl operation");
		close(fd);
		return -1;
	}
	
	//绑定物理网卡
	stLocal.sll_family = PF_PACKET;
	stLocal.sll_ifindex = stIf.ifr_ifindex;
	stLocal.sll_protocol = htons(ETH_P_ALL);
	iRet = bind(fd,(struct sockaddr *)&stLocal,sizeof(stLocal));
	if (0 > iRet)
	{
		perror("[Error]Bind the interface");
		close(fd);
		return -1;
	}
	
	return fd;   
}

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
)
{
	int iRet = -1;
	int fd = -1;
	struct sockaddr_in sin = {0};
	
	//创建SOCKET
	fd = socket(AF_INET,SOCK_DGRAM,0);
	if (0 > fd)
	{
		perror("[Error]Initinate L4 UDP socket");
		return -1;
	}

	int i,j;
	char physicalportIP[16];
	//查找网口IP
	for(i=0;i<=ipnodelistcount;i++)
	{
		if(strncmp(ipnodelist[i].nid,NID,NIDLEN) == 0)
		{
			for(j=i;strncmp(ipnodelist[j].nid,NID,NIDLEN) == 0;j++)
			{
				if(strncmp(ipnodelist[j].pp,PhysicalPort,30) == 0)
				{
					strcpy(physicalportIP,ipnodelist[j].ip);
					break;
				}
			}
			break;
		}
	}

	if(pysicalportDEVETESTIMPL <= 1)
		printf("[%s] physicalportIP == %s\n",PhysicalPort,physicalportIP);
	
	//绑定物理网卡
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(physicalportIP);
	sin.sin_port = htons(6000);
	
	iRet = bind(fd,(struct sockaddr *)&sin,sizeof(sin));
	if (0 > iRet)
	{
		perror("[Error]Bind the interface");
		close(fd);
		return -1;
	}
	
	return fd; 
}

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
)
{
	//接收缓冲区
	int EnBUFlength = BUFSIZE;
	uint8_t EnBUF[BUFSIZE];

	int iRet = -1;
	socklen_t stFromLen = 0;

	int packetcount=1;
	
	int cancelrepetition=0;//由于未知原因，每一个来自物理介质的数据包都会被接收两次。故设定相邻的每两次收包仅一次有效，这是权宜之计，没有根治问题。
	printf("[%s] South interface listening start... (RAW Socket to Physical Port: %s)\n",PhysicalPort,PhysicalPort);
	//循环监听
	while(1)
	{
		//清空接收缓冲区
		memset(EnBUF, 0, BUFSIZE);
		
		//接收数据帧
		iRet = recvfrom(fd, EnBUF, EnBUFlength, 0, NULL, &stFromLen);

		//接收错误
		if (0 > iRet)
		{
			continue;
		}

		//第一时间丢弃自己发出的数据包
		//方法一：（简单粗暴）直接丢弃距离上次发包最近的、接收上来的包，因为有极大可能是自己发出的
		/*
		if(selfpacketdonotcatch[portnum] == 1)
		{
			if(pysicalportDEVETESTIMPL <= 1)
				printf("Drop the pkg sent by myself.\n");
			selfpacketdonotcatch[portnum] = 0;
			continue;
		}
		*/
		//方法二：采用判断源MAC地址的方法丢弃自己发出的包
		if(strncmp(EnBUF+6,LocalMAC,6) == 0)
		{
			if(pysicalportDEVETESTIMPL <= 1)
				printf("Drop the pkg sent by myself.\n");
			continue;
		}

		//输出新包接收提示
		if(pysicalportDEVETESTIMPL <= 1)
		{
			printf("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n\n");
			printf("[%s] Physical Port report for new RAW Packet / No. %d\n",PhysicalPort,packetcount++);
		}

		//接收数据帧检测
		//printf("[Ethernet]New Packet Received. Noooo.%d:\n",packetcount++);

		//if(cancelrepetition == 0)
		if(1)
		{
			//解析数据帧
			PhysicalPort_Ethernet_ParseFrame(EnBUF,PhysicalPort,local_ip);
			cancelrepetition=1;
		}
		else
		{
			cancelrepetition=0;
		}
	}
}

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
)
{
	//接收缓冲区
	int EnBUFlength = BUFSIZE;
	uint8_t EnBUF[BUFSIZE];

	int iRet = -1;
	int packetcount=1;

	int sockaddr_len = sizeof(struct sockaddr_in);

	printf("[%s] South interface listening start... (UDP Socket to Physical Port: %s)\n",PhysicalPort,PhysicalPort);
	//循环监听
	while(1)
	{
		//清空接收缓冲区
		//memset(EnBUF, 0, BUFSIZE);
		bzero(EnBUF,BUFSIZE);
		
		//接收数据帧
		iRet = recvfrom(fd, EnBUF+14, EnBUFlength-14, 0, NULL, &sockaddr_len);

		//接收错误
		if (0 > iRet)
		{
			continue;
		}

		//输出新包接收提示
		if(pysicalportDEVETESTIMPL <= 1)
		{
			printf("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n\n");
			printf("[%s] Physical Port report for new UDP Packet / No. %d\n",PhysicalPort,packetcount++);
		}

		//接收数据帧检测
		//printf("[Ethernet]New Packet Received. Noooo.%d:\n",packetcount++);

		//填充ethernet包文
		//memcpy(EnBUF,dest_mac,6);
		//memcpy(EnBUF+6,local_mac,6);
		EnBUF[12] = (char)(htons(0x0800)%256);
		EnBUF[13] = (char)(htons(0x0800)/256);

		//解析数据帧（接收的UDP-CoLOR包原不包含MAC层，假封一个）
		PhysicalPort_Ethernet_ParseFrame(EnBUF,PhysicalPort,local_ip);
	}
}

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
)
{
	static int packetcount=1;
	//检查本机mac和IP地址
	/*
	memset ( local_mac,0,sizeof ( local_mac ) );
	memset ( local_ip,0,sizeof ( local_ip ) );
	memset ( dest_ip,0,sizeof ( dest_ip ) );
	
	if ( GetLocalMac ( PhysicalPort,local_mac,local_ip ) ==-1 )
		return ( -1 );
	*/
	
	int iEther = 0;
	int iRet = -1;
	
	/*
	struct <A name=ether_header < a>ether_header {
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
	};
	*/
	
	Ether_VersionType *pEtherVT = NULL;
	//struct Ether_CoLoR_VersionType *pCoLoRVT = NULL;
	
	//接收到的原始数据流赋值为以太网头
	pEtherVT = (Ether_VersionType*)EnBUF;
	
	//判断以太网数据帧类型
	iEther = PhysicalPort_Ethernet_SeeType(pEtherVT);

	if(iEther == 10)//收到指向本端口MAC的IP包，网络层协议为CoLoR
	{
		if(pysicalportDEVETESTIMPL <= -1)
		{
			int dd=0;
			char c;
			printf("\n");
			while(dd<68)
			{
				c = *(EnBUF+dd);
				printf("%d",c/128);
				c%=128;
				printf("%d",c/64);
				c%=64;
				printf("%d",c/32);
				c%=32;
				printf("%d",c/16);
				c%=16;
				printf("%d",c/8);
				c%=8;
				printf("%d",c/4);
				c%=4;
				printf("%d",c/2);
				c%=2;
				printf("%d",c);
				printf(" ");
				dd++;
			}
			printf("\n\n");

			//pCoLoRVT = (struct Ether_CoLoR_VersionType*)EnBUF;
			//pkglength = pCoLoRVT->total_len;
		}
		if(pysicalportDEVETESTIMPL <= 1)
			printf("[%s] New CoLoR packet received. No.%d:\n",PhysicalPort,packetcount++);

		//处理CoLoR包
		iRet = PhysicalPort_CoLoR_Parsepacket(EnBUF,PhysicalPort,local_ip);
	}
	else if(iEther == 4)//收到指向本端口MAC的IP包，网络层协议为IPv4
	{
		if(pysicalportDEVETESTIMPL <= 1)
			printf("[%s] New IPv4 packet received. No.%d\n",PhysicalPort,packetcount++);
	}
	else if(iEther == 6)//收到指向本端口MAC的IP包，网络层协议为IPv6
	{
		if(pysicalportDEVETESTIMPL <= 1)
			printf("[%s] New IPv6 packet received. No.%d\n",PhysicalPort,packetcount++);
	}
	else if(iEther == -10)//收到的不是指向本端口MAC的IP包，网络层协议为CoLoR
	{
		if(pysicalportDEVETESTIMPL <= -1)
		{
			int dd=0;
			char c;
			printf("\n");
			while(dd<68)
			{
				c = *(EnBUF+dd);
				printf("%d",c/128);
				c%=128;
				printf("%d",c/64);
				c%=64;
				printf("%d",c/32);
				c%=32;
				printf("%d",c/16);
				c%=16;
				printf("%d",c/8);
				c%=8;
				printf("%d",c/4);
				c%=4;
				printf("%d",c/2);
				c%=2;
				printf("%d",c);
				printf(" ");
				dd++;
			}
			printf("\n\n");

			//iRet = CoLoR_Parsepacket(EnBUF);
		}
		if(pysicalportDEVETESTIMPL <= 1)
			printf("[%s] Strange CoLoR packet received. No.%d\n",PhysicalPort,packetcount++);
	}
	else if(iEther == -4)//收到的不是指向本端口MAC的IP包，网络层协议为IPv4
	{
		if(pysicalportDEVETESTIMPL <= 1)
			printf("[%s] Strange IPv4 packet received. No.%d\n",PhysicalPort,packetcount++);
	}
	else if(iEther == -6)//收到的不是指向本端口MAC的IP包，网络层协议为IPv6
	{
		if(pysicalportDEVETESTIMPL <= 1)
			printf("[%s] Strange IPv6 packet received. No.%d\n",PhysicalPort,packetcount++);
	}
	else
	{
		if(pysicalportDEVETESTIMPL <= 1)
			printf("[%s] Strange packet received. Protocol unknown. No.%d\n",PhysicalPort,packetcount++);
	}
	return iRet;
}

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
)
{
	if (NULL == pkg)
	{
		return 0;
	}
	//这里为判断，确保收上来的数据包不是自己发出的，所以本机开两个对端进行测试的时候须将pysicalportGLOBALTEST判断值设为0值
	/*
	struct <A name=ether_header < a>ether_header {
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
	};
	*/

	/*检测mac地址的匹配情况
	int qq=0;

	for(qq=0;qq<6;qq++)
	{
		printf("pkg->ether_dhost[%d] == %d\n",qq,pkg->ether_dhost[qq]);
		printf("local_mac[%d]        == %d\n",qq,local_mac[qq]);
	}
	if((strncmp((uint8_t*)pkg->ether_dhost,(uint8_t*)local_mac ,6)==0) || 
			    (strncmp((uint8_t*)pkg->ether_dhost,(uint8_t*)broad_mac1,6)==0) || 
			    (strncmp((uint8_t*)pkg->ether_dhost,(uint8_t*)broad_mac2,6)==0))
	{
		printf("pre-mac same!\n");
	}
	*/
	unsigned int type=0;
	if(pysicalportGLOBALTEST == 0)
	{
		if(((strncmp((uint8_t*)pkg->ether_dhost,(uint8_t*)local_mac ,6)==0) || 1 ||
		    (strncmp((uint8_t*)pkg->ether_dhost,(uint8_t*)broad_mac1,6)==0) || 
		    (strncmp((uint8_t*)pkg->ether_dhost,(uint8_t*)broad_mac2,6)==0)) && 
		   (pkg->ether_type == 8))//0x0800怎么读取？这里的8是敷衍了事的，因为只能读出8
		{
			type = pkg->version_type/16;
			return type;
		}
		else if(pkg->ether_type == 8)
		{
			type = pkg->version_type/16;
			return -type;
		}
	}
	else if(pysicalportGLOBALTEST >= 1)
	{
		if(pkg->ether_type == 8)
		{
			type = pkg->version_type/16;
			return type;
		}
	}
	
	return 0;
}

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
)
{
	int i;
	
	char* p;
	p = (char*)pkg;
	
	if (NULL == pkg)
	{
		return -1;
	}
	
	//根据CoLoR包长度字段所在位置获取包长度数值
	Ether_CoLoR_VersionType * pCoLoRVT = NULL;
	pCoLoRVT = (Ether_CoLoR_VersionType *)pkg;
	unsigned int pkglength;

	if(pysicalportDEVETESTIMPL <= 1)
		printf("[%s] pCoLoRVT->version_type=%d\n",PhysicalPort,pCoLoRVT->version_type);

	//强制修改包属性，在无校验的情况下用于避免包误码
	/*
	if(CNFTCP == 0)
	{
		pCoLoRVT->options_static = 32;
	}
	else
	{
		pCoLoRVT->options_static = 0;
	}
	*/

	//提取包长度
	if(pCoLoRVT->version_type == 161 && pCoLoRVT->options_static % 64 / 32 == 1)//如果收到的包是CNF缓存DATA包
	{
		pkglength = pCoLoRVT->total_len;
		PhysicalPort_CNF_NewClientThread(pkg,pkglength,PhysicalPort,local_ip);
		return 0;
	}
	else if(pCoLoRVT->version_type == 163 || pCoLoRVT->version_type == 164)//如果收到的包是CNF-SEQ/ACK包
	{
		pkglength = pCoLoRVT->total_len;
		PhysicalPort_CNF_SendMessage(pkg,pkglength,pCoLoRVT->version_type,PhysicalPort,local_ip);
		return 0;
	}
	else if((pCoLoRVT->version_type == 160 || pCoLoRVT->version_type == 161) && pCoLoRVT->options_static % 64 / 32 == 0)//如果收到的包是非缓存GET/DATA包
	{
		pkglength = pCoLoRVT->total_len;

		if(pysicalportDEVETESTIMPL <= 1)
			printf("[%s] pkglength == %d\n",PhysicalPort,pkglength);

		//封装并向上层发送消息
		if(INTRACOMMUNICATION == 0)
			PhysicalPort_UDP_SendMessage(pkg,pkglength,PhysicalPort,local_ip);
		else if(INTRACOMMUNICATION == 1)
			PhysicalPort_SEM_SendMessage(pkg,pkglength,PhysicalPort,local_ip);
	}
	else if(pCoLoRVT->version_type == 162)//如果收到的包是注册包
	{
		CoLoR_register_parse * pRegisterlen = NULL;
		pRegisterlen = (CoLoR_register_parse *)(pkg+14);
		pkglength = pRegisterlen->total_len;

		if(pysicalportDEVETESTIMPL <= 1)
			printf("[%s] pkglength == %d\n",PhysicalPort,pkglength);

		//封装并向上层发送消息
		if(INTRACOMMUNICATION == 0)
			PhysicalPort_UDP_SendMessage(pkg,pkglength,PhysicalPort,local_ip);
		else if(INTRACOMMUNICATION == 1)
			PhysicalPort_SEM_SendMessage(pkg,pkglength,PhysicalPort,local_ip);
	}
	else//收包的版本类型字段错误，无法判断类型
	{
		printf("Error: PhysicalPort_CoLoR_Parsepacket() - Recv a bad packet!\n");
		exit(0);
	}
	
	return 0;
}

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
)
{
		//计算时间节点（微秒）		
		gettimeofday(&utime,NULL);
		printf("<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<\n");
		printf("==================Time==================\nClient Connection Start   %ld us\n========================================\n",1000000 * utime.tv_sec + utime.tv_usec);

	int i;
	//解析DATA包
	Ether_CoLoR_data * datapkg = NULL;
	datapkg = (Ether_CoLoR_data *)originalbuf;
	
	//队列缓存DATA包
	for(i=0;i<10;i++)
	{
		if(datapkglist[i].flag_occupied == 0)
		{
			datapkglist[i].flag_occupied = 1;
			datapkglist[i].pkglength = pkglength;
			memcpy(datapkglist[i].physicalport,PhysicalPort,30);
			memcpy(datapkglist[i].local_ip,local_ip,16);
			memcpy(datapkglist[i].sid,datapkg->sid,SIDLEN);
			memcpy(datapkglist[i].offset,datapkg->offset,OFFLEN);
			memcpy(datapkglist[i].datapkg,originalbuf,pkglength);
			break;
		}
	}
	//溢出判断
	if(i >= 10)
	{
		printf("[PhysicalPort - CNF Client Init]datapkglist Over Loaded!\n");
		exit(0);
	}

	int DATAPKGLocation = i;
	
	//查表获取可用的CNF缓存块
	for(i=0;i<10;i++)
	{
		if(CacheList[i].flag_occupied == 0)
		{
			CacheList[i].flag_occupied = 1;
			CacheList[i].datapkglocation = DATAPKGLocation;
			memcpy(CacheList[i].physicalport,PhysicalPort,30);
			memcpy(CacheList[i].sid,datapkg->sid,SIDLEN);
			memcpy(CacheList[i].offset,datapkg->offset,OFFLEN);
			break;
		}
	}
	//溢出判断
	if(i >= 10)
	{
		printf("[PhysicalPort - CNF Client Init]CacheList Over Loaded!\n");
		exit(0);
	}
	
	int CacheLocation = i;
	
	//查表获取可用的CNF任务序号
	for(i=0;i<10;i++)
	{
		if(CNFThreadList[i].flag_occupied == 0)
		{
			CNFThreadList[i].flag_occupied = 1;
			CNFThreadList[i].flag_IO = 0;
			CNFThreadList[i].datapkglocation = DATAPKGLocation;
			CNFThreadList[i].cachelocation = CacheLocation;
			memcpy(CNFThreadList[i].physicalport,PhysicalPort,30);
			memcpy(CNFThreadList[i].physicalportIP,local_ip,16);
			memcpy(CNFThreadList[i].sid,datapkg->sid,SIDLEN);
			memcpy(CNFThreadList[i].offset,datapkg->offset,OFFLEN);
			break;
		}
	}
	//溢出判断
	if(i >= 10)
	{
		printf("[PhysicalPort - CNF Client Init]CNFThreadList Over Loaded!\n");
		exit(0);
	}

	int CNFThreadNum = i;
	
	datapkglist[DATAPKGLocation].CNFthreadnum = CNFThreadNum;
	
	//启动新CNF-Client任务实例
	struct cnfcliinput cnfinput;

	cnfinput.threadnum = CNFThreadNum;
	cnfinput.cachelocation = CacheLocation;
	cnfinput.cachelength = CACHESIZE;
	memcpy(cnfinput.physicalportIP,local_ip,16);
	memcpy(cnfinput.sid,datapkg->sid,SIDLEN);
	memcpy(cnfinput.offset,datapkg->offset,OFFLEN);
	
	pthread_t pthread_cnfclient;
	
	//创建子线程
	if(pthread_create(&pthread_cnfclient, NULL, CNFClient_main, (void *)&cnfinput)!=0)
	{
		perror("Creation of CNF Client main thread failed.");
	}
}

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
)
{
		//计算时间节点（微秒）		
		gettimeofday(&utime,NULL);
		printf(">->->->->->->->->->->->->->->->->->->->->->->->->->->->->->->->->->\n");
		printf("==================Time==================\nServer Connection Start   %ld us\n========================================\n",1000000 * utime.tv_sec + utime.tv_usec);

	int i;
	//解析DATA包
	CoLoR_data * datapkg = NULL;
	datapkg = (CoLoR_data *)originalbuf;
	
	//查表获取需要提取数据的CNF缓存块
	if(DEVETESTIMPL <= 6)
	{
		printf("[Init]datapkg->sid    = %s\n",datapkg->sid);
		printf("[Init]datapkg->offset = %s\n",datapkg->offset);
	}
	
	for(i=0;i<10;i++)
	{
		if(DEVETESTIMPL <= 6)
		{
			printf("[Init]CacheList[%d].sid    = %s\n",i,CacheList[i].sid);
			printf("[Init]CacheList[%d].offset = %s\n",i,CacheList[i].offset);
		}
		
		if(strncmp(CacheList[i].sid,datapkg->sid,SIDLEN)==0 && strncmp(CacheList[i].offset,datapkg->offset,OFFLEN)==0)
		{
			break;
		}
	}
	//溢出判断
	if(i >= 10)
	{
		printf("[PhysicalPort - CNF Server Init]CacheList Over Loaded!\n");
		exit(0);
	}

	int CacheLocation = i;
	
	//查表获取可用的CNF任务序号
	for(i=0;i<10;i++)
	{
		if(CNFThreadList[i].flag_occupied == 0)
		{
			CNFThreadList[i].flag_occupied = 1;
			CNFThreadList[i].flag_IO = 1;
			CNFThreadList[i].datapkglocation = -1;
			CNFThreadList[i].cachelocation = CacheLocation;
			memcpy(CNFThreadList[i].physicalport,PhysicalPort,30);
			memcpy(CNFThreadList[i].physicalportIP,local_ip,16);
			memcpy(CNFThreadList[i].sid,datapkg->sid,SIDLEN);
			memcpy(CNFThreadList[i].offset,datapkg->offset,OFFLEN);

			if(DEVETESTIMPL <= 6)
			{
				printf("==O==ThreadNum = %d\n",i);
				printf("flag_occupied  = %d\n",CNFThreadList[i].flag_occupied);
				printf("flag_IO        = %d\n",CNFThreadList[i].flag_IO);
				printf("datapkglocation= %d\n",CNFThreadList[i].datapkglocation);
				printf("cachelocation  = %d\n",CNFThreadList[i].cachelocation);
				printf("physicalport   = %s\n",CNFThreadList[i].physicalport);
				printf("physicalportIP = %s\n",CNFThreadList[i].physicalportIP);
				printf("sid            = %s\n",CNFThreadList[i].sid);
				printf("offset         = %s\n",CNFThreadList[i].offset);
				printf("===================\n");
				printf("PhysicalPort   = %s\n",PhysicalPort);
				printf("datapkg->sid   = %s\n",datapkg->sid);
				printf("datapkg->offset= %s\n",datapkg->offset);
				printf("===================\n");
			}

			break;
		}
	}
	//溢出判断
	if(i >= 10)
	{
		printf("[PhysicalPort - CNF Server Init]CNFThreadList Over Loaded!\n");
		exit(0);
	}

	int CNFThreadNum = i;
	
	//CNF线程传参载体
	struct cnfserinput cnfinput;
	//启动新CNF-Server任务实例
	cnfinput.threadnum = CNFThreadNum;
	cnfinput.cachelocation = CacheLocation;
	cnfinput.cachelength = CACHESIZE;
	memcpy(cnfinput.physicalportIP,local_ip,16);
	memcpy(cnfinput.sid,datapkg->sid,SIDLEN);
	memcpy(cnfinput.offset,datapkg->offset,OFFLEN);
	
	if(DEVETESTIMPL <= 6)
	{
		printf("[NEW]local_ip = %s\n",local_ip);
		printf("[NEW]cnfinput.threadnum = %d\n",cnfinput.threadnum);
		printf("[NEW]CacheLocation = %d\n",CacheLocation);
	}
	
	pthread_t pthread_cnfserver;
	
	//创建子线程
	if(pthread_create(&pthread_cnfserver, NULL, CNFServer_main, (void *)&cnfinput)!=0)
	{
		perror("Creation of CNF Client main thread failed.");
	}
	sem_wait(&CNFThreadList[CNFThreadNum].StartParaTransEnd);
}

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
)
{
	int i;
	int ThreadNum;
	//解析CNF包
	int flag_occupied;
	int flag_IO;
	int datapkglocation;
	int cachelocation;
	unsigned long cachelength;
	uint8_t physicalport[30];
	uint8_t sid[SIDLEN];
	uint8_t sbd[SBDLEN];
	uint8_t offset[OFFLEN];
	if(versiontype == 163)//如果CNF包为SEQ包
	{
		//解析SEG包
		Ether_CoLoR_seg * segpkg = NULL;
		segpkg = (Ether_CoLoR_seg *)originalbuf;
		
		//拷贝匹配字段
		memcpy(sid,segpkg->sid,SIDLEN);
		memcpy(offset,segpkg->offset,OFFLEN);
		
		//查找匹配任务列表，获取目标端口号的偏移量
		for(i=0;i<10;i++)
		{
			if(CNFThreadList[i].flag_occupied == 1
			&& CNFThreadList[i].flag_IO == 0
			&& strncmp(CNFThreadList[i].physicalport,PhysicalPort,30) == 0
			&& strncmp(CNFThreadList[i].sid,sid,SIDLEN) == 0
			&& strncmp(CNFThreadList[i].offset,offset,OFFLEN) == 0)
			{
				break;
			}
		}
//缺少溢出判断
		ThreadNum = i;
	}
	else if(versiontype == 164)//如果CNF包为ACK包
	{
		//解析ACK包
		Ether_CoLoR_ack * ackpkg = NULL;
		ackpkg = (Ether_CoLoR_ack *)originalbuf;
		
		//拷贝匹配字段
		memcpy(sid,ackpkg->sid,SIDLEN);
		memcpy(offset,ackpkg->offset,OFFLEN);
		
		//查找匹配任务列表，获取目标端口号的偏移量
		for(i=0;i<10;i++)
		{
			if(CNFThreadList[i].flag_occupied == 1
			&& CNFThreadList[i].flag_IO == 1
			&& strncmp(CNFThreadList[i].physicalport,PhysicalPort,30) == 0
			&& strncmp(CNFThreadList[i].sid,sid,SIDLEN) == 0
			&& strncmp(CNFThreadList[i].offset,offset,OFFLEN) == 0)
			{
				break;
			}
		}
//缺少溢出判断
		ThreadNum = i;
	}
	/*
	printf("==S==ThreadNum = %d\n",0);
	printf("flag_occupied  = %d\n",CNFThreadList[0].flag_occupied);
	printf("flag_IO        = %d\n",CNFThreadList[0].flag_IO);
	printf("datapkglocation= %d\n",CNFThreadList[0].datapkglocation);
	printf("cachelocation  = %d\n",CNFThreadList[0].cachelocation);
	printf("physicalport   = %s\n",CNFThreadList[0].physicalport);
	printf("sid            = %s\n",CNFThreadList[0].sid);
	printf("offset         = %s\n",CNFThreadList[0].offset);
	printf("===================\n");
	printf("PhysicalPort   = %s\n",PhysicalPort);
	printf("sid            = %s\n",sid);
	printf("offset         = %s\n",offset);
	printf("===================\n");
	*/

	//查找匹配任务列表，获取目标IP和端口号

	//发送CNF消息
	int socket_sender;
	socket_sender=socket(AF_INET,SOCK_DGRAM,0);
	
	struct sockaddr_in addrTo;
	bzero(&addrTo,sizeof(addrTo));
	addrTo.sin_family=AF_INET;
	addrTo.sin_port=htons(PhysicalportInterPORT + ThreadNum * CNFPORTRANGE);
	addrTo.sin_addr.s_addr=inet_addr(LOOPIP);

	sendto(socket_sender,originalbuf+14,pkglength,0,(struct sockaddr *)&addrTo,sizeof(addrTo));
	close(socket_sender);
}

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
)
{
	char pkg[BUFSIZE];
	
	int socket_sender;
	socket_sender=socket(AF_INET,SOCK_DGRAM,0);
	
	struct sockaddr_in addrFrom;
	bzero(&addrFrom,sizeof(addrFrom));
	addrFrom.sin_family=AF_INET;
	//addrFrom.sin_addr.s_addr=htonl(INADDR_ANY);
	addrFrom.sin_addr.s_addr=inet_addr(local_ip);
	addrFrom.sin_port=htons(0);

	int error = bind(socket_sender,(struct sockaddr *)&addrFrom,sizeof(addrFrom));
	if(error != 0)
	{
		printf("bind() error!\n");
	}

	memcpy(pkg,"NET",3);
	memcpy(pkg+3,originalbuf+14,pkglength);
	
	struct sockaddr_in addrTo;
	bzero(&addrTo,sizeof(addrTo));
	addrTo.sin_family=AF_INET;
	addrTo.sin_port=htons(PhysicalportInterPORT);
	addrTo.sin_addr.s_addr=inet_addr(dest_ip);
	
	if(pysicalportDEVETESTIMPL <= 1)
	{
		//printf("[%s] UDP Message has been sent out:%s\n",PhysicalPort,pkg);
		printf("[%s] UDP Message has been sent out.\n",PhysicalPort);
		printf("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n\n");
	}

	sendto(socket_sender,pkg,pkglength+3,0,(struct sockaddr *)&addrTo,sizeof(addrTo));
	close(socket_sender);
}

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
)
{
/*
//网络层包转发缓冲队列
typedef struct _PkgCacheUnit PkgCacheUnit;
struct _PkgCacheUnit
{
	int flag_occupied;
	int pkglength;
	uint8_t sourcepp[30];
	uint8_t pkg[MTU];
}PkgBUF[10];
int PkgBUFHead;
int PkgBUFTail;
*/

	//数据包进入转发缓冲队列（此处需要线程锁）
	pthread_mutex_lock(&lockPkgBUF);
	int LocalPkgBUFHead;
	if(PkgBUF[PkgBUFHead].flag_occupied == 0)
	{
		LocalPkgBUFHead = PkgBUFHead;
		PkgBUFHead++;
		if(PkgBUFHead >=10)
			PkgBUFHead -= 10;
		
		PkgBUF[LocalPkgBUFHead].flag_occupied = 1;
		PkgBUF[LocalPkgBUFHead].pkglength = pkglength;
		strcpy(PkgBUF[LocalPkgBUFHead].sourcepp,PhysicalPort);
		memcpy(PkgBUF[LocalPkgBUFHead].pkg,originalbuf+14,pkglength);
		
		//触发网络层信号量
		sem_post(&semPacketRECV);

		if(pysicalportDEVETESTIMPL <= 1)
		{
			//printf("[%s] SEM Message has been sent to NetworkLayer:%s\n",PhysicalPort,originalbuf+14);
			printf("[%s] SEM Message has been sent to NetworkLayer.\n",PhysicalPort);
			printf("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n\n");
		}
	}
	else
	{
		if(pysicalportDEVETESTIMPL <= 1)
		{
			//printf("[%s] SEM Message failed to be sent to NetworkLayer:%s\n",PhysicalPort,originalbuf+14);
			printf("[%s] SEM Message failed to be sent to NetworkLayer.\n",PhysicalPort);
			printf("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n\n");
		}
	}
	pthread_mutex_unlock(&lockPkgBUF);
}

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
)
{
	//拷贝形参
	struct pplip * pi = (struct pplip *)fd;
	char * PhysicalPort = pi->pp;
	uint8_t * LocalMAC = pi->lmac;
	char * local_ip = pi->ip;

	int i;
	
	//获取本机本网口编号
	int portnum = -1;
	for(i = 30;i>=0;i--)
	{
		if(strncmp(PhysicalPort+i,"eth",3) == 0)
		{
			if(PhysicalPort[i+4] > '0' && PhysicalPort[i+4] < '9')
			{
				portnum = ((int)PhysicalPort[i+3] - 48)*10 + ((int)PhysicalPort[i+4] - 48);
			}
			else
				portnum = (int)PhysicalPort[i+3] - 48;
			break;
		}
	}
	printf("[%s] PhysicalPort_thread_send() - portnum == %d\n",PhysicalPort,portnum);

	//发送缓冲区
	int ExBUFlength = BUFSIZE;
	uint8_t ExBUF[BUFSIZE];

	static int packetcount=1;
	
	int socket_FORPreceiver;
	socket_FORPreceiver = socket(AF_INET,SOCK_DGRAM,0);
	
	struct sockaddr_in sin;
	int sockaddr_len=sizeof(sin);
	bzero(&sin,sockaddr_len);
	sin.sin_family=AF_INET;
	//sin.sin_addr.s_addr=htonl(INADDR_ANY);
	sin.sin_addr.s_addr=inet_addr(local_ip);
	sin.sin_port=htons(PhysicalportInterPORT);
	
	bind(socket_FORPreceiver,(struct sockaddr *)&sin,sockaddr_len);
	
	printf("[%s] North interface listening start... (UDP Socket to Forwarding Plane: %s)\n",PhysicalPort,local_ip);


	int iCoLoR = 0;
	int iRet = -1;
	
	int LocalPkgBUFSearch=0;
	int LocalPkgBUFTail;
	while(1)
	{
		memset(ExBUF,0,BUFSIZE);

		if(INTRACOMMUNICATION == 0)
			recvfrom(socket_FORPreceiver,ExBUF,sizeof(ExBUF),0,(struct sockaddr *)&sin,&sockaddr_len);//printf("1\n");
		else if(INTRACOMMUNICATION == 1)
		{
			sem_wait(&semPacketSEND[portnum]);
			pthread_mutex_lock(&lockPkgBUF);
			for(;;)
			{
				if(PkgBUF[LocalPkgBUFSearch++].destppnum == portnum)
				{
					LocalPkgBUFTail = LocalPkgBUFSearch-1;

					ExBUFlength = PkgBUF[LocalPkgBUFTail].pkglength;
					memcpy(ExBUF,"FOR",3);
					memcpy(ExBUF+3,PkgBUF[LocalPkgBUFTail].pkg,ExBUFlength);

					//清空转发表项，解除占用
					memset(PkgBUF[LocalPkgBUFTail].sourcepp,0,30);
					memset(PkgBUF[LocalPkgBUFTail].pkg,0,MTU);
					PkgBUF[LocalPkgBUFTail].destppnum = 0;
					PkgBUF[LocalPkgBUFTail].pkglength = 0;
					PkgBUF[LocalPkgBUFTail].flag_occupied = 0;

					if(LocalPkgBUFSearch>=10)
						LocalPkgBUFSearch -= 10;
					break;
				}

				if(LocalPkgBUFSearch>=10)
					LocalPkgBUFSearch -= 10;
			}
			pthread_mutex_unlock(&lockPkgBUF);
		}

		if(pysicalportDEVETESTIMPL <= 1)
		{
			printf("\n<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n\n");
			//printf("[%s] Got a UDP message:%s\n",PhysicalPort,ExBUF);
			printf("[%s] Got a UDP message.\n",PhysicalPort);
		}

		if(strncmp(ExBUF,"FOR",3) == 0)//收到来自上级转发平面的转发包
		{//printf("2\n");
			iCoLoR = 0;
			iRet = -1;
	
			CoLoR_VersionType * pCoLoRVT = NULL;
			pCoLoRVT = (CoLoR_VersionType *)(ExBUF+3);
			
			//判断CoLoR数据帧类型
			iCoLoR = PhysicalPort_CoLoR_SeeType(pCoLoRVT);

			if(iCoLoR == 10)//收到指向本端口MAC的IP包，网络层协议为CoLoR
			{//printf("3\n");
				//待转发的包是启用CNF协议的DATA包，将触发CNF-Server任务实例
				if(pCoLoRVT->version_type == 161 && pCoLoRVT->options_static % 64 / 32 == 1)
				{//printf("4\n");
					PhysicalPort_CNF_NewServerThread(ExBUF+3,pCoLoRVT->total_len,PhysicalPort,local_ip);
				}
				
				if(pysicalportDEVETESTIMPL <= 1)
					printf("[%s] A CoLoR packet will be sent. No.%d:\n",PhysicalPort,packetcount++);

				if(pysicalportDEVETESTIMPL <= 1)
					printf("[%s] pCoLoRVT->version_type=%d\n",PhysicalPort,pCoLoRVT->version_type);

				//拷贝数据包长度信息
				if(pCoLoRVT->version_type == 162)
				{
					CoLoR_register_parse *pRegisterlen = NULL;
					pRegisterlen = (CoLoR_register_parse*)(ExBUF+3);
					ExBUFlength = pRegisterlen->total_len;
				}
				else
				{
					ExBUFlength = pCoLoRVT->total_len;
				}

				if(pysicalportDEVETESTIMPL <= 1)
					printf("[%s] ExBUFlength == %d\n",PhysicalPort,ExBUFlength);

				//向物理网口发送数据包
				if(pysicalportPROTOCOL == 0)
					PhysicalPort_Ethernet_Sendpkg(PhysicalPort,portnum,LocalMAC,dest_mac,local_ip,dest_ip,ExBUF+3,ExBUFlength);
				else if(pysicalportPROTOCOL == 1)
					PhysicalPort_UDP_Sendpkg(PhysicalPort,ExBUF+3,ExBUFlength);
			}
			else
			{
				if(pysicalportDEVETESTIMPL <= 1)
					printf("[%s] A Strange forwarding UDP message received. Protocol unknown. No.%d\n",PhysicalPort,packetcount++);
			}
		}
		else
		{
			if(pysicalportDEVETESTIMPL <= 1)
				printf("[%s] A Strange UDP message received. Not forwarding. No.%d\n",PhysicalPort,packetcount++);
		}
	}
	//关闭线程
	close(socket_FORPreceiver);
	//exit(0);
	free(fd);
	pthread_exit(NULL);
}

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
)
{
	//拷贝形参
	struct pplip * pi = (struct pplip *)fd;
	char * PhysicalPort = pi->pp;
	uint8_t * LocalMAC = pi->lmac;
	char * local_ip = pi->ip;

	int i;

	//获取本机本网口编号
	int portnum = -1;
	for(i = 30;i>=0;i--)
	{
		if(strncmp(PhysicalPort+i,"eth",3) == 0)
		{
			if(PhysicalPort[i+4] > '0' && PhysicalPort[i+4] < '9')
			{
				portnum = ((int)PhysicalPort[i+3] - 48)*10 + ((int)PhysicalPort[i+4] - 48);
			}
			else
				portnum = (int)PhysicalPort[i+3] - 48;
			break;
		}
	}
	printf("[%s] PhysicalPort_thread_send() - portnum == %d\n",PhysicalPort,portnum);

	int socket_recv = -1;
	if(pysicalportPROTOCOL == 0)
	{
		//初始化SOCKET
		socket_recv = PhysicalPort_Ethernet_InitSocket(PhysicalPort);
		if(socket_recv < 0)
		{
			printf("[%s] Failed to Initiate Socket! Existing...\n",PhysicalPort);
			exit(0);
		}
	
		//捕获数据包（死循环）
		PhysicalPort_Ethernet_StartCapture(socket_recv,PhysicalPort,portnum,LocalMAC,local_ip);
	}
	else if(pysicalportPROTOCOL == 1)
	{
		//初始化SOCKET
		socket_recv = PhysicalPort_UDP_InitSocket(PhysicalPort);
		if(socket_recv < 0)
		{
			printf("[%s] Failed to Initiate Socket! Existing...\n",PhysicalPort);
			exit(0);
		}

		PhysicalPort_UDP_StartCapture(socket_recv,PhysicalPort,portnum,local_ip);
	}
	
	//关闭SOCKET
	close(socket_recv);
}

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
)
{
	//全局变量赋初值
	PhysicalPort_Parameterinit();

	int i,j,k,l;

	struct physicalportinput * ppinput;
	ppinput = (struct physicalportinput *)argv;
	//printf("[RECV]ppinput.pp == %s\n",ppinput->pp);

	char PhysicalPort[30]={0};
	
	strcpy(PhysicalPort,ppinput->pp);
	strcpy(dest_ip,     ppinput->ip);

	//读取自身文件名
	if(pysicalportDEVETESTIMPL <= 0)
	{
		char sysfile[15] = "/proc/self/exe";
		char selfname[256];
		memset(selfname,0,256);
		int selfnamelen=256;
		if (-1 != readlink(sysfile,selfname,selfnamelen))
		{
			printf("[%s] Self Name == %s\n",PhysicalPort,selfname);
		}
	}

	FILE *fp;
	char ch=0;
	int file_i=0;
	//读取配置文件
	//文件1：读取IP节点网口与IP地址对应关系文件
	char FILEIPNODEname[100];
	strcpy(FILEIPNODEname,FILEIPNODE);

	char IPNODEbuf[FILEIPNODELENTH];
	char IPNODEcmd[FILEIPNODELENTH/50][50];

	if((fp=fopen(FILEIPNODEname,"r"))==NULL)
	{
		printf("Cannot open routingtable file!\n");
	}
	else
	{
		file_i = 0;
		while ((ch=fgetc(fp))!=EOF)
			IPNODEbuf[file_i++]=ch;
		if(file_i == 0)
		{
			fclose(fp);
			return 0;
		}
		IPNODEbuf[--file_i] = '\0';
		file_i = 0;
		fclose(fp);

		//为配置命令分行
		i=0;j=0;k=0;l=0;
		while(1)
		{
			if(IPNODEbuf[i] == 10 || IPNODEbuf[i] == 0)
			{
				l=0;
				while(j<i)
				{
					IPNODEcmd[k][l++] = IPNODEbuf[j++];
				}
				IPNODEcmd[k][l] = 0;

				j++;
				k++;
			}
			if(IPNODEbuf[i] == 0)
			{
				break;
			}
			i++;
		}

		//i,j==totallength; k==numofcmds;
		//逐行解析配置命令
		int IPNODEnid=0;
		int IPNODEpp=0;
		int IPNODEip=0;
		for(i=0,j=0;i<k;j=0,i++)
		{
			ipnodelistcount++;
		
			//NID input
			for(IPNODEnid=0;IPNODEcmd[i][j] != ' ' && IPNODEcmd[i][j] != 0;IPNODEnid++,j++)
				ipnodelist[ipnodelistcount].nid[IPNODEnid] = IPNODEcmd[i][j];
			ipnodelist[ipnodelistcount].nid[IPNODEnid] = 0;
printf("ipnodelist[ipnodelistcount].nid == %s\n",ipnodelist[ipnodelistcount].nid);
		
			j++;
		
			//physical port input
			for(IPNODEpp=0;IPNODEcmd[i][j] != ' ' && IPNODEcmd[i][j] != 0;IPNODEpp++,j++)
				ipnodelist[ipnodelistcount].pp[IPNODEpp] = IPNODEcmd[i][j];
			ipnodelist[ipnodelistcount].pp[IPNODEpp] = 0;
printf("ipnodelist[ipnodelistcount].pp  == %s\n",ipnodelist[ipnodelistcount].pp);

			j++;
		
			//IP input
			for(IPNODEip=0;IPNODEcmd[i][j] != ' ' && IPNODEcmd[i][j] != 0;IPNODEip++,j++)
				ipnodelist[ipnodelistcount].ip[IPNODEip] = IPNODEcmd[i][j];
			ipnodelist[ipnodelistcount].ip[IPNODEip] = 0;
printf("ipnodelist[ipnodelistcount].ip  == %s\n",ipnodelist[ipnodelistcount].ip);
		}
	}
	
	//确认输出配置结果
	printf("[FILEipnodelist]\n%s\n",IPNODEbuf);
	//printf("[input]SwitchDevice_local_ip  == %s\n",SwitchDevice_local_ip);
	
	//配置变量
	int configsuccess = 0;
	char local_ip[16]={0};
	uint8_t LocalMAC[6]={0};
	configsuccess = PhysicalPort_Configure(PhysicalPort,LocalMAC,local_ip);
	if(configsuccess == -1)
	{
		printf("[%s] Failed to Read Configure File! Existing...\n",PhysicalPort);
		exit(0);
	}
	if(configsuccess == 0)
	{
		printf("[%s] No Required Information in Configure File! Existing...\n",PhysicalPort);
		exit(0);
	}
	//检查MAC地址获取情况
	/*
	printf("LocalMAC = %x:%x:%x:%x:%x:%x\n",
	LocalMAC[0],
	LocalMAC[1],
	LocalMAC[2],
	LocalMAC[3],
	LocalMAC[4],
	LocalMAC[5]);
	*/

	//拷贝线程启动参数
	struct pplip pi;
	strcpy(pi.pp,PhysicalPort);
	strcpy(pi.lmac,LocalMAC);
	strcpy(pi.ip,local_ip);

	//创建下行发送子线程
	pthread_t pthread_send;
	if(pthread_create(&pthread_send, NULL, PhysicalPort_thread_send, (void *)&pi)!=0)
	{
		perror("Creation of send thread failed.");
	}

	//创建上行接收子线程
	pthread_t pthread_recv;
	if(pthread_create(&pthread_recv, NULL, PhysicalPort_thread_recv, (void *)&pi)!=0)
	{
		perror("Creation of recv thread failed.");
	}
	
	//主循环阻塞，不提供实际功能
	while(1)
	{
		sleep(10000);
	}
	
	return 0;
}
