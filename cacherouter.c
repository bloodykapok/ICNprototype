/*******************************************************************************************************************************************
* 文件名：cacherouter.c
* 文件描述：973智慧协同网络SAR系统TestBed套件——域内缓存路由器（Cache Router）——转发平面+路由获取
* 声明：本模板代码作者王兆旭，为北京交通大学下一代互联网互联设备国家工程实验室新生基础工程技术培训专用。作者王兆旭在此郑重声明，此文件及其它用于培训的模板代码均为本人精力与经验的产物，本资源的传播方式均为作者本人向他人进行一对一传授，任何个人不得向第三方转交或展示该资源内容。任何有需求的学员，均须向王兆旭本人直接索要，亦无向他人索要或传授之权利和义务。因有些资源内容涉及实验室项目秘密，暂不考虑申请专利保护或软件著作权等事宜，故个别资源仅限实验室内部一对一发放，如发现有辜负作者本人的一片好意的行为，作者将保留就其原创性进行追查、举证、申诉和问责的权利。本资源的发放权归作者本人所有，其整理和总结过程浸透无偿贡献的热忱和为诸君学业尽绵薄之力的真诚，愿学员尊重作者的劳动成果，谢谢合作！
* 作者：王兆旭
* 身份：北京交通大学下一代互联网互联设备国家工程实验室 2013级硕博连读研究生
* E-mail. hellozxwang@foxmail.com
* Mobile. 18811774990
* QQ    . 535667240
* Addr  . 北京市海淀区西直门外北京交通大学机械楼D706室, 100044
*******************************************************************************************************************************************/
/*******************************************************************************************************************************************
*****功能说明：1.接收由虚拟物理网口上传的SAR/CoLoR类型数据包；
**************2.读取路由表，根据NID决定转发的目的网口
**************3.将数据下传至选定的虚拟物理网口
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

//物理端口与其所属内部通信IP的映射表项
PPIP ppiplist[49];//声明映射表

//路由表项
RoutingTableEvent routingtable[100];//声明路由表

//CoLoR协议用于类型判断的字段（截止到固定首部，其中Version/Type字段为Get包、Data包、Register包所通用）
CoLoR_VersionType tempCoLoRwithoutMAC;

//CoLoR协议Get包首部（PID之前）字段长度可变，用于解析
CoLoR_get_parse tempGet;

//CoLoR协议Data包首部（PID之前）字段长度可变，用于解析
CoLoR_data_parse tempData;

//CoLoR协议Register包首部（PID之前）
CoLoR_register_parse tempRegister;

/*******************************************************************************************************************************************
*******************************************初始化参数配置相关********************************************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：CacheRouter_Parameterinit
* 功能描述：CacheRouter模块全局变量赋初值
* 参数列表：
* 返回结果：
*****************************************/
void
CacheRouter_Parameterinit()
{
	memset(SwitchDevice_local_ip,0,16);
	memcpy(SwitchDevice_local_ip,"127.1.1.1",9);
	memset(CacheRouter_dest_ip,0,16);

	memset(ppiplist,0,26*49);
	ppiplistcount=-1;

	memset(routingtable,0,50*100);
	routingtablecount=-1;

	//配置文件路径初始化
	strcpy(FILERTname,FILERT);

	//运行过程相关的中转及判断变量
	memset(tempNID,0,NIDLENst);

	//接收缓冲区
	RecvBUFLength = 0;
	memset(RecvBUF,0,BUFSIZE);
	//发送缓冲区
	SendBUFLength = 0;
	memset(SendBUF,0,BUFSIZE);

	//缓冲区列表参数初始化
	PkgBUFHead=0;
	PkgBUFTail=0;

	CacheRouter_PlaneOccupy = 0; //CacheRouter模块转发平面占用标识
	CacheRouter_UpOccupy = 0;    //CacheRouter模块上行通道占用标识
	CacheRouter_DownOccupy = 0;  //CacheRouter模块下行通道占用标识
}

/*******************************************************************************************************************************************
*******************************************转发平面 - From.来源虚拟物理网口 To.目标虚拟物理网口***********************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：CacheRouter_CoLoR_ParseGet
* 功能描述：解析CoLoR-Get包头
* 参数列表：
* 返回结果：
*****************************************/
static int
CacheRouter_CoLoR_ParseGet
(
	const CoLoR_get_parse * pkg
)
{
	int i;
	
	char* p;
	p = (char*)pkg;
	
	if (NULL == pkg)
	{
		return -1;
	}
	
	//解析Get包各字段
	//free(tempGet.sid);
	//free(tempGet.nid);
	//free(tempGet.data);
	//free(tempGet.publickey);

	//tempGet.version_type = pkg->version_type;
	//tempGet.ttl = pkg->ttl;
	tempGet.total_len = pkg->total_len;

	//tempGet.port_no = pkg->port_no;
	//tempGet.checksum = pkg->checksum;

	tempGet.sid_len = pkg->sid_len;
	tempGet.nid_len = pkg->nid_len;
	tempGet.pid_n = pkg->pid_n;
	//tempGet.options_static = pkg->options_static;

	//p += sizeof(uint8_t) * (14 + 12);
	p += sizeof(uint8_t) * (12+16);

	tempGet.publickey_len = (uint16_t)(*p);
	//tempGet.mtu = (uint16_t)(*(p+sizeof(uint16_t)));

	p += sizeof(uint16_t) * 2;

	//tempGet.sid = (uint8_t*)calloc(tempGet.sid_len,sizeof(uint8_t));
	//memcpy((uint8_t*)tempGet.sid,(uint8_t*)p,tempGet.sid_len);

	p += sizeof(uint8_t) * tempGet.sid_len;

	//tempGet.nid = (uint8_t*)calloc(tempGet.nid_len,sizeof(uint8_t));
	//memcpy((uint8_t*)tempGet.nid,(uint8_t*)p,tempGet.nid_len);

	p += sizeof(uint8_t) * (tempGet.nid_len/2);

	//tempNID = (uint8_t*)calloc(tempGet.nid_len/2,sizeof(uint8_t));
	memset(tempNID,0,NIDLENst);
	memcpy(tempNID,(uint8_t*)p,tempGet.nid_len/2);

	//p += sizeof(uint8_t) * tempGet.nid_len;
	
	int data_len_int = tempGet.total_len - 16 - 16 - tempGet.sid_len - tempGet.nid_len - tempGet.pid_n*4 - tempGet.publickey_len;

	//如果存在残包，恰好总长度字段或其它长度字段数值出现了错误又没有校验，则有可能出现data_len值为负值的情况，在这里需要排除掉
	if(data_len_int <= 0 || data_len_int > DATALENst)
	{
		if(netDEVETESTIMPL <= 2)
			printf("data_len == %d (break out)\n",data_len_int);
		return -1;
	}

	//uint16_t data_len = tempGet.total_len - 16 - 16 - tempGet.sid_len - tempGet.nid_len - tempGet.pid_n*4 - tempGet.publickey_len;
	//tempGet.data = (uint8_t*)calloc(data_len+1/*+1修正，是为结束符特别预留*/,sizeof(uint8_t));
	//memcpy((uint8_t*)tempGet.data,(uint8_t*)p,data_len);
	//*(tempGet.data+data_len) = '\0';//不清楚为什么唯独data后需要特别腾出1byte作为结束符否则会越界读取

	//p += sizeof(uint8_t) * data_len;

	//tempGet.publickey = (uint8_t*)calloc(tempGet.publickey_len,sizeof(uint8_t));
	//memcpy((uint8_t*)tempGet.publickey,(uint8_t*)p,tempGet.publickey_len);
	//memcpy(tempsid, tempGet.sid, tempGet.sid_len/*SID长度*/);

	//测试输出
	if(0)
	{
		p = (char*)pkg;
		
		printf(">>>CoLoR-Get  Received.\n");

		printf("   |====================GetPkg===================|\n");
		printf("   |version_type   = %d\n",tempGet.version_type);
		printf("   |ttl            = %d\n",tempGet.ttl);
		printf("   |total_len      = %d\n",tempGet.total_len);

		printf("   |port_no        = %d\n",tempGet.port_no);
		printf("   |checksum       = %d\n",tempGet.checksum);

		printf("   |sid_len        = %d\n",tempGet.sid_len);
		printf("   |nid_len        = %d\n",tempGet.nid_len);
		printf("   |pid_n          = %d\n",tempGet.pid_n);
		printf("   |options_static = %d\n",tempGet.options_static);

		//p += sizeof(uint8_t) * (14 + 12);
		p += sizeof(uint8_t) * (12+16);

		//printf("   |publickey_len = %d\n",tempGet.publickey_len);
		//printf("   |mtu = %d\n",tempGet.mtu);

		p += sizeof(uint16_t) * 2;

		//printf("   |sid = %s\n",tempGet.sid);

		p += sizeof(uint8_t) * tempGet.sid_len;

		//printf("   |nid = %s\n",tempGet.nid);

		p += sizeof(uint8_t) * (tempGet.nid_len/2);

		//printf("   |nid = %s\n",tempNID);

		//p += sizeof(uint8_t) * tempGet.nid_len;

		//printf("   |data = %s\n",tempGet.data);

		//p += sizeof(uint8_t) * data_len;

		//printf("   |publickey = %s\n",tempGet.publickey);

		printf("   |=============================================|\n");
	}

	return 1;
}

/*****************************************
* 函数名称：CacheRouter_CoLoR_ParseData
* 功能描述：解析CoLoR-Data包头
* 参数列表：
* 返回结果：
*****************************************/
static int
CacheRouter_CoLoR_ParseData
(
	const CoLoR_data_parse * pkg
)
{
	int i;
	
	char* p;
	p = (char*)pkg;
	
	if (NULL == pkg)

	{
		return -1;
	}
	
	//解析Data包各字段
	//free(tempData.sid);
	//free(tempData.nid);
	//free(tempData.data);
	
	//tempData.version_type = pkg->version_type;
	//tempData.ttl = pkg->ttl;
	tempData.total_len = pkg->total_len;

	//tempData.port_no = pkg->port_no;
	//tempData.checksum = pkg->checksum;

	tempData.sid_len = pkg->sid_len;
	tempData.nid_len = pkg->nid_len;
	tempData.pid_n = pkg->pid_n;
	//tempData.options_static = pkg->options_static;

	//p += sizeof(uint8_t) * (14 + 12);
	p += sizeof(uint8_t) * (12+16);

	//tempData.signature_algorithm = (uint8_t)(*p);
	//tempData.if_hash_cache = (uint8_t)(*(p+sizeof(uint8_t)));
	//tempData.options_dynamic = (uint16_t)(*(p+sizeof(uint16_t)));

	p += sizeof(uint32_t);

	//tempData.sid = (uint8_t*)calloc(tempData.sid_len,sizeof(uint8_t));
	//memcpy((uint8_t*)tempData.sid,(uint8_t*)p,tempData.sid_len);

	p += sizeof(uint8_t) * tempData.sid_len;

	//tempData.nid = (uint8_t*)calloc(tempData.nid_len,sizeof(uint8_t));
	//memcpy((uint8_t*)tempData.nid,(uint8_t*)p,tempData.nid_len);

	p += sizeof(uint8_t) * (tempData.nid_len/2);

	//tempNID = (uint8_t*)calloc(tempData.nid_len/2,sizeof(uint8_t));
	memset(tempNID,0,NIDLENst);
	memcpy(tempNID,(uint8_t*)p,tempData.nid_len/2);

	//p += sizeof(uint8_t) * tempData.nid_len;
	
	int data_len_int = tempData.total_len - 16 - 16 - tempData.sid_len - tempData.nid_len - tempData.pid_n*4 - 16;

	//如果存在残包，恰好总长度字段或其它长度字段数值出现了错误又没有校验，则有可能出现data_len值为负值的情况，在这里需要排除掉
	if(data_len_int <= 0 || data_len_int > DATALENst)
	{
		if(netDEVETESTIMPL <= 2)
			printf("data_len == %d (break out)\n",data_len_int);
		return -1;
	}

	//uint16_t data_len = tempData.total_len - sizeof(uint8_t)*(16+16+16) - tempData.sid_len - tempData.nid_len - tempData.pid_n*sizeof(uint8_t)*4;
	//tempData.data = (uint8_t*)calloc(data_len+1/*+1修正，是为结束符特别预留*/,sizeof(uint8_t));
	//memcpy((uint8_t*)tempData.data,(uint8_t*)p,data_len);
	//*(tempData.data+data_len) = '\0';//不清楚为什么唯独data后需要特别腾出1Byte作为结束符否则会越界读取

	//p += sizeof(uint8_t) * data_len;

/*
	for(i=0;i<16;i++)
	{
		tempData.data_signature[i] = (uint8_t)(*(p+sizeof(uint8_t)*i));

	}
*/

	//测试输出
	if(0)
	{
		p = (char*)pkg;

		printf (">>>CoLoR-Data Received.\n");

		printf ("   |====================Datapkg==================|\n");

		printf("   |version_type   = %d\n",tempData.version_type);
		printf("   |ttl            = %d\n",tempData.ttl);
		printf("   |total_len      = %d\n",tempData.total_len);

		printf("   |port_no        = %d\n",tempData.port_no);
		printf("   |checksum       = %d\n",tempData.checksum);

		printf("   |sid_len        = %d\n",tempData.sid_len);
		printf("   |nid_len        = %d\n",tempData.nid_len);
		printf("   |pid_n          = %d\n",tempData.pid_n);
		printf("   |options_static = %d\n",tempData.options_static);

		//p += sizeof(uint8_t) * (14 + 12);
		p += sizeof(uint8_t) * (12+16);

		//printf("   |signature_algorithm = %d\n",tempData.signature_algorithm);
		//printf("   |if_hash_cache = %d\n",tempData.if_hash_cache);
		//printf("   |options_dynamic = %d\n",tempData.options_dynamic);

		p += sizeof(uint32_t);

		//printf("   |sid = %s\n",tempData.sid);

		p += sizeof(uint8_t) * tempData.sid_len;

		//printf("   |nid = %s\n",tempData.nid);

		p += sizeof(uint8_t) * (tempData.nid_len/2);

		//printf("   |nid = %s\n",tempNID);

		//p += sizeof(uint8_t) * tempData.nid_len;

		//printf("   |data = %s\n",tempData.data);

		//p += sizeof(uint8_t) * data_len;

		//printf("   |data_signature = %s\n",tempData.data_signature);
		printf("   |=============================================|\n");
	}
	
	return 1;
}

/*****************************************
* 函数名称：CacheRouter_CoLoR_ParseRegister
* 功能描述：解析CoLoR-Register包头
* 参数列表：
* 返回结果：
*****************************************/
static int
CacheRouter_CoLoR_ParseRegister
(
	const CoLoR_register_parse * pkg
)
{
	int i;
	
	char* p;
	p = (char*)pkg;
	
	if (NULL == pkg)
	{
		return -1;
	}
	
	//解析Register包各字段
	tempRegister.total_len = pkg->total_len;

	tempRegister.nid_len = pkg->nid_len;

	p += sizeof(uint8_t) * (16+tempRegister.nid_len/2);

	//tempNID = (uint8_t*)calloc(tempRegister.nid_len/2,sizeof(uint8_t));
	memset(tempNID,0,NIDLENst);
	memcpy(tempNID,(uint8_t*)p,tempRegister.nid_len/2);
	
	return 0;
}

/*****************************************
* 函数名称：CacheRouter_FindDest
* 功能描述：寻找数据包中的NID字段，判断其转发方向
* 参数列表：
* 返回结果：
*****************************************/
int
CacheRouter_FindDest
(
	const CoLoR_VersionType * pkg
)
{
	int infolen = -1;
	
	if(pkg->version_type == 160)//仅显示IP版本号为10，包类型为0（专属CoLoR-Get包  字段为1010 0000）的包
	{
		if(netDEVETESTIMPL <= 1)
			printf("[%s] This is a GET pkt.\n",SwitchDevice_local_ip);

		infolen = CacheRouter_CoLoR_ParseGet((CoLoR_get_parse*)pkg);
		if(infolen <= 0)
			return -1;
		
		RecvBUFLength = tempGet.total_len;
	}
	else if(pkg->version_type == 161)//仅显示IP版本号为10，包类型为1（专属CoLoR-Data包 字段为1010 0001）的包
	{
		if(netDEVETESTIMPL <= 1)
			printf("[%s] This is a DATA pkt.\n",SwitchDevice_local_ip);

		infolen = CacheRouter_CoLoR_ParseData((CoLoR_data_parse*)pkg);
		if(infolen <= 0)
			return -1;

		RecvBUFLength = tempData.total_len;
	}
	else if(pkg->version_type == 162)//仅显示IP版本号为10，包类型为2（专属CoLoR-Register包 字段为1010 0010）的包
	{
		if(netDEVETESTIMPL <= 1)
			printf("[%s] This is a REGISTER pkt.\n",SwitchDevice_local_ip);

		infolen = CacheRouter_CoLoR_ParseRegister((CoLoR_register_parse*)pkg);
		RecvBUFLength = tempRegister.total_len;
	}
	else
		printf("[%s] [ Recv WRONG ] version_type == %d\n",SwitchDevice_local_ip,pkg->version_type);

	if(netDEVETESTIMPL <= 1)
		printf("[%s] [ Find ] NID == %s\n",SwitchDevice_local_ip,tempNID);

	return infolen;
}

/*******************************************************************************************************************************************
**********************************************************多线程主干程序********************************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：CacheRouter_thread_recv
* 功能描述：接收来自物理网口PhysicalPort模块的数据包
* 参数列表：
* 返回结果：
*****************************************/
void *
CacheRouter_thread_recv
(
	void * fd
)
{
	char sourceip[16]={0};
	char sourcepp[30]={0};
	char destpp[30]={0};

	int sourcefound=0;
	int destfound=0;
	int portfound=0;

	int i,j;
	
	int socket_receiver;
	socket_receiver=socket(AF_INET,SOCK_DGRAM,0);

	struct sockaddr_in sin;
	int sockaddr_len=sizeof(struct sockaddr_in);
	bzero(&sin,sockaddr_len);
	sin.sin_family=AF_INET;
	//sin.sin_addr.s_addr=htonl(INADDR_ANY);
	sin.sin_addr.s_addr=inet_addr(SwitchDevice_local_ip);
	sin.sin_port=htons(localPORT);
	
	bind(socket_receiver,(struct sockaddr *)&sin,sockaddr_len);
	
	printf("UDP listening start...\n");

	while(1)
	{
		RecvBUFLength = 0;
		memset(RecvBUF,0,BUFSIZE);

		if(INTRACOMMUNICATION == 0)
			recvfrom(socket_receiver,RecvBUF,sizeof(RecvBUF),0,(struct sockaddr *)&sin,&sockaddr_len);
		else if(INTRACOMMUNICATION == 1)
		{
			sem_wait(&semPacketRECV);
			//printf("[Forwarding Plane]semPacketRECV triggered.\n");
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
			pthread_mutex_lock(&lockPkgBUF);
			for(;;)
			{
				if(PkgBUF[PkgBUFTail++].flag_occupied == 1)
				{
					LocalPkgBUFTail = PkgBUFTail-1;

					RecvBUFLength = PkgBUF[LocalPkgBUFTail].pkglength;
					memcpy(RecvBUF,"NET",3);
					memcpy(RecvBUF+3,PkgBUF[LocalPkgBUFTail].pkg,RecvBUFLength);
					strcpy(sourcepp,PkgBUF[LocalPkgBUFTail].sourcepp);

					if(PkgBUFTail>=10)
						PkgBUFTail -= 10;
					break;
				}
				
				if(PkgBUFTail>=10)
					PkgBUFTail -= 10;
			}
			//printf("[Forwarding Plane]pkg found.\n");
			pthread_mutex_unlock(&lockPkgBUF);
		}


		//usleep(7500);
		//第一时间检查CacheRouter模块转发平面中是否有其它数据包占用，如果有，直接丢包；如果没有，启动占用
		if(CacheRouter_PlaneOccupy == 1)
		{
			if(netDEVETESTIMPL <= 0)
				printf("CacheRouter ForwardingPlane Occupied\n");
			continue;
		}
		else
		{
			CacheRouter_PlaneOccupy = 1;
		}

		//Main Forwarding Procession with Routing Table
		if(strncmp(RecvBUF,"NET",3) == 0)
		{
			if(SEETIME >=1)
			{
				gettimeofday(&starttime,0);
				timefornow = 0;
			}
			
			if(netDEVETESTIMPL <= 1)
			{
				printf("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n\n");
				//printf("[%s] Got a NET message:%s\n",SwitchDevice_local_ip,RecvBUF);
				printf("[%s] Got a NET message.\n",SwitchDevice_local_ip);
			}
			
			bzero(sourceip,16);
			bzero(sourcepp,30);
			bzero(destpp,30);

			strcpy(sourceip,(const char*)inet_ntoa(sin.sin_addr));
			
			if(netDEVETESTIMPL <= 1)
				printf("[%s] [Source] IP == %s\n",SwitchDevice_local_ip,sourceip);
			
			/*
			//Search for the Source Physical Port
			sourcefound=0;
			for(j=0;j<=ppiplistcount;j++)

			{
				if(strncmp(sourceip,ppiplist[j].ip,16) == 0)

				{
					memcpy(sourcepp,ppiplist[j].pp,16);

					sourcefound=1;
					break;

				}
			}
			if(sourcefound==0)
			{

				printf("Do not found the proper source port to match the routingtable.\n");

				//对CacheRouter模块转发平面解除占用
				CacheRouter_PlaneOccupy = 0;
				if(netDEVETESTIMPL <= 0)
					printf("[%s] CacheRouter_PlaneOccupy == %d, released.\n",SwitchDevice_local_ip,CacheRouter_PlaneOccupy);

				continue;

			}
			printf("[Source] PhysicalPort == %s\n",sourcepp);
			*/

			if(SEETIME >=1)
			{
				gettimeofday(&forwardingtime,0);
				timefornow = 1000000*(forwardingtime.tv_sec - starttime.tv_sec) + forwardingtime.tv_usec - starttime.tv_usec;
				printf("%lf microsecond: initial parameter.\n",timefornow);
			}
			
			//Find the dest value in the "NET" packet
			int JudgeByte = -1;
			JudgeByte = CacheRouter_FindDest((CoLoR_VersionType*)(RecvBUF+3));

			//收到非CoLoR类的数据包或残包
			if(JudgeByte <= 0)
			{
				//对CacheRouter模块转发平面解除占用
				CacheRouter_PlaneOccupy = 0;
				if(netDEVETESTIMPL <= 0)
					printf("[%s] CacheRouter_PlaneOccupy == %d, released.(Bad Pakcet)\n",SwitchDevice_local_ip,CacheRouter_PlaneOccupy);

				continue;
			}
			
			if(SEETIME >=1)
			{
				gettimeofday(&forwardingtime,0);
				timefornow = 1000000*(forwardingtime.tv_sec - starttime.tv_sec) + forwardingtime.tv_usec - starttime.tv_usec;
				printf("%lf microsecond: Find the dest value in the packet.\n",timefornow);
			}

			//Search for the Location of Routing Table Event
			destfound=0;
			i=0;
			while(destfound==0)
			{
				if(strncmp(routingtable[i++].dest,tempNID,8) == 0)
				{
					destfound=1;
					i--;
				}
				if(i==routingtablecount+1)
				{
					break;
				}
			}
			memcpy(destpp,routingtable[i].port,30);

			if(SEETIME >=1)
			{
				gettimeofday(&forwardingtime,0);
				timefornow = 1000000*(forwardingtime.tv_sec - starttime.tv_sec) + forwardingtime.tv_usec - starttime.tv_usec;
				printf("%lf microsecond: Search for the Location of Routing Table Event.\n",timefornow);
			}

			if(netDEVETESTIMPL <= 1)
				printf("[%s] [ Dest ] PhysicalPort == %s\n",SwitchDevice_local_ip,destpp);
			
			//Search for the Dest IP address (UDP)
			if(destfound==1)
			{
				portfound=0;
				for(j=0;j<=ppiplistcount;j++)
				{
					if(strncmp(routingtable[i].port,ppiplist[j].pp,30) == 0)
					{
						memcpy(CacheRouter_dest_ip,ppiplist[j].ip,16);
						portfound=1;

						//将接收缓冲区数据包拷贝至发送缓冲区
						SendBUFLength = RecvBUFLength;
						memcpy(SendBUF,RecvBUF,BUFSIZE);
						
						if(INTRACOMMUNICATION == 0)
						{
							//创建socket
							//套接口描述字
							int socket_NETUtoNETD;
							socket_NETUtoNETD = socket(AF_INET,SOCK_DGRAM,0);

							struct sockaddr_in addrNtoS;
							bzero(&addrNtoS,sizeof(addrNtoS));
							addrNtoS.sin_family=AF_INET;
							addrNtoS.sin_port=htons(NETUtoNETD);
							//unsigned long IPto = 2130706433;//回环地址名称 == 2130706433
							//addrNtoS.sin_addr.s_addr=htonl(IPto);//htonl将主机字节序转换为网络字节序
							addrNtoS.sin_addr.s_addr=inet_addr(LOOPIP);//htonl将主机字节序转换为网络字节序
						
							//发送南向触发指令
							sendto(socket_NETUtoNETD,"NTOS",4,0,(struct sockaddr *)&addrNtoS,sizeof(addrNtoS));
							close(socket_NETUtoNETD);
						}
						else if(INTRACOMMUNICATION == 1)
						{
							sem_post(&semNTOS);
						}
						
						if(netDEVETESTIMPL <= 6)
							printf("[%s] NTOS sent.\n",SwitchDevice_local_ip);
						
						break;
					}
				}
				if(portfound==0)
				{
					if(netDEVETESTIMPL <= 2)
						printf("[%s] Do not found the proper port to forward message.\n",SwitchDevice_local_ip);

					//对CacheRouter模块转发平面解除占用
					CacheRouter_PlaneOccupy = 0;
					if(netDEVETESTIMPL <= 0)
						printf("[%s] CacheRouter_PlaneOccupy == %d, released.(Do Not Found Port)\n",SwitchDevice_local_ip,CacheRouter_PlaneOccupy);

					continue;
				}
			}
			else
			{
				if(netDEVETESTIMPL <= 2)
					printf("[%s] Do not found the proper routing table event to forward message.\n",SwitchDevice_local_ip);

				//对CacheRouter模块转发平面解除占用
				CacheRouter_PlaneOccupy = 0;
				if(netDEVETESTIMPL <= 0)
					printf("[%s] CacheRouter_PlaneOccupy == %d, released.(Do Not Found Routing)\n",SwitchDevice_local_ip,CacheRouter_PlaneOccupy);

				continue;//Print the content of message or not? "continue" for "No"
			}

			if(netDEVETESTIMPL <= 1)
				printf("[%s] [ Dest ] IP == %s\n",SwitchDevice_local_ip,CacheRouter_dest_ip);

			if(SEETIME >=1)
			{
				gettimeofday(&forwardingtime,0);
				timefornow = 1000000*(forwardingtime.tv_sec - starttime.tv_sec) + forwardingtime.tv_usec - starttime.tv_usec;
				printf("%lf microsecond: Search for the Dest IP address (UDP) and set ON-Signal for SEND thread.\n",timefornow);
			}
		}

		if(netDEVETESTIMPL <= -1)
		{
			printf("The Content of Packet NTOS:\n");
			int dd=0;
			char c;
			printf("\n");
			while(dd<100)
			{
				c = *(RecvBUF+3+dd);
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
		}
	}

	//关闭线程
	//exit(0);
	close(socket_receiver);
	free(fd);
	pthread_exit(NULL);
}

/*****************************************
* 函数名称：CacheRouter_thread_send
* 功能描述：向物理网口PhysicalPort模块发送数据包
* 参数列表：
* 返回结果：
*****************************************/
void *
CacheRouter_thread_send
(
	void * fd
)
{
	int i;
	
	int socket_recvNtoSSignal;
	socket_recvNtoSSignal = socket(AF_INET,SOCK_DGRAM,0);

	struct sockaddr_in addrSignal;
	int sockaddr_len=sizeof(struct sockaddr_in);
	bzero(&addrSignal,sockaddr_len);
	addrSignal.sin_family=AF_INET;
	//addrSignal.sin_addr.s_addr=htonl(INADDR_ANY);
	addrSignal.sin_addr.s_addr=inet_addr(LOOPIP);
	addrSignal.sin_port=htons(NETUtoNETD);

	bind(socket_recvNtoSSignal,(struct sockaddr *)&addrSignal,sockaddr_len);
	
	char signal[10];

	char sendbuf[BUFSIZE];
	
	int socket_sender;
	socket_sender=socket(AF_INET,SOCK_DGRAM,0);
	
	int portnum;
	while(1)
	{
		memset(signal,0,10);
		memset(sendbuf,0,BUFSIZE);
		
		if(INTRACOMMUNICATION == 0)
			recvfrom(socket_recvNtoSSignal,signal,sizeof(signal),0,(struct sockaddr *)&addrSignal,&sockaddr_len);
		else if(INTRACOMMUNICATION == 1)
		{
			sem_wait(&semNTOS);
			memcpy(signal,"NTOS",4);
		}

		if(strncmp(signal,"NTOS",4) != 0)
		{
			//对CacheRouter模块转发平面解除占用
			CacheRouter_PlaneOccupy = 0;
			if(netDEVETESTIMPL <= 6)
				printf("[%s] CacheRouter_PlaneOccupy == %d, released.(NOT NTOS)\n",SwitchDevice_local_ip,CacheRouter_PlaneOccupy);

			continue;
		}

		if(SEETIME >=1)
		{
			gettimeofday(&forwardingtime,0);
			timefornow = 1000000*(forwardingtime.tv_sec - starttime.tv_sec) + forwardingtime.tv_usec - starttime.tv_usec;
			printf("%lf microsecond: Prepare socket for SEND thread.\n",timefornow);
		}

		if(INTRACOMMUNICATION == 0)
		{
			struct sockaddr_in addrFrom;
			bzero(&addrFrom,sizeof(addrFrom));
			addrFrom.sin_family=AF_INET;
			//addrFrom.sin_addr.s_addr=htonl(INADDR_ANY);
			addrFrom.sin_addr.s_addr=inet_addr(SwitchDevice_local_ip);
			addrFrom.sin_port=htons(0);

			bind(socket_sender,(struct sockaddr *)&addrFrom,sizeof(addrFrom));

			memcpy(sendbuf,"FOR",3);
			memcpy(sendbuf+3,SendBUF+3,SendBUFLength);
		
			struct sockaddr_in addrTo;
			bzero(&addrTo,sizeof(addrTo));
			addrTo.sin_family=AF_INET;
			addrTo.sin_port=htons(destPORT);
			addrTo.sin_addr.s_addr=inet_addr(CacheRouter_dest_ip);
		
			if(SEETIME >=1)
			{
				gettimeofday(&forwardingtime,0);
				timefornow = 1000000*(forwardingtime.tv_sec - starttime.tv_sec) + forwardingtime.tv_usec - starttime.tv_usec;
				printf("%lf microsecond: Preparation of socket succeed.\n",timefornow);
			}

			if(netDEVETESTIMPL <= 1)
			{
				//printf("[%s] Message has been sent out:%s\n",SwitchDevice_local_ip,sendbuf);
				printf("[%s] Message has been sent out.\n",SwitchDevice_local_ip);
			}
		
			sendto(socket_sender,sendbuf,SendBUFLength+3,0,(struct sockaddr *)&addrTo,sizeof(addrTo));
		}
		else if(INTRACOMMUNICATION == 1)
		{
			for(i=15;i>=0;i--)
			{
				if(CacheRouter_dest_ip[i] == '.')
				{
					portnum = CacheRouter_dest_ip[i+2] - '0';
					PkgBUF[LocalPkgBUFTail].destppnum = portnum;
					sem_post(&semPacketSEND[portnum]);
					break;
				}
			}
		}

		//对CacheRouter模块转发平面解除占用
		CacheRouter_PlaneOccupy = 0;
		if(netDEVETESTIMPL <= 6)
			printf("[%s] CacheRouter_PlaneOccupy == %d, released.(NTOS recv)\n",SwitchDevice_local_ip,CacheRouter_PlaneOccupy);
	}

	//关闭线程
	//exit(0);
	close(socket_sender);
	free(fd);
	pthread_exit(NULL);
}


/*****************************************
* 函数名称：CacheRouter_main
* 功能描述：CacheRouter模块主函数，启动各个线程，自身不提供实际功能
* 参数列表：
* 返回结果：
*****************************************/
//int main(int argc,char *argv[])
int
CacheRouter_main
(
	int argc,char argv[][30]
)
{
	CacheRouter_Parameterinit();
	
	int i,j,k,l;
	
	printf("argc == %d\n",argc);
	for(i=0;i<argc;i++)
	{
		printf("argv[%d] == %s\n",i,argv[i]);
	}

	strcpy(NID,argv[1]);
	
	int ii;
	int numfound=0;
	char port[30];
	memset(port,0,30);
	char portnum[3]={0};
	for(i=2;i<argc;i++)
	{
		numfound=0;
		memset(port,0,30);
		memset(portnum,0,3);

		//提取物理网口名称末尾序号
		strcpy(port,argv[i]);

		for(ii=29;ii>=0;ii--)
		{
			if(port[ii] >= '0' && port[ii] <= '9' && numfound == 0)
			{
				numfound=1;
				portnum[1]=port[ii];
				continue;
			}
			if(port[ii] >= '0' && port[ii] <= '9' && numfound == 1)
			{
				numfound=2;
				portnum[0]=port[ii];
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

		//拷贝物理端口与其所属内部通信IP的映射表项
		strcpy(ppiplist[i-2].pp,port);
	
		strcpy(ppiplist[i-2].ip,SwitchDevice_local_ip);
		for(ii=0;ii<16;ii++)
		{
			if(ppiplist[i-2].ip[ii] == 0)
			{
				strcpy(ppiplist[i-2].ip+ii,portnum);
				break;
			}
		}
		ppiplistcount++;
	}

	//确定配置文件路径
	if(GLOBALTEST >= 1)
	{
		memset(FILERTname,0,FILEnameL);

		memset(domainID,0,10);
		memset(deviceNA,0,30);
		memset(deviceID,0,30);

		strcpy(domainID,NID);
		strcpy(deviceNA,NID);
		strcpy(deviceID,NID);

		int sliceflag=0;

		//抠取参数
		for(i=0;i<30;i++)
		{
			if(NID[i]==0)
				break;
			if(((NID[i] >= 'A' && NID[i] <= 'Z') || (NID[i] >= 'a' && NID[i] <= 'z')) && sliceflag == 0)
			{
				domainID[i]=0;
				deviceNA[i]=0;
				deviceID[i]=0;
printf("NID[%d] == %c, domainID[%d] == %c, deviceNA[%d] == %c, deviceID[%d] == %c\n",i,NID[i],i,domainID[i],i,deviceNA[i],i,deviceID[i]);
				continue;
			}
			else if(NID[i] >= '0' && NID[i] <= '9' && sliceflag == 0)
			{
				sliceflag=1;
				deviceNA[i]=0;
				deviceID[i]=0;
printf("NID[%d] == %c, domainID[%d] == %c, deviceNA[%d] == %c, deviceID[%d] == %c\n",i,NID[i],i,domainID[i],i,deviceNA[i],i,deviceID[i]);
				continue;
			}
			else if(sliceflag == 0)
			{
				printf("Input wrong!\n");
				exit(0);
			}

			if(NID[i] >= '0' && NID[i] <= '9' && sliceflag == 1)
			{
				deviceNA[i]=0;
				deviceID[i]=0;
printf("NID[%d] == %c, domainID[%d] == %c, deviceNA[%d] == %c, deviceID[%d] == %c\n",i,NID[i],i,domainID[i],i,deviceNA[i],i,deviceID[i]);
				continue;
			}
			else if(((NID[i] >= 'A' && NID[i] <= 'Z') || (NID[i] >= 'a' && NID[i] <= 'z')) && sliceflag == 1)
			{
				sliceflag=2;
				memset(domainID+i,0,10-i);
				deviceID[i]=0;
printf("NID[%d] == %c, domainID[%d] == %c, deviceNA[%d] == %c, deviceID[%d] == %c\n",i,NID[i],i,domainID[i],i,deviceNA[i],i,deviceID[i]);
				continue;
			}
			else if(sliceflag == 1)
			{
				printf("Input wrong!\n");
				exit(0);
			}

			if(((NID[i] >= 'A' && NID[i] <= 'Z') || (NID[i] >= 'a' && NID[i] <= 'z')) && sliceflag == 2)
			{
				deviceID[i]=0;
printf("NID[%d] == %c, domainID[%d] == %c, deviceNA[%d] == %c, deviceID[%d] == %c\n",i,NID[i],i,domainID[i],i,deviceNA[i],i,deviceID[i]);
				continue;
			}
			else if(NID[i] >= '0' && NID[i] <= '9' && sliceflag == 2)
			{
				sliceflag=3;
				memset(deviceNA+i,0,30-i);
printf("NID[%d] == %c, domainID[%d] == %c, deviceNA[%d] == %c, deviceID[%d] == %c\n",i,NID[i],i,domainID[i],i,deviceNA[i],i,deviceID[i]);
				continue;
			}
			else if(sliceflag == 2)
			{
				memset(deviceID,0,30);
			}
			if((NID[i] < '0' || NID[i] > '9') && sliceflag == 3)
			{
				memset(deviceID+i,0,30-i);
				break;
			}
		}

		int founddomainID=0;
		int founddeviceNA=0;
		int founddeviceID=0;

		//参数前置
		for(i=0;i<10;i++)
		{
			if(domainID[i]!=0 && founddomainID==0)
			{
				founddomainID=1;
				for(j=0;j<10;j++)
					domainID[j] = domainID[j+i];
				break;
			}
		}
		for(i=0;i<30;i++)
		{
			if(deviceNA[i]!=0 && founddeviceNA==0)
			{
				founddeviceNA=1;
				for(j=0;j<30;j++)
					deviceNA[j] = deviceNA[j+i];
				break;
			}
		}
		for(i=0;i<30;i++)
		{
			if(deviceID[i]!=0 && founddeviceID==0)
			{
				founddeviceID=1;
				for(j=0;j<30;j++)
					deviceID[j] = deviceID[j+i];
				break;
			}
		}

		printf("domainID == %s\n",domainID);
		printf("deviceNA == %s\n",deviceNA);
		printf("deviceID == %s\n",deviceID);

		//配置文件路径
		memset(FILERTname,0,FILEnameL);
		configure_RTfilepath(FILERTname,domainID,deviceNA,deviceID);
	}

	FILE *fp;
	char ch=0;
	int file_i=0;
	
	//文件1：读取路由表配置文件
	char RTbuf[RTLENTH];
	char RTcmd[RTLENTH/70][70];

	if((fp=fopen(FILERTname,"r"))==NULL)
	{
		printf("Cannot open routingtable file!\n");
	}
	else
	{
		file_i = 0;
		while ((ch=fgetc(fp))!=EOF)
			RTbuf[file_i++]=ch;
		if(file_i == 0)
		{
			fclose(fp);
			return 0;
		}
		RTbuf[--file_i] = '\0';
		file_i = 0;
		fclose(fp);

		//为配置命令分行
		i=0;j=0;k=0;l=0;
		while(1)
		{
			if(RTbuf[i] == 10 || RTbuf[i] == 0)
			{
				l=0;
				while(j<i)
				{
					RTcmd[k][l++] = RTbuf[j++];
				}
				RTcmd[k][l] = 0;

				j++;
				k++;
			}
			if(RTbuf[i] == 0)
			{
				break;
			}
			i++;
		}

		//i,j==totallength; k==numofcmds;
		//逐行解析配置命令
		//uint8_t sdest_mac[18]={0};
		//int dMACno=0;
		int RTdest=0;
		int RTport=0;
		for(i=0,j=0;i<k;j=0,i++)
		{
			routingtablecount++;
		
			//dest flag input
			for(RTdest=0;RTcmd[i][j] != ' ' && RTcmd[i][j] != 0;RTdest++,j++)
				routingtable[routingtablecount].dest[RTdest] = RTcmd[i][j];
			routingtable[routingtablecount].dest[RTdest] = 0;
		
			j++;
		
			//combined physical port input
			for(RTport=0;RTcmd[i][j] != ' ' && RTcmd[i][j] != 0;RTport++,j++)
				routingtable[routingtablecount].port[RTport] = RTcmd[i][j];
			routingtable[routingtablecount].port[RTport] = 0;
		}
	}
	
	//确认输出配置结果
	printf("[FILEroutingtable]\n%s\n",RTbuf);
	printf("[input]SwitchDevice_local_ip  == %s\n",SwitchDevice_local_ip);
	
	
	//创建recv子线程
	pthread_t pthread_recv;
	if(pthread_create(&pthread_recv, NULL, CacheRouter_thread_recv, NULL)!=0)
	{
		perror("Creation of recv thread failed.");
	}
	
	//创建send子线程
	pthread_t pthread_send;
	if(pthread_create(&pthread_send, NULL, CacheRouter_thread_send, NULL)!=0)
	{
		perror("Creation of send thread failed.");
	}

	//创建为physicalport模块输出的通信参数，并储存
	struct physicalportinput
	{
		char pp[30];
		char ip[16];
	}ppinput[100];

	pthread_t pthread_physicalport[100];

	for(i=2;i<argc;i++)
	{
		memset(ppinput[i].pp,0,30);
		strcpy(ppinput[i].pp,argv[i]);
		strcpy(ppinput[i].ip,SwitchDevice_local_ip);

		//printf("[SEND]ppinput[%d].pp == %s\n",i,ppinput[i].pp);
		
		//创建physicalport子线程
		if(pthread_create(&pthread_physicalport[i], NULL, thread_physicalport, (void *)&ppinput[i])!=0)
		{
			perror("Creation of physicalport thread failed.");
		}
	}
	
	//维持主线程的运行，没有实际功能
	while(1)
	{
		//尽可能大地减小CPU占用
		sleep(10000);
	}
	
	exit(0);
	return (EXIT_SUCCESS);
}


