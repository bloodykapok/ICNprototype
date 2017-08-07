/*******************************************************************************************************************************************
* 文件名：subscriber.c
* 文件描述：973智慧协同网络SAR系统TestBed套件——数据请求端（Data Subscriber）——浏览器支持+GET包封装发送+DATA包接收解析
* 声明：本模板代码作者王兆旭，为北京交通大学下一代互联网互联设备国家工程实验室新生基础工程技术培训专用。作者王兆旭在此郑重声明，此文件及其它用于培训的模板代码均为本人精力与经验的产物，本资源的传播方式均为作者本人向他人进行一对一传授，任何个人不得向第三方转交或展示该资源内容。任何有需求的学员，均须向王兆旭本人直接索要，亦无向他人索要或传授之权利和义务。因有些资源内容涉及实验室项目秘密，暂不考虑申请专利保护或软件著作权等事宜，故个别资源仅限实验室内部一对一发放，如发现有辜负作者本人的一片好意的行为，作者将保留就其原创性进行追查、举证、申诉和问责的权利。本资源的发放权归作者本人所有，其整理和总结过程浸透无偿贡献的热忱和为诸君学业尽绵薄之力的真诚，愿学员尊重作者的劳动成果，谢谢合作！
* 作者：王兆旭
* 身份：北京交通大学下一代互联网互联设备国家工程实验室 2013级硕博连读研究生
* E-mail. hellozxwang@foxmail.com
* Mobile. 18811774990
* QQ    . 535667240
* Addr  . 北京市海淀区西直门外北京交通大学机械楼D706室, 100044
*******************************************************************************************************************************************/
/*******************************************************************************************************************************************
*****功能说明：1.向物理网口发送包含请求SID的GET类型包
**************2.接收由物理网口监听的SAR/CoLoR类型数据包；
**************3.从接收到的DATA包中提取SID对应的Data
**************4.向上以HTTP协议对接浏览器，实现数据的请求和回送
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
gcc subscriber.c -o subscriber -lpthread
4、运行（因涉及原始套接字的使用，须root权限）
sudo ./subscriber
*/

#include"subscriber.h"

/*******************************************************************************************************************************************
*************************************宏定义配置数据************全局变量定义************包格式声明*********************************************
*******************************************************************************************************************************************/

//声明映射表
PPIP ppiplist[48];

//Ethernet层 / 用于CoLoR类型判断的包头（截止到固定首部，其中Version/Type字段为Get包、Data包、Register包所通用）
Ether_CoLoR_VersionType tempVersionType;

//Ethernet层 / CoLoR协议Get包首部（PID之前）字段长度固定，用于封装

//Ethernet层 / CoLoR协议Get包首部（PID之前）字段长度可变，用于解析
CoLoR_get_parse tempGet;

//Ethernet层 / CoLoR协议Data包首部（PID之前）字段长度固定，用于封装

//Ethernet层 / CoLoR协议Data包首部（PID之前）字段长度可变，用于解析
CoLoR_data_parse tempData;

//Ethernet层 / CoLoR协议Register包首部（PID之前）
CoLoR_register_parse tempRegister;

/*******************************************************************************************************************************************
*******************************************初始化参数配置相关********************************************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：Subscriber_Parameterinit
* 功能描述：Subscriber模块全局变量赋初值
* 参数列表：
* 返回结果：
*****************************************/
void
Subscriber_Parameterinit()
{
	memset(PhysicalPort,0,30);//网卡端口

	//本机配置信息
	memset(SwitchDevice_local_ip,0,16);
	memcpy(SwitchDevice_local_ip,"127.1.1.1",9);//这里的赋值就无效，放到本函数靠下端的位置就有效，同样的初始化代码仅RM出现这个问题，奇怪
	memset(Subscriber_dest_ip,0,16);

	//接收缓冲区
	RecvBUFLength = 0;
	memset(RecvBUF,0,BUFSIZE);
	//发送缓冲区
	SendBUFLength = 0;
	memset(SendBUF,0,BUFSIZE);
	//缓冲区列表参数初始化
	PkgBUFHead=0;
	PkgBUFTail=0;

	//全局变量
	//专用于各种字符串格式化的中间暂存变量
	memset(temp,0,100);
	memset(tempdata,0,DATALEN);
	memset(tempSID,0,SIDLEN);
	//已知用于主函数接收HTTP请求与其调用函数之间的数值传递
	memset(SID,0,SIDLEN);

	Subscriber_selfpacketdonotcatch=0;

	memset(local_mac,0,7);
	memset(local_ip,0,5);
	memset(dest_ip,0,16);

	uint8_t bm1[7]={0xff,0xff,0xff,0xff,0xff,0xff,0x00};
	memcpy(broad_mac1,bm1,7);
	uint8_t bm2[7]={0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	memcpy(broad_mac2,bm2,7);

	memset(destmac,0,7);
	memset(localmac,0,7);

	//uint8_t sn[NIDLEN] = {'d','2','s','u','b','1',0,0,'d','2','r','m',0,0,0,0};
	//memcpy(sendnid,sn,NIDLEN);
	memset(sendnid,0,NIDLEN);
}

/*******************************************************************************************************************************************
*******************************************应用层服务器**************************************************************************************
*******************************************************************************************************************************************/

/*******************************************************************************************************************************************
*******************************************上行通道 - From.虚拟物理网口 To.应用层服务器*******************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：Subscriber_CoLoR_ParsePacket
* 功能描述：CoLoR包解析函数
* 参数列表：
* 返回结果：
*****************************************/
int
Subscriber_CoLoR_ParsePacket
(
	const uint8_t * Packet,
	uint8_t * info
)
{	
	int PacketType = -1;
	int infolen = -1;
	
	CoLoR_VersionType * pkgvt = 0;
	CoLoR_get * pkgget = 0;
	CoLoR_data * pkgdata = 0;
	CoLoR_register * pkgregister = 0;
	
	//判断CoLoR数据包类型
	pkgvt = (CoLoR_VersionType *)Packet;

	PacketType = Subscriber_CoLoR_SeeType(pkgvt);
	
	if(PacketType == 0)//收到Get包
	{
		pkgget  = (CoLoR_get *)Packet;
		infolen = Subscriber_CoLoR_ParseGet(pkgget,info);
	}
	else if(PacketType == 1)//收到Data包
	{
		pkgdata  = (CoLoR_data *)Packet;
		infolen = Subscriber_CoLoR_ParseData(pkgdata,info);
		if(infolen <= 0)
			return -1;
	}
	else if(PacketType == 2)//收到Register包
	{
		pkgregister  = (CoLoR_register *)Packet;
		infolen = Subscriber_CoLoR_ParseRegister(pkgregister,info);
	}
	else//包类型不属于CoLoR协议
	{
	}
	
	return infolen;
}

/*****************************************
* 函数名称：Subscriber_CoLoR_SeeType
* 功能描述：判断是否为、为何种CoLoR包头
* 参数列表：
* 返回结果：
*****************************************/
int
Subscriber_CoLoR_SeeType
(
	const CoLoR_VersionType * pkg
)
{
	int i;
	struct protoent *pstIpProto = NULL;
	
	if (NULL == pkg)
	{
		return -1;
	}
	
	//版本、协议类型
	//int version = pkg->version_type / 16;//取version_type字段8位二进制数的前四位，即取IP版本号
	//int type    = pkg->version_type % 16;//取version_type字段8位二进制数的后四位，即取CoLoR包类型号
	if(pkg->version_type == 160)//仅显示IP版本号为10，包类型为0（专属CoLoR-Get包  字段为1010 0000）的包
	{
		return 0;
	}
	else if(pkg->version_type == 161)//仅显示IP版本号为10，包类型为1（专属CoLoR-Data包 字段为1010 0001）的包
	{
		return 1;
	}
	else if(pkg->version_type == 162)//仅显示IP版本号为10，包类型为2（专属CoLoR-Register包 字段为1010 0010）的包
	{
		return 2;
	}
	else
		printf("[ Recv WRONG ] version_type == %s\n",pkg->version_type);
	
	
	return -1;
}

/*****************************************
* 函数名称：Subscriber_CoLoR_ParseGet
* 功能描述：解析CoLoR-Get包头
* 参数列表：
* 返回结果：
*****************************************/
int
Subscriber_CoLoR_ParseGet
(
	const CoLoR_get * pkg,
	uint8_t * info
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
	

	/*
	memcpy((uint8_t*)tempGet.ether_dhost,(uint8_t*)pkg->ether_dhost,6);
	memcpy((uint8_t*)tempGet.ether_shost,(uint8_t*)pkg->ether_shost,6);
	tempGet.ether_type = pkg->ether_type;
	*/
	
	tempGet.version_type = pkg->version_type;
	tempGet.ttl = pkg->ttl;
	tempGet.total_len = pkg->total_len;
	tempGet.port_no = pkg->port_no;
	tempGet.checksum = pkg->checksum;
	tempGet.sid_len = pkg->sid_len;
	tempGet.nid_len = pkg->nid_len;
	tempGet.pid_n = pkg->pid_n;
	tempGet.options_static = pkg->options_static;

	//p += sizeof(uint8_t) * (14 + 12);
	p += sizeof(uint8_t) * 12;

	memset(tempGet.offset,0,OFFLENst);
	memcpy(tempGet.offset,(uint8_t*)p,OFFLEN);

	p+= sizeof(uint8_t) * 16;
	
	tempGet.publickey_len = (uint16_t)(*p);
	tempGet.mtu = (uint16_t)(*(p+sizeof(uint16_t)));
	
	p += sizeof(uint16_t) * 2;
	
	//tempGet.sid = (uint8_t*)calloc(tempGet.sid_len,sizeof(uint8_t));
	memset(tempGet.sid,0,SIDLENst);
	memcpy(tempGet.sid,(uint8_t*)p,tempGet.sid_len);

	memcpy(info,tempGet.sid,tempGet.sid_len);
	
	p += sizeof(uint8_t) * tempGet.sid_len;
	
	//tempGet.nid = (uint8_t*)calloc(tempGet.nid_len,sizeof(uint8_t));
	memset(tempGet.nid,0,NIDLENst);
	memcpy(tempGet.nid,(uint8_t*)p,tempGet.nid_len);
	
	p += sizeof(uint8_t) * tempGet.nid_len;
	
	uint16_t data_len = tempGet.total_len - 16 - 16 - tempGet.sid_len - tempGet.nid_len - tempGet.pid_n*4 - tempGet.publickey_len;
	//tempGet.data = (uint8_t*)calloc(data_len+1/*+1修正，是为结束符特别预留*/,sizeof(uint8_t));
	memset(tempGet.data,0,DATALENst);
	memcpy(tempGet.data,(uint8_t*)p,data_len);
	*(tempGet.data+data_len) = '\0';//不清楚为什么唯独data后需要特别腾出1byte作为结束符否则会越界读取
	
	p += sizeof(uint8_t) * data_len;
	
	//tempGet.publickey = (uint8_t*)calloc(tempGet.publickey_len,sizeof(uint8_t));
	memset(tempGet.publickey,0,PUBKEYLENst);
	memcpy(tempGet.publickey,(uint8_t*)p,tempGet.publickey_len);

	if(DEVETESTIMPL <= 1)
		printf(">>>CoLoR-Get  Received.\n");
	if(DEVETESTIMPL <= 0)
	{
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
		printf("   |publickey_len  = %d\n",tempGet.publickey_len);
		printf("   |mtu            = %d\n",tempGet.mtu);
		printf("   |sid            = %s\n",tempGet.sid);
		printf("   |nid            = %s\n",tempGet.nid);
		//printf("   |data           = %s\n",tempGet.data);
		printf("   |publickey      = %s\n",tempGet.publickey);
		printf("   |=============================================|\n");
	}
	
	return tempGet.sid_len;
}

/*****************************************
* 函数名称：Subscriber_CoLoR_ParseData
* 功能描述：解析CoLoR-Data包头
* 参数列表：
* 返回结果：
*****************************************/
int
Subscriber_CoLoR_ParseData
(
	const CoLoR_data * pkg,
	uint8_t * info
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
	
	/*
	memcpy((uint8_t*)tempData.ether_dhost,(uint8_t*)pkg->ether_dhost,6);
	memcpy((uint8_t*)tempData.ether_shost,(uint8_t*)pkg->ether_shost,6);
	tempData.ether_type = pkg->ether_type;
	*/

	tempData.version_type = pkg->version_type;
	tempData.ttl = pkg->ttl;
	tempData.total_len = pkg->total_len;
	tempData.port_no = pkg->port_no;
	tempData.checksum = pkg->checksum;
	tempData.sid_len = pkg->sid_len;
	tempData.nid_len = pkg->nid_len;
	tempData.pid_n = pkg->pid_n;
	tempData.options_static = pkg->options_static;
	
	//p += sizeof(uint8_t) * (14 + 12);
	p += sizeof(uint8_t) * 12;

	memset(tempData.offset,0,OFFLENst);
	memcpy(tempData.offset,(uint8_t*)p,OFFLEN);

	p+= sizeof(uint8_t) * 16;
	
	tempData.signature_algorithm = (uint8_t)(*p);
	tempData.if_hash_cache = (uint8_t)(*(p+sizeof(uint8_t)));
	tempData.options_dynamic = (uint16_t)(*(p+sizeof(uint16_t)));
	
	p += sizeof(uint32_t);

	//tempData.sid = (uint8_t*)calloc(tempData.sid_len,sizeof(uint8_t));
	memset(tempData.sid,0,SIDLENst);
	memcpy(tempData.sid,(uint8_t*)p,tempData.sid_len);
	
	p += sizeof(uint8_t) * tempData.sid_len;

	//tempData.nid = (uint8_t*)calloc(tempData.nid_len,sizeof(uint8_t));
	memset(tempData.nid,0,NIDLENst);
	memcpy(tempData.nid,(uint8_t*)p,tempData.nid_len);
	
	p += sizeof(uint8_t) * tempData.nid_len;
	
	int data_len_int = tempData.total_len - 16 - 16 - tempData.sid_len - tempData.nid_len - tempData.pid_n*4 - 16;

	//如果存在残包，恰好总长度字段或其它长度字段数值出现了错误又没有校验，则有可能出现data_len值为负值的情况，在这里需要排除掉
	if(data_len_int <= 0 || data_len_int > DATALENst)
	{
		if(DEVETESTIMPL <= 2)
			printf("data_len == %d (break out)\n",data_len_int);
		return -1;
	}
	
	uint16_t data_len = data_len_int;

	//tempData.data = (uint8_t*)calloc(data_len+1/*+1修正，是为结束符特别预留*/,sizeof(uint8_t));
	memset(tempData.data,0,DATALENst);

	memcpy(tempData.data,(uint8_t*)p,data_len);

	*(tempData.data+data_len) = '\0';//不清楚为什么唯独data后需要特别腾出1Byte作为结束符否则会越界读取

	memcpy(info,tempData.data,data_len);
	
	p += sizeof(uint8_t) * data_len;

	for(i=0;i<16;i++)
	{
		tempData.data_signature[i] = (uint8_t)(*(p+sizeof(uint8_t)*i));
	}

	if(DEVETESTIMPL <= 1)
		printf(">>>CoLoR-Data Received.\n");//输出从MAC层收到CoLoR-Data的提示
	if(DEVETESTIMPL <= 0)
	{
		printf("   |====================Datapkg==================|\n");
		printf("   |version_type        = %d\n",tempData.version_type);
		printf("   |ttl                 = %d\n",tempData.ttl);
		printf("   |total_len           = %d\n",tempData.total_len);
		printf("   |port_no             = %d\n",tempData.port_no);
		printf("   |checksum            = %d\n",tempData.checksum);
		printf("   |sid_len             = %d\n",tempData.sid_len);
		printf("   |nid_len             = %d\n",tempData.nid_len);
		printf("   |pid_n               = %d\n",tempData.pid_n);
		printf("   |options_static      = %d\n",tempData.options_static);
		printf("   |signature_algorithm = %d\n",tempData.signature_algorithm);
		printf("   |if_hash_cache       = %d\n",tempData.if_hash_cache);
		printf("   |options_dynamic     = %d\n",tempData.options_dynamic);
		printf("   |sid                 = %s\n",tempData.sid);
		printf("   |nid                 = %s\n",tempData.nid);
		//printf("   |data                = %s\n",tempData.data);
		printf("   |data_signature      = %s\n",tempData.data_signature);
		printf("   |=============================================|\n");
	}
	
	return data_len;
}

/*****************************************
* 函数名称：Subscriber_CoLoR_ParseRegister
* 功能描述：解析CoLoR-Register包头
* 参数列表：
* 返回结果：
*****************************************/
int
Subscriber_CoLoR_ParseRegister
(
	const CoLoR_register * pkg,
	uint8_t * info
)
{
	int i;
	
	if (NULL == pkg)
	{
		return -1;
	}
	//解析Register包各字段
	//不清楚Register包格式，待添加
	
	if(DEVETESTIMPL <= 1)
		printf (">>>CoLoR-Register from Somewhere. Type : %d\n",pkg->version_type%16);
	
	return 0;
}

/*****************************************
* 函数名称：Subscriber_SendtoAPPLayer
* 功能描述：向应用层服务器返回响应消息
* 参数列表：
* 返回结果：
*****************************************/
int
Subscriber_SendtoAPPLayer
(
	char * DATA,
	int DATAlen
)
{
	int i;
	
	int socket_datasender;
	socket_datasender = socket(AF_INET,SOCK_DGRAM,0);
	
	uint8_t pkg[sizeof(Trans_data)];
	Trans_data * ppkg;
	ppkg = (Trans_data *)pkg;

	memset(pkg,0,sizeof(Trans_data));

	memcpy(ppkg->data,DATA,DATALEN);
	memcpy(ppkg->offset,tempData.offset,OFFLEN);

	//封装消息
	/*
	memcpy(pkg,"GOT",3);
	memcpy(pkg+3,DATA,DATAlen);//按照DATA的实际长度发送
	//memcpy(pkg+3,DATA,DATALEN);//忽略DATA的实际长度，按照标准DATA数据字段长度发送
	memcpy(pkg+3+DATAlen,"OFF",3);
	memcpy(pkg+3+DATAlen+3,tempData.offset,OFFLEN);
	*/
	
	//封装套接字
	struct sockaddr_in addrTo;
	bzero(&addrTo,sizeof(addrTo));
	addrTo.sin_family=AF_INET;
	addrTo.sin_port=htons(TRALtoAPPL);
	addrTo.sin_addr.s_addr=inet_addr(LOOPIP);
	
	sendto(socket_datasender,pkg,sizeof(Trans_data),0,(struct sockaddr *)&addrTo,sizeof(addrTo));
	close(socket_datasender);

	if(DEVETESTIMPL <= 1)
		printf("GOT pkg has been sent to the DATA server, pkg == %s\n",pkg);

	return 1;
}

/*******************************************************************************************************************************************
*******************************************下行通道 - From.应用层服务器 To.虚拟物理网口*******************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：Subscriber_CoLoR_PacketGet
* 功能描述：组装不含mac层的Get包
* 参数列表：
* 返回结果：
*****************************************/
int
Subscriber_CoLoR_PacketGet
(
	uint8_t * pkg,
	uint8_t * SID,
	uint8_t * OFF
)
{
	CoLoR_get * getpkg;
	getpkg = (CoLoR_get *)pkg;
	
	//填充CoLoR-Get包文
	getpkg->version_type = 160;//版本4位，类型4位，此为设置成CoLoR_get包
	getpkg->ttl = 255;//生存时间
	//getpkg->data_len = htons(4);
	getpkg->total_len = 16 + 16 + SIDLEN + NIDLEN + DATALEN + PUBKEYLEN + PIDN*4;//总长度
	
	getpkg->port_no = 0;//端口号
	getpkg->checksum = 0;//检验和
	
	getpkg->sid_len = SIDLEN;//SID长度
	getpkg->nid_len = NIDLEN;//NID长度
	getpkg->pid_n = PIDN;//PID长度
	getpkg->options_static = 0;//固定首部选项

	memset(getpkg->offset,0,OFFLEN);
	memcpy(getpkg->offset,OFF,OFFLEN);
	
	memcpy(getpkg->sid, SID, SIDLEN);//SID

	char nid[NIDLEN] = {'d','1','s','u','b','1',0,0,'d','1','r','m',0,0,0,0};
	memcpy(getpkg->nid, sendnid, NIDLEN);//NID
	
	getpkg->publickey_len = PUBKEYLEN;
	getpkg->mtu = MTU;
	
	char data[DATALEN] = {'I',' ','a','m',' ','t','h','e',' ','d','a','t','a','~','~','~','~','~','~','!'};
	memcpy(getpkg->data, data, DATALEN);//Data
	
	char publickey[PUBKEYLEN] = {'I',' ','a','m',' ','t','h','e',' ','p','u','b','k','e','y','!'};
	memcpy(getpkg->publickey, publickey, PUBKEYLEN);//公钥

	return 1;
}

/*****************************************
* 函数名称：Subscriber_SendtoPhysicalPort
* 功能描述：向虚拟物理网口发送数据包
* 参数列表：
* 返回结果：
*****************************************/
int
Subscriber_SendtoPhysicalPort
(
	uint8_t * pkg
)
{
	int i;

	memset(DownPKG,0,PKGSIZE);
	
	//封装发往虚拟物理网口的消息
	memcpy(DownPKG,"FOR",3);
	memcpy(DownPKG+3,pkg,sizeof(CoLoR_get));
	
	//Search for the Dest IP address (UDP)
	int portfound=0;
	for(i=0;i<=ppiplistcount;i++)
	{
		if(ppiplist[i].pp[0] != 0)
		{
			memcpy(Subscriber_dest_ip,ppiplist[i].ip,16);
			portfound=1;
			break;
		}
	}
	if(portfound==0)
	{
		printf("[%s] Do not found the proper port to forward message.\n",SwitchDevice_local_ip);
		return 0;
	}

	//Getting ready to send pkg to physical port
	int portnum;
	int LocalPkgBUFHead;
	if(INTRACOMMUNICATION == 0)
	{
		int socket_sender;
		socket_sender=socket(AF_INET,SOCK_DGRAM,0);

		struct sockaddr_in addrTo;
		bzero(&addrTo,sizeof(addrTo));
		addrTo.sin_family=AF_INET;
		addrTo.sin_port=htons(destPORT);
		addrTo.sin_addr.s_addr=inet_addr(Subscriber_dest_ip);
	
		if(DEVETESTIMPL <= 1)
			printf("[%s] Message has been sent out:%s\n",SwitchDevice_local_ip,DownPKG);

		sendto(socket_sender,DownPKG,sizeof(CoLoR_get)+3,0,(struct sockaddr *)&addrTo,sizeof(addrTo));
		close(socket_sender);
	}
	else if(INTRACOMMUNICATION == 1)
	{
		pthread_mutex_lock(&lockPkgBUF);
		for(i=15;i>=0;i--)
		{
			if(Subscriber_dest_ip[i] == '.')
			{
				portnum = Subscriber_dest_ip[i+2] - '0';

				if(PkgBUF[PkgBUFHead].flag_occupied == 0)
				{
					LocalPkgBUFHead = PkgBUFHead;
					PkgBUFHead++;
					if(PkgBUFHead >=10)
						PkgBUFHead -= 10;
		
					PkgBUF[LocalPkgBUFHead].flag_occupied = 1;
					PkgBUF[LocalPkgBUFHead].pkglength = sizeof(CoLoR_get);
					PkgBUF[LocalPkgBUFHead].destppnum = portnum;
					strcpy(PkgBUF[LocalPkgBUFHead].sourcepp,PhysicalPort);
					memcpy(PkgBUF[LocalPkgBUFHead].pkg,DownPKG+3,sizeof(CoLoR_get));

					if(pysicalportDEVETESTIMPL <= 1)
					{
						printf("[] SEM Message has been sent to NetworkLayer:\n");
						printf("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n\n");
					}
				}
				else
				{
					if(pysicalportDEVETESTIMPL <= 1)
					{
						printf("[] SEM Message failed to be sent to NetworkLayer:\n");
						printf("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n\n");
					}
				}

				sem_post(&semPacketSEND[portnum]);
				break;
			}
		}
		pthread_mutex_unlock(&lockPkgBUF);
	}

	return 1;
}

/*******************************************************************************************************************************************
**********************************************************多线程主干程序********************************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：Subscriber_thread_timer
* 功能描述：为各线程提供计时信号
* 参数列表：
* 返回结果：
*****************************************/
void *
Subscriber_thread_timer
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
* 函数名称：Subscriber_thread_PhysicalPorttoAPPLayer
* 功能描述：上行通道 - From.虚拟物理网口 To.应用层服务器
* 参数列表：
* 返回结果：
*****************************************/
void *
Subscriber_thread_PhysicalPorttoAPPLayer
(
	void * fd
)
{
	int i;

	int socket_receiver;
	socket_receiver = socket(AF_INET,SOCK_DGRAM,0);

	struct sockaddr_in sin;
	int sockaddr_len=sizeof(struct sockaddr_in);
	bzero(&sin,sockaddr_len);
	sin.sin_family=AF_INET;
	//sin.sin_addr.s_addr=htonl(INADDR_ANY);
	sin.sin_addr.s_addr=inet_addr(SwitchDevice_local_ip);
	sin.sin_port=htons(localPORT);
	
	bind(socket_receiver,(struct sockaddr *)&sin,sockaddr_len);
	
	printf("UDP listening start...\n");

	int SIDDATAlen;
	uint8_t SIDDATA[100];
	memset(SIDDATA,0,100);

	while(1)
	{
		memset(RecvBUF,0,sizeof(RecvBUF));
		SIDDATAlen = -1;
		memset(SIDDATA,0,100);

		if(INTRACOMMUNICATION == 0)
			recvfrom(socket_receiver,RecvBUF,sizeof(RecvBUF),0,(struct sockaddr *)&sin,&sockaddr_len);
		else if(INTRACOMMUNICATION == 1)
		{
			sem_wait(&semPacketRECV);
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

/*待废除代码
			pthread_mutex_lock(&lockPkgBUF);
			for(;;)
			{
				if(PkgBUF[PkgBUFTail++].flag_occupied == 1)
				{
					LocalPkgBUFTail = PkgBUFTail-1;

					RecvBUFLength = PkgBUF[LocalPkgBUFTail].pkglength;
					memcpy(RecvBUF,"NET",3);
					memcpy(RecvBUF+3,PkgBUF[LocalPkgBUFTail].pkg,RecvBUFLength);
					//strcpy(sourcepp,PkgBUF[LocalPkgBUFTail].sourcepp);

					break;
				}
				
				if(PkgBUFTail>=10)
					PkgBUFTail -= 10;
			}
			pthread_mutex_unlock(&lockPkgBUF);
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
					//strcpy(sourcepp,PkgBUF[LocalPkgBUFTail].sourcepp);

					//清空转发表项，解除占用
					memset(PkgBUF[LocalPkgBUFTail].sourcepp,0,30);
					memset(PkgBUF[LocalPkgBUFTail].pkg,0,MTU);
					PkgBUF[LocalPkgBUFTail].destppnum = 0;
					PkgBUF[LocalPkgBUFTail].pkglength = 0;
					PkgBUF[LocalPkgBUFTail].flag_occupied = 0;

					//释放CacheList缓存位置
					for(i=0;i<10;i++)
					{
						memset(CacheList[i].physicalport,0,30);
						memset(CacheList[i].sid,0,SIDLEN);
						memset(CacheList[i].sbd,0,SBDLEN);
						memset(CacheList[i].offset,0,OFFLEN);
						memset(CacheList[i].cache,0,CACHESIZE);
						CacheList[i].cachetop = 0;
						CacheList[i].datapkglocation = -1;
						CacheList[i].flag_ack = 0;
						CacheList[i].flag_occupied = 0;
					}

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

		//Main Forwarding Procession with Routing Table
		if(strncmp(RecvBUF,"NET",3) == 0)
		{
			//解析CoLoR包
			SIDDATAlen = Subscriber_CoLoR_ParsePacket(RecvBUF+3,SIDDATA);
			//包类型不属于CoLoR协议，如果网络中没有IP包，就意味着收到的CoLoR数据包原本就是破损的
			if(SIDDATAlen <= 0)
				continue;

			//向应用层服务器返回响应消息
			Subscriber_SendtoAPPLayer(SIDDATA,SIDDATAlen);
		}
	}

	//关闭线程
	close(socket_receiver);
	exit(0);
	free(fd);
	pthread_exit(NULL);
}

/*****************************************
* 函数名称：Subscriber_thread_APPLayertoPhysicalPort
* 功能描述：下行通道 - From.应用层服务器 To.虚拟物理网口
* 参数列表：
* 返回结果：
*****************************************/
void *
Subscriber_thread_APPLayertoPhysicalPort
(
	void * fd
)
{
	int socket_sidreceiver;
	socket_sidreceiver = socket(AF_INET,SOCK_DGRAM,0);
	
	struct sockaddr_in sin;
	int sockaddr_len=sizeof(struct sockaddr_in);
	bzero(&sin,sockaddr_len);
	sin.sin_family=AF_INET;
	//sin.sin_addr.s_addr=htonl(INADDR_ANY);
	sin.sin_addr.s_addr=inet_addr(LOOPIP);
	sin.sin_port=htons(APPLtoTRAL);

	bind(socket_sidreceiver,(struct sockaddr *)&sin,sockaddr_len);

	uint8_t SID[SIDLEN];
	uint8_t OFF[OFFLEN];
	
	uint8_t recvpkg[sizeof(Trans_get)];
	Trans_get * precvpkg;
	precvpkg = (Trans_get *)recvpkg;
	uint8_t sendpkg[sizeof(CoLoR_get)];
	
	while(1)
	{
		memset(SID,0,SIDLEN);
		memset(OFF,0,OFFLEN);
		memset(recvpkg,0,sizeof(Trans_get));
		memset(sendpkg,0,sizeof(CoLoR_get));
		
		recvfrom(socket_sidreceiver,recvpkg,sizeof(Trans_get),0,(struct sockaddr *)&sin,&sockaddr_len);
		
		memcpy(SID,precvpkg->sid,SIDLEN);
		memcpy(OFF,precvpkg->offset,OFFLEN);

		//封装CoLoR-Get报文
		Subscriber_CoLoR_PacketGet(sendpkg,SID,OFF);

		//将CoLoR-Get报文发往虚拟物理网口
		Subscriber_SendtoPhysicalPort(sendpkg);
	}
	//关闭线程
	close(socket_sidreceiver);
	exit(0);
	free(fd);
	pthread_exit(NULL);
}

/*****************************************
* 函数名称：Subscriber_main
* 功能描述：Subscriber模块主函数，启动ForwardingPlane转发平面线程。自身主循环执行简单HTTP服务器功能。
* 参数列表：
eg: ./sub d1sub1 d1sub1-eth1
第二参数使用char**argv的方式声明报错，不知是不是语法问题
* 返回结果：
*****************************************/
//int main(int argc,char *argv[])
//Subscriber模块直接调用模式
/*
int
Subscriber_main
(
	int argc,
	char argv[][30]
)
*/
//Subscriber模块线程调用模式
void *
Subscriber_main
(
	void * fd
)
{
	int i,j,k,l;

	Subscriber_Parameterinit();

	//对Subscriber模块进行线程调用的参数拷贝接口
	struct subscriberinput * subinput;
	subinput = (struct subscriberinput *)fd;

	int argc = subinput->argc;
	char argv[50][30];
	memset(argv,0,1500);
	for(i=0;i<argc;i++)
	{
		strcpy(argv[i],subinput->argv[i]);
	}

	//参数处理
	printf("argc == %d\n",argc);
	for(i=0;i<argc;i++)
	{
		printf("argv[%d] == %s\n",i,argv[i]);
	}

	strcpy(NID,argv[1]);

	int ii;
	int numfound=0;
	char tempport[30];
	memset(tempport,0,30);
	char portnum[3]={0};
	for(i=2;i<argc;i++)
	{
		numfound=0;
		memset(tempport,0,30);
		memset(portnum,0,3);

		//提取物理网口名称末尾序号
		strcpy(tempport,argv[i]);

		for(ii=29;ii>=0;ii--)
		{
			if(tempport[ii] >= '0' && tempport[ii] <= '9' && numfound == 0)
			{
				numfound=1;
				portnum[1]=tempport[ii];
				continue;
			}
			if(tempport[ii] >= '0' && tempport[ii] <= '9' && numfound == 1)
			{
				numfound=2;
				portnum[0]=tempport[ii];
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
		strcpy(ppiplist[i-2].pp,tempport);
	
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
	if(GLOBALTEST <= 2)
	{
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

		//确定本域内的GET包请求目标，即本域RM的NID
		memcpy(sendnid,NID,NIDLEN/2);
		strcpy(sendnid+NIDLEN/2,"d");
		strcpy(sendnid+NIDLEN/2+1,domainID);
		for(i=NIDLEN/2+1;i<NIDLEN;i++)
		{
			if(sendnid[i]==0)
			{
				strcpy(sendnid+i,"rm");
				break;
			}
		}
	}
	
	//创建发送计时器子线程
	pthread_t pthread_timer;
	if(pthread_create(&pthread_timer, NULL, Subscriber_thread_timer, NULL)!=0)
	{
		perror("Creation of timer thread failed.");
	}
	
	//创建thread_PhysicalPorttoAPPLayer子线程
	pthread_t pthread_PhysicalPorttoAPPLayer;
	if(pthread_create(&pthread_PhysicalPorttoAPPLayer, NULL, Subscriber_thread_PhysicalPorttoAPPLayer, NULL)!=0)
	{
		perror("Creation of PhysicalPorttoAPPLayer thread failed.");
	}
	
	//创建thread_APPLayertoPhysicalPort子线程
	pthread_t pthread_APPLayertoPhysicalPort;
	if(pthread_create(&pthread_APPLayertoPhysicalPort, NULL, Subscriber_thread_APPLayertoPhysicalPort, NULL)!=0)
	{
		perror("Creation of APPLayertoPhysicalPort thread failed.");
	}

	//创建为physicalport模块输出的通信参数，并储存
	/*
	struct physicalportinput
	{
		char pp[30];
		char ip[16];
	};
	*/
	struct physicalportinput ppinput;
	memset(ppinput.pp,0,30);
	strcpy(ppinput.pp,argv[2]);
	strcpy(ppinput.ip,SwitchDevice_local_ip);

	pthread_t pthread_physicalport;
	//创建physicalport子线程
	if(pthread_create(&pthread_physicalport, NULL, thread_physicalport, (void *)&ppinput)!=0)
	{
		perror("Creation of physicalport thread failed.");
	}

	while(1)
	{
		sleep(10000);
	}

	printf("Subscriber_main exit success!\n");
	//return (EXIT_SUCCESS);
}
