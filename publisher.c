/*******************************************************************************************************************************************
* 文件名：publisher.c
* 文件描述：973智慧协同网络SAR系统TestBed套件——数据发布端（Data Publisher）——GET包接收解析+本地SID与Data匹配+DATA包封装发送
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
FILEsidname指存储SID与Data匹配关系的文件，默认文件名cache.log，路径需要运行该程序的人员自行决定，能与该文件实际存在的位置对上号就行了
PhysicalPort指CoLoR协议发出Get包和接收Data包的网卡端口，注意网卡的默认有线端口名称是否为eth0，而Fedora20系统中的默认名称为em1，请注意识别
2、系统设置
在Fedora系统中因需要使用原始套接字发送自定义格式的数据包，须关闭Fedora的防火墙，命令：
sudo systemctl stop firewalld.service
在Ubuntu系统中无需任何操作
3、编译命令
gcc publisher.c -o publisher -lpthread
4、运行（因涉及原始套接字的使用，须root权限）
sudo ./publisher
*/

#include"publisher.h"

/*******************************************************************************************************************************************
*************************************宏定义配置数据************全局变量定义************包格式声明*********************************************
*******************************************************************************************************************************************/

//声明映射表
PPIP ppiplist[48];

//Ethernet层 / 用于CoLoR类型判断的包头（截止到固定首部，其中Version/Type字段为Get包、Data包、Register包所通用）
Ether_CoLoR_VersionType tempVersionType;

//Ethernet层 / CoLoR协议Get包首部（PID之前）字段长度固定，用于封装

//Ethernet层 / CoLoR协议Get包首部（PID之前）字段长度可变，用于解析
Ether_CoLoR_get_parse tempGet;

//Ethernet层 / CoLoR协议Data包首部（PID之前）字段长度固定，用于封装

//Ethernet层 / CoLoR协议Data包首部（PID之前）字段长度可变，用于解析
Ether_CoLoR_data_parse tempData;

//Ethernet层 / CoLoR协议Register包首部（PID之前）
Ether_CoLoR_register tempRegister;

/*******************************************************************************************************************************************
*******************************************初始化参数配置相关********************************************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：Publisher_Parameterinit
* 功能描述：Publisher模块全局变量赋初值
* 参数列表：
* 返回结果：
*****************************************/
void
Publisher_Parameterinit()
{
	//网卡端口
	memset(PhysicalPort,0,30);

	//本机配置信息
	memset(SwitchDevice_local_ip,0,16);
	memcpy(SwitchDevice_local_ip,"127.1.1.1",9);//这里的赋值就无效，放到本函数靠下端的位置就有效，同样的初始化代码仅RM出现这个问题，奇怪
	memset(Publisher_dest_ip,0,16);

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
	Publisher_selfpacketdonotcatch=0;

	memset(tempsid,0,SIDLEN);
	memset(tempPIDs,0,120);

	memset(local_mac,0,7);
	memset(local_ip,0,5);
	memset(dest_ip,0,16);

	uint8_t bm1[7]={0xff,0xff,0xff,0xff,0xff,0xff,0x00};
	memcpy(broad_mac1,bm1,7);
	uint8_t bm2[7]={0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	memcpy(broad_mac2,bm2,7);

	memset(destmac,0,7);
	memset(localmac,0,7);

	//PID表项
	memset(pidlist,0,3000);
	pidlistcount=-1;
}

/*****************************************
* 函数名称：Publisher_configure_SIDfilepath
* 功能描述：自动配置节点SID注册配置文件的读取路径
* 参数列表：
* 返回结果：
*****************************************/
void
Publisher_configure_SIDfilepath
(
	char * SIDfilepath,
	char * domainID,
	char * deviceNA,
	char * deviceID
)
{
	int i;
	int zeropoint;

	strcpy(SIDfilepath,"./973domain/domain");

	for(i=0;i<FILEnameL;i++)
	{
		if(SIDfilepath[i]==0)
		{
			zeropoint=i;
			break;
		}
	}

	strcpy(SIDfilepath+zeropoint,domainID);

	for(i=0;i<FILEnameL;i++)
	{
		if(SIDfilepath[i]==0)
		{
			zeropoint=i;
			break;
		}
	}

	strcpy(SIDfilepath+zeropoint,"/");
	strcpy(SIDfilepath+zeropoint+1,deviceNA);

	for(i=0;i<FILEnameL;i++)
	{
		if(SIDfilepath[i]==0)
		{
			zeropoint=i;
			break;
		}
	}

	strcpy(SIDfilepath+zeropoint,deviceID);

	for(i=0;i<FILEnameL;i++)
	{
		if(SIDfilepath[i]==0)
		{
			zeropoint=i;
			break;
		}
	}

	strcpy(SIDfilepath+zeropoint,"/sid");

	printf("SIDfilepath == %s\n",SIDfilepath);
}

/*****************************************
* 函数名称：Publisher_configure_PIDfilepath

* 功能描述：自动配置节点PID通告表配置文件的读取路径
* 参数列表：
* 返回结果：
*****************************************/
void
Publisher_configure_PIDfilepath
(
	char * PIDfilepath,
	char * domainID,
	char * deviceNA,
	char * deviceID
)
{
	int i;
	int zeropoint;

	strcpy(PIDfilepath,"./973domain/domain");

	for(i=0;i<FILEnameL;i++)
	{
		if(PIDfilepath[i]==0)
		{
			zeropoint=i;
			break;
		}
	}

	strcpy(PIDfilepath+zeropoint,domainID);

	for(i=0;i<FILEnameL;i++)
	{
		if(PIDfilepath[i]==0)
		{
			zeropoint=i;
			break;
		}
	}

	strcpy(PIDfilepath+zeropoint,"/pid");

	printf("PIDfilepath == %s\n",PIDfilepath);
}

/*******************************************************************************************************************************************
*******************************************上行通道 - From.虚拟物理网口   To.应用服务器*******************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：Publisher_CoLoR_ParsePacket
* 功能描述：CoLoR包解析函数
* 参数列表：
* 返回结果：
*****************************************/
int
Publisher_CoLoR_ParsePacket
(
	const uint8_t * Packet,
	uint8_t * info
)
{	
	int PacketType = -1;
	int infolen = -1;
	
	CoLoR_VersionType * pkgvt = NULL;
	CoLoR_get * pkgget = NULL;
	CoLoR_data * pkgdata = NULL;
	CoLoR_register * pkgregister = NULL;
	
	//判断CoLoR数据包类型
	pkgvt = (CoLoR_VersionType *)Packet;

	PacketType = Publisher_CoLoR_SeeType(pkgvt);
	
	if(PacketType == 0)//收到Get包
	{
		pkgget  = (CoLoR_get *)Packet;
		infolen = Publisher_CoLoR_ParseGet(pkgget,info);
		if(infolen <= 0)
			return -1;
	}
	else if(PacketType == 1)//收到Data包
	{
		pkgdata  = (CoLoR_data *)Packet;
		infolen = Publisher_CoLoR_ParseData(pkgdata,info);
	}
	else if(PacketType == 2)//收到Register包
	{
		pkgregister  = (CoLoR_register *)Packet;
		infolen = Publisher_CoLoR_ParseRegister(pkgregister,info);
	}
	else//包类型不属于CoLoR协议
	{
	}
	
	return infolen;
}

/*****************************************
* 函数名称：Publisher_CoLoR_SeeType
* 功能描述：判断是否为、为何种CoLoR包头
* 参数列表：
* 返回结果：
*****************************************/
int
Publisher_CoLoR_SeeType
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
* 函数名称：Publisher_CoLoR_ParseGet
* 功能描述：解析CoLoR-Get包头
* 参数列表：
* 返回结果：
*****************************************/
int
Publisher_CoLoR_ParseGet
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
	
	int data_len_int = tempGet.total_len - 16 - 16 - tempGet.sid_len - tempGet.nid_len - tempGet.pid_n*4 - tempGet.publickey_len;

	//如果存在残包，恰好总长度字段或其它长度字段数值出现了错误又没有校验，则有可能出现data_len值为负值的情况，在这里需要排除掉
	if(data_len_int <= 0 || data_len_int > DATALENst)
	{
		if(DEVETESTIMPL <= 2)
			printf("data_len == %d (break out)\n",data_len_int);
		return -1;
	}

	uint16_t data_len = data_len_int;
	//tempGet.data = (uint8_t*)calloc(data_len+1,sizeof(uint8_t));
	memset(tempGet.data,0,DATALENst);
	memcpy(tempGet.data,(uint8_t*)p,data_len);
	*(tempGet.data+data_len) = 0;//不清楚为什么唯独data后需要特别腾出1byte作为结束符否则会越界读取
	
	p += sizeof(uint8_t) * data_len;
	
	//tempGet.publickey = (uint8_t*)calloc(tempGet.publickey_len,sizeof(uint8_t));
	memset(tempGet.publickey,0,PUBKEYLENst);
	memcpy(tempGet.publickey,(uint8_t*)p,tempGet.publickey_len);

	p += sizeof(uint8_t) * tempGet.publickey_len;
	
	//tempPIDs = (uint8_t*)calloc(tempGet.pid_n*4,sizeof(uint8_t));
	memset(tempPIDs,0,120);
	memcpy(tempPIDs,(uint8_t*)p,tempGet.pid_n*4);
	
	if(DEVETESTIMPL <= 1)
		printf(">>>CoLoR-Get  Received.\n");
	if(DEVETESTIMPL <= 0)
	{
		printf("   |====================Getpkg===================|\n");
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
		for(i=0;i<tempGet.pid_n;i++)
		{
		printf("   |PID%d          = %s\n",i+1,tempPIDs+i*4);
		}
		printf("   |=============================================|\n");
	}

	memcpy(tempsid, tempGet.sid, tempGet.sid_len);

	
	return tempGet.sid_len;
}

/*****************************************
* 函数名称：Publisher_CoLoR_ParseData
* 功能描述：解析CoLoR-Data包头
* 参数列表：
* 返回结果：
*****************************************/
int
Publisher_CoLoR_ParseData
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
	
	uint16_t data_len = tempData.total_len - sizeof(uint8_t)*(16+16+16) - tempData.sid_len - tempData.nid_len - tempData.pid_n*sizeof(uint8_t)*4;
	//tempData.data = (uint8_t*)calloc(data_len+1/*+1修正，是为结束符特别预留*/,sizeof(uint8_t));
	memset(tempData.data,0,DATALENst);
	memcpy(tempData.data,(uint8_t*)p,data_len);
	*(tempData.data+data_len) = 0;//不清楚为什么唯独data后需要特别腾出1Byte作为结束符否则会越界读取

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
		printf("   |version_type = %d\n",tempData.version_type);
		printf("   |ttl = %d\n",tempData.ttl);
		printf("   |total_len = %d\n",tempData.total_len);
		printf("   |port_no = %d\n",tempData.port_no);
		printf("   |checksum = %d\n",tempData.checksum);
		printf("   |sid_len = %d\n",tempData.sid_len);
		printf("   |nid_len = %d\n",tempData.nid_len);
		printf("   |pid_n = %d\n",tempData.pid_n);
		printf("   |options_static = %d\n",tempData.options_static);
		printf("   |signature_algorithm = %d\n",tempData.signature_algorithm);
		printf("   |if_hash_cache = %d\n",tempData.if_hash_cache);
		printf("   |options_dynamic = %d\n",tempData.options_dynamic);
		printf("   |sid = %s\n",tempData.sid);
		printf("   |nid = %s\n",tempData.nid);
		//printf("   |data = %s\n",tempData.data);
		printf("   |data_signature = %s\n",tempData.data_signature);
		printf("   |=============================================|\n");
	}
	
	return data_len;
}

/*****************************************
* 函数名称：Publisher_CoLoR_ParseRegister
* 功能描述：解析CoLoR-Register包头
* 参数列表：
* 返回结果：
*****************************************/
int
Publisher_CoLoR_ParseRegister
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

/*******************************************************************************************************************************************
*******************************************下行通道 - From.应用服务器 To.虚拟物理网口*********************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：Publisher_CoLoR_PacketData
* 功能描述：根据输入SID查找对应DATA并封装CoLoR-Data数据包（目前用于收到Get包后返回Data包的过程）
* 参数列表：
* 返回结果：
*****************************************/
int
Publisher_CoLoR_PacketData
(
	uint8_t * SID,
	uint8_t * DATA,
	uint8_t * offset,
	uint8_t * pkgdata
)
{
	int i,j;
	CoLoR_data * pkg = (CoLoR_data *)pkgdata;
	struct hostent *host =NULL;
	struct sockaddr sa;
	int sockfd,len;
	uint8_t temp_ip[5];

	uint8_t pkg_pids[PKGSIZE];
	//pkg_pids = (uint8_t*)calloc(16 +16 + SIDLEN + NIDLEN + tempGet.pid_n*4 + DATALEN + 16,sizeof(uint8_t));
	
	/*
	int SIDlen=0,DATAlen=0;
	for(i=0;i<SIDLEN;i++)
	{
		if(SID[i] == 0)
			break;
	}
	SIDlen = i;
	i=0;
	for(i=0;i<DATALEN;i++)
	{
		if(DATA[i] == 0)
			break;
	}
	DATAlen = i;
	i=0;
	*/
	
	//填充CoLoR-data包文
	pkg->version_type = 161;//版本4位，类型4位，此为设置成CoLoR_Data包
	pkg->ttl = 255;//生存时间
	pkg->total_len = 16 + 16 + SIDLEN + NIDLEN + tempGet.pid_n*4 + DATALEN + 16;//总长度
	
	pkg->port_no = 1;//端口号
	pkg->checksum = 0;//检验和
	
	pkg->sid_len = SIDLEN;//SID长度
	pkg->nid_len = NIDLEN;//NID长度
	pkg->pid_n = tempGet.pid_n;//PID长度
	//固定首部选项
	if(CNFON == 1)//CNF设定
		pkg->options_static = 32;
	else if(CNFON == 0)//CNF设定
		pkg->options_static = 0;
	
	
	memset(pkg->offset,0,OFFLEN);
	memcpy(pkg->offset,offset,OFFLEN);
	
	pkg->signature_algorithm = 1;//签名算法
	pkg->if_hash_cache = 255;//是否哈希4位，是否缓存4位
	pkg->options_dynamic = 0;//可变首部选项
	
	//拷贝SID
	memcpy(pkg->sid, SID, SIDLEN);

	//拷贝NID
	//char nid[NIDLEN] = {'I',' ','a','m',' ','t','h','e',' ','h','o','s','t','~','~','!'};
	int pidnidfound=0;

	static long flagerror=0;
	if(flagerror>2000000000)
		flagerror = 0;

	char destNID[NIDLEN/2];
	if(tempGet.pid_n != 0)
	{
		uint8_t judgedPID[4];
		memcpy(judgedPID,tempPIDs+(tempGet.pid_n-1)*4,4);

		i=0;
		pidnidfound=0;

		
		//对pidlist不明原因清空的bug没有对策，只好先将就把pidlist拷贝出来另存一个副本
		while(pidnidfound==0)
		{
			if(strncmp(pidlist2[i].pid,judgedPID,4) == 0)
			{
				strcpy(destNID,pidlist2[i].nid);
				pidnidfound=1;
			}
			i++;
			if(i==pidlistcount2+1)
			{
				break;
			}
		}
		


		if(pidnidfound == 0)
		{
			flagerror++;
			/*
			printf("===============================================================\n");
			printf("Do not found a proper NID for the PID. This is not normal.\n");
			printf("flagerror          = %ld\n",flagerror);
			printf("tempGet.pid_n      = %d\n",tempGet.pid_n);
			printf("tempPIDs+(tempGet.pid_n-1)*4 = %s\n",tempPIDs+(tempGet.pid_n-1)*4);
			printf("judgedPID                    = %s\n",judgedPID);
			
			printf("pidlistcount = %d\n",pidlistcount2);
			
			i=0;
			while(1)
			{
				printf("pidlist[i].pid = %s\n",pidlist2[i].pid);
				printf("pidlist[i].nid = %s\n",pidlist2[i].nid);
				i++;
				if(i==pidlistcount2+1)
				{
					break;
				}
			}
			*/
		}
		else
		{
		}
	}
	else
	{
		pidnidfound=1;
		memcpy(destNID,tempGet.nid,NIDLEN/2);
	}
	if(pidnidfound == 1)
	{
		memcpy(pkg->nid,tempGet.nid,NIDLEN/2);//NID
		memcpy(pkg->nid+NIDLEN/2,destNID,NIDLEN/2);//NID
	}
	else
	{
		if(DEVETESTIMPL <= 1)
			printf("Search for dest NID failed.\n");
	}
	
	if(DEVETESTIMPL <= 1)
	{
		printf("localNID == %s\n",pkg->nid);
		printf("NIDLEN/2 == %d\n",NIDLEN/2);
		printf("destNID  == %s\n",destNID);
		printf("pkg->total_len == %d\n",pkg->total_len);
	}
	
	//转移内存空间，拷贝PID
	memcpy(pkg_pids, (uint8_t*)pkg, pkg->total_len);
	memcpy(pkg_pids+pkg->total_len-16-DATALEN-tempGet.pid_n*4, (uint8_t*)tempPIDs, tempGet.pid_n*4);
	
	//拷贝DATA
	memcpy(pkg_pids+pkg->total_len-16-DATALEN, (uint8_t*)DATA, DATALEN);
	
	//拷贝Data Signature
	char data_signature[16] = {'I',' ','a','m',' ','t','h','e',' ','s','i','g','~','~','~','!'};
	memcpy(pkg_pids+pkg->total_len-16, data_signature, 16);
	
	memcpy(pkgdata,pkg_pids,pkg->total_len);
	
	return 1;
}

/*****************************************
* 函数名称：Publisher_SendtoPhysicalPort
* 功能描述：向虚拟物理网口发送数据包
* 参数列表：
* 返回结果：
*****************************************/
int
Publisher_SendtoPhysicalPort
(
	uint8_t * pkg
)
{
	int i;

	memset(DownPKG,0,PKGSIZE);
	
	//封装发往虚拟物理网口的消息
	memcpy(DownPKG,"FOR",3);
	memcpy(DownPKG+3,pkg,sizeof(CoLoR_data));
	
	//Search for the Dest IP address (UDP)
	int portfound=0;
	for(i=0;i<=ppiplistcount;i++)
	{
		if(ppiplist[i].pp[0] != 0)
		{
			memcpy(Publisher_dest_ip,ppiplist[i].ip,16);
			portfound=1;
			break;
		}
	}
	if(portfound==0)
	{
		printf("[%s] Do not found the proper port to forward message.\n",SwitchDevice_local_ip);
		return 0;
	}

	//为CNF开辟初始传输的缓存数据块
	if(CNFON == 1 && CacheList[0].flag_occupied == 0)//第一缓存块未被占用，说明该转发节点为传输的始发节点（如果不是始发，则在上一跳接收中，第一缓存块一定会被占用，故未被占用是不可能出现的情形）
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

	//Getting ready to send pkg to physical port
	int portnum;
	int LocalPkgBUFHead;
	if(INTRACOMMUNICATION == 0)
	{
		int socket_sender;
		socket_sender = socket(AF_INET,SOCK_DGRAM,0);

		struct sockaddr_in addrTo;
		bzero(&addrTo,sizeof(addrTo));
		addrTo.sin_family=AF_INET;
		addrTo.sin_port=htons(destPORT);
		addrTo.sin_addr.s_addr=inet_addr(Publisher_dest_ip);
	
		if(DEVETESTIMPL <= 1)
			printf("[%s] Message has been sent out:%s\n",SwitchDevice_local_ip,DownPKG);

		sendto(socket_sender,DownPKG,sizeof(CoLoR_data)+3,0,(struct sockaddr *)&addrTo,sizeof(addrTo));
		close(socket_sender);
	}
	else if(INTRACOMMUNICATION == 1)
	{
		pthread_mutex_lock(&lockPkgBUF);
		for(i=15;i>=0;i--)
		{
			if(Publisher_dest_ip[i] == '.')
			{
				portnum = Publisher_dest_ip[i+2] - '0';

				if(PkgBUF[PkgBUFHead].flag_occupied == 0)
				{
					LocalPkgBUFHead = PkgBUFHead;
					PkgBUFHead++;
					if(PkgBUFHead >=10)
						PkgBUFHead -= 10;
		
					PkgBUF[LocalPkgBUFHead].flag_occupied = 1;
					PkgBUF[LocalPkgBUFHead].pkglength = sizeof(CoLoR_data);
					PkgBUF[LocalPkgBUFHead].destppnum = portnum;
					strcpy(PkgBUF[LocalPkgBUFHead].sourcepp,PhysicalPort);
					memcpy(PkgBUF[LocalPkgBUFHead].pkg,DownPKG+3,sizeof(CoLoR_data));

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
* 函数名称：Publisher_thread_PhysicalPorttoAPPLayer
* 功能描述：上行通道 - From.虚拟物理网口   To.应用服务器
* 参数列表：
* 返回结果：
*****************************************/
void *
Publisher_thread_PhysicalPorttoAPPLayer
(
	void * fd
)
{
	int i;
	
	//创建socket：接收链路层包
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
	
	//创建socket：发送传输层包
	int socket_sidsender;
	socket_sidsender = socket(AF_INET,SOCK_DGRAM,0);

	struct sockaddr_in addrTo;
	bzero(&addrTo,sizeof(addrTo));
	addrTo.sin_family=AF_INET;
	addrTo.sin_port=htons(NETLtoTRAL);
	addrTo.sin_addr.s_addr=inet_addr(LOOPIP);

	printf("UDP listening start...\n");

	int SIDlen;
	uint8_t SID[SIDLEN];
	uint8_t OFF[OFFLEN];

	uint8_t sendpkg[sizeof(CoLoR_get)];
	Trans_data * psendpkg;
	psendpkg = (Trans_data *)sendpkg;

	while(1)
	{
		memset(RecvBUF,0,sizeof(RecvBUF));

		SIDlen = 0;
		memset(SID,0,SIDLEN);
		memset(sendpkg,0,sizeof(CoLoR_get));

		//接收链路层包
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

					if(PkgBUFTail>=10)
						PkgBUFTail -= 10;

					break;
				}
				
				if(PkgBUFTail>=10)
					PkgBUFTail -= 10;
			}
			pthread_mutex_unlock(&lockPkgBUF);
		}
		
		if(DEVETESTIMPL <= 1)
			printf("Publisher: A new UDP message received.\n");

		//Main Forwarding Procession with Routing Table
		if(strncmp(RecvBUF,"NET",3) == 0)
		{
			//解析CoLoR包
			SIDlen = Publisher_CoLoR_ParsePacket(RecvBUF+3,SID);
			//包类型不属于CoLoR协议，如果网络中没有IP包，就意味着收到的CoLoR数据包原本就是破损的
			if(SIDlen <= 0)
				continue;

			//封装链路层包：SID,offset
			memcpy(psendpkg->sid,SID,SIDLEN);
			memcpy(psendpkg->offset,tempGet.offset,OFFLEN);

			//发送传输层包
			sendto(socket_sidsender,sendpkg,sizeof(CoLoR_get),0,(struct sockaddr *)&addrTo,sizeof(addrTo));
			
			if(DEVETESTIMPL <= 1)
				printf("   Starting to search for the SID: %s\n",SID);
		}
	}
	close(socket_receiver);
	close(socket_sidsender);

	//关闭线程
	exit(0);
	free(fd);
	pthread_exit(NULL);
}

/*****************************************
* 函数名称：Publisher_thread_APPLayertoPhysicalPort
* 功能描述：下行通道 - From.应用服务器 To.虚拟物理网口
* 参数列表：
* 返回结果：
*****************************************/
void *
Publisher_thread_APPLayertoPhysicalPort
(
	void * fd
)
{
	int i,j;

	//接收上层发来的DATA响应
	int socket_datareceiver;
	socket_datareceiver = socket(AF_INET,SOCK_DGRAM,0);

	struct sockaddr_in sin;
	int sockaddr_len=sizeof(struct sockaddr_in);
	bzero(&sin,sockaddr_len);
	sin.sin_family=AF_INET;
	//sin.sin_addr.s_addr=htonl(INADDR_ANY);
	sin.sin_addr.s_addr=inet_addr(LOOPIP);
	sin.sin_port=htons(TRALtoNETL);

	bind(socket_datareceiver,(struct sockaddr *)&sin,sockaddr_len);
	
	uint8_t datapkg[sizeof(CoLoR_data)+120];
	
	uint8_t SID[SIDLEN];
	uint8_t DATA[DATALEN];
	uint8_t offset[OFFLEN];

	uint8_t recvpkg[sizeof(Trans_data)];
	Trans_data * precvpkg;
	precvpkg = (Trans_data *)recvpkg;

	while(1)
	{
		memset(DATA,0,DATALEN);
		memset(offset,0,OFFLEN);
		
		memset(recvpkg,0,sizeof(Trans_data));
		memset(datapkg,0,sizeof(CoLoR_data)+120);

		recvfrom(socket_datareceiver,recvpkg,sizeof(Trans_data),0,(struct sockaddr *)&sin,&sockaddr_len);
		
		if(DEVETESTIMPL <= 1)
			printf("Publisher: A north to south UDP message received.\n");
		memcpy(DATA,precvpkg->data,DATALEN);
		memcpy(SID,precvpkg->sid,SIDLEN);
		memcpy(offset,precvpkg->offset,OFFLEN);
		
		//封装CoLoR-Data报文
		Publisher_CoLoR_PacketData(SID,DATA,offset,datapkg);

		//将CoLoR-Data报文发往虚拟物理网口
		Publisher_SendtoPhysicalPort(datapkg);

		/*
		i=0;
		j=0;
		//获取来自应用层服务器的DATA响应消息
		if(strncmp(message,"GOT",3) == 0)
		{
			i+=2;
			for(j=0,i++;j<DATALEN;j++,i++)
			{
				if(1)
				{
					DATA[j] = message[i];
				}
				else
					break;
			}
			DATA[j] = 0;
			//printf("DATA = %s\n",DATA);

			i+=2;
			for(j=0;;j++)
			{
				i++;
				if(!(message[i]=='O' && message[i+1]=='F' && message[i+2]=='F'))
				{
					SID[j] = message[i];
				}
				else
					break;
			}
			SID[j] = 0;

			i+=2;
			for(j=0;j<OFFLEN;j++)
			{
				i++;
				offset[j] = message[i];

			}
			offset[j] = 0;
			
			//没有正常接收到SID和对应的DATA
			//if(DATA[0] == 0 || SID[0] == 0)
				//continue;
			
			//封装CoLoR-Data报文
			Publisher_CoLoR_PacketData(SID,DATA,offset,datapkg);

			//将CoLoR-Data报文发往虚拟物理网口
			Publisher_SendtoPhysicalPort(datapkg);
		}
		*/
	}
	close(socket_datareceiver);

	//关闭线程
	exit(0);
	free(fd);
	pthread_exit(NULL);
}

/*****************************************
* 函数名称：Publisher_main
* 功能描述：Publisher模块主函数，启动各个线程，自身不提供实际功能
* 参数列表：第二参数使用char**argv的方式声明报错，不知是不是语法问题
* 返回结果：
*****************************************/
//int main(int argc, char *argv[])
//Publisher模块直接调用模式
/*
int
Publisher_main
(
	int argc,
	char argv[][30]
)
*/
//Publisher模块线程调用模式
void *
Publisher_main
(
	void * fd
)
{
	int i,j,k,l;

	Publisher_Parameterinit();

	//对Publisher模块进行线程调用的参数拷贝接口
	struct publisherinput * pubinput;
	pubinput = (struct publisherinput *)fd;

	int argc = pubinput->argc;
	char argv[50][30];
	memset(argv,0,1500);
	for(i=0;i<argc;i++)
	{
		strcpy(argv[i],pubinput->argv[i]);
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
		memset(FILEsidname,0,FILEnameL);
		memset(FILEpidname,0,FILEnameL);
		Publisher_configure_SIDfilepath(FILEsidname,domainID,deviceNA,deviceID);
		Publisher_configure_PIDfilepath(FILEpidname,domainID,deviceNA,deviceID);
	}

	FILE *fp;
	char ch=0;
	int file_i=0;
	
	//文件1：读取PID注册文件
	char PIDbuf[PIDLENTH];
	char PIDcmd[PIDLENTH/32][32];

	if((fp=fopen(FILEpidname,"r"))==NULL)
	{
		printf("cannot open PID file!\n");
		exit(0);
	}

	file_i = 0;
	while ((ch=fgetc(fp))!=EOF)
		PIDbuf[file_i++]=ch;

	if(file_i == 0)
	{
		printf("FILEpid is empty!\n");
		fclose(fp);
		exit(0);
	}
	PIDbuf[--file_i] = 0;
	file_i = 0;

	fclose(fp);

	//为配置命令分行
	i=0;j=0;k=0;l=0;
	while(1)
	{
		if(PIDbuf[i] == 10 || PIDbuf[i] == 0)
		{
			l=0;
			while(j<i)
			{
				PIDcmd[k][l++] = PIDbuf[j++];
			}
			PIDcmd[k][l] = 0;

			j++;
			k++;
		}
		if(PIDbuf[i] == 0)
		{
			break;
		}
		i++;
	}

	//i,j==totallength; k==numofcmds;
	//逐行解析配置命令
	int higherupsno=0;
	int PIDdidno=0;
	int PIDpidno=0;
	int PIDnidno=0;
	for(i=0,j=0;i<k;j=0,i++)
	{
		if(strncmp("higherups",PIDcmd[i],9) == 0)
		{
			continue;
		}
		else
		{
			pidlistcount++;
		
			//DID input
			for(PIDdidno=0;PIDcmd[i][j] != ' ' && PIDcmd[i][j] != 0;PIDdidno++,j++)
				pidlist[pidlistcount].did[PIDdidno] = PIDcmd[i][j];
			pidlist[pidlistcount].did[PIDdidno] = 0;

			j++;

			//PID input
			for(PIDpidno=0;PIDcmd[i][j] != ' ' && PIDcmd[i][j] != 0;PIDpidno++,j++)
				pidlist[pidlistcount].pid[PIDpidno] = PIDcmd[i][j];
			pidlist[pidlistcount].pid[PIDpidno] = 0;
		
			j++;

			//NID input
			for(PIDnidno=0;PIDcmd[i][j] != ' ' && PIDcmd[i][j] != 0;PIDnidno++,j++)
				pidlist[pidlistcount].nid[PIDnidno] = PIDcmd[i][j];
			pidlist[pidlistcount].nid[PIDnidno] = 0;
			
			continue;
		}
	}
	
	printf("[FILEpid]\n%s\n",PIDbuf);
	
	i=0;
	pidlistcount2 = pidlistcount;
	while(1)
	{
		strcpy(pidlist2[i].did,pidlist[i].did);
		strcpy(pidlist2[i].pid,pidlist[i].pid);
		strcpy(pidlist2[i].nid,pidlist[i].nid);
		i++;
		if(i == pidlistcount2 + 1)
			break;
	}

	//文件2：读取SID缓存文件
	char SIDbuf[SIDLENTH];
	char SIDcmd[SIDLENTH/32][32];
	int sidlistcount=0;

	if((fp=fopen(FILEsidname,"r"))==NULL)
	{
		printf("cannot open SID file!\n");
		exit(0);
	}

	file_i = 0;
	while ((ch=fgetc(fp))!=EOF)
		SIDbuf[file_i++]=ch;

	if(file_i == 0)
	{
		printf("FILEpid is empty!\n");
		fclose(fp);
		exit(0);
	}
	SIDbuf[--file_i] = 0;
	file_i = 0;

	fclose(fp);

	//为配置命令分行
	i=0;j=0;k=0;l=0;
	while(1)
	{
		if(SIDbuf[i] == 10 || SIDbuf[i] == 0)
		{
			l=0;
			while(j<i)
			{
				SIDcmd[k][l++] = SIDbuf[j++];
			}
			SIDcmd[k][l] = 0;

			j++;
			k++;
		}
		if(SIDbuf[i] == 0)
		{

			break;
		}
		i++;
	}

	//i,j==totallength; k==numofcmds;
	//逐行解析配置命令
	int SIDno=0;
	for(i=0,j=0;i<k;j=0,i++)
	{
		sidlistcount++;
		
		//SID shaping
		for(SIDno=0;SIDcmd[i][j] != ' ' && SIDcmd[i][j] != 0;SIDno++,j++)
			continue;
		bzero(SIDcmd[i]+j,32-j-1);
	}

	//文件3：读取IP节点网口与IP地址对应关系文件
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
			exit(0);
		}
		IPNODEbuf[--file_i] = 0;
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
	printf("[FILEsid]\n%s\n",SIDbuf);
	printf("[FILEipnodelist]\n%s\n",IPNODEbuf);

	printf("Get packet listening...\n");



	//创建thread_PhysicalPorttoAPPLayer子线程
	pthread_t pthread_PhysicalPorttoAPPLayer;
	if(pthread_create(&pthread_PhysicalPorttoAPPLayer, NULL, Publisher_thread_PhysicalPorttoAPPLayer, NULL)!=0)
	{
		perror("Creation of recv thread failed.");
	}
	
	//创建thread_APPLayertoPhysicalPort子线程
	pthread_t pthread_APPLayertoPhysicalPort;
	if(pthread_create(&pthread_APPLayertoPhysicalPort, NULL, Publisher_thread_APPLayertoPhysicalPort, NULL)!=0)
	{
		perror("Creation of send thread failed.");
	}

	//创建为physicalport模块输出的通信参数，并储存
	struct physicalportinput
	{
		char pp[30];
		char ip[16];
	}ppinput;

	pthread_t pthread_physicalport;

	memset(ppinput.pp,0,30);
	strcpy(ppinput.pp,argv[2]);
	strcpy(ppinput.ip,SwitchDevice_local_ip);

	//创建physicalport子线程
	if(pthread_create(&pthread_physicalport, NULL, thread_physicalport, (void *)&ppinput)!=0)
	{
		perror("Creation of physicalport thread failed.");
	}

	while(1)
	{
		sleep(10000);
	}

	/*
	int iRet = -1;
	int fd   = -1;
	
	if(PROTOCOL == 0)
	{printf("PROTOCOL == 0\n");
		//初始化SOCKET
		fd = Publisher_Ethernet_InitSocket();
		if(0 > fd)
		{
			return -1;
		}
		//向RM发送注册包
		struct hostent *host =NULL;
		struct sockaddr sa;
		int sockfd,len;
		uint8_t temp_ip[5];
		int sidnum;

		uint8_t* pkgregister;
		pkgregister = (uint8_t*)calloc(14+16+NIDLEN+SIDLEN*sidlistcount+PUBKEYLEN+SIGNATURELEN,sizeof(uint8_t));
		bzero(pkgregister,14+16+NIDLEN+SIDLEN*sidlistcount+PUBKEYLEN+SIGNATURELEN);
	
		Ether_CoLoR_register * pkg=0;
		pkg = (Ether_CoLoR_register *)pkgregister;
	
		//填充ethernet包文
		memcpy((char*)pkg->ether_dhost,(char*)destmac,6);
		memcpy((char*)pkg->ether_shost,(char*)localmac,6);
		//pkg.ether_type = htons ( ETHERTYPE_ARP );
		pkg->ether_type=htons(0x0800);
	
		//填充CoLoR-data包文
		pkg->version_type = 162;//版本4位，类型4位，此为设置成CoLoR_Register包
		pkg->nid_len = NIDLEN;//NID长度
		pkg->sid_n = sidlistcount;//SID长度
		pkg->sid_len = SIDLEN;//SID长度

		pkg->Public_key_len = PUBKEYLEN;
		pkg->signature_algorithm = 1;//签名算法
		pkg->options_static = 0;//固定首部选项

		pkg->checksum = 0;//检验和
		pkg->Sequence_number = 0;//序列号

		pkg->Sequence_number_ack = 0;//序列号_ack
		pkg->total_len = 16+NIDLEN+SIDLEN*sidlistcount+PUBKEYLEN+SIGNATURELEN;//总长度
	
		memcpy(pkg->nid,"d1pub1",NIDLEN/2);
		bzero(pkg->nid+6,NIDLEN/2-6);
		memcpy(pkg->nid+NIDLEN/2,"d1rm",NIDLEN/2);
		bzero(pkg->nid+NIDLEN/2+4,NIDLEN/2-4);
	
		for(i=0;i<sidlistcount;i++)
			memcpy(pkg->nid+NIDLEN+i*SIDLEN,SIDcmd[i],SIDLEN);//SID input
	
		//实际应该使用PF_PACKET
		if((sockfd=socket(PF_PACKET,SOCK_PACKET,htons(ETH_P_ALL)))==-1)
		{
			fprintf(stderr,"Socket Error:%s\n\a",strerror(errno));
			return(0);
		}
	
		memset(&sa,0,sizeof(sa));
		strcpy(sa.sa_data,PhysicalPort);
	
		len=sendto(sockfd,pkg,14+pkg->total_len,0,&sa,sizeof(sa));//发送Data包至mac层广播
		printf(">>>CoLoR-Register to  RM.\n");//输出发送register包提示
		if(len!=14+pkg->total_len)//如果发送长度与实际包不匹配，发送失败
		{
			fprintf(stderr,"Sendto Error:%s\n\a",strerror(errno));
			close(sockfd);
			return (0);
		}
	
		close(sockfd);
		free(pkgregister);
	
		//捕获数据包（死循环）
		Publisher_Ethernet_StartCapture(fd);
	}
	else if(PROTOCOL == 1)
	{printf("PROTOCOL == 1\n");
		//初始化SOCKET
		fd = Publisher_UDP_InitSocket();
		if(0 > fd)
		{
			return -1;
		}

		//捕获数据包（死循环）
		Publisher_UDP_StartCapture(fd);
	}

	//关闭SOCKET
	close(fd);
	*/
	
	exit(0);
}
