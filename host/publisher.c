/*******************************************************************************************************************************************
* 文件名：publisher.c
* 文件描述：973智慧协同网络SAR系统TestBed套件——数据发布端（Data Publisher）——GET包接收解析+本地SID与Data匹配+DATA包封装发送
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
gcc publisher.c -o publisher -lpthread
4、运行（因涉及原始套接字的使用，须root权限）
sudo ./publisher
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <netdb.h>

#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <resolv.h>
#include <signal.h>
#include <getopt.h>
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/*******************************************************************************************************************************************
*************************************宏定义配置数据************全局变量定义************包格式声明*********************************************
*******************************************************************************************************************************************/

//面向内部CoLoR网络
uint8_t PhysicalPort[30];                     //网卡端口
#define LOCALTEST     0                       //是否为本地双端测试，是则置为非0值，不是则置为0
#define PORTNUM       1                       //本程序使用的端口号
#define CACHEPATH     "./cache.log"//缓存文件路径

//协议相关（用于发包，不影响根据具体字段规定的长度收包）
#define SIDLEN    20                          //SID长度
#define NIDLEN    16                          //NID长度
#define PIDN      0                           //PID数量
#define DATALEN   20                          //Data长度
#define PUBKEYLEN 16                          //公钥长度
#define MTU       1500                        //最大传输单元
#define SIGNATURELEN 16

//全局变量
int flag_localtest = LOCALTEST;

int selfpacketdonotcatch=0;

uint8_t tempsid[SIDLEN];
uint8_t * tempPIDs=NULL;

uint8_t local_mac[7];
uint8_t local_ip[5];
char dest_ip[16]={0};
uint8_t broad_mac[7]={0xff,0xff,0xff,0xff,0xff,0xff,0x00};

uint8_t  destmac[7]={0x01,0x01,0x01,0x01,0x01,0x02,0x00};//01-01-01-01-01-02
uint8_t localmac[7]={0x01,0x01,0x01,0x04,0x01,0x01,0x00};//01-01-01-04-01-01

//unsigned char sendnid[NIDLEN] = {'d','4','s','u','b','1',0,0,'d','1','s','u','b','1',0,0};

#define FILEpid "../sar6domain/domain1/pid"
#define PIDLENTH 5000
#define FILEsid "./cache.log"
#define SIDLENTH 5000

//PID表项
typedef struct _PIDEvent PIDEvent;
struct _PIDEvent
{
	unsigned char did[10];
	unsigned char pid[4];
	unsigned char nid[16];
};
PIDEvent pidlist[100];//声明PID表
int pidlistcount=-1;

//SID向RM注册表项


//CoLoR协议用于类型判断的字段（截止到固定首部，其中Version/Type字段为Get包、Data包、Register包所通用）
typedef struct _Ether_VersionType Ether_VersionType;
struct _Ether_VersionType
{
	//ethernet头
	uint8_t ether_dhost[6]; //目地硬件地址
	uint8_t ether_shost[6]; //源硬件地址
	uint16_t ether_type; //网络类型
	
	//CoLoR-Data头
	uint8_t version_type;////版本4位，类型4位
	uint8_t ttl;//生存时间
	uint16_t total_len;//总长度
	
	uint16_t port_no;//端口号
	uint16_t checksum;//检验和
	
	uint8_t sid_len;//SID长度
	uint8_t nid_len;//NID长度
	uint8_t pid_n;//PID数量
	uint8_t options_static;//固定首部选项
};
Ether_VersionType tempVersionType;

//CoLoR协议Get包首部（PID之前）字段长度固定，用于封装
typedef struct _Ether_CoLoR_get Ether_CoLoR_get;
struct _Ether_CoLoR_get
{
	//ethernet头
	uint8_t ether_dhost[6]; //目地硬件地址
	uint8_t ether_shost[6]; //源硬件地址
	uint16_t ether_type; //网络类型
	
	//CoLoR-Get头
	uint8_t version_type;////版本4位，类型4位
	uint8_t ttl;//生存时间
	uint16_t total_len;//总长度
	
	uint16_t port_no;//端口号
	uint16_t checksum;//检验和
	
	uint8_t sid_len;//SID长度
	uint8_t nid_len;//NID长度
	uint8_t pid_n;//PID数量
	uint8_t options_static;//固定首部选项
	
	uint16_t publickey_len;//公钥长度
	uint16_t mtu;//最大传输单元
	
	uint8_t sid[SIDLEN];//SID
	uint8_t nid[NIDLEN];//NID
	
	uint8_t data[DATALEN];//Data
	
	uint8_t publickey[PUBKEYLEN];//公钥
};

//CoLoR协议Get包首部（PID之前）字段长度可变，用于解析
typedef struct _Ether_CoLoR_get_parse Ether_CoLoR_get_parse;
struct _Ether_CoLoR_get_parse
{
	//ethernet头
	uint8_t ether_dhost[6]; //目地硬件地址
	uint8_t ether_shost[6]; //源硬件地址
	uint16_t ether_type; //网络类型
	
	//CoLoR-Get头
	uint8_t version_type;////版本4位，类型4位
	uint8_t ttl;//生存时间
	uint16_t total_len;//总长度
	
	uint16_t port_no;//端口号
	uint16_t checksum;//检验和
	
	uint8_t sid_len;//SID长度
	uint8_t nid_len;//NID长度
	uint8_t pid_n;//PID数量
	uint8_t options_static;//固定首部选项
	
	uint16_t publickey_len;//公钥长度
	uint16_t mtu;//最大传输单元
	
	uint8_t* sid;//SID
	uint8_t* nid;//NID
	
	uint8_t* data;//Data
	
	uint8_t* publickey;//公钥
};
Ether_CoLoR_get_parse tempGet;

//CoLoR协议Data包首部（PID之前）字段长度固定，用于封装
typedef struct _Ether_CoLoR_data Ether_CoLoR_data;
struct _Ether_CoLoR_data
{
	//ethernet头
	uint8_t ether_dhost[6]; //目地硬件地址
	uint8_t ether_shost[6]; //源硬件地址
	uint16_t ether_type; //网络类型
	
	//CoLoR-Data头
	uint8_t version_type;////版本4位，类型4位
	uint8_t ttl;//生存时间
	uint16_t total_len;//总长度
	
	uint16_t port_no;//端口号
	uint16_t checksum;//检验和
	
	uint8_t sid_len;//SID长度
	uint8_t nid_len;//NID长度
	uint8_t pid_n;//PID数量
	uint8_t options_static;//固定首部选项
	
	uint8_t signature_algorithm;//签名算法
	uint8_t if_hash_cache;//是否哈希4位，是否缓存4位
	uint16_t options_dynamic;//可变首部选项
	
	uint8_t sid[SIDLEN];//SID
	uint8_t nid[NIDLEN];//NID
	
	uint8_t data[DATALEN];//Data
	
	uint8_t data_signature[16];//数字签名
};

//CoLoR协议Data包首部（PID之前）字段长度可变，用于解析
typedef struct _Ether_CoLoR_data_parse Ether_CoLoR_data_parse;
struct _Ether_CoLoR_data_parse
{
	//ethernet头
	uint8_t ether_dhost[6]; //目地硬件地址
	uint8_t ether_shost[6]; //源硬件地址
	uint16_t ether_type; //网络类型
	
	//CoLoR-Data头
	uint8_t version_type;////版本4位，类型4位
	uint8_t ttl;//生存时间
	uint16_t total_len;//总长度
	
	uint16_t port_no;//端口号
	uint16_t checksum;//检验和
	
	uint8_t sid_len;//SID长度
	uint8_t nid_len;//NID长度
	uint8_t pid_n;//PID数量
	uint8_t options_static;//固定首部选项
	
	uint8_t signature_algorithm;//签名算法
	uint8_t if_hash_cache;//是否哈希4位，是否缓存4位
	uint16_t options_dynamic;//可变首部选项
	
	uint8_t* sid;//SID
	uint8_t* nid;//NID
	
	uint8_t* data;//Data
	
	uint8_t data_signature[16];//数字签名
};
Ether_CoLoR_data_parse tempData;

//CoLoR协议Register包首部（PID之前）
typedef struct _Ether_CoLoR_register Ether_CoLoR_register;
struct _Ether_CoLoR_register
{
	//ethernet头
	uint8_t ether_dhost[6]; //目地硬件地址
	uint8_t ether_shost[6]; //源硬件地址
	uint16_t ether_type; //网络类型
	
	//CoLoR-Register头
	uint8_t version_type;////版本4位，类型4位
	uint8_t nid_len;//NID长度
	uint8_t sid_n;//SID数量
	uint8_t sid_len;//SID长度

	uint16_t Public_key_len;//公钥长度
	uint8_t signature_algorithm;//签名算法
	uint8_t options_static;//固定首部选项

	uint16_t checksum;//检验和
	uint16_t Sequence_number;//序列号

	uint16_t Sequence_number_ack;//序列号_ack
	uint16_t total_len;//总长度
	
	uint8_t nid[NIDLEN];//NID
};
Ether_CoLoR_register tempRegister;

/*******************************************************************************************************************************************
*******************************************原始套接字发送数据包，封装从MAC层以上的所有数据****************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：GetLocalMac
* 功能描述：
得到本机的mac地址和ip地址
为数据包封装时mac层源地址字段提供数据
* 参数列表：
const char *device
char *mac
char *ip
* 返回结果：
int
*****************************************/
int GetLocalMac ( const char *device,char *mac,char *ip )
{
	int sockfd;
	struct ifreq req;
	struct sockaddr_in * sin;
	
	if ( ( sockfd = socket ( PF_INET,SOCK_DGRAM,0 ) ) ==-1 )
	{
		fprintf ( stderr,"Sock Error:%s\n\a",strerror ( errno ) );
		return ( -1 );
	}
	
	memset ( &req,0,sizeof ( req ) );
	strcpy ( req.ifr_name,device );
	if ( ioctl ( sockfd,SIOCGIFHWADDR, ( char * ) &req ) ==-1 )
	{
		fprintf ( stderr,"ioctl SIOCGIFHWADDR:%s\n\a",strerror ( errno ) );
		close ( sockfd );
		return ( -1 );
	}

	memcpy ( mac,req.ifr_hwaddr.sa_data,6 );
	
	req.ifr_addr.sa_family = PF_INET;
	if ( ioctl ( sockfd,SIOCGIFADDR, ( char * ) &req ) ==-1 )
	{
		fprintf ( stderr,"ioctl SIOCGIFADDR:%s\n\a",strerror ( errno ) );
		close ( sockfd );
		return ( -1 );
	}
	sin = ( struct sockaddr_in * ) &req.ifr_addr;
	memcpy ( ip, ( char * ) &sin->sin_addr,4 );
	
	return ( 0 );
}

/*****************************************
* 函数名称：CoLoR_Sendpkg
* 功能描述：发送mac层组装的数据包（目前用于收到Get包后返回Data包的过程）
* 参数列表：
char * mac
char * broad_mac
char * ip
char * dest
* 返回结果：
int
*****************************************/
int CoLoR_Sendpkg ( char * mac,char * broad_mac,char * ip,char * dest )
{
	int i,j;
	Ether_CoLoR_data pkg;
	struct hostent *host =NULL;
	struct sockaddr sa;
	int sockfd,len;
	unsigned char temp_ip[5];

	uint8_t* pkg_pids;
	pkg_pids = (uint8_t*)calloc(14+16+SIDLEN + NIDLEN + tempGet.pid_n*4 + DATALEN + 16,sizeof(uint8_t));

	memset ( ( char * ) &pkg,'\0',sizeof ( pkg ) );
	
	//填充ethernet包文
	memcpy ( ( char * ) pkg.ether_dhost, ( char * ) destmac,6 );
	memcpy ( ( char * ) pkg.ether_shost, ( char * ) localmac,6 );

	//pkg.ether_type = htons ( ETHERTYPE_ARP );
	pkg.ether_type = htons ( 0x0800 );
	
	//查询SID缓存列表
	//文件读操作
	FILE *fp;
	
	char ch;
	char buf[SIDLEN/*sid长度*/ + DATALEN/*data长度*/ +1/*中间空格*/];
	char len_sid;
	char data[DATALEN/*data长度*/+1/*承载'\0'*/];
	
	int flag_sidfound;
	int file_i;
	
	for(i=0;i<SIDLEN/*sid长度*/;i++)
	{
		if(tempsid[i] == '\0')
			break;
	}
	len_sid = i;
	i=0;
	
	if((fp=fopen(CACHEPATH,"r"))==NULL)
	{
		printf("cannot open file!\n");
		exit(0);
	}
	file_i = 0;
	flag_sidfound = 0;
	int runcount = 0;//temp
	while(1)
	{
		if(len_sid == 0)//如果收到的SID为空
		{
			printf("   SID %s not found!\n",tempsid);
			memcpy(data, "xxxx", 4);
			break;
		}
		
		ch=fgetc(fp);
		if(ch==EOF)
		{
			buf[file_i] = '\0';
			if(strncmp(buf,tempsid,(size_t)len_sid) == 0)
			{
				if(buf[(size_t)len_sid] != ' ')
				{
					file_i = 0;
					buf[0] = '\0';
					continue;
				}
				printf("   SID %s found! ",tempsid);
				for(i=len_sid+1,j=0;;i++)
				{
					if(buf[i] != '\0')
					{
						data[j++] = buf[i];
					}
					else
					{
						data[j] = '\0';
						flag_sidfound = 1;
						break;
					}
				}
				printf("Data is: %s\n",data);
				break;
			}
			else
			{
				printf("   SID %s not found!\n",tempsid);
				memcpy(data, "xxxx", 4);
				break;
			}
		}
		else if(ch=='\n')
		{
			buf[file_i] = '\0';
			if(strncmp(buf,tempsid,(size_t)len_sid) == 0)
			{
				if(buf[(size_t)len_sid] != ' ')
				{
					file_i = 0;
					buf[0] = '\0';
					continue;
				}
				
				printf("   SID %s found! ",tempsid);
				for(i=len_sid+1,j=0;;i++)
				{
					if(buf[i] != '\0')
					{
						data[j++] = buf[i];
					}
					else
					{
						data[j] = '\0';
						flag_sidfound = 1;
						break;
					}
				}
				printf("Data is: %s\n",data);
				break;
			}
			else
			{
				file_i = 0;
				buf[0] = '\0';
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
	
	//填充CoLoR-data包文
	pkg.version_type = 161;//版本4位，类型4位，此为设置成CoLoR_Data包
	pkg.ttl = 255;//生存时间
	pkg.total_len = 16 + SIDLEN + NIDLEN + tempGet.pid_n*4 + DATALEN + 16;//总长度
	
	pkg.port_no = PORTNUM;//端口号
	pkg.checksum = 0;//检验和
	
	pkg.sid_len = SIDLEN;//SID长度
	pkg.nid_len = NIDLEN;//NID长度
	pkg.pid_n = tempGet.pid_n;//PID长度
	pkg.options_static = 0;//固定首部选项
	
	
	pkg.signature_algorithm = 1;//签名算法
	pkg.if_hash_cache = 255;//是否哈希4位，是否缓存4位
	pkg.options_dynamic = 0;//可变首部选项
	
	memcpy(pkg.sid, tempsid, SIDLEN);//SID
	//char nid[NIDLEN] = {'I',' ','a','m',' ','t','h','e',' ','h','o','s','t','~','~','!'};


	unsigned char judgedPID[4];
	memcpy(judgedPID,tempPIDs+(tempGet.pid_n-1)*4,4);

	int pidnidfound=0;
	i=0;pidnidfound=0;
	while(pidnidfound==0)
	{
		if(strncmp(pidlist[i++].pid,judgedPID,4) == 0)
		{
			i--;
			pidnidfound=1;
		}
		if(i==pidlistcount+1)
		{
			break;
		}
	}

	if(pidnidfound == 0)
	{
		printf("Do not found a proper NID for the PID. This is not normal.\n");
	}

	memcpy(pkg.nid, tempGet.nid, NIDLEN);//NID
	printf("tempGet.nid == %s\n",tempGet.nid);
	printf("NIDLEN/2 == %d\n",NIDLEN/2);
	printf("pidlist[i].nid == %s\n",pidlist[i].nid);
	if(pidnidfound == 1)
	{
		memcpy(pkg.nid+NIDLEN/2,pidlist[i].nid,NIDLEN/2);
	}
	
	memcpy((uint8_t*)pkg_pids, (uint8_t*)&pkg, 14+pkg.total_len);
	memcpy((uint8_t*)(pkg_pids+14+pkg.total_len-16-DATALEN-tempGet.pid_n*4), (uint8_t*)tempPIDs, tempGet.pid_n*4);
	
	memcpy((uint8_t*)(pkg_pids+14+pkg.total_len-16-DATALEN), (uint8_t*)data, DATALEN);//Data
	
	fclose(fp);//关闭文件
	
	char data_signature[16] = {'I',' ','a','m',' ','t','h','e',' ','s','i','g','~','~','~','!'};
	memcpy(pkg_pids+14+pkg.total_len-16, data_signature, 16);


	
	fflush ( stdout );
	memset ( temp_ip,0,sizeof ( temp_ip ) );
	if ( inet_aton ( dest, ( struct in_addr * ) temp_ip ) ==0 )
	{
		if ( ( host = gethostbyname ( dest ) ) ==NULL )
		{
			fprintf ( stderr,"Fail! %s\n\a",hstrerror ( h_errno ) );
			return ( -1 );
		}
		memcpy ( ( char * ) temp_ip,host->h_addr,4 );
	}
	
	//实际应该使用PF_PACKET
	if ( ( sockfd = socket ( PF_PACKET/*PF_INET*/,SOCK_PACKET,htons ( ETH_P_ALL ) ) ) ==-1 )
	{
		fprintf ( stderr,"Socket Error:%s\n\a",strerror ( errno ) );
		return ( 0 );
	}
	
	memset ( &sa,'\0',sizeof ( sa ) );
	strcpy ( sa.sa_data,PhysicalPort );
	
	selfpacketdonotcatch=1;
	
	len = sendto ( sockfd,pkg_pids,14+pkg.total_len,0,&sa,sizeof ( sa ) );//发送Data包至mac层广播
	printf(">>>CoLoR-Data to   Proxy. Data: %s\n",data);//输出返回Data包提示
	if ( len != 14+pkg.total_len )//如果发送长度与实际包不匹配，发送失败
	{
		fprintf ( stderr,"Sendto Error:%s\n\a",strerror ( errno ) );
		close(sockfd);
		return ( 0 );
	}
	
	close(sockfd);
	return 1;
}

/*******************************************************************************************************************************************
*******************************************原始套接字接收数据包，解析从MAC层以上的所有数据****************************************************
*******************************************************************************************************************************************/

//接收缓冲区（即接收原始数据）大小
#define BUFSIZE     1024 * 5

//接收缓冲区
static int g_iRecvBufSize = BUFSIZE;
static char g_acRecvBuf[BUFSIZE] = {0};

//物理网卡接口,需要根据具体情况修改
static const char *g_szIfName = PhysicalPort;

/*****************************************
* 函数名称：Ethernet_SetPromisc
* 功能描述：物理网卡混杂模式属性操作
* 参数列表：
const char *pcIfName
int fd
int iFlags
* 返回结果：
static int
*****************************************/
static int Ethernet_SetPromisc(const char *pcIfName, int fd, int iFlags)
{
	int iRet = -1;
	struct ifreq stIfr;
	
	//获取接口属性标志位
	strcpy(stIfr.ifr_name, pcIfName);
	iRet = ioctl(fd, SIOCGIFFLAGS, &stIfr);
	if (0 > iRet)
	{
		perror("[Error]Get Interface Flags");   
		return -1;
	}
	
	if (0 == iFlags)
	{
		//取消混杂模式
		stIfr.ifr_flags &= ~IFF_PROMISC;
	}
	else
	{
		//设置为混杂模式
		stIfr.ifr_flags |= IFF_PROMISC;
	}
	
	iRet = ioctl(fd, SIOCSIFFLAGS, &stIfr);
	if (0 > iRet)
	{
		perror("[Error]Set Interface Flags");
		return -1;
	}
	
	return 0;
}

/*****************************************
* 函数名称：Ethernet_InitSocket
* 功能描述：创建原始套接字
* 参数列表：
* 返回结果：
static int
*****************************************/
static int Ethernet_InitSocket()
{
	int iRet = -1;
	int fd = -1;
	struct ifreq stIf;
	struct sockaddr_ll stLocal = {0};
	
	//创建SOCKET
	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (0 > fd)
	{
		perror("[Error]Initinate L2 raw socket");
		return -1;
	}
	
	//网卡混杂模式设置
	Ethernet_SetPromisc(g_szIfName, fd, 1);
	
	//设置SOCKET选项
	iRet = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &g_iRecvBufSize,sizeof(int));
	if (0 > iRet)
	{
		perror("[Error]Set socket option");
		close(fd);
		return -1;
	}
	
	//获取物理网卡接口索引
	strcpy(stIf.ifr_name, g_szIfName);
	iRet = ioctl(fd, SIOCGIFINDEX, &stIf);
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
	iRet = bind(fd, (struct sockaddr *)&stLocal, sizeof(stLocal));
	if (0 > iRet)
	{
		perror("[Error]Bind the interface");
		close(fd);
		return -1;
	}
	
	return fd;   
}

/*****************************************
* 函数名称：CoLoR_SeeType
* 功能描述：判断是否为、为何种CoLoR包头
* 参数列表：
const Ether_CoLoR_get *pkg
* 返回结果：
static int
*****************************************/
static int CoLoR_SeeType(const Ether_VersionType *pkg)
{
	int i;
	struct protoent *pstIpProto = NULL;
	
	if (NULL == pkg)
	{
		return -1;
	}
	
	//这里为判断，确保收上来的数据包不是自己发出的，所以本机开两个对端进行测试的时候须将flag_localtest判断值设为非零值
	//在不填充MAC的网络中无效
	/*
	if(flag_localtest != 0)
	{
		if((strncmp((char*)pkg->ether_shost,(char*)local_mac,6)==0) && (pkg->port_no == PORTNUM))
		{
			return -1;
		}
	}
	*/
	
	//版本、协议类型
	//int version = pkg->version_type / 16;//取version_type字段8位二进制数的前四位，即取IP版本号
	//int type    = pkg->version_type % 16;//取version_type字段8位二进制数的后四位，即取CoLoR包类型号
	if(pkg->version_type == 160)//仅显示IP版本号为10，包类型为0（专属CoLoR-Get包  字段为1010 0000）的包
	{
		return 0;
	}
	if(pkg->version_type == 161)//仅显示IP版本号为10，包类型为1（专属CoLoR-Data包 字段为1010 0001）的包
	{
		return 1;
	}
	if(pkg->version_type == 161)//仅显示IP版本号为10，包类型为2（专属CoLoR-Register包 字段为1010 0010）的包
	{
		return 2;
	}
	
	
	return -1;
}



/*****************************************
* 函数名称：CoLoR_ParseGet
* 功能描述：解析CoLoR-Get包头
* 参数列表：
const Ether_CoLoR_get *pkg
* 返回结果：
static int
*****************************************/
static int CoLoR_ParseGet(const Ether_CoLoR_get *pkg)
{
	int i;
	
	char* p;
	p = (char*)pkg;
	
	if (NULL == pkg)
	{
		return -1;
	}
	
	//解析Get包各字段
	free(tempGet.sid);
	free(tempGet.nid);
	free(tempGet.data);
	free(tempGet.publickey);
	free(tempPIDs);
	
	printf (">>>CoLoR-Get  Received.\n");
	printf ("   |====================Getpkg===================|\n");
	memcpy((uint8_t*)tempGet.ether_dhost,(uint8_t*)pkg->ether_dhost,6);
	memcpy((uint8_t*)tempGet.ether_shost,(uint8_t*)pkg->ether_shost,6);
	tempGet.ether_type = pkg->ether_type;
	
	tempGet.version_type = pkg->version_type;
	printf("   |version_type = %d\n",tempGet.version_type);
	tempGet.ttl = pkg->ttl;
	printf("   |ttl = %d\n",tempGet.ttl);
	tempGet.total_len = pkg->total_len;
	printf("   |total_len = %d\n",tempGet.total_len);
	tempGet.port_no = pkg->port_no;
	printf("   |port_no = %d\n",tempGet.port_no);
	tempGet.checksum = pkg->checksum;
	printf("   |checksum = %d\n",tempGet.checksum);
	tempGet.sid_len = pkg->sid_len;
	printf("   |sid_len = %d\n",tempGet.sid_len);
	tempGet.nid_len = pkg->nid_len;
	printf("   |nid_len = %d\n",tempGet.nid_len);
	tempGet.pid_n = pkg->pid_n;
	printf("   |pid_n = %d\n",tempGet.pid_n);
	tempGet.options_static = pkg->options_static;
	printf("   |options_static = %d\n",tempGet.options_static);
	
	p += sizeof(uint8_t) * (14 + 12);
	
	tempGet.publickey_len = (uint16_t)(*p);
	printf("   |publickey_len = %d\n",tempGet.publickey_len);
	tempGet.mtu = (uint16_t)(*(p+sizeof(uint16_t)));
	printf("   |mtu = %d\n",tempGet.mtu);
	
	p += sizeof(uint16_t) * 2;
	
	tempGet.sid = (uint8_t*)calloc(tempGet.sid_len,sizeof(uint8_t));
	memcpy((uint8_t*)tempGet.sid,(uint8_t*)p,tempGet.sid_len);
	printf("   |sid = %s\n",tempGet.sid);
	
	p += sizeof(uint8_t) * tempGet.sid_len;
	
	tempGet.nid = (uint8_t*)calloc(tempGet.nid_len,sizeof(uint8_t));
	memcpy((uint8_t*)tempGet.nid,(uint8_t*)p,tempGet.nid_len);
	printf("   |nid = %s\n",tempGet.nid);
	
	p += sizeof(uint8_t) * tempGet.nid_len;
	
	uint16_t data_len = tempGet.total_len - 16 - tempGet.sid_len - tempGet.nid_len - tempGet.pid_n*4 - tempGet.publickey_len;
	tempGet.data = (uint8_t*)calloc(data_len+1/*+1修正，是为结束符特别预留*/,sizeof(uint8_t));
	memcpy((uint8_t*)tempGet.data,(uint8_t*)p,data_len);
	*(tempGet.data+data_len) = '\0';//不清楚为什么唯独data后需要特别腾出1byte作为结束符否则会越界读取
	printf("   |data = %s\n",tempGet.data);
	
	p += sizeof(uint8_t) * data_len;
	
	tempGet.publickey = (uint8_t*)calloc(tempGet.publickey_len,sizeof(uint8_t));
	memcpy((uint8_t*)tempGet.publickey,(uint8_t*)p,tempGet.publickey_len);
	printf("   |publickey = %s\n",tempGet.publickey);

	p += sizeof(uint8_t) * tempGet.publickey_len;
	
	tempPIDs = (uint8_t*)calloc(tempGet.pid_n*4,sizeof(uint8_t));
	memcpy((uint8_t*)tempPIDs,(uint8_t*)p,tempGet.pid_n*4);
	for(i=0;i<tempGet.pid_n;i++)
	{
		printf("   |PID%d = %s\n",i+1,tempPIDs+i*4);
	}
	printf ("   |=============================================|\n");
	
	memcpy(tempsid, tempGet.sid, tempGet.sid_len/*SID长度*/);
	
	//封装并发送CoLoR-Data数据包
	sprintf ( dest_ip,"255.255.255.255",i );
	CoLoR_Sendpkg ( local_mac,broad_mac,local_ip,dest_ip );//需要修改为可针对不同类型包格式发出不同响应的功能
	
	return 0;
}

/*****************************************
* 函数名称：CoLoR_ParseData
* 功能描述：解析CoLoR-Data包头
* 参数列表：
const Ether_CoLoR_get *pkg
* 返回结果：
static int
*****************************************/
static int CoLoR_ParseData(const Ether_CoLoR_data *pkg)
{
	int i;
	
	char* p;
	p = (char*)pkg;
	
	if (NULL == pkg)
	{
		return -1;
	}
	
	//解析Data包各字段
	free(tempData.sid);
	free(tempData.nid);
	free(tempData.data);
	
	
	printf (">>>CoLoR-Data Received.\n");
	printf ("   |====================Datapkg==================|\n");
	memcpy((uint8_t*)tempData.ether_dhost,(uint8_t*)pkg->ether_dhost,6);
	memcpy((uint8_t*)tempData.ether_shost,(uint8_t*)pkg->ether_shost,6);
	tempData.ether_type = pkg->ether_type;
	tempData.version_type = pkg->version_type;
	printf("   |version_type = %d\n",tempData.version_type);
	tempData.ttl = pkg->ttl;
	printf("   |ttl = %d\n",tempData.ttl);
	tempData.total_len = pkg->total_len;
	printf("   |total_len = %d\n",tempData.total_len);
	tempData.port_no = pkg->port_no;
	printf("   |port_no = %d\n",tempData.port_no);
	tempData.checksum = pkg->checksum;
	printf("   |checksum = %d\n",tempData.checksum);
	tempData.sid_len = pkg->sid_len;
	printf("   |sid_len = %d\n",tempData.sid_len);
	tempData.nid_len = pkg->nid_len;
	printf("   |nid_len = %d\n",tempData.nid_len);
	tempData.pid_n = pkg->pid_n;
	printf("   |pid_n = %d\n",tempData.pid_n);
	tempData.options_static = pkg->options_static;
	printf("   |options_static = %d\n",tempData.options_static);
	
	p += sizeof(uint8_t) * (14 + 12);
	
	tempData.signature_algorithm = (uint8_t)(*p);
	printf("   |signature_algorithm = %d\n",tempData.signature_algorithm);
	tempData.if_hash_cache = (uint8_t)(*(p+sizeof(uint8_t)));
	printf("   |if_hash_cache = %d\n",tempData.if_hash_cache);
	tempData.options_dynamic = (uint16_t)(*(p+sizeof(uint16_t)));
	printf("   |options_dynamic = %d\n",tempData.options_dynamic);
	
	p += sizeof(uint32_t);
	
	tempData.sid = (uint8_t*)calloc(tempData.sid_len,sizeof(uint8_t));
	memcpy((uint8_t*)tempData.sid,(uint8_t*)p,tempData.sid_len);
	printf("   |sid = %s\n",tempData.sid);
	
	p += sizeof(uint8_t) * tempData.sid_len;
	
	tempData.nid = (uint8_t*)calloc(tempData.nid_len,sizeof(uint8_t));
	memcpy((uint8_t*)tempData.nid,(uint8_t*)p,tempData.nid_len);
	printf("   |nid = %s\n",tempData.nid);
	
	p += sizeof(uint8_t) * tempData.nid_len;
	
	uint16_t data_len = tempData.total_len - sizeof(uint8_t)*32 - tempData.sid_len - tempData.nid_len - tempData.pid_n*sizeof(uint8_t)*4;
	tempData.data = (uint8_t*)calloc(data_len+1/*+1修正，是为结束符特别预留*/,sizeof(uint8_t));
	memcpy((uint8_t*)tempData.data,(uint8_t*)p,data_len);
	*(tempData.data+data_len) = '\0';//不清楚为什么唯独data后需要特别腾出1Byte作为结束符否则会越界读取
	printf("   |data = %s\n",tempData.data);
	
	p += sizeof(uint8_t) * data_len;
	
	for(i=0;i<16;i++)
	{
		tempData.data_signature[i] = (uint8_t)(*(p+sizeof(uint8_t)*i));
	}
	printf("   |data_signature = %s\n",tempData.data_signature);
	printf ("   |=============================================|\n");
	
	
	return 0;
}

/*****************************************
* 函数名称：CoLoR_ParseRegister
* 功能描述：解析CoLoR-Register包头
* 参数列表：
const Ether_CoLoR_get *pkg
* 返回结果：
static int
*****************************************/
static int CoLoR_ParseRegister(const Ether_CoLoR_register *pkg)
{
	int i;
	
	if (NULL == pkg)
	{
		return -1;
	}
	//解析Register包各字段
	//不清楚Register包格式，待添加
	
	
	printf (">>>CoLoR-Register from Somewhere. Type : %d\n",pkg->version_type%16);
	
	return 0;
}

/*****************************************
* 函数名称：Ethernet_ParseFrame
* 功能描述：数据帧解析函数
* 参数列表：
const char *pcFrameData
* 返回结果：
static int
*****************************************/
static int Ethernet_ParseFrame(const char *pcFrameData)
{
	//检查本机mac和IP地址
	memset ( local_mac,0,sizeof ( local_mac ) );
	memset ( local_ip,0,sizeof ( local_ip ) );
	memset ( dest_ip,0,sizeof ( dest_ip ) );
	
	if ( GetLocalMac ( PhysicalPort,local_mac,local_ip ) ==-1 )
		return ( -1 );
	
	
	int iType = -1;
	int iRet = -1;
	
	struct ether_header *pstEthHead = NULL;
	Ether_VersionType *pkgvt = NULL;
	Ether_CoLoR_get *pkgget = NULL;
	Ether_CoLoR_data *pkgdata = NULL;
	Ether_CoLoR_register *pkgregister = NULL;
	
	//接收到的原始数据流赋值为以太网头
	pstEthHead = (struct ether_header*)g_acRecvBuf;
	
	//判断CoLoR数据包类型
	pkgvt = (Ether_VersionType *)(pstEthHead + 0);

	/*
	if(strncmp((char*)pkgvt->ether_dhost,(char*)localmac,6)!=0)
	{
		iRet=-1;
		return iRet;
	}
	*/

	iType = CoLoR_SeeType(pkgvt);
	
	if(iType == 0)//收到Get包
	{
		pkgget  = (Ether_CoLoR_get *)(pstEthHead + 0);
		iRet = CoLoR_ParseGet(pkgget);
	}
	else if(iType == 1)//收到Data包
	{
		pkgdata  = (Ether_CoLoR_data *)(pstEthHead + 0);
		iRet = CoLoR_ParseData(pkgdata);
	}
	else if(iType == 2)//收到Register包
	{
		pkgregister  = (Ether_CoLoR_register *)(pstEthHead + 0);
		iRet = CoLoR_ParseRegister(pkgregister);
	}
	else//包类型不属于CoLoR协议
	{
	}
	
	return iRet;
}

/*****************************************
* 函数名称：Ethernet_StartCapture
* 功能描述：捕获网卡数据帧
* 参数列表：
const int fd
* 返回结果：void
*****************************************/
static void Ethernet_StartCapture(const int fd)
{
	int iRet = -1;
	socklen_t stFromLen = 0;
	int packetcount=1;
	
	int cancelrepetition=0;//由于未知原因，每一个来自物理介质的数据包都会被接收两次。故设定相邻的每两次收包仅一次有效，这是权宜之计，没有根治问题。
	//循环监听
	while(1)
	{
		//清空接收缓冲区
		//memset(g_acRecvBuf, 0, BUFSIZE);
		bzero(g_acRecvBuf,BUFSIZE);
		
		//接收数据帧
		iRet = recvfrom(fd, g_acRecvBuf, g_iRecvBufSize, 0, NULL, &stFromLen);

		//第一时间丢弃自己发出的数据包
		if(selfpacketdonotcatch == 1)
		{
			selfpacketdonotcatch=0;
			continue;
		}
		
		if (0 > iRet)
		{
			continue;
		}

		//接收数据帧检测
		//printf("[Ethernet]New Packet Received. Noooo.%d:\n",packetcount++);

		//if(cancelrepetition == 0)
		if(1)
		{
			//解析数据帧
			Ethernet_ParseFrame(g_acRecvBuf);
			cancelrepetition=1;
		}
		else
		{
			cancelrepetition=0;
		}
	}
}

/*****************************************
* 函数名称：main
* 功能描述：主函数
* 参数列表：
int argc
char *argv[]
* 返回结果：
int
*****************************************/
int main(int argc, char *argv[])
{
	memset(PhysicalPort,0,30);
	strcpy(PhysicalPort,argv[1]);
	
	int i=0,j=0,k=0,l=0;

	FILE *fp;
	char ch=0;
	int file_i=0;
	
	//文件1：读取PID注册文件
	char PIDbuf[PIDLENTH];
	char PIDcmd[PIDLENTH/32][32];

	if((fp=fopen(FILEpid,"r"))==NULL)
	{
		printf("cannot open file!\n");
		return -1;
	}

	file_i = 0;
	while ((ch=fgetc(fp))!=EOF)
		PIDbuf[file_i++]=ch;

	if(file_i == 0)
	{
		printf("FILEpid is empty!\n");
		fclose(fp);
		return 0;
	}
	PIDbuf[--file_i] = '\0';
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

	//文件2：读取SID缓存文件
	char SIDbuf[SIDLENTH];
	char SIDcmd[SIDLENTH/32][32];
	int sidlistcount=0;

	if((fp=fopen(FILEsid,"r"))==NULL)
	{
		printf("cannot open file!\n");
		return -1;
	}

	file_i = 0;
	while ((ch=fgetc(fp))!=EOF)
		SIDbuf[file_i++]=ch;

	if(file_i == 0)
	{
		printf("FILEpid is empty!\n");
		fclose(fp);
		return 0;
	}
	SIDbuf[--file_i] = '\0';
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
	
	printf("[FILEsid]\n%s\n",SIDbuf);


	printf("Get packet listening...\n");

	int iRet = -1;
	int fd   = -1;
	
	//初始化SOCKET
	fd = Ethernet_InitSocket();
	if(0 > fd)
	{
		return -1;
	}
/*
	//向RM发送注册包
	struct hostent *host =NULL;
	struct sockaddr sa;
	int sockfd,len;
	unsigned char temp_ip[5];
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
	
	memset(&sa,'\0',sizeof(sa));
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
*/
	
	//捕获数据包（死循环）
	Ethernet_StartCapture(fd);
	
	//关闭SOCKET
	close(fd);
	
	return 0;
}
