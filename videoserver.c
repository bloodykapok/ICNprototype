/*******************************************************************************************************************************************
* 文件名：videoserver.c
* 文件描述：973智慧协同网络SAR系统TestBed套件——过渡方案新网代理HTTP服务器
* 声明：本模板代码作者王兆旭，为北京交通大学下一代互联网互联设备国家工程实验室新生基础工程技术培训专用。作者王兆旭在此郑重声明，此文件及其它用于培训的模板代码均为本人精力与经验的产物，本资源的传播方式均为作者本人向他人进行一对一传授，任何个人不得向第三方转交或展示该资源内容。任何有需求的学员，均须向王兆旭本人直接索要，亦无向他人索要或传授之权利和义务。因有些资源内容涉及实验室项目秘密，暂不考虑申请专利保护或软件著作权等事宜，故个别资源仅限实验室内部一对一发放，如发现有辜负作者本人的一片好意的行为，作者将保留就其原创性进行追查、举证、申诉和问责的权利。本资源的发放权归作者本人所有，其整理和总结过程浸透无偿贡献的热忱和为诸君学业尽绵薄之力的真诚，愿学员尊重作者的劳动成果，谢谢合作！
* 作者：王兆旭
* 身份：北京交通大学下一代互联网互联设备国家工程实验室 2013级硕博连读研究生
* E-mail. hellozxwang@foxmail.com
* Mobile. 18811774990
* QQ    . 535667240
* Addr  . 北京市海淀区西直门外北京交通大学机械楼D706室, 100044
*******************************************************************************************************************************************/
/*******************************************************************************************************************************************
*****功能说明：1.传过渡方案新网代理HTTP服务器
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

//Proxy外部通信
//面向外部IPv4网络
#define DEFAULTIP     "127.0.0.1"             //接收HTTP请求的本地IP地址（公网地址）
#define DEFAULTPORT   "3390"                  //接收HTTP请求的本地端口
#define DEFAULTDIR    "/home"                 //HTTP目录访问服务的根路径
//面向内部CoLoR网络
#define Physical_Port "eth0"                  //网卡端口
#define LOCALTEST     1                       //是否为本地双端测试，是则置为非0值，不是则置为0
#define PORTNUM       0                       //本程序使用的端口号

//Proxy内部通信
#define PORTtoMAC   6001                      //[UDP端口号]HTTP协议栈  发往 CoLoR协议栈
#define PORTtoHTTP  6002                      //[UDP端口号]CoLoR协议栈 发往 HTTP协议栈
#define SIDDES "127.0.0.1"

//Proxy内部配置
#define DATAFLOWPATH  "/home/zxwang/vedioserver/rich.mp3"//流媒体文件路径
#define DEFAULTLOG    "/home/HTTP_Server.log" //程序日志路径
#define DEFAULTBACK   "10"                    //（可能是最大并发任务数）
#define MAX_GETSIDTIME 10                     //等待内网取回Data最长时间

//协议相关
#define SIDLEN    20                          //SID长度
#define NIDLEN    16                          //NID长度
#define PIDN      0                           //PID数量
#define DATALEN   20                          //Data长度
#define PUBKEYLEN 16                          //公钥长度
#define MTU       1500                        //最大传输单元

//全局变量
char temp[100];              //专用于各种字符串格式化的中间暂存变量
uint8_t tempdata[DATALEN];
uint8_t tempSID[SIDLEN];
uint8_t tempsid[SIDLEN];
uint8_t SID[SIDLEN];//已知用于主函数接收HTTP请求与其调用函数之间的数值传递

int flag_localtest = LOCALTEST;

unsigned char local_mac[7];
unsigned char local_ip[5];
char dest_ip[16]={0};
unsigned char broad_mac[7]={0xff,0xff,0xff,0xff,0xff,0xff,0x00};

int test_count=0;

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
	//具体包格式不清楚，待添加
};
Ether_CoLoR_register tempRegister;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////（下）子线程调用声明与函数集合
///////////////////////////////////////////////////////////////////////////////////////////////////////////////HTTP_Server调用声明与函数
void prterrmsg(char *msg);
#define prterrmsg(msg)         {perror(msg); abort();}
void wrterrmsg(char *msg);
#define wrterrmsg(msg)         {fputs(msg, logfp); fputs(strerror(errno), logfp);fflush(logfp); abort();}


void prtinfomsg(char *msg);
#define prtinfomsg(msg)        {fputs(msg, stdout);}
void wrtinfomsg(char *msg);
#define wrtinfomsg(msg)        {fputs(msg, logfp); fflush(logfp);}


#define MAXPATH 150
#define MAXBUF  1024

char buffer[MAXBUF + 1];
char *host               = 0;
char *port               = 0;
char *back               = 0;
char *dirroot            = 0;
char *logdir             = 0;
unsigned char daemon_y_n = 0;

FILE *logfp;

/*****************************************
* 函数名称：dir_up
* 功能描述：
查找dirpath所指目录的上一级目录
* 参数列表：
* 返回结果：
*****************************************/
char *dir_up(char *dirpath)
{
	static char Path[MAXPATH];
	int len;
	
	strcpy(Path, dirpath);
	len = strlen(Path);
	if (len > 1 && Path[len - 1] == '/')
		len--;
	while (Path[len - 1] != '/' && len > 1)
		len--;
	Path[len] = 0;
	return Path;
}


/*****************************************
* 函数名称：AllocateMemory
* 功能描述：
分配空间并把d所指的内容复制
* 参数列表：
* 返回结果：
*****************************************/
void AllocateMemory(char **s, int l, char *d)
{
	*s = malloc(l + 1);
	bzero(*s, l + 1);
	memcpy(*s, d, l);
}

/*****************************************
* 函数名称：GiveResponse
* 功能描述：
把Path所指的内容发送到client_sock去
* 参数列表：
* 返回结果：
如果Path是一个目录，则列出目录内容
如果Path是一个文件，则下载文件
*****************************************/
void GiveResponse(FILE * client_sock, char *Path)
{
	int i=0;
	int j=0;
	char str[30];
	
	
	struct dirent *dirent;
	struct stat info;
	char Filename[MAXPATH];
	DIR *dir;
	int fd, len, ret;
	char *p, *realPath, *realFilename, *nport;
	
	//获得实际工作目录或文件
	len = strlen(dirroot) + strlen(Path) + 1;
	realPath = malloc(len + 1);
	bzero(realPath, len + 1);
	sprintf(realPath, "%s/%s", dirroot, Path);
	
	//获得实际工作端口
	len = strlen(port) + 1;
	nport = malloc(len + 1);
	bzero(nport, len + 1);
	sprintf(nport, ":%s", port);
	
	//如果收到的请求路径不存在
    if (stat(realPath, &info))
	{
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
		socket_sidsender=socket(AF_INET,SOCK_DGRAM,0);
		
		sprintf(temp,"GET%s",SID);
		
		struct sockaddr_in addrTo;
		bzero(&addrTo,sizeof(addrTo));
		addrTo.sin_family=AF_INET;
		addrTo.sin_port=htons(PORTtoHTTP);
		//unsigned long IPto = 2130706433;//回环地址名称 == 2130706433
		//addrTo.sin_addr.s_addr=htonl(IPto);//htonl将主机字节序转换为网络字节序
		addrTo.sin_addr.s_addr=inet_addr(SIDDES);//htonl将主机字节序转换为网络字节序
		//发送SID信令
		sendto(socket_sidsender,temp,sizeof(temp),0,(struct sockaddr *)&addrTo,sizeof(addrTo));
		printf("   The HTTP Client asked for Data whitch match the SID: %s\n",SID);
		//死循环监听回送资源成功的信令
		int sin_len;
		char message[100];
		int socket_sidreceiver;
		
		struct sockaddr_in sin;
		bzero(&sin,sizeof(sin));
		sin.sin_family=AF_INET;
		sin.sin_addr.s_addr=htonl(INADDR_ANY);
		sin.sin_port=htons(PORTtoMAC);
		sin_len=sizeof(sin);
		
		socket_sidreceiver=socket(AF_INET,SOCK_DGRAM,0);
		bind(socket_sidreceiver,(struct sockaddr *)&sin,sizeof(sin));
		
		int flag_sidgot = 0;
		int counter_sidget = 0;
		while(1)
		{
			recvfrom(socket_sidreceiver,message,sizeof(message),0,(struct sockaddr *)&sin,&sin_len);
			//接受到的消息为 “GOT”
			if(strncmp(message,"GOT",3) == 0)
			{
				flag_sidgot = 1;
				i=2;
				for(j=0;;j++)
				{
					if(message[++i]!='\0')
					{
						str[j] = message[i];
					}
					else
						break;
				}
				str[j]='\0';
				break;
			}printf("Data \"%s\" has been received and it will be sent to the HTTP Client immediately./n",str);
			/*
			sleep(1);
			counter_sidget++;
			if(counter_sidget >= MAX_GETSIDTIME)//如果提取SID对应资源的请求超过MAX_GETSIDTIME的预设时间没有回复，则认为请求失败
			{
			break;
			}
			*/
		}
		/*
		输入接口：直接将取回的文件存入DEFAULTDIR（见代码开头宏定义）所指向的根目录，并由下面的代码调取文件
		输入来源：CoLoR协议取回的文件
		可拓展性：基于文件提取和下载的机制实际上完成了缓存的基础功能，未来还可以在程序中添加缓存索引列表和老化机制
		*/
		
		if(flag_sidgot == 1)//如果获取到了资源并已经存储到本地文件，直接显示在页面上
		{
			fprintf(client_sock,
				"HTTP/1.1 200 OK\r\nServer:SONG\r\nConnection: close\r\nContent-Type:text/html; charset=UTF-8\r\n\r\n<html><head><title>%d - %s</title></head>"
				"<body><font size=+4>[NGI Lab] 973 Project Testing Server - coded by zxWang</font><br><hr width=\"100%%\"><br><center>"
				"<table border cols=3 width=\"100%%\">", errno,
				strerror(errno));
			fprintf(client_sock,
				"</table><font color=\"CC0000\" size=+2>Success: SID \"%s\" was recognized successfully! The Data is: \"%s\"</font></body></html>",
				SID,str);
			goto out;
		}
		else if(flag_sidgot == 0)
		{
			fprintf(client_sock,
				"HTTP/1.1 200 OK\r\nServer:SONG\r\nConnection: close\r\nContent-Type:text/html; charset=UTF-8\r\n\r\n<html><head><title>%d - %s</title></head>"
				"<body><font size=+4>[NGI Lab] 973 Project Testing Server - coded by zxWang</font><br><hr width=\"100%%\"><br><center>"
				"<table border cols=3 width=\"100%%\">", errno,
				strerror(errno));
			fprintf(client_sock,
				"</table><font color=\"CC0000\" size=+2>Error: \n%s %s</font></body></html>",
				Path, strerror(errno));
			goto out;
		}
	}
	//处理浏览文件请求，即下载文件
    if (S_ISREG(info.st_mode))
	{
		fd = open(realPath, O_RDONLY);
		len = lseek(fd, 0, SEEK_END);
		p = (char *) malloc(len + 1);
		bzero(p, len + 1);
		lseek(fd, 0, SEEK_SET);
		ret = read(fd, p, len);
		close(fd);
		fprintf(client_sock,
			"HTTP/1.1 200 OK\r\nServer:SONG\r\nConnection: keep-alive\r\nContent-type: application/*\r\nContent-Length:%d\r\n\r\n",
			len);
			/*
			printf("len = %d\n",len);
			int dd=0;
			char c;
			while(dd<100)
			{
			c = *(p+dd);
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
		*/
		fwrite(p, len, 1, client_sock);
free(p);
	} 
	else if (S_ISDIR(info.st_mode))
	{
		//处理浏览目录请求
		dir = opendir(realPath);
		fprintf(client_sock,
			"HTTP/1.1 200 OK\r\nServer:SONG\r\nConnection: close\r\nContent-Type:text/html; charset=UTF-8\r\n\r\n<html><head><title>%s</title></head>"
			"<body><font size=+4>[NGI Lab] 973 Project Testing Server - coded by zxWang-dir</font><br><hr width=\"100%%\"><br><center>"
			"<table border cols=3 width=\"100%%\">", Path);
		fprintf(client_sock,
			"<caption><font size=+3>Dir %s</font></caption>\n",
			Path);
		fprintf(client_sock,
			"<tr><td>Name</td><td>Size</td><td>Time</td></tr>\n");
		if (dir == 0)
		{
			fprintf(client_sock,
				"</table><font color=\"CC0000\" size=+2>%s</font></body></html>",
				strerror(errno));
			return;
		}
		//读取目录里的所有内容
		while ((dirent = readdir(dir)) != 0)
		{
			if (strcmp(Path, "/") == 0)
				sprintf(Filename, "/%s", dirent->d_name);
			else
				sprintf(Filename, "%s/%s", Path, dirent->d_name);
			fprintf(client_sock, "<tr>");
			len = strlen(dirroot) + strlen(Filename) + 1;
			realFilename = malloc(len + 1);
			bzero(realFilename, len + 1);
			sprintf(realFilename, "%s/%s", dirroot, Filename);
			if (stat(realFilename, &info) == 0)
			{
				if (strcmp(dirent->d_name, "..") == 0)
				{
					fprintf(client_sock,
						"<td><a href=\"http://%s%s%s\">(parent)</a></td>",
						host, atoi(port) == 80 ? "" : nport,
						dir_up(Path));
				}
				else
				{
					fprintf(client_sock,
						"<td><a href=\"http://%s%s%s\">%s</a></td>",
						host, atoi(port) == 80 ? "" : nport, Filename,
						dirent->d_name);
				}
				if (S_ISDIR(info.st_mode))
					//fprintf(client_sock, "<td>目录</td>");
fprintf(client_sock, "<td>Dir</td>");
else if (S_ISREG(info.st_mode))
fprintf(client_sock, "<td>%d</td>", (int)info.st_size);
				else if (S_ISLNK(info.st_mode))
					//fprintf(client_sock, "<td>链接</td>");
					fprintf(client_sock, "<td>Link</td>");
				else if (S_ISCHR(info.st_mode))
					//fprintf(client_sock, "<td>字符设备</td>");
					fprintf(client_sock, "<td>Char Device</td>");
				else if (S_ISBLK(info.st_mode))
					//fprintf(client_sock, "<td>块设备</td>");
					fprintf(client_sock, "<td>Block Device</td>");
else if (S_ISFIFO(info.st_mode))
					fprintf(client_sock, "<td>FIFO</td>");
				else if (S_ISSOCK(info.st_mode))
					fprintf(client_sock, "<td>Socket</td>");
				else
					//fprintf(client_sock, "<td>(未知)</td>");
					fprintf(client_sock, "<td>(Unknown)</td>");
				fprintf(client_sock, "<td>%s</td>", ctime(&info.st_ctime));
			}
			fprintf(client_sock, "</tr>\n");
			free(realFilename);
		}
fprintf(client_sock, "</table></center></body></html>");
	}
	else
	{
		//既非常规文件又非目录，禁止访问
		fprintf(client_sock,
			"HTTP/1.1 200 OK\r\nServer:SONG\r\nConnection: close\r\nContent-Type:text/html; charset=UTF-8\r\n<html><head><title>permission denied</title></head>"
			"<body><font size=+4>[NGI Lab] 973 Project Testing Server - coded by zxWang-wrong</font><br><hr width=\"100%%\"><br><center>"
			"<table border cols=3 width=\"100%%\">");
		fprintf(client_sock,
			"</table><font color=\"CC0000\" size=+2>Path '%s' denied</font></body></html& gt;",
			Path);
	}
out:
	free(realPath);
	free(nport);
}

/*****************************************
* 函数名称：getoption
* 功能描述：
分析取出程序的参数
* 参数列表：
* 返回结果：
*****************************************/
void getoption(int argc, char **argv)
{
	int c, len;
	char *p = 0;
	
	opterr = 0;
	while (1)
	{
		int option_index = 0;
		static struct option long_options[] =
		{
			{"host", 1, 0, 0},
			{"port", 1, 0, 0},
			{"back", 1, 0, 0},
			{"dir", 1, 0, 0},
			{"log", 1, 0, 0},
			{"daemon", 0, 0, 0},
			{0, 0, 0, 0}
		};
		//本程序支持如一些参数：
		//--host   IP地址        或  -H  IP地址
		//--port   端口          或  -P  端口
		//--back   监听数量      或  -B  监听数量
		//--dir    网站根目录    或  -D  网站根目录
		//--log    日志存放路径  或  -L  日志存放路径
		//--daemon 后台模式
		c = getopt_long(argc, argv, "H:P:B:D:L",
			long_options, &option_index);
		if (c == -1 || c == '?')
			break;
		
		if(optarg)
			len = strlen(optarg);
		else
			len = 0;
		
		if ((!c
			&& !(strcasecmp(long_options[option_index].name, "host")))
			|| c == 'H')
			p = host = malloc(len + 1);
		else if ((!c
			&& !(strcasecmp(long_options[option_index].name, "port")))
			|| c == 'P')
			p = port = malloc(len + 1);
		else if ((!c
			&& !(strcasecmp(long_options[option_index].name, "back")))
			|| c == 'B')
			p = back = malloc(len + 1);
		else if ((!c
			&& !(strcasecmp(long_options[option_index].name, "dir")))
			|| c == 'D')
			p = dirroot = malloc(len + 1);
		else if ((!c
			&& !(strcasecmp(long_options[option_index].name, "log")))
			|| c == 'L')
			p = logdir = malloc(len + 1);
		else if ((!c
			&& !(strcasecmp(long_options[option_index].name, "daemon"))))
		{
			daemon_y_n = 1;
			continue;
		}
		else
			break;
		bzero(p, len + 1);
		memcpy(p, optarg, len);
	}
}

/*******************************************************************************************************************************************
*******************************************原始套接字接收数据包，解析从MAC层以上的所有数据****************************************************
*******************************************************************************************************************************************/
int CoLoR_Sendpkg ( char * mac,char * broad_mac,char * ip,char * dest,uint16_t port );

//接收缓冲区（即接收原始数据）大小
#define RCV_BUF_SIZE     1024 * 5

//接收缓冲区
static int g_iRecvBufSize = RCV_BUF_SIZE;
static char g_acRecvBuf[RCV_BUF_SIZE] = {0};

//物理网卡接口,需要根据具体情况修改
static const char *g_szIfName = Physical_Port;

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
	if(flag_localtest != 0)
	{
		if((strncmp((char*)pkg->ether_shost,(char*)local_mac,6)==0) && (pkg->port_no == PORTNUM))
		{
			return -1;
		}
	}
	
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
	
	memcpy((uint8_t*)tempGet.ether_dhost,(uint8_t*)pkg->ether_dhost,6);
	memcpy((uint8_t*)tempGet.ether_shost,(uint8_t*)pkg->ether_shost,6);
	tempGet.ether_type = pkg->ether_type;
	
	printf (">>>CoLoR-Get Received.\n");
	printf ("   |=================Packet=================|\n");
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
	
	memcpy(tempsid, tempGet.sid, tempGet.sid_len/*SID长度*/);
	printf ("   |========================================|\n");
	
	//启动对Get包的响应
	if(tempGet.port_no == 4141)//来自mplayer的Get请求
	{
		CoLoR_Sendpkg ( local_mac,broad_mac,local_ip,dest_ip,4141 );
	}
	
	
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
	printf ("   |=================Packet=================|\n");
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
	
	p += sizeof(uint32_t)-1;//-1修正，尚不清楚p为什么在这里会向后错一位
	
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
	
	//向HTTP_Server发送Got信令
	int socket_sidsender;
	socket_sidsender=socket(AF_INET,SOCK_DGRAM,0);
	
	printf ("   |========================================|\n");
	
	sprintf(temp,"GOT%s",pkg->data);//When this code file is moved to CoLoR, change "wangzhaoxu" to a char* witch contains the SID.
	
	struct sockaddr_in addrTo;
	bzero(&addrTo,sizeof(addrTo));
	addrTo.sin_family=AF_INET;
	addrTo.sin_port=htons(PORTtoMAC);
	addrTo.sin_addr.s_addr=inet_addr(SIDDES);
	
	sendto(socket_sidsender,temp,sizeof(temp),0,(struct sockaddr *)&addrTo,sizeof(addrTo));
	
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
	
	if ( GetLocalMac ( Physical_Port,local_mac,local_ip ) ==-1 )
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
	
	//循环监听
	while(1)
	{
		//清空接收缓冲区
		memset(g_acRecvBuf, 0, RCV_BUF_SIZE);
		
		//接收数据帧
		iRet = recvfrom(fd, g_acRecvBuf, g_iRecvBufSize, 0, NULL, &stFromLen);
		if (0 > iRet)
		{
			continue;
		}
		
		//解析数据帧
		Ethernet_ParseFrame(g_acRecvBuf);
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////（上）子线程back调用声明与函数
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////（下）子线程get调用声明与函数

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
* 功能描述：发送mac层组装的数据包（目前用于发送Get包的过程）
* 参数列表：
char * mac
char * broad_mac
char * ip
char * dest
* 返回结果：
int
*****************************************/

int CoLoR_Sendpkg ( char * mac,char * broad_mac,char * ip,char * dest,uint16_t port )
{
	
	if(port == 1)//为HTTP的SID匹配请求发送Get包
	{
		int i;
		Ether_CoLoR_get pkg;
		struct hostent *host =NULL;
		struct sockaddr sa;
		int sockfd,len;
		unsigned char temp_ip[5];
		memset ( ( char * ) &pkg,'\0',sizeof ( pkg ) );
		
		//填充ethernet包文
		memcpy ( ( char * ) pkg.ether_shost, ( char * ) mac,6 );
		memcpy ( ( char * ) pkg.ether_dhost, ( char * ) broad_mac,6 );
		//pkg.ether_type = htons ( ETHERTYPE_ARP );
		pkg.ether_type = htons ( 0x0800 );
		
		//填充CoLoR-Get包文
		pkg.version_type = 160;//版本4位，类型4位，此为设置成CoLoR_Get包
		pkg.ttl = 255;//生存时间
		//pkg.data_len = htons(4);
		pkg.total_len = SIDLEN + NIDLEN + PIDN*4 + DATALEN + PUBKEYLEN + 16;//总长度
		
		pkg.port_no = 0;//端口号
		pkg.checksum = 0;//检验和
		
		pkg.sid_len = SIDLEN;//SID长度
		pkg.nid_len = NIDLEN;//NID长度
		pkg.pid_n = PIDN;//PID长度
		pkg.options_static = 0;//固定首部选项
		
		memcpy(pkg.sid, tempSID, SIDLEN);//SID
		char nid[NIDLEN] = {'I',' ','a','m',' ','t','h','e',' ','h','o','s','t','~','~','!'};		
		memcpy(pkg.nid, nid, NIDLEN);//NID
		
		pkg.publickey_len = PUBKEYLEN;
		pkg.mtu = MTU;
		
		char data[DATALEN] = {'I',' ','a','m',' ','t','h','e',' ','d','a','t','a','~','~','~','~','~','~','!'};
		memcpy(pkg.data, data, DATALEN);//Data
		
		char publickey[PUBKEYLEN] = {'I',' ','a','m',' ','t','h','e',' ','p','u','b','k','e','y','!'};
		memcpy(pkg.publickey, publickey, PUBKEYLEN);//公钥
		
		
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
		strcpy ( sa.sa_data,Physical_Port );
		
		len = sendto ( sockfd,&pkg,sizeof ( pkg ),0,&sa,sizeof ( sa ) );//发出Get包到mac层
		
		printf ("   CoLoR-Get  to   Cache Terminal. SID : %s\n",pkg.sid);//输出CoLoR-Get向MAC层发包的提示
		
		if ( len != sizeof ( pkg ) )//如果发送长度与实际包不匹配，发送失败
		{
			fprintf ( stderr,"Sendto Error:%s\n\a",strerror ( errno ) );
			close(sockfd);
			return ( 0 );
		}
		
		close(sockfd);
	}
	
	
	if(port == 4141)//为mplayer回送Data
	{
		int i;
		//
		//CoLoR协议Data包首部（PID之前）字段长度固定，用于封装-mplayer发送HTTP导引头专用
		typedef struct _Ether_CoLoR_data_mplayer_head Ether_CoLoR_data_mplayer_head;
		struct _Ether_CoLoR_data_mplayer_head
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
			
			uint8_t data[110];//Data
			
			uint8_t data_signature[16];//数字签名
		};
		//CoLoR协议Data包首部（PID之前）字段长度固定，用于封装-mplayer发送音频视频正文专用
		typedef struct _Ether_CoLoR_data_mplayer_data Ether_CoLoR_data_mplayer_data;
		struct _Ether_CoLoR_data_mplayer_data
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
			
			uint8_t data[1000];//Data
			
			uint8_t data_signature[16];//数字签名
		};
		//
		Ether_CoLoR_data_mplayer_head pkg_head;
		struct sockaddr sa1;
		int sockfd_head,len_head;
		memset((char*)&pkg_head,'\0',sizeof(pkg_head));
		
		//读取文件
		int fd, datalen, ret;
		char *p, *realPath, data_head[110];
		
		fd = open(DATAFLOWPATH, O_RDONLY);
		datalen = lseek(fd, 0, SEEK_END);
		p = (char *) malloc(datalen + 1);
		bzero(p, datalen + 1);
		lseek(fd, 0, SEEK_SET);
		ret = read(fd, p, datalen);
		
		close(fd);
		sprintf(data_head,
			"HTTP/1.1 200 OK\r\nServer:SONG\r\nConnection: keep-alive\r\nContent-type: application/*\r\nContent-Length:%d\r\n\r\n",
			110);
		
		//发送HTTP导引头
		//填充ethernet包文
		memcpy ( ( char * ) pkg_head.ether_shost, ( char * ) mac,6 );
		memcpy ( ( char * ) pkg_head.ether_dhost, ( char * ) broad_mac,6 );
		//pkg_head.ether_type = htons ( ETHERTYPE_ARP );
		pkg_head.ether_type = htons ( 0x0800 );
		
		//填充CoLoR-Get包文
		pkg_head.version_type = 161;//版本4位，类型4位，此为设置成CoLoR_Data包
		pkg_head.ttl = 255;//生存时间
		//pkg_head.data_len = htons(4);
		pkg_head.total_len = SIDLEN + NIDLEN + PIDN*4 + 110 + PUBKEYLEN + 16;//总长度
		
		pkg_head.port_no = 4141;//端口号
		pkg_head.checksum = 0;//检验和
		
		pkg_head.sid_len = SIDLEN;//SID长度
		pkg_head.nid_len = NIDLEN;//NID长度
		pkg_head.pid_n = PIDN;//PID长度
		pkg_head.options_static = 0;//固定首部选项
		
		pkg_head.signature_algorithm=1;//签名算法
		pkg_head.if_hash_cache=0;//是否哈希4位，是否缓存4位
		pkg_head.options_dynamic=0;//可变首部选项
		
		memcpy(pkg_head.sid, tempSID, SIDLEN);//SID
		char nid[NIDLEN] = {'I',' ','a','m',' ','t','h','e',' ','h','o','s','t','~','~','!'};		
		memcpy(pkg_head.nid, nid, NIDLEN);//NID
		
		
		
		memcpy(pkg_head.data, data_head, 110);//Data
		
		
		//实际应该使用PF_PACKET
		if ( ( sockfd_head = socket ( PF_PACKET/*PF_INET*/,SOCK_PACKET,htons ( ETH_P_ALL ) ) ) ==-1 )
		{
			fprintf ( stderr,"Socket Error:%s\n\a",strerror ( errno ) );
			return ( 0 );
		}
		
		memset ( &sa1,'\0',sizeof ( sa1 ) );
		strcpy ( sa1.sa_data,Physical_Port );
		
		len_head = sendto ( sockfd_head,&pkg_head,sizeof ( pkg_head ),0,&sa1,sizeof ( sa1 ) );//发出Get包到mac层
		
		printf(">>>CoLoR-Data Sent\n");//输出CoLoR-Get向MAC层发包的提示
		printf ("   |=================HTTPhead=================|\n");
        printf("%s\n",pkg_head.data);
		printf ("   |==========================================|\n");
		
		if ( len_head != sizeof ( pkg_head ) )//如果发送长度与实际包不匹配，发送失败
		{
			fprintf ( stderr,"Sendto Error:%s\n\a",strerror ( errno ) );
			close(sockfd_head);
			return ( 0 );
		}
		
		close(sockfd_head);
		/*
		//检查读取文件正文的头100个字节
		printf("datalen = %d\ndata = \n",datalen);
		int dd=0;
		char c;
		while(dd<100)
		{
		c = *(p+dd);
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
		printf("\n");
		*/
		
		//fwrite(p, datalen, 1, client_sock);//将p中的字符串以长度为datalen写进client_sock
		////////////////////////////////////////////////////////
		Ether_CoLoR_data_mplayer_data pkg_data;
		struct sockaddr sa2;
		int sockfd_data;
		int len_data;
		memset((char*)&pkg_data,'\0',sizeof(pkg_data));
		
		//读取文件
		char data_data[1000];
		
		int point=0;
		int totallen = (datalen/1000+1)*1000;
		
		
		while(point<totallen)
		{//printf("||roundstart:\n");
			char d;
			scanf("%c",&d);
			
			memcpy(data_data,p+point,1000);
			printf(">>>CoLoR-Data Sent\n");//输出CoLoR-Get向MAC层发包的提示
			printf("   datalen = %d; totallen = %d; point = %d\n",datalen,totallen,point);
			
			point+=1000;
			
			//发送dataflow正文
			//填充ethernet包文
			memcpy ( ( char * ) pkg_data.ether_shost, ( char * ) mac,6 );
			memcpy ( ( char * ) pkg_data.ether_dhost, ( char * ) broad_mac,6 );
			//pkg_data.ether_type = htons ( ETHERTYPE_ARP );
			pkg_data.ether_type = htons ( 0x0800 );
			
			//填充CoLoR-Get包文
			pkg_data.version_type = 161;//版本4位，类型4位，此为设置成CoLoR_Data包
			pkg_data.ttl = 255;//生存时间
			//pkg_data.data_len = htons(4);
			pkg_data.total_len = SIDLEN + NIDLEN + PIDN*4 + 1000 + PUBKEYLEN + 16;//总长度
			
			pkg_data.port_no = 4141;//端口号
			pkg_data.checksum = 0;//检验和
			
			pkg_data.sid_len = SIDLEN;//SID长度
			
			pkg_data.nid_len = NIDLEN;//NID长度
			pkg_data.pid_n = PIDN;//PID长度
			pkg_data.options_static = 0;//固定首部选项
			
			pkg_data.signature_algorithm=1;//签名算法
			pkg_data.if_hash_cache=0;//是否哈希4位，是否缓存4位
			pkg_data.options_dynamic=0;//可变首部选项
			
			memcpy(pkg_data.sid, tempSID, SIDLEN);//SID
			//char nid[NIDLEN] = {'I',' ','a','m',' ','t','h','e',' ','h','o','s','t','~','~','!'};		
			//memcpy(pkg_data.nid, nid, NIDLEN);//NID
			
			
			
			memcpy(pkg_data.data, data_data, 1000);//Data
			
			
			
			printf ("   |=================HTTPdata=================|\n");
			//
			int dd=0;
			char c;
			while(dd<1000)
			{
				c = *(pkg_data.data+dd);
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
			printf ("\n   |==========================================|\n");
			
			//实际应该使用PF_PACKET
			if ( ( sockfd_data = socket ( PF_PACKET/*PF_INET*/,SOCK_PACKET,htons ( ETH_P_ALL ) ) ) ==-1 )
			{
				fprintf ( stderr,"Socket Error:%s\n\a",strerror ( errno ) );
				return ( 0 );
			}
			
			memset ( &sa2,'\0',sizeof ( sa2 ) );
			strcpy ( sa2.sa_data,Physical_Port );
			
			len_data = sendto ( sockfd_data,&pkg_data,sizeof ( pkg_data ),0,&sa2,sizeof ( sa2 ) );//发出Get包到mac层
			
			//printf ("   CoLoR-Data to   mplayer.\n");//输出CoLoR-Data向MAC层发包的提示
			
			if ( len_data != sizeof ( pkg_data ) )//如果发送长度与实际包不匹配，发送失败
			{
				fprintf ( stderr,"Sendto Error:%s\n\a",strerror ( errno ) );
				close(sockfd_data);
				return ( 0 );
			}printf(">>>flow pkg count = %d\n",++test_count);
			
			close(sockfd_data);
		}
		/////////////////////////////////////////////////////////
        free(p);
		
		
}

return 1;
}


/*******************************************************************************************************************************************
**********************************************************多线程计时器基本模型***************************************************************
*******************************************************************************************************************************************/

//单点基本配置
//#define PORTtoHTTP 6001
//#define PORTtoMAC 6002

//计时器
#define SLEEP 1
#define SLEEP_XX 1

int flag_timer_XX = 0;      //XX线程执行标识符

time_t GMT;                     //国际标准时间，实例化time_t结构(typedef long time_t;)
struct tm *UTC;                 //北京时区时间，实例化tm结构指针(tm记录年月日星期时分秒的int型表示)

//线程函数
void *thread_timer(void *fd);
void *thread_XX(void *fd);
void *thread_recvdata(void *fd);
void *thread_sendget(void *fd);

/*****************************************
* 函数名称：main
* 功能描述：主函数，启动各个线程，自身不提供实际功能
* 参数列表：
* 返回结果：
*****************************************/
int main(int argc,char *argv[])
{
	int i,j;
	
	//创建发送计时器子线程
	pthread_t pthread_timer;
	if(pthread_create(&pthread_timer, NULL, thread_timer, NULL)!=0)
	{
		perror("Creation of timer thread failed.");
	}
	
	//创建XX子线程
	pthread_t pthread_XX;
	if(pthread_create(&pthread_XX, NULL, thread_XX, NULL)!=0)
	{
		perror("Creation of XX thread failed.");
	}
	
	//创建thread_recvdata子线程
	pthread_t pthread_recvdata;
	if(pthread_create(&pthread_recvdata, NULL, thread_recvdata, NULL)!=0)
	{
		perror("Creation of recvdata thread failed.");
	}
	
	//创建thread_sendget子线程
	pthread_t pthread_sendget;
	if(pthread_create(&pthread_sendget, NULL, thread_sendget, NULL)!=0)
	{
		perror("Creation of sendget thread failed.");
	}
	/*
	//维持主线程的运行，没有实际功能
	while(1)
	{
	}
	*/
	
	struct sockaddr_in addr;
	struct sockaddr_in my_addr;
	my_addr.sin_addr.s_addr=htonl(INADDR_ANY);
	int sock_fd, addrlen;
	
	//获得程序工作的参数，如 IP 、端口、监听数、网页根目录、目录存放位置等
	getoption(argc, argv);
	
	if (!host)
	{
		addrlen = strlen(DEFAULTIP);
		AllocateMemory(&host, addrlen,DEFAULTIP);
	}
	if (!port)
	{
		addrlen = strlen(DEFAULTPORT);
		AllocateMemory(&port, addrlen, DEFAULTPORT);
	}
	if (!back)
	{
		addrlen = strlen(DEFAULTBACK);
		AllocateMemory(&back, addrlen, DEFAULTBACK);
	}
	if (!dirroot)
	{
		addrlen = strlen(DEFAULTDIR);
		AllocateMemory(&dirroot, addrlen, DEFAULTDIR);
	}
	if (!logdir)
	{
		addrlen = strlen(DEFAULTLOG);
		AllocateMemory(&logdir, addrlen, DEFAULTLOG);
	}
	
	
	printf("host=%s \nport=%s \nback=%s \ndirroot=%s \nlogdir=%s \n%sthe background model(Process ID: %d)\n",
		host, port, back, dirroot, logdir, daemon_y_n?"This is ":"This is not ", getpid());
	
	//fork() 两次处于后台工作模式下
	if (daemon_y_n)
	{
		if (fork())
			exit(0);
		if (fork())
			exit(0);
		close(0), close(1), close(2);
		logfp = fopen(logdir, "a+");
		if (!logfp)
			exit(0);
	}
	
	//处理子进程退出以免产生僵尸进程
	signal(SIGCHLD, SIG_IGN);
	
	//创建 socket
	/*
	PF_INET is for BSD
	AF_INET is for POSIX
	This location maybe the very place the bug which occured in Debian but not occured in Ubuntu lies.
	*/
	if ((sock_fd = socket(AF_INET/*原为PF_INET*/, SOCK_STREAM, 0)) < 0)
	{
		if (!daemon_y_n)
		{
			prterrmsg("socket()");
		}
		else
		{
			wrterrmsg("socket()");
		}
	}
	
	//设置端口快速重用
	addrlen = 1;
	setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &addrlen,
		sizeof(addrlen));
	
	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(port));
	addr.sin_addr.s_addr = inet_addr(host);
	addrlen = sizeof(struct sockaddr_in);
	//绑定地址、端口等信息
	if (bind(sock_fd, (struct sockaddr *) &addr, addrlen) < 0)
	{
		if (!daemon_y_n)
		{
			prterrmsg("bind()");
		}
		else
		{
			wrterrmsg("bind()");
		}
	}
	
	//开启监听
	if (listen(sock_fd, atoi(back)) < 0)
	{
		if (!daemon_y_n)
		{
			prterrmsg("listen()");
		}
		else
		{
			wrterrmsg("listen()");
		}
	}
	while (1)
	{
		int len;
		int new_fd;
		addrlen = sizeof(struct sockaddr_in);
		//接受新连接请求
		new_fd = accept(sock_fd, (struct sockaddr *) &addr, &addrlen);
		if (new_fd < 0) 
		{
			if (!daemon_y_n) 
			{
				prterrmsg("accept()");
			} 
			else
			{
				wrterrmsg("accept()");
			}
			break;
		}
		bzero(buffer, MAXBUF + 1);
		sprintf(buffer, ">>>Connection from: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
		if (!daemon_y_n) 
		{
			prtinfomsg(buffer);
		} 
		else 
		{
			wrtinfomsg(buffer);
		}
		//产生一个子进程去处理请求，当前进程继续等待新的连接到来
		if (!fork()) 
		{
			bzero(buffer, MAXBUF + 1);
			if ((len = recv(new_fd, buffer, MAXBUF, 0)) > 0) 
			{
				FILE *ClientFP = fdopen(new_fd, "w");
				if (ClientFP == NULL) 
				{
					if (!daemon_y_n) 
					{
						prterrmsg("fdopen()");
					} 
					else 
					{
						prterrmsg("fdopen()");
					}
				} 
				else 
				{
					char Req[MAXPATH + 1] = "";
					sscanf(buffer, "GET %s HTTP", Req);
					bzero(buffer, MAXBUF + 1);
					//提取SID
					for(i=1,j=0;;i++)
					{
						if(Req[i]!='\0')
						{
							SID[j++]=Req[i];
						}
						else
						{
							SID[j] = '\0';
							break;
						}
					}
					if (strcmp(SID, "favicon.ico") == 0)
					{
						continue;
					}
					sprintf(buffer, "");
					if (!daemon_y_n) 
					{
						prtinfomsg(buffer);
					} 
					else
					{
						wrtinfomsg(buffer);
					}
					//处理用户请求
					GiveResponse(ClientFP, Req);
					fclose(ClientFP);
				}
			}
			exit(0);
		}
		close(new_fd);
	}
	close(sock_fd);
	return 0;
	
	exit(0);
	return (EXIT_SUCCESS);
}

/*****************************************
* 函数名称：thread_timer
* 功能描述：为各线程提供计时信号
* 参数列表：fd——连接套接字
* 返回结果：void
*****************************************/
void *thread_timer(void *fd)
{
	int timer_XX = 0;
	
	while(1)
	{
		sleep(SLEEP);
		
		time(&GMT);//读取GMT，赋值给GMT
		UTC = localtime(&GMT);//GMT-UTC转换
		//printf("GMT(long)   %ld\n",GMT);//[GMT]输出1970.1.1.00:00:00至今秒数
		//printf("UTC(human)  %s",asctime(UTC));//[UTC]输出字符化人类可读时间
		
		//为thread_XX定时
		if(++timer_XX == SLEEP_XX)
		{
			flag_timer_XX = 1;
			timer_XX = 0;
		}
	}
	//关闭线程
	exit(0);
	free(fd);
	pthread_exit(NULL);
}

/*******************************************************************************************************************************************
*************************************************************子线程函数*********************************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：thread_XX
* 功能描述：
* 参数列表：fd——连接套接字
* 返回结果：void
*****************************************/
void *thread_XX(void *fd)
{
	static int count_runtime = 0;
	int end = 0;
	while(!end)
	{
		if(flag_timer_XX == 1)
		{/*
		 printf("UTC(human)  %s",asctime(UTC));//[UTC]输出字符化人类可读时间
		 count_runtime++;
		 printf("runtime:%d\n",count_runtime);//输出该线程核心代码执行次数
			flag_timer_XX = 0;*/
		}
	}
	//关闭线程
	exit(0);
	free(fd);
	pthread_exit(NULL);
}


/*****************************************
* 函数名称：thread_recvdata
* 功能描述：
* 参数列表：fd——连接套接字
* 返回结果：void
*****************************************/
void *thread_recvdata(void *fd)
{
    int iRet = -1;
    int fd_socket   = -1;
	
    //初始化SOCKET
    fd_socket = Ethernet_InitSocket();
    if(0 > fd)//SOCKET初始化失败
    {
        printf("Error: thread_sendget() - socket initiate failed./n");
		//关闭线程
		exit(0);
		free(fd);
		pthread_exit(NULL);
    }
	
    //捕获数据包
    Ethernet_StartCapture(fd_socket);
	
    //关闭SOCKET
    close(fd_socket);
	
	//关闭线程
	exit(0);
	free(fd);
	pthread_exit(NULL);
}



/*****************************************
* 函数名称：thread_sendget
* 功能描述：
* 参数列表：fd——连接套接字
* 返回结果：void
*****************************************/
void *thread_sendget(void *fd)
{
	int sin_len;
	char message[100];
	
	int socket_sidreceiver;
	
	struct sockaddr_in sin;
	bzero(&sin,sizeof(sin));
	sin.sin_family=AF_INET;
	sin.sin_addr.s_addr=htonl(INADDR_ANY);
	sin.sin_port=htons(PORTtoHTTP);
	sin_len=sizeof(sin);
	
	socket_sidreceiver=socket(AF_INET,SOCK_DGRAM,0);
	bind(socket_sidreceiver,(struct sockaddr *)&sin,sizeof(sin));
	
	while(1)
	{
		while(1)
		{
			recvfrom(socket_sidreceiver,message,sizeof(message),0,(struct sockaddr *)&sin,&sin_len);
			
			int i=0;
			int j=0;
			int flag_GET = 0;
			if(strncmp(message,"GET",3) == 0)
			{
				flag_GET = 1;
				i+=2;
				for(j=0;;j++)
				{
					if(message[++i]!='\0')
					{
						tempSID[j] = message[i];
					}
					else
						break;
				}
				tempSID[j]=0;
				
				//封装CoLoR-Get协议
				struct timeval tvafter,tvpre;
				struct timezone tz;
				gettimeofday ( &tvpre , &tz );
				
				unsigned char mac[7];
				unsigned char ip[5];
				char dest[16]={0};
				unsigned char broad_mac[7]={0xff,0xff,0xff,0xff,0xff,0xff,0x00};
				
				memset ( mac,0,sizeof ( mac ) );
				memset ( ip,0,sizeof ( ip ) );
				
				if ( GetLocalMac ( Physical_Port,mac,ip ) ==-1 )
				{
					//关闭线程
					exit(0);
					free(fd);
					pthread_exit(NULL);
				}
				
				int i=0;
				{
					sprintf ( dest,"255.255.255.255",i );
					CoLoR_Sendpkg ( mac,broad_mac,ip,dest,1 );
				}
				gettimeofday ( &tvafter , &tz );
				
				break;
			}
		}
	}
	//关闭线程
	exit(0);
	free(fd);
	pthread_exit(NULL);
}

