/*******************************************************************************************************************************************
* 文件名：browserclient.c
* 文件描述：973智慧协同网络SAR系统TestBed套件——浏览器本地协议转接件，上端连接浏览器软件，下端连接数据请求端（Data Subscriber）
* 声明：本模板代码作者王兆旭，为北京交通大学下一代互联网互联设备国家工程实验室新生基础工程技术培训专用。作者王兆旭在此郑重声明，此文件及其它用于培训的模板代码均为本人精力与经验的产物，本资源的传播方式均为作者本人向他人进行一对一传授，任何个人不得向第三方转交或展示该资源内容。任何有需求的学员，均须向王兆旭本人直接索要，亦无向他人索要或传授之权利和义务。因有些资源内容涉及实验室项目秘密，暂不考虑申请专利保护或软件著作权等事宜，故个别资源仅限实验室内部一对一发放，如发现有辜负作者本人的一片好意的行为，作者将保留就其原创性进行追查、举证、申诉和问责的权利。本资源的发放权归作者本人所有，其整理和总结过程浸透无偿贡献的热忱和为诸君学业尽绵薄之力的真诚，愿学员尊重作者的劳动成果，谢谢合作！
* 作者：王兆旭
* 身份：北京交通大学下一代互联网互联设备国家工程实验室 2013级硕博连读研究生
* E-mail. hellozxwang@foxmail.com
* Mobile. 18811774990
* QQ    . 535667240
* Addr  . 北京市海淀区西直门外北京交通大学机械楼D706室, 100044
*******************************************************************************************************************************************/
/*******************************************************************************************************************************************
*****功能说明：1.充当上端浏览器软件的本地HTTP服务器
**************2.向下端数据请求端（Data Subscriber）提供所请求的SID，接收DATA并向浏览器软件以HTTP协议返回
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
gcc browserclient.c -o browserclient -lpthread
4、运行（因涉及原始套接字的使用，须root权限）
sudo ./browserclient
*/

#include"browserclient.h"

/*******************************************************************************************************************************************
*************************************宏定义配置数据************全局变量定义******************************************************************
*******************************************************************************************************************************************/

/*******************************************************************************************************************************************
*******************************************初始化参数配置相关********************************************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：BrowserClient_Parameterinit
* 功能描述：BrowserClient模块全局变量赋初值
* 参数列表：
* 返回结果：
*****************************************/
void
BrowserClient_Parameterinit()
{
	//HTTP_Server调用声明与函数
	memset(buffer,0,MAXBUF+1);

	host       = 0;
	port       = 0;
	back       = 0;
	dirroot    = 0;
	logdir     = 0;
	daemon_y_n = 0;

	logfp      = 0;
}

/*******************************************************************************************************************************************
*******************************************应用层（HTTP）服务器（由browserclient主循环调用和控制）***********************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：BrowserClient_dir_up
* 功能描述：查找dirpath所指目录的上一级目录
* 参数列表：
* 返回结果：
*****************************************/
char *
BrowserClient_dir_up
(
	char * dirpath
)
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
* 函数名称：BrowserClient_AllocateMemory
* 功能描述：分配空间并把d所指的内容复制
* 参数列表：
* 返回结果：
*****************************************/
void
BrowserClient_AllocateMemory
(
	char ** s,
	int l,
	char * d
)
{
	*s = malloc(l + 1);
	bzero(*s, l + 1);
	memcpy(*s, d, l);
}

/*****************************************
* 函数名称：BrowserClient_GiveResponse
* 功能描述：把Path所指的内容发送到client_sock去
* 参数列表：
* 返回结果：
如果Path是一个目录，则列出目录内容
如果Path是一个文件，则下载文件
*****************************************/
void
BrowserClient_GiveResponse
(
	FILE * client_sock,
	char * Path
)
{
	int i=0;
	int j=0;
	char str[100];
	memset(str,0,100);
	
	
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
		socket_sidsender = socket(AF_INET,SOCK_DGRAM,0);
		
		struct sockaddr_in addrTo;
		bzero(&addrTo,sizeof(addrTo));
		addrTo.sin_family=AF_INET;
		addrTo.sin_port=htons(APPLtoTRAL);
		//unsigned long IPto = 2130706433;//回环地址名称 == 2130706433
		//addrTo.sin_addr.s_addr=htonl(IPto);//htonl将主机字节序转换为网络字节序
		addrTo.sin_addr.s_addr=inet_addr(LOOPIP);//htonl将主机字节序转换为网络字节序

		//发送SID信令
		sprintf(temp,"GET%s",SID);
		sendto(socket_sidsender,temp,sizeof(temp),0,(struct sockaddr *)&addrTo,sizeof(addrTo));
		close(socket_sidsender);

		if(DEVETESTIMPL <= 1)
			printf("   The HTTP Client asked for Data whitch match the SID: %s\n",SID);
		
		//死循环监听回送资源成功的信令
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
			printf("HTTP responce listening start.\n");
		
		char message[100];
		while(1)
		{
			memset(message,0,100);
			
			recvfrom(socket_datareceiver,message,sizeof(message),0,(struct sockaddr *)&sin,&sockaddr_len);

			if(DEVETESTIMPL <= 1)
				printf("HTTP responce listener receives a new UDP message.\n");
			
			//接受到的消息为 “GOT”
			if(strncmp(message,"GOT",3) == 0)
			{
				if(DEVETESTIMPL <= 1)
					printf("HTTP responce listener receives a new UDP GOT message.\n");

				flag_sidgot = 1;
				i=2;
				for(j=0;;j++)
				{
					if(message[++i] != 0)
					{
						str[j] = message[i];
					}
					else
						break;
				}
				str[j] = 0;
				break;
			}
			//printf("Data \"%s\" has been received and it will be sent to the HTTP Client immediately./n",str);
			/*
			sleep(1);
			counter_sidget++;
			if(counter_sidget >= MAX_GETSIDTIME)//如果提取SID对应资源的请求超过MAX_GETSIDTIME的预设时间没有回复，则认为请求失败
			{
			break;
			}
			*/
		}	
		close(socket_datareceiver);
		
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
						BrowserClient_dir_up(Path));
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
* 函数名称：BrowserClient_getoption
* 功能描述：分析取出程序的参数
* 参数列表：
* 返回结果：
*****************************************/
void
BrowserClient_getoption
(
	int argc,
	char argv[][30]
)
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
		c = getopt_long(argc, (char **)argv, "H:P:B:D:L",
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
*******************************************上行通道 - From.数据请求端   To.应用服务器*********************************************************
*******************************************************************************************************************************************/

/*******************************************************************************************************************************************
*******************************************下行通道 - From.应用服务器 To.数据请求端***********************************************************
*******************************************************************************************************************************************/

/*******************************************************************************************************************************************
**********************************************************多线程主干程序********************************************************************
*******************************************************************************************************************************************/

/*****************************************
* 函数名称：BrowserClient_main
* 功能描述：BrowserClient模块主函数，启动ForwardingPlane转发平面线程。自身主循环执行简单HTTP服务器功能。
* 参数列表：
eg: ./sub d1sub1 d1sub1-eth1
第二参数使用char**argv的方式声明报错，不知是不是语法问题
* 返回结果：
*****************************************/
int
BrowserClient_main
(
	int argc,
	char argv[][30]
)
{
	int i,j;

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

	//主循环——HTTP服务端代码

	struct sockaddr_in addr;
	struct sockaddr_in my_addr;
	my_addr.sin_addr.s_addr=htonl(INADDR_ANY);
	int sock_fd, addrlen;
	
	//获得程序工作的参数，如 IP 、端口、监听数、网页根目录、目录存放位置等
	//BrowserClient_getoption(argc, (char (*)[30])argv);
	
	if (!host)
	{
		addrlen = strlen(DEFAULTIP);
		BrowserClient_AllocateMemory(&host, addrlen,DEFAULTIP);
	}
	if (!port)
	{
		addrlen = strlen(DEFAULTPORT);
		BrowserClient_AllocateMemory(&port, addrlen, DEFAULTPORT);
	}
	if (!back)
	{
		addrlen = strlen(DEFAULTBACK);
		BrowserClient_AllocateMemory(&back, addrlen, DEFAULTBACK);
	}
	if (!dirroot)
	{
		addrlen = strlen(DEFAULTDIR);
		BrowserClient_AllocateMemory(&dirroot, addrlen, DEFAULTDIR);
	}
	if (!logdir)
	{
		addrlen = strlen(DEFAULTLOG);
		BrowserClient_AllocateMemory(&logdir, addrlen, DEFAULTLOG);
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
		
		if(DEVETESTIMPL <= 1)
		{
			sprintf(buffer, ">>>Connection from: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
			if (!daemon_y_n) 
			{
				prtinfomsg(buffer);
			} 
			else 
			{
				wrtinfomsg(buffer);
			}
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
					BrowserClient_GiveResponse(ClientFP, Req);
					
					fclose(ClientFP);
				}
			}
			//exit(0);
		}
		close(new_fd);
	}
	close(sock_fd);
}
