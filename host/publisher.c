/*******************************************************************************************************************************************
* �ļ�����publisher.c
* �ļ�������973�ǻ�Эͬ����SARϵͳTestBed�׼��������ݷ����ˣ�Data Publisher������GET�����ս���+����SID��Dataƥ��+DATA����װ����
*******************************************************************************************************************************************/
/*******************************************************************************************************************************************
*****����˵����1.���������ڷ��Ͱ�������SID��ӦData��DATA���Ͱ�
**************2.�������������ڼ�����SAR/CoLoR�������ݰ���
**************3.�ӽ��յ���GET������ȡSID
**************4.���ز�ѯ�������ݣ��ҵ�SIDƥ���Data����
*******************************************************************************************************************************************/
/*
�������ò��裺
1���궨���޸�
CACHEPATHָ�洢SID��Dataƥ���ϵ���ļ���Ĭ���ļ���cache.log��·����Ҫ���иó������Ա���о�����������ļ�ʵ�ʴ��ڵ�λ�ö��Ϻž�����
PhysicalPortָCoLoRЭ�鷢��Get���ͽ���Data���������˿ڣ�ע��������Ĭ�����߶˿������Ƿ�Ϊeth0����Fedora20ϵͳ�е�Ĭ������Ϊem1����ע��ʶ��
2��ϵͳ����
��Fedoraϵͳ������Ҫʹ��ԭʼ�׽��ַ����Զ����ʽ�����ݰ�����ر�Fedora�ķ���ǽ�����
sudo systemctl stop firewalld.service
��Ubuntuϵͳ�������κβ���
3����������
gcc publisher.c -o publisher -lpthread
4�����У����漰ԭʼ�׽��ֵ�ʹ�ã���rootȨ�ޣ�
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
*************************************�궨����������************ȫ�ֱ�������************����ʽ����*********************************************
*******************************************************************************************************************************************/

//�����ڲ�CoLoR����
uint8_t PhysicalPort[30];                     //�����˿�
#define LOCALTEST     0                       //�Ƿ�Ϊ����˫�˲��ԣ�������Ϊ��0ֵ����������Ϊ0
#define PORTNUM       1                       //������ʹ�õĶ˿ں�
#define CACHEPATH     "./cache.log"//�����ļ�·��

//Э����أ����ڷ�������Ӱ����ݾ����ֶι涨�ĳ����հ���
#define SIDLEN    20                          //SID����
#define NIDLEN    16                          //NID����
#define PIDN      0                           //PID����
#define DATALEN   20                          //Data����
#define PUBKEYLEN 16                          //��Կ����
#define MTU       1500                        //����䵥Ԫ
#define SIGNATURELEN 16

//ȫ�ֱ���
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

//PID����
typedef struct _PIDEvent PIDEvent;
struct _PIDEvent
{
	unsigned char did[10];
	unsigned char pid[4];
	unsigned char nid[16];
};
PIDEvent pidlist[100];//����PID��
int pidlistcount=-1;

//SID��RMע�����


//CoLoRЭ�����������жϵ��ֶΣ���ֹ���̶��ײ�������Version/Type�ֶ�ΪGet����Data����Register����ͨ�ã�
typedef struct _Ether_VersionType Ether_VersionType;
struct _Ether_VersionType
{
	//ethernetͷ
	uint8_t ether_dhost[6]; //Ŀ��Ӳ����ַ
	uint8_t ether_shost[6]; //ԴӲ����ַ
	uint16_t ether_type; //��������
	
	//CoLoR-Dataͷ
	uint8_t version_type;////�汾4λ������4λ
	uint8_t ttl;//����ʱ��
	uint16_t total_len;//�ܳ���
	
	uint16_t port_no;//�˿ں�
	uint16_t checksum;//�����
	
	uint8_t sid_len;//SID����
	uint8_t nid_len;//NID����
	uint8_t pid_n;//PID����
	uint8_t options_static;//�̶��ײ�ѡ��
};
Ether_VersionType tempVersionType;

//CoLoRЭ��Get���ײ���PID֮ǰ���ֶγ��ȹ̶������ڷ�װ
typedef struct _Ether_CoLoR_get Ether_CoLoR_get;
struct _Ether_CoLoR_get
{
	//ethernetͷ
	uint8_t ether_dhost[6]; //Ŀ��Ӳ����ַ
	uint8_t ether_shost[6]; //ԴӲ����ַ
	uint16_t ether_type; //��������
	
	//CoLoR-Getͷ
	uint8_t version_type;////�汾4λ������4λ
	uint8_t ttl;//����ʱ��
	uint16_t total_len;//�ܳ���
	
	uint16_t port_no;//�˿ں�
	uint16_t checksum;//�����
	
	uint8_t sid_len;//SID����
	uint8_t nid_len;//NID����
	uint8_t pid_n;//PID����
	uint8_t options_static;//�̶��ײ�ѡ��
	
	uint16_t publickey_len;//��Կ����
	uint16_t mtu;//����䵥Ԫ
	
	uint8_t sid[SIDLEN];//SID
	uint8_t nid[NIDLEN];//NID
	
	uint8_t data[DATALEN];//Data
	
	uint8_t publickey[PUBKEYLEN];//��Կ
};

//CoLoRЭ��Get���ײ���PID֮ǰ���ֶγ��ȿɱ䣬���ڽ���
typedef struct _Ether_CoLoR_get_parse Ether_CoLoR_get_parse;
struct _Ether_CoLoR_get_parse
{
	//ethernetͷ
	uint8_t ether_dhost[6]; //Ŀ��Ӳ����ַ
	uint8_t ether_shost[6]; //ԴӲ����ַ
	uint16_t ether_type; //��������
	
	//CoLoR-Getͷ
	uint8_t version_type;////�汾4λ������4λ
	uint8_t ttl;//����ʱ��
	uint16_t total_len;//�ܳ���
	
	uint16_t port_no;//�˿ں�
	uint16_t checksum;//�����
	
	uint8_t sid_len;//SID����
	uint8_t nid_len;//NID����
	uint8_t pid_n;//PID����
	uint8_t options_static;//�̶��ײ�ѡ��
	
	uint16_t publickey_len;//��Կ����
	uint16_t mtu;//����䵥Ԫ
	
	uint8_t* sid;//SID
	uint8_t* nid;//NID
	
	uint8_t* data;//Data
	
	uint8_t* publickey;//��Կ
};
Ether_CoLoR_get_parse tempGet;

//CoLoRЭ��Data���ײ���PID֮ǰ���ֶγ��ȹ̶������ڷ�װ
typedef struct _Ether_CoLoR_data Ether_CoLoR_data;
struct _Ether_CoLoR_data
{
	//ethernetͷ
	uint8_t ether_dhost[6]; //Ŀ��Ӳ����ַ
	uint8_t ether_shost[6]; //ԴӲ����ַ
	uint16_t ether_type; //��������
	
	//CoLoR-Dataͷ
	uint8_t version_type;////�汾4λ������4λ
	uint8_t ttl;//����ʱ��
	uint16_t total_len;//�ܳ���
	
	uint16_t port_no;//�˿ں�
	uint16_t checksum;//�����
	
	uint8_t sid_len;//SID����
	uint8_t nid_len;//NID����
	uint8_t pid_n;//PID����
	uint8_t options_static;//�̶��ײ�ѡ��
	
	uint8_t signature_algorithm;//ǩ���㷨
	uint8_t if_hash_cache;//�Ƿ��ϣ4λ���Ƿ񻺴�4λ
	uint16_t options_dynamic;//�ɱ��ײ�ѡ��
	
	uint8_t sid[SIDLEN];//SID
	uint8_t nid[NIDLEN];//NID
	
	uint8_t data[DATALEN];//Data
	
	uint8_t data_signature[16];//����ǩ��
};

//CoLoRЭ��Data���ײ���PID֮ǰ���ֶγ��ȿɱ䣬���ڽ���
typedef struct _Ether_CoLoR_data_parse Ether_CoLoR_data_parse;
struct _Ether_CoLoR_data_parse
{
	//ethernetͷ
	uint8_t ether_dhost[6]; //Ŀ��Ӳ����ַ
	uint8_t ether_shost[6]; //ԴӲ����ַ
	uint16_t ether_type; //��������
	
	//CoLoR-Dataͷ
	uint8_t version_type;////�汾4λ������4λ
	uint8_t ttl;//����ʱ��
	uint16_t total_len;//�ܳ���
	
	uint16_t port_no;//�˿ں�
	uint16_t checksum;//�����
	
	uint8_t sid_len;//SID����
	uint8_t nid_len;//NID����
	uint8_t pid_n;//PID����
	uint8_t options_static;//�̶��ײ�ѡ��
	
	uint8_t signature_algorithm;//ǩ���㷨
	uint8_t if_hash_cache;//�Ƿ��ϣ4λ���Ƿ񻺴�4λ
	uint16_t options_dynamic;//�ɱ��ײ�ѡ��
	
	uint8_t* sid;//SID
	uint8_t* nid;//NID
	
	uint8_t* data;//Data
	
	uint8_t data_signature[16];//����ǩ��
};
Ether_CoLoR_data_parse tempData;

//CoLoRЭ��Register���ײ���PID֮ǰ��
typedef struct _Ether_CoLoR_register Ether_CoLoR_register;
struct _Ether_CoLoR_register
{
	//ethernetͷ
	uint8_t ether_dhost[6]; //Ŀ��Ӳ����ַ
	uint8_t ether_shost[6]; //ԴӲ����ַ
	uint16_t ether_type; //��������
	
	//CoLoR-Registerͷ
	uint8_t version_type;////�汾4λ������4λ
	uint8_t nid_len;//NID����
	uint8_t sid_n;//SID����
	uint8_t sid_len;//SID����

	uint16_t Public_key_len;//��Կ����
	uint8_t signature_algorithm;//ǩ���㷨
	uint8_t options_static;//�̶��ײ�ѡ��

	uint16_t checksum;//�����
	uint16_t Sequence_number;//���к�

	uint16_t Sequence_number_ack;//���к�_ack
	uint16_t total_len;//�ܳ���
	
	uint8_t nid[NIDLEN];//NID
};
Ether_CoLoR_register tempRegister;

/*******************************************************************************************************************************************
*******************************************ԭʼ�׽��ַ������ݰ�����װ��MAC�����ϵ���������****************************************************
*******************************************************************************************************************************************/

/*****************************************
* �������ƣ�GetLocalMac
* ����������
�õ�������mac��ַ��ip��ַ
Ϊ���ݰ���װʱmac��Դ��ַ�ֶ��ṩ����
* �����б�
const char *device
char *mac
char *ip
* ���ؽ����
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
* �������ƣ�CoLoR_Sendpkg
* ��������������mac����װ�����ݰ���Ŀǰ�����յ�Get���󷵻�Data���Ĺ��̣�
* �����б�
char * mac
char * broad_mac
char * ip
char * dest
* ���ؽ����
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
	
	//���ethernet����
	memcpy ( ( char * ) pkg.ether_dhost, ( char * ) destmac,6 );
	memcpy ( ( char * ) pkg.ether_shost, ( char * ) localmac,6 );

	//pkg.ether_type = htons ( ETHERTYPE_ARP );
	pkg.ether_type = htons ( 0x0800 );
	
	//��ѯSID�����б�
	//�ļ�������
	FILE *fp;
	
	char ch;
	char buf[SIDLEN/*sid����*/ + DATALEN/*data����*/ +1/*�м�ո�*/];
	char len_sid;
	char data[DATALEN/*data����*/+1/*����'\0'*/];
	
	int flag_sidfound;
	int file_i;
	
	for(i=0;i<SIDLEN/*sid����*/;i++)
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
		if(len_sid == 0)//����յ���SIDΪ��
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
	
	//���CoLoR-data����
	pkg.version_type = 161;//�汾4λ������4λ����Ϊ���ó�CoLoR_Data��
	pkg.ttl = 255;//����ʱ��
	pkg.total_len = 16 + SIDLEN + NIDLEN + tempGet.pid_n*4 + DATALEN + 16;//�ܳ���
	
	pkg.port_no = PORTNUM;//�˿ں�
	pkg.checksum = 0;//�����
	
	pkg.sid_len = SIDLEN;//SID����
	pkg.nid_len = NIDLEN;//NID����
	pkg.pid_n = tempGet.pid_n;//PID����
	pkg.options_static = 0;//�̶��ײ�ѡ��
	
	
	pkg.signature_algorithm = 1;//ǩ���㷨
	pkg.if_hash_cache = 255;//�Ƿ��ϣ4λ���Ƿ񻺴�4λ
	pkg.options_dynamic = 0;//�ɱ��ײ�ѡ��
	
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
	
	fclose(fp);//�ر��ļ�
	
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
	
	//ʵ��Ӧ��ʹ��PF_PACKET
	if ( ( sockfd = socket ( PF_PACKET/*PF_INET*/,SOCK_PACKET,htons ( ETH_P_ALL ) ) ) ==-1 )
	{
		fprintf ( stderr,"Socket Error:%s\n\a",strerror ( errno ) );
		return ( 0 );
	}
	
	memset ( &sa,'\0',sizeof ( sa ) );
	strcpy ( sa.sa_data,PhysicalPort );
	
	selfpacketdonotcatch=1;
	
	len = sendto ( sockfd,pkg_pids,14+pkg.total_len,0,&sa,sizeof ( sa ) );//����Data����mac��㲥
	printf(">>>CoLoR-Data to   Proxy. Data: %s\n",data);//�������Data����ʾ
	if ( len != 14+pkg.total_len )//������ͳ�����ʵ�ʰ���ƥ�䣬����ʧ��
	{
		fprintf ( stderr,"Sendto Error:%s\n\a",strerror ( errno ) );
		close(sockfd);
		return ( 0 );
	}
	
	close(sockfd);
	return 1;
}

/*******************************************************************************************************************************************
*******************************************ԭʼ�׽��ֽ������ݰ���������MAC�����ϵ���������****************************************************
*******************************************************************************************************************************************/

//���ջ�������������ԭʼ���ݣ���С
#define BUFSIZE     1024 * 5

//���ջ�����
static int g_iRecvBufSize = BUFSIZE;
static char g_acRecvBuf[BUFSIZE] = {0};

//���������ӿ�,��Ҫ���ݾ�������޸�
static const char *g_szIfName = PhysicalPort;

/*****************************************
* �������ƣ�Ethernet_SetPromisc
* ����������������������ģʽ���Բ���
* �����б�
const char *pcIfName
int fd
int iFlags
* ���ؽ����
static int
*****************************************/
static int Ethernet_SetPromisc(const char *pcIfName, int fd, int iFlags)
{
	int iRet = -1;
	struct ifreq stIfr;
	
	//��ȡ�ӿ����Ա�־λ
	strcpy(stIfr.ifr_name, pcIfName);
	iRet = ioctl(fd, SIOCGIFFLAGS, &stIfr);
	if (0 > iRet)
	{
		perror("[Error]Get Interface Flags");   
		return -1;
	}
	
	if (0 == iFlags)
	{
		//ȡ������ģʽ
		stIfr.ifr_flags &= ~IFF_PROMISC;
	}
	else
	{
		//����Ϊ����ģʽ
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
* �������ƣ�Ethernet_InitSocket
* ��������������ԭʼ�׽���
* �����б�
* ���ؽ����
static int
*****************************************/
static int Ethernet_InitSocket()
{
	int iRet = -1;
	int fd = -1;
	struct ifreq stIf;
	struct sockaddr_ll stLocal = {0};
	
	//����SOCKET
	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (0 > fd)
	{
		perror("[Error]Initinate L2 raw socket");
		return -1;
	}
	
	//��������ģʽ����
	Ethernet_SetPromisc(g_szIfName, fd, 1);
	
	//����SOCKETѡ��
	iRet = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &g_iRecvBufSize,sizeof(int));
	if (0 > iRet)
	{
		perror("[Error]Set socket option");
		close(fd);
		return -1;
	}
	
	//��ȡ���������ӿ�����
	strcpy(stIf.ifr_name, g_szIfName);
	iRet = ioctl(fd, SIOCGIFINDEX, &stIf);
	if (0 > iRet)
	{
		perror("[Error]Ioctl operation");
		close(fd);
		return -1;
	}
	
	//����������
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
* �������ƣ�CoLoR_SeeType
* �����������ж��Ƿ�Ϊ��Ϊ����CoLoR��ͷ
* �����б�
const Ether_CoLoR_get *pkg
* ���ؽ����
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
	
	//����Ϊ�жϣ�ȷ�������������ݰ������Լ������ģ����Ա����������Զ˽��в��Ե�ʱ���뽫flag_localtest�ж�ֵ��Ϊ����ֵ
	//�ڲ����MAC����������Ч
	/*
	if(flag_localtest != 0)
	{
		if((strncmp((char*)pkg->ether_shost,(char*)local_mac,6)==0) && (pkg->port_no == PORTNUM))
		{
			return -1;
		}
	}
	*/
	
	//�汾��Э������
	//int version = pkg->version_type / 16;//ȡversion_type�ֶ�8λ����������ǰ��λ����ȡIP�汾��
	//int type    = pkg->version_type % 16;//ȡversion_type�ֶ�8λ���������ĺ���λ����ȡCoLoR�����ͺ�
	if(pkg->version_type == 160)//����ʾIP�汾��Ϊ10��������Ϊ0��ר��CoLoR-Get��  �ֶ�Ϊ1010 0000���İ�
	{
		return 0;
	}
	if(pkg->version_type == 161)//����ʾIP�汾��Ϊ10��������Ϊ1��ר��CoLoR-Data�� �ֶ�Ϊ1010 0001���İ�
	{
		return 1;
	}
	if(pkg->version_type == 161)//����ʾIP�汾��Ϊ10��������Ϊ2��ר��CoLoR-Register�� �ֶ�Ϊ1010 0010���İ�
	{
		return 2;
	}
	
	
	return -1;
}



/*****************************************
* �������ƣ�CoLoR_ParseGet
* ��������������CoLoR-Get��ͷ
* �����б�
const Ether_CoLoR_get *pkg
* ���ؽ����
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
	
	//����Get�����ֶ�
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
	tempGet.data = (uint8_t*)calloc(data_len+1/*+1��������Ϊ�������ر�Ԥ��*/,sizeof(uint8_t));
	memcpy((uint8_t*)tempGet.data,(uint8_t*)p,data_len);
	*(tempGet.data+data_len) = '\0';//�����ΪʲôΨ��data����Ҫ�ر��ڳ�1byte��Ϊ�����������Խ���ȡ
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
	
	memcpy(tempsid, tempGet.sid, tempGet.sid_len/*SID����*/);
	
	//��װ������CoLoR-Data���ݰ�
	sprintf ( dest_ip,"255.255.255.255",i );
	CoLoR_Sendpkg ( local_mac,broad_mac,local_ip,dest_ip );//��Ҫ�޸�Ϊ����Բ�ͬ���Ͱ���ʽ������ͬ��Ӧ�Ĺ���
	
	return 0;
}

/*****************************************
* �������ƣ�CoLoR_ParseData
* ��������������CoLoR-Data��ͷ
* �����б�
const Ether_CoLoR_get *pkg
* ���ؽ����
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
	
	//����Data�����ֶ�
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
	tempData.data = (uint8_t*)calloc(data_len+1/*+1��������Ϊ�������ر�Ԥ��*/,sizeof(uint8_t));
	memcpy((uint8_t*)tempData.data,(uint8_t*)p,data_len);
	*(tempData.data+data_len) = '\0';//�����ΪʲôΨ��data����Ҫ�ر��ڳ�1Byte��Ϊ�����������Խ���ȡ
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
* �������ƣ�CoLoR_ParseRegister
* ��������������CoLoR-Register��ͷ
* �����б�
const Ether_CoLoR_get *pkg
* ���ؽ����
static int
*****************************************/
static int CoLoR_ParseRegister(const Ether_CoLoR_register *pkg)
{
	int i;
	
	if (NULL == pkg)
	{
		return -1;
	}
	//����Register�����ֶ�
	//�����Register����ʽ�������
	
	
	printf (">>>CoLoR-Register from Somewhere. Type : %d\n",pkg->version_type%16);
	
	return 0;
}

/*****************************************
* �������ƣ�Ethernet_ParseFrame
* ��������������֡��������
* �����б�
const char *pcFrameData
* ���ؽ����
static int
*****************************************/
static int Ethernet_ParseFrame(const char *pcFrameData)
{
	//��鱾��mac��IP��ַ
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
	
	//���յ���ԭʼ��������ֵΪ��̫��ͷ
	pstEthHead = (struct ether_header*)g_acRecvBuf;
	
	//�ж�CoLoR���ݰ�����
	pkgvt = (Ether_VersionType *)(pstEthHead + 0);

	/*
	if(strncmp((char*)pkgvt->ether_dhost,(char*)localmac,6)!=0)
	{
		iRet=-1;
		return iRet;
	}
	*/

	iType = CoLoR_SeeType(pkgvt);
	
	if(iType == 0)//�յ�Get��
	{
		pkgget  = (Ether_CoLoR_get *)(pstEthHead + 0);
		iRet = CoLoR_ParseGet(pkgget);
	}
	else if(iType == 1)//�յ�Data��
	{
		pkgdata  = (Ether_CoLoR_data *)(pstEthHead + 0);
		iRet = CoLoR_ParseData(pkgdata);
	}
	else if(iType == 2)//�յ�Register��
	{
		pkgregister  = (Ether_CoLoR_register *)(pstEthHead + 0);
		iRet = CoLoR_ParseRegister(pkgregister);
	}
	else//�����Ͳ�����CoLoRЭ��
	{
	}
	
	return iRet;
}

/*****************************************
* �������ƣ�Ethernet_StartCapture
* ����������������������֡
* �����б�
const int fd
* ���ؽ����void
*****************************************/
static void Ethernet_StartCapture(const int fd)
{
	int iRet = -1;
	socklen_t stFromLen = 0;
	int packetcount=1;
	
	int cancelrepetition=0;//����δ֪ԭ��ÿһ������������ʵ����ݰ����ᱻ�������Ρ����趨���ڵ�ÿ�����հ���һ����Ч������Ȩ��֮�ƣ�û�и������⡣
	//ѭ������
	while(1)
	{
		//��ս��ջ�����
		//memset(g_acRecvBuf, 0, BUFSIZE);
		bzero(g_acRecvBuf,BUFSIZE);
		
		//��������֡
		iRet = recvfrom(fd, g_acRecvBuf, g_iRecvBufSize, 0, NULL, &stFromLen);

		//��һʱ�䶪���Լ����������ݰ�
		if(selfpacketdonotcatch == 1)
		{
			selfpacketdonotcatch=0;
			continue;
		}
		
		if (0 > iRet)
		{
			continue;
		}

		//��������֡���
		//printf("[Ethernet]New Packet Received. Noooo.%d:\n",packetcount++);

		//if(cancelrepetition == 0)
		if(1)
		{
			//��������֡
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
* �������ƣ�main
* ����������������
* �����б�
int argc
char *argv[]
* ���ؽ����
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
	
	//�ļ�1����ȡPIDע���ļ�
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

	//Ϊ�����������
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
	//���н�����������
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

	//�ļ�2����ȡSID�����ļ�
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

	//Ϊ�����������
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
	//���н�����������
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
	
	//��ʼ��SOCKET
	fd = Ethernet_InitSocket();
	if(0 > fd)
	{
		return -1;
	}
/*
	//��RM����ע���
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
	
	//���ethernet����
	memcpy((char*)pkg->ether_dhost,(char*)destmac,6);
	memcpy((char*)pkg->ether_shost,(char*)localmac,6);
	//pkg.ether_type = htons ( ETHERTYPE_ARP );
	pkg->ether_type=htons(0x0800);
	
	//���CoLoR-data����
	pkg->version_type = 162;//�汾4λ������4λ����Ϊ���ó�CoLoR_Register��
	pkg->nid_len = NIDLEN;//NID����
	pkg->sid_n = sidlistcount;//SID����
	pkg->sid_len = SIDLEN;//SID����

	pkg->Public_key_len = PUBKEYLEN;
	pkg->signature_algorithm = 1;//ǩ���㷨
	pkg->options_static = 0;//�̶��ײ�ѡ��

	pkg->checksum = 0;//�����
	pkg->Sequence_number = 0;//���к�

	pkg->Sequence_number_ack = 0;//���к�_ack
	pkg->total_len = 16+NIDLEN+SIDLEN*sidlistcount+PUBKEYLEN+SIGNATURELEN;//�ܳ���
	
	memcpy(pkg->nid,"d1pub1",NIDLEN/2);
	bzero(pkg->nid+6,NIDLEN/2-6);
	memcpy(pkg->nid+NIDLEN/2,"d1rm",NIDLEN/2);
	bzero(pkg->nid+NIDLEN/2+4,NIDLEN/2-4);
	
	for(i=0;i<sidlistcount;i++)
		memcpy(pkg->nid+NIDLEN+i*SIDLEN,SIDcmd[i],SIDLEN);//SID input
	
	//ʵ��Ӧ��ʹ��PF_PACKET
	if((sockfd=socket(PF_PACKET,SOCK_PACKET,htons(ETH_P_ALL)))==-1)
	{
		fprintf(stderr,"Socket Error:%s\n\a",strerror(errno));
		return(0);
	}
	
	memset(&sa,'\0',sizeof(sa));
	strcpy(sa.sa_data,PhysicalPort);
	
	len=sendto(sockfd,pkg,14+pkg->total_len,0,&sa,sizeof(sa));//����Data����mac��㲥
	printf(">>>CoLoR-Register to  RM.\n");//�������register����ʾ
	if(len!=14+pkg->total_len)//������ͳ�����ʵ�ʰ���ƥ�䣬����ʧ��
	{
		fprintf(stderr,"Sendto Error:%s\n\a",strerror(errno));
		close(sockfd);
		return (0);
	}
	
	close(sockfd);
	free(pkgregister);
*/
	
	//�������ݰ�����ѭ����
	Ethernet_StartCapture(fd);
	
	//�ر�SOCKET
	close(fd);
	
	return 0;
}
