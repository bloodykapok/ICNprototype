/*******************************************************************************************************************************************
* 文件名：packet.h
* 文件描述：973智慧协同网络SAR系统TestBed套件——包格式头文件
* 声明：本模板代码作者王兆旭，为北京交通大学下一代互联网互联设备国家工程实验室新生基础工程技术培训专用。作者王兆旭在此郑重声明，此文件及其它用于培训的模板代码均为本人精力与经验的产物，本资源的传播方式均为作者本人向他人进行一对一传授，任何个人不得向第三方转交或展示该资源内容。任何有需求的学员，均须向王兆旭本人直接索要，亦无向他人索要或传授之权利和义务。因有些资源内容涉及实验室项目秘密，暂不考虑申请专利保护或软件著作权等事宜，故个别资源仅限实验室内部一对一发放，如发现有辜负作者本人的一片好意的行为，作者将保留就其原创性进行追查、举证、申诉和问责的权利。本资源的发放权归作者本人所有，其整理和总结过程浸透无偿贡献的热忱和为诸君学业尽绵薄之力的真诚，愿学员尊重作者的劳动成果，谢谢合作！
* 作者：王兆旭
* 身份：北京交通大学下一代互联网互联设备国家工程实验室 2013级硕博连读研究生
* E-mail. hellozxwang@foxmail.com
* Mobile. 18811774990
* QQ    . 535667240
* Addr  . 北京市海淀区西直门外北京交通大学机械楼D706室, 100044
*******************************************************************************************************************************************/
/*******************************************************************************************************************************************
*****功能说明：1.存储以太网和CoLoR格式各种所需包格式******************************************************************************************
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

//字段长度（用于规定某些可变字段的最大长度，固定包处理预留空间的大小，用以替代高速转发过程中不稳定的calloc等动态内存方式）
#define OFFLENst      4                         //偏移量最大长度
#define LENLENst      4                         //偏移长度最大长度
#define RESERVEDLENst 8                         //保留区段最大长度
#define SIDLENst      20                        //SID最大长度
#define SBDLENst      20                        //SBD最大长度
#define NIDLENst      16                        //NID最大长度
#define DATALENst     1000                      //Data最大长度
#define PUBKEYLENst   16                        //公钥最大长度

//字段长度（用于发包，不影响根据具体字段规定的长度收包）
#define OFFLEN        4                         //偏移量长度
#define LENLEN        4                         //偏移长度长度
#define RESERVEDLEN   8                         //保留区段长度
#define SIDLEN        20                        //SID长度
#define SBDLEN        20                        //SBD长度
#define NIDLEN        16                        //NID长度
#define PIDN          0                         //PID数量
#define DATALEN       1000                      //Data长度
#define PUBKEYLEN     16                        //公钥长度
#define MTU           1500                      //最大传输单元
#define SIGNATURELEN  16

#ifndef _PACKET_
#define _PACKET_

//用于统一识别包类型
typedef struct _Ether_VersionType         Ether_VersionType;
typedef struct _Ether_CoLoR_VersionType   Ether_CoLoR_VersionType;
typedef struct _CoLoR_VersionType         CoLoR_VersionType;
//带MAC层的CoLoR包
typedef struct _Ether_CoLoR_get           Ether_CoLoR_get;
typedef struct _Ether_CoLoR_get_parse     Ether_CoLoR_get_parse;
typedef struct _Ether_CoLoR_data          Ether_CoLoR_data;
typedef struct _Ether_CoLoR_data_parse    Ether_CoLoR_data_parse;
typedef struct _Ether_CoLoR_register      Ether_CoLoR_register;
//无MAC层的CoLoR包
typedef struct _CoLoR_get                 CoLoR_get;
typedef struct _CoLoR_get_parse           CoLoR_get_parse;
typedef struct _CoLoR_data                CoLoR_data;
typedef struct _CoLoR_data_parse          CoLoR_data_parse;
typedef struct _CoLoR_register            CoLoR_register;
typedef struct _CoLoR_register_parse      CoLoR_register_parse;
//传输层包
typedef struct _Trans_get                 Trans_get;
typedef struct _Trans_data                Trans_data;

//带MAC层的CNF包
typedef struct _Ether_CoLoR_ack           Ether_CoLoR_ack;
typedef struct _Ether_CoLoR_ack_parse     Ether_CoLoR_ack_parse;
typedef struct _Ether_CoLoR_seg           Ether_CoLoR_seg;
typedef struct _Ether_CoLoR_seg_parse     Ether_CoLoR_seg_parse;
//无MAC层的CNF包
typedef struct _CoLoR_ack                 CoLoR_ack;
typedef struct _CoLoR_ack_parse           CoLoR_ack_parse;
typedef struct _CoLoR_seg                 CoLoR_seg;
typedef struct _CoLoR_seg_parse           CoLoR_seg_parse;

//Ethernet层 / 用于Ethernet类型判断的包头（截止到固定首部，其中Version/Type字段为IP包、CoLoR包所通用）
struct _Ether_VersionType
{
	//ethernet头
	uint8_t ether_dhost[6]; //目地硬件地址
	uint8_t ether_shost[6]; //源硬件地址
	uint16_t ether_type; //网络类型
	
	//CoLoR头
	uint8_t version_type;////版本4位，类型4位
};


//Ethernet层 / 用于CoLoR类型判断的包头（截止到固定首部，其中Version/Type字段为Get包、Data包、Register包所通用）
struct _Ether_CoLoR_VersionType
{
	//ethernet头
	uint8_t ether_dhost[6]; //目地硬件地址
	uint8_t ether_shost[6]; //源硬件地址
	uint16_t ether_type; //网络类型
	
	//CoLoR头
	uint8_t version_type;////版本4位，类型4位
	uint8_t ttl;//生存时间
	uint16_t total_len;//总长度
	
	uint16_t port_no;//端口号
	uint16_t checksum;//检验和
	
	uint8_t sid_len;//SID长度
	uint8_t nid_len;//NID长度
	uint8_t pid_n;//PID数量
	uint8_t options_static;//固定首部选项

	uint8_t offset[OFFLEN];//偏移量
	uint8_t length[LENLEN];//偏移长度
	uint8_t reserved[RESERVEDLEN];//偏移长度
};


//CoLoR层 / 用于CoLoR类型判断的包头（截止到固定首部，其中Version/Type字段为Get包、Data包、Register包所通用）
struct _CoLoR_VersionType
{
	//CoLoR头
	uint8_t version_type;////版本4位，类型4位
	uint8_t ttl;//生存时间
	uint16_t total_len;//总长度
	
	uint16_t port_no;//端口号
	uint16_t checksum;//检验和
	
	uint8_t sid_len;//SID长度
	uint8_t nid_len;//NID长度
	uint8_t pid_n;//PID数量
	uint8_t options_static;//固定首部选项

	uint8_t offset[OFFLEN];//偏移量
	uint8_t length[LENLEN];//偏移长度
	uint8_t reserved[RESERVEDLEN];//偏移长度
};

//Ethernet层 / CoLoR协议Get包首部（PID之前）字段长度固定，用于封装
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

	uint8_t offset[OFFLEN];//偏移量
	uint8_t length[LENLEN];//偏移长度
	uint8_t reserved[RESERVEDLEN];//偏移长度
	
	uint16_t publickey_len;//公钥长度
	uint16_t mtu;//最大传输单元
	
	uint8_t sid[SIDLEN];//SID
	uint8_t nid[NIDLEN];//NID
	
	uint8_t data[DATALEN];//Data
	
	uint8_t publickey[PUBKEYLEN];//公钥
};

//Ethernet层 / CoLoR协议Get包首部（PID之前）字段长度可变，用于解析
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

	uint8_t offset[OFFLEN];//偏移量
	uint8_t length[LENLEN];//偏移长度
	uint8_t reserved[RESERVEDLEN];//偏移长度
	
	uint16_t publickey_len;//公钥长度
	uint16_t mtu;//最大传输单元
	
	uint8_t sid[SIDLENst];//SID
	uint8_t nid[NIDLENst];//NID
	
	uint8_t data[DATALENst];//Data
	
	uint8_t publickey[PUBKEYLENst];//公钥
};


//Ethernet层 / CoLoR协议Data包首部（PID之前）字段长度固定，用于封装
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

	uint8_t offset[OFFLEN];//偏移量
	uint8_t length[LENLEN];//偏移长度
	uint8_t reserved[RESERVEDLEN];//偏移长度
	
	uint8_t signature_algorithm;//签名算法
	uint8_t if_hash_cache;//是否哈希4位，是否缓存4位
	uint16_t options_dynamic;//可变首部选项
	
	uint8_t sid[SIDLEN];//SID
	uint8_t nid[NIDLEN];//NID
	
	uint8_t data[DATALEN];//Data
	
	uint8_t data_signature[16];//数字签名
};

//Ethernet层 / CoLoR协议Data包首部（PID之前）字段长度可变，用于解析
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

	uint8_t offset[OFFLEN];//偏移量
	uint8_t length[LENLEN];//偏移长度
	uint8_t reserved[RESERVEDLEN];//偏移长度
	
	uint8_t signature_algorithm;//签名算法
	uint8_t if_hash_cache;//是否哈希4位，是否缓存4位
	uint16_t options_dynamic;//可变首部选项
	
	uint8_t sid[SIDLENst];//SID
	uint8_t nid[NIDLENst];//NID
	
	uint8_t data[DATALENst];//Data
	
	uint8_t data_signature[16];//数字签名
};


//Ethernet层 / CoLoR协议Register包首部（PID之前）
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
};


//CoLoR层 / CoLoR协议Get包首部（PID之前）字段长度固定，用于封装
struct _CoLoR_get
{
	//ethernet头
	//uint8_t ether_dhost[6]; //目地硬件地址
	//uint8_t ether_shost[6]; //源硬件地址
	//uint16_t ether_type; //网络类型
	
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

	uint8_t offset[OFFLEN];//偏移量
	uint8_t length[LENLEN];//偏移长度
	uint8_t reserved[RESERVEDLEN];//保留区间
	
	uint16_t publickey_len;//公钥长度
	uint16_t mtu;//最大传输单元
	
	uint8_t sid[SIDLEN];//SID
	uint8_t nid[NIDLEN];//NID
	
	uint8_t data[DATALEN];//Data
	
	uint8_t publickey[PUBKEYLEN];//公钥
};

//CoLoR层 / CoLoR协议Get包首部（PID之前）字段长度可变，用于解析
struct _CoLoR_get_parse
{

	//ethernet头
	//uint8_t ether_dhost[6]; //目地硬件地址
	//uint8_t ether_shost[6]; //源硬件地址
	//uint16_t ether_type; //网络类型

	
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

	uint8_t offset[OFFLEN];//偏移量
	uint8_t length[LENLEN];//偏移长度
	uint8_t reserved[RESERVEDLEN];//偏移长度
	
	uint16_t publickey_len;//公钥长度
	uint16_t mtu;//最大传输单元
	
	uint8_t sid[SIDLENst];//SID
	uint8_t nid[NIDLENst];//NID
	
	uint8_t data[DATALENst];//Data
	
	uint8_t publickey[PUBKEYLENst];//公钥
};

//CoLoR层 / CoLoR协议Data包首部（PID之前）字段长度固定，用于封装
struct _CoLoR_data
{
	//ethernet头
	//uint8_t ether_dhost[6]; //目地硬件地址
	//uint8_t ether_shost[6]; //源硬件地址
	//uint16_t ether_type; //网络类型
	
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

	uint8_t offset[OFFLEN];//偏移量
	uint8_t length[LENLEN];//偏移长度
	uint8_t reserved[RESERVEDLEN];//偏移长度
	
	uint8_t signature_algorithm;//签名算法
	uint8_t if_hash_cache;//是否哈希4位，是否缓存4位
	uint16_t options_dynamic;//可变首部选项
	
	uint8_t sid[SIDLEN];//SID
	uint8_t nid[NIDLEN];//NID
	
	uint8_t data[DATALEN];//Data
	
	uint8_t data_signature[16];//数字签名
};

//CoLoR层 / CoLoR协议Data包首部（PID之前）字段长度可变，用于解析
struct _CoLoR_data_parse
{

	//ethernet头
	//uint8_t ether_dhost[6]; //目地硬件地址
	//uint8_t ether_shost[6]; //源硬件地址
	//uint16_t ether_type; //网络类型
	
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

	uint8_t offset[OFFLEN];//偏移量
	uint8_t length[LENLEN];//偏移长度
	uint8_t reserved[RESERVEDLEN];//偏移长度
	
	uint8_t signature_algorithm;//签名算法
	uint8_t if_hash_cache;//是否哈希4位，是否缓存4位
	uint16_t options_dynamic;//可变首部选项
	
	uint8_t sid[SIDLENst];//SID
	uint8_t nid[NIDLENst];//NID
	
	uint8_t data[DATALENst];//Data
	
	uint8_t data_signature[16];//数字签名
};

//CoLoR层 / CoLoR协议Register包首部（PID之前）
struct _CoLoR_register
{

	//ethernet头
	//uint8_t ether_dhost[6]; //目地硬件地址
	//uint8_t ether_shost[6]; //源硬件地址
	//uint16_t ether_type; //网络类型

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
};

//CoLoR层 / CoLoR协议Register包首部（PID之前）
struct _CoLoR_register_parse
{
	//ethernet头
	//uint8_t ether_dhost[6]; //目地硬件地址
	//uint8_t ether_shost[6]; //源硬件地址
	//uint16_t ether_type; //网络类型
	
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
};

///////////////////////////////////////////////////////////////////////////////////////////////////////////传输层
//传输层Get包
struct _Trans_get
{
	uint8_t version_type;////版本4位，类型4位
	uint8_t sid_len;//SID长度
	uint16_t total_len;//总长度
	
	uint16_t port_no;//端口号
	uint16_t checksum;//检验和

	uint8_t offset[OFFLEN];//偏移量

	uint8_t length[LENLEN];//偏移长度

	uint8_t options[4];//首部选项
	
	uint8_t sid[SIDLEN];//SID

	uint8_t sbd[SBDLEN];//SBD

	uint8_t data[DATALEN];//Data
};

//传输层Data包
struct _Trans_data
{
	uint8_t version_type;////版本4位，类型4位
	uint8_t sid_len;//SID长度
	uint16_t total_len;//总长度
	
	uint16_t port_no;//端口号
	uint16_t checksum;//检验和

	uint8_t offset[OFFLEN];//偏移量

	uint8_t length[LENLEN];//偏移长度

	uint8_t options[4];//首部选项
	
	uint8_t sid[SIDLEN];//SID

	uint8_t data[DATALEN];//Data
};

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////CNF
//Ethernet层 / CoLoR协议ACK包首部（PID之前）字段长度固定，用于封装
struct _Ether_CoLoR_ack
{
	//ethernet头
	uint8_t ether_dhost[6]; //目地硬件地址
	uint8_t ether_shost[6]; //源硬件地址
	uint16_t ether_type; //网络类型
	
	//CoLoR-ACK头
	uint8_t version_type;////版本4位，类型4位
	uint8_t ttl;//生存时间
	uint16_t total_len;//总长度
	
	uint16_t port_no;//端口号
	uint16_t checksum;//检验和
	
	uint8_t sid_len;//SID长度
	uint8_t nid_len;//NID长度
	uint8_t pid_n;//PID数量
	uint8_t options_static;//固定首部选项

	uint8_t offset[OFFLEN];//偏移量
	uint8_t length[LENLEN];//偏移长度
	uint8_t reserved[RESERVEDLEN];//偏移长度
	
	uint16_t publickey_len;//公钥长度
	uint16_t mtu;//最大传输单元
	
	uint8_t sid[SIDLEN];//SID
	uint8_t nid[NIDLEN];//NID
	
	uint8_t data[DATALEN];//Data
	
	uint8_t publickey[PUBKEYLEN];//公钥
};

//Ethernet层 / CoLoR协议ACK包首部（PID之前）字段长度可变，用于解析
struct _Ether_CoLoR_ack_parse
{
	//ethernet头
	uint8_t ether_dhost[6]; //目地硬件地址
	uint8_t ether_shost[6]; //源硬件地址
	uint16_t ether_type; //网络类型
	
	//CoLoR-ACK头
	uint8_t version_type;////版本4位，类型4位
	uint8_t ttl;//生存时间
	uint16_t total_len;//总长度
	
	uint16_t port_no;//端口号
	uint16_t checksum;//检验和
	
	uint8_t sid_len;//SID长度
	uint8_t nid_len;//NID长度
	uint8_t pid_n;//PID数量
	uint8_t options_static;//固定首部选项

	uint8_t offset[OFFLEN];//偏移量
	uint8_t length[LENLEN];//偏移长度
	uint8_t reserved[RESERVEDLEN];//偏移长度
	
	uint16_t publickey_len;//公钥长度
	uint16_t mtu;//最大传输单元
	
	uint8_t sid[SIDLENst];//SID
	uint8_t nid[NIDLENst];//NID
	
	uint8_t data[DATALEN];//Data
	
	uint8_t publickey[PUBKEYLEN];//公钥
};


//Ethernet层 / CoLoR协议Seg包首部（PID之前）字段长度固定，用于封装
struct _Ether_CoLoR_seg
{
	//ethernet头
	uint8_t ether_dhost[6]; //目地硬件地址
	uint8_t ether_shost[6]; //源硬件地址
	uint16_t ether_type; //网络类型
	
	//CoLoR-Seg头
	uint8_t version_type;////版本4位，类型4位
	uint8_t ttl;//生存时间
	uint16_t total_len;//总长度
	
	uint16_t port_no;//端口号
	uint16_t checksum;//检验和
	
	uint8_t sid_len;//SID长度
	uint8_t nid_len;//NID长度
	uint8_t pid_n;//PID数量
	uint8_t options_static;//固定首部选项

	uint8_t offset[OFFLEN];//偏移量
	uint8_t length[LENLEN];//偏移长度
	uint8_t reserved[RESERVEDLEN];//偏移长度
	
	uint8_t signature_algorithm;//签名算法
	uint8_t if_hash_cache;//是否哈希4位，是否缓存4位
	uint16_t options_dynamic;//可变首部选项
	
	uint8_t sid[SIDLEN];//SID
	uint8_t nid[NIDLEN];//NID
	
	uint8_t data[DATALEN];//Data
	
	uint8_t data_signature[16];//数字签名
};

//Ethernet层 / CoLoR协议Seg包首部（PID之前）字段长度可变，用于解析
struct _Ether_CoLoR_seg_parse
{
	//ethernet头
	uint8_t ether_dhost[6]; //目地硬件地址
	uint8_t ether_shost[6]; //源硬件地址
	uint16_t ether_type; //网络类型
	
	//CoLoR-Seg头
	uint8_t version_type;////版本4位，类型4位
	uint8_t ttl;//生存时间
	uint16_t total_len;//总长度
	
	uint16_t port_no;//端口号
	uint16_t checksum;//检验和
	
	uint8_t sid_len;//SID长度
	uint8_t nid_len;//NID长度
	uint8_t pid_n;//PID数量
	uint8_t options_static;//固定首部选项

	uint8_t offset[OFFLEN];//偏移量
	uint8_t length[LENLEN];//偏移长度
	uint8_t reserved[RESERVEDLEN];//偏移长度
	
	uint8_t signature_algorithm;//签名算法
	uint8_t if_hash_cache;//是否哈希4位，是否缓存4位
	uint16_t options_dynamic;//可变首部选项
	
	uint8_t sid[SIDLENst];//SID
	uint8_t nid[NIDLENst];//NID
	
	uint8_t data[DATALENst];//Data
	
	uint8_t data_signature[16];//数字签名
};

//CoLoR层 / CoLoR协议ACK包首部（PID之前）字段长度固定，用于封装
struct _CoLoR_ack
{
	//ethernet头
	//uint8_t ether_dhost[6]; //目地硬件地址
	//uint8_t ether_shost[6]; //源硬件地址
	//uint16_t ether_type; //网络类型
	
	//CoLoR-ACK头
	uint8_t version_type;////版本4位，类型4位
	uint8_t ttl;//生存时间
	uint16_t total_len;//总长度
	
	uint16_t port_no;//端口号
	uint16_t checksum;//检验和
	
	uint8_t sid_len;//SID长度
	uint8_t nid_len;//NID长度
	uint8_t pid_n;//PID数量
	uint8_t options_static;//固定首部选项

	uint8_t offset[OFFLEN];//偏移量
	uint8_t length[LENLEN];//偏移长度
	uint8_t reserved[RESERVEDLEN];//偏移长度
	
	uint16_t publickey_len;//公钥长度
	uint16_t mtu;//最大传输单元
	
	uint8_t sid[SIDLEN];//SID
	uint8_t nid[NIDLEN];//NID
	
	uint8_t data[DATALEN];//Data
	
	uint8_t publickey[PUBKEYLEN];//公钥
};

//CoLoR层 / CoLoR协议ACK包首部（PID之前）字段长度可变，用于解析
struct _CoLoR_ack_parse
{

	//ethernet头
	//uint8_t ether_dhost[6]; //目地硬件地址
	//uint8_t ether_shost[6]; //源硬件地址
	//uint16_t ether_type; //网络类型

	
	//CoLoR-ACK头
	uint8_t version_type;////版本4位，类型4位
	uint8_t ttl;//生存时间
	uint16_t total_len;//总长度
	
	uint16_t port_no;//端口号
	uint16_t checksum;//检验和
	
	uint8_t sid_len;//SID长度
	uint8_t nid_len;//NID长度
	uint8_t pid_n;//PID数量
	uint8_t options_static;//固定首部选项

	uint8_t offset[OFFLEN];//偏移量
	uint8_t length[LENLEN];//偏移长度
	uint8_t reserved[RESERVEDLEN];//偏移长度
	
	uint16_t publickey_len;//公钥长度
	uint16_t mtu;//最大传输单元
	
	uint8_t sid[SIDLENst];//SID
	uint8_t nid[NIDLENst];//NID
	
	uint8_t data[DATALEN];//Data
	
	uint8_t publickey[PUBKEYLEN];//公钥
};

//CoLoR层 / CoLoR协议Seg包首部（PID之前）字段长度固定，用于封装
struct _CoLoR_seg
{
	//ethernet头
	//uint8_t ether_dhost[6]; //目地硬件地址
	//uint8_t ether_shost[6]; //源硬件地址
	//uint16_t ether_type; //网络类型
	
	//CoLoR-Seg头
	uint8_t version_type;////版本4位，类型4位
	uint8_t ttl;//生存时间
	uint16_t total_len;//总长度
	
	uint16_t port_no;//端口号
	uint16_t checksum;//检验和
	
	uint8_t sid_len;//SID长度
	uint8_t nid_len;//NID长度
	uint8_t pid_n;//PID数量
	uint8_t options_static;//固定首部选项

	uint8_t offset[OFFLEN];//偏移量
	uint8_t length[LENLEN];//偏移长度
	uint8_t reserved[RESERVEDLEN];//偏移长度
	
	uint8_t signature_algorithm;//签名算法
	uint8_t if_hash_cache;//是否哈希4位，是否缓存4位
	uint16_t options_dynamic;//可变首部选项
	
	uint8_t sid[SIDLEN];//SID
	uint8_t nid[NIDLEN];//NID
	
	uint8_t data[DATALEN];//Data
	
	uint8_t data_signature[16];//数字签名
};

//CoLoR层 / CoLoR协议Seg包首部（PID之前）字段长度可变，用于解析
struct _CoLoR_seg_parse
{

	//ethernet头
	//uint8_t ether_dhost[6]; //目地硬件地址
	//uint8_t ether_shost[6]; //源硬件地址
	//uint16_t ether_type; //网络类型
	
	//CoLoR-Seg头
	uint8_t version_type;////版本4位，类型4位
	uint8_t ttl;//生存时间
	uint16_t total_len;//总长度
	
	uint16_t port_no;//端口号
	uint16_t checksum;//检验和
	
	uint8_t sid_len;//SID长度
	uint8_t nid_len;//NID长度
	uint8_t pid_n;//PID数量
	uint8_t options_static;//固定首部选项

	uint8_t offset[OFFLEN];//偏移量
	uint8_t length[LENLEN];//偏移长度
	uint8_t reserved[RESERVEDLEN];//偏移长度
	
	uint8_t signature_algorithm;//签名算法
	uint8_t if_hash_cache;//是否哈希4位，是否缓存4位
	uint16_t options_dynamic;//可变首部选项
	
	uint8_t sid[SIDLENst];//SID
	uint8_t nid[NIDLENst];//NID
	
	uint8_t data[DATALENst];//Data
	
	uint8_t data_signature[16];//数字签名
};

#endif
