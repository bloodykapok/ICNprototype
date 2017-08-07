/*******************************************************************************************************************************************
* 文件名：general.c
* 文件描述：973智慧协同网络SAR系统TestBed套件——网络层通用调用文件
* 声明：本模板代码作者王兆旭，为北京交通大学下一代互联网互联设备国家工程实验室新生基础工程技术培训专用。作者王兆旭在此郑重声明，此文件及其它用于培训的模板代码均为本人精力与经验的产物，本资源的传播方式均为作者本人向他人进行一对一传授，任何个人不得向第三方转交或展示该资源内容。任何有需求的学员，均须向王兆旭本人直接索要，亦无向他人索要或传授之权利和义务。因有些资源内容涉及实验室项目秘密，暂不考虑申请专利保护或软件著作权等事宜，故个别资源仅限实验室内部一对一发放，如发现有辜负作者本人的一片好意的行为，作者将保留就其原创性进行追查、举证、申诉和问责的权利。本资源的发放权归作者本人所有，其整理和总结过程浸透无偿贡献的热忱和为诸君学业尽绵薄之力的真诚，愿学员尊重作者的劳动成果，谢谢合作！
* 作者：王兆旭
* 身份：北京交通大学下一代互联网互联设备国家工程实验室 2013级硕博连读研究生
* E-mail. hellozxwang@foxmail.com
* Mobile. 18811774990
* QQ    . 535667240
* Addr  . 北京市海淀区西直门外北京交通大学机械楼D706室, 100044
*******************************************************************************************************************************************/
/*******************************************************************************************************************************************
*****功能说明：1.网络层通用调用文件**********************************************************************************************************
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

#include"general.h"

/*****************************************
* 函数名称：configure_RTfilepath
* 功能描述：自动配置节点路由表配置文件的读取路径
* 参数列表：
* 返回结果：
*****************************************/
void
configure_RTfilepath
(
	char * RTfilepath,
	char * domainID,
	char * deviceNA,
	char * deviceID
)
{
	int i;
	int zeropoint;

	strcpy(RTfilepath,configFILEprefix);

	for(i=0;i<FILEnameL;i++)
	{
		if(RTfilepath[i]==0)
		{
			zeropoint=i;
			break;
		}
	}

	strcpy(RTfilepath+zeropoint,domainID);

	for(i=0;i<FILEnameL;i++)
	{
		if(RTfilepath[i]==0)
		{
			zeropoint=i;
			break;
		}
	}

	strcpy(RTfilepath+zeropoint,"/");
	strcpy(RTfilepath+zeropoint+1,deviceNA);

	for(i=0;i<FILEnameL;i++)
	{
		if(RTfilepath[i]==0)
		{
			zeropoint=i;
			break;
		}
	}

	strcpy(RTfilepath+zeropoint,deviceID);

	for(i=0;i<FILEnameL;i++)
	{
		if(RTfilepath[i]==0)
		{
			zeropoint=i;
			break;
		}
	}

	strcpy(RTfilepath+zeropoint,"/routingtable");

	printf("RTfilepath == %s\n",RTfilepath);
}

/*****************************************
* 函数名称：configure_InterSwitchfilepath
* 功能描述：自动配置节点边界转发配置文件的读取路径
* 参数列表：
* 返回结果：
*****************************************/
void
configure_InterSwitchfilepath
(
	char * InterSwitchfilepath,
	char * domainID,
	char * deviceNA,
	char * deviceID
)
{
	int i;
	int zeropoint;

	strcpy(InterSwitchfilepath,configFILEprefix);

	for(i=0;i<FILEnameL;i++)
	{
		if(InterSwitchfilepath[i]==0)
		{
			zeropoint=i;
			break;
		}
	}

	strcpy(InterSwitchfilepath+zeropoint,domainID);

	for(i=0;i<FILEnameL;i++)
	{
		if(InterSwitchfilepath[i]==0)
		{
			zeropoint=i;
			break;
		}
	}

	strcpy(InterSwitchfilepath+zeropoint,"/");
	strcpy(InterSwitchfilepath+zeropoint+1,deviceNA);

	for(i=0;i<FILEnameL;i++)
	{
		if(InterSwitchfilepath[i]==0)
		{
			zeropoint=i;
			break;
		}
	}

	strcpy(InterSwitchfilepath+zeropoint,deviceID);

	for(i=0;i<FILEnameL;i++)
	{
		if(InterSwitchfilepath[i]==0)
		{
			zeropoint=i;
			break;
		}
	}

	strcpy(InterSwitchfilepath+zeropoint,"/interswitch");

	printf("InterSwitchfilepath == %s\n",InterSwitchfilepath);
}

/*****************************************
* 函数名称：configure_SIDfilepath
* 功能描述：自动配置节点SID注册配置文件的读取路径
* 参数列表：
* 返回结果：
*****************************************/
void
configure_SIDfilepath
(
	char * SIDfilepath,
	char * domainID,
	char * deviceNA,
	char * deviceID
)
{
	int i;
	int zeropoint;

	strcpy(SIDfilepath,configFILEprefix);

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
* 函数名称：configure_PIDfilepath
* 功能描述：自动配置节点PID通告表配置文件的读取路径
* 参数列表：
* 返回结果：
*****************************************/
void
configure_PIDfilepath
(
	char * PIDfilepath,
	char * domainID,
	char * deviceNA,
	char * deviceID
)
{
	int i;
	int zeropoint;

	strcpy(PIDfilepath,configFILEprefix);

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

