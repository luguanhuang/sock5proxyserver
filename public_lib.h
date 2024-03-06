/*****************************************************************************
** 文件：public_lib.h                                    					**
** 作者：李勇新                                                				**
** 日期：
** 功能：公共操作库函数头文件                          	   					**
** 修改记录																	**
*****************************************************************************/

#ifndef  __PUBLIC_LIB_H__
#define  __PUBLIC_LIB_H__

#include <ctype.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
//#include <popt.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>


//#define		CONFIG_FILE_NAME     "scpbrlinkmon.conf"
#define		MAX_ETH_NUM		8

#define	ETH_STATUS_DOWN		0
#define	ETH_STATUS_UP			1
#define	ETH_STATUS_ERROR		2

#define	ETH_START		1


#define		CONFIG_FILE_NAME     "ydsoc_auth_info.conf"
#define		MAX_DB_NUM				6
#define     	MAX_DIRSER_NUM            6
#define		MAX_SEND_DIRSER_TIME     180


//连通性检测应急响应  1  关闭接口   2   重启系统
#define	CONN_EMERGENCY_RES_DOWN		1
#define	CONN_EMERGENCY_RES_REBOOT			2
#define  		MAX_FCNUM 			16


#define	SCP_MODE_MASTER			1		//主
#define	SCP_MODE_SLAVE			2		//备
#define	SCP_MODE_INDEPENDENT	3		//独立

#define	SCP_MODE_MTOS			4      	//主到备切换
#define	SCP_MODE_STOM			5      	//备到主切换
#define	SCP_MODE_NULL				6		//未知


#define         SCP_HEARTBEAT_MMC          "!#!^*&!!##@YDSCP86319519ydscp=!#!^*&!!##@YDSCP86319519ydscp=1234"

#pragma pack(1)

typedef struct __st_scp_heartbeat__
{
        char udpsign[64];     //签字信息
        char scpip[16];       	//IP地址
        int   runmode;		//运行模式
        int	 scptime;         //时间戳
}YDSCP_HEARTBEAT;

typedef struct __st_eth_status__
{
	char ethname[16];	//网卡名称
	int 	ethstatus;		//实际状态
}ETHSTATUS;


typedef struct __st_scpbrlink__
{
	char brname[16];
	int	ifnum;
//	char ethname[MAX_ETH_NUM][16];
	ETHSTATUS stEthStatus[MAX_ETH_NUM]; 
}SCPBRLINKMON;


typedef struct __st_db_server__
{
    char sDbIp[16];
    char sDbUser[32];
    char sDbPass[32];
    char sDbName[32];
    int  iDbPort;
}DBSERVER;


typedef struct __st_dir_server__
{
	char sServerIp[16];    //内网IP 
	char sServerPort[6];   //监听认证服务器状态的UDP端口
}DIRSERVER;


//add by lity 20170608
typedef struct __st_yw_server__
{
	char sServerIp[16];    //内网IP 
	char sServerPort[6];   //监听认证服务器状态的UDP端口
}YWSERVER;

typedef struct __st_fc_server__
{
	char sServerIp[16];    //内网IP 
	char sServerPort[6];   //监听认证服务器状态的UDP端口
}FWCLOUND;

typedef struct __fc_packet__
{
	int iPacketLen;
}FC_PACKET;

typedef struct __st_brlink__
{
	char brname[16];
	int	ifnum;
//	char ethname[MAX_ETH_NUM][16];
	ETHSTATUS stEthStatus[MAX_ETH_NUM]; 
}LINKMON;

typedef struct __st_sysconfig__
{
	char sBaseDir[64];	
	char sConfFile[128];
	char sNodeId[16];
	char sScpIp[16];
	int iAuthSerNum;
	char sAuthSerIp[10][16];        
	char sAuthPort[6];
	char encKeyPath[256];
	char sManageName[16];
	int  iCommTimeout;
	int  iPollTime;
	int logsize;
	int runmode;
	LINKMON stLink;
	int pollmon;
}stSYSCONFIG, *pstSYSCONFIG;



#pragma pack()

/**************************************************************************
** 函数名: mon_daemon()
** 函数原型: void mon_daemon()
** 参数:	      
** 功能描述:  将程序转换为守护进程精灵进程
** 返回值: 
** 作者: liyx
** 日期:
** 修改记录:
**************************************************************************/
void mon_daemon();


/**************************************************************************
** 函数名: IsValidIpAddr()
** 函数原型: int IsValidIpAddr(char *pIpAddr, int iAddrLen)
** 参数:	
**     入参:  char *pIpAddr  IP地址字符串
**     入参:  int iAddrLen   IP地址字符串长度
** 功能描述:  判断是否有效IP地址
** 返回值: 0 成功 -1 失败
** 作者: liyx
** 日期:
** 修改记录:
**************************************************************************/
int IsValidIpAddr(char *pIpAddr, int iAddrLen);


/**************************************************************************
** 函数名: Get_System_Config()
** 函数原型: int Get_System_Config()
** 参数:	
** 功能描述:  取系统配置文件配置信息  
** 返回值: 0 成功 -1 失败
** 作者: liyx
** 日期: 
** 修改记录: 可考虑不使用全局结构变量 传结构指针参数
**************************************************************************/
int Get_System_Config();


int checkprogramisrun(char *pName);

int CalNodeIDPos(char *psKeyID, int iKeyLen, int iAreaSize, int *piKeyPos);


#endif


