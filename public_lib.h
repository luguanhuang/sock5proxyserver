/*****************************************************************************
** �ļ���public_lib.h                                    					**
** ���ߣ�������                                                				**
** ���ڣ�
** ���ܣ����������⺯��ͷ�ļ�                          	   					**
** �޸ļ�¼																	**
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


//��ͨ�Լ��Ӧ����Ӧ  1  �رսӿ�   2   ����ϵͳ
#define	CONN_EMERGENCY_RES_DOWN		1
#define	CONN_EMERGENCY_RES_REBOOT			2
#define  		MAX_FCNUM 			16


#define	SCP_MODE_MASTER			1		//��
#define	SCP_MODE_SLAVE			2		//��
#define	SCP_MODE_INDEPENDENT	3		//����

#define	SCP_MODE_MTOS			4      	//�������л�
#define	SCP_MODE_STOM			5      	//�������л�
#define	SCP_MODE_NULL				6		//δ֪


#define         SCP_HEARTBEAT_MMC          "!#!^*&!!##@YDSCP86319519ydscp=!#!^*&!!##@YDSCP86319519ydscp=1234"

#pragma pack(1)

typedef struct __st_scp_heartbeat__
{
        char udpsign[64];     //ǩ����Ϣ
        char scpip[16];       	//IP��ַ
        int   runmode;		//����ģʽ
        int	 scptime;         //ʱ���
}YDSCP_HEARTBEAT;

typedef struct __st_eth_status__
{
	char ethname[16];	//��������
	int 	ethstatus;		//ʵ��״̬
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
	char sServerIp[16];    //����IP 
	char sServerPort[6];   //������֤������״̬��UDP�˿�
}DIRSERVER;


//add by lity 20170608
typedef struct __st_yw_server__
{
	char sServerIp[16];    //����IP 
	char sServerPort[6];   //������֤������״̬��UDP�˿�
}YWSERVER;

typedef struct __st_fc_server__
{
	char sServerIp[16];    //����IP 
	char sServerPort[6];   //������֤������״̬��UDP�˿�
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
** ������: mon_daemon()
** ����ԭ��: void mon_daemon()
** ����:	      
** ��������:  ������ת��Ϊ�ػ����̾������
** ����ֵ: 
** ����: liyx
** ����:
** �޸ļ�¼:
**************************************************************************/
void mon_daemon();


/**************************************************************************
** ������: IsValidIpAddr()
** ����ԭ��: int IsValidIpAddr(char *pIpAddr, int iAddrLen)
** ����:	
**     ���:  char *pIpAddr  IP��ַ�ַ���
**     ���:  int iAddrLen   IP��ַ�ַ�������
** ��������:  �ж��Ƿ���ЧIP��ַ
** ����ֵ: 0 �ɹ� -1 ʧ��
** ����: liyx
** ����:
** �޸ļ�¼:
**************************************************************************/
int IsValidIpAddr(char *pIpAddr, int iAddrLen);


/**************************************************************************
** ������: Get_System_Config()
** ����ԭ��: int Get_System_Config()
** ����:	
** ��������:  ȡϵͳ�����ļ�������Ϣ  
** ����ֵ: 0 �ɹ� -1 ʧ��
** ����: liyx
** ����: 
** �޸ļ�¼: �ɿ��ǲ�ʹ��ȫ�ֽṹ���� ���ṹָ�����
**************************************************************************/
int Get_System_Config();


int checkprogramisrun(char *pName);

int CalNodeIDPos(char *psKeyID, int iKeyLen, int iAreaSize, int *piKeyPos);


#endif


