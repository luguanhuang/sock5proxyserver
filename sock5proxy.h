#ifndef SOCK5_PROXY_H
#define SOCK5_PROXY_H

#include <deque>
#include <mutex>
#include <string>

#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <netdb.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <algorithm> 
#include <vector>
#include <map>
#include <string>
#include <iostream>
#include <queue>
#include "log_lib_cplus.h" 
#include <sstream>
#include <thread>
#include <queue>
#include "ThreadPool.h"
#define BUFSIZE 65536
#define IPSIZE 4
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define ARRAY_INIT    {0}

#include <condition_variable>
using std::condition_variable;
using std::mutex;
using std::string;
using std::vector;
using std::map;

// const int maxsendcnt = 2000;
const int maxsendcnt = 500;
const int maxresetcnt = 6;
const int maxconnfailcnt = 50;

class StSockInfo
{
public:
	int sock;
	int seq;
	CLog *log;
};

class CRunNicInfo
{
public:
	CRunNicInfo();

	int requestcnt;
	int errcnt;
};


#if 0
class StResetInfo 
{
public:
	StResetInfo()
	{
		curidx = 0;
		sndtotalcnt = 0;
	}

	void SetResetInfo(string strnic, CRunNicInfo nicinfo);
	void DelResetInfo(string strnic);
	void SetError(string strnic);
	int ProcResetInfo(CLog &log, string strnic);
	string getnic();
	map <string, CRunNicInfo> m_mapResetInfo;
	std::mutex nicmutex;
	std::mutex resetmutex;
	int curidx;
	int sndtotalcnt;
};
#endif
class StNicInfo 
{
public:
	StNicInfo(string nicdata, int index);
	void enable();
	bool isavalable();
	bool isresetavalable();
	void disable();
	void increcnt();
	
	bool isenable();
	string strnic;
	bool iscanused;
	int currentcnt;
	int resetcnt;
	int connectfailcnt;
	int idx;
	bool isreset;
	CLog *log;
	string strip;
	bool isneedset;
	std::mutex *nicmutex;
};



class CConnInfo
{
public:
	string strNic;
	int sock;
	string strip;
	int port;
};

class CConnData
{
public:
	map <string, vector <CConnInfo> > m_mapConnInfo;
	//vector <CConnInfo> m_vecConnInfo;
	//vector <int> m_vecConnSucThd;
	
	CConnInfo GetConnInfo();
	void SetConnInfo(string strnic, int fd, string strip, int port);
	std::mutex connmutex;
	// std::mutex thdmutex;
};

class CConnectServer
{
public:
	CConnectServer();
	
	std::deque<int> &getqueue()
	{
		return deqNic;
	}

	std::deque<int> &getUpIpInfoqueue()
	{
		return deqUpIpInfo;
	}

	void UpdateIpInfo(CLog &log);

	// ThreadPool pool;  // 弄4个线程

	StNicInfo &getNicInfo();
	void ResetNic(CLog &log);
	void ResetNicip(CLog &log);
	int UpModemInfo(string strNic);
	void UadateConnFailInfo(CLog &log, string strnic);
	// std::deque<StNicInfo *> deqNic;
	std::deque<int> deqNic;

	std::deque<int> deqUpIpInfo;

	vector <StNicInfo> vecstr;

	vector <StNicInfo> vecResetInfo;

	int m_curnicidx;
	std::mutex connmutex;
	std::condition_variable conncond;
	std::mutex nicmutex;
	std::mutex resetmutex;
};

class CResetNic
{
public:
	std::deque<string> &getqueue()
	{
		return deqStr;
	}

	// ThreadPool pool;  // 弄4个线程

	std::deque<string> deqStr;
	std::mutex resetmutex;
	std::condition_variable resetcond;
};

enum socks 
{
	RESERVED = 0x00,
	VERSION4 = 0x04,
	VERSION5 = 0x05
};

enum socks_auth_methods 
{
	NOAUTH = 0x00,
	USERPASS = 0x02,
	NOMETHOD = 0xff
};

enum socks_auth_userpass 
{
	AUTH_OK = 0x00,
	AUTH_VERSION = 0x01,
	AUTH_FAIL = 0xff
};

enum socks_command 
{
	CONNECT = 0x01
};

enum socks_command_type 
{
	IP = 0x01,
	DOMAIN = 0x03
};

enum socks_status 
{
	OK = 0x00,
	FAILED = 0x05
};

enum cmd_id
{
	RESTART_NETWORK = 0x00,
	IFUP_NIC = 0x01
};

int connect_timeout(CLog &log, int sockfd, const struct sockaddr *addr,
                    socklen_t addrlen);

int socks_invitation(int fd, int *version, CLog &log);
char *socks5_auth_get_user(int fd);
char *socks5_auth_get_pass(int fd);
int socks5_auth_userpass(int fd);
int socks5_auth_noauth(int fd);
void socks5_auth_notsupported(int fd);
int socks5_auth(int fd, int methods_count);
int socks5_command(int fd);
unsigned short int socks_read_port(int fd);
char *socks_ip_read(int fd);
void socks5_ip_send_response(int fd, char *ip, unsigned short int port);

int resetnicinfo(CLog &log, int idx, string strnicinfo);

char *socks5_domain_read(int fd, unsigned char *size);

void socks5_domain_send_response(int fd, char *domain, unsigned char size,
				 unsigned short int port);

void *reset_nic_process(void *fd);
void managerconnthd();
// void checknicinfo();
void connproxysrvthd();

void resetnic();

void log_message(const char *message, ...);
void executethd();

int  GetModemInfo(CLog &log);

void resetnicthd();

int readn(int fd, void *buf, int n);
int writen(int fd, void *buf, int n);
class CCmdInfo
{
public:
    cmd_id id;
    int idx;
    string strnic;     
};

class CSock5Proxy
{
    public:
};

#endif