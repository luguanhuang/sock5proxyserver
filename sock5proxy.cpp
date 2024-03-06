
#include "sock5proxy.h"
#include "ThreadPool.h"
#include <sys/time.h>
#include <errno.h>
#include <sys/epoll.h>

std::deque<CCmdInfo> cmdqueue;
std::mutex mu;
// std::condition_variable cond;
using std::vector;

std::mutex resetmu;
std::condition_variable resetcond;

extern char *arg_username;
extern char *arg_password;

extern CLog connproxysrvlog;

extern FILE *log_file;
extern int auth_type;
extern CLog nicresetlog;
// ThreadPool resetnicpool(35);  // 弄4个线程
// extern vector <StNicInfo> vecstr;
// extern pthread_mutex_t idxlock;

CConnData connData;
CResetNic g_resetnic;

int  GetModemInfo(CLog &log);
// StResetInfo resetInfo;

CConnectServer connserver;

// extern pthread_mutex_t niclock;
#if 0
CConnInfo CConnData::GetConnInfo()
{
	std::unique_lock<std::mutex> locker(connmutex);
	for(auto i=m_mapConnInfo.begin();i!=m_mapConnInfo.end();)
	{
		if(0 == i->second.size())
		{
			m_mapConnInfo.erase(i++);
		}
		else if(i->second.size() > 0)
			break;
	}

	auto begin = m_mapConnInfo.begin();
	auto end = m_mapConnInfo.end();

	int test=0;
	if (begin != end)
	{
		auto vecbegin = begin->second.begin();
		CConnInfo tmpinfo = *vecbegin;
		begin->second.erase(vecbegin);
		locker.unlock();
		return tmpinfo;
	}

	locker.unlock();
	CConnInfo tmpinfo;
	tmpinfo.sock = -1;
	tmpinfo.strNic = "";
	tmpinfo.strip = "";
	tmpinfo.port = 0;
	return tmpinfo;
}
#endif

int resetnicinfo(CLog &log, int idx, string strnicinfo)
{
	FILE *fp;
	char buf[128];

	snprintf(buf, sizeof(buf), "mmcli -m %d --command=\"AT+CFUN=0\"", idx);
	int ret = system(buf);
	logDebug(log, "resetnicinfo: buf=%s ret=%d strnicinfo=%s", buf, ret, strnicinfo.c_str());
	if (0 != ret)
	{
		logError(log, "resetnicinfo: Excute shell cmd[%s] failed, return:%d strnicinfo=%s.", buf, ret>>8, strnicinfo.c_str());
		snprintf(buf, sizeof(buf), "mmcli -m %d --command=AT+CRESET", idx);
		// logDebug(log, "executethd: cmd=%s", buf);
		ret = system(buf);
		logDebug(log, "resetnicinfo: cmd=%s ret=%d strnicinfo=%s", buf, ret, strnicinfo.c_str());
		if (0 != ret)
		{
			logError(log, "Excute shell cmd[%s] failed, return:%d strnicinfo=%s.", buf, ret>>8, strnicinfo.c_str());
			// resetInfo.SetError(strnicinfo);
			return -1;
		}

		return 0;
	}

	sleep(1);
	snprintf(buf, sizeof(buf), "mmcli -m %d --command=\"AT+CFUN=1\"", idx);
	ret = system(buf);
	logDebug(log, "resetnicinfo: buf=%s ret=%d strnicinfo=%s", buf, ret, strnicinfo.c_str());
	if (0 != ret)
	{
		logError(log, "resetnicinfo: Excute shell cmd[%s] failed, return:%d strnicinfo=%s.", buf, ret>>8, strnicinfo.c_str());
		snprintf(buf, sizeof(buf), "mmcli -m %d --command=AT+CRESET", idx);
		// logDebug(log, "executethd: cmd=%s", buf);
		ret = system(buf);
		logDebug(log, "resetnicinfo: cmd=%s ret=%d strnicinfo=%s", buf, ret, strnicinfo.c_str());
		if (0 != ret)
		{
			logError(log, "resetnicinfo: Excute shell cmd[%s] failed, return:%d strnicinfo=%s.", buf, ret>>8, strnicinfo.c_str());
			// return 0;
		}
		return -1;
	}
	int sleepcnt = 0;
	int maxcnt = 7;
	// sleep(2);
	while (1)
	{
		char cmd[128];
		snprintf(cmd, sizeof(cmd), "ifconfig %s|grep inet|grep -v 127.0.0.1|grep -v inet6|awk '{print $2}'|tr -d \"addr:\"",
			strnicinfo.c_str());
		if ((fp = popen(cmd, "r")) == NULL)
		{
			logError(log, "popen fail strnicinfo=%s\n", strnicinfo.c_str());
			sleepcnt++;
			sleep(1);
			continue;
			// return -1;
		}

		// logDebug(log, "resetnicinfo: cmd=%s", cmd);

		if (fgets(buf, sizeof(cmd), fp) != NULL)
		{
			logDebug(log, "resetnicinfo: %s network restart succeed buf=%s cmd=%s", strnicinfo.c_str(), buf, cmd);
			pclose(fp);
			return 0;
		}

		pclose(fp);
		// logDebug(log, "sleep 1 sec and try again");
		if (sleepcnt >= maxcnt)
		{
			// logDebug(log, "will resset %d", idx);

			snprintf(buf, sizeof(buf), "mmcli -m %d --command=AT+CRESET", idx);
			// logDebug(log, "executethd: cmd=%s", buf);
			ret = system(buf);
			logDebug(log, "resetnicinfo: cmd=%s ret=%d strnicinfo=%s", buf, ret, strnicinfo.c_str());
			if (0 != ret)
			{
				logError(log, "Excute shell cmd[%s] failed, return:%d strnicinfo=%s.", buf, ret>>8, strnicinfo.c_str());
				// return 0;
			}
			break;
		}

		sleepcnt++;
		sleep(1);
	}

	return 1;
}

int socks_invitation(int fd, int *version, CLog &log)
// int socks_invitation(int fd, int *version)
{
	char init[2];
	int nread = readn(fd, (void *)init, ARRAY_SIZE(init));
	if (nread == 2 && init[0] != VERSION5 && init[0] != VERSION4) 
	{
        logDebug(log, "They send us %hhX %hhX", init[0], init[1]);
		logDebug(log, "Incompatible version!");
		// app_thread_exit(0, fd);
        close(fd);
		return -1;
	}

	// log_message("socks_invitation nread=%d", nread);

	// log_message("Initial %hhX %hhX", init[0], init[1]);
	*version = init[0];
	return init[1];
}

char *socks5_auth_get_user(int fd)
{
	unsigned char size;
	readn(fd, (void *)&size, sizeof(size));

	char *user = (char *)malloc(sizeof(char) * size + 1);
	readn(fd, (void *)user, (int)size);
	user[size] = 0;

	return user;
}

char *socks5_auth_get_pass(int fd)
{
	unsigned char size;
	readn(fd, (void *)&size, sizeof(size));

	char *pass = (char *)malloc(sizeof(char) * size + 1);
	readn(fd, (void *)pass, (int)size);
	pass[size] = 0;

	return pass;
}

int socks5_auth_userpass(int fd)
{
	char answer[2] = { (char)VERSION5, (char)USERPASS };
	writen(fd, (void *)answer, ARRAY_SIZE(answer));
	char resp;
	readn(fd, (void *)&resp, sizeof(resp));
	// log_message("auth %hhX", resp);
	char *username = socks5_auth_get_user(fd);
	char *password = socks5_auth_get_pass(fd);
	// log_message("l: %s p: %s", username, password);
	if (strcmp(arg_username, username) == 0
	    && strcmp(arg_password, password) == 0) 
	{
		char answer[2] = { AUTH_VERSION, AUTH_OK };
		writen(fd, (void *)answer, ARRAY_SIZE(answer));
		free(username);
		free(password);
		return 0;
	} 
	else 
	{
		char answer[2] = { (char)AUTH_VERSION, (char)AUTH_FAIL };
		writen(fd, (void *)answer, ARRAY_SIZE(answer));
		free(username);
		free(password);
		return 1;
	}
}

int socks5_auth_noauth(int fd)
{
	char answer[2] = { (char)VERSION5, (char)NOAUTH };
	writen(fd, (void *)answer, ARRAY_SIZE(answer));
	return 0;
}

void socks5_auth_notsupported(int fd)
{
	char answer[2] = { (char)VERSION5, (char)NOMETHOD };
	writen(fd, (void *)answer, ARRAY_SIZE(answer));
}

int socks5_auth(int fd, int methods_count)
{
	int supported = 0;
	int num = methods_count;
	// log_message("methods_count=%d", methods_count);
	for (int i = 0; i < num; i++) 
	{
		char type;
		readn(fd, (void *)&type, 1);
		// log_message("Method AUTH %hhX auth_type=%d", type, auth_type);
		if (type == auth_type) 
		{
			supported = 1;
			break;
		}
	}
	if (supported == 0) 
	{
		socks5_auth_notsupported(fd);
		// app_thread_exit(1, fd);
        close(fd);
		return -1;
	}
	int ret = 0;
	switch (auth_type) 
	{
	case NOAUTH:
		ret = socks5_auth_noauth(fd);
		break;
	case USERPASS:
		ret = socks5_auth_userpass(fd);
		break;
	}

	if (ret == 0) 
	{
		return 0;
	} 
	else 
	{
		// app_thread_exit(1, fd);
        close(fd);
		return -1;
	}

	return 0;
}

int socks5_command(int fd)
{
	// log_message("socks5_command fd=%d", fd);
	char command[4];
	readn(fd, (void *)command, ARRAY_SIZE(command));
	// log_message("Command %hhX %hhX %hhX %hhX", command[0], command[1],
	// 	    command[2], command[3]);

	// log_message("Command %d %d %d %d", command[0], command[1],
		    // command[2], command[3]);

	return command[3];
}

unsigned short int socks_read_port(int fd)
{
	unsigned short int p;
	readn(fd, (void *)&p, sizeof(p));
	// log_message("Port %hu", ntohs(p));
	return p;
}

char *socks_ip_read(int fd)
{
	char *ip = (char *)malloc(sizeof(char) * IPSIZE);
	readn(fd, (void *)ip, IPSIZE);
	// log_message("IP %hhu.%hhu.%hhu.%hhu", ip[0], ip[1], ip[2], ip[3]);
	return ip;
}

void socks5_ip_send_response(int fd, char *ip, unsigned short int port)
{
	char response[4] = { VERSION5, OK, RESERVED, IP };
	writen(fd, (void *)response, ARRAY_SIZE(response));
	writen(fd, (void *)ip, IPSIZE);
	writen(fd, (void *)&port, sizeof(port));
}

char *socks5_domain_read(int fd, unsigned char *size)
{
	unsigned char s;
	readn(fd, (void *)&s, sizeof(s));
	char *address = (char *)malloc((sizeof(char) * s) + 1);
	readn(fd, (void *)address, (int)s);
	address[s] = 0;
	// log_message("Address %s", address);
	*size = s;
	return address;
}

void socks5_domain_send_response(int fd, char *domain, unsigned char size,
				 unsigned short int port)
{
	char response[4] = { VERSION5, OK, RESERVED, DOMAIN };
	writen(fd, (void *)response, ARRAY_SIZE(response));
	writen(fd, (void *)&size, sizeof(size));
	writen(fd, (void *)domain, size * sizeof(char));
	writen(fd, (void *)&port, sizeof(port));
}

int connect_timeout(CLog &log, int sockfd, const struct sockaddr *addr,
                    socklen_t addrlen) 
{
    int flags = fcntl( sockfd, F_GETFL, 0 );
    if (flags == -1) {
    return -1;
    }
    if (fcntl( sockfd, F_SETFL, flags | O_NONBLOCK ) < 0) {
    return -1;
    }
	// logDebug(log, "connect_timeout  sock2=%d", sockfd);
    int status = connect(sockfd, addr, addrlen);
    if (status == -1 and errno != EINPROGRESS) 
	{
		logError(log, "connect Error sock=%d", sockfd);
		// logError(log, "Connect Error.");
    	return -1;
    }

    if (status == 0) 
	{
		// logDebug(log, "connect_timeout  sock4=%d", sockfd);
    	if (fcntl(sockfd, F_SETFL, flags) <  0) 
		{
			logError(log, "fcntl  sock=%d", sockfd);
        	return -1;
    	}

    	return 1;
    }

	int epollfd = epoll_create1(0);
	if (epollfd <= 0)
	{
		logError(log, "epoll_create1 err=%s sockfd=%d\n", strerror(errno), sockfd);
		return -1;
	}
    // handle_error("epoll_create");

	#define MAX_EVENTS 10
	struct epoll_event ev, events[MAX_EVENTS];
	// ev.events = EPOLLOUT;
	ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
	ev.data.fd = sockfd;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sockfd, &ev) == -1)
	{
		logError(log, "epoll_ctl err=%s sockfd=%d\n", strerror(errno), sockfd);
		close(epollfd);
		return -1;
	}

	#define TIMEOUT 3000
	
	int nfds = epoll_wait(epollfd, events, MAX_EVENTS, TIMEOUT);
	if (nfds < 0) 
	{
		logError(log, "epoll_wait err=%s sockfd=%d\n", strerror(errno), sockfd);
		epoll_ctl(epollfd, EPOLL_CTL_DEL, sockfd, NULL);
		close(epollfd);
		return -1;
		// logError(log, "epoll_wait\n");
		// handle_error("epoll_wait");
	} 
	else if (nfds == 0) 
	{
		logError(log, "epoll_wait timeout err=%s sockfd=%d\n", strerror(errno), sockfd);
		epoll_ctl(epollfd, EPOLL_CTL_DEL, sockfd, NULL);
		close(epollfd);
		return -1;
		// handle_error("epoll_wait timeout");
	}
	else 
	{
		bool fail = (events[0].events & EPOLLIN) || !(events[0].events & EPOLLOUT);
		epoll_ctl(epollfd, EPOLL_CTL_DEL, sockfd, NULL);
		close(epollfd);
		if (fail)
		{
			logError(log, "connect error\n");
			return -1;
		}

		 if (fcntl(sockfd, F_SETFL, flags) <  0) 
		 {
			logError(log, "fcntl  sock=%d", sockfd);
        	return -1;
    	}
		else
		{
			logDebug(log, "fcntl  sock=%d succeed", sockfd);
        	return 1;
		}
		
		

		// for (int n = 0; n < nfds; ++n) 
		// {
			


		// 	if (events[n].data.fd == sockfd && (events[n].events & EPOLLOUT)) 
		// 	{
		// 		int connect_error = 0;
		// 		socklen_t len = sizeof(connect_error);
		// 		if (getsockopt(epollfd, SOL_SOCKET, SO_ERROR, (void*)(&connect_error), &len) < 0)
		// 		{
		// 			logError(log, "getsockopt error\n");
		// 			return -1;
		// 		}
		// 		// handle_error("getsockopt");

		// 		if (connect_error != 0) 
		// 		{
		// 			logError(log, "connect: %s sock=%d\n", strerror(connect_error), epollfd);
		// 			return -1;
		// 			// fprintf(stderr, );
		// 			// exit(EXIT_FAILURE);
		// 		}

		// 		if ( fcntl( sockfd, F_SETFL, flags ) < 0 ) 
		// 		{
    	// 			return -1;
		// 		 }

		// 		return 1;
		// 	}
		// }
  	} 
		// handle_error("epoll_ctl");


	// logDebug(log, "connect_timeout  sock6=%d", sockfd);
    // fd_set read_events;
	// logDebug(log, "connect_timeout  sock71=%d", sockfd);
    // fd_set write_events;
	// logDebug(log, "connect_timeout  sock72=%d", sockfd);
    // FD_ZERO(&read_events);
	// logDebug(log, "connect_timeout  sock73=%d", sockfd);
	// FD_ZERO(&write_events);
	// logDebug(log, "connect_timeout  sock74=%d", sockfd);
	// int err = 0;
    // socklen_t errlen = sizeof(err);
	// logDebug(log, "connect_timeout  sock75=%d", sockfd);
    // // FD_SET(sockfd, &read_events);
	// // FD_ZERO(&fdr);
	// // FD_ZERO(&fdw);
	// FD_SET(sockfd, &read_events);
	// logDebug(log, "connect_timeout  sock76=%d", sockfd);
	// FD_SET(sockfd, &write_events);
	// logDebug(log, "connect_timeout  sock77=%d", sockfd);
    // // write_events = read_events;
	// timeval tm;
	// tm.tv_sec = 10;
	// tm.tv_usec = 0;
    // int rc = select(sockfd + 1, &read_events, &write_events, nullptr, &tm );
    // if (rc < 0) {
	// 	logError(log, "Connect error.");
    // return -1;
    // } else if (rc == 0) {
	// 	logError(log, "Connect timeout.");
    // return -1;
    // }
	// logDebug(log, "connect_timeout  sock8=%d", sockfd);
	//  /*[1] 当连接成功建立时，描述符变成可写,rc=1*/
	// if (rc == 1 && FD_ISSET(sockfd, &write_events)) 
	// {
	// 	// printf("Connect success\n");
	// 	// close(fd);
	// 	logDebug(log, "connect_timeout  sock9=%d", sockfd);
	// 	return 1;
	// }

	//  /*[2] 当连接建立遇到错误时，描述符变为即可读，也可写，rc=2 遇到这种情况，可调用getsockopt函数*/
	// if (rc == 2) 
	// {
	// 	if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &err, &errlen) == -1) 
	// 	{
	// 		logDebug(log, "connect_timeout  sock10=%d", sockfd);
	// 		logError(log, "getsockopt(SO_ERROR): %s", strerror(errno));
	// 		// close(fd);
	// 		return -1;
	// 	}
	// 	logDebug(log, "connect_timeout  sock11=%d", sockfd);
	// 	if (err) 
	// 	{
	// 		logDebug(log, "connect_timeout  sock12=%d", sockfd);
	// 		errno = err;
	// 		logError(log, "connect error:%s\n", strerror(errno));
	// 		// close(fd);
	// 		return -1;
	// 	}
	// }

	// logError(log, "connect failed, error:%s.\n", strerror(errno));
    // return -1;
    // if (!isconnected(sockfd, &read_events, &write_events) )
    // {
    // return -1;
    // }
    // if ( fcntl( sockfd, F_SETFL, flags ) < 0 ) {
    // return -1;
    // }
    // return 1;
}

std::string getHostIpByName(const std::string &name)
{
    struct hostent *hptr;
    hptr = gethostbyname(name.c_str());
	
    if (hptr == nullptr)
    {
        hstrerror(h_errno);
        throw std::exception();
    }

    if (hptr->h_addrtype != AF_INET)
    {
        throw std::exception();
    }

    char **pptr = hptr->h_addr_list;
    if (*pptr == nullptr)
    {
        throw std::exception();
    }

    char str[INET_ADDRSTRLEN];
    inet_ntop(hptr->h_addrtype, hptr->h_addr, str, sizeof(str));
    return std::string{str};
}

void CConnData::SetConnInfo(string strnic, int fd, string strip, int port)
// void CConnData::SetConnInfo(string strnic, int fd)
{
	std::unique_lock<std::mutex> locker(connmutex);
	CConnInfo connInfo;
	connInfo.sock = fd;
	connInfo.strNic = strnic;
	connInfo.strip = strip;
	connInfo.port = port;
	m_mapConnInfo[strnic].push_back(connInfo);	
	locker.unlock();
}
#if 0
int ConnectServer(string strnic, int port, CLog &log)
{
	// CLog log("ConnectServer");
	// if(log.init(CLOG_DEBUG) < 0)
	// {
	// 	fprintf(stderr, "init log faild.\n");
	// }

	struct sockaddr_in remote;
	memset(&remote, 0, sizeof(remote));
	remote.sin_port = htons(port);
	remote.sin_family = AF_INET;
	struct timeval start;
    struct timeval end;
	std::string str = getHostIpByName("api64.ipify.org");
	for (int i=0; i<10; i++)
	{
		remote.sin_addr.s_addr = inet_addr(str.c_str());
		int fd = socket(AF_INET, SOCK_STREAM, 0);
		struct ifreq interface;
		// string str = "10.16.117.152";
		// int portnum = 443;
		int portnum = port;
		// logDebug(log, "get nic name =%s connect ip=%s portnum=%d sndtotalcnt=%d", str.c_str(), address, portnum, resetInfo.sndtotalcnt);
		// cout << "get nic name =" << str << " connect ip=" << address << " portnum=" << portnum <<  endl;
		snprintf(interface.ifr_ifrn.ifrn_name, sizeof(interface.ifr_ifrn.ifrn_name),
			"%s", strnic.c_str());
    	// strncpy(interface.ifr_ifrn.ifrn_name, str.c_str(), str.size());
		if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&interface, sizeof(interface))  < 0) 
		{
			perror("SO_BINDTODEVICE failed 1");
		}

		// log_message("connect() in before connect");
		// if (connect(fd, (struct sockaddr *)&remote, sizeof(remote)) < 0) 
		
		timeval tm;
		tm.tv_sec = 8;
		tm.tv_usec = 0;
		gettimeofday(&start,NULL); //gettimeofday(&start,&tz);结果一样

		int keepalive = 1;
		setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepalive , sizeof(keepalive));
		//发送 keepalive 报文的时间间隔
		int val = 1;
		setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &val, sizeof(val));
		// //两次重试报文的时间间隔
		// int interval = 1;
		// setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
		// int cnt = 3;
		// setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));

		if (connect_timeout(log, fd, (struct sockaddr *)&remote, sizeof(remote)) < 0) 
		{

			logError(log, "connect() in connect_timeout ip=%s port=%d error", str.c_str(), portnum);
			gettimeofday(&end,NULL); //gettimeofday(&start,&tz);结果一样	
			float time_use=(end.tv_sec-start.tv_sec)*1000+(end.tv_usec-start.tv_usec)/1000;//微秒
			logDebug(log, "connect_timeout  need  %.6f ms\n",time_use);
			close(fd);
			continue;
			// return -1;
		}
		else
		{
			logDebug(log, "connect() in ip=%s port=%d succeed socket=%d", 
				str.c_str(), portnum, fd);
		}

		gettimeofday(&end,NULL); //gettimeofday(&start,&tz);结果一样	
		float time_use=(end.tv_sec-start.tv_sec)*1000+(end.tv_usec-start.tv_usec)/1000;//微秒
		logDebug(log, "Connect Server  need  %.6f ms\n",time_use);
		
		connData.SetConnInfo(strnic, fd, str, 443);
	}
	
	return 0;
}
#endif
#if 0
void connproxysrvthd()
{	
	int second = 120;
	#if 0
	std::deque<StNicInfo *> &queue = connserver.getqueue();
	// connserver.
	while (1)
	{
		std::unique_lock<std::mutex> locker(connserver.connmutex);
		while(queue.empty())
		{
			connserver.conncond.wait(locker); // Unlock mu and wait to be notified
		}
			

		string strnic = queue.front()->strnic;
		int idx = queue.front()->idx;
		delete queue.front();
		// int idx = cmdqueue.front().idx;
		// logDebug(log, "nic=%s idx=%d have data to process", strnic, idx);
		queue.pop_front();

		locker.unlock();
		ConnectServer(strnic, 443, connproxysrvlog);
		// resetnicinfo(log, idx, strnic);
	}
	#endif
}

void resetnicthd()
{	
	#if 0
	std::deque<string> &queue = g_resetnic.getqueue();
	while (1)
	{
		std::unique_lock<std::mutex> locker(g_resetnic.resetmutex);
		while(queue.empty())
		{
			g_resetnic.resetcond.wait(locker); // Unlock mu and wait to be notified
		}
			

		string strnic = queue.front();

		queue.pop_front();
		locker.unlock();

		// for (auto data:connserver.vecstr)
		// {
		// 	if (data.strnic == strnic)
		// 	{
		// 		resetnicinfo(nicresetlog, data.idx, strnic);
		// 	}
		// }
	}
	#endif
}
#endif
int readn(int fd, void *buf, int n)
{
	int nread, left = n;
	char *tmpdata = (char *)buf;
	while (left > 0) 
	{
		if ((nread = read(fd, tmpdata, left)) == -1) 
		{
			if (errno == EINTR || errno == EAGAIN) 
			{
				continue;
			}
		} 
		else 
		{
			if (nread == 0) 
			{
				return 0;
			} 
			else 
			{
				left -= nread;
				tmpdata += nread;
			}
		}
	}
	return n;
}

int writen(int fd, void *buf, int n)
{
	int nwrite, left = n;
	char *tmpdata = (char *)buf;
	while (left > 0) {
		if ((nwrite = write(fd, tmpdata, left)) == -1) 
		{
			if (errno == EINTR || errno == EAGAIN) 
			{
				continue;
			}
		} 
		else 
		{
			if (nwrite == n) 
			{
				return 0;
			} 
			else 
			{
				left -= nwrite;
				tmpdata += nwrite;
				// buf += nwrite;
			}
		}
	}
	return n;
}



bool StNicInfo::isavalable()
{
	// std::unique_lock<std::mutex> locker(*nicmutex);
	if (true == iscanused && currentcnt < maxsendcnt && connectfailcnt < maxconnfailcnt)
	// if (true == iscanused)
	{
		currentcnt++;
		//locker.unlock();
		return true;
	}

	isneedset=true;
	
	disable();
	// locker.unlock();
	// resetcnt++;
	return false;
}

bool StNicInfo::isresetavalable()
{
	return resetcnt < maxresetcnt;
}

StNicInfo::StNicInfo(string nicdata, int index)
{
	strnic = nicdata;
	iscanused = false;
	currentcnt = 0;
	idx = index;
	resetcnt = 0;
	connectfailcnt = 0;
	isneedset = false;
	nicmutex = new std::mutex();
}

void StNicInfo::increcnt()
{
	currentcnt++;
}

bool StNicInfo::isenable()
{
	return true == iscanused;
}

void StNicInfo::enable()
{
	iscanused = true;
	currentcnt = 0;
	connectfailcnt = 0;
}

void StNicInfo::disable()
{
	iscanused = false;
	currentcnt = 0;
	connectfailcnt = 0;
}


CRunNicInfo::CRunNicInfo()
{
	requestcnt = 0;
	errcnt = 0;
}

CConnectServer::CConnectServer()
{
	m_curnicidx = 0;
}

void CConnectServer::ResetNicip(CLog &log)
{
	std::unique_lock<std::mutex> niclocker(nicmutex);
	char buf[128];
	for(auto &data:vecstr)
	{
		
		char cmd[128];
		snprintf(cmd, sizeof(cmd), "ifconfig %s|grep inet|grep -v 127.0.0.1|grep -v inet6|awk '{print $2}'|tr -d \"addr:\"",
			data.strnic.c_str());
		FILE *fp;
		if ((fp = popen(cmd, "r")) == NULL)
		{
			logError(log, "popen fail strnicinfo=%s\n", data.strnic.c_str());
			continue;
		}

		// logDebug(log, "resetnicinfo: cmd=%s", cmd);

		if (fgets(buf, sizeof(buf), fp) != NULL)
		{
			logDebug(log, "resetnicinfo: %s network restart succeed buf=%s cmd=%s", data.strnic.c_str(), buf, cmd);
			pclose(fp);
			return;
		}

		pclose(fp);

		if (true == data.isneedset)
		{
			data.isneedset = false;
			
			niclocker.unlock();
			resetnicinfo(log, data.idx, data.strnic);
			return;
		}			
	}

	niclocker.unlock();
}

void CConnectServer::ResetNic(CLog &log)
{
	std::unique_lock<std::mutex> niclocker(nicmutex);
	for(auto &data:vecstr)
	{
		if (true == data.isneedset)
		{
			data.isneedset = false;
			
			niclocker.unlock();
			resetnicinfo(log, data.idx, data.strnic);
			std::unique_lock<std::mutex> locker1(resetmutex);
			vecResetInfo.push_back(data);
			locker1.unlock();
			return;
		}			
	}

	niclocker.unlock();
}

StNicInfo &CConnectServer::getNicInfo()
{
	std::unique_lock<std::mutex> locker(nicmutex);
	if (vecstr[m_curnicidx].isavalable())
	{
		locker.unlock();
		return vecstr[m_curnicidx];
	}
		

	int lastidx = m_curnicidx;
	++m_curnicidx;
	m_curnicidx = m_curnicidx % vecstr.size();
	while (lastidx != m_curnicidx)
	{
		// 
		if (vecstr[m_curnicidx].isavalable())
		{
			locker.unlock();
			return vecstr[m_curnicidx];
		}

		++m_curnicidx;
		m_curnicidx = m_curnicidx % vecstr.size();
	}

	locker.unlock();
	return vecstr[lastidx];
}

void CConnectServer::UadateConnFailInfo(CLog &log, string strnic)
{
	std::unique_lock<std::mutex> locker(nicmutex);
	size_t i=0;
	for (i=0; i<vecstr.size(); i++)
	{
		if (vecstr[i].strnic == strnic)
		{
			break;
		}
	}

	if (i<vecstr.size())
	{
		vecstr[i].connectfailcnt++;
		logDebug(log, "connect server error strnic=%s connectfailcnt=%d",
			strnic.c_str(), vecstr[i].connectfailcnt);
	}
	locker.unlock();
}

