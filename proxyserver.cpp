#include "ThreadPool.h"
#include "sock5proxy.h"
#include <algorithm>
#include <sys/time.h>
#include "server.h"
CLog nicresetlog;
CLog workerThreadlog;
CLog connproxysrvlog;
int epollfd;
using std::queue;
using std::map;
using std::string;
using std::vector;
#include <sys/epoll.h>
// CConnectServer connserver;
char abs_path_buff[256];
server g_server;

extern std::mutex resetmu;
extern std::condition_variable resetcond;

extern CConnectServer connserver;

extern CConnData connData;

extern std::deque<CCmdInfo> cmdqueue;
extern std::mutex mu;

// extern StResetInfo resetInfo;

std::mutex acceptmutex;

int sndtotalcnt;

unsigned short int port = 1080;
int daemon_mode = 0;
int auth_type;
char *arg_username;
char *arg_password;
FILE *log_file;

// pthread_mutex_t niclock;

#include "log_lib_cplus.h" 

// vector <StNicInfo> vecstr;

// string getnic()
// {
// 	pthread_mutex_lock(&niclock);

// 	int tmpidx = curidx % vecstr.size();
// 	if (vecstr[tmpidx].isavalable())
// 	{
// 		pthread_mutex_unlock(&niclock);
// 		return vecstr[tmpidx].strnic;
// 	}
// 	else
// 	{
// 		StNicInfo *stNicInfo = new StNicInfo(vecstr[tmpidx].strnic, vecstr[tmpidx].idx);
// 		// resetnicpool.addTask(reset_nic_process, stNicInfo);	
// 	}

// 	int cnt = 0;
// 	while (1)
// 	{
// 		if (vecstr[tmpidx].isavalable())
// 		{
// 			break;
// 		}
// 		else if (cnt > vecstr.size())
// 		{
// 			pthread_mutex_unlock(&niclock);
// 			return "";
// 		}

// 		tmpidx = ++tmpidx % vecstr.size();
// 		cnt++;
// 	}

// 	curidx = tmpidx;
// 	// curidx++;
// 	// curidx = ++curidx % vecstr.size();
// 	pthread_mutex_unlock(&niclock);

// 	return vecstr[tmpidx].strnic;
// }

#if 0
int app_connect(int type, void *buf, unsigned short int portnum, CLog &log)
{
	int fd;
	struct sockaddr_in remote;
	char address[16];

	memset(address, 0, ARRAY_SIZE(address));

	if (type == IP) 
	{
		char *ip = (char *)buf;
		snprintf(address, ARRAY_SIZE(address), "%hhu.%hhu.%hhu.%hhu",
			 ip[0], ip[1], ip[2], ip[3]);
		memset(&remote, 0, sizeof(remote));
		remote.sin_family = AF_INET;
		remote.sin_addr.s_addr = inet_addr(address);
		remote.sin_port = htons(portnum);

		

		struct ifreq interface;
		// string str = resetInfo.getnic();
		string str = "wwan7";
		// CConnInfo conn = connData.GetConnInfo();
		
		// if (conn.strNic == "")
		if (str == "")
		{
			logDebug(log, "dont have nic");
			close(fd);
			return -1;
		}

		sndtotalcnt++;
		logDebug(log, "get nic name =%s connect ip=%s portnum=%d sndtotalcnt=%d", 
			str.c_str(), address, portnum, resetInfo.sndtotalcnt);
		// cout << "get nic name =" << str << " connect ip=" << address << " portnum=" << portnum <<  endl;
		// snprintf(interface.ifr_ifrn.ifrn_name, sizeof(interface.ifr_ifrn.ifrn_name),
		// 	"%s", conn.strNic.c_str());
		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, "wwan4", strlen("wwan4")+1)  < 0) 
		{
			perror("SO_BINDTODEVICE failed 1");
		}

		
    	// strncpy(interface.ifr_ifrn.ifrn_name, str.c_str(), str.size());
		// 
		// if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&interface, sizeof(interface))  < 0) 
		// {
		// 	perror("SO_BINDTODEVICE failed 1");
		// }

		// log_message("connect() in before connect");
		// if (connect(fd, (struct sockaddr *)&remote, sizeof(remote)) < 0) 
		timeval tm;
		tm.tv_sec = 10;
		tm.tv_usec = 0;
		if (connect_timeout(log, fd, (struct sockaddr *)&remote, sizeof(remote), &tm) < 0) 
		{
			logDebug(log, "connect() in app_connect ip=%s port=%d", address, portnum);
			close(fd);
			return -1;
		}

		return fd;
		// return conn.sock;
	} 
	// else if (type == DOMAIN) 
	// {
	// 	char portaddr[6];
	// 	struct addrinfo *res;
	// 	snprintf(portaddr, ARRAY_SIZE(portaddr), "%d", portnum);
		
	// 	int ret = getaddrinfo((char *)buf, portaddr, NULL, &res);
	// 	if (ret == EAI_NODATA) 
	// 	{
	// 		return -1;
	// 	} 
	// 	else if (ret == 0) 
	// 	{
	// 		struct addrinfo *r;
	// 		for (r = res; r != NULL; r = r->ai_next) 
	// 		{
	// 			fd = socket(r->ai_family, r->ai_socktype,
	// 				    r->ai_protocol);
    //             if (fd == -1) 
	// 			{
    //                 continue;
    //             }
	// 			ret = connect(fd, r->ai_addr, r->ai_addrlen);
	// 			if (ret == 0) 
	// 			{
	// 				freeaddrinfo(res);
	// 				return fd;
    //             } 
	// 			else 
	// 			{
    //                 close(fd);
    //             }
	// 		}
	// 	}
	// 	freeaddrinfo(res);
	// 	return -1;
	// }

    // return -1;
}
#endif
int socks4_is_4a(char *ip)
{
	return (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0);
}

int socks4_read_nstring(int fd, char *buf, int size)
{
	char sym = 0;
	int nread = 0;
	int i = 0;

	while (i < size) 
	{
		nread = recv(fd, &sym, sizeof(char), 0);

		if (nread <= 0) 
		{
			break;
		} 
		else 
		{
			buf[i] = sym;
			i++;
		}

		if (sym == 0) 
		{
			break;
		}
	}

	return i;
}

void socks4_send_response(int fd, int status)
{
	char resp[8] = {0x00, (char)status, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	writen(fd, (void *)resp, ARRAY_SIZE(resp));
}

void app_socket_pipe(int serverfd, int clientfd, CLog &log, int seq)
{
	int maxfd, ret;
	fd_set rd_set;
	size_t nread;
	char buffer_r[BUFSIZE];	
	struct timeval start;
    struct timeval end;
	// float time_use=0;

	timeval tm;
	tm.tv_sec = 5;
	maxfd = (serverfd > clientfd) ? serverfd : clientfd;
	logDebug(log, "app_socket_pipe func begin\n");
	while (1) 
	{
		FD_ZERO(&rd_set);
		FD_SET(serverfd, &rd_set);
		FD_SET(clientfd, &rd_set);
		ret = select(maxfd + 1, &rd_set, NULL, NULL, &tm);
		if (ret <= 0)
			break;

		if (FD_ISSET(serverfd, &rd_set)) 
		{
			gettimeofday(&start,NULL); //gettimeofday(&start,&tz);结果一样
			nread = recv(serverfd, buffer_r, BUFSIZE, 0);
			if (nread <= 0)
			{
				// cout << "app_socket_pipe: recv=" << nread << endl; 
				logDebug(log, "recv quit  nread=%d seq=%d\n", nread, seq);
				break;
			}

			logDebug(log, "recv data  nread=%d seq=%d\n", nread, seq);

			int ret = send(clientfd, (const void *)buffer_r, nread, 0);
			if (ret <=0)
			{
				// cout << "app_socket_pipe: recv11=" << nread << endl; 
				logDebug(log, "send quit  nread=%d\n", ret);
				
				break;
			}

			logDebug(log, "send data  nread=%d seq=%d\n", ret, seq);

			gettimeofday(&end,NULL); //gettimeofday(&start,&tz);结果一样
			// float time_use=(end.tv_sec-start.tv_sec)*1000+(end.tv_usec-start.tv_usec)/1000;//微秒
   			// logDebug(log, "recv from server  need  %.6f ms seq=%d\n",time_use, seq);
		}

		if (FD_ISSET(clientfd, &rd_set)) 
		{
			gettimeofday(&start,NULL); //gettimeofday(&start,&tz);结果一样
			nread = recv(clientfd, buffer_r, BUFSIZE, 0);
			if (nread <= 0)
			{
				// cout << "app_socket_pipe: recv22=" << nread << endl; 
				logDebug(log, "send quit  nread=%d\n", nread);
				break;
			}

			logDebug(log, "recv data  nread=%d seq=%d\n", nread, seq);
				
			int ret = send(serverfd, (const void *)buffer_r, nread, 0);
			if (ret <=0)
			{
				
				// cout << "app_socket_pipe: recv33=" << nread << endl; 
				logDebug(log, "send quit  ret=%d\n", ret);
				break;
			}
			gettimeofday(&end,NULL); //gettimeofday(&start,&tz);结果一样
			// time_use=(end.tv_sec-start.tv_sec)*1000+(end.tv_usec-start.tv_usec)/1000;//微秒
			logDebug(log, "send data  nread=%d seq=%d\n", ret, seq);
   			// logDebug(log, "send to client  need  %.6f ms seq=%d\n",time_use, seq);
		}
	}
}
#if 0
void *app_thread_process(void *fd)
{
	StSockInfo *info = (StSockInfo *)fd;
	int seq = info->seq;
	int client_fd = info->sock;
	int version = 0;
	int server_fd = -1;
	struct timeval start;
    struct timeval end;
	float time_use=0;
	 struct timeval starttotal;
    struct timeval endtotal;
    float totaltime_use=0;
	// CLog log("procclientmsg");
	// if(log.init(CLOG_DEBUG) < 0)
	// {
	// 	fprintf(stderr, "init log faild.\n");
	// }
	gettimeofday(&starttotal,NULL); //gettimeofday(&start,&tz);结果一样
	gettimeofday(&start,NULL); //gettimeofday(&start,&tz);结果一样
	char methods = socks_invitation(client_fd, &version, (*(info->log)));
	if (-1 == methods)
	{
		// close(server_fd);
		return NULL;
	}

	gettimeofday(&end,NULL);
	time_use=(end.tv_sec-start.tv_sec)*1000+(end.tv_usec-start.tv_usec)/1000;//微秒
    // logDebug((*(info->log)), "socks_invitation function need  %.6f ms seq=%d\n",time_use, seq);

	switch (version) {
	case VERSION5: 
	{
			gettimeofday(&start,NULL); //gettimeofday(&start,&tz);结果一样
			if (socks5_auth(client_fd, methods))
			{
				// close(server_fd);
				return NULL;
			}
			gettimeofday(&end,NULL);
			time_use=(end.tv_sec-start.tv_sec)*1000+(end.tv_usec-start.tv_usec)/1000;//微秒
   			// logDebug((*(info->log)), "socks5_auth function need  %.6f ms seq=%d\n",time_use, seq);

			gettimeofday(&start,NULL); //gettimeofday(&start,&tz);结果一样
			int command = socks5_command(client_fd);
			gettimeofday(&end,NULL); //gettimeofday(&start,&tz);结果一样
			time_use=(end.tv_sec-start.tv_sec)*1000+(end.tv_usec-start.tv_usec)/1000;//微秒
   			logDebug((*(info->log)), "socks5_command function need  %.6f ms seq=%d\n",time_use, seq);

			// log_message("command11=%d", command);
			if (command == (int)IP) 
			{
				// log_message("command11111=%d", command);
				gettimeofday(&start,NULL); //gettimeofday(&start,&tz);结果一样
				char *ip = socks_ip_read(client_fd);
				gettimeofday(&end,NULL); //gettimeofday(&start,&tz);结果一样
				time_use=(end.tv_sec-start.tv_sec)*1000+(end.tv_usec-start.tv_usec)/1000;//微秒
   				// logDebug((*(info->log)), "socks_ip_read function need  %.6f ms seq=%d\n",time_use, seq);

				// log_message("ip=%s", ip);
				gettimeofday(&start,NULL); //gettimeofday(&start,&tz);结果一样
				unsigned short int p = socks_read_port(client_fd);
				gettimeofday(&end,NULL); //gettimeofday(&start,&tz);结果一样
				time_use=(end.tv_sec-start.tv_sec)*1000+(end.tv_usec-start.tv_usec)/1000;//微秒
   				// logDebug((*(info->log)), "socks_read_port function need  %.6f ms seq=%d\n",time_use, seq);


				gettimeofday(&start,NULL); //gettimeofday(&start,&tz);结果一样
				// CConnInfo conn = connData.GetConnInfo();
				// if (conn.strNic == "")
				// {
				// 	logDebug((*(info->log)), "dont have nic");
				// 	close(conn.sock);
				// 	return NULL;
				// }

				// server_fd = conn.sock;

				server_fd = app_connect(IP, (void *)ip, ntohs(p), (*(info->log)));
				if (server_fd == -1) 
				{

					// app_thread_exit(1, client_fd);
					close(client_fd);
					gettimeofday(&end,NULL); //gettimeofday(&start,&tz);结果一样
					
					time_use=(end.tv_sec-start.tv_sec)*1000+(end.tv_usec-start.tv_usec)/1000;//微秒
   					logDebug((*(info->log)), "app_connect timeout  %.6f ms seq=%d\n",time_use, seq);
					// close(server_fd);
					return NULL;
				}
				int fd;
				
				char address[16];
				memset(address, 0, ARRAY_SIZE(address));

	
				// char *ip = (char *)buf;
				snprintf(address, ARRAY_SIZE(address), "%hhu.%hhu.%hhu.%hhu",
					 ip[0], ip[1], ip[2], ip[3]);
				gettimeofday(&end,NULL); //gettimeofday(&start,&tz);结果一样
				time_use=(end.tv_sec-start.tv_sec)*1000+(end.tv_usec-start.tv_usec)/1000;//微秒
   				// logDebug((*(info->log)), "app_connect function need  %.6f ms seq=%d inet_fd=%d"
				// " nic name =%s connect ip=%s portnum=%d reqip=%s reqport=%d\n",
				// 	time_use, seq, server_fd, conn.strNic.c_str(), conn.strip.c_str(), conn.port,
				// 	address, ntohs(p));

				logDebug((*(info->log)), "app_connect function need  %.6f ms seq=%d inet_fd=%d"
				" nic name =%s connect ip=%s portnum=%d reqip=%s reqport=%d\n",
					time_use, seq, server_fd, "wwan3", address, p,
					address, ntohs(p));

				gettimeofday(&start,NULL); //gettimeofday(&start,&tz);结果一样
				socks5_ip_send_response(client_fd, ip, p);
				// socks5_ip_send_response(client_fd, (char *)conn.strip.c_str(), conn.port);
				gettimeofday(&end,NULL); //gettimeofday(&start,&tz);结果一样
				time_use=(end.tv_sec-start.tv_sec)*1000+(end.tv_usec-start.tv_usec)/1000;//微秒
   				// logDebug((*(info->log)), "socks5_ip_send_response function need  %.6f ms seq=%d\n",time_use, seq);
				free(ip);
				break;
			} 
			else if (command == (int)DOMAIN) 
			{
				// log_message("command33=%d", command);
				// unsigned char size;
				// char *address = socks5_domain_read(client_fd, &size);
				// unsigned short int p = socks_read_port(client_fd);

				// server_fd = app_connect(DOMAIN, (void *)address, ntohs(p), (*(info->log)));
				// if (server_fd == -1) {
				// 	// app_thread_exit(1, client_fd);
				// 	close(client_fd);
				// 	return NULL;
				// }
				// socks5_domain_send_response(client_fd, address, size, p);
				// free(address);
				// break;
			} 
			else 
			{
				// log_message("command44=%d", command);
				// app_thread_exit(1, client_fd);
				close(client_fd);
				return NULL;
			}
		}
		case VERSION4: 
		{
			if (methods == 1) 
			{
				char ident[255];
				unsigned short int p = socks_read_port(client_fd);
				char *ip = socks_ip_read(client_fd);
				socks4_read_nstring(client_fd, ident, sizeof(ident));

				if (socks4_is_4a(ip)) 
				{
					char domain[255];
					socks4_read_nstring(client_fd, domain, sizeof(domain));
					logDebug((*(info->log)), "Socks4A: ident:%s; domain:%s;", ident, domain);
					// server_fd = app_connect(DOMAIN, (void *)domain, ntohs(p), (*(info->log)));
				} 
				else 
				{
					logDebug((*(info->log)), "Socks4: connect by ip & port");
					// server_fd = app_connect(IP, (void *)ip, ntohs(p), (*(info->log)));
				}

				if (server_fd != -1) 
				{
					socks4_send_response(client_fd, 0x5a);
				}
				else 
				{
					socks4_send_response(client_fd, 0x5b);
					free(ip);
					// app_thread_exit(1, client_fd);
					close(client_fd);
					return NULL;
				}

				free(ip);
            } 
			else 
			{
                logDebug((*(info->log)), "Unsupported mode");
            }
			break;
		}
	}

	gettimeofday(&start,NULL); //gettimeofday(&start,&tz);结果一样
	app_socket_pipe(server_fd, client_fd, (*(info->log)), seq);
	gettimeofday(&end,NULL); //gettimeofday(&start,&tz);结果一样
	time_use=(end.tv_sec-start.tv_sec)*1000+(end.tv_usec-start.tv_usec)/1000;//微秒
	logDebug((*(info->log)), "app_socket_pipe function need  %.6f ms seq=%d\n",time_use, seq);
	close(server_fd);
	// app_thread_exit(0, client_fd);
	close(client_fd);
	
	gettimeofday(&endtotal,NULL);
	time_use=(endtotal.tv_sec-starttotal.tv_sec)*1000+(endtotal.tv_usec-starttotal.tv_usec)/1000;//微秒
	logDebug((*(info->log)), "app_thread_process function need  %.6f ms seq=%d sndtotalcnt=%d\n",
		time_use, seq, resetInfo.sndtotalcnt);


	delete (StSockInfo *)fd;
    // logDebug(*(info->log)), "app_thread_process function need  %.6f ms seq=%d\n",time_use, seq);
    return NULL;
}
#endif

void daemonize()
{
	pid_t pid;
	int x;

	pid = fork();

	if (pid < 0) 
	{
		exit(EXIT_FAILURE);
	}

	if (pid > 0) 
	{
		exit(EXIT_SUCCESS);
	}

	if (setsid() < 0) 
	{
		exit(EXIT_FAILURE);
	}

	signal(SIGCHLD, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	pid = fork();

	if (pid < 0) 
	{
		exit(EXIT_FAILURE);
	}

	if (pid > 0) 
	{
		exit(EXIT_SUCCESS);
	}

	umask(0);
	int res = chdir("/");
	if(-1 == res)
	{
		std::cout<<"error"<<std::endl;
	}

	for (x = sysconf(_SC_OPEN_MAX); x >= 0; x--) 
	{
		close(x);
	}
}

void usage(char *app, CLog &log)
{
	logDebug(log, "USAGE: %s [-h][-n PORT][-a AUTHTYPE][-u USERNAME][-p PASSWORD][-l LOGFILE]\n", app);
	logDebug(log, "AUTHTYPE: 0 for NOAUTH, 2 for USERPASS\n");
	logDebug(log, "By default: port is 1080, authtype is no auth, logfile is stdout\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	
	char *tmp = getcwd(abs_path_buff, 256);
	if (tmp == NULL)
	{
		
	}
	std::cout << "path=" << abs_path_buff << std::endl;
	int ret;
	string str = abs_path_buff;
	str += "/";
	str+="server";
	CLog log(str.c_str());
	if(log.init(CLOG_DEBUG) < 0)
	{
		fprintf(stderr, "init log faild.\n");
	}

	logDebug(log, "test");

	// int fd;
	

	// fd = socket(AF_INET, SOCK_STREAM, 0);

	// struct ifreq interface;
	// // string str = resetInfo.getnic();
	// string str = "wwan4";
	// // CConnInfo conn = connData.GetConnInfo();
	
	// // if (conn.strNic == "")
	// if (str == "")
	// {
	// 	logDebug(log, "dont have nic");
	// 	close(fd);
	// 	return -1;
	// }


	// // cout << "get nic name =" << str << " connect ip=" << address << " portnum=" << portnum <<  endl;
	// // snprintf(interface.ifr_ifrn.ifrn_name, sizeof(interface.ifr_ifrn.ifrn_name),
	// // 	"%s", conn.strNic.c_str());
	// strncpy(interface.ifr_ifrn.ifrn_name, str.c_str(), str.size());
	// if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&interface, sizeof(interface))  < 0) 
	// {
	// 	perror("SO_BINDTODEVICE failed 1");
	// }
	// else
	// {
	// 	std::cout << "bind succeed" << std::endl;
	// }
	// // log_message("connect() in before connect");
	// // if (connect(fd, (struct sockaddr *)&remote, sizeof(remote)) < 0) 
	
	// return 0;
		// return conn.sock;
	


	// return 0;
	

	// GetModemInfo(log);
	// for (auto str:connserver.vecstr)
	// {
	// 	resetnicinfo(log, str.idx, str.strnic);
	// }
	
	// return 0;
	// sndtotalcnt = 0;


	str = abs_path_buff;
	str += "/";
	str+="nicresetlog";
	nicresetlog.setname(str.c_str());
	if(nicresetlog.init(CLOG_DEBUG) < 0)
	{
		fprintf(stderr, "init log faild.\n");
	}

	str = abs_path_buff;
	str += "/";
	str+="connproxysrv";
	connproxysrvlog.setname(str.c_str());
	if(connproxysrvlog.init(CLOG_DEBUG) < 0)
	{
		fprintf(stderr, "init log faild.\n");
	}

	str = abs_path_buff;
	str += "/";
	str+="workerThreadlog";
	workerThreadlog.setname(str.c_str());
	if(workerThreadlog.init(CLOG_DEBUG) < 0)
	{
		fprintf(stderr, "init log faild.\n");
	}

		//创建epoll事件
	

	// int tmpdata = 256;
	// logDebug(log, "ret=%d", tmpdata>>8);
	// return 0;
	
	//自定义排序，按身高降序，身高相同时则按名字升序排列

	// for (auto &data:connserver.vecstr)
	// {
	// 	logDebug(log, "str=%s idx=%d iscanused=%d currentcnt=%d", data.strnic.c_str(), data.idx, data.iscanused,
	// 		data.currentcnt);
	// }
	
	log_file = stdout;
	auth_type = NOAUTH;
	arg_username = (char *)"user";
	arg_password = (char *)"pass";
	
	// pthread_mutex_init(&niclock, NULL);

	signal(SIGPIPE, SIG_IGN);
	
	while ((ret = getopt(argc, argv, "n:u:p:l:a:hd")) != -1) 
	{
		switch (ret) 
		{
		case 'd':{
				daemon_mode = 1;
				daemonize();
				break;
			}
		case 'n':{
				port = atoi(optarg) & 0xffff;
				break;
			}
		case 'u':{
				arg_username = strdup(optarg);
				break;
			}
		case 'p':{
				arg_password = strdup(optarg);
				break;
			}
		case 'l':{
				FILE *tmp = freopen(optarg, "wa", log_file);
				if(NULL == tmp)
                {
                    std::cout<<"error"<<std::endl;
                }
				break;
			}
		case 'a':{
				auth_type = atoi(optarg);
				break;
			}
		case 'h':
		default:
			usage(argv[0], log);
		}
	}
	// log_message("Starting with authtype 11 %X", auth_type);
	if (auth_type != NOAUTH) 
	{
		logError(log, "Username is %s, password is %s", arg_username,
			    arg_password);
	}

	// managerconnthd(log);
	// std::thread* thrd = nullptr;
	// for (int i=0; i<10; i++)
	// {
	// 	thrd = new (std::nothrow) std::thread(connproxysrvthd);
	// 	// std::thread t1(connproxysrvthd);
	// }

	// for (int i=0; i<10; i++)
	// {
	// 	thrd = new (std::nothrow) std::thread(resetnicthd);
	// 	// std::thread t1(connproxysrvthd);
	// }

	// std::thread t2(managerconnthd);
	// struct timeval start;
    // struct timeval end;
	
	// gettimeofday(&start,NULL); //gettimeofday(&start,&tz);结果一样
	// GetModemInfo(log);
	
	// float time_use=0;
	
	// for (auto &data:connserver.vecstr)
	// {
	// 	logDebug(log, "str=%s idx=%d iscanused=%d currentcnt=%d strip=%s", 
	// 		data.strnic.c_str(), data.idx, data.iscanused, data.currentcnt,
	// 		data.strip.c_str());
	// }

	// gettimeofday(&end,NULL); //gettimeofday(&start,&tz);结果一样
	// time_use=(end.tv_sec-start.tv_sec)*1000+(end.tv_usec-start.tv_usec)/1000;//微秒
    // logDebug(log, "GetModemInfo  need  %.6f ms\n",time_use);
	// for (auto &data:connserver.vecstr)
	// {
	// 	resetnicinfo(log, data.idx, data.strnic.c_str());
	// }

	// // 
	// return 0;
	g_server.SetLog();
	g_server.run(port);
	// app_loop(log);
	
}

