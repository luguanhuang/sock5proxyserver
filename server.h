#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <string>
#include <unordered_map>

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
#include "threadpool.h"
#include "sock5proxy.h"

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

extern char abs_path_buff[256];

class server {
 public:
  // ThreadPool *pool;  // 弄4个线程
  std::mutex fdmapmutex;

  enum Socks5State {
    AUTH,           // 未授权
    ESTABLISHMENT,  // 建立连接
    FORWARDING,     // 转发
  };
  struct Connect {
    Socks5State state;
    int clientfd;
    int serverfd;
    time_t updatetime;
    Connect() : state(AUTH), clientfd(-1), serverfd(-1), updatetime(time(NULL)) {}
  };
  static constexpr int MAX_EPOLL_EVENTS = 1024;
  ThreadPool1 threadpool;
  ThreadPool1 resetpool;
  CConnectServer connserver;
  int listenfd;
  int epollfd;
  int port;
  std::string username, password;
  uint8_t authmethod;
  std::unordered_map<int, Connect*> fdmap;
  CLog log;//("proclimsg");
  bool setNonBlocking(int fd);
  bool addIntoEpoll(int fd, void* ptr);
  bool delFromEpoll(int fd);
  void forever();
  void newConnect(int fd);
  void resetnic();
  int GetModemInfo();
  static bool compareByNic(StNicInfo nic1,StNicInfo nic2);
  int Getdx(const string str);
  // int AcceptConn();
  void AcceptConn();
  // StNicInfo nicInfo;
  void SetLog()
  {
    // // log.setname
    if (log.init(CLOG_DEBUG) < 0)
    {
      fprintf(stderr, "init log faild.\n");
    }

    string str = abs_path_buff;
    str += "/";
    str+="proclimsg";
    
    log.setname(str.c_str());
  }
  void delConnect(int fd);
  void eventHandle(int fd);
  void authHandle(int fd);
  void establishmentHandle(int fd);
  void forwardingHandle(int fd);
  void getnicip();
  int UpModemInfo(string strNic);
  void TimeoutThd();

  void ResetNoIPmodemThd();
  
  int UpAllModemInfo();

 public:

  server():threadpool(350), resetpool(1)
  {
    epollfd = epoll_create1(0);
    if (epollfd < 0) 
    {
    std::cout << "create epollfd fail" << std::endl;	
    }

  }
  ~server() {}
  // void run(int port);
  void run(int);
};