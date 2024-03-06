#include "server.h"

#include <deque>
#include <mutex>
#include <string>
#include <algorithm> 
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
#include <sys/time.h>
#include <sstream>
#include <thread>
#include <queue>
#include "sock5proxy.h"

bool server::setNonBlocking(int fd) 
{
  //将套接字设置为非阻塞
  int flag = fcntl(fd, F_GETFL, 0);
  flag |= O_NONBLOCK;
  return fcntl(fd, F_SETFL, flag) != -1;
}
bool server::addIntoEpoll(int fd, void* ptr) 
{
  //将套接字加入epoll
    // setNonBlocking(fd);
  struct epoll_event event;
  event.data.ptr = ptr;
  event.data.fd = fd;
  event.events = EPOLLIN | EPOLLET;
  // event.events = EPOLLIN;
  return epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event) != -1;
}

bool server::delFromEpoll(int fd) 
{
  //将套接字从epoll中删除
  struct epoll_event event;
  event.data.fd = fd;
  event.events = 0;
  return epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, &event) != -1;
}

void server::newConnect(int fd) 
{
    addIntoEpoll(fd, NULL);
    Connect* con = new Connect();
    con->state = AUTH;
    con->clientfd = fd;
    con->updatetime = time(NULL);
    std::unique_lock<std::mutex> locker(fdmapmutex);
    fdmap[fd] = con;
}

void server::delConnect(int fd) 
{
  //删除已有链接
  //某一方关闭后，将其端口置为-1
  //两个都为-1，说明转发结束
  
  std::unique_lock<std::mutex> locker(fdmapmutex);
  auto it = fdmap.find(fd);
  if (it != fdmap.end()) 
  {
    Connect* con = it->second;
    if (con)
    {
      delFromEpoll(con->clientfd);
      delFromEpoll(con->serverfd);
      close(con->clientfd);
      close(con->serverfd);
      

      auto cliit = fdmap.find(con->clientfd);
      if (cliit != fdmap.end()) 
        fdmap.erase(cliit);

      auto srvit = fdmap.find(con->serverfd);
      if (srvit != fdmap.end()) 
        fdmap.erase(srvit);

      delete con;
    }
  }
}

void server::eventHandle(int fd) 
{
  std::unique_lock<std::mutex> locker(fdmapmutex);
  auto it = fdmap.find(fd);
  if (it == fdmap.end()) 
    return;
  Connect* con = it->second;
  Socks5State state= con->state;
  locker.unlock();
  
  if (state == AUTH) 
  {
    // logDebug(log, "AUTH");
    authHandle(fd);
  } 
  else if (state == ESTABLISHMENT) 
  {
    // logDebug(log, "ESTABLISHMENT");
    establishmentHandle(fd);
  } 
  else if (state == FORWARDING) 
  {
    // logDebug(log, "FORWARDING");
    forwardingHandle(fd);
  } 
}

void server::authHandle(int fd) {
    
  constexpr int BUFF_SIZE = 1024;
  uint8_t buf[BUFF_SIZE];
  int len = recv(fd, buf, BUFF_SIZE, MSG_PEEK);
   if (len <= 0) 
   {
    
    delConnect(fd);
    logDebug(log, "authHandle: recv len=%d will call delConnect err=%s fd=%d", len, strerror(errno),
      fd);
    return;
  } else if (len < 3) 
  {
    logError(log, "authHandle: error data len=%d", len);
    return;
  } 
  else 
  {
    if (buf[0] == 0x05 && len == 2 + buf[1]) 
    {
      len = recv(fd, buf, 2 + buf[1], 0);
      if (len <= 0) 
      {
          logDebug(log, "authHandle: recv len=%d will call delConnect err=%s fd=%d", len, strerror(errno),
            fd);
          delConnect(fd);
          return;
        } 

      if (authmethod == 0x00)  // NO AUTH模式
      {
        // std::cout << "NO AUTH" << std::endl;
       std::unique_lock<std::mutex> locker(fdmapmutex);
        auto it = fdmap.find(fd);
        if (it != fdmap.end()) 
        {
          Connect* con = it->second;
          con->state = ESTABLISHMENT;
          con->updatetime = time(NULL);
        }

        locker.unlock();
      }
      uint8_t reply[2] = {0x05, authmethod};
      len = send(fd, reply, 2, 0);
      if (len <= 0) 
      {
          logDebug(log, "authHandle: len=%d will call delConnect err=%s fd=%d", len, strerror(errno), fd);
          delConnect(fd);
          return;
        } 
      return;
    }
    if (authmethod == 0x02 && buf[0] == 0x01) 
    {
      if (len < 3 + buf[1])  // 1+1+username+1
        return;
      if (len < 3 + buf[1] + buf[2 + buf[1]])  // 1+1+username+1+password
        return;
      recv(fd, buf, 3 + buf[1] + buf[2 + buf[1]], 0);
      std::string cusername((char*)buf + 2, (char*)buf + 2 + buf[1]);
      std::string cpassword((char*)buf + 2 + buf[1],
                            (char*)3 + buf[1] + buf[2 + buf[1]]);
      uint8_t authstate = 0x01;
      if (username == cusername && password == cpassword) {
        auto it = fdmap.find(fd);
        if (it != fdmap.end()) {
          Connect* con = it->second;
          con->state = ESTABLISHMENT;
          con->updatetime = time(NULL);
        }
        authstate = 0x00;
      }
      uint8_t reply[2] = {0x01, authstate};
      send(fd, reply, 2, 0);
      return;
    }
  }
}

int server::GetModemInfo()
{
	FILE *fp1 = NULL;
	char buf[2560];
	char cmd[256];
	// logDebug(log, "GetModemInfo: func begn");
	snprintf(cmd, sizeof(cmd), "mmcli -L");
	if ((fp1 = popen(cmd, "r")) == NULL)
	{
		logError(log, "authHandle: popen fail\n");
		return -1;
	}

	connserver.vecstr.clear();
	std::vector<std::string> strResult;
	while (fgets(buf, sizeof(buf), fp1) != NULL)
	{
		char *pos = strstr(buf, "\r");
		if (pos)
			*pos = '\0';
		pos = strstr(buf, "\n");
		if (pos)
			*pos = '\0';
		
		string str = buf;
		str.erase(str.begin(), std::find_if(str.begin(), str.end(),
		std::not1(std::ptr_fun(::isspace))));
		
		int idx = Getdx(str);
		// logDebug(log, "str=[%s] idx=%d\n", str.c_str(), idx);
		
		FILE *fp2 = NULL;
		snprintf(cmd, sizeof(cmd), "mmcli -m %d", idx);
		if ((fp2 = popen(cmd, "r")) == NULL)
		{
			logError(log, "authHandle: popen fail\n");
		}

		// log_message("GetModemInfo cmd=%s\n", cmd);

		// cout << "cmd=" << cmd << endl;
		while (fgets(buf, sizeof(buf), fp2) != NULL)
		{
      // logDebug(log, "buf=%s", buf);
			char *pos = strstr(buf, "\r");
			if (pos)
				*pos = '\0';

			pos = strstr(buf, "\n");
			if (pos)
				*pos = '\0';
		
			str = buf;
			str.erase(str.begin(), std::find_if(str.begin(), str.end(),
			std::not1(std::ptr_fun(::isspace))));
			
			std::vector<string> value;
			char* s_input = (char*)str.c_str();
			char* split = (char*)",";// 以分号为分隔符拆分字符串
			char* ptr = NULL;
			char* p = strtok_r(s_input, split, &ptr);
			string strres = "";
			while (p != NULL)
			{
				value.push_back(p);
				
				p = strtok_r(NULL, split, &ptr);
			}

			vector<string>::reverse_iterator it = value.rbegin();
			split = (char*)" ";// 以分号为分隔符拆分字符串
			ptr = NULL;
			
			s_input = (char*)(*it).c_str();
			p = strtok_r(s_input, split, &ptr);
			strres = "";
			while (p != NULL)
			{
				strres = p;
				break;
			}
			
			// if (NULL != strstr(strres.c_str(), "wwan"))
      // logDebug(log, "strres=%s", strres.c_str());
      if (NULL != strstr(strres.c_str(), "wwan") && strstr(strres.c_str(), "_") == NULL)
			{
				// logDebug(log, "str=%s idx=%d", strres.c_str(), idx);
				FILE *fp3 = NULL;
				
				snprintf(cmd, sizeof(cmd), "ifconfig |grep %s",strres.c_str());
				if ((fp3 = popen(cmd, "r")) != NULL)
				{
					
					// logDebug(log, "popen fail\n");
					// continue;
					// return -1;
					if (fgets(buf, sizeof(buf), fp3) == NULL)
					{
						snprintf(cmd, sizeof(cmd), "ifconfig %s up", strres.c_str());
						int ret = system(cmd);
						logDebug(log, "cmd=%s ret=%d", cmd, ret);
						if (0 != ret)
						{
							logError(log, "Excute shell cmd[%s] failed, return:%d.", cmd, ret>>8);
							// return 0;
						}
						else
						{
							StNicInfo stNicInfo(strres, idx);
							connserver.vecstr.push_back(stNicInfo);
						}
					}
					else
					{
						StNicInfo stNicInfo(strres, idx);
						connserver.vecstr.push_back(stNicInfo);
					}
				
					pclose(fp3);
				}
			}
		}

		pclose(fp2);
	}

	pclose(fp1);
	for (auto &data:connserver.vecstr)
	{
		snprintf(cmd, sizeof(cmd), "ifconfig %s|grep inet|grep -v 127.0.0.1|grep -v inet6|awk '{print $2}'|tr -d \"addr:\"",
		data.strnic.c_str());
		if ((fp1 = popen(cmd, "r")) == NULL)
		{
			logError(log, "popen fail\n");
			continue;
			// return -1;
		}
		if (fgets(buf, sizeof(buf), fp1) != NULL)
		{
			// logDebug(log, "%s network restart succeed", data.strnic.c_str());
			// pthread_mutex_lock(&niclock);
			data.strip = buf;
			data.enable();
			// pthread_mutex_unlock(&niclock);
		}

		pclose(fp1);
	}

	// for (auto data:vecTmp)
	// {
	// 	for (auto &inf:connserver.vecstr)
	// 	{
	// 		if (inf.strnic == data.strnic && inf.strip == data.strip)
	// 		{
	// 			data.disable();
	// 			break;
	// 		}
	// 	}
	// }

	//自定义排序，按身高降序，身高相同时则按名字升序排列
    std::sort(connserver.vecstr.begin(),connserver.vecstr.end(),compareByNic);
	
	// for (auto &data:connserver.vecstr)
	// {
	// 	logDebug(log, "str=%s idx=%d iscanused=%d currentcnt=%d strip=%s", 
	// 		data.strnic.c_str(), data.idx, data.iscanused, data.currentcnt,
	// 		data.strip.c_str());
	// }
	
	return 0;
}

int server::Getdx(const string str)
{
	 std::vector<string>value;
    char* s_input = (char*)str.c_str();
	char* split = (char*)" ";// 以分号为分隔符拆分字符串
	char* ptr = NULL;
	char* p = strtok_r(s_input, split, &ptr);
	string strres = "";
	while (p != NULL)
	{
		// value.push_back(p);
		// cout << "p=" << p << endl;
		strres = p;
		break;
		// p = strtok_r(NULL, split, &ptr);
	}

	split = (char*)"/";
	p = strtok_r(s_input, split, &ptr);
	while (p != NULL)
	{
		value.push_back(p);
		
		// break;
		p = strtok_r(NULL, split, &ptr);
	}


	vector<string>::reverse_iterator it = value.rbegin();
	// cout << "p=" << *it << endl;
	return atoi((*it).c_str());
}

int server::UpAllModemInfo()
{
	FILE *fp1 = NULL;
	char buf[2560];
	char cmd[256];
	// logDebug(log, "GetModemInfo: func begn");
	snprintf(cmd, sizeof(cmd), "mmcli -L");
	if ((fp1 = popen(cmd, "r")) == NULL)
	{
		logError(log, "popen fail\n");
		return -1;
	}

	// connserver.vecstr.clear();
	std::vector<std::string> strResult;
	while (fgets(buf, sizeof(buf), fp1) != NULL)
	{
		char *pos = strstr(buf, "\r");
		if (pos)
			*pos = '\0';
		pos = strstr(buf, "\n");
		if (pos)
			*pos = '\0';
		
		string str = buf;
		str.erase(str.begin(), std::find_if(str.begin(), str.end(),
		std::not1(std::ptr_fun(::isspace))));
		
		int idx = Getdx(str);
		// printf("main: str=[%s] idx=%d\n", str.c_str(), idx);
		// char buf[2560];
		
		FILE *fp2 = NULL;
		snprintf(cmd, sizeof(cmd), "mmcli -m %d", idx);
		if ((fp2 = popen(cmd, "r")) == NULL)
		{
			logError(log, "popen fail\n");
		}

		// log_message("GetModemInfo cmd=%s\n", cmd);

		// cout << "cmd=" << cmd << endl;
		while (fgets(buf, sizeof(buf), fp2) != NULL)
		{
			char *pos = strstr(buf, "\r");
			if (pos)
				*pos = '\0';

			pos = strstr(buf, "\n");
			if (pos)
				*pos = '\0';
		
			str = buf;
			str.erase(str.begin(), std::find_if(str.begin(), str.end(),
			std::not1(std::ptr_fun(::isspace))));
			
			std::vector<string> value;
			char* s_input = (char*)str.c_str();
			char* split = (char*)",";// 以分号为分隔符拆分字符串
			char* ptr = NULL;
			char* p = strtok_r(s_input, split, &ptr);
			string strres = "";
			while (p != NULL)
			{
				value.push_back(p);
				
				p = strtok_r(NULL, split, &ptr);
			}

			vector<string>::reverse_iterator it = value.rbegin();
			split = (char*)" ";// 以分号为分隔符拆分字符串
			ptr = NULL;
			
			s_input = (char*)(*it).c_str();
			p = strtok_r(s_input, split, &ptr);
			strres = "";
			while (p != NULL)
			{
				strres = p;
				break;
			}
			
			if (NULL != strstr(strres.c_str(), "wwan"))
			{
				// logDebug(log, "str=%s idx=%d", strres.c_str(), idx);
				FILE *fp3 = NULL;
				
				snprintf(cmd, sizeof(cmd), "ifconfig |grep %s",strres.c_str());
				if ((fp3 = popen(cmd, "r")) != NULL)
				{
					
					// logDebug(log, "popen fail\n");
					// continue;
					// return -1;
          // auto resiter = connserver.vecstr.find(strres);
          bool isfind = false;
					if (fgets(buf, sizeof(buf), fp3) == NULL)
					{
						snprintf(cmd, sizeof(cmd), "ifconfig %s up", strres.c_str());
						int ret = system(cmd);
						logDebug(log, "cmd=%s ret=%d", cmd, ret);
						if (0 != ret)
						{
							logError(log, "Excute shell cmd[%s] failed, return:%d.", cmd, ret>>8);
							// return 0;
						}
						else
						{
              std::unique_lock<std::mutex> niclocker(connserver.nicmutex);
              for (auto &destdata:connserver.vecstr)
              {
                  if (destdata.strnic == strres)
                  {
                    destdata.idx = idx;
                    destdata.disable();
                    isfind = true; 
                    break;
                  }
              }

              if (isfind == false)
              {
                StNicInfo stNicInfo(strres, idx);
                connserver.vecstr.push_back(stNicInfo);
              }

              niclocker.unlock() ;
						}
					}
					else
					{
            std::unique_lock<std::mutex> niclocker(connserver.nicmutex);
            for (auto &destdata:connserver.vecstr)
            {
                if (destdata.strnic == strres)
                {
                  destdata.idx = idx;
                  destdata.disable();
                  isfind = true; 
                  break;
                }
            }

            if (isfind == false)
            {
              StNicInfo stNicInfo(strres, idx);
              connserver.vecstr.push_back(stNicInfo);
            }
            niclocker.unlock();
						// StNicInfo stNicInfo(strres, idx);
            // for (auto &destdata:connserver.vecstr)
            // {
            //     if (destdata.strnic == strres)
            //     {
            //       break;
            //     }
            // }
						// connserver.vecstr.push_back(stNicInfo);
					}
				
					pclose(fp3);
				}
			}
		}

		pclose(fp2);
	}

	pclose(fp1);
   std::unique_lock<std::mutex> niclocker(connserver.nicmutex);
	for (auto &data:connserver.vecstr)
	{
		snprintf(cmd, sizeof(cmd), "ifconfig %s|grep inet|grep -v 127.0.0.1|grep -v inet6|awk '{print $2}'|tr -d \"addr:\"",
		data.strnic.c_str());
		if ((fp1 = popen(cmd, "r")) == NULL)
		{
			logError(log, "popen fail\n");
			continue;
			// return -1;
		}
		if (fgets(buf, sizeof(buf), fp1) != NULL)
		{
			// logDebug(log, "%s network restart succeed", data.strnic.c_str());
			// pthread_mutex_lock(&niclock);
			data.strip = buf;
			data.enable();
			// pthread_mutex_unlock(&niclock);
		}
    
		pclose(fp1);
	}
 niclocker.unlock();
	// for (auto data:vecTmp)
	// {
	// 	for (auto &inf:connserver.vecstr)
	// 	{
	// 		if (inf.strnic == data.strnic && inf.strip == data.strip)
	// 		{
	// 			data.disable();
	// 			break;
	// 		}
	// 	}
	// }

	//自定义排序，按身高降序，身高相同时则按名字升序排列
    std::sort(connserver.vecstr.begin(),connserver.vecstr.end(),compareByNic);
	
	// for (auto &data:connserver.vecstr)
	// {
	// 	logDebug(log, "str=%s idx=%d iscanused=%d currentcnt=%d strip=%s", 
	// 		data.strnic.c_str(), data.idx, data.iscanused, data.currentcnt,
	// 		data.strip.c_str());
	// }
	
	return 0;
}

int server::UpModemInfo(string strNic)
{
	FILE *fp1 = NULL;
	char buf[2560];
	char cmd[256];
	snprintf(cmd, sizeof(cmd), "mmcli -L");
	if ((fp1 = popen(cmd, "r")) == NULL)
	{
		logError(log, "popen fail\n");
		return -1;
	}
	
	// connserver.vecstr.clear();
	std::vector<std::string> strResult;
   bool isfind = false;
   int idx = 0;
	while (fgets(buf, sizeof(buf), fp1) != NULL)
	{
		char *pos = strstr(buf, "\r");
		if (pos)
			*pos = '\0';
		pos = strstr(buf, "\n");
		if (pos)
			*pos = '\0';
		
		string str = buf;
		str.erase(str.begin(), std::find_if(str.begin(), str.end(),
		std::not1(std::ptr_fun(::isspace))));
		
		idx = Getdx(str);
		// printf("str=[%s] idx=%d\n", str.c_str(), idx);
		
		FILE *fp2 = NULL;
		snprintf(cmd, sizeof(cmd), "mmcli -m %d", idx);
		if ((fp2 = popen(cmd, "r")) == NULL)
		{
			logError(log, "popen fail\n");
      	pclose(fp1);
      return -1;
		}

		while (fgets(buf, sizeof(buf), fp2) != NULL)
		{
			char *pos = strstr(buf, "\r");
			if (pos)
				*pos = '\0';

			pos = strstr(buf, "\n");
			if (pos)
				*pos = '\0';
		
			str = buf;
			str.erase(str.begin(), std::find_if(str.begin(), str.end(),
			std::not1(std::ptr_fun(::isspace))));
			
			std::vector<string> value;
			char* s_input = (char*)str.c_str();
			char* split = (char*)",";// 以分号为分隔符拆分字符串
			char* ptr = NULL;
			char* p = strtok_r(s_input, split, &ptr);
			string strres = "";
			while (p != NULL)
			{
				value.push_back(p);
				
				p = strtok_r(NULL, split, &ptr);
			}

			vector<string>::reverse_iterator it = value.rbegin();
			split = (char*)" ";// 以分号为分隔符拆分字符串
			ptr = NULL;
			
			s_input = (char*)(*it).c_str();
			p = strtok_r(s_input, split, &ptr);
			strres = "";
			while (p != NULL)
			{
				strres = p;
				break;
			}
			
			// if (NULL != strstr(strres.c_str(), "wwan"))
      if (NULL != strstr(strres.c_str(), strNic.c_str()))
			{
				// logDebug(log, "str=%s idx=%d", strres.c_str(), idx);
				FILE *fp3 = NULL;
				
				snprintf(cmd, sizeof(cmd), "ifconfig |grep %s",strres.c_str());
				if ((fp3 = popen(cmd, "r")) != NULL)
				{
					if (fgets(buf, sizeof(buf), fp3) == NULL)
					{
						snprintf(cmd, sizeof(cmd), "ifconfig %s up", strres.c_str());
						int ret = system(cmd);
						logDebug(log, "cmd=%s ret=%d", cmd, ret);
						if (0 != ret)
						{
							logError(log, "Excute shell cmd[%s] failed, return:%d.", cmd, ret>>8);
              pclose(fp1);
              pclose(fp2);
							return -1;
						}
						else
						{
							// StNicInfo stNicInfo(strres, idx);
							// connserver.vecstr.push_back(stNicInfo);
              isfind = true;
              break;
						}
					}
					else
					{
						// StNicInfo stNicInfo(strres, idx);
						// connserver.vecstr.push_back(stNicInfo);
            isfind = true;
            break;
					}
				
					pclose(fp3);
				}
			}
		}

   
		pclose(fp2);
     if (isfind == true)
      break;
	}

	pclose(fp1);
  if (false == isfind)
    return -1;

  std::unique_lock<std::mutex> niclocker(connserver.nicmutex);
	for (auto &data:connserver.vecstr)
	{
      if (data.strnic == strNic)
      {
        snprintf(cmd, sizeof(cmd), "ifconfig %s|grep inet|grep -v 127.0.0.1|grep -v inet6|awk '{print $2}'|tr -d \"addr:\"",
      data.strnic.c_str());
      if ((fp1 = popen(cmd, "r")) == NULL)
      {
        logError(log, "popen fail\n");
        niclocker.unlock();
        return -1;
      }
      if (fgets(buf, 256, fp1) != NULL)
      {
        logDebug(log, "%s update idx=%d ip=%s", data.strnic.c_str(), idx, buf);
        // pthread_mutex_lock(&niclock);
        data.strip = buf;
        data.idx = idx;
        data.enable();
        niclocker.unlock();
        	pclose(fp1);
        return 0;
        // pthread_mutex_unlock(&niclock);
      }

      pclose(fp1);
      niclocker.unlock();
      return -1;
    }
	}
	niclocker.unlock();
	return -1;
}

void server::establishmentHandle(int fd) {
  constexpr int BUFF_SIZE = 1024;
  uint8_t buf[BUFF_SIZE];
  int len = recv(fd, buf, BUFF_SIZE, MSG_PEEK);
  // logDebug(log, "establishmentHandle recv=%d", len);
  if (len <= 0) 
  {
    logDebug(log, "establishmentHandle recv=%d will call delConnect err=%s fd=%d", len, strerror(errno), fd);
    delConnect(fd);
    return;
  } 
  else if (len < 10) 
  {
    return;
  } 
  else 
  {
    if (buf[0] == 0x05) 
    {
      if (buf[1] == 0x01)  // CMD为Connect
      {
        // uint8_t addtype = buf[3];
        uint8_t ip[4];
        uint8_t port[2];
        uint8_t addlen;
        // if (addtype == 0x01)  // IPV4
        // {
        
        // } 
        
          addlen = 4;
          if (len < 6 + addlen) {
            return;
          }
          memcpy(ip, buf + 4, addlen);
          memcpy(port, buf + 4 + addlen, 2);
          len = recv(fd, buf, 6 + addlen, 0);
          if (len <= 0)
          {
            logError(log, "establishmentHandle len=%d will call delConnect err=%s fd=%d", len, strerror(errno), fd);
            delConnect(fd);
            return;
          }

        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        memcpy(&server_addr.sin_addr.s_addr, ip, 4);
        server_addr.sin_port = *((uint16_t*)port);

        uint8_t reply[10];
        memset(reply, 0, sizeof(reply));
        int serverfd = socket(PF_INET, SOCK_STREAM, 0);
        // struct ifreq interface;
        struct timeval start;
        struct timeval end;

        // logDebug(log, "we use wwan0 to send data");
        
        StNicInfo &nicInfo = connserver.getNicInfo();
        if (nicInfo.isenable())
        {
          string strnic = nicInfo.strnic;
            if (setsockopt(serverfd, SOL_SOCKET, SO_BINDTODEVICE, nicInfo.strnic.c_str(), nicInfo.strnic.size()+1)  < 0) 
            {
              logError(log, "SO_BINDTODEVICE failed");
            }

            // logDebug(log, "establishmentHandle strnic=%s", nicInfo.strnic.c_str());

          
            float time_use=0;

            gettimeofday(&start,NULL); //gettimeofday(&start,&tz);结果一样
            // int ret = connect_timeout(log, serverfd, (struct sockaddr *)&server_addr, sizeof(server_addr), &tm);
            int ret = connect_timeout(log, serverfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
            gettimeofday(&end,NULL); //gettimeofday(&start,&tz);结果一样
            time_use=(end.tv_sec-start.tv_sec)*1000+(end.tv_usec-start.tv_usec)/1000;//微秒
            logDebug(log, "connect_timeout  need  %.6f ms name=%s\n",time_use, nicInfo.strnic.c_str());
            if (ret < 0) 
            {
              logError(log, "call connect_timeout  error will call delConnect err=%s fd=%d\n", strerror(errno), fd);
              connserver.UadateConnFailInfo(log, strnic);
              reply[1] = 0x01;
               reply[0] = 0x05;
              reply[3] = 0x01;
              send(fd, reply, 10, 0);
              delConnect(fd);
            } 
            else 
            {
              // logDebug(log, "connect_timeout  need 111  %.6f ms name=%s\n",time_use, nicInfo.strnic.c_str());
                std::unique_lock<std::mutex> locker(fdmapmutex);
                auto it = fdmap.find(fd);
                if (it != fdmap.end()) {
                  // logDebug(log, "connect_timeout  need 222  %.6f ms name=%s\n",time_use, nicInfo.strnic.c_str());
                Connect* con = it->second;
                con->state = FORWARDING;
                con->serverfd = serverfd;
                con->updatetime = time(NULL);
                fdmap[serverfd] = con;
                }
                // logDebug(log, "connect_timeout  need 33  %.6f ms name=%s\n",time_use, nicInfo.strnic.c_str());
                locker.unlock();
                // logDebug(log, "connect_timeout  need 44  %.6f ms name=%s\n",time_use, nicInfo.strnic.c_str());
                addIntoEpoll(serverfd, NULL);
                reply[0] = 0x05;
                reply[3] = 0x01;
                // logDebug(log, "connect_timeout  need 555  %.6f ms name=%s\n",time_use, nicInfo.strnic.c_str());
                len = send(fd, reply, 10, 0);
                // logDebug(log, "after connect send len=%d", len);
                if (len <= 0)
                {
                  // logDebug(log, "connect_timeout send need  %.6f ms name=%s will call delConnect\n",time_use, nicInfo.strnic.c_str());
                  logDebug(log, "send len=%d will call delConnect err=%s fd=%d", len, strerror(errno), fd);
                  delConnect(fd);
                }
                // logDebug(log, "connect_timeout  need 777  %.6f ms name=%s\n",time_use, nicInfo.strnic.c_str());
            }
        }
        else
        {
          logError(log, "dont have nic will call delConnect err=%s fd=%d", strerror(errno), fd);
          reply[1] = 0x01;
          reply[0] = 0x05;
          reply[3] = 0x01;
          send(fd, reply, 10, 0);
          delConnect(fd);
        }
      } 
      else 
      {
        // TODO
      }
    }
  }
}

void server::forwardingHandle(int fd) {
    std::unique_lock<std::mutex> locker(fdmapmutex);
  auto it = fdmap.find(fd);
  int sendfd;
  if (it != fdmap.end()) 
  {
    Connect* con = it->second;
    if (fd == con->clientfd) 
    {
      sendfd = con->serverfd;
    } else 
    {
      sendfd = con->clientfd;
    }

    con->updatetime = time(NULL);

    locker.unlock();
    constexpr int BUFF_SIZE = 1024 * 10;
    uint8_t buf[BUFF_SIZE];
    int len = recv(fd, buf, BUFF_SIZE, 0);
  if (len <= 0) 
  {
      logDebug(log, "forwardingHandle: recv len=%d will call delConnect err=%s fd=%d", len, strerror(errno), fd);
      delConnect(fd);
      return;
    } else 
    {
      len = send(sendfd, buf, len, 0);
      if (len <= 0) 
      {
        logDebug(log, "forwardingHandle: send len=%d will call delConnect err=%s fd=%d", len, strerror(errno), fd);
        delConnect(fd);
      }
    }
  }
}

bool server::compareByNic(StNicInfo nic1,StNicInfo nic2)
{
	if (nic1.strnic.length() == nic2.strnic.length())
    	return nic1.strnic < nic2.strnic;
	else if (nic1.strnic.length() < nic2.strnic.length())
	{
		return true;
	}
	else
	{
		return false;
	}
}

void server::run(int port) 
{
  logDebug(log, "socks5server is starting at port %d", port);
  // GetModemInfo();
  //创建监听套接字
  listenfd = socket(AF_INET, SOCK_STREAM, 0);
  // listenfd = socket(PF_INET, SOCK_STREAM, 0);
  if (listenfd == -1) 
  {
    logDebug(log, "create listenfd fail %d", port);
    
    return;
  }

  // setNonBlocking(listenfd);

  //设置监听地址为 0.0.0.0:port
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  int optval = 1;
  if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval,sizeof(optval)) < 0) 
	{
		logError(log, "setsockopt()");
		exit(1);
	}

  //绑定套接字到端口
  if (bind(listenfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) 
  {
    // std::cout << "bind fail" << std::endl;
    logError(log, "bind fail");
    close(listenfd);
    return;
  }

  //监听端口
  if (listen(listenfd, 3000) < 0) 
  {
    // std::cout << "listen fail" << std::endl;
    logError(log, "listen fail");
    close(listenfd);
    return;
  }

  //创建epoll事件
  epollfd = epoll_create1(0);
  if (epollfd < 0) 
  {
    // std::cout << "create epollfd fail" << std::endl;
    logError(log, "create epollfd fail");
    return;
  }

  GetModemInfo();
 
   for (auto &data:connserver.vecstr)
	{
		logDebug(log, "str=%s idx=%d iscanused=%d currentcnt=%d strip=%s", 
			data.strnic.c_str(), data.idx, data.iscanused, data.currentcnt,
			data.strip.c_str());
      // resetnicinfo(log, data.idx, data.strnic);
	}

  // return;
  std::thread t2(std::bind(&server::getnicip, this));

  for (int i=0; i<1; i++)
  {
    resetpool.add_task(std::bind(&server::resetnic, this));
  }

  std::thread t3(std::bind(&server::AcceptConn, this));
  std::thread t4(std::bind(&server::TimeoutThd, this));
  std::thread t5(std::bind(&server::ResetNoIPmodemThd, this));
  // resetpool.add_task(std::bind(&server::resetnic, this));
  //开始循环处理epoll事件
  forever();
  while (1)
  {
    sleep(1);
  }
}

void server::AcceptConn()
{
  int conncnt = 0;
  struct sockaddr_in clientaddr;
  socklen_t len = sizeof(clientaddr);
  while (1) 
  {
       int fd = accept(listenfd, (struct sockaddr*)&clientaddr, &len);
        if (fd <=0)
        {
          logDebug(log, "newConnect after accept ret=%d errno=%d err=%s", 
            fd, errno, strerror(errno)); 
          continue;
        }

      //  logDebug(log, "You got a connection from host[%s] port[%d] fd[%d] conn=%d",
      // inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port), fd, ++conncnt);

      // if (0 == strcmp(inet_ntoa(clientaddr.sin_addr), "192.168.0.234"))
      // {
      //   close(fd);
      //   continue;
      // }

      logDebug(log, "You got a connection from host[%s] port[%d] fd[%d] conn=%d",
      inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port), fd, ++conncnt);
      // threadpool.add_task(std::bind(&server::newConnect, this));
      // threadpool.add_task(std::bind(&server::newConnect, this));
      newConnect(fd);
      // logDebug(log, "You got a connection 11 from host[%s] port[%d] fd[%d] conn=%d",
      // inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port), fd, conncnt);
  }

  return;
}

void server::TimeoutThd()
{
  while (1)
  {
     std::unique_lock<std::mutex> locker(fdmapmutex);
    for(auto it: fdmap)
    {
      if ((time(NULL) - it.second->updatetime) > 4*60)
      {
        Connect* con = it.second;
        if (con)
        {
          delFromEpoll(con->clientfd);
          delFromEpoll(con->serverfd);
          close(con->clientfd);
          close(con->serverfd);
        
          auto cliit = fdmap.find(con->clientfd);
          if (cliit != fdmap.end()) 
            fdmap.erase(cliit);

          auto srvit = fdmap.find(con->serverfd);
          if (srvit != fdmap.end()) 
            fdmap.erase(srvit);

          delete con;
        }
      
      
      }
    }

    sleep(60);
  }
 
}

void server::ResetNoIPmodemThd()
{
  char cmd[128];
  FILE *fp1 = NULL;
  while (1)
  {
    bool needunlock = true;
    std::unique_lock<std::mutex> niclocker(connserver.nicmutex);
    for(auto &data:connserver.vecstr)
    {
        snprintf(cmd, sizeof(cmd), "ifconfig %s|grep inet|grep -v 127.0.0.1|grep -v inet6|awk '{print $2}'|tr -d \"addr:\"",
        data.strnic.c_str());
        if ((fp1 = popen(cmd, "r")) == NULL)
        {
          logError(log, "ResetNoIPmodemThd: popen fail\n");
          
          needunlock = false;
          niclocker.unlock();
          break;
        }

        needunlock = false;
        niclocker.unlock();
        resetnicinfo(log, data.idx, data.strnic);
        break;
    }

    if (true == needunlock)
      niclocker.unlock();
    sleep(120);
  }
  
}

void server::forever() 
{
  struct epoll_event events[MAX_EPOLL_EVENTS];
  struct sockaddr_in clientaddr;
  socklen_t len = sizeof(clientaddr);
  
  while (1) 
  {
    int n = epoll_wait(epollfd, events, MAX_EPOLL_EVENTS, -1);
    for (int i = 0; i < n; ++i) 
    {
        if (events[i].data.fd == listenfd) 
        {
          int fd = accept(listenfd, (struct sockaddr*)&clientaddr, &len);
          if (fd <=0)
          {
          logDebug(log, "newConnect after accept ret=%d errno=%d err=%s", 
          fd, errno, strerror(errno)); 
          continue;
          }
        } 
        else 
        {
            // continue;
            //已有连接
            int fd = events[i].data.fd;
            
            threadpool.add_task(
            	std::bind(&server::eventHandle, this, fd));
        }
    }
  }
}

void server::getnicip()
{
  while(1)
  {
    std::unique_lock<std::mutex> locker(connserver.resetmutex);
    for (auto it = connserver.vecResetInfo.begin(); it != connserver.vecResetInfo.end();) 
    {
      int ret = UpModemInfo(it->strnic);
      // logDebug(log, "ret=%d", ret);
      if (0 == ret)
      {
        it = connserver.vecResetInfo.erase(it);
      }
      else 
      {
			  ++it;
		  }
	  }

    locker.unlock();
    sleep(3);
  }
}

void server::resetnic()
{
    while(1)
    {
      connserver.ResetNic(log);
      if (connserver.m_curnicidx % connserver.vecstr.size() == 0)
      {
          // UpAllModemInfo();
      }

      sleep(10);
    }
}
