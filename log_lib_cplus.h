/***************************************
  *   ��Ȩ����(C) 2003-2005.
  *   �� �� �� : _lib_clog.h
  *   ��    �� : 
  *   ������� : 
  *   ��    �� : ��־��ͷ�ļ���
  *   �޸ļ�¼ :
  *     ����    ʱ��        �汾    ����
  *   ���ݽṹ :
  *   ��    ע :
  ***************************************/

#ifndef __LIB_CLOG_CPLUS_H__
#define __LIB_CLOG_CPLUS_H__


#include <string>
#include <map>
#include <cstring>
#include <iostream>

//#ifdef __cplusplus
//extern "C" {
//#endif // __cplusplus 
 
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>

using std::string;
using std::map;
//#ifdef __cplusplus
//}
//#endif // __cplusplus 


#include "cdatetime_lib.h"


// using namespace std;


#ifndef MAX_FILENAME_LEN
#define MAX_FILENAME_LEN    256     // �ļ�������󳤶�         
#endif

// ��־�ļ�Ĭ�ϴ�С 
#define CLOG_MAX_FILESIZE   (20*1024*1024)


// ��־�ȼ�  
enum {
    CLOG_DEBUG = 0,
    CLOG_INFO,
    CLOG_ERROR,
    CLOG_NONE
};


class CLog
{
public:
    CLog();
    CLog(const char *szPath);
    CLog(const string& cstrPath);
    ~CLog();
   
    // ��־������ʼ�� 
    int init(int iloglevel = CLOG_DEBUG);

    // ��־������ʼ�� 
    int init(const string& cstrPath, int iloglevel = CLOG_DEBUG);

    // ������־�ļ������� 
    int rename(const char *fname);

    // ������־д���� 
    int write(const char *fmt, ...);

    // ������־д���� 
    int write(const char *file, const char *func, int line, const char *fmt, ...);

    // ������־����д��־�ĺ��� 
    int write(int lvl, const char *file, const char *func, int line, const char *fmt, ...);
//	int write(int lvl, const char *fmt, ...);

    // ������־����ĺ��� 
    int setLogLevel(int lvl);

    // ������־����ĺ��� 
    int setLogLevel(const char* szLvl);

    // ��ȡ��־����ĺ��� 
    int getLogLevel(void);

    // ��ȡ��ǰ��־�������Ƶĺ��� 
    const char* getLogLevelName(void);

    // ��ȡָ����־�������Ƶĺ��� 
    const char* getLogLevelName(int lvl);

    // ������־�ļ������ߴ� 
    void setMaxFileSize(int iMaxSize){ m_maxFileSize = iMaxSize; };

    // ��ȡ��־�ļ������ߴ� 
    int getMaxFileSize(){ return m_maxFileSize; };

    // ������Դ���ر��Ѵ򿪵��ļ� 
    void cleanup(void);

    int writeBuffer(const char *file, const char *func, const char* buffer, const int len);

    void setname(const char *szPath);

    // SOC ��־ 
 //   CSOCLog soc;

private:
    // ���ó�ʼ����־��������Ҫ����Դ 
    void fill(const string& cstrPath);

    // �����־�ļ��Ĵ�С�Ƿ���, ������޾��Զ�ת�� 
    int chkLogFileSize(void);

    // ����־�ļ� 
    int openLog();

    // �ر���־�ļ� 
    int closeLog();

private:
    static map<string, int> ms_filemap;

    FILE    *m_logfp;

    CDateTime   m_datetime;     // datetime utils 
    std::string m_logfname;     // ��־�ļ���ȫ·���� 
    std::string m_logfpath;     // ��־�ļ���ŵ�·�� 
    pthread_mutex_t   m_mutex;  // ��־�ļ��� 

    int  m_maxFileSize; // ��־�ļ������ߴ� 
    int  m_logLevel;    // ��ǰ���õ���־���� 

    int  m_flag;  // ���캯���Ƿ�ִ�гɹ� 
};


#define logError(clog, fmt, arg...) \
do \
{ \
    clog.write(CLOG_ERROR, __FILE__, __FUNCTION__, __LINE__, fmt, ##arg); \
} while (0)


#define logDebug(clog, fmt, arg...) \
do \
{ \
    clog.write(CLOG_DEBUG, __FILE__, __FUNCTION__, __LINE__, fmt, ##arg); \
} while (0)


#endif // __CLOG_H__ 

/* 
 * vi: sw=4 ts=4 et
*/ 

/*******************************************************************************

#include "lib_log.h"

int main(int argc, char *argv[])
{
    string szLogFile="./log";        //����Ҫ��׺Ĭ���� .log
    CLog log(szLogFile);   
    if (log.init(CLOG_DEBUG) < 0)
    {
        cout<<"init log faild."<<endl;
        exit(-1);
    }
    logDebug(log, "hello.");
    logError(log, "sorry.");
}
*******************************************************************************/

