/******************************************************************************
  *   ��Ȩ����(C) 2003-2050
  *   �� �� �� : 
  *   ��    �� : 
  *   ������� : 
  *   ��    �� : ��־�����̡�
  *   �޸ļ�¼ :
  *     ����    ʱ��        �汾    ����
  *    �ڻ�ȡ��־�ĵȼ�����ʱ, ���ø���ȫ�ķ�ʽ��ȡ��־�ȼ�������Ϣ
  *    �޸���־���뻷��������صĲ���, �������ھ�����
  *    ��־���Ϊ��һ��־�ļ���¼
  *    ����rename()����, ���������й����и�����־�ļ��� 
  *    �޸���־��ʽΪ "(pid) [date time] [file:line] [function]"
  *    ��־�ķּ���Ϊ��clog���е���־����������
  *    �����µĴ�����־�����write()�ӿ���������ּ���־ 
  *    �����˶���־��������ĺ��� 
  *   ���ݽṹ :
  *   ��    ע :
  *****************************************************************************/
#include "public_lib.h"
#include "log_lib_cplus.h"


 //ȫ��ϵͳ������Ϣ�ṹ
 //����־��С���п����� 
// extern pstSYSCONFIG pstSysConfig; 

// ��¼����־�е���־�ȼ���־  
static const char * s_lvlname[CLOG_NONE+1] = {
    "DBG",
    "INF",
    "ERR",
    "NONE"
};

// ����ͬ����־�ļ���map 
map<string,int> CLog::ms_filemap;

// ���캯�� 
CLog::CLog()
{
    m_flag  = 0;
    m_logfp = NULL;
    m_logLevel = CLOG_DEBUG;     // ��־��Ĭ�ϵȼ� 
    m_logfname = "";
    m_logfpath = "./";
    m_maxFileSize = CLOG_MAX_FILESIZE; // ��־�ļ������ߴ� 
    pthread_mutex_init(&m_mutex, NULL);
};


// ���캯�� 
CLog::CLog(const string& cstrPath)
{
    m_flag  = 0;
    m_logfp = NULL;

    m_logLevel = CLOG_DEBUG;     // ��־��Ĭ�ϵȼ� 

    m_logfname = "";
    m_logfpath = "./";
    m_maxFileSize = CLOG_MAX_FILESIZE; // ��־�ļ������ߴ� 

    pthread_mutex_init(&m_mutex, NULL);
    fill(cstrPath);
}

void CLog::setname(const char *szPath)
{
    fill(szPath);
}

// ���캯�� 
CLog::CLog(const char* szPath)
{
    m_flag  = 0;
    m_logfp = NULL;

    m_logLevel = CLOG_DEBUG;     // ��־��Ĭ�ϵȼ� 

    m_logfname = "";
    m_logfpath = "./";
    m_maxFileSize = CLOG_MAX_FILESIZE; // ��־�ļ������ߴ� 

    string cstrPath = "";
    if (szPath)
    {
        cstrPath = szPath;
    }

    pthread_mutex_init(&m_mutex, NULL);
    fill(cstrPath);
}


// �������� 
CLog::~CLog()
{
    cleanup();
}


/*****************************************************************************
 *   ��Ȩ����(C) 2003-2050.
 *   �� �� �� : init
 *   ��    ; : ��־����־ϵͳ��ʼ��������
 *   ��    �� : const char* pmode
 *   �� �� ֵ : int 0��ʾ�ɹ���-1��ʾʧ��
 *   �� �� �� : 
 *   ��    �� : 
 *   ������� : 
 *   ��    �� :
 *   �޸ļ�¼ :
 *   ���ݽṹ : 
 *   ��    ע :
 *****************************************************************************/
//int CLog::init(int iloglevel = CLOG_DEBUG);
int CLog::init(int iloglevel)
{
    if ( m_flag )
    {
        return -1;
    }

    setLogLevel(iloglevel);
    
    return 0;
}


//int init(const string& cstrPath, int iloglevel = CLOG_DEBUG);
int CLog::init(const string& cstrPath, int iloglevel)
{
    // ���ԭ�е���Դ 
    cleanup();
    
    // ���û�����Ϣ 
    fill(cstrPath);
    if (m_flag != 0)
    {
        return -1;
    }

    return init(iloglevel);
}


/*****************************************************************************
 *   �� �� �� : write
 *   ��    ; : ��־��������־д������
 *   ��    �� : const char* fmt
 *      ...
 *   �� �� ֵ : int 0��ʾ�ɹ���-1��ʾʧ��
 *   �� �� �� : clog.cpp
 *   ��    �� : 
 *   ������� : 
 *   ��    �� :
 *   �޸ļ�¼ :
 *   ���ݽṹ : 
 *   ��    ע :
*****************************************************************************/
int CLog::write(const char* fmt, ...)
{
    int ret = 0;

    if (0 != (ret = openLog()))
    {
        return ret;
    }
    
    if (0 != (ret = chkLogFileSize()) )
    {
        closeLog();
        return ret;
    }

    // base info 
    fprintf(m_logfp, "(%ld) [%s %s]\n\t", 
                     pthread_self(), 
                     m_datetime.getDate(), m_datetime.getMiTime());
    
    // run info 
    va_list pvar;
    va_start(pvar, fmt);    
    vfprintf(m_logfp, fmt, pvar);
    va_end(pvar);

    fprintf(m_logfp, "\n");
    
    return closeLog();
}


/*****************************************************************************
  *   �� �� �� : write
  *   ��    ; : ��־�������־д������
  *   ��    �� : const char* file
  *     const char* func
  *     const int line
  *     const char* fmt
  *       ...
  *   �� �� ֵ : int 0��ʾ�ɹ���-1��ʾʧ��
  *   �� �� �� : clog.cpp
  *   ��    �� : 
  *   ������� : 
  *   ��    �� :
  *   �޸ļ�¼ :
  *   ���ݽṹ : 
  *   ��    ע :
  *****************************************************************************/
int CLog::write(const char* file, const char* func, const int line, const char* fmt, ...) 
//int CLog::write(const char* fmt, ...) 
{
    if (!file || !func)
    {
        return -1;
    }

    int ret = 0;

    if (0 != (ret = openLog()))
    {
        return ret;
    }
    
    if (0 != (ret = chkLogFileSize()) )
    {
        closeLog();
        return ret;
    }

    fprintf(m_logfp, "(%ld) [%s %s] %s %d\n\t", 
                     pthread_self(), 
                     m_datetime.getDate(), m_datetime.getMiTime(),
                     file, line);

    va_list ap;
    va_start(ap, fmt);    
    vfprintf(m_logfp, fmt, ap);
    va_end(ap);
    
    fprintf(m_logfp, "\n");
    
    return closeLog();
}

// ������Դ���ر��Ѵ򿪵��ļ� 
void CLog::cleanup(void)
{
    ;
}

/*****************************************************************************
  *   ��    ; : ���ó�ʼ����־��������Ҫ����Դ
  *   ��    �� : cstrPath   ��־�ļ���ȫ·�� 
  *   �� �� ֵ : �� 
  *   �� �� �� : clog.cpp
  *   ��    �� : 
  *   ������� : 
  *   ��    �� :
  *   �޸ļ�¼ :
  *   ���ݽṹ : 
  *   ��    ע :
  ***************************************************************************/
void CLog::fill(const string& cstrPath)
{
    m_flag = -1;

    map<string,int>::iterator pos = ms_filemap.find(cstrPath);

    int filecount;
    if (pos != ms_filemap.end())
    {
        pos->second++;
        filecount = pos->second;
    }
    else
    {
        filecount = 1;
        ms_filemap[cstrPath] = filecount;
    }

    char szTmp[cstrPath.size()+20];

    if (filecount == 1)
    {
        snprintf(szTmp, sizeof(szTmp), "%s.log", cstrPath.c_str());
    }
    else
    {
        //snprintf(szTmp, sizeof(szTmp), "%s%d.log", cstrPath.c_str(), filecount);
        snprintf(szTmp, sizeof(szTmp), "%s.log", cstrPath.c_str());
    }

    // ������������־�ļ��� 
    m_logfname = szTmp;

    // ��ȡ��־�ļ���·�� 
    char *ps = (char *)rindex(m_logfname.c_str(), '/');

    if (NULL == ps)
    {
        m_logfpath = "./";
    }
    else
    {
        m_logfpath.assign(m_logfname.c_str(), ps-m_logfname.c_str()+1);
    }

    m_flag = 0;
}

/*****************************************************************************
  *   ��    ; : ��ȡ��ǰ��־��������� 
  *   ��    �� : 
  *   �� �� ֵ : ��־��������� 
  *   �� �� �� : clog.cpp
  *   ��    �� :  
  *   ������� :  
  *   ��    �� :
  *   �޸ļ�¼ :
  *   ���ݽṹ : 
  *   ��    ע :
*****************************************************************************/
const char* CLog::getLogLevelName(void)
{
    return getLogLevelName(getLogLevel());
}

/*****************************************************************************
  *   ��    ; : ��ȡ��־��������� 
  *   ��    �� : 
  *     int lvl             ��ǰ����־���� 
  *
  *   �� �� ֵ : ��־��������� 
  *   �� �� �� : clog.cpp
  *   ��    �� :  
  *   ������� :  
  *   ��    �� :
  *   �޸ļ�¼ :
  *   ���ݽṹ : 
  *   ��    ע :
*****************************************************************************/
const char* CLog::getLogLevelName(int lvl)
{
    if ((unsigned int)lvl > CLOG_NONE)
    {
        return s_lvlname[CLOG_DEBUG];
    }

    return s_lvlname[(unsigned int)lvl];
}

/*****************************************************************************
  *   ��    ; : ������־����
  *   ��    �� : 
  *     int lvl             ��־���� 
  *
  *   �� �� ֵ : �µ���־����
  *   �� �� �� : clog.cpp
  *   ��    �� :  
  *   ������� :  
  *   ��    �� :
  *   �޸ļ�¼ :
  *   ���ݽṹ : 
  *   ��    ע :
*****************************************************************************/
int CLog::setLogLevel(int lvl)
{
    if ((unsigned int)lvl > CLOG_NONE)
    {
        return m_logLevel = CLOG_DEBUG;
    }

    return m_logLevel = (unsigned int)lvl;
}

/*****************************************************************************
  *   ��    ; : ������־����, ���ַ����ķ�ʽ���� 
  *   ��    �� : 
  *     const char *szLvl   ��־���� 
  *
  *   �� �� ֵ : �µ���־����
  *   �� �� �� : clog.cpp
  *   ��    �� :  
  *   ������� :  
  *   ��    �� :
  *   �޸ļ�¼ :
  *   ���ݽṹ : 
  *   ��    ע :
*****************************************************************************/
int CLog::setLogLevel(const char *szLvl)
{
    // ������õ���־���𲻴���, ����DEBUG�ļ��� 
    for (int i=0; i<CLOG_NONE+1; i++)
    {
        if (!strcasecmp(szLvl, s_lvlname[i]))
        {
            setLogLevel(i);
            return 0;
        }
    }
    setLogLevel(CLOG_DEBUG);

    return -1;
}


/*****************************************************************************
  *   ��    ; : ��ȡ��־����
  *   ��    �� : 
  *   �� �� ֵ : ��־����
  *   �� �� �� : clog.cpp
  *   ��    �� :  
  *   ������� :  
  *   ��    �� :
  *   �޸ļ�¼ :
  *   ���ݽṹ : 
  *   ��    ע :
*****************************************************************************/
int CLog::getLogLevel(void)
{
    return m_logLevel;
}

/*****************************************************************************
  *   ��    ; : ��⵱ǰ�򿪵���־�ļ��Ĵ�С�Ƿ���, �������
  *              ���Զ�ת�� 
  *   ��    �� : 
  *   �� �� ֵ : �ɹ�����0, ���򷵻ش����� 
  *   �� �� �� : clog.cpp
  *   ��    �� :  
  *   ������� :  
  *   ��    �� :
  *   �޸ļ�¼ :
  *   ���ݽṹ : 
  *   ��    ע :
*****************************************************************************/
int CLog::chkLogFileSize(void)
{
//    if ( ftell(m_logfp) > m_maxFileSize )
//fprintf(stderr, "logsize[%d]\n", pstSysConfig->logsize);

	// if ( ftell(m_logfp) > pstSysConfig->logsize)
    if ( ftell(m_logfp) > 1024*1014*10)
    {
        char *ps;
        char sCmd[2*MAX_FILENAME_LEN];
        string str_bakfname;

        if ( NULL == (ps = (char *)rindex(m_logfname.c_str(), '/')) )
        {
            ps = (char*)m_logfname.c_str();
        }
        else
        {
            ps += 1;
        }

        memset(sCmd, 0x00, sizeof(sCmd));

        str_bakfname = m_logfpath + "bak/" + ps;
        if (!access("/bin/cp", X_OK))
        {
 //       fprintf(stderr, "access cp\n");
            if ( !access("/bin/gzip", X_OK) )
            {
 //           fprintf(stderr, "access gzip\n");
                // ���������ļ� 
                snprintf(sCmd, sizeof(sCmd), 
                         "/bin/cp -f %s %s 1>/dev/null 2>&1\n",
                          m_logfname.c_str(), str_bakfname.c_str());
//		fprintf(stderr, "sCmd[%s]\n", sCmd);		
                int res =  system(sCmd);
                if(-1 == res)
                {
                    std::cout<<"error"<<std::endl;
                }
                // ѹ�������ļ� 
                if ( !access(str_bakfname.c_str(), X_OK))
                {
                    snprintf(sCmd, sizeof(sCmd), 
                            "/bin/gzip -f %s 1>/dev/null 2>&1\n", 
                            str_bakfname.c_str());
//			fprintf(stderr, "sCmd[%s]\n", sCmd);				
                   
                    int res =  system(sCmd);
                    if(-1 == res)
                    {
                        std::cout<<"error"<<std::endl;
                    }
                }
            }
            else
            {
                // ���������ļ� 
                snprintf(sCmd, sizeof(sCmd), 
                         "cp -f %s %s 1>/dev/null 2>/dev/null",
                          m_logfname.c_str(), str_bakfname.c_str() );
                int res =  system(sCmd);
                if(-1 == res)
                {
                    std::cout<<"error"<<std::endl;
                }
            }
        }

        if ( ftruncate(fileno(m_logfp), 0) != 0 )
        {
            return -1;
        }

        rewind(m_logfp);
    }

    return 0;
}


/*****************************************************************************
  *   ��    ; : ����־�ļ� 
  *   ��    �� : 
  *   �� �� ֵ : �ɹ�����0, ���򷵻ش����� 
  *   �� �� �� : clog.cpp
  *   ��    �� :  
  *   ������� :  
  *   ��    �� :
  *   �޸ļ�¼ :
  *   ���ݽṹ : 
  *   ��    ע :
*****************************************************************************/
int CLog::openLog(void)
{
    if (m_logfp)
    {
        fclose(m_logfp);
    }

    if (NULL == (m_logfp = fopen(m_logfname.c_str(), "a")))
    {
        if (errno == ENOENT )
        {
            return -1;
        }
        else if (errno == EPERM )
        {
            return -1;
        }

        return -1;
    }

    return 0;
}

/*****************************************************************************
  *   ��    ; : ����־�ļ� 
  *   ��    �� : 
  *   �� �� ֵ : �ɹ�����0, ���򷵻ش����� 
  *   �� �� �� : clog.cpp
  *   ��    �� :  
  *   ������� :  
  *   ��    �� :
  *   �޸ļ�¼ :
  *   ���ݽṹ : 
  *   ��    ע :
*****************************************************************************/
int CLog::closeLog(void)
{
    if (m_logfp)
    {
        fclose(m_logfp);
        m_logfp = NULL;
        return 0;
    }

    return 0;
}


/*****************************************************************************
  *   ��    ; : ��־�������־д������
  *   ��    �� : 
  *     int lvl             ��ǰҪд����־���� 
  *     const char* file
  *     const char* func
  *     const int line
  *     const char* fmt
  *       ...
  *   �� �� ֵ : int 0��ʾ�ɹ���-1��ʾʧ��
  *   �� �� �� : clog.cpp
  *   ��    �� :  
  *   ������� :  
  *   ��    �� :
  *   �޸ļ�¼ :
  *   ���ݽṹ : 
  *   ��    ע :
*****************************************************************************/
int  CLog::write(int lvl, const char *file, const char *func, int line, const char *fmt, ...)
//int  CLog::write(int lvl, const char *fmt, ...)
{
    int ret = 0;

    if ( (lvl == CLOG_NONE) || (lvl < m_logLevel) )
    {
        return 0;
    }


    if (!file || !func)
    {
        return -1;
    }


    pthread_mutex_lock(&m_mutex);
    if (0 != (ret = openLog()))
    {
        pthread_mutex_unlock(&m_mutex);
        return ret;
    }

    pthread_t self = pthread_self();
    fprintf(m_logfp, "(%ld) [%s %s] [%s] [%s:%d] [%s]\n\t", 
                     self, 
                     m_datetime.getDate(), m_datetime.getMiTime(), 
                     getLogLevelName(lvl),
                     file, line, func);

    va_list ap;
    va_start(ap, fmt);    
    vfprintf(m_logfp, fmt, ap);
    va_end(ap);
    
    fprintf(m_logfp, "\n");

    if (0 != (ret = chkLogFileSize()) )
    {
        closeLog();
        pthread_mutex_unlock(&m_mutex);
        return ret;
    }
    
    ret = closeLog();
    pthread_mutex_unlock(&m_mutex);

    return ret;
}


/*****************************************************************************
  *   ��    ; : ���ĵ�ǰ��־������ 
  *   ��    �� : �µ���־�ļ��� 
  *   �� �� ֵ : 0��ʾ�ɹ�, ������ʾʧ��
  *   �� �� �� : clog.cpp
  *   ��    �� :  
  *   ������� :  
  *   ��    �� :
  *   �޸ļ�¼ :
  *   ���ݽṹ : 
  *   ��    ע :
*****************************************************************************/
int  CLog::rename(const char *fname)
{
    if (!fname) 
    {
        return -1;
    }

    pthread_mutex_lock(&m_mutex);
    string strNewFile;
    strNewFile = string(fname) + ".log";

    char szTmp[2048] = {0};

    if (!access("/bin/cat", X_OK))
    {
//        snprintf(szTmp, sizeof(szTmp), "/bin/cat %s >> %s", m_logfname.c_str(), strNewFile.c_str());
        snprintf(szTmp, sizeof(szTmp), ">> %s", strNewFile.c_str());
        int res =  system(szTmp);
        if(-1 == res)
        {
            std::cout<<"error"<<std::endl;
        }
    }


    if (!access("/bin/rm", X_OK))
    {
        snprintf(szTmp, sizeof(szTmp), "rm -f %s", m_logfname.c_str());
        int res =  system(szTmp);
        if(-1 == res)
        {
            std::cout<<"error"<<std::endl;
        }
    }

    m_logfname = strNewFile;
    pthread_mutex_unlock(&m_mutex);

    return 0;
}

/*
 * vi: sw=4 ts=4 et
 */

