/*******************************************************************************
  *   ��Ȩ����(C) 2003-2005.
  *   �� �� �� : lib_cdatetime.cpp
  *   ��    �� : 
  *   ������� :  
  *   ��    �� : ��־�����̡�
  *   �޸ļ�¼ :
  *   ���ݽṹ :
  *   ��    ע :
  ******************************************************************************/


#include "cdatetime_lib.h"

/*******************************************************************************
  *   ��Ȩ����(C) 2003-2005.
  *   �� �� �� : getDateTime
  *   ��    ; : ������ȡ��ǰϵͳ����ʱ�亯����
  *   ��    �� : ��
  *   �� �� ֵ : const char* const
  *   �� �� �� :  
  *   ��    �� : 
  *   ������� :  
  *   ��    �� :
  *   �޸ļ�¼ :
  *   ���ݽṹ : 
  *   ��    ע :����ʱ���ʽΪ��YYYYMMDDHHMMSS
  ******************************************************************************/
 char*  CDateTime::getDateTime()
{
	struct tm *ptm;
	time_t t = 0;
	
	memset(m_datetime, 0x00, g_date_len + g_time_len);
	
	// convert time format  
	time(&t);
	ptm = localtime(&t);
	
	strftime(m_datetime, g_date_len + g_time_len, "%Y%m%d%H%M%S", ptm);
	
	return m_datetime;
}

/*******************************************************************************
  *   ��Ȩ����(C) 2003-2005, .
  *   �� �� �� : getDate
  *   ��    ; : ������ȡ��ǰϵͳ���ں�����
  *   ��    �� : ��
  *   �� �� ֵ : const char* const
  *   �� �� �� : clog.cpp
  *   ��    �� : 
  *   ������� : 2003�� 07�� 21��
  *   ��    �� :
  *   �޸ļ�¼ :
  *   ���ݽṹ : 
  *   ��    ע :���ڸ�ʽΪ��YYYY-MM-DD
  ******************************************************************************/
 char*  CDateTime::getDate()
{
	struct tm *ptm;
	time_t t = 0;
	
	memset(m_date, 0x00, g_date_len);
	
	// convert time format  
	time(&t);
	ptm = localtime(&t);
	
	strftime(m_date, g_date_len, "%Y-%m-%d", ptm);
	
	return m_date;
}

/*******************************************************************************
  *   ��Ȩ����(C) 2003-2005, .
  *   �� �� �� : getTime
  *   ��    ; : ������ȡ��ǰϵͳʱ�亯����
  *   ��    �� : ��
  *   �� �� ֵ : const char* const
  *   �� �� �� : clog.cpp
  *   ��    �� :  
  *   ������� :  
  *   ��    �� :
  *   �޸ļ�¼ :
  *   ���ݽṹ : 
  *   ��    ע :ʱ���ʽΪ��HH:MM:SS
  ******************************************************************************/
 char*  CDateTime::getTime()
{
	struct tm *ptm;
	time_t t = 0;

	memset(m_time, 0x00, g_time_len);
	
	// convert time format  
	time(&t);
	ptm = localtime(&t);
	
	strftime(m_time, g_time_len, "%X", ptm);
	
	return m_time;
}


/*******************************************************************************
  *   ��Ȩ����(C) 2003-2005, .
  *   �� �� �� : getMiTime
  *   ��    ; : ������ȡ��ǰϵͳʱ�亯����
  *   ��    �� : ��
  *   �� �� ֵ : const char* const
  *   �� �� �� :  
  *   ��    �� :  
  *   ������� :  
  *   ��    �� :
  *   �޸ļ�¼ :
  *   ���ݽṹ : 
  *   ��    ע :ʱ���ʽΪ�� HH:MM:SS,UUU
  ******************************************************************************/
 char*  CDateTime::getMiTime()
{
	struct tm *ptm;
    // struct timeb tp;
	char strtime[g_time_len];

	// ftime(&tp);
		time_t t = 0;

	memset(m_time, 0x00, g_time_len);
	
	// convert time format  
	time(&t);
	memset (strtime, 0x0, sizeof(strtime));
	memset (m_mitime, 0x0, g_mitime_len);
	
	// convert time format  
	ptm = localtime(&t);
	
	strftime(strtime, sizeof(strtime), "%X", ptm);
	// snprintf(m_mitime, sizeof(m_mitime)-1, "%s,%03d", strtime, tp.millitm);
  snprintf(m_mitime, sizeof(m_mitime)-1, "%s", strtime);

        return m_mitime;
}


