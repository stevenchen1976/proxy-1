#ifndef __RsLogX_H__
#define __RsLogX_H__


#include <string>
#include <map>
#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>


#ifdef WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <pthread.h>
#endif


#ifndef Assert
	#include <assert.h>
	#define Assert(_expr)     { if(!(_expr)) { __asm int 3 }}  //assert
#endif


#ifndef FORMAT_ARGS_STRING
	#define FORMAT_ARGS_STRING(_buf, _fmt) \
		va_list args; \
		va_start(args, _fmt); \
		int _slen = strlen(_buf), _nlen = sizeof(_buf) - _slen - 1; \
		vsnprintf(_buf + _slen, _nlen, _fmt, args); \
		va_end(args);
#endif


inline void GetProcessFileName(char * szFileName, int nSize)
{
	Assert(szFileName);
	Assert(nSize > 0);

	#ifdef WIN32
		GetModuleFileNameA(0, szFileName, nSize);
	#else
		int nRet = readlink("/proc/self/exe", szFileName, nSize - 1);
		if(nRet > 0 && nRet < nSize) szFileName[nSize] = 0;
	#endif
}

inline int  GetProcessId()
{
	#ifdef WIN32
		return GetCurrentProcessId();
	#else
		return getpid();
	#endif
}

inline int  GetThreadId()
{
	#ifdef WIN32
		return GetCurrentThreadId();
	#else
		return (int)pthread_self();
	#endif
}

inline void GetNowTime(char * szTime, int nSize)
{
	time_t now;
	struct tm *curtime;		
	time(&now);
	curtime = localtime(&now);
	strftime(szTime, nSize, "%Y-%m-%d %H:%M:%S", curtime);
}


enum enumLogType
{ 
	LogType_No       = 0, 
	LogType_ProcInfo = 0x01, 
	LogType_Time     = 0x02, 
	LogType_Default  = LogType_ProcInfo | LogType_Time, 
};


class CLogF
{
public:
	static CLogF * GetInstance()
	{
		static CLogF g_logf;
		return &g_logf;
	}


	FILE * Open(const char * szName, const char * szMode = "a", bool bAbsolute = false)
	{
		std::string strFileName;

		if(!bAbsolute) strFileName = m_md;
		strFileName += szName;

		std::map<std::string, FILE*>::const_iterator it = m_pfs.find(strFileName);
		if(it == m_pfs.end())
		{
			extern int errno;
			FILE * pf  = fopen(strFileName.c_str(), szMode); 
			int nError = errno; Assert(pf);
			m_pfs.insert(std::make_pair(strFileName, pf));
			return pf;
		}

		return it->second;
	}

	void Log(int nLevel, int nType, FILE * pf, const char* szFormat, ...)
	{
		Assert(pf);

		char szLogBuffer[1024] = {0};
		if(nType & LogType_Time)
		{
			char       szTime[32] = {0};
			GetNowTime(szTime, sizeof(szTime));
			sprintf(szLogBuffer, "%s", szTime);
		}

		if(nType & LogType_ProcInfo)
		{
			sprintf(szLogBuffer + strlen(szLogBuffer), "<%4d, %4d> ", GetProcessId(), GetThreadId());
		}

		FORMAT_ARGS_STRING(szLogBuffer, szFormat);
		fwrite(szLogBuffer, strlen(szLogBuffer), 1, pf);
		printf("%s", szLogBuffer);
		fflush(pf);
	}


private:
	CLogF()
	{
		char szModule[1024] = {0};
		GetProcessFileName(szModule, sizeof(szModule));
		m_md = szModule;
	}

	~CLogF()
	{
		for(std::map<std::string, FILE*>::const_iterator it = m_pfs.begin(); 
			it != m_pfs.end(); it++)
		{
			fclose(it->second);
		}
		m_pfs.clear();
	}


private:
	std::map<std::string, FILE*>   m_pfs;
	std::string                    m_md;
};


#ifndef LOGF_NAME
	#define LOGF_NAME                            ".def.log"
#endif

#ifndef LOGF_MODE
	#define LOGF_MODE                            "a"
#endif

#ifndef LOGF_TYPE
	#define LOGF_TYPE                            LogType_Default
#endif

#define LOGF_IMPL                                Log
#define LOG_PF                                   CLogF::GetInstance()
#define LOG_FILE                                 LOG_PF->Open(LOGF_NAME, LOGF_MODE)


#ifdef WIN32
#define LOG_FLOG(_level, _fmt, ...)              LOG_PF->LOGF_IMPL(_level, LOGF_TYPE, LOG_FILE, _fmt, __VA_ARGS__)
#else
#define LOG_FLOG(_level, _fmt, args...)          LOG_PF->LOGF_IMPL(_level, LOGF_TYPE, LOG_FILE, _fmt, ##args)
#endif


// 使用说明: 
// 
// #define LOGF_NAME    ".xxx.log"
// #include "rslogx.h"
// #define RSLOGX       LOG_FLOG
// RSLOGX(0, "%s", "this is a test");
// 


#endif  // __RsLogX_H__
