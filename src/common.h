#pragma once

// lib
#pragma comment(lib, "ws2_32.lib")

// log
#define LOGF_MODE             "w"
#include <assert.h>
#include "rslogx.h"
#ifndef LogX
	#define LogX(_fmt, ...)   LOG_FLOG(0, _fmt, __VA_ARGS__)
#endif

#ifndef AssertLog
	#define AssertLog(_expr)  { \
		if(!(_expr)) { \
		LOG_FLOG(1, "[error]: proxy %s:%d %s, ('%s', werr = %d)\n", __FILE__, __LINE__, __FUNCTION__, #_expr, ::GetLastError()); return -1; } \
	}
#endif

#ifndef LogByteData
	#define LogXX(_fmt, ...)  LOG_PF->LOGF_IMPL(0, LogType_No, LOG_FILE, _fmt, __VA_ARGS__)
	#define LogByteData(_b, _l) { \
		LogX("------------------%d:\n", _l); \
		for(int i = 0; i < _l && _b[i] > 0 && _b[i] < 127; i++) { LogXX("%c", _b[i]); } \
		LogX("--------------------.\n"); \
	}
	#define LogByteData2(_b, _l) { \
		LogX("------------------%d:\n", _l); \
		for(int i = 0; i < _l; i++) { LogXX("%x ", (unsigned char)_b[i]); } \
		LogXX("\n"); \
		for(int i = 0; i < _l && _b[i] > 0 && _b[i] < 127; i++) { LogXX("%c", _b[i]); } \
		LogX("--------------------.\n"); \
	}
#endif
		

// -----------------------------------
// windows or linux net function. 
inline int InitSocket(int nVesion = AF_INET)
{
	int nRet = 0;

	#ifdef WIN32
	WSADATA wData  = {0};

	nRet = WSAStartup(MAKEWORD(2, 2), &wData
		#ifdef __WINSOCK2_X_H__	
		, nVesion
		#endif
		);
	#endif

	return nRet;
}

inline void CleanSocket()
{
	#ifdef WIN32
	WSACleanup();
	#endif
}


class CGobalNetIo
{
public:
	static CGobalNetIo * GetInstance()
	{
		static CGobalNetIo g_nio;
		return &g_nio;
	}

	static void Init()
	{
		CGobalNetIo::GetInstance();
	}


private:
	CGobalNetIo()
	{
		InitSocket();
	}

	~CGobalNetIo()
	{
		CleanSocket();
	}
};

#define INIT_NET_SOCKET()  CGobalNetIo::Init()
