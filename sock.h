#pragma once
#include <winsock2.h>
#include <string>


#ifndef Socket_t
	#define Socket_t SOCKET
#endif


extern const char * GetExePath(int pt);
class CSocket
{
public:
	CSocket(Socket_t s = 0, int nProtocol = IPPROTO_TCP)
		: m_socket(s)
		, m_nProtocol(nProtocol)
		, m_bNoBlock(FALSE)
		, m_https(FALSE)
		, m_event(0)
	{}

	virtual ~CSocket()
	{}

	BOOL     IsHttps()      { return m_https;    }
	Socket_t Socket() const { return m_socket;   }
	BOOL     IsNoBlock()    { return m_bNoBlock; }
	int      NetEvent()     { return m_event;    }


	virtual int  Create(Socket_t s = 0)
	{
		if(m_socket) return 1;
		if(s) { m_socket = s; return 0; }

		int nType = 0;
		switch(m_nProtocol)
		{
		case IPPROTO_TCP: nType = SOCK_STREAM; break;
		case IPPROTO_UDP: nType = SOCK_DGRAM;  break;
		case IPPROTO_IP:  nType = SOCK_RAW;    break;
		default:          return -1;
		}

		m_socket = ::socket(AF_INET, nType, m_nProtocol);
		if(m_socket == INVALID_SOCKET) m_socket = 0;

		//LogX("== sock, create (%d)\n", m_socket);
		return m_socket != 0 ? 0 : -1;
	}

	virtual void Close()
	{
		if(m_socket)
		{
			LogX("== socket, close it, %d\n", m_socket);
			closesocket(m_socket);
			m_socket = 0;
		}

		// 重置属性, 重新使用. 
		m_bNoBlock = FALSE;
		m_https    = FALSE;
		m_event    = 0;
	}

	virtual int  Connect(const char * szDomain)
	{
		int nPort = 80;

		std::string  strDomain = szDomain;
		const char * szPort = strchr(szDomain, ':');
		if(szPort)
		{
			strDomain[szPort - szDomain] = 0;
			nPort  = atoi(szPort + 1);
		}

		struct hostent * host = gethostbyname(strDomain.c_str());
		if(!host) return -1;

		int nIp = *((unsigned long*)host->h_addr_list[0]);
		return Connect(nIp, nPort);
	}

	virtual int  Connect(int nIp, int nPort, int nTimeout = -1)
	{
		sockaddr_in addr = {0};
		addr.sin_addr.S_un.S_addr = nIp;
		addr.sin_port             = htons(nPort);
		addr.sin_family           = AF_INET;

		int nRet = 0;
		if(nTimeout <= 0) nRet = connect(m_socket, (sockaddr*)&addr, sizeof(addr));
		else
		{
			timeval tm = { nTimeout, 0 };
			nRet = ConnectTm(m_socket, addr, &tm);
		}

		return nRet;
	}

	virtual int  Listen(int nIp, int nPort)
	{
		sockaddr_in addr = {0};
		addr.sin_addr.S_un.S_addr = nIp;
		addr.sin_port             = htons(nPort);
		addr.sin_family           = AF_INET;

		if(!bind(m_socket, (sockaddr*)&addr, sizeof(addr)))
		{
			int nRet = listen(m_socket, 200);
			return nRet != SOCKET_ERROR ? 0 : -1;
		}

		return -1;
	}

	virtual int  Accept(Socket_t * ps, sockaddr_in * paddr)
	{
		int      len  = sizeof(sockaddr_in);
		Socket_t s    = accept(m_socket, (sockaddr*)paddr, &len);
		if(s != INVALID_SOCKET) *ps = s;

		return s != INVALID_SOCKET ? 0 : -1;
	}

	virtual int  Send(const char * pbData, int nLen, int nType)
	{
		AssertLog(m_socket);
		AssertLog(pbData);
		AssertLog(nLen > 0);
		return send(m_socket, pbData, nLen, 0);
	}

	virtual int  Recv(char * pbBuf, int nSize, int nType)
	{
		AssertLog(m_socket);
		AssertLog(pbBuf);
		AssertLog(nSize > 0);
		return recv(m_socket, pbBuf, nSize, 0);
	}


	int  SendAll(const char * pbData, int nLen, int * pSendLen, int nType)
	{
		AssertLog(pbData);
		AssertLog(nLen > 0);

		// 这儿发送错误后, 再也收不到写事件**************
		// 首先这个问题是 openssl::SSL_write()的. 
		// 发送的问题是如果第一次错误, openssl会返回 3(SSL_ERROR_WANT_WRITE). 
		// 要求再次发送, 然后当再次发送的时候就会出错了, 错误码是 1(SSL_ERROR_SSL)
		// 
		// 我跟踪 openssl-1.1.0代码发现是因为其内部缓存了上次未发送的缓存的
		// 地址和大小, 如果再次发送的时候这个地址和大小变化了, 就会出错. 
		// 
		// 而不幸的是我的程序当再次发送的时候地址肯定会变化, 因为删除已发送的数据和
		// 可能有新收的数据都会导致地址的变化. 导致openssl出错. 
		// 
		int  nRet = 0, nErr = 0, nSendLen = 0;
		for(int n = 0, m; nSendLen < nLen; nSendLen += n)
		{
			n  = nLen-nSendLen >= 1024 ? 1024 : nLen-nSendLen; m = n;
			n  = Send(pbData+nSendLen, m, nType);
			if(n == SOCKET_ERROR)
			{
				nRet = n; nErr = GetLastError(nRet);
				LogX("** socket, send ret(%d, %d, %d)...(%p,%d)\n", m_socket, nRet, nErr, pbData+nSendLen, nSendLen);
				break;
			}
		}

		LogX("== socket, send ret(%d), sock(%d), data(%p, %d, %d)\n", nRet, m_socket, pbData, nLen, nSendLen);
		if(pSendLen) *pSendLen = nSendLen;
		return nRet;
	}

	int  RecvAll(char * pbBuf, int nSize, int * pRecvLen, int nType)
	{
		Assert(pbBuf);
		Assert(nSize);

		int nRet     = 0, nRecvLen = 0;
		while(1)
		{
			nRet = Recv(pbBuf + nRecvLen, nSize - nRecvLen, nType);
			if(nRet <= 0)
			{
				int nError = GetLastError(nRet);
				LogX("** socket, recv error(%d, %d), sock(%d), data(%d, %d).\n", nRet, nError, m_socket, nSize, nRecvLen);
				break;
			}

			nRecvLen += nRet;
			if(nRecvLen >= nSize)
			{
				Assert(nRecvLen == nSize);
				nRet = 0;
				break;
			}
		}

		if(pRecvLen) *pRecvLen = nRecvLen;

		#ifdef _DEBUG
		LogX("== socket, recv ret(%d), sock(%d), data(%d, %d)\n", nRet, m_socket, nSize, nRecvLen);
		//if(nRecvLen > 0) LogByteData(pbBuf, nRecvLen);
		#endif
		return nRet;
	}


	// ctrl. 
	virtual int  SetNoBlock(BOOL bNoBlock)
	{
		m_bNoBlock = bNoBlock;
		return ioctlsocket(m_socket, FIONBIO, (unsigned long*)&bNoBlock) ? -1 : 0;
	}

	virtual int  GetLastError(int & nRet)
	{
		if(nRet == 0)
		{
			nRet = -1;
			return 0;
		}

		int nError =  WSAGetLastError();
		if( nError == WSAEWOULDBLOCK) nRet = 0;
		return nError;
	}


protected:
	int  ConnectTm(SOCKET s, sockaddr_in & addr, const timeval * ptmConn)
	{
		int nRet1 = 0, nRet2 = 0;
		fd_set fdReadEvent, fdWriteEvent, fdExceptionEvent;

		FD_ZERO(&fdReadEvent); FD_ZERO(&fdWriteEvent); FD_ZERO(&fdExceptionEvent);
		FD_SET(s, &fdReadEvent); FD_SET(s, &fdWriteEvent); FD_SET(s, &fdExceptionEvent);

		::connect(s, (const sockaddr*)&addr, sizeof(sockaddr_in));

		// timeout也去判断一下. 
		if((nRet2 = ::select(0, &fdReadEvent, &fdWriteEvent, &fdExceptionEvent, ptmConn)) < 0 || 
			!IsConnected(s, &fdReadEvent, &fdWriteEvent, &fdExceptionEvent))
		{
			nRet1 = SOCKET_ERROR;
		}

		return nRet1;
	}

	BOOL IsConnected(SOCKET s, fd_set* fdRead, fd_set* fdWrite, fd_set* fdException)
	{
		BOOL bRet    = TRUE;
		int  nError  = 0;
		int  nErrLen = sizeof(nError);

		if(!FD_ISSET(s, fdRead) && !FD_ISSET(s, fdWrite))
		{
			bRet = FALSE;
		}

		if(::getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&nError, &nErrLen) != 0)
		{
			bRet = FALSE;
		}

		#ifdef _DEBUG
		LogX("%s socket, net connect %s, error = %d ...\n", bRet ? ">>" : "**", bRet ? "ok" : "failed", nError);
		#endif
		return bRet;
	}


protected:
	Socket_t m_socket;
	int      m_nProtocol;
	BOOL     m_bNoBlock;
	BOOL     m_https;
	int      m_event;
};
