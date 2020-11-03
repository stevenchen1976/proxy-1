#pragma once
#include <set>
#include "netio.h"


#ifdef __USE_SSL__
#include "sockws.h"
#define  CSocketX      CSocketWS
#else
#include "sock.h"
#define  CSocketX      CSocket
#endif


typedef struct NetAddr_t
{
	int  nIp;
	int  nPort;
}NetAddr_t;


class CChannel
{
public:
	CChannel()
		: m_pNetIo(0)
		, m_socket(0)
		, m_bDelete(TRUE)
		, m_bExit(false)
		, m_nHttps(0)
		, m_nConnect(S_Dissconnect)
		, m_user(0)
		, m_nDataIndex(0)
		, m_nDataOff(0)
		, m_bPartial(false)
		, m_id(0)
	{
		memset(&m_local, 0, sizeof(m_local));
		memset(&m_remote, 0, sizeof(m_remote));
	}

	virtual ~CChannel()
	{
		// �ṩ��ǰ�ȴ��ͷŵĹ���. 
		// ��������״̬����, ����ڶ��ϴ���. 
		Uninit();
	}

	virtual void Close()
	{
		// ���Ҫ����һ��, ��ɾ����ʱ��ʹ��. 
		if(!m_socket) m_socket = m_sock.Socket();
		m_sock.Close();
	}

	// SetExit --> �����ⲿ���ùر�, �Ȼص��ɹ���ر�. 
	virtual int  Init(CNetIo * pNetIo)    { m_pNetIo = pNetIo; return 0; }
	virtual void Uninit()                 { while(!m_bDelete) Sleep(1000); m_socket = 0; }
	Socket_t     Socket() const           { return m_sock.Socket();      }
	virtual bool IsClose()                { return m_socket != 0;        }
	virtual BOOL IsDelete()               { return m_bDelete;            }
	virtual bool IsSend()                 { return !IsSendDataEmpty();   }
	virtual void SetExit()                { m_bExit = true;              }
	virtual void SetHttps(bool val)       { m_nHttps = val ? 2 : 1;      }
	virtual int  GetHttps()               { return m_nHttps;             }
	virtual int  GetConnectState()        { return m_nConnect;           }
	virtual int  GetId()                  { return m_id;                 }
	virtual void SetId(int id)            { m_id = id;                   }
	CSocketX   * SocketClass()            { return &m_sock;              }
	void       * UserData()               { return m_user;               }
	NetAddr_t  * LocalAddress()           { return &m_local;             }
	NetAddr_t  * RemoteAddress()          { return &m_remote;            }

	bool IsConnectFinish()
	{
		return m_nConnect >= S_ConnectOk;
	}


	// ע��: ����������뱣֤�ڻص���ʹ��. ***
	// �п����� ���˵Ļص���, ��ʱ��Ҫ��֤���ߵĻص���ͬһ���߳�. 
	virtual int  Echo(const char * pbData, int nLen)
	{
		// �п��� socket���ر���. ***
		if(m_socket) return 0;

		std::string & buf = GetSendData(true);
		buf.append(pbData, nLen); Assert(!buf.empty());

		NetCtrl(Action_CtrlMod, Event_NetWrite);
		return 0;
	}

	// ����һ���¼�
	virtual void SetEvent(int nEvent)
	{
		NetCtrl(Action_CtrlMod, nEvent);
	}

	virtual int  Dispatch(int nEvent, int nError)
	{
		// ʵ����û���õ� Write�¼�. 
		// ����ٴ��� error�¼�. 
		// �رյ�ʱ��������д�¼�. 
		// nError �� select �Ĵ���. 
		LogX("== channel_base, event dipatch (%x, %d) -> (%p, %d/%d)\n", nEvent, nError, this, m_sock.Socket(), m_socket);

		int  nRet = 0;
		bool bDelete = nError == WSAENOTSOCK;

		if(!m_socket && !bDelete)
		{
			if(!nRet && nEvent & Event_NetConnect)   nRet = OnConnect();
			if(!nRet && nEvent & Event_NetRead)      nRet = OnRead();
			if(!nRet && nEvent & Event_NetWrite)     nRet = OnWrite();
			if(!nRet && nEvent & Event_NetTimeout)   nRet = OnTimeout();
		}

		if(!nRet && nEvent & Event_NetExcept) return OnError(bDelete);
		if(!nRet && m_bExit) OnError(TRUE);
		return nRet;
	}

	// for std's list, set.
	virtual bool operator < (const CChannel & other) const
	{
		return Socket() < other.Socket();
	}


protected:
	// delete ���� 1, ���󷵻� -1, ok ���� 0
	// ��Ҫ: OnError������ʾɾ��, ���� 1. 
	virtual int  OnConnect()
	{
		m_nConnect = S_RawConnectOk;
		return 0;
	}

	virtual int  OnRead()
	{
		return 0;
	}

	virtual int  OnWrite()
	{
		int nRet = 0, nSendLen = 0;

		if(!IsSendDataEmpty())
		{
			std::string & buf = GetSendData(false);
			nRet = Send(buf.c_str()+m_nDataOff, buf.length()-m_nDataOff, &nSendLen, 0);
			if(nRet)
			{
				// ֱ�ӵ���delete --> OnError ???
				// �ⲿ���ư� ?? �μ� CTcpProxyClient
				Assert(nRet != WSAEWOULDBLOCK);
				//Close(); 
				OnError();
				LogX("== channel_base, socket send error ----------------\n");
				return -1;
			}

			HandleSendedData(buf, nSendLen);
		}

		return 0;
	}

	virtual int  OnTimeout()
	{
		return 0;
	}

	virtual int  OnError(BOOL bDelete = FALSE)
	{
		// ***
		// ��������� close��delete������ socket��Ч������. 
		if(bDelete && !m_socket) 
		{
			return 0;
		}

		if(!m_bDelete)
		{
			if(m_nConnect == S_ConnectOk) m_nConnect = S_ConnectBreak;
			Close();
			NetCtrl(Action_CtrlDel);
			m_bDelete = TRUE;
			LogX("** channel_base, on error -> delete channel(%p, %d/%d)(%d)\n", this, m_sock.Socket(), m_socket, m_nConnect);
		}
		return 1;
	}


protected:
	std::string& GetSendData(bool bCache)
	{
		if(bCache || !m_bPartial)
		{
			return m_nDataIndex ? m_strData2 : m_strData;
		}

		Assert(m_nDataOff >= 0 && !bCache)
		return m_nDataIndex ? m_strData : m_strData2;
	}

	bool         IsSendDataEmpty()
	{
		return m_strData.empty() && m_strData2.empty();
	}

	void         HandleSendedData(std::string & strData, int nLength)
	{
		m_nDataOff  += nLength;
		Assert(m_nDataOff <= (int)strData.length());

		if((int)strData.length() > m_nDataOff)
		{
			const char * b = GetSendData(true).c_str();
			const char * p = strData.c_str();
			LogX(">> channel_base, send partial data, --->(%p,%p,%d,%d), (%d,%d)\n", p, b, strData.length(), nLength, m_nDataOff, m_nDataIndex);
			m_bPartial = true;
			if(b == p) m_nDataIndex = m_nDataIndex ? 0 : 1;
			return ;
		}

		m_nDataOff = 0; m_bPartial = false; strData.clear();
	}

	virtual int  NetCtrl(int nAction, int nEvent = 0, int nTimeout = -1)
	{
		if(!m_pNetIo) return 0;

		IoCtrlEvent_t ev = { nEvent, 0, this };
		int nRet = m_pNetIo->Ctrl(nAction == Action_CtrlDel ? m_socket : m_sock.Socket(), nAction, &ev, nTimeout);
		Assert(!nRet);

		if(nAction == Action_CtrlAdd) m_bDelete = FALSE;
		return nRet;
	}

	// ע��: 
	// �ⲿʹ���������ʱҪע�ⷢ������ʱ, ��Ҫ���� OnError
	// ���ڲ������ᵼ�ºܶ�����. 
	virtual int  Recv(char * pbBuf, int nSize, int * pRecvLen, int nType)
	{
		Assert(pbBuf);
		Assert(nSize);

		int nRecvLen = 0;
		int nRet = m_sock.RecvAll(pbBuf, nSize, &nRecvLen, nType);

		// �첽https
		//int nEvent = 0;
		//if(!(nType & 0x2) && m_sock.IsHttps() && (nEvent = m_sock.NetEvent()))
		//{
		//	Assert(!nRet);
		//	NetCtrl(Action_CtrlMod, nEvent);
		//}

		if(pRecvLen) *pRecvLen = nRecvLen;
		if(nRecvLen == nSize) NetCtrl(Action_CtrlMod, Event_NetRead|Event_NetAgain);

		return nRet;
	}

	// ��� send�����жԶ˶Ͽ�. 
	// local Ӧ����û������, ��ʱlocal Ӧ�� close(), �ȴ� callback, Ȼ���� delete local. 
	// ������� local �� close��ʱ��û�� wait. ����ܵò����¼�. ??? (select �¿��Եȵ��¼�)
	// 
	// ע��: ��������������Իָ�������... ***
	// �������Ӹ� Echo����. 
	// 
	// ��ʱ GetLastError() ��ȡ����������. ***
	virtual int  Send(const char * pbData, int nLen, int * pSendLen, int nType)
	{
		Assert(pbData && nLen > 0);
		int nRet = m_sock.SendAll(pbData, nLen, pSendLen, nType);

		// �첽https
		//int nEvent = 0;
		//if(!(nType & 0x2) && m_sock.IsHttps() && (nEvent = m_sock.NetEvent()))
		//{
		//	Assert(!nRet);
		//	NetCtrl(Action_CtrlMod, nEvent);
		//}

		if(!IsSendDataEmpty()) NetCtrl(Action_CtrlMod, Event_NetWrite|Event_NetAgain);

		return nRet;
	}


protected:
	NetAddr_t      m_local;
	NetAddr_t      m_remote;
	Socket_t       m_socket;
	CSocketX       m_sock;

	CNetIo       * m_pNetIo;
	std::string    m_strData,    m_strData2;
	int            m_nDataOff,   m_id;
	char           m_nDataIndex, m_bPartial, m_bExit, m_nHttps;  // 0= unknown, 1= http, 2= https,

	enum enumConnectState 
	{ 
		S_Dissconnect,  S_RawConnectOk, S_UnkownProto, 
		S_UnkownProto2, S_Handshake, S_ConnectOk, S_ConnectFailed, S_ConnectBreak, 
	}              m_nConnect;
	volatile BOOL  m_bDelete;
	void         * m_user;
};


// ����չ
// CTcpClient, CTcpServer. CTcpChannel. 
class CTcpChannel : public CChannel
{
public:
	CTcpChannel(void * lst, Socket_t s, sockaddr_in & addr, CChannel * srv)
		: m_list(lst)
		, m_pServer(srv)
	{
		m_sock.Create(s);
		m_remote.nIp   = *(int*)&addr.sin_addr;
		m_remote.nPort = ntohs(addr.sin_port);
	}

	virtual ~CTcpChannel()
	{}


	virtual int  Init(CNetIo * pNetIo)
	{
		Assert(m_sock.Socket());
		CChannel::Init(pNetIo);

		int nRet = 0;
		nRet = m_sock.SetNoBlock(TRUE);
		Assert(!nRet);

		nRet = NetCtrl(Action_CtrlAdd, Event_NetRead);
		Assert(!nRet);

		m_nConnect = S_RawConnectOk;
		OnConnect();
		return nRet;
	}


protected:
	virtual int  OnConnect()
	{
		// ����϶��� serverģʽ. 
		// �˴����ȷ���� sslЭ��Ļ�, ��ô����Ҫ�ж���. 
		// ˵�����Ǵ���ģʽ, ���Ƿ�����ģʽ. ��ʱ����Ҫ����֤��. 
		#ifdef __USE_SSL__
		if(m_nConnect == S_RawConnectOk)
		{
			Assert(m_nHttps);
			m_sock.SetServerSSL();
			m_nConnect = S_Handshake;
		}

		int nRet = m_sock.HandShake();
		if(nRet < 0)
		{
			m_nConnect = S_ConnectFailed;
			return nRet;
		}

		if(nRet > 0)
		{
			NetCtrl(Action_CtrlMod, Event_NetRead);
			return 1;
		}
		#endif

		m_nConnect = S_ConnectOk;
		return 0;
	}

	virtual int  OnRead()
	{
		if(!IsConnectFinish())
		{
			int nRet = OnConnect();
			if(nRet) return nRet;
		}

		if(m_nConnect != S_ConnectOk) return OnError();
		return CChannel::OnRead();
	}

	virtual int  OnWrite()
	{
		if(!IsConnectFinish())
		{
			int nRet = OnConnect();
			if(nRet) return nRet;
		}

		if(m_nConnect != S_ConnectOk) return OnError();
		return CChannel::OnWrite();
	}

	virtual int  OnError(BOOL bDelete = FALSE);


protected:
	void     * m_list;
	CChannel * m_pServer;
};


// ע������� server ����������� client connect. ���ݽ������� channel��. 
// client = channel;
// server = channel + n * tcp_channel;. 
// ����ͻ���ʹ�ö�� channel, ��Ҫ����client, ʹ�ö�� client. 
typedef std::set<CTcpChannel*> 
ChannelList_t;


inline int  CTcpChannel::OnError(BOOL bDelete)
{
	if(CChannel::OnError(bDelete))
	{
		Assert(m_list);
		ChannelList_t * pList = (ChannelList_t*)m_list;
		pList->erase(this);
		delete this;
		return 1;
	}

	return 0;
}


template<typename TTcpChannel = CTcpChannel>
class CTcpServer : public CChannel
{
public:
	CTcpServer(int nPort, int nIp = ADDR_ANY)
	{
		m_local.nPort = nPort;
		m_local.nIp   = nIp;
	}

	virtual ~CTcpServer()
	{
	}

	virtual int  Init(CNetIo * pNetIo)
	{
		CChannel::Init(pNetIo);

		int nRet = m_sock.Create();
		Assert(!nRet);

		nRet = m_sock.SetNoBlock(TRUE);
		Assert(!nRet);

		nRet = m_sock.Listen(m_local.nIp, m_local.nPort);
		AssertLog(!nRet);

		// accept �Ͳ�ʹ�� select��. ??
		// �� accept �ŵ� netio��, ����Ļ�����ռ��һ���߳�. 
		nRet = NetCtrl(Action_CtrlAdd, Event_NetRead);
		Assert(!nRet);

		OnConnect();
		return 0;
	}


protected:
	virtual int  OnRead()
	{
		Socket_t    s;
		sockaddr_in addr;

		int nRet = m_sock.Accept(&s, &addr);
		if(nRet)
		{
			LogX("** channel_server, accept %d\n", WSAGetLastError());
			return OnError();
		}

		TTcpChannel * pChannel = new TTcpChannel(&m_chaList, s, addr, this);
		if(!pChannel) return -1;

		// init --> on_connect.
		pChannel->Init(m_pNetIo);
		m_chaList.insert(pChannel);
		return 0;
	}

	virtual int  OnError(BOOL bDelete = FALSE)
	{
		// ���ڷ�������˵, ����ʲô������ ???
		// 
		// ***** 
		// ԭ���� Close��, ���� m_chaList���̳߳�ͻ�ŵ� OnError��. 
		// 
		// ����û�йرյ� sock, ������� close, ��delete
		// ���� select����������ӭ����. 
		// �������ݾͶ���, ���������ν��. ***
		int nError = GetLastError();
		LogX("** channel server, error = %d, %d\n", nError, m_socket);

		if(!m_socket) return 0;
		if(CChannel::OnError(bDelete))
		{
			for(ChannelList_t::iterator it = m_chaList.begin(); it != m_chaList.end(); it++)
			{
				LogX("?? channel server, not be delete ***%d\n", (*it)->Socket());
				(*it)->Close();
			}

			return 1;
		}

		return 0;
	}


protected:
	ChannelList_t  m_chaList;
};


class CTcpClient : public CChannel
{
public:
	CTcpClient(int nIp, int nPort)
		: m_nTimeout(-1)
	{
		m_remote.nIp   = nIp;
		m_remote.nPort = nPort;
	}

	CTcpClient(const char * szDomain)
		: m_strDomain(szDomain)
	{}

	virtual ~CTcpClient()
	{}


	void         SetDomain(const char * szDomain)
	{
		if(szDomain) m_strDomain = szDomain;
	}

	std::string& GetDomain()
	{
		return m_strDomain;
	}

	virtual int  Connect(int nConnectTimeout = -1)
	{
		int nRet = m_sock.Create();
		Assert(nRet >= 0);

		m_nTimeout = nConnectTimeout;
		if(nConnectTimeout >= 0)
		{
			m_sock.SetNoBlock(TRUE);
			nRet = ConnectImpl();
			if(nRet)
			{
				int nError = WSAGetLastError();
				if(nError != WSAEWOULDBLOCK)
				{
					LogX("** channel client, async connect error -->%d\n", nError);
					return -1;
				}
			}

			// connect ok --> writeable(msdn, connect)
			return NetCtrl(Action_CtrlAdd, Event_NetWrite, nConnectTimeout);
		}

		nRet = ConnectImpl();
		AssertLog(!nRet);

		m_sock.SetNoBlock(TRUE);
		nRet = NetCtrl(Action_CtrlAdd, Event_NetRead);
		Assert(!nRet);

		m_nConnect = S_RawConnectOk;
		OnConnect();
		return 0;
	}

	virtual int  Echo(const char * pbData, int nLen)
	{
		// �п��� socket���ر���. ***
		if(m_socket) return 0;

		std::string & buf = GetSendData(true);
		buf.append(pbData, nLen); Assert(!buf.empty());

		NetCtrl(Action_CtrlMod, Event_NetWrite);
		return 0;
	}


protected:
	virtual int  ConnectImpl()
	{
		int nRet = 0;
		if(m_strDomain.empty())
		{
			nRet = m_sock.Connect(m_remote.nIp, m_remote.nPort);
		}
		else
		{
			nRet = m_sock.Connect(m_strDomain.c_str());
		}

		return nRet;
	}

	virtual int  OnConnect()
	{
		int nRet;

		switch(m_nConnect)
		{
		case S_Dissconnect:
			// �ͻ��˵���������ܹ��жϳ��Ƿ��� ssl��. 
			Assert(m_nHttps);
			m_nConnect = S_RawConnectOk;

		case S_RawConnectOk:
			if(m_remote.nPort == 0)
			{
				sockaddr_in addr = {0};
				int         nLen = sizeof(addr);

				nRet = getpeername(m_sock.Socket(), (sockaddr*)&addr, &nLen);
				if(nRet || addr.sin_port == 0) return 1;

				m_remote.nIp     = *(int*)&addr.sin_addr;
				m_remote.nPort   = ntohs(addr.sin_port);
			}

			nRet = OnConnectRaw();
			if(nRet != 0)
			{
				if(nRet < 0) m_nConnect = S_ConnectFailed;
				return nRet;
			}

			if(m_nHttps == 2)
			{
				#ifdef __USE_SSL__
				m_sock.SetClientSSL(m_strDomain.c_str());
				LogX("== channel client, sock set ssl -->%d, %s\n", m_sock.Socket(), m_strDomain.c_str());
				#endif
			}
			m_nConnect = S_Handshake;

		case S_Handshake:
			// ����Ͳ���ssl���¼���, ���Ƕ�д. 
			#ifdef __USE_SSL__
			int nRet = m_sock.HandShake();
			if(nRet < 0)
			{
				m_nConnect = S_ConnectFailed;
				return nRet;
			}

			if(nRet > 0)
			{
				NetCtrl(Action_CtrlMod, Event_NetRead);
				return 1;
			}
			#endif

			m_nConnect = S_ConnectOk;
			break;
		}

		return 0;
	}

	virtual int  OnRead()
	{
		if(m_nTimeout > 0 && !IsConnectFinish())
		{
			int nRet = OnConnect();
			if(nRet) return nRet;
		}

		if(m_nConnect != S_ConnectOk) return OnError();
		return CChannel::OnRead();
	}

	virtual int  OnWrite()
	{
		if(m_nTimeout > 0 && !IsConnectFinish())
		{
			int nRet = OnConnect();
			if(nRet) return nRet;
		}

		if(m_nConnect != S_ConnectOk) return OnError();
		return CChannel::OnWrite();
	}

	virtual int  OnTimeout()
	{
		// ��ʱֱ�ӹر�
		if(m_nTimeout > 0 && m_nConnect == S_ConnectFailed)
		{
			LogX("** channel client, connect failed, (%d, %p), '0x%x:%d'/'%s'\n", m_sock.Socket(), this, m_remote.nIp, m_remote.nPort, m_strDomain.c_str());
		}

		return OnError();
	}

	virtual int  OnConnectRaw()
	{
		return 0;
	}


protected:
	std::string m_strDomain;
	int         m_nTimeout;
};
