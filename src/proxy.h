// 
// Server ������� Proxy, 
// Proxy���������� Client...
// -- proxy���տͻ��˹���������, Ȼ��ͨ�� client���ͳ�ȥ. 
//    client ���յ�����, ʹ�� proxy ���͸��ͻ���. 
// mod: ����ʹ���첽��ʽ. 
//

#include "channel.h"
#include "httpp.h"
#include "pcapf.h"


#define MAX_BUF_SIZE      8


class CTcpProxyClient : public CTcpClient
{
public:
	CTcpProxyClient()
		: CTcpClient(0, 80)
		, m_hpp(0)
		, m_pAgent(0)
		, m_pcapf(0)
	{
		memset(&m_proxy, 0, sizeof(m_proxy));
	}

	void SetAgent(CChannel * pAgent)            { m_pAgent = pAgent; }
	void SetProxyPcapFile(CProxyPcapFile * f)   { m_pcapf = f; }
	void SetHttpFilter(CHttpProtoclProxy * hpp) { m_hpp = hpp; }

	void SetProxyAddr(int nIp, int nPort)
	{
		Assert(nIp && nPort);
		m_proxy.nIp    = nIp;
		m_proxy.nPort  = nPort;
	}

	void SetRemoteAddr(int nIp, int nPort)
	{
		Assert(nIp && nPort);
		m_remote.nIp   = nIp;
		m_remote.nPort = nPort;
	}

	virtual int  Echo(const char * pbData, int nLen)
	{
		int nRet;

		nRet = CTcpClient::Echo(pbData, nLen);
		m_pcapf->WritePcapData(pbData, nLen, m_proxy.nIp, m_proxy.nPort, m_remote.nIp, m_remote.nPort);
		return nRet;
	}


protected:
	virtual int  OnConnect()
	{
		int nRet = 0;

		Assert(m_nHttps);
		nRet = CTcpClient::OnConnect();

		if(IsConnectFinish())
		{
			// ������ɴ���һ���¼�. 
			Assert(m_pAgent);
			m_pAgent->SetEvent(Event_NetWrite);
		}

		LogX(">> proxy, client connect (%s_%d), (%d, %d)(%p, %p), '0x%x:%d'/'%s'\n", 
			nRet > 0 ? "handshake" : "ok", m_pAgent->GetId(), 
			m_sock.Socket(), m_pAgent->Socket(), this, m_pAgent, m_remote.nIp, m_remote.nPort, m_strDomain.c_str());

		return nRet;
	}

	virtual int  OnRead()
	{
		// 1. �յ�Զ�˵����ݺ�ͨ�� proxy_channel ���͸� local. 
		// 2. ��������ֱ�ӹر� proxy. Ҳ���� proxy ���ٽ��� recv, ������Ҳû����. 
		//    ��� proxy��send. ��ô��Ҫ�ȴ� send�ɹ�. (������ send �¼�, ����ܾõ�)
		Assert(m_pAgent);
		int  nRet     = 0;
		int  nRecvLen = 0;
		int  nSize    = 0, i = 0;

		// ���������Ӧ�����ȷ�������. �����д����� ???
		if(!IsSendDataEmpty())
		{
			Assert(IsConnectFinish());
			OnWrite();
			if(!IsSendDataEmpty()) return 0;
		}

		nRet = CTcpClient::OnRead();
		if(nRet < 0) return OnError();
		if(nRet)     return 0;

		do
		{
			char szBuf[1024] = {0};
			nRecvLen = 0;
			nSize    = sizeof(szBuf) - 1;

			nRet = Recv(szBuf, nSize, &nRecvLen, 0);
			if(nRecvLen > 0)
			{
				Assert(m_hpp);
				Assert(m_remote.nIp && m_remote.nPort);
				m_pcapf->WritePcapData(szBuf, nRecvLen, m_remote.nIp, m_remote.nPort, m_proxy.nIp, m_proxy.nPort);
				m_pAgent->Echo(szBuf, nRecvLen);
			}
		}while(nRecvLen == nSize && i++ < MAX_BUF_SIZE);

		if(nRet < 0) return OnError();
		return 0;
	}

	virtual int  OnWrite()
	{
		// ������� Agent�ж���Ϊ�˷�ֹ ������Ҫ�� clt����. 
		// ??? �б�Ҫ��, ��ʱ������. 
		int nRet = CTcpClient::OnWrite();
		if( nRet < 0 || !m_pAgent) return OnError();
		return 0;
	}

	virtual int  OnError(BOOL bDelete = FALSE);


private:
	NetAddr_t           m_proxy;
	CChannel          * m_pAgent;
	CHttpProtoclProxy * m_hpp;
	CProxyPcapFile    * m_pcapf;
};


class CProxyServerPlug : public CTcpClient
{
public:
	CProxyServerPlug()
		: CTcpClient(0x0100007f, 29001)
		, m_bRedirectProxy(false)
	{
	}

	CPcapWriteFile * GetPcapFile()
	{
		Assert(m_pcapf.File());
		return &m_pcapf;
	}

	const char * GetConfigFile()
	{
		return m_strCfg.c_str();
	}

	void SetLogDir(const char * szPath)
	{
		Assert(szPath && *szPath);
		DWORD dwAtti = GetFileAttributesA(szPath);

		if(dwAtti != -1 && dwAtti & FILE_ATTRIBUTE_DIRECTORY)
		{
			m_strWorkDir = szPath;
		}
	}

	int  AllocateId()
	{
		static int g_id = 1;
		return g_id++;
	}

	virtual int  Init(CNetIo * pNetIo)
	{
		char  szPcapLogPath[MAX_PATH] = {0};
		const char * szLogDir = GetExePath(1);
		FILE       * pf = 0;

		if(!m_strWorkDir.empty())
		{
			szLogDir = m_strWorkDir.c_str();
			m_strCfg = m_strWorkDir + "\\mproxy.exe.cfg";
			DWORD dwAttr = GetFileAttributesA(m_strCfg.c_str());
			if(dwAttr == -1 || dwAttr & FILE_ATTRIBUTE_DIRECTORY) m_strCfg.clear();
		}

		if(m_strCfg.empty())
		{
			m_strCfg = GetExePath(0); m_strCfg += ".cfg";
		}

		sprintf(szPcapLogPath, "%s\\mproxy_%u.pcap", szLogDir, _time32(0));
		pf = m_pcapf.Open(szPcapLogPath); Assert(pf);

		// show config.
		LogX(">> proxy, server plug init (%s)-->\n"
			"\t config_path: %s\n"
			"\t log_path: %s\n\n"
			,
			m_bRedirectProxy ? "redirect":"ie proxy", m_strCfg.c_str(), szPcapLogPath
			);

		if(!m_bRedirectProxy) return 0;
		return Connect();
	}

	virtual int  Connect(int nConnectTimeout = -1)
	{
		int nRet = m_sock.Create();
		AssertLog(nRet >= 0);

		nRet = ConnectImpl();
		LogX(">> proxy, server plug connect rfw proxy serivce --> %s (%d, %x:%d)\n", !nRet ? "ok" : "failed", m_sock.Socket(), m_remote.nIp, m_remote.nPort);

		AssertLog(!nRet);
		m_nConnect = S_ConnectOk;

		// ��һ�ν������� pid����ȥ�� service���й���. 
		NetAddr_t q = {0}, r = {0}; char t = 0;
		nRet = RedirectQuery(q, r, t, (SOCKET)GetCurrentProcessId(), 0);
		AssertLog(!nRet);
		return 0;
	}

	int  RedirectQuery(NetAddr_t & query, NetAddr_t & reply, char & ssl_type, SOCKET c, SOCKET s)
	{
		// ��������Ƕ�rising rfw proxy����
		// �� WIN8����, ����Ҫ proxy_client���� client.socket �� server.socket.
		// ��˴˴����ȴ���SOCKET.
		// 
		// d:\rising\esm\soho.code\xfw\test_asyncpacket\test_drv.h
		typedef struct ProxyQueryProtocol_t
		{
			int    ip;
			int    port;
			union
			{
				struct
				{
					SOCKET c, s;
				};
				struct
				{
					int  pid, ssl_type;
				};
			};
		}ProxyQueryProtocol_t;

		int    nRet, nRecvLen = 0;
		ProxyQueryProtocol_t q = {0}, r = {0};

		q.ip = query.nIp; q.port = query.nPort;
		q.c  = c;         q.s    = s;

		nRet = SendData((const char*)&q, sizeof(q));
		nRet = RecvData((char*)&r, sizeof(r), &nRecvLen);

		if(nRecvLen != sizeof(r))
		{
			// falt error. need to reconnect ???
			LogX("** proxy, server plug error to get remote addr ******by rising rfw!!!(%08x:%d)\n", q.ip, q.port);
			return -1;
		}

		ssl_type  = r.ssl_type;
		reply.nIp = r.ip; reply.nPort = r.port;
		return 0;
	}


protected:
	int  SendData(const char * szData, int nLen)
	{
		int nRet, nSendedLen;
		if(nLen <= 0) nLen = strlen(szData);

		nRet = Send(szData, nLen, &nSendedLen, 2);
		if(nRet) OnError();

		return nRet;
	}

	int  RecvData(char * szData, int nSize, int * pRecvLen)
	{
		int nRet;

		nRet = Recv(szData, nSize, pRecvLen, 2);
		if(nRet) OnError();

		return nRet;
	}


public:
	bool           m_bRedirectProxy;
	CPcapWriteFile m_pcapf;
	std::string    m_strCfg, m_strWorkDir;
};


class CHttpProxyChannel	: public CTcpChannel
{
public:
	CHttpProxyChannel(void * lst, Socket_t s, sockaddr_in & addr, CChannel * srv)
		: CTcpChannel(lst, s, addr, srv)
		, m_bCreateClient(true)
		, m_bFirstReply(true)
		, m_nMyExcept(0)
		, m_nQuerySize(0)
		, m_nQueryLen(0)
		, m_nQueryIndex(0)
		, m_bValidHeader(FALSE)
		, m_pSrvPlug(0)
		, m_szCfg(0)
	{
		m_pSrvPlug = (CProxyServerPlug*)m_pServer->UserData();
		Assert(m_pSrvPlug);
		m_szCfg    = m_pSrvPlug->GetConfigFile(); 
		m_id       = m_pSrvPlug->AllocateId();
		m_pcapf.Init(m_pSrvPlug->GetPcapFile()->File());
	}

	virtual int  DeleteSelf()
	{
		delete this;
		return 1;
	}


protected:
	virtual int  OnConnect()
	{
		// �������ӵļ������: 
		// 1 http����, �������, �����ϲ���Ҫ�κδ���
		// 2 https IE����ģʽ, �ͻ��˻��ȷ��� CONNECT xxx.xxx.xxx.xx:443 HTTP/1.1, 
		//   ���������, ��Ҫ proxy�Ƚ��������Ϣ, ��ȥ���� server�õ�֤��. 
		// 3 https ֱ�Ӵ���ģʽ, ������ RFW����ת���˿ں�, ���������Ҫ�ⲿ
		//   ��ȡ server.ip+server.port, Ȼ�������� server�õ�֤��. 
		// ------------------------------------------------------------------
		// 4 https�����������, Ŀǰ���������ⲿ������, 
		//   �ҵ��뷨���Ƚ���һ�������ݽ����ж�, ���� opensslû������ӿ�, ������
		//   �ڽ�������ǰ���� SSL_set_accept_state().
		int nRet = 1;

		Assert(m_remote.nIp && m_remote.nPort);
		switch(m_nConnect)
		{
		case S_RawConnectOk:
			m_nConnect = S_UnkownProto;

		case S_UnkownProto:
			if(!m_pSrvPlug->m_bRedirectProxy)
			{
				// ���� http/https
				char szBuf[1024] = {0};
				int  nRet, nRecvLen;

				nRet = Recv(szBuf, sizeof(szBuf), &nRecvLen, 0);
				if(nRet < 0) return OnError();
				if(nRecvLen > 0)
				{
					m_strBuf.append(szBuf, nRecvLen);
					nRet = DissectProxyProtocol();
					if(nRet < 0) return OnError();
				}
			}
			else
			{
				// ���� remote.ip+remote.portȥȷ������Ҫ���ӵ�IP��PORT. 
				nRet = QueryRedirectIpPort();
				if(nRet < 0) return OnError();
			}

			if(m_nHttps == 1)
			{
				// ҲҪ�ȴ� client������. 
				m_nConnect = S_UnkownProto2;
			}
			else if(m_nHttps == 2)
			{
				// ������ serverȥ��ȡ cert. 
				m_strBuf.clear();
				m_nConnect = S_UnkownProto2;
			}
			else
			{
				nRet = 1;
				break;
			}

		case S_UnkownProto2:
			if(!m_clt.IsConnectFinish()) break;
			if(m_clt.GetConnectState() != S_ConnectOk) return OnError();

			if(m_nHttps == 2)
			{
				#ifdef __USE_SSL__
				Assert(m_clt.SocketClass()->GetVerifiedCert());
				#endif
				Assert(m_strBuf.empty());
				Assert(m_pSrvPlug->m_bRedirectProxy || !m_clt.GetDomain().empty());

				if(!m_pSrvPlug->m_bRedirectProxy)
				{
					Send(g_strHttpsConnectReply.c_str(), g_strHttpsConnectReply.length(), 0, 2);
				}

				#ifdef __USE_SSL__
				m_sock.SetProxySSL(m_clt.SocketClass());
				#endif
			}
			m_nConnect = S_Handshake;

		case S_Handshake:
			nRet = CTcpChannel::OnConnect();
			if(!nRet)
			{
				Assert(m_nConnect == S_ConnectOk);
				if(!m_strBuf.empty())
				{
					m_clt.Echo(m_strBuf.c_str(), m_strBuf.length());
					m_strBuf.clear();
				}
			}
			break;
		}

		LogX(">> proxy, agent accept new connect(%s_%d_%d), (%p, %d, %x:%d)\n", 
			nRet ? "handshake" : "ok", m_id, m_nConnect, 
			this, m_sock.Socket(), m_remote.nIp, m_remote.nPort);

		return nRet;
	}

	virtual int  OnRead()
	{
		int  nRet     = 0, nRecvLen = 0, nSize;
		char szBuf[1024] = {0};

		// ���������Ӧ�����ȷ�������. �����д����� ???
		if(!IsSendDataEmpty())
		{
			Assert(IsConnectFinish());
			OnWrite();
			if(!IsSendDataEmpty()) return 0;
		}

		nRet = CTcpChannel::OnRead();
		if(nRet < 0)    return OnError();
		if(nRet)        return 0;

		nSize = sizeof(szBuf) - 12;
		nRet  = Recv(szBuf, nSize, &nRecvLen, 0);
		if(nRecvLen > 0)
		{
			Assert(m_remote.nIp && m_remote.nPort);
			Assert(m_clt.IsConnectFinish());
			m_clt.Echo(szBuf, nRecvLen);
		}

		if(nRet) return OnError();
		return 0;
	}

	virtual int  OnWrite()
	{
		int nRet = CTcpChannel::OnWrite();
		if( nRet)  return nRet;

		return 0;
	}

	virtual int  OnError(BOOL bDelete = FALSE)
	{
		// *** ������ܻ��� clt �ں��津����� ���� ???
		// ��ȷ�Ĵ�������, 
		// 1 �ж� clt delete����� delete self. ��������ر�, 
		//   �رպ� select ���ظ��״����, ���Կ϶����ٴ��յ� error. 
		// 2 ��� clt �ر�, ��Ҫ�� clt���ж��Ƿ�ر�, ����Ļ�, 
		//   ��� clt ��ʱ���� RW�¼�, ������. 
		// 3 ��� clt �д���������, ����Ҳ���ٴ���. ???
		//   ���� post. ��Ҫ���� ???
		if(CChannel::OnError(bDelete))
		{
			((ChannelList_t*)m_list)->erase(this);

			if(!m_clt.IsSend())  m_clt.Close();
			else                 m_clt.SetExit();

			m_bExit = true;
			if(m_clt.IsDelete() && bDelete)
			{
				LogX("** proxy, channel agent error and delete channel(%p_%d, %d/%d)\n", this, m_id, m_sock.Socket(), m_socket);
				delete this;
			}
			return 1;
		}

		return 0;
	}


private:
	int  DissectProxyProtocol()
	{
		// ���Է���, ���֤�鱻�������������غ�, ����ͻ��������ӵĻ�
		// ����Ҫ�ٴ�ȥ����֤��, ����������һ��. 
		Assert(!m_strBuf.empty());

		const char * b = m_strBuf.c_str();
		const char * p = strstr(b, "\r\n\r\n");
		LogX(">> proxy, agent dissect proxy protocol --->%s\n", b);
		if(!p)
		{
			if(m_strBuf.length() > 1024*1024) return -1;
			return  1;
		}

		int nRet, nMethod, nVersion, nIp = 0, nPort = 0;
		std::string strUri, strUrl, strHost;

		p = strstr(b, "\r\n"); Assert(p);
		nRet = ParserHttpFirstLine(b, p - b, strUri, nMethod, nVersion);
		if(nRet) { LogX("** proxy, agent parser http first line failed2(***), %d(%s)\n", nRet, b); return -1; }

		m_nHttps = nMethod == 3 ? 2:1;
		UriToHost(strUri.c_str(), strHost, strUrl, m_nHttps == 2);
		nRet = HostToAddr(strHost.c_str(), m_nHttps == 2, nIp, nPort);
		if(nRet == 0)
		{
			// ad filter
			std::string strRefer;  // ???
			nRet = CFilter::Instance()->Filter(strUrl, strRefer, m_nHttps == 2);
			if(nRet == 1)
			{
				const char * szAd = "ad filter";
				Echo(szAd, 9);
				m_bCreateClient = false;
				m_nMyExcept     = 0x1002;
				return -1;
			}

			Assert(nIp && nPort);
			nRet = ClientConnect(nIp, nPort, strHost.c_str());
		}

		return nRet;
	}

	int  QueryRedirectIpPort()
	{
		int       nRet;
		NetAddr_t reply = {0};
		SOCKET    clients, servers;

		m_clt.SocketClass()->Create();
		clients = SocketClass()->Socket();
		servers = m_clt.SocketClass()->Socket();
		Assert(clients && servers);
		Assert(m_pSrvPlug->GetConnectState() == S_ConnectOk);

		do
		{
			nRet = m_pSrvPlug->RedirectQuery(m_remote, reply, m_nHttps, clients, servers);
			if(nRet)
			{
				Sleep(1000);
				m_pSrvPlug->Close();
				m_pSrvPlug->Connect();
			}
		}while(nRet);

		if(!m_nHttps)
		{
			// ��ʱ��� HTTPS���� 80/443�˿ڵĻ�, �ȳ��Զ�����, 
			// ����Ͱ��� http������. �����Ļ��������ԭʼ���� ???
			if(reply.nPort == 80)       m_nHttps = 1;
			else if(reply.nPort == 443) m_nHttps = 2;
			else
			{
				char szKey[64] = {0};
				sprintf(szKey, "%s:%d", inet_ntoa(*(in_addr*)&reply.nIp), reply.nPort);
				m_nHttps = GetPrivateProfileIntA("is_https", szKey, 0, m_szCfg) == 0 ? 1 : 2;
			}
		}

		// �˿��ض���ģʽ���ǾͲ����� url��. 
		return ClientConnect(reply.nIp, reply.nPort, 0);
	}

	int  ClientConnect(int nIp, int nPort, const char* szHost)
	{
		m_clt.Init(m_pNetIo);
		m_clt.SetAgent(this);
		m_clt.SetHttpFilter(&m_hpp);
		m_clt.SetProxyPcapFile(&m_pcapf);
		m_clt.SetHttps(m_nHttps == 2);
		m_clt.SetProxyAddr(m_remote.nIp, m_remote.nPort);
		m_clt.SetRemoteAddr(nIp, nPort);
		m_clt.SetDomain(szHost);

		LogX(">> proxy, client connect --->c(%p:%d), s(%p_%d:%d)\n", &m_clt, m_clt.Socket(), this, m_id, Socket());
		return m_clt.Connect(30000);
	}

	// �����������û��ʹ��, ������Ϊ�˽������ܻ��õ�
	// ???
	void CloseClient()
	{
		if(!m_clt.Socket() || !m_socket) return;

		Close();
		NetCtrl(Action_CtrlDel);

		// reset attr.
		m_socket = 0;
		m_hpp.Reset();
	}


private:
	CTcpProxyClient     m_clt;
	CHttpProtoclProxy   m_hpp;
	bool                m_bCreateClient;
	bool                m_bFirstReply;
	int                 m_nMyExcept;
	const char        * m_szCfg;

	// �ڴ���ģʽ�� m_strBuf�����������ݲ��ж�Э��
	std::string         m_strBuf;
	CProxyServerPlug  * m_pSrvPlug;
	CProxyPcapFile      m_pcapf;

	// ���� socket. 
	int                 m_nQuerySize;
	int                 m_nQueryLen;
	int                 m_nQueryIndex;
	BOOL                m_bValidHeader;
	std::string         m_strHost;
};


class CTcpProxyServer : public CTcpServer<CHttpProxyChannel>
{
public:
	CTcpProxyServer(int nPort, bool bIeProxy)
		: CTcpServer(nPort)
	{
		m_plug.m_bRedirectProxy = !bIeProxy;
		m_user = &m_plug;
	}

	virtual int  Init(CNetIo * pNetIo)
	{
		int nRet = 0;

		nRet = m_plug.Init(0);
		if(nRet) return nRet;

		return CTcpServer::Init(pNetIo);
	}


protected:
	int  OnConnect()
	{
		CTcpServer::OnConnect();
		LogX(">> proxy, server listen ok ....(%p,%d, %x:%d)\n", this, m_sock.Socket(), m_local.nIp, m_local.nPort);
		return 0;
	}


private:
	CProxyServerPlug m_plug;
};


inline int  CTcpProxyClient::OnError(BOOL bDelete)
{
	BOOL bDeleteAgent = TRUE;
	if(!bDelete)
	{
		if(m_pAgent->IsSend())
		{
			m_pAgent->SetExit();
		}
		else if(!m_pAgent->IsClose())
		{
			m_pAgent->Close();
			bDeleteAgent = FALSE;
		}
	}

	// ����л�������, Ҫ�������. 
	if(!IsSendDataEmpty())
	{
		LogX(">> proxy, channel client error, send data before close -->%d, (%d,%d), (%d,%d)\n", m_pAgent->GetId(), m_nDataIndex, m_nDataOff, m_strData.length(), m_strData2.length());
		OnWrite();
	}

	if(CTcpClient::OnError(bDelete))
	{
		// agent�Ͳ��ͷ���, �Ѿ��������б���ɾ����. 
		if(bDeleteAgent && m_pAgent->IsClose())
		{
			if(bDelete)
			{
				LogX("** proxy, channel client error and delete channel(%p_%d)\n", m_pAgent, m_pAgent->GetId());
				((CHttpProxyChannel*)m_pAgent)->DeleteSelf();
			}
			else
			{
				LogX("??????\n");
			}
		}
		return 1;
	}

	return 0;
}
