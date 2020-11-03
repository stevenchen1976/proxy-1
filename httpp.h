#include "common.h"
#include "logf.h"


// for https: connect 
const std::string g_strHttpsConnectReply = 
	"HTTP/1.0 200 Connection established\r\n"
	"Proxy-agent: cgproxy/1.1\r\n"
	"\r\n";


inline bool  CheckHttpMethod(const char * szMethod, int & nMethod)
{
	static const char * g_szHttpMethod[] = 
	{
		"get", 
		"post", 
		"head", 
		"connect", 
		"put", 
		"delete", 
		"trace", 
		"options",  // ???
	};

	bool bValid = false;
	for(int i = 0; i < _countof(g_szHttpMethod); i++)
	{
		if(!strcmp(g_szHttpMethod[i], szMethod))
		{
			nMethod = i;
			bValid = true;
			break;
		}
	}

	return bValid;
}

inline int  ParserHttpFirstLine(const char * szFirst, int nLen, std::string & strUrl, int & nMethod, int & nVersion)
{
	bool  bValid = false;
	const char * p1 = 0, * p2 = 0;
	std::string  strLine(szFirst, nLen); strlwr(&strLine[0]);
	std::string  strTmp;

	p1 = strchr(strLine.c_str(), ' '); if(!p1) return -1;
	p2 = strchr(p1 + 1, ' ');          if(!p2) return -2;

	static const char * g_szHttpMethod[] = 
	{
		"get", 
		"post", 
		"head", 
		"connect", 
		"put", 
		"delete", 
		"trace", 
		"options",  // ???
	};
	static const char * g_szHttpVersion[] = 
	{
		"http/1.0", 
		"http/1.1", 
	};

	strTmp.append(strLine.c_str(), p1 - strLine.c_str());
	bValid = CheckHttpMethod(strTmp.c_str(), nMethod);
	if(!bValid) return -3;

	strTmp.clear(); strTmp.append(p2 + 1); bValid = false;
	for(int i = 0; i < _countof(g_szHttpVersion); i++)
	{
		if(!strcmp(g_szHttpVersion[i], strTmp.c_str()))
		{
			nVersion = i;
			bValid = true;
			break;
		}
	}
	if(!bValid) return -4;

	strUrl.append(p1 + 1, p2 - p1 - 1);
	return strUrl.empty() ? -5 : 0;
}

int  UriToHost(const char * szUri, std::string & strHost, std::string & strUrl, bool bHttps)
{
	const char * szTmp1 = 0, * szTmp2 = 0;
	bool  bIsHttps = false;

	szTmp1 = strstr(szUri, bHttps ? "https://" : "http://");

	if(szTmp1)    szTmp1  += bHttps ? 8 : 7;
	else          szTmp1   = szUri;

	Assert(szTmp1);
	strUrl.append(szTmp1);
	szTmp1  = strUrl.c_str();
	szTmp2  = strchr(szTmp1, '/');

	if(szTmp2) strHost = std::string(szTmp1, szTmp2 - szTmp1);
	else       strHost = strUrl;
	return 0;
}

int  HostToAddr(const char * szHost, bool bHttps, int & nIp, int & nPort)
{
	std::string  strHost;
	const char * szPort;

	if(szPort = strchr(szHost, ':'))
	{
		nPort   = atoi(szPort + 1);
		strHost = std::string(szHost, szPort - szHost);
		szHost  = strHost.c_str();
	}
	else
	{
		nPort   = bHttps ? 443 : 80;
	}

	struct hostent * pHost = gethostbyname(szHost);
	AssertLog(pHost);

	LogX("[test]: _________________%s\n", szHost);
	nIp = *((unsigned long*)pHost->h_addr_list[0]);
	return 0;
}



class CHttpProtoclProxy
{
public:
	CHttpProtoclProxy()
		: m_szQuery(0)
		, m_nQueryLen(0)
		, m_szReply(0)
		, m_nReplyLen(0)
		, m_bHttps(false)
		, m_bFirstQuery(true)
		, m_bFirstReply(true)
	{}

	void Reset()
	{
		m_szQuery = 0;
		m_nQueryLen = 0;
		m_szReply = 0;
		m_nReplyLen = 0;
		m_bHttps = 0;
		m_bFirstQuery = true;
		m_bFirstReply = true;
	}

	bool IsHttps()
	{
		return m_bHttps;
	}

	void GetReply(const char ** szReply, int & nReplyLen)
	{
		if(m_bHttps && m_bFirstReply)
		{
			*szReply      = g_strHttpsConnectReply.c_str();
			nReplyLen     = g_strHttpsConnectReply.length();
			m_bFirstReply = false;
			return ;
		}

		*szReply  = m_szReply;
		nReplyLen = m_nReplyLen;
	}

	void GetForward(const char ** szSend, int & nSendLen)
	{
		if(m_bHttps && m_bFirstQuery)
		{
			const char * szContext = strstr(m_szQuery, "\r\n\r\n");
			if(szContext)
			{
				int nLen = szContext - m_szQuery;
				if(nLen > 0 &&  nLen < m_nQueryLen)
				{
					*szSend  = szContext + 4;
					nSendLen = m_nQueryLen - nLen - 4;
				}
			}
			m_bFirstQuery = false;
			return;
		}

		*szSend  = m_szQuery;
		nSendLen = m_nQueryLen;
	}

	void SetForward(const char * pbData, int nDataLen)
	{
		// 如果我们不解析内容就不需要 保存数据. 
		//Assert(pbData);
		//Assert(nDataLen);

		m_szQuery   = pbData;
		m_nQueryLen = nDataLen;
	}

	void SetReply(const char * pbData, int nDataLen)
	{
		Assert(pbData);
		Assert(nDataLen);

		m_szReply   = pbData;
		m_nReplyLen = nDataLen;
	}

	int  QueryToAddr(int & nIp, int & nPort)
	{
		AssertLog(m_szQuery);
		AssertLog(m_nQueryLen);
		const char * szHttpQuery = m_szQuery;

		// 可能不够长. 基本上没有这个可能. ???
		const char * szTmp = 0;
		szTmp = strstr(szHttpQuery, "\r\n");
		AssertLog(szTmp && szTmp != szHttpQuery);

		int nMethod = -1, nVersion = -1;
		std::string strUri;
		int nRet = ParserHttpFirstLine(szHttpQuery, szTmp - szHttpQuery, strUri, nMethod, nVersion);
		if(nRet) { LogX("[error]: proxy agent, parser http first line failed1, %d(%s)\n", nRet, szHttpQuery); return nRet; }

		// connect == https
		if(nMethod == 3) m_bHttps = true;

		// http文档. ***
		// 当代理服务器产生请求时，绝对URI地址是不可缺少的．
		// 所有基于HTTP/1.1的服务器必须接受绝对URL地址的组成，虽然基于HTTP/1.1的客户机将只产生请求发给代理服务器
		std::string strHost, strUrl, strRefer;
		UriToHost(strUri.c_str(), strHost, strUrl, m_bHttps == TRUE);

		if(strHost.empty()) { GetHostByHeader(strHost); strUrl.insert(0, strHost.c_str()); }
		AssertLog(!strHost.empty());

		// filter.
		GetReferByHeader(strRefer);
		nRet = CFilter::Instance()->Filter(strUrl, strRefer, m_bHttps);
		if(nRet) return nRet;

		return HostToAddr(strHost.c_str(), m_bHttps, nIp, nPort);
	}


private:
	int  GetHostByHeader(std::string & strHost)
	{
		GetHeaderValue(strHost, "Host:");
		if(strHost.empty()) GetHeaderValue(strHost, "host:");
		AssertLog(!strHost.empty());
		return 0;
	}

	void GetReferByHeader(std::string & strRefer)
	{
		GetHeaderValue(strRefer, "Referer:");
	}

	int  GetHeaderValue(std::string & strValue, const char * szKey)
	{
		AssertLog(m_szQuery);
		AssertLog(m_nQueryLen);
		const char * szHeader = m_szQuery;

		// 不考虑头部不完整 ???
		const char * szValue  = strstr(szHeader, szKey);
		if(!szValue) return 0;

		szValue += strlen(szKey);
		while(*szValue == ' ') szValue++;
		AssertLog(szValue && *szValue);

		const char * szEnd  = strstr(szValue, "\r\n");
		AssertLog(szEnd && *szEnd);

		strValue = std::string(szValue, szEnd - szValue);
		return 0;
	}


private:
	const char * m_szQuery;
	int          m_nQueryLen;
	const char * m_szReply;
	int          m_nReplyLen;
	bool         m_bHttps;
	bool         m_bFirstQuery;
	bool         m_bFirstReply;
};
