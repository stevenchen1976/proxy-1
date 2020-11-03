#pragma  once


#include "sock.h"
#include "openssl/ssl.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"


extern const char * GetExePath(int pt);
class CGobalSSL
{
public:
	typedef std::map<std::string, SSL_SESSION*> SslSessionList_t;
	static CGobalSSL * GetInstance()
	{
		static CGobalSSL g_ssl;
		return &g_ssl;
	}

	static void  Init()
	{
		CGobalSSL::GetInstance();
	}

	int  LoadServerCrt()
	{
		std::string  srv_crt_path, srv_key_path;
		const char * srv_key = "12345678";

		srv_crt_path = GetExePath(1); srv_crt_path += "/certs.self/server2020.crt";
		srv_key_path = GetExePath(1); srv_key_path += "/certs.self/server2020.key";

		SSL_CTX * ctx = SSL_CTX_new(SSLv23_server_method()); Assert(ctx);
		SSL_CTX_set_default_passwd_cb_userdata(ctx, (void*)srv_key);
		AssertLog(SSL_CTX_use_certificate_file(ctx, srv_crt_path.c_str(), SSL_FILETYPE_PEM) > 0);
		AssertLog(SSL_CTX_use_PrivateKey_file(ctx,  srv_key_path.c_str(), SSL_FILETYPE_PEM) > 0);
		AssertLog(SSL_CTX_check_private_key(ctx));

		m_ctx = ctx;
		return 0;
	}

	int  LoadCA()
	{
		// *** 对于服务器来说必须 load, 否则验证是失败的. 
		// 20200923+
		// 1 使用新的 openssl-1.1.0库后. 
		// 2 对于用老的 openssl版本生成的的证书来说，SSL_CTX_use_certificate_file() 会返回错误
		//   跟踪错误为 SSL_R_CA_MD_TOO_WEAK, 查看 SSL_SECOP_CA_MD的说明是 "CA digest algorithm in certificate".
		//   也就是说 CA的数字签名算法太弱了. 
		// 
		std::string  ca_crt_path, ca_key_path;
		const char * ca_key      = "12345678";

		ca_crt_path = GetExePath(1); ca_crt_path += "/certs.self/ca2020.crt";
		ca_key_path = GetExePath(1); ca_key_path += "/certs.self/ca2020.key";

		SSL_CTX * ctx = SSL_CTX_new(SSLv23_server_method()); Assert(ctx);
		SSL_CTX_set_default_passwd_cb_userdata(ctx, (void*)ca_key);
		AssertLog(SSL_CTX_use_certificate_file(ctx, ca_crt_path.c_str(), SSL_FILETYPE_PEM) > 0);
		AssertLog(SSL_CTX_use_PrivateKey_file(ctx,  ca_key_path.c_str(), SSL_FILETYPE_PEM) > 0);
		AssertLog(SSL_CTX_check_private_key(ctx));

		m_ctx  = ctx;
		m_cak  = SSL_CTX_get0_privatekey(ctx);
		m_cax  = SSL_CTX_get0_certificate(ctx);

		// ------------------------------------------
		//#define __TEST_CREATE_CERT2__
		#ifdef  __TEST_CREATE_CERT2__
		SSL_CTX  * ctx2  = SSL_CTX_new(SSLv23_server_method()); Assert(ctx);
		X509     * cert2 = 0;

		FILE * pf = fopen("d:/project.2016/proxy/bin/.baidu.com.crt", "r"); Assert(pf);
		cert2 = PEM_read_X509(pf, 0, 0, 0);
		fclose(pf);

		GetCertByCert(ctx2, cert2);
		#endif
		return 0;
	}

	SSL_CTX * GetSSL()
	{
		return m_ctx;
	}

	int  GetCertByCert(SSL_CTX * ctx, X509 * old_cert, const char * host)
	{
		int   nRet;
		char  szHost[256] = {0};
		std::string strCertPath, strHost2;

		// 发现证书的 commonName和 host不同. 
		if(!host || !*host)
		{
			GetCertCommonName(old_cert, szHost, sizeof(szHost));
			host = szHost;
		}
		else
		{
			const char * p = strchr(host, ':');
			if(p)
			{
				strHost2.append(host, p-host);
				host = strHost2.c_str();
			}
		}

		do
		{
			const char * p = strchr(host, '.');
			if(!p) break;

			if(FindCacheCert(ctx, host, ".crt", true, strCertPath)) return 0;
			host = p+1;
		}while(1);

		if(!strHost2.empty())
		{
			GetCertCommonName(old_cert, szHost, sizeof(szHost));
			FindCacheCert(ctx, szHost, ".crt", true, strCertPath);
		}
		LogX(">> sockets, create new self cert -->%s\n", szHost);
		nRet = CreateCertByCert(ctx, old_cert, strCertPath.c_str()); Assert(!nRet);
		return 0;
	}

	int  GetOldCert(SSL_CTX * ctx, const char * path)
	{
		int nRet;
		X509     * cert = 0;
		EVP_PKEY * pkey = 0;

		Assert(path);
		FILE * pf = fopen(path, "r"); Assert(pf);
		cert = PEM_read_X509(pf, 0, 0, 0);
		pkey = PEM_read_PrivateKey(pf, 0, 0, 0);
		fclose(pf);

		Assert(cert);
		if(cert) nRet = SSL_CTX_use_certificate(ctx, cert); Assert(nRet);
		if(pkey) nRet = SSL_CTX_use_PrivateKey(ctx, pkey); Assert(nRet);

		LogX("== sockets, ssl set cert -->%p,%p,%s\n", cert, pkey, path);
		EVP_PKEY_free(pkey);
		X509_free(cert);
		return 0;
	}

	int  CreateCertByCert(SSL_CTX * ctx, X509 * cert, const char * path)
	{
		// 1. gen key.
		int        nRet;
		EVP_PKEY * pkey = EVP_PKEY_new();
		RSA      * rsa = RSA_generate_key(2048, 0x10001/*65537*/, 0, 0);
		nRet = EVP_PKEY_assign_RSA(pkey, rsa);

		// 2 x509_REQ.sign(pkey)
		Assert(pkey && rsa && nRet);
		X509_REQ  * req = X509_REQ_new(); Assert(req);
		X509_NAME * req_name  = X509_REQ_get_subject_name(req); Assert(req_name);
		X509_NAME * cert_name = X509_get_subject_name(cert); Assert(cert_name);

		for(int i = 0; i < X509_NAME_entry_count(cert_name); i++)
		{
			X509_NAME_ENTRY * e = X509_NAME_get_entry(cert_name, i);
			X509_NAME_add_entry(req_name, e, -1, 0);

			#ifdef _DEBUG
			ASN1_OBJECT * o = X509_NAME_ENTRY_get_object(e);
			ASN1_STRING * d = X509_NAME_ENTRY_get_data(e);
			int id = OBJ_obj2nid(o);
			const char * key = OBJ_nid2sn(id);
			unsigned char * str = ASN1_STRING_data(d);
			printf(">> (%d)%s= %s\n", id, key, str);
			#endif
		}

		nRet = X509_REQ_set_pubkey(req, pkey);  Assert(nRet);
		nRet = X509_REQ_sign(req, pkey, EVP_sha256());  Assert(nRet);

		// 3 x509.sign(ca_key).
		X509 * x = X509_new(); Assert(x);
		nRet = X509_set_version(x, 2); Assert(nRet);
		ASN1_INTEGER_set(X509_get_serialNumber(x), (int)_time32(0)*1000);
		X509_gmtime_adj(X509_get_notBefore(x), 0);
		X509_gmtime_adj(X509_get_notAfter(x),  (long)3650*24*60*60);
		nRet = X509_set_issuer_name(x, X509_get_subject_name(m_cax));
		nRet = X509_set_subject_name(x, req_name); Assert(nRet);
		
		const STACK_OF(X509_EXTENSION) * exts;
		if(exts = X509_get0_extensions(cert))
		{
			for(int i = 0, n = exts ? sk_X509_EXTENSION_num(exts):0; i < n; i++)
			{
				X509_EXTENSION * e = sk_X509_EXTENSION_value(exts, i);   // x509.h
				ASN1_OBJECT * o = X509_EXTENSION_get_object(e); Assert(o);

				int id = OBJ_obj2nid(o);
				if(id == NID_subject_alt_name || id == NID_basic_constraints || id == NID_ext_key_usage)
				{
					nRet = X509_add_ext(x, e, -1); Assert(nRet > 0);
				}
			}
		}

		nRet = X509_set_pubkey(x, pkey); Assert(nRet);
		nRet = X509_sign(x, m_cak, EVP_sha256()); Assert(nRet);

		// 4. out file.
		FILE * pf = fopen(path, "w"); Assert(pf);
		BIO  * bio = BIO_new(BIO_s_file()); Assert(bio); 
		BIO_set_fp(bio, pf, BIO_NOCLOSE);
		PEM_write_bio_X509(bio, x);
		PEM_write_PrivateKey(pf, pkey, 0, 0, 0, 0, 0);
		BIO_free(bio); fclose(pf);

		// 5.
		nRet = SSL_CTX_use_certificate(ctx, x); Assert(nRet);
		nRet = SSL_CTX_use_PrivateKey(ctx, pkey); Assert(nRet);
		EVP_PKEY_free(pkey);
		X509_free(cert);
		return 0;
	}

	// 这个函数最终还是没有起作用, 因为没有调用 CacheServerSession(). 
	// 而如果起了作用也还是不能解决 CacheServerSession()所说的问题
	int  FindClientCacheCert(SSL * s, SSL_CTX * ctx, const char * host)
	{
		Assert(host);
		int          nRet;
		std::string  strHost2 = host, strPath;
		const char * p = strchr(host, ':');
		if(p)
		{
			strHost2.clear();
			strHost2.append(host, p-host);
			host = strHost2.c_str();
		}

		do
		{
			p = strchr(host, '.');
			if(!p) break;

			// 此处不是发现证书, 而是去发现 session. 
			//if(FindCacheCert(ctx, host, ".crt", false, strPath)) return 0;
			SslSessionList_t::iterator it = m_lstSession.find(host);
			if(it != m_lstSession.end())
			{
				//nRet = SSL_CTX_add_session(ctx, it->second); Assert(nRet > 0);
				nRet = SSL_set_session(s, it->second);
				LogX(">> sockets, ssl client to find session -->%s/%s,%p,(%p,%p)\n", strHost2.c_str(), host, it->second, s, ctx);
				return 0;
			}

			host = p+1;
		}while(1);

		LogX(">> sockets, ssl client to find session failed -->%s\n", strHost2.c_str());
		return -1;
	}

	void CacheServerSession(const SSL * ssl, X509 * cert, const char * name)
	{
		// baidu的网址中像下列的必须使用 seesion_id去连接, 否则获取的证书不对导致连接关闭
		// https://pics6.baidu.com/feed/faf2b2119313b07e54f656eb3761cb2495dd8cc3.jpeg?token=df462792f4b5b8311c4c3040659e2a05
		// 上面的网址获取出来的证书不是 baidu的证书, 而是 cdn.bcebos.com.crt. 这样在 chrome里
		// 会校验失败. 
		char  szHost[256] = {0};
		SSL_SESSION * sess = SSL_get_session(ssl);
		if(!sess) return;

		if(!name)
		{
			GetCertCommonName(cert, szHost, sizeof(szHost)); Assert(szHost[0]);
			name = szHost;
		}

		SslSessionList_t::iterator it = m_lstSession.find(name);
		if(it != m_lstSession.end())
		{
			//if(stricmp(name, "baidu.com")) Assert(sess == it->second);
			SSL_SESSION_free(it->second);
			return ;
		}

		SSL_SESSION_up_ref(sess);
		m_lstSession[name] = sess;
		CacheCert(cert, name, ".crt");
		LogX("== sockets, ssl client to cache server session -->%s:%p\n", name, sess);
	}

	void CacheCert(X509 * cert, const char * name, const char * suffix)
	{
		// 这儿缓存的肯定不是我们生成的证书
		std::string  strCertPath;
		char         szHost[256] = {0};

		if(!name)
		{
			GetCertCommonName(cert, szHost, sizeof(szHost));
			name = szHost; Assert(*name);
		}

		strCertPath  = GetExePath(1); strCertPath += "/certs.ok/";
		strCertPath += name; strCertPath += suffix;

		FILE * pf = fopen(strCertPath.c_str(), "w"); Assert(pf);
		BIO  * bio = BIO_new(BIO_s_file()); Assert(bio); 
		BIO_set_fp(bio, pf, BIO_NOCLOSE);
		PEM_write_bio_X509(bio, cert);
		BIO_free(bio); fclose(pf);
	}

	bool FindCacheCert(SSL_CTX * ctx, const char * name, const char * suffix, bool bSelfSign, std::string & strCertPath)
	{
		int   nRet,  nAttr;

		strCertPath  = GetExePath(1); strCertPath += bSelfSign ? "/certs/" : "/certs.ok/";
		strCertPath += name; strCertPath += suffix;
		nAttr = GetFileAttributesA(strCertPath.c_str());
		if(nAttr != -1)
		{
			Assert(!(nAttr & FILE_ATTRIBUTE_DIRECTORY));
			nRet = GetOldCert(ctx, strCertPath.c_str()); Assert(!nRet);
			return true;
		}

		return false;
	}


private:
	int  GetCertCommonName(X509 * cert, char * name, int size)
	{
		X509_NAME * req_name = X509_get_subject_name(cert); Assert(req_name);
		int nRet = X509_NAME_get_text_by_NID(req_name, NID_commonName, name, size); Assert(nRet > 0);

		int nLen = strlen(name);
		for(int i = 0; i < nLen; i++)
		{
			if(name[i] == '*') name[i] = '#';
		}

		return 0;
	}

	int  CreateCert(const char * domain)
	{
		// 下面这个流程是抄 goagent:proxy.py中的
		const char * common_name = "baidu.com";
		int nRet = 0;

		// 1. gen key.
		EVP_PKEY * pkey = EVP_PKEY_new();
		RSA * rsa = RSA_generate_key(2048, 0x10001/*65537*/, 0, 0);
		nRet = EVP_PKEY_assign_RSA(pkey, rsa);

		// 2 x509_REQ.sign(pkey)
		Assert(pkey && rsa && nRet);
		X509_REQ  * req = X509_REQ_new(); Assert(req);
		X509_NAME * req_name = X509_REQ_get_subject_name(req); Assert(req_name);
		// c=coutry, ST=province, L=locality, O=organistaion, OU=department, emailAddress, CN=cname.
		nRet = X509_NAME_add_entry_by_txt(req_name, "C",  MBSTRING_ASC, (const unsigned char *)"CN", -1, -1, 0); Assert(nRet);
		nRet = X509_NAME_add_entry_by_txt(req_name, "ST", MBSTRING_ASC, (const unsigned char *)"beijing", -1, -1, 0); Assert(nRet);
		nRet = X509_NAME_add_entry_by_txt(req_name, "O",  MBSTRING_ASC, (const unsigned char *)"rising", -1, -1, 0); Assert(nRet);
		nRet = X509_NAME_add_entry_by_txt(req_name, "CN", MBSTRING_ASC, (const unsigned char *)common_name, -1, -1, 0); Assert(nRet);

		STACK_OF(X509_EXTENSION) * exts = sk_X509_EXTENSION_new_null();
		openssl_add_ext(exts, NID_subject_alt_name, "???");
		X509_REQ_add_extensions(req, exts);
		sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

		nRet = X509_REQ_set_pubkey(req, pkey);  Assert(nRet);
		nRet = X509_REQ_sign(req, pkey, EVP_sha256());  Assert(nRet);

		// 3 x509.sign(ca_key).
		X509 * x = X509_new(); Assert(x);
		nRet = X509_set_version(x, 2); Assert(nRet);
		ASN1_INTEGER_set(X509_get_serialNumber(x), (int)_time32(0)*1000);
		X509_gmtime_adj(X509_get_notBefore(x), 0);
		X509_gmtime_adj(X509_get_notAfter(x),  (long)3650*24*60*60);
		nRet = X509_set_issuer_name(x, X509_get_subject_name(m_cax));
		nRet = X509_set_subject_name(x, req_name); Assert(nRet);
		nRet = X509_set_pubkey(x, pkey); Assert(nRet);
		nRet = X509_sign(x, m_cak, EVP_sha256()); Assert(nRet);

		// 4. out file.
		FILE * pf = fopen("d:/project.2016/proxy/Bin/test.crt", "w"); Assert(pf);
		BIO  * bio = BIO_new(BIO_s_file()); Assert(bio); 
		BIO_set_fp(bio, pf, BIO_NOCLOSE);
		PEM_write_bio_X509(bio, x);
		PEM_write_PrivateKey(pf, pkey, 0, 0, 0, 0, 0);
		BIO_free(bio); fclose(pf);

		return 0;
	}

	int  ParserCert(X509 * cert)
	{
		// 主要关心的有 subject_name. extension. 不关心 到期时间等. 
		// 不需要free. 
		X509_NAME * subject = X509_get_subject_name(cert);
		for(int i = 0; i < X509_NAME_entry_count(subject); i++)
		{
			X509_NAME_ENTRY * e = X509_NAME_get_entry(subject, i);
			ASN1_OBJECT * o = X509_NAME_ENTRY_get_object(e);
			ASN1_STRING * d = X509_NAME_ENTRY_get_data(e);

			int id = OBJ_obj2nid(o);
			const char * key = OBJ_nid2sn(id);
			unsigned char * str = ASN1_STRING_data(d);
			printf(">> (%d)%s= %s\n", id, key, str);
		}

		// extension里配置下列三项就可以了:
		// NID_subject_alt_name, NID_basic_constraints, NID_ext_key_usage
		printf("------------------------------------\n");
		const STACK_OF(X509_EXTENSION) * exts = X509_get0_extensions(cert);
		for(int i = 0, n = exts ? sk_X509_EXTENSION_num(exts):0; i < n; i++)
		{
			X509_EXTENSION * e = sk_X509_EXTENSION_value(exts, i);   // x509.h
			ASN1_OBJECT * o = X509_EXTENSION_get_object(e);
			ASN1_STRING * d = X509_EXTENSION_get_data(e);

			int id = OBJ_obj2nid(o);
			const char * key = OBJ_nid2sn(id);
			const unsigned char * data = ASN1_STRING_get0_data(d);
			int len = ASN1_STRING_length(d);
			printf(">> (%d)%s= %d:%s\n", id, key, len, data);
		}
		return 0;
	}


private:
	CGobalSSL()
		: m_ctx(0)
		, m_cax(0)
		, m_cak(0)
	{
		int nRet;
		SSL_load_error_strings();
		nRet = SSLeay_add_ssl_algorithms();
		OpenSSL_add_all_algorithms();
	}

	~CGobalSSL()
	{
		EVP_cleanup();
		CRYPTO_cleanup_all_ex_data();
	}

	bool openssl_add_ext(STACK_OF(X509_EXTENSION) * exts, int id, char * value)
	{
		X509_EXTENSION * e;
		e = X509V3_EXT_conf_nid(0, 0, id, value); // x509v3.h
		if(!e) return 0;

		sk_X509_EXTENSION_push(exts, e);
		return 1;
	}


private:
	SSL_CTX          * m_ctx;
	EVP_PKEY         * m_cak;
	X509             * m_cax;
	SslSessionList_t   m_lstSession;
};


enum enumSslConnectState
{ 
	HandShake_Unknown = 0, 
	HandShake_Start, 
	HandShake_Continue, 
	HandShake_End, 
	HandShake_End2, 
};


// socket with ssl. 
class CSocketWS : public CSocket
{
public:
	CSocketWS(Socket_t s = 0, int nProtocol = IPPROTO_TCP)
		: CSocket(s, nProtocol)
		, m_ctx(0)
		, m_ssl(0)
		, m_cert(0)
		, m_state(HandShake_Unknown)
		, m_error(0)
		, m_ref(false)
		, m_srv(false)
	{}

	~CSocketWS()     {}

	SSL_CTX * Context() 
	{ 
		return m_ctx;
	}

	X509 * GetVerifiedCert()
	{
		return m_cert;
	}


	int  SetServerSSL()
	{
		Assert(!m_ctx);
		m_https = TRUE; m_srv = true; m_ref = true;
		m_ctx   = CGobalSSL::GetInstance()->GetSSL();
		AssertLog(m_ctx);
		return 0;
	}

	int  SetClientSSL(const char * szHost)
	{
		Assert(!m_ctx);
		m_https = TRUE; m_srv = false; m_host = szHost;
		m_ctx   = SSL_CTX_new(SSLv23_client_method());
		AssertLog(m_ctx);

		// SSL_get1_session
		// SSL_set_session/SSL_CTX_add_session.
		//Assert(szHost);
		//CGobalSSL::GetInstance()->FindClientCacheCert(m_ctx, szHost);
		return 0;
	}

	int  SetProxySSL(CSocketWS * pServerWs)
	{
		// 代理模式. 
		Assert(!m_ctx);
		Assert(pServerWs && pServerWs->m_cert);
		m_https = TRUE; m_srv = true;
		m_ctx   = SSL_CTX_new(SSLv23_server_method());
		AssertLog(m_ctx);

		m_host = pServerWs->m_host;
		CGobalSSL::GetInstance()->GetCertByCert(m_ctx, pServerWs->m_cert, m_host.c_str());
		return 0;
	}

	int  HandShake()
	{
		int nRet = 0, nErr = 0;
		LogX("==================== sockets, handshake (%d)\n", m_socket);
		switch(m_state)
		{
		case HandShake_Unknown:
			m_state  = HandShake_End;
			if(m_https && m_bNoBlock) m_state = HandShake_Start;
			else return HandShake();

		case HandShake_Start:
			Assert(m_ctx);
			Assert(!m_ssl);
			Assert(m_socket);
			Assert(m_bNoBlock);

			AssertLog(m_ssl = SSL_new(m_ctx));
			SSL_CTX_set_session_cache_mode(m_ctx, SSL_SESS_CACHE_CLIENT);
			CGobalSSL::GetInstance()->FindClientCacheCert(m_ssl, m_ctx, m_host.c_str());
			AssertLog(SSL_set_fd(m_ssl, m_socket) != 0);                                                                                                                                        
			if(m_srv) SSL_set_accept_state(m_ssl);
			else      SSL_set_connect_state(m_ssl);
			m_state  = HandShake_Continue;

		case HandShake_Continue:
			m_event  = 0;
			nRet     = SSL_do_handshake(m_ssl);
			if(nRet != 1) nErr = GetLastError(nRet);
			else          nRet = 0;
			printf("***********handshake: %d,%d\n", nRet, nErr); // m_ssl->packet_length);
			if(m_event)
			{
				// 如果服务器长时间没有返回的话, 会在此处循环. 
				// 而 Sleep()会卡整个 netio线程因此不能设置. 
				//Sleep(1000);
				return 1;
			}
			m_state  = HandShake_End;

		case HandShake_End:
			if(!nRet && m_ssl)
			{
				X509 * pX509  = SSL_get_peer_certificate(m_ssl);
				char * szName = 0;

				if(pX509) szName = X509_NAME_oneline(X509_get_subject_name(pX509), 0, 0);
				//X509_free(pX509);

				// X509_V_OK
				int nRet = SSL_get_verify_result(m_ssl);
				m_cert   = pX509;

				//if(pX509)  CGobalSSL::GetInstance()->CacheServerSession(m_ssl, pX509, 0);
				LogX(">> sockets, connect end ------------%p_%d\n\t(%s)\n", pX509, nRet, szName);
			}
			m_state = HandShake_End2;
			break;
		case HandShake_End2:
			printf(">> sockets, ..............\n");
			break;
		}

		return nRet;
	}


public:
	virtual void Close()
	{
		if(m_ssl)
		{
			SSL_shutdown(m_ssl);
			SSL_free(m_ssl);
			m_ssl = 0;
		}

		CSocket::Close();

		if(m_ctx && !m_ref)
		{
			SSL_CTX_free(m_ctx);
			m_ctx = 0;
		}
	}

	virtual int  Accept(Socket_t * ps, sockaddr_in * paddr)
	{
		AssertLog(ps);
		AssertLog(paddr);

		int nRet = 0;
		nRet = CSocket::Accept(ps, paddr);
		if(nRet) return nRet;

		return SyncAccept();
	}

	virtual int  Connect(int nIp, int nPort)
	{
		int nRet = 0;
		nRet = CSocket::Connect(nIp, nPort);
		if(nRet) return nRet;

		return SyncConnect();
	}

	virtual int  Connect(const char * szDomain)
	{
		int nRet = 0;
		nRet = CSocket::Connect(szDomain);
		if(nRet) return nRet;

		return SyncConnect();
	}

	virtual int  Send(const char * pbData, int nLen, int nType)
	{
		// type现阶段有几种情况: 
		// =1, 表示 force raw. 
		// =2, 表示 外部调用. 
		if(m_https && !(nType & 1))
		{
			Assert(m_ctx);
			Assert(m_ssl);

			return SSL_write(m_ssl, pbData, nLen);
		}

		return CSocket::Send(pbData, nLen, nType);
	}

	virtual int  Recv(char * pbBuf, int nSize, int nType)
	{
		if(m_https && !(nType & 1))
		{
			Assert(m_ctx);
			Assert(m_ssl);
			return SSL_read(m_ssl, pbBuf, nSize);
		}

		return CSocket::Recv(pbBuf, nSize, nType);
	}


	virtual int  GetLastError(int & nRet)
	{
		if(!m_https || !m_ssl) return CSocket::GetLastError(nRet);

		m_event = 0;
		m_error = SSL_get_error(m_ssl, nRet);
		switch(m_error)
		{
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_WANT_READ:
			m_event = Event_NetReadWrite;
			nRet    = 0;
			LogX(">> sockets, ssl last error code = (%d, %d, %d)\n", nRet, m_error, m_event);
			break;

		default:
			m_event = 0;
			nRet    = -1;
			LogX("** sockets, ssl last error code = (%d, %d, %d)\n", nRet, m_error, m_event);
			break;
		}

		return m_error;
	}


private:
	int  SyncConnect()
	{
		if(m_https && !m_bNoBlock)
		{
			Assert(m_ctx);
			Assert(!m_ssl);

			AssertLog(m_ssl = SSL_new(m_ctx));
			AssertLog(SSL_set_fd(m_ssl, m_socket) != 0);
			AssertLog(SSL_connect(m_ssl) >= 0);
		}

		return 0;
	}

	int  SyncAccept()
	{
		if(m_https && !m_bNoBlock)
		{
			AssertLog(m_ctx);
			Assert(!m_ssl);

			AssertLog(m_ssl = SSL_new(m_ctx));
			AssertLog(SSL_set_fd(m_ssl, m_socket) != 0);
			AssertLog(SSL_accept(m_ssl) >= 0);
		}

		return 0;
	}


private:
	SSL_CTX   * m_ctx;
	SSL       * m_ssl;
	X509      * m_cert;
	int         m_state, m_error;
	bool        m_ref, m_srv;
	std::string m_host;
};
