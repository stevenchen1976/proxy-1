#define  __UseNetServiceThread__
#include "service.h"
#include "proxy.h"
#include "logf.h"
#include "path.ipp"


//#define __USE_OPENSSL_100__
#ifdef  __USE_OPENSSL_100__
// 链接的 openssl版本, 老的版本没有 tls1.1, 这样有的网址不支持了
//include -->d:\opensrc\openssl-1.0.0a\inc32
//library -->d:\opensrc\openssl-1.0.0a\ms\bin
//apps.lib crypto.lib ssl.lib
#pragma comment(lib, "d:/opensrc/openssl-1.0.0a/ms/bin/apps.lib")
#pragma comment(lib, "d:/opensrc/openssl-1.0.0a/ms/bin/crypto.lib")
#pragma comment(lib, "d:/opensrc/openssl-1.0.0a/ms/bin/ssl.lib")
#else

// 新的 openssl版本
//include -->d:/opensrc/openssl-1.1.0f.debug_lib_mt/include
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "d:/opensrc/openssl-1.1.0f.debug_lib_mt/libcrypto.lib")
#pragma comment(lib, "d:/opensrc/openssl-1.1.0f.debug_lib_mt/libssl.lib")

// vs2017编译错误
// unresolved external symbol _fprintf
// unresolved external symbol ___iob_func
//#pragma comment(lib, "legacy_stdio_definitions.lib")
//extern "C" { FILE __iob_func[3] = { *stdin,*stdout,*stderr }; }
#endif

// 
// openssl-1.1.0f.debug_lib_mt 内部如果出现异常就会自动退出. 
// d:\opensrc\openssl-1.1.0f.debug_lib_mt\crypto\cryptlib.c:292!OPENSSL_die()
// 


int  Test_Proxy()
{
	INIT_NET_SOCKET();

	// 初始化PLUG (允许错误)
	CFilter::Instance()->Load();

	// 加载 CA证书. 
	#ifdef __USE_SSL__
	AssertLog(!CGobalSSL::GetInstance()->LoadCA());
	#endif


	int nRet = 0;
	CThreadNetService svc;
	nRet = svc.Start();
	AssertLog(!nRet);

	int  nPort = 10000, nIeProxy = 1, nAgain = 0;
	char ch;

	while(1)
	{
		printf(">> ---------------------------------------------------------\n");
		printf(">> 程序配置: 服务器端口(p)= %d, 代理模式(m)= %s. \n", nPort, nIeProxy ? "IE代理":"重定向");
		fflush(stdin); ch = getchar();
		if(ch == 'p')
		{
			while(1)
			{
				printf(">> 设置服务器监听端口(0 ~ 65535): ");
				fflush(stdin); scanf("%d", &nPort);
				if(nPort <= 0 || nPort > 65535) continue;
				break;
			}
		}
		else if(ch == 'm')
		{
			while(1)
			{
				printf(">> 设置模式(重定向=0, IE代理=1): ");
				fflush(stdin); scanf("%d", &nIeProxy);
				if(nIeProxy != 0 && nIeProxy != 1) continue;
				break;
			}
		}
		else break;
	}

	// --------------------------------
	CTcpProxyServer    srvProxy(nPort, nIeProxy != 0);
	CProxyServerPlug * pSrvPlug = (CProxyServerPlug*)srvProxy.UserData();

	pSrvPlug->SetLogDir("d:\\mylog\\proxy");
	nRet = srvProxy.Init(&svc);
	AssertLog(!nRet);

	printf("**********按任意键关闭 svc\n");
	fflush(stdin); getchar();

	srvProxy.Close();
	svc.Exit();
	srvProxy.Uninit();

	return 0;
}


void main()
{
	Test_Proxy();

	printf("**********退出了. 请再按一下\n");
	fflush(stdin); getchar();
}
