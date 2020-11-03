#define  __UseNetServiceThread__
#include "service.h"
#include "proxy.h"
#include "logf.h"
#include "path.ipp"


//#define __USE_OPENSSL_100__
#ifdef  __USE_OPENSSL_100__
// ���ӵ� openssl�汾, �ϵİ汾û�� tls1.1, �����е���ַ��֧����
//include -->d:\opensrc\openssl-1.0.0a\inc32
//library -->d:\opensrc\openssl-1.0.0a\ms\bin
//apps.lib crypto.lib ssl.lib
#pragma comment(lib, "d:/opensrc/openssl-1.0.0a/ms/bin/apps.lib")
#pragma comment(lib, "d:/opensrc/openssl-1.0.0a/ms/bin/crypto.lib")
#pragma comment(lib, "d:/opensrc/openssl-1.0.0a/ms/bin/ssl.lib")
#else

// �µ� openssl�汾
//include -->d:/opensrc/openssl-1.1.0f.debug_lib_mt/include
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "d:/opensrc/openssl-1.1.0f.debug_lib_mt/libcrypto.lib")
#pragma comment(lib, "d:/opensrc/openssl-1.1.0f.debug_lib_mt/libssl.lib")

// vs2017�������
// unresolved external symbol _fprintf
// unresolved external symbol ___iob_func
//#pragma comment(lib, "legacy_stdio_definitions.lib")
//extern "C" { FILE __iob_func[3] = { *stdin,*stdout,*stderr }; }
#endif

// 
// openssl-1.1.0f.debug_lib_mt �ڲ���������쳣�ͻ��Զ��˳�. 
// d:\opensrc\openssl-1.1.0f.debug_lib_mt\crypto\cryptlib.c:292!OPENSSL_die()
// 


int  Test_Proxy()
{
	INIT_NET_SOCKET();

	// ��ʼ��PLUG (�������)
	CFilter::Instance()->Load();

	// ���� CA֤��. 
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
		printf(">> ��������: �������˿�(p)= %d, ����ģʽ(m)= %s. \n", nPort, nIeProxy ? "IE����":"�ض���");
		fflush(stdin); ch = getchar();
		if(ch == 'p')
		{
			while(1)
			{
				printf(">> ���÷����������˿�(0 ~ 65535): ");
				fflush(stdin); scanf("%d", &nPort);
				if(nPort <= 0 || nPort > 65535) continue;
				break;
			}
		}
		else if(ch == 'm')
		{
			while(1)
			{
				printf(">> ����ģʽ(�ض���=0, IE����=1): ");
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

	printf("**********��������ر� svc\n");
	fflush(stdin); getchar();

	srvProxy.Close();
	svc.Exit();
	srvProxy.Uninit();

	return 0;
}


void main()
{
	Test_Proxy();

	printf("**********�˳���. ���ٰ�һ��\n");
	fflush(stdin); getchar();
}
