#pragma once


#include "channel.h"


// 
// client, server的 close() 将导致 netio 退出. 
class CNetService : public CSelectIo
{
public:
	CNetService()
		: m_bExit(FALSE)
	{}

	virtual ~CNetService()
	{}

	virtual int  RunForever()
	{
		while(1)
		{
			int nRet = Run();
			if(nRet)
			{
				// 注意: 这儿要保证 io 的安全退出. 
				if(m_bExit) break;
				//LogX("** service, loop run error -->%d\n", nRet);
				Sleep(1000);
			}
		}

		return 0;
	}

	virtual int  Run()
	{
		CtrlEventList_t evLst;
		int nRet = Wait(evLst);
		if(nRet) return nRet;

		LogX("== service, ****** get event list(%d, %d)\n", evLst.size(), GetLastError());
		for(CtrlEventList_t::iterator it = evLst.begin(); it != evLst.end(); it++)
		{
			CChannel   * pChannel = (CChannel*)it->second.pud;
			if(pChannel) pChannel->Dispatch(it->second.nEvent, it->second.nError);
		}

		return 0;
	}

	virtual int  Exit()
	{
		m_bExit = TRUE;
		return 0;
	}


private:
	BOOL       m_bExit;
};


#ifdef  __UseNetServiceThread__
#include "sthread.h"

class CThreadNetService
	: public CNetService
	, public CSimplifyThread<CThreadNetService>
{
public:
	CThreadNetService()
		: CSimplifyThread<CThreadNetService>(0)
	{
		m_call = this;
	}

	virtual ~CThreadNetService()
	{}

	virtual void operator ()()
	{
		RunForever();
	}

	virtual int  Exit()
	{
		CNetService::Exit();
		return SafeStop();
	}
};
#endif
