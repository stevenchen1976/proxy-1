#ifndef __SimplifyThread_H__
#define __SimplifyThread_H__


#include <process.h>
#include <windows.h>


template <typename TThreadCallback>
class CSimplifyThread
{
public:
	CSimplifyThread(TThreadCallback * tc)
		: m_call(tc)
		, m_handle(NULL)
		, m_id(0)
		, m_running(false)
	{}

	virtual ~CSimplifyThread()
	{
		_ASSERT(m_handle == 0);
	}

	int Start()
	{
		return CreateThread();
	}

	int Stop()
	{
		if(!m_handle) return 0;

		if(TerminateThread(m_handle, 0))
		{ 
			CloseHandle(m_handle); m_handle = 0; 
		}
		return !bRet;
	}

	int SafeStop()
	{
		if(!m_handle) return 0;

		if(WAIT_OBJECT_0 == WaitForSingleObject(m_handle, INFINITE))
		{
			CloseHandle(m_handle);
			m_handle = NULL;
			return 0;
		}

		return -1;
	}

	int SafeStopX()
	{
		if(m_handle)
		{
			WaitForMsgThreadExit(m_handle, INFINITE);
			CloseHandle(m_handle);
			m_handle = NULL;
		}

		return 0;
	}


private:
	static unsigned int __stdcall ThreadFunctionImpl(void* param)
	{
		_ASSERT(param != NULL);
		static_cast<CSimplifyThread *>(param)->m_running = true;
		if(NULL != static_cast<CSimplifyThread *>(param)->m_call)
		{
			(*static_cast<CSimplifyThread *>(param)->m_call)();
		}

		Sleep(100);		// prevent for thread exited too quickly
		static_cast<CSimplifyThread *>(param)->m_running = false;
		return 0;
	}

	int CreateThread()
	{
		/* 
		 * uintptr_t _beginthreadex( 
		 *		void     *security,
		 *		unsigned stack_size,
		 *		unsigned ( *start_address )( void * ),
		 *		void     *arglist,
		 *		unsigned initflag,
		 *		unsigned *thrdaddr 
		 *		);
		 */
		_ASSERT(m_handle == 0);
		return (m_handle = (HANDLE)_beginthreadex(NULL, 0, ThreadFunctionImpl, this, 0, &m_id)) <= (HANDLE)1L ? -1 : 0;
	}

	int WaitForMsgThreadExit(HANDLE hThread, int nWaitTime)
	{
		_ASSERT(hThread);

		while(TRUE)
		{
			DWORD dwResult = 0;

			dwResult = ::MsgWaitForMultipleObjects(1, &hThread, FALSE, nWaitTime, QS_ALLINPUT); 
			if(dwResult == WAIT_OBJECT_0)
			{
				break;
			}
			else 
			{ 
				MSG msg;
				::PeekMessage(&msg, NULL, 0, 0, PM_REMOVE);
				::DispatchMessage(&msg); 
			}
		}

		return 0;
	}


protected:
	TThreadCallback*    m_call;
	HANDLE              m_handle;
	unsigned int        m_id; 
	volatile bool       m_running;
};


#endif
