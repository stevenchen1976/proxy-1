#pragma once


#include <winsock2.h>

#include <map>
#include <list>
#include <assert.h>
#include "rstimer.h"
#include "common.h"


#ifndef uint
	#define uint     unsigned int
#endif

#ifndef Socket_t
	#define Socket_t SOCKET
#endif

#ifndef Assert
	//#define Assert   assert
	#define Assert(_expr)     { if(!(_expr)) { __asm int 3 }}  //assert
#endif


class CNetTimer
{
public:
	CNetTimer(int nTimer = -1)
		: m_nTimer(nTimer)
	{}

	int  GetTimer()           { return m_nTimer;     }
	int  GetTimeout()         { return m_nTimer >= 0 ?  (m_nTimer - m_timer.Elapsed()) :  -1; }
	bool IsTimeout()          { return m_nTimer >= 0 && m_timer.Elapsed() >= m_nTimer; }
	void SetTimer(int nTimer) { m_nTimer = nTimer;   }
	void Reset()              { m_timer.Reset();     }


private:
	int                m_nTimer;
	nsRsTool::CRsTimer m_timer;
};


typedef struct IoCtrlEvent_t
{
	int           nEvent;
	int           nError;
	void        * pud;
}IoCtrlEvent_t;

typedef struct IoCtrlContext_t
{
	IoCtrlEvent_t ev;
	CNetTimer     timer;
}IoCtrlContext_t;

typedef std::map<Socket_t, IoCtrlContext_t>  
CtrlContextList_t;

typedef std::list<std::pair<Socket_t, IoCtrlEvent_t> > 
CtrlEventList_t;

typedef std::list<std::pair<Socket_t, IoCtrlContext_t> > 
CtrlContextCacheList_t;


enum enumActionCtrl
{ 
	Action_CtrlAdd     = 1, 
	Action_CtrlDel     = 2, 
	Action_CtrlMod     = 3, 
};

enum enumEventCtrl
{
	Event_Unknown      = 0x00, 
	Event_NetRead      = 0x01, 
	Event_NetWrite     = 0x02, 
	Event_NetReadWrite = 0x03, 
	Event_NetExcept    = 0x04, 
	Event_NetTimeout   = 0x08, 
	Event_NetConnect   = 0x10, 
	Event_NetAgain     = 0x20, 
};


class CNetIo
{
public:
	virtual ~CNetIo() {};

	virtual int  Ctrl(Socket_t s, int nAction, IoCtrlEvent_t * ev, int nTimeout = -1) = 0;
	virtual int  Wait(CtrlEventList_t & evList) = 0;
	virtual int  Clear() = 0;
};


// 此函数保证放入事件列表的事件不会重复. 
inline void PushNetEventList(CtrlEventList_t & evList, Socket_t s, IoCtrlEvent_t & ev)
{
	for(CtrlEventList_t::iterator it = evList.begin(); it != evList.end(); it++)
	{
		if(it->first == s && it->second.pud == ev.pud) return;
	}

	evList.push_back(std::make_pair(s, ev));
}


// Socket_t;
class CSelectIo : public CNetIo
{
public:
	CSelectIo()
		: m_nThreadId(0)
		, m_bTimer(false)
	{}

	virtual ~CSelectIo()
	{
		// 执行到这儿的时候, m_socks 应该是空的. 
		Assert(m_socks.empty());
	}

	// method. 
	// close: 合理的流程是先调用 closesocket, 然后在回调中调用 Ctrl 删除它. 
	virtual int  Ctrl(Socket_t s, int nAction, IoCtrlEvent_t * pev, int nTimeout)
	{
		// 这个函数必须由外部保证线程安全, 
		// 它允许初始化调用, 回调中调用. 
		Assert(s); if(!s) return 0;

		int nThreadId = GetCurrentThreadId(), nOldEvent = 0;
		if(!m_socks.empty() && nThreadId != (int)m_nThreadId)
		{
			LogX("** netio, multi-thread conflict, forbidden to ctrl socket ......\n");
			return -1;
		}

		CtrlContextList_t::iterator it = m_socks.find(s);
		switch(nAction)
		{
		case Action_CtrlAdd:
			// 增加的时候可能会重用删除的 socket. 导致增加失败. 
			// 如果失败, 我们将增加放到缓存中, 等 Refresh时再试. 
			Assert(pev);
			if(it != m_socks.end())
			{
				LogX("** netio, iolist find this socket, cannot readd it ...(%d, %p) -> (%d, %p)\n", it->first, it->second.ev.pud, s, pev->pud);
				//Assert(m_socksTmp.find(s) == m_socksTmp.end());

				IoCtrlContext_t   context;
				context.ev      = *pev;
				context.timer.SetTimer(nTimeout);
				m_socksTmp.push_back(std::make_pair(s, context));
			}
			else
			{
				IoCtrlContext_t   context;
				context.ev      = *pev;
				context.timer.SetTimer(nTimeout);
				m_socks[s]      = context;
			}
			break;

		case Action_CtrlDel:
			if(it == m_socks.end() || it->second.ev.pud != pev->pud)
			{
				CtrlContextCacheList_t::iterator it2 = m_socksTmp.begin();
				for(; it2 != m_socksTmp.end(); it2++)
				{
					if(it2->first == s) break;
				}

				Assert(it2 != m_socksTmp.end());
				Assert(it2->second.ev.pud == pev->pud);
				m_socksTmp.erase(it2);
				break;
			}

			m_socks.erase(it);
			break;

		case Action_CtrlMod:
			Assert(pev);
			if(it == m_socks.end())
			{
				LogX("** netio, iolist cannot find this socket...(%d)\n", s);
				return -1;
			}

			if(it->second.ev.pud != pev->pud)
			{
				CtrlContextCacheList_t::iterator it2 = m_socksTmp.begin();
				for(; it2 != m_socksTmp.end(); it++)
				{
					if(it2->first == s) break;
				}

				Assert(it2 != m_socksTmp.end());
				Assert(it2->second.ev.pud == pev->pud);
				it->second.ev = *pev;
				it->second.timer.SetTimer(nTimeout);
				break;
			}

			nOldEvent     = it->second.ev.nEvent;
			it->second.ev = *pev;
			it->second.ev.nEvent |= nOldEvent;
			it->second.timer.SetTimer(nTimeout);
			break;

		default:
			Assert(0);
			break;
		}

		return 0;
	}

	virtual int  Clear()
	{
		int nThreadId = GetCurrentThreadId();
		if(!m_socks.empty() && nThreadId != (int)m_nThreadId)
		{
			LogX("** netio, multi-thread conflict, forbidden to ctrl socket ......\n");
			return -1;
		}

		m_socks.clear();
		return 0;
	}

	virtual int  Wait(CtrlEventList_t & evList)
	{
		int nRet = -1, nErr = 0;
		if(m_socks.empty()) return nRet;
		else                m_nThreadId = ::GetCurrentThreadId();

		HandleCacheSocks(evList);
		if(!evList.empty()) return 0;

		Refresh();
		if((nRet = Select()) <  0)
		{
			// 可能会恢复哦 ...
			nErr = GetLastError();
			LogX("** netio, select error -->%d, %d\n", nRet, nErr);
		}

		// 由于我们是 先 close再 delete from select. 
		// 那么 select如果发现有 close的 socket, 会报错. 
		// 此时我们需要处理这种情况. 
		// 此时我们不能够
		LogX("== netio, select ret -->%d,%d, (%d)\n", m_setRead.fd_count, m_setWrite.fd_count, nRet);
		Dispatch(nRet > 0, nErr, evList);
		return 0;
	}


private:
	void Dispatch(BOOL bIo, int nError, CtrlEventList_t & evList)
	{
		// 这儿可能会改变事件的顺序. 导致问题. 
		//if(!bIo && !m_bTimer) return;

		// 特殊处理 10038错误. 
		if(nError == WSAENOTSOCK)
		{
			for(CtrlContextList_t::iterator it = m_socks.begin(); it != m_socks.end(); it++)
			{
				IoCtrlEvent_t ev = { Event_NetExcept, nError, it->second.ev.pud };
				evList.push_back(std::make_pair(it->first, ev));
				it->second.timer.Reset();
			}
			return ;
		}

		for(CtrlContextList_t::iterator it = m_socks.begin(); it != m_socks.end(); it++)
		{
			int  nOldEvent = it->second.ev.nEvent, nNewEvent = 0;
			IoCtrlEvent_t ev = { 0, nError, it->second.ev.pud };

			#define SET_SOCKET_EVENT(_e) { nNewEvent |= _e; ev.nEvent |= _e; it->second.ev.nEvent &= ~_e; } 
			if(FD_ISSET(it->first, &m_setRead))             SET_SOCKET_EVENT(Event_NetRead);
			if(FD_ISSET(it->first, &m_setWrite))            SET_SOCKET_EVENT(Event_NetWrite);
			if(FD_ISSET(it->first, &m_setExcept))           SET_SOCKET_EVENT(Event_NetExcept);
			if(!ev.nEvent && it->second.timer.IsTimeout())  SET_SOCKET_EVENT(Event_NetTimeout);
			if(it->second.ev.nEvent == Event_NetConnect)    SET_SOCKET_EVENT(Event_NetConnect);
			if(it->second.ev.nEvent & Event_NetAgain)
			{
				it->second.ev.nEvent &= ~Event_NetAgain;
				ev.nEvent |= it->second.ev.nEvent;
			}

			if(ev.nEvent) 
			{
				evList.push_back(std::make_pair(it->first, ev));
				it->second.timer.Reset();
			}

			// 内部总是保留一个read
			//LogX("== netio, dispatch to set socket and read (%d,%p) -->(%d,%d,%d,%d)\n", it->first, it->second.ev.pud, it->second.ev.nEvent, nOldEvent, nNewEvent, ev.nEvent);
			it->second.ev.nEvent |= Event_NetRead;
		}
	}

	void HandleCacheSocks(CtrlEventList_t & evList)
	{
		// ******
		// 放入 cache中的 socket均已关闭, 如果在这儿不处理, select中等待将是新创建的. 
		// 所以这儿将它设置为 异常. 
		// 如果有多个 cache中有多个 socket ???
		CtrlContextCacheList_t socksTmp = m_socksTmp;
		m_socksTmp.clear();

		for(CtrlContextCacheList_t::iterator it = socksTmp.begin(); it != socksTmp.end(); it++)
		{
			CtrlContextList_t::iterator it2 = m_socks.find(it->first);
			if(it2 != m_socks.end())
			{
				LogX("** netio, add socket error(dunplicate), (%d, %p) -> (%d, %p)\n", it2->first, it2->second.ev.pud, it->first, it->second.ev.pud);

				IoCtrlEvent_t  ev  = { Event_NetExcept, WSAENOTSOCK, it2->second.ev.pud };
				PushNetEventList(evList, it->first, ev);
				ev.pud = it->second.ev.pud;
				PushNetEventList(evList, it->first, ev);
				m_socksTmp.push_back(*it);
				continue;
			}
			m_socks[it->first] = it->second;
		}
	}

	int  Refresh()
	{
		FD_ZERO(&m_setRead);
		FD_ZERO(&m_setWrite);
		FD_ZERO(&m_setExcept);

		// 
		int  nTimer = -1; m_bTimer = FALSE;
		for(CtrlContextList_t::iterator it = m_socks.begin(); it != m_socks.end(); it++)
		{
			// 不能因为超时阻塞了, 而延迟时间. 
			if(it->second.timer.GetTimer() >= 0)
			{
				// 这儿不能重置超时, 这样就不会有 OnTimeout消息了. 
				int nTimeout = it->second.timer.GetTimeout();
				if(nTimeout  < 0)  nTimeout = 0;
				if((uint)nTimeout  < (uint)nTimer) nTimer = nTimeout;
				m_bTimer = TRUE;
			}

			// msdn, connect ok == the socket is writeable.
			int nEvent = it->second.ev.nEvent;
			//if( nEvent == Event_NetConnect) nEvent = Event_NetWrite;

			if( nEvent &  Event_NetRead)    FD_SET(it->first, &m_setRead);
			if( nEvent &  Event_NetWrite)   FD_SET(it->first, &m_setWrite);
			FD_SET(it->first, &m_setExcept);
		}

		m_nTimer = m_bTimer ? nTimer : -1;
		return 0;
	}

	int  Select()
	{
		int     nRet     = 0;
		int     nFdCount = m_setRead.fd_count + m_setWrite.fd_count + 1;
		timeval tv       = { 0 };

		if(m_bTimer) tv.tv_usec = m_nTimer * 1000;
		LogX("== netio, select begin -->%d,%d, \n", m_setRead.fd_count, m_setWrite.fd_count);
		return ::select(nFdCount, &m_setRead, &m_setWrite, &m_setExcept, m_bTimer ? &tv : 0);
	}


private:
	fd_set                  m_setRead;
	fd_set                  m_setWrite;
	fd_set                  m_setExcept;

	unsigned int            m_nThreadId;
	unsigned int            m_nTimer;
	BOOL                    m_bTimer;

	CtrlContextList_t       m_socks;
	CtrlContextCacheList_t  m_socksTmp;
};
