#pragma once


#include <time.h>
#include <assert.h>


namespace nsRsTool
{
	class CRsTimer
	{
	public:
		CRsTimer()
		{
			Reset();
		}

		void  Reset()
		{
			m_begin = clock();
		}

		int   Elapsed()
		{
			assert(CLOCKS_PER_SEC >= 1000);
			return int(double(clock() - m_begin) / (CLOCKS_PER_SEC / 1000));
		}

		unsigned long Begin()
		{
			return (unsigned long)m_begin;
		}


	private:
		clock_t  m_begin;
	};
}
