#pragma  once


#include "rslogx.h"
#include "loadlib.h"


#define LOGF_NAME2             ".url.log"
#define LOG_FILE2              LOG_PF->Open(LOGF_NAME2, LOGF_MODE)

#define LOG_FLOG2(_l, _f, ...) LOG_PF->LOGF_IMPL(_l, LOGF_TYPE, LOG_FILE2, _f, __VA_ARGS__)
#define LOGY(_f, ...)          LOG_FLOG2(1, _f, __VA_ARGS__)


// "urlfilter.dll"
//typedef int  (*PfnLoadAdFiles)();
//typedef int  (*PfnMatchAdUrlA)(LPCSTR szUrl, LPCSTR szRefer);
//typedef void (*PfnPrintAdbInfo)();

typedef int  (*FnUpInit)();
typedef void (*FnUpUninit)();
typedef int  (*FnUpMatch)(const char * szUrl, const char * szRefer);


typedef struct UrlFilterPlug_t
{
	CLoadLib    * pDllLoader;
	std::string   strName;

	FnUpInit      UpInit;
	FnUpUninit    UpUninit;
	FnUpMatch     UpMatch;

	UrlFilterPlug_t()
		: pDllLoader(0)
		, UpInit(0)
		, UpUninit(0)
		, UpMatch(0)
	{
	}
}UrlFilterPlug_t;

typedef std::list<UrlFilterPlug_t> 
UrlFilerPlugList_t;


class CFilter
{
public:
	static CFilter * Instance()
	{
		static CFilter g_filter;
		return &g_filter;
	}

	int  Load()
	{
		extern const char * GetExePath(int);
		const  char * szPath  = GetExePath(1);
		std::string   strFind = szPath; strFind += "\\up?_*.dll";

		WIN32_FIND_DATAA wfd = {0};
		HANDLE hDir = FindFirstFileA(strFind.c_str(), &wfd);
		if(hDir == INVALID_HANDLE_VALUE) return 1;

		do
		{
			if(wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

			UrlFilterPlug_t plug;
			plug.pDllLoader = new CLoadLib();
			plug.strName    = wfd.cFileName;
			if(!plug.pDllLoader)       Assert(0);
			if(LoadPlug(plug, szPath)) m_listPlug.push_back(plug);
			else                       delete plug.pDllLoader;
		}while(FindNextFileA(hDir, &wfd) != 0);

		FindClose(hDir);
		return 0;
	}

	void Unload()
	{
		for(UrlFilerPlugList_t::const_iterator it = m_listPlug.begin(); it != m_listPlug.end(); it++)
		{
			if(it->pDllLoader) delete it->pDllLoader;
		}
	}

	int  Filter(std::string & strUrl, std::string & strRefer, bool bHttps)
	{
		if(bHttps) strUrl.insert(0, "https://");
		else       strUrl.insert(0, "http://");

		// test.
		if(strstr(strUrl.c_str(), "google"))
		{
			return 1;
		}

		for(UrlFilerPlugList_t::const_iterator it = m_listPlug.begin(); it != m_listPlug.end(); it++)
		{
			int nRet = it->UpMatch(strUrl.c_str(), strRefer.empty() ? 0 : strRefer.c_str());
			if(nRet)
			{
				LOGY("%-2d, %-12s ->%s  (%s)\n", nRet, it->strName.c_str(), strUrl.c_str(), strRefer.c_str());
				return nRet;
			}
		}

		LOGY("0 , log          ->%s  (%s)\n", strUrl.c_str(), strRefer.c_str());
		return 0;
	}


private:
	bool LoadPlug(UrlFilterPlug_t & plug, const char * szExePath)
	{
		std::string strDllPath = szExePath;
		strDllPath += "\\"; strDllPath += plug.strName;

		int nRet    = plug.pDllLoader->Load(strDllPath.c_str()); Assert(!nRet);
		if( nRet) return false;

		plug.UpInit   = (FnUpInit)plug.pDllLoader->GetFunc("UpInit");
		plug.UpUninit = (FnUpUninit)plug.pDllLoader->GetFunc("UpUninit");
		plug.UpMatch  = (FnUpMatch)plug.pDllLoader->GetFunc("UpMatch");

		if(!plug.UpInit || !plug.UpMatch) return false;
		nRet = plug.UpInit();
		return nRet == 0;
	}


private:
	UrlFilerPlugList_t  m_listPlug;
};
