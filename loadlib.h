#pragma  once


class CLoadLib
{
public:
	CLoadLib()
		: m_hMod(0)
	{}

	explicit CLoadLib(const char * szLibName)
		: m_hMod(0)
	{
		Load(szLibName);
	}

	~CLoadLib();
	int    Load(const char * szLibName);
	void * GetFunc(const char * szFunName);


	#ifdef WIN32
	explicit CLoadLib(const wchar_t * szLibName)
		: m_hMod(0)
	{
		Load(szLibName);
	}

	int    Load(const wchar_t * szLibName);
	#endif


	CLoadLib(CLoadLib & ll)
	{
		m_hMod = ll.Detach();
	}

	CLoadLib & operator = (CLoadLib & ll)
	{
		m_hMod = ll.Detach();
		return *this;
	}

	void   Attach(void * hMod)
	{
		m_hMod = hMod;
	}

	void * Detach() 
	{
		void * pTmp = m_hMod; m_hMod = 0;
		return pTmp;
	}


private:
	void * m_hMod;
};


#ifdef WIN32
#include <windows.h>


inline CLoadLib::~CLoadLib()
{
	if(m_hMod) ::FreeLibrary((HMODULE)m_hMod);
}

inline int    CLoadLib::Load(const char * szLibName)
{
	if(szLibName) m_hMod = ::LoadLibraryA(szLibName);
	return m_hMod != 0 ? 0 : -1;
}

inline int    CLoadLib::Load(const wchar_t * szLibName)
{
	if(szLibName) m_hMod = ::LoadLibraryW(szLibName);
	return m_hMod != 0 ? 0 : -1;
}

inline void * CLoadLib::GetFunc(const char * szFunName)
{
	return ::GetProcAddress((HMODULE)m_hMod, szFunName);
}


#else
#include <dlfcn.h>


inline int    CLoadLib::Load(const char * szLibName)
{
	if(szLibName) m_hMod = dlopen(szLibName, RTLD_LAZY);
	return m_hMod != 0 ? 0 : -1;
}

inline CLoadLib::~CLoadLib()
{
	if(m_hMod) dlclose(m_hMod);
}

inline void * CLoadLib::GetFunc(const char * szFunName)
{
	return dlsym(m_hMod, szFunName);
}


#endif  // WIN32
