#pragma once


enum  enumPathType { PathT_Exe = 0, PathT_Dir = 1, PathT_Name = 2, };
const char * GetExePath(int pt = PathT_Exe)
{
	static char   g_szPathExe[MAX_PATH] = {0};
	static char   g_szPathDir[MAX_PATH] = {0};
	static char * g_szPathName = 0;
	if(!g_szPathName)
	{
		GetModuleFileNameA(0, g_szPathExe, _countof(g_szPathExe));
		strcpy(g_szPathDir, g_szPathExe);

		char * pTmp = strrchr(g_szPathDir, '\\');
		if(pTmp) *pTmp = 0;

		g_szPathName = pTmp + 1;
	}

	switch(pt)
	{
	case PathT_Exe:  return g_szPathExe;
	case PathT_Dir:  return g_szPathDir;
	case PathT_Name: return g_szPathName;
	default:
		Assert(0);
		return 0;
	}
}
