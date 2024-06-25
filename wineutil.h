#ifndef __WINEUTIL_H__
#define __WINEUTIL_H__

#include <windows.h>

#define WINEUTIL_DLL "wineutil.dll.so"

BOOL WineUtilInit(LPCSTR szLibFile);
void WineUtilDeinit();

BOOL GetWineVersion(DWORD *pdwMajor, DWORD *pdwMinor);

BOOL IsWine();

BOOL WineSetEnv(LPCSTR szName, LPCSTR szValue);
BOOL WineUnsetEnv(LPCSTR szName);

BOOL WineVerifyPKCS12(LPCSTR szPKCS12File, LPCSTR szPKCS12Pass);

// TODO: check custom wine patch IsCustomWine() ?

#endif // __WINEUTIL_H__
