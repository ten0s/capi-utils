#include <stdio.h>
#include "wineutil.h"

static HMODULE hModule;
static BOOL __stdcall (*pWineSetEnv)(LPCSTR szName, LPCSTR szValue);
static BOOL __stdcall (*pWineUnsetEnv)(LPCSTR szName);
static BOOL __stdcall (*pWineVerifyPKCS12)(LPCSTR szPKCS12File, LPCSTR szPKCS12Pass);

BOOL WineUtilInit(LPCSTR szLibFile)
{
    if (hModule)
    {
        SetLastError(ERROR_ALREADY_INITIALIZED);
        return FALSE;
    }

    hModule = LoadLibraryA(szLibFile);
    if (!hModule)
    {
        fprintf(stderr, "LoadLibrary(%s) failed with 0x%x\n",
                szLibFile, GetLastError());
        return FALSE;
    }

    pWineSetEnv = (typeof(pWineSetEnv))GetProcAddress(hModule, "WineSetEnv");
    if (!pWineSetEnv)
    {
        fprintf(stderr, "GetProcAddress(, \"%s\") failed with 0x%x\n",
                "WineSetEnv", GetLastError());
        return FALSE;
    }

    pWineUnsetEnv = (typeof(pWineUnsetEnv))GetProcAddress(hModule, "WineUnsetEnv");
    if (!pWineUnsetEnv)
    {
        fprintf(stderr, "GetProcAddress(, \"%s\") failed with 0x%x\n",
                "WineUnsetEnv", GetLastError());
        return FALSE;
    }

    pWineVerifyPKCS12 = (typeof(pWineVerifyPKCS12))GetProcAddress(hModule, "WineVerifyPKCS12");
    if (!pWineVerifyPKCS12)
    {
        fprintf(stderr, "GetProcAddress(, \"%s\") failed with 0x%x\n",
                "WineVerifyPKCS12", GetLastError());
        return FALSE;
    }

    return TRUE;
}

void WineUtilDeinit()
{
    if (hModule)
    {
        FreeLibrary(hModule);
        hModule = 0;
        pWineSetEnv = NULL;
        pWineUnsetEnv = NULL;
    }
}

BOOL GetWineVersion(DWORD *pdwMajor, DWORD *pdwMinor)
{
    if (!pdwMajor || !pdwMinor) {
        SetLastError(ERROR_BAD_ARGUMENTS);
        return FALSE;
    }

    HMODULE hMod = GetModuleHandleA("ntdll.dll");
    if (!hMod) {
        return FALSE;
    }

    const char * __cdecl (*wine_get_version)();
    wine_get_version = (typeof(wine_get_version))GetProcAddress(hMod, "wine_get_version");
    if (!wine_get_version) {
        return FALSE;
    }

    const char *version = wine_get_version();
    if (!version) {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    if (sscanf(version, "%d.%d", pdwMajor, pdwMinor) != 2) {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    return TRUE;
}

BOOL IsWine()
{
    DWORD dwMajor = 0;
    DWORD dwMinor = 0;
    if (GetWineVersion(&dwMajor, &dwMinor)) {
        return TRUE;
    }

    return FALSE;
}

BOOL WineSetEnv(LPCSTR szName, LPCSTR szValue)
{
    if (!pWineSetEnv)
    {
        SetLastError(ERROR_NOT_READY);
        return FALSE;
    }

    return pWineSetEnv(szName, szValue);
}

BOOL WineUnsetEnv(LPCSTR szName)
{
    if (!pWineUnsetEnv)
    {
        SetLastError(ERROR_NOT_READY);
        return FALSE;
    }

    return pWineUnsetEnv(szName);
}

BOOL WineVerifyPKCS12(LPCSTR szPKCS12File, LPCSTR szPKCS12Pass)
{
    if (!pWineVerifyPKCS12)
    {
        SetLastError(ERROR_NOT_READY);
        return FALSE;
    }

    return pWineVerifyPKCS12(szPKCS12File, szPKCS12Pass);
}
