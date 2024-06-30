#ifndef __UTIL_H__
#define __UTIL_H__

#ifdef _WIN32
#   include <windows.h>
#   include <wincrypt.h>
#else
#   include "CSP_WinDef.h"
#   include "CSP_WinCrypt.h"
#endif

LPCSTR
ErrorToString(DWORD dwError);

void
PrintError(LPCSTR szMsgFmt, DWORD dwError);

void
PrintBytes(const BYTE *pbByte, DWORD dwSize);

DWORD
ParseAlgId(LPCSTR szStr);

LPCSTR
KeyType(DWORD dwKeyType);

#endif // __UTIL_H__
