#include <stdio.h>
#include "util.h"

LPCSTR
ErrorToString(DWORD dwError)
{
    switch (dwError) {
    case ERROR_FILE_NOT_FOUND:
        return "ERROR_FILE_NOT_FOUND";
    case ERROR_CANCELLED:
        return "ERROR_CANCELLED";
    case ERROR_MORE_DATA:
        return "ERROR_MORE_DATA";
    case ERROR_NO_MORE_ITEMS:
        return "ERROR_NO_MORE_ITEMS";
    case NTE_KEYSET_NOT_DEF:
        return "NTE_KEYSET_NOT_DEF";
    case NTE_BAD_ALGID:
        return "NTE_BAD_ALGID";
    case NTE_BAD_KEY:
        return "NTE_BAD_KEY";
    case NTE_BAD_KEYSET:
        return "NTE_BAD_KEYSET";
    case NTE_EXISTS:
        return "NTE_EXISTS";
    case NTE_PROV_TYPE_NO_MATCH:
        return "NTE_PROV_TYPE_NO_MATCH";
    case NTE_PROVIDER_DLL_FAIL:
        return "NTE_PROVIDER_DLL_FAIL";
    case SCARD_W_CANCELLED_BY_USER:
        return "SCARD_W_CANCELLED_BY_USER";
    case SCARD_E_INVALID_CHV:
        return "SCARD_E_INVALID_CHV";
    default:
        return NULL;
    }
}

void
PrintError(LPCSTR szErrorMsg, DWORD dwError)
{
    LPCSTR szErrorStr = ErrorToString(dwError);
    printf("%s error: 0x%x", szErrorMsg, dwError);
    if (szErrorStr) {
        printf(" (%s)", szErrorStr);
    }
    printf("\n");
}

void
PrintBytes(const BYTE *pbByte, DWORD dwSize)
{
    for (DWORD i = 0; i < dwSize; ++i) {
        printf("%02x", pbByte[i]);
    }
    printf("\n");
}
