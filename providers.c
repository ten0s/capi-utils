#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>

void main()
{
    DWORD       cbName;
    DWORD       dwType = 0;
    DWORD       dwIndex;
    CHAR        *pszName = NULL;

    printf("    ProvType    ProvName\n");
    printf("    --------    --------\n");

    dwIndex = 0;
    while (CryptEnumProviders(
           dwIndex,
           NULL,    // Reserved must be NULL
           0,       // Reserved nust be 0
           &dwType,
           NULL,
           &cbName
           ))
    {

        if (!(pszName = (LPTSTR)LocalAlloc(LMEM_ZEROINIT, cbName)))
        {
           printf("ERROR - LocalAlloc failed\n");
           exit(1);
        }

        if (CryptEnumProviders(
               dwIndex++,
               NULL,      // Reserved must be NULL
               0,         // Reserved must be 0
               &dwType,
               pszName,
               &cbName
               ))
        {
            printf("    %-4d        %s\n", dwType, pszName);
        }
        else
        {
            printf("ERROR - CryptEnumProviders failed.\n");
            exit(1);
        }
        LocalFree(pszName);
        dwType = 0;
    }
}
