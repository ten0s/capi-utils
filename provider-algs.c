#include <libgen.h> // basename
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // getopt

#ifdef _WIN32
#   include <windows.h>
#   include <wincrypt.h>
#else
#   include "CSP_WinDef.h"
#   include "CSP_WinCrypt.h"
#endif

#include "util.h"

static void
usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [options...]\n"
            "   -n <prov name> Provider Name, optional\n"
            "   -t <prov type> Provider Type, mandatory\n"
            "   -x             Use PP_ENUMALGS_EX, by default: PP_ENUMALGS\n"
            "   -h             Help\n"
            "Hint: run enum-providers.exe to get <prov type>\n",
            prog
    );
}

int
main(int argc, char* argv[])
{
    const char *prog = basename(argv[0]);
    if (argc == 1) {
        usage(prog);
        exit(EXIT_FAILURE);
    }

    LPSTR szProvName = NULL;
    BOOL bFreeProvName = FALSE;
    DWORD dwProvType = 0;
    BOOL bEnumAlgsEx = FALSE;

    int opt;
    while ((opt = getopt(argc, argv, "n:t:xh")) != -1) {
        switch (opt) {
        case 'n':
            szProvName = optarg;
            break;

        case 't':
            dwProvType = atoi(optarg);
            break;

        case 'x':
            bEnumAlgsEx = TRUE;
            break;

        case 'h':
            usage(prog);
            exit(EXIT_SUCCESS);
            break;

        default:
            usage(prog);
            exit(EXIT_FAILURE);
        }
    }

    if (!dwProvType) {
        usage(prog);
        exit(EXIT_FAILURE);
    }

    if (!szProvName)
    {
        // Get the name of the default CSP specified for the
        // dwProvType type for the computer.

        DWORD cbProvName;

        if (!CryptGetDefaultProvider(dwProvType,
                                     NULL,
                                     CRYPT_MACHINE_DEFAULT,
                                     NULL,
                                     &cbProvName))
        {
            PrintError("CryptGetDefaultProvider", GetLastError());
            exit(1);
        }

        szProvName = malloc(cbProvName);
        bFreeProvName = TRUE;

        if (!CryptGetDefaultProvider(dwProvType,
                                     NULL,
                                     CRYPT_MACHINE_DEFAULT,
                                     szProvName,
                                     &cbProvName))
        {
            PrintError("CryptGetDefaultProvider", GetLastError());
            exit(1);
        }

        printf("The default provider name for %d is \"%s\"\n\n", dwProvType, szProvName);
    }

    HCRYPTPROV hProv;

    if (!CryptAcquireContext(&hProv,
                             NULL,
                             szProvName,
                             dwProvType,
                             CRYPT_VERIFYCONTEXT))
    {
        PrintError("CryptAcquireContext CRYPT_VERIFYCONTEXT", GetLastError());
        exit(1);
    }

    if (bEnumAlgsEx)
    {
        printf("    Algid         Bits    Class         Type         Len   Name                     LongLen     LongName\n");
        printf("    -----         ----    -----         ----         ---   ----                     -------     --------\n");
    }
    else
    {
        printf("    Algid         Bits    Class         Type         Len   Name\n");
        printf("    -----         ----    -----         ----         ---   ----\n");
    }

    PROV_ENUMALGS_EX AlgInfo;
    DWORD cbAlgInfo = sizeof(AlgInfo);

    DWORD dwFlags = CRYPT_FIRST;
    while (CryptGetProvParam(hProv,
                             bEnumAlgsEx ? PP_ENUMALGS_EX : PP_ENUMALGS,
                             (BYTE *)&AlgInfo,
                             &cbAlgInfo,
                             dwFlags))
    {
        dwFlags = CRYPT_NEXT;

        CHAR bufClass[10];
        CHAR bufType[10];
        CHAR* szAlgClass = NULL;
        CHAR* szAlgType = NULL;
        DWORD dwClass = GET_ALG_CLASS(AlgInfo.aiAlgid);
        DWORD dwType  = GET_ALG_TYPE(AlgInfo.aiAlgid);

        switch (dwClass)
        {
        case ALG_CLASS_DATA_ENCRYPT:
            szAlgClass = "Encrypt";
            break;
        case ALG_CLASS_HASH:
            szAlgClass = "Hash";
            break;
        case ALG_CLASS_KEY_EXCHANGE:
            szAlgClass = "Exchange";
            break;
        case ALG_CLASS_SIGNATURE:
            szAlgClass = "Signature";
            break;
        default:
            szAlgClass = itoa(dwClass, bufClass, 10);
            break;
        }

        switch (dwType)
        {
        case ALG_TYPE_DSS:
            szAlgType = "DSS";
            break;
        case ALG_TYPE_RSA:
            szAlgType = "RSA";
            break;
        case ALG_TYPE_BLOCK:
            szAlgType = "Block";
            break;
        case ALG_TYPE_STREAM:
            szAlgType = "Stream";
            break;
        case ALG_TYPE_DH:
            szAlgType = "DH";
            break;
        case ALG_TYPE_SECURECHANNEL:
            szAlgType = "SCHANNEL";
            break;
        default:
            szAlgType = itoa(dwType, bufType, 10);
            break;
        }

        if (bEnumAlgsEx)
        {
            PROV_ENUMALGS_EX *algInfo = (PROV_ENUMALGS_EX *)&AlgInfo;
            printf("    0x%8.8x    %-4d    %-10s    %-10s   %-2d    %-20s     %-2d          %s\n",
                   algInfo->aiAlgid,
                   algInfo->dwDefaultLen,
                   szAlgClass,
                   szAlgType,
                   algInfo->dwNameLen,
                   algInfo->szName,
                   algInfo->dwLongNameLen,
                   algInfo->szLongName);
        }
        else
        {
            PROV_ENUMALGS *algInfo = (PROV_ENUMALGS *)&AlgInfo;
            printf("    0x%8.8x    %-4d    %-10s    %-10s   %-2d    %-20s\n",
                   algInfo->aiAlgid,
                   algInfo->dwBitLen,
                   szAlgClass,
                   szAlgType,
                   algInfo->dwNameLen,
                   algInfo->szName);
        }
    }

    DWORD dwError = GetLastError();
    if (dwError != ERROR_NO_MORE_ITEMS)
    {
        PrintError("CryptGetProvParam", dwError);
    }

    if (!(CryptReleaseContext(hProv, 0)))
    {
        PrintError("CryptReleaseContext", GetLastError());
    }

    if (bFreeProvName)
    {
        free(szProvName);
        szProvName = NULL;
    }

    return EXIT_SUCCESS;
}
