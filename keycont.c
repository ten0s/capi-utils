#include <libgen.h> // basename
#include <locale.h>
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
ListContainers(LPCSTR szProvName,
               DWORD szProvType,
               BOOL bMachineKeySet);

static void
CreateContainer(LPCSTR szProvName,
                DWORD dwProvType,
                LPCSTR szContName,
                BOOL bMachineKeySet,
                BOOL bSignatureKey,
                BOOL bExchangeKey);

static void
DeleteContainer(LPCSTR szProvName,
                DWORD dwProvType,
                LPCSTR szContName,
                BOOL bMachineKeySet);

static void
usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [options...]\n"
            "   -L             List Containers\n"
            "   -C <cont name> Create Container\n"
            "   -D <cont name> Delete Container\n"
            "   -n <prov name> Provider Name, optional\n"
            "   -t <prov type> Provider Type, mandatory\n"
            "   -m             Machine KeySet, by default: User KeySet\n"
            "   -s             Create Signature Key, might be ignored by CSP\n"
            "   -x             Create Exchange Key, might be ignored by CSP\n"
            "   -h             Help\n",
            prog
    );
}

int
main(int argc, char *argv[])
{
    setlocale(LC_ALL, "Russian");

    const char *prog = basename(argv[0]);
    if (argc == 1) {
        usage(prog);
        exit(EXIT_FAILURE);
    }

    BOOL bList = FALSE;
    BOOL bCreate = FALSE;
    BOOL bDelete = FALSE;
    LPSTR szContName = NULL;
    LPSTR szProvName = NULL;
    DWORD dwProvType = 0;
    BOOL bMachineKeySet = FALSE;
    BOOL bSignatureKey = FALSE;
    BOOL bExchangekey = FALSE;

    int opt;
    while ((opt = getopt(argc, argv, "LC:D:n:t:msxh")) != -1) {
        switch (opt) {
        case 'L':
            bList = TRUE;
            break;

        case 'C':
            bCreate = TRUE;
            szContName = optarg;
            break;

        case 'D':
            bDelete = TRUE;
            szContName = optarg;
            break;

        case 'n':
            szProvName = optarg;
            break;

        case 't':
            dwProvType = atoi(optarg);
            break;

        case 'm':
            bMachineKeySet = TRUE;

        case 's':
            bSignatureKey = TRUE;
            break;

        case 'x':
            bExchangekey = TRUE;
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

    if (!bList && !bCreate && !bDelete) {
        usage(prog);
        exit(EXIT_FAILURE);
    }

    if (!dwProvType) {
        usage(prog);
        exit(EXIT_FAILURE);
    }

    if (bList) {
        ListContainers(szProvName, dwProvType, bMachineKeySet);
    } else if (bCreate) {
        CreateContainer(szProvName, dwProvType, szContName, bMachineKeySet, bSignatureKey, bExchangekey);
    } else if (bDelete) {
        DeleteContainer(szProvName, dwProvType, szContName, bMachineKeySet);
    }

    return EXIT_SUCCESS;
}

static void
ListContainers(LPCSTR szProvName,
               DWORD dwProvType,
               BOOL bMachineKeySet)
{
    HCRYPTPROV hProv = 0;

    DWORD dwFlags = CRYPT_VERIFYCONTEXT;
    dwFlags = bMachineKeySet ? dwFlags | CRYPT_MACHINE_KEYSET : dwFlags;

    if (!CryptAcquireContext(&hProv, NULL, szProvName, dwProvType, dwFlags)) {
        PrintError("CryptAcquireContext CRYPT_VERIFYCONTEXT", GetLastError());
        exit(1);
    }

    DWORD flags = CRYPT_FIRST;

    DWORD size;
    if (!CryptGetProvParam(hProv, PP_ENUMCONTAINERS, 0, &size, flags)) {
        PrintError("CryptGetProvParam PP_ENUMCONTAINERS", GetLastError());
        exit(1);
    }

    CHAR buf[size];
    while (CryptGetProvParam(hProv, PP_ENUMCONTAINERS, buf, &size, flags)) {
        printf("%s\n", buf);
        flags = 0;
    }

    CryptReleaseContext(hProv, 0);
}

static void
CreateContainer(LPCSTR szProvName,
                DWORD dwProvType,
                LPCSTR szContName,
                BOOL bMachineKeySet,
                BOOL bSignatureKey,
                BOOL bExchangeKey)
{
    HCRYPTPROV hProv;

    DWORD dwFlags = CRYPT_NEWKEYSET;
    dwFlags = bMachineKeySet ? dwFlags | CRYPT_MACHINE_KEYSET : dwFlags;

    if (!CryptAcquireContext(&hProv, szContName, szProvName, dwProvType, dwFlags)) {
        PrintError("CryptAcquireContext CRYPT_NEWKEYSET", GetLastError());
        exit(1);
    }

    if (bSignatureKey) {
        HCRYPTKEY hKey;
        if (!CryptGenKey(hProv, AT_SIGNATURE, CRYPT_EXPORTABLE, &hKey)) {
            PrintError("CryptGenKey AT_SIGNATURE CRYPT_EXPORTABLE", GetLastError());
            exit(1);
        }
        CryptDestroyKey(hKey);
    }

    if (bExchangeKey) {
        HCRYPTKEY hKey;
        if (!CryptGenKey(hProv, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &hKey)) {
            PrintError("CryptGenKey AT_KEYEXCHANGE CRYPT_EXPORTABLE", GetLastError());
            exit(1);
        }
        CryptDestroyKey(hKey);
    }

    CryptReleaseContext(hProv, 0);
}

static void
DeleteContainer(LPCSTR szProvName,
                DWORD dwProvType,
                LPCSTR szContName,
                BOOL bMachineKeySet)
{
    HCRYPTPROV hProv;

    DWORD dwFlags = CRYPT_DELETEKEYSET;
    dwFlags = bMachineKeySet ? dwFlags | CRYPT_MACHINE_KEYSET : dwFlags;

    if (!CryptAcquireContext(&hProv, szContName, szProvName, dwProvType, dwFlags)) {
        PrintError("CryptAcquireContext CRYPT_DELETEKEYSET", GetLastError());
        exit(1);
    }

    CryptReleaseContext(hProv, 0);
}
