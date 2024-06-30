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
               BOOL bMachineKeySet,
               INT iVerbose,
               BOOL bNoUI);

static void
ListKeyParams(HCRYPTPROV hProv,
              DWORD dwKeyType,
              INT iVerbose);

static void
CreateContainer(LPCSTR szProvName,
                DWORD dwProvType,
                LPCSTR szContName,
                BOOL bMachineKeySet,
                BOOL bSignatureKey,
                BOOL bExchangeKey,
                BOOL bNoUI);

static void
DeleteContainer(LPCSTR szProvName,
                DWORD dwProvType,
                LPCSTR szContName,
                BOOL bMachineKeySet,
                BOOL bNoUI);

static void
ExportKey(LPCSTR szProvName,
          DWORD dwProvType,
          LPCSTR szContName,
          BOOL bMachineKeySet,
          BOOL bSignatureKey,
          BOOL bExchangeKey,
          BOOL bNoUI);

static void
PrintKey(HCRYPTPROV hProv,
         DWORD dwKeyType);

// NB:
// Create AT_SIGNATURE and AT_KEYEXCHANGE key pairs might be ignored by
// some CSP since it creates the key pairs automatically.

static void
usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [options...]\n"
            "   -L             List Containers\n"
            "   -C <cont name> Create Container\n"
            "   -D <cont name> Delete Container\n"
            "   -E <cont name> Export Key Pair\n"
            "   -n <prov name> Provider Name, optional\n"
            "   -t <prov type> Provider Type, mandatory\n"
            "   -m             Create CRYPT_MACHINE_KEYSET\n"
            "   -s             Create/Export AT_SIGNATURE Key Pair\n"
            "   -x             Create/Export AT_KEYEXCHANGE Key Pair\n"
            "   -v[...]        Verbose Level, by default: 0\n"
            "   -q             Quiet / Silent / No UI Mode\n"
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
    BOOL bExport = FALSE;
    LPSTR szContName = NULL;
    LPSTR szProvName = NULL;
    DWORD dwProvType = 0;
    BOOL bMachineKeySet = FALSE;
    BOOL bSignatureKey = FALSE;
    BOOL bExchangekey = FALSE;
    INT iVerbose = 0;
    BOOL bNoUI = FALSE;

    int opt;
    while ((opt = getopt(argc, argv, "LC:D:E:n:t:msxvqh")) != -1) {
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

        case 'E':
            bExport = TRUE;
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

        case 'v':
            iVerbose++;
            break;

        case 'q':
            bNoUI = TRUE;
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

    if (!bList && !bCreate && !bDelete && !bExport) {
        usage(prog);
        exit(EXIT_FAILURE);
    }

    if (!dwProvType) {
        fprintf(stderr, "Provider Type is not given\n");
        usage(prog);
        exit(EXIT_FAILURE);
    }

    if ((bCreate || bDelete || bExport) && !szContName) {
        fprintf(stderr, "Container Name is not given\n");
        usage(prog);
        exit(EXIT_FAILURE);
    }

    if (bList) {
        ListContainers(szProvName, dwProvType, bMachineKeySet, iVerbose, bNoUI);
    } else if (bCreate) {
        CreateContainer(szProvName, dwProvType, szContName, bMachineKeySet, bSignatureKey, bExchangekey, bNoUI);
    } else if (bDelete) {
        DeleteContainer(szProvName, dwProvType, szContName, bMachineKeySet, bNoUI);
    } else if (bExport) {
        ExportKey(szProvName, dwProvType, szContName, bMachineKeySet, bSignatureKey, bExchangekey, bNoUI);
    }

    return EXIT_SUCCESS;
}

static void
ListContainers(LPCSTR szProvName,
               DWORD dwProvType,
               BOOL bMachineKeySet,
               BOOL iVerbose,
               BOOL bNoUI)
{
    HCRYPTPROV hProv;

    DWORD dwACFlags = CRYPT_VERIFYCONTEXT;
    dwACFlags = bMachineKeySet ? dwACFlags | CRYPT_MACHINE_KEYSET : dwACFlags;
    dwACFlags = bNoUI ? dwACFlags | CRYPT_SILENT : dwACFlags;

    if (!CryptAcquireContext(&hProv, NULL, szProvName, dwProvType, dwACFlags)) {
        PrintError("CryptAcquireContext CRYPT_VERIFYCONTEXT", GetLastError());
        exit(1);
    }

    DWORD dwPPFlags = CRYPT_FIRST;

    DWORD dwSize;
    if (!CryptGetProvParam(hProv, PP_ENUMCONTAINERS, 0, &dwSize, dwPPFlags)) {
        PrintError("CryptGetProvParam PP_ENUMCONTAINERS", GetLastError());
        exit(1);
    }

    CHAR szContName[dwSize];
    while (CryptGetProvParam(hProv, PP_ENUMCONTAINERS, szContName, &dwSize, dwPPFlags)) {

        dwPPFlags = CRYPT_NEXT;

        if (iVerbose) {
            printf("Name: ");
        }
        printf("%s\n", szContName);

        if (iVerbose) {
            HCRYPTPROV hContProv;

            dwACFlags = 0;
            dwACFlags = bMachineKeySet ? dwACFlags | CRYPT_MACHINE_KEYSET : dwACFlags;
            dwACFlags = bNoUI ? dwACFlags | CRYPT_SILENT : dwACFlags;

            if (!CryptAcquireContext(&hContProv, szContName, szProvName, dwProvType, dwACFlags)) {
                PrintError("CryptAcquireContext szContName", GetLastError());
            }

            ListKeyParams(hContProv, AT_SIGNATURE, iVerbose);
            ListKeyParams(hContProv, AT_KEYEXCHANGE, iVerbose);

            CryptReleaseContext(hContProv, 0);
        }
    }

    CryptReleaseContext(hProv, 0);
}

static void
ListKeyParams(HCRYPTPROV hProv,
              DWORD dwKeyType,
              INT iVerbose)
{
    HCRYPTKEY hKey;
    if (CryptGetUserKey(hProv, dwKeyType, &hKey)) {
        printf(" Type: %s\n", KeyType(dwKeyType));
        ALG_ID aiAlgid;
        DWORD dwSize = sizeof(aiAlgid);
        if (CryptGetKeyParam(hKey, KP_ALGID, (BYTE *)&aiAlgid, &dwSize, 0)) {
            printf("   KP_ALGID: 0x%08x\n", aiAlgid);
        } else if (iVerbose > 1) {
            PrintError("CryptGetKeyParam KP_ALGID", GetLastError());
        }
        DWORD dwKeyLen;
        dwSize = sizeof(dwKeyLen);
        if (CryptGetKeyParam(hKey, KP_KEYLEN, (BYTE *)&dwKeyLen, &dwSize, 0)) {
            printf("   KP_KEYLEN: %d\n", dwKeyLen);
        } else if (iVerbose > 1) {
            PrintError("CryptGetKeyParam KP_KEYLEN", GetLastError());
        }
        DWORD dwPerms;
        dwSize = sizeof(dwPerms);
        if (CryptGetKeyParam(hKey, KP_PERMISSIONS, (BYTE *)&dwPerms, &dwSize, 0)) {
            printf("   KP_PERMISSIONS: (%d) ", dwPerms);
            struct { DWORD key; const char *name; } perms[] = {
                {CRYPT_ARCHIVE   , "CRYPT_ARCHIVE"},
                {CRYPT_DECRYPT   , "CRYPT_DECRYPT"},
                {CRYPT_ENCRYPT   , "CRYPT_ENCRYPT"},
                {CRYPT_EXPORT    , "CRYPT_EXPORT"},
                {CRYPT_EXPORT_KEY, "CRYPT_EXPORT_KEY"},
                {CRYPT_IMPORT_KEY, "CRYPT_IMPORT_KEY"},
                {CRYPT_MAC       , "CRYPT_MAC"},
                {CRYPT_READ      , "CRYPT_READ"},
                {CRYPT_WRITE     , "CRYPT_WRITE"},
            };
            for (int i = 0; i < sizeof(perms)/sizeof(perms[0]); i++) {
                if (dwPerms & perms[i].key) {
                    printf("%s ", perms[i].name);
                }
            }
            printf("\n");
        } else if (iVerbose > 1) {
            PrintError("CryptGetKeyParam KP_PERMISSIONS", GetLastError());
        }
        dwSize = 0;
        if (CryptGetKeyParam(hKey, KP_SALT, NULL, &dwSize, 0)) {
            BYTE bSalt[dwSize];
            if (CryptGetKeyParam(hKey, KP_SALT, bSalt, &dwSize, 0)) {
                printf("   KP_SALT: ");
                PrintBytes(bSalt, dwSize);
            }
        } else if (iVerbose > 1) {
            PrintError("CryptGetKeyParam KP_SALT", GetLastError());
        }

        CryptDestroyKey(hKey);
    } else if (iVerbose > 1) {
        switch (dwKeyType) {
        case AT_SIGNATURE:
            PrintError("CryptGetUserKey AT_SIGNATURE", GetLastError());
            break;
        case AT_KEYEXCHANGE:
            PrintError("CryptGetUserKey AT_KEYEXCHANGE", GetLastError());
            break;
        default:
            PrintError("CryptGetUserKey dwKeyType", GetLastError());
        }
    }
}

static void
CreateContainer(LPCSTR szProvName,
                DWORD dwProvType,
                LPCSTR szContName,
                BOOL bMachineKeySet,
                BOOL bSignatureKey,
                BOOL bExchangeKey,
                BOOL bNoUI)
{
    HCRYPTPROV hProv;

    DWORD dwFlags = CRYPT_NEWKEYSET;
    dwFlags = bMachineKeySet ? dwFlags | CRYPT_MACHINE_KEYSET : dwFlags;
    dwFlags = bNoUI ? dwFlags | CRYPT_SILENT : dwFlags;

    if (!CryptAcquireContext(&hProv, szContName, szProvName, dwProvType, dwFlags)) {
        DWORD dwError = GetLastError();
        if (dwError = NTE_EXISTS) {
            dwFlags = 0;
            dwFlags = bMachineKeySet ? dwFlags | CRYPT_MACHINE_KEYSET : dwFlags;
            dwFlags = bNoUI ? dwFlags | CRYPT_SILENT : dwFlags;

            if (!CryptAcquireContext(&hProv, szContName, szProvName, dwProvType, dwFlags)) {
                PrintError("CryptAcquireContext 0", GetLastError());
                exit(1);
            }
        } else {
            PrintError("CryptAcquireContext CRYPT_NEWKEYSET", GetLastError());
            exit(1);
        }
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
                BOOL bMachineKeySet,
                BOOL bNoUI)
{
    HCRYPTPROV hProv;

    DWORD dwFlags = CRYPT_DELETEKEYSET;
    dwFlags = bMachineKeySet ? dwFlags | CRYPT_MACHINE_KEYSET : dwFlags;
    dwFlags = bNoUI ? dwFlags | CRYPT_SILENT : dwFlags;

    if (!CryptAcquireContext(&hProv, szContName, szProvName, dwProvType, dwFlags)) {
        PrintError("CryptAcquireContext CRYPT_DELETEKEYSET", GetLastError());
        exit(1);
    }

    CryptReleaseContext(hProv, 0);
}

static void
ExportKey(LPCSTR szProvName,
          DWORD dwProvType,
          LPCSTR szContName,
          BOOL bMachineKeySet,
          BOOL bSignatureKey,
          BOOL bExchangeKey,
          BOOL bNoUI)
{
    HCRYPTPROV hProv;

    DWORD dwACFlags = 0;
    dwACFlags = bMachineKeySet ? dwACFlags | CRYPT_MACHINE_KEYSET : dwACFlags;
    dwACFlags = bNoUI ? dwACFlags | CRYPT_SILENT : dwACFlags;

    if (!CryptAcquireContext(&hProv, szContName, szProvName, dwProvType, dwACFlags)) {
        PrintError("CryptAcquireContext 0", GetLastError());
        exit(1);
    }

    if (bSignatureKey) {
        PrintKey(hProv, AT_SIGNATURE);
    }

    if (bExchangeKey) {
        PrintKey(hProv, AT_KEYEXCHANGE);
    }

    CryptReleaseContext(hProv, 0);
}

static void
PrintKey(HCRYPTPROV hProv,
         DWORD dwKeyType)
{
    HCRYPTKEY hKey;
    if (!CryptGetUserKey(hProv, dwKeyType, &hKey)) {
        DWORD dwError = GetLastError();
        if (dwError == NTE_NO_KEY) {
            fprintf(stderr, "%s Key Pair not found\n", KeyType(dwKeyType));
            exit(1);
        } else {
            PrintError("CryptGetUserKey", dwError);
            exit(1);
        }
    }

    DWORD cbKeyBlob = 0;

    if (!CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, NULL, &cbKeyBlob)) {
        PrintError("CryptExportKey", GetLastError());
        exit(1);
    }

    BYTE bKeyBlob[cbKeyBlob];

    if (!CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, bKeyBlob, &cbKeyBlob)) {
        PrintError("CryptExportKey", GetLastError());
        exit(1);
    }

    printf("PUBLICKEYBLOB %s:\n", KeyType(dwKeyType));
    PrintBytes(bKeyBlob, cbKeyBlob);

    CryptDestroyKey(hKey);
}
