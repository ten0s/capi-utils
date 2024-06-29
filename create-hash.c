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
            "   -a <algid>     Hash Algorithm Id, mandatory\n"
            "   -h             Help\n",
            prog
    );
}

int
main(int argc, char *argv[])
{
    const char *prog = basename(argv[0]);
    if (argc == 1) {
        usage(prog);
        exit(EXIT_FAILURE);
    }

    LPSTR szProvName = NULL;
    DWORD dwProvType = 0;
    DWORD dwAlgId = 0;

    int opt;
    while ((opt = getopt(argc, argv, "n:t:a:h")) != -1) {
        switch (opt) {
        case 'n':
            szProvName = optarg;
            break;

        case 't':
            dwProvType = atoi(optarg);
            break;

        case 'a':
            dwAlgId = ParseAlgId(optarg);
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

    if (!dwAlgId) {
        fprintf(stderr, "Invalid AlgId\n");
        exit(EXIT_FAILURE);
    }

    HCRYPTPROV hProv;

    if (!CryptAcquireContext(&hProv, NULL, szProvName, dwProvType, CRYPT_VERIFYCONTEXT)) {
        PrintError("CryptAcquireContext CRYPT_VERIFYCONTEXT", GetLastError());
        exit(1);
    }

    HCRYPTHASH hHash;

    if (!CryptCreateHash(hProv, dwAlgId, 0x0 /* HCRYPTKEY */, 0, &hHash)) {
        PrintError("CryptCreateHash", GetLastError());
        exit(1);
    }

#if 0
    BYTE buf[] = {'H', 'E', 'L', 'L', 'O'};
    if (!CryptHashData(hHash, buf, sizeof(buf), 0)) {
        PrintError("CryptHashData", GetLastError());
        exit(1);
    }
#else
    BYTE buf[BUFSIZ];
    int count = fread(buf, 1, sizeof(buf), stdin);
    while (count) {
		if (!CryptHashData(hHash, buf, count, 0)) {
            PrintError("CryptHashData", GetLastError());
            exit(1);
        }
        count = fread(buf, 1, sizeof(buf), stdin);
	}
#endif


    DWORD dwHashSize = 0;
    DWORD cbHashSize = sizeof(dwHashSize);

    if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE *)&dwHashSize, &cbHashSize, 0)) {
        PrintError("CryptGetHashParam HP_HASHSIZE", GetLastError());
        exit(1);
    }

    BYTE bHashData[dwHashSize];
    DWORD cbHashData = sizeof(bHashData);

    if (!CryptGetHashParam(hHash, HP_HASHVAL, bHashData, &cbHashData, 0)) {
        PrintError("CryptGetHashParam HP_HASHVAL", GetLastError());
        exit(1);
    }

    PrintBytes(bHashData, cbHashData);

    if (!CryptDestroyHash(hHash)) {
        PrintError("CryptDestroyHash", GetLastError());
        exit(1);
    }

    if (!CryptReleaseContext(hProv, 0)) {
        PrintError("CryptReleaseContext", GetLastError());
    }

    return EXIT_SUCCESS;
}
