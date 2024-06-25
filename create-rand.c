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
            "   -s <size>      Random String Size, by default: 8\n"
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
    DWORD dwSize = 8;

    int opt;
    while ((opt = getopt(argc, argv, "n:t:s:h")) != -1) {
        switch (opt) {
        case 'n':
            szProvName = optarg;
            break;

        case 't':
            dwProvType = atoi(optarg);
            break;

        case 's':
            dwSize = atoi(optarg);
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

    if (dwSize <= 0) {
        fprintf(stderr, "Invalid Size\n");
        exit(EXIT_FAILURE);
    }

    HCRYPTPROV hProv;

    if (!CryptAcquireContext(&hProv, NULL, szProvName, dwProvType, CRYPT_VERIFYCONTEXT)) {
        PrintError("CryptAcquireContext CRYPT_VERIFYCONTEXT", GetLastError());
        exit(1);
    }

    BYTE bRandom[dwSize];

    if (!CryptGenRandom(hProv, sizeof(bRandom), bRandom)) {
        PrintError("CryptGenRandom", GetLastError());
        exit(1);
    }

    PrintBytes(bRandom, sizeof(bRandom));

    if (!CryptReleaseContext(hProv, 0)) {
        PrintError("CryptReleaseContext", GetLastError());
    }

    return EXIT_SUCCESS;
}
