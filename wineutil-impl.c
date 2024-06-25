#include <errno.h>
#include <gnutls/gnutls.h> // # apt install libgnutls28-dev
#include <gnutls/pkcs12.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

BOOL __stdcall WineSetEnv(LPCSTR szName, LPCSTR szValue)
{
    if (setenv(szName, szValue, 1) == -1) {
        DWORD dwError;

        switch (errno) {
        case EINVAL:
            dwError = ERROR_BAD_ARGUMENTS;
            break;
        case ENOMEM:
            dwError = ERROR_NOT_ENOUGH_MEMORY;
            break;
        default:
            dwError = errno;
            break;
        }

        SetLastError(dwError);
        return FALSE;
    }

    return TRUE;
}

BOOL __stdcall WineUnsetEnv(LPCSTR szName)
{
    if (unsetenv(szName) == -1) {
        DWORD dwError;

        switch (errno) {
        case EINVAL:
            dwError = ERROR_BAD_ARGUMENTS;
            break;
        case ENOMEM:
            dwError = ERROR_NOT_ENOUGH_MEMORY;
            break;
        default:
            dwError = errno;
            break;
        }

        SetLastError(dwError);
        return FALSE;
    }

    return TRUE;
}

BOOL __stdcall WineVerifyPKCS12(LPCSTR szPKCS12File, LPCSTR szPKCS12Pass)
{
    FILE *file = fopen(szPKCS12File, "rb");
    if (!file) {
        fprintf(stderr, "File not found\n");
        SetLastError(ERROR_FILE_NOT_FOUND);
        return FALSE;
    }

    gnutls_datum_t p12blob;

    fseek(file, 0, SEEK_END);
    p12blob.size = ftell(file);
    fseek(file, 0, SEEK_SET);
    p12blob.data = malloc(p12blob.size);
    fread(p12blob.data, 1, p12blob.size, file);
    fclose(file);
    file = NULL;

    // TODO: If the PKCS12 is PEM encoded it should have a header of "PKCS12".
    gnutls_x509_crt_fmt_t type = GNUTLS_X509_FMT_DER;
    if (strstr(p12blob.data, "BEGIN CERTIFICATE") != NULL) {
        type = GNUTLS_X509_FMT_PEM;
    }

    printf("Type: %s\n", type == GNUTLS_X509_FMT_DER ? "DER" : "PEM");

    gnutls_pkcs12_t p12;

    int ret = gnutls_pkcs12_init(&p12);
    if (ret != GNUTLS_E_SUCCESS) {
        fprintf(stderr, "gnutls_pkcs12_init failed with %d\n", ret);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    ret = gnutls_pkcs12_import(p12, &p12blob, type, 0);
    if (ret != GNUTLS_E_SUCCESS) {
        fprintf(stderr, "gnutls_pkcs12_import failed with %d\n", ret);
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    if (szPKCS12Pass) {
        ret = gnutls_pkcs12_verify_mac(p12, szPKCS12Pass);
        if (ret != GNUTLS_E_SUCCESS) {
            if (ret == GNUTLS_E_MAC_VERIFY_FAILED) {
                printf("MAC: Failed\n");
                SetLastError(ERROR_INVALID_PASSWORD);
            } else {
                fprintf(stderr, "gnutls_pkcs12_verify_mac with %d\n", ret);
                SetLastError(ERROR_INVALID_DATA);
            }
            return FALSE;
        }
        printf("MAC: Verified\n");
    }

    gnutls_x509_privkey_t key = NULL;
    gnutls_x509_crt_t *chain = NULL;
    unsigned int chain_size = 0;

    ret = gnutls_pkcs12_simple_parse(p12, szPKCS12Pass, &key, &chain,
                                     &chain_size, NULL, NULL, NULL, 0);
    if (ret != GNUTLS_E_SUCCESS) {
        if (ret == GNUTLS_E_DECRYPTION_FAILED) {
            printf("Pass: Invalid\n");
            SetLastError(ERROR_INVALID_PASSWORD);
        } else {
            fprintf(stderr, "gnutls_pkcs12_simple_parse with %d\n", ret);
            SetLastError(ERROR_INVALID_DATA);
        }
        return FALSE;
    }
    printf("Pass: Valid\n");

    // TODO: free chain?

    gnutls_pkcs12_deinit(p12);
    return TRUE;
}
