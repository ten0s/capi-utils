#include <libgen.h> // basename
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h> // getopt

#ifdef _WIN32
#   include <windows.h>
#   include <wincrypt.h>
#else
#   include "CSP_WinDef.h"
#   include "CSP_WinCrypt.h"
#endif

#define REQ_NAME "admin"
#define COUNTRY "RU"

static void
usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [options...]\n"
            "   -n <prov name> Provider Name, optional\n"
            "   -t <prov type> Provider Type, mandatory\n"
            "   -a <sign alg>  Signature Algorithm, mandatory\n"
            "   -r <req name>  Request Name, by default: %s\n"
            "   -c <country>   Country, by default: %s\n"
            "   -h             Help\n",
            prog,
            REQ_NAME,
            COUNTRY
    );
}

int main(int argc, char *argv[])
{
    const char *prog = basename(argv[0]);
    if (argc == 1) {
        usage(prog);
        exit(EXIT_FAILURE);
    }

    LPSTR szProvName = NULL;
    DWORD dwProvType = 0;
    LPSTR szSignAlg = NULL;
    LPSTR szName = REQ_NAME;
    LPSTR szCountry = COUNTRY;

    int opt;
    while ((opt = getopt(argc, argv, "n:t:a:r:c:h")) != -1) {
        switch (opt) {
        case 'n':
            szProvName = optarg;
            break;

        case 't':
            dwProvType = atoi(optarg);
            break;

        case 'a':
            szSignAlg = optarg;
            break;

        case 'r':
            szName = optarg;
            break;

        case 'c':
            szCountry = optarg;
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

    if (!dwProvType || !szSignAlg) {
        usage(prog);
        exit(EXIT_FAILURE);
    }

    CHAR szReqName[50];
    snprintf(szReqName, sizeof(szReqName), "%s-%ld", szName, time(NULL));

    HCRYPTPROV hProv;
    DWORD dwFlags = CRYPT_NEWKEYSET;

    if (!CryptAcquireContext(
            &hProv,
            szReqName,
            szProvName,
            dwProvType,
            dwFlags))
    {
        fprintf(stderr, "CryptAcquireContext failed with: 0x%x\n",
                GetLastError());
        return 1;
    }

    HCRYPTKEY hKey;
    if (!CryptGenKey(hProv,
                     AT_KEYEXCHANGE, //ctx.csp()->certificate_import_algorithm_id();
                     CRYPT_EXPORTABLE,
                     &hKey))
    {
        fprintf(stderr, "CryptGenKey failed with: 0x%x\n",
                GetLastError());
        return 1;
    }

    CHAR szSubject[1024];
    snprintf(szSubject, sizeof(szSubject),
            "CN=%s,C=%s,O=%s,E=%s@mail.com",
             szReqName, szCountry, szReqName, szReqName);

    DWORD dwSubjectBlobSize;
    if (!CertStrToNameA(X509_ASN_ENCODING,
                        szSubject,
                        CERT_X500_NAME_STR,
                        NULL,
                        NULL,
                        &dwSubjectBlobSize,
                        NULL))
    {
        fprintf(stderr, "CertStrToNameA #1 failed with: 0x%x\n",
                GetLastError());
        return 1;
    }

    BYTE bSubjectBlob[dwSubjectBlobSize];
    if (!CertStrToNameA(X509_ASN_ENCODING,
                        szSubject,
                        CERT_X500_NAME_STR,
                        NULL,
                        bSubjectBlob,
                        &dwSubjectBlobSize,
                        NULL))
    {
        fprintf(stderr, "CertStrToNameA #2 failed with: 0x%x\n",
                GetLastError());
        return 1;
    }

    //PublicKeyInfo pubkey = key_ctx.get_public_key();
    //req_info.SubjectPublicKeyInfo   = *pubkey.info();

    DWORD dwPubKeySize = 0;
    if (!CryptExportPublicKeyInfo(
            hProv,
            AT_KEYEXCHANGE, //csp->certificate_request_algorithm_id(),
            X509_ASN_ENCODING,
            NULL,
            &dwPubKeySize))
    {
        fprintf(stderr, "CryptExportPublicKeyInfo #1 failed with: 0x%x\n",
                GetLastError());
        return 1;
    }

    BYTE bPubKeyBlob[dwPubKeySize];
    if (!CryptExportPublicKeyInfo(
            hProv,
            AT_KEYEXCHANGE, //csp->certificate_request_algorithm_id(),
            X509_ASN_ENCODING,
            (CERT_PUBLIC_KEY_INFO *)bPubKeyBlob,
            &dwPubKeySize))
    {
        fprintf(stderr, "CryptExportPublicKeyInfo #2 failed with: 0x%x\n",
                GetLastError());
        return 1;
    }

    CERT_PUBLIC_KEY_INFO *pPubKeyInfo = (CERT_PUBLIC_KEY_INFO *)bPubKeyBlob;

    CERT_REQUEST_INFO req_info;
    memset(&req_info, 0, sizeof(req_info));
    req_info.dwVersion      = CERT_REQUEST_V1;
    req_info.Subject.cbData = dwSubjectBlobSize;
    req_info.Subject.pbData = bSubjectBlob;
    req_info.SubjectPublicKeyInfo = *pPubKeyInfo;

    /*
    blob extblob;
    CRYPT_ATTR_BLOB attr_blob;
    CRYPT_ATTRIBUTE attr_ex;
    if (certext.get()->cExtension > 0)
    {
        extblob                      = certext.encode();
        attr_blob.cbData             = (DWORD)extblob.size();
        attr_blob.pbData             = &extblob[0];
        attr_ex.cValue               = 1;
        attr_ex.pszObjId             = szOID_CERT_EXTENSIONS;
        attr_ex.rgValue              = &attr_blob;
        req_info.cAttribute          = 1;
        req_info.rgAttribute         = &attr_ex;
    }
    else
    {
        req_info.cAttribute          = 0;
        req_info.rgAttribute         = nullptr;
    }
    */

    req_info.cAttribute          = 0;
    req_info.rgAttribute         = NULL;

    CRYPT_ALGORITHM_IDENTIFIER alg_id;
    memset(&alg_id, 0, sizeof(alg_id));
    alg_id.pszObjId = szSignAlg;

    DWORD dwReqBlobSize = 0;
    if (!CryptSignAndEncodeCertificate(
            hProv,
            AT_KEYEXCHANGE, //csp()->certificate_request_algorithm_id(),
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            X509_CERT_REQUEST_TO_BE_SIGNED,
            &req_info,
            &alg_id,
            NULL,
            NULL,
            &dwReqBlobSize))
    {
        fprintf(stderr, "CryptSignAndEncodeCertificate #1 failed with: 0x%x\n",
                GetLastError());
        return 1;
    }

    BYTE bReqBlob[dwReqBlobSize];
    if (!CryptSignAndEncodeCertificate(
            hProv,
            AT_KEYEXCHANGE, //csp()->certificate_request_algorithm_id(),
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            X509_CERT_REQUEST_TO_BE_SIGNED,
            &req_info,
            &alg_id,
            NULL,
            bReqBlob,
            &dwReqBlobSize))
    {
        fprintf(stderr, "CryptSignAndEncodeCertificate #2 failed with: 0x%x\n",
                GetLastError());
        return 1;
    }

    CHAR szFileName[255];
    snprintf(szFileName, sizeof(szFileName), "%s.req", szReqName);

    FILE *file = fopen(szFileName, "wb");
    fwrite(bReqBlob, dwReqBlobSize, 1, file);
    fclose(file);

    CryptReleaseContext(hProv, 0);

    return 0;
}
