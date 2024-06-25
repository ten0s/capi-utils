#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <string.h>

#ifdef _WIN32
#   include <windows.h>
#   include <winsock.h>
#   include <wincrypt.h>
#   include <cryptuiapi.h>
#   include <wintrust.h>
#   include <schannel.h>
#   define SECURITY_WIN32
#   include <security.h>
#   include <sspi.h>
#   include <tchar.h>
#   define IS_SOCKET_ERROR(a) (a==SOCKET_ERROR)
#else
#   include "CSP_WinDef.h"
#   include "CSP_WinCrypt.h"
#   include "CSP_Sspi.h"
#   include "CSP_SChannel.h"
#   include <sys/types.h>
#   if defined (_AIX) || defined (ANDROID)
#	include <fcntl.h>
#   else
#	include <sys/fcntl.h>
#   endif
#   include <sys/stat.h>
#   include <sys/socket.h>
#   include <netinet/in.h>
#   include <arpa/inet.h>
#   include <netdb.h>
#   include <errno.h>
#   include <unistd.h>

#   define INVALID_SOCKET (-1)
#   define IS_SOCKET_ERROR(a) ((unsigned)a == (unsigned)-1)
    typedef int SOCKET;
    typedef struct sockaddr_in SOCKADDR_IN;
    typedef struct sockaddr *LPSOCKADDR;
    static int WSAGetLastError()
    {
      return errno;
    }
#   define LocalAlloc(a, b) malloc(b)
#   define LocalFree free
#   define MoveMemory memmove
#   define closesocket close
#endif

#include "WinCryptEx.h" // # dpkg -i lsb-cprocsp-devel_5.0.12000-6_all.deb
#include "AvCSPDef.h"
#include "wineutil.h"

#define IO_BUFFER_SIZE  0x8000

#define DEFAULT_FILENAME "/index.html"
#define DEFAULT_SSPI_DLL "secur32.dll"

// Опции пользователя.
static LPSTR   pszServerName   = NULL;
static LPSTR   pszSNI          = NULL;
static BOOL    bCertDialog     = FALSE;
static LPSTR   pszThumbprint   = NULL;
static LPSTR   pszCertPass     = NULL;
static INT     iPortNumber     = 443;
static LPSTR   pszHeader       = NULL;
static LPCSTR  pszFileName     = DEFAULT_FILENAME;
static LPCSTR  pszSSPIDll      = DEFAULT_SSPI_DLL;
static BOOL    bInitA          = TRUE;
static LPSTR   pszSecPkgName   = UNISP_NAME;

static HCERTSTORE      hMyCertStore = NULL;

static SCHANNEL_CRED   SchannelCred;

#ifdef _WIN32
static HMODULE g_hSSPI = NULL;
#endif

static PSecurityFunctionTableA g_pSSPI_A;
static PSecurityFunctionTableW g_pSSPI_W;

static
SECURITY_STATUS
CreateCredentials(
    PCredHandle phCreds);

static INT
ConnectToServer(
    LPSTR pszServerName,
    INT   iPortNumber,
    SOCKET *pSocket);

static
SECURITY_STATUS
PerformClientHandshake(
    SOCKET          Socket,
    PCredHandle     phCreds,
    LPSTR           pszServerName,
    CtxtHandle *    phContext,
    SecBuffer *     pExtraData);

static
SECURITY_STATUS
ClientHandshakeLoop(
    SOCKET          Socket,
    PCredHandle     phCreds,
    CtxtHandle *    phContext,
    BOOL            fDoInitialRead,
    SecBuffer *     pExtraData);

static
SECURITY_STATUS
HttpsGetFile(
    SOCKET          Socket,
    PCredHandle     phCreds,
    CtxtHandle *    phContext,
    LPCSTR          pszFileName);

static
void
DisplayCertChain(
    PCCERT_CONTEXT  pServerCert,
    BOOL            fLocal);

static
DWORD
VerifyServerCertificate(
    PCCERT_CONTEXT  pServerCert,
    PSTR            pszServerName,
    DWORD           dwCertFlags);

static
LONG
DisconnectFromServer(
    SOCKET          Socket,
    PCredHandle     phCreds,
    CtxtHandle *    phContext);

static void
DisplayConnectionInfo(
    CtxtHandle *phContext);

static void
GetNewClientCredentials(
    CredHandle *phCreds,
    CtxtHandle *phContext);

static void Usage()
{
    printf("\n");
    printf("Usage: https <options>\n");
    printf("Options:\n");
    printf("    -s<server>      DNS name of server\n");
    printf("    -p<port>        Port number\n");
    printf("    -f<file>        Request file path, by default: %s\n", DEFAULT_FILENAME);
    printf("    -I<SSPI>        SSPI DLL, by default: %s\n", DEFAULT_SSPI_DLL);
    printf("    -W              Call InitSecurityInterfaceW, by default: InitSecurityInterfaceA\n");
    printf("    -N<sec pkg>     Security package name, by default: UNISP_NAME\n");
    printf("    -H<header>      HTTP header\n");
    printf("    -S<sni>         Server name indication\n");
    printf("    -D              Client certificate select dialog\n");
    printf("    -T<thumbprint>  Client certificate thumbprint\n");
    printf("    -P<cert pass>   Client certificate pass\n");
}

static BOOL
LoadSecurityLibrary()
{
#ifdef _WIN32
    g_hSSPI = LoadLibrary(pszSSPIDll);
    if (g_hSSPI == NULL)
    {
        printf("Error 0x%x loading %s.\n", GetLastError(), pszSSPIDll);
        return FALSE;
    }

    INIT_SECURITY_INTERFACE_A pInitSecurityInterfaceA = NULL;
    INIT_SECURITY_INTERFACE_W pInitSecurityInterfaceW = NULL;

    if (bInitA)
    {
        pInitSecurityInterfaceA = (INIT_SECURITY_INTERFACE_A)
            GetProcAddress(g_hSSPI, "InitSecurityInterfaceA");
    }
    else
    {
        pInitSecurityInterfaceW = (INIT_SECURITY_INTERFACE_W)
            GetProcAddress(g_hSSPI, "InitSecurityInterfaceW");
    }

#else
    if (bInitA)
    {
        pInitSecurityInterfaceA = InitSecurityInterfaceA;
    }
    else
    {
        pInitSecurityInterfaceW = InitSecurityInterfaceW;
    }
#endif

    if (pInitSecurityInterfaceA == NULL && pInitSecurityInterfaceW == NULL)
    {
        printf("Error 0x%x reading InitSecurityInterface entry point.\n",
               GetLastError());
        return FALSE;
    }

    if (bInitA)
    {
        g_pSSPI_A = pInitSecurityInterfaceA();
    }
    else
    {
        g_pSSPI_W = pInitSecurityInterfaceW();
    }

    if (g_pSSPI_A == NULL && g_pSSPI_W == NULL)
    {
        printf("Error 0x%x reading security interface.\n",
               GetLastError());
        return FALSE;
    }

    return TRUE;
}

static void
UnloadSecurityLibrary()
{
#ifdef _WIN32
    FreeLibrary(g_hSSPI);
    g_hSSPI = NULL;
#endif
}


static LPWSTR
Str2WStr(LPCSTR szStr)
{
    LPWSTR wszStr = NULL;

    if (szStr)
    {
        size_t len = strlen(szStr) + 1;
        size_t lenW = MultiByteToWideChar(CP_ACP, 0, szStr, len, NULL, 0);
        wszStr = malloc(lenW * sizeof(WCHAR));
        MultiByteToWideChar(CP_ACP, 0, szStr, len, wszStr, lenW);
    }

    return wszStr;
}

//
// Universal SSPI interface
//

static SECURITY_STATUS
AcquireCredentialsHandleU(
    CHAR *pszPrincipal,
    CHAR *pszPackage,
    ULONG fCredentialUse,
    PLUID pvLogonID,
    PVOID pAuthData,
    SEC_GET_KEY_FN pGetKeyFn,
    PVOID pvGetKeyArgument,
    PCredHandle phCredential,
    PTimeStamp ptsExpiry)
{
    if (bInitA)
    {
        return g_pSSPI_A->AcquireCredentialsHandleA(
            pszPrincipal,
            pszPackage,
            fCredentialUse,
            pvLogonID,
            pAuthData,
            pGetKeyFn,
            pvGetKeyArgument,
            phCredential,
            ptsExpiry);
    }
    else
    {
        LPWSTR pwszPrincipal = Str2WStr(pszPrincipal);
        LPWSTR pwszPackage   = Str2WStr(pszPackage);

        SECURITY_STATUS ret;
        ret = g_pSSPI_W->AcquireCredentialsHandleW(
            pwszPrincipal,
            pwszPackage,
            fCredentialUse,
            pvLogonID,
            pAuthData,
            pGetKeyFn,
            pvGetKeyArgument,
            phCredential,
            ptsExpiry);

        free(pwszPrincipal);
        free(pwszPackage);

        return ret;
    }
}

static SECURITY_STATUS
InitializeSecurityContextU(
    PCredHandle phCredential,
    PCtxtHandle phContext,
    CHAR *pszTargetName,
    ULONG fContextReq,
    ULONG Reserved1,
    ULONG TargetDataRep,
    PSecBufferDesc pInBufferDesc,
    ULONG Reserved2,
    PCtxtHandle phNewContext,
    PSecBufferDesc pOutBufferDesc,
    ULONG *pfContextAttr,
    PTimeStamp ptsExpiry)
{
    if (bInitA)
    {
        return g_pSSPI_A->InitializeSecurityContextA(
            phCredential,
            phContext,
            pszTargetName,
            fContextReq,
            Reserved1,
            TargetDataRep,
            pInBufferDesc,
            Reserved2,
            phNewContext,
            pOutBufferDesc,
            pfContextAttr,
            ptsExpiry);
    }
    else
    {
        LPWSTR pwszTargetName = Str2WStr(pszTargetName);

        SECURITY_STATUS ret;
        ret = g_pSSPI_W->InitializeSecurityContextW(
            phCredential,
            phContext,
            pwszTargetName,
            fContextReq,
            Reserved1,
            TargetDataRep,
            pInBufferDesc,
            Reserved2,
            phNewContext,
            pOutBufferDesc,
            pfContextAttr,
            ptsExpiry);

        free(pwszTargetName);

        return ret;
    }
}

static SECURITY_STATUS
ApplyControlTokenU(
    PCtxtHandle phContext,
    SecBufferDesc *pBufferDesc)
{
    if (bInitA)
    {
        return g_pSSPI_A->ApplyControlToken(
            phContext,
            pBufferDesc);
    }
    else
    {
        return g_pSSPI_W->ApplyControlToken(
            phContext,
            pBufferDesc);
    }
}

static SECURITY_STATUS
DeleteSecurityContextU(
    PCtxtHandle phContext)
{
    if (bInitA)
    {
        return g_pSSPI_A->DeleteSecurityContext(
            phContext);
    }
    else
    {
        return g_pSSPI_W->DeleteSecurityContext(
            phContext);
    }
}

static SECURITY_STATUS
FreeContextBufferU(
    PVOID pvContextBuffer)
{
    if (bInitA)
    {
        return g_pSSPI_A->FreeContextBuffer(
            pvContextBuffer);
    }
    else
    {
        return g_pSSPI_W->FreeContextBuffer(
            pvContextBuffer);
    }
}

static SECURITY_STATUS
FreeCredentialsHandleU(
    PCredHandle phCredential)
{
    if (bInitA)
    {
        return g_pSSPI_A->FreeCredentialsHandle(
            phCredential);
    }
    else
    {
        return g_pSSPI_W->FreeCredentialsHandle(
            phCredential);
    }
}

static SECURITY_STATUS
QueryContextAttributesU(
    PCtxtHandle phContext,
    ULONG ulAttribute,
    PVOID pBuffer)
{
    if (bInitA)
    {
        return g_pSSPI_A->QueryContextAttributesA(
            phContext,
            ulAttribute,
            pBuffer);
    }
    else
    {
        return g_pSSPI_W->QueryContextAttributesW(
            phContext,
            ulAttribute,
            pBuffer);
    }
}

static SECURITY_STATUS
EncryptMessageU(
    PCtxtHandle phContext,
    ULONG fQOP,
    SecBufferDesc *pBufferDesc,
    ULONG MessageSeqNo)
{
    if (bInitA)
    {
        return g_pSSPI_A->EncryptMessage(
            phContext,
            fQOP,
            pBufferDesc,
            MessageSeqNo);
    }
    else
    {
        return g_pSSPI_W->EncryptMessage(
            phContext,
            fQOP,
            pBufferDesc,
            MessageSeqNo);
    }
}

static SECURITY_STATUS
DecryptMessageU(
    PCtxtHandle phContext,
    SecBufferDesc *pBufferDesc,
    ULONG MessageSeqNo,
    ULONG *pfQOP)
{
    if (bInitA)
    {
        return g_pSSPI_A->DecryptMessage(
            phContext,
            pBufferDesc,
            MessageSeqNo,
            pfQOP);
    }
    else
    {
        return g_pSSPI_W->DecryptMessage(
            phContext,
            pBufferDesc,
            MessageSeqNo,
            pfQOP);
    }
}

#ifdef _WIN32
int _cdecl
#else
int
#endif
main(int argc, char *argv[])
{
#ifdef _WIN32
    WSADATA WsaData;
#endif
    SOCKET  Socket = INVALID_SOCKET;

    CredHandle hClientCreds;
    CtxtHandle hContext;
    BOOL fCredsInitialized = FALSE;
    BOOL fContextInitialized = FALSE;

    SecBuffer  ExtraData;
    SECURITY_STATUS Status;

    int ret = 1;
    INT i;
    INT iOption;
    PCHAR pszOption;

    if (argc <= 1)
    {
        Usage();
        return 1;
    }

    for (i = 1; i < argc; i++)
    {
        if (argv[i][0] == '/') argv[i][0] = '-';

        if (argv[i][0] != '-')
        {
            printf("**** Invalid argument \"%s\"\n", argv[i]);
            Usage();
            return 1;
        }

        iOption = argv[i][1];
        pszOption = &argv[i][2];

        switch (iOption)
        {
        case 's':
            pszServerName = pszOption;
            break;

        case 'p':
            iPortNumber = atoi(pszOption);
            break;

        case 'f':
            pszFileName = pszOption;
            break;

        case 'I':
            pszSSPIDll = pszOption;
            break;

        case 'W':
            bInitA = FALSE;
            break;

        case 'N':
            pszSecPkgName = pszOption;
            break;

        case 'H':
            pszHeader = pszOption;
            break;

        case 'S':
            pszSNI = pszOption;
            break;

        case 'D':
            bCertDialog = TRUE;
            break;

        case 'T':
            pszThumbprint = pszOption;
            break;

        case 'P':
            pszCertPass = pszOption;
            break;

        default:
            printf("**** Invalid option \"%s\"\n", argv[i]);
            Usage();
            return 1;
        }
    }


    if (!LoadSecurityLibrary())
    {
        printf("Error initializing the security library\n");
        goto cleanup;
    }

#ifdef _WIN32
    //
    // Инициализация подсистемы WinSock.
    //

    if (WSAStartup(0x0101, &WsaData) == SOCKET_ERROR)
    {
        printf("Error %d returned by WSAStartup\n", GetLastError());
        goto cleanup;
    }

    //
    // Инициализация WineUtil
    //
    if (IsWine() && !WineUtilInit(WINEUTIL_DLL))
    {
        printf("Error initializing WineUtil\n");
        goto cleanup;
    }
#endif
    //
    // Создание мандатов.
    //

    if (CreateCredentials(&hClientCreds))
    {
        printf("Error creating credentials\n");
        goto cleanup;
    }
    fCredsInitialized = TRUE;

    //
    // Соединение с сервером.
    //

    if (ConnectToServer(pszServerName, iPortNumber, &Socket))
    {
        printf("Error connecting to server\n");
        goto cleanup;
    }

    //
    // Установление связи
    //
    if (PerformClientHandshake(Socket,
                              &hClientCreds,
                              pszServerName,
                              &hContext,
                              &ExtraData))
    {
    LocalFree(ExtraData.pvBuffer); /* pacify CSA */
        printf("Error performing handshake\n");
        goto cleanup;
    }
    LocalFree(ExtraData.pvBuffer); /* pacify CSA */
    fContextInitialized = TRUE;

    //
    // Вывод информации о соединении.
    //

    DisplayConnectionInfo(&hContext);

    //
    // Чтение файла с сервера.
    //

    if (HttpsGetFile(Socket,
                    &hClientCreds,
                    &hContext,
                    pszFileName))
    {
        printf("Error fetching file from server\n");
        goto cleanup;
    }

    //
    // Отправка уведомления серверу и закрытие соединения.
    //

    if (DisconnectFromServer(Socket, &hClientCreds, &hContext))
    {
        printf("Error disconnecting from server\n");
        goto cleanup;
    }
    fContextInitialized = FALSE;
    Socket = INVALID_SOCKET;


    ret = 0;
cleanup:

#if 0
    // Освобождение контекста сертификата сервера.
    if (pRemoteCertContext)
    {
        CertFreeCertificateContext(pRemoteCertContext);
        pRemoteCertContext = NULL;
    }
#endif

    // Освобождение дескриптора SSPI контекста.
    if (fContextInitialized)
    {
        DeleteSecurityContextU(&hContext);
    }

    // Освобождение дескриптора SSPI мандатов.
    if (fCredsInitialized)
    {
        FreeCredentialsHandleU(&hClientCreds);
    }

    // Закрытие сокета.
    if (Socket != INVALID_SOCKET)
    {
        closesocket(Socket);
    }

#ifdef _WIN32
    // Завершение работы подсистемы WinSock.
    WSACleanup();
#endif

    // Закрытие хранилища сертификатов "MY".
    if (hMyCertStore)
    {
        CertCloseStore(hMyCertStore, 0);
    }

    UnloadSecurityLibrary();

    printf("Done\n");
    return ret;
}

static BOOL SetCertPass(PCCERT_CONTEXT pCertContext, LPCSTR pszCertPass)
{
    HCRYPTPROV hCryptProv;
    DWORD dwKeySpec = 0;

    if (CryptAcquireCertificatePrivateKey(pCertContext,
                                          CRYPT_ACQUIRE_SILENT_FLAG,
                                          NULL,
                                          &hCryptProv,
                                          &dwKeySpec,
                                          NULL))
    {
        DWORD dwNameLen = 0;
        CryptGetProvParam(hCryptProv, PP_CONTAINER, NULL, &dwNameLen, 0);

        LPSTR szName = LocalAlloc(LMEM_FIXED, dwNameLen);

        if (!CryptGetProvParam(hCryptProv, PP_CONTAINER, szName, &dwNameLen, 0))
        {
            return FALSE;
        }

        if (!CryptSetProvParam(hCryptProv, PP_KEYEXCHANGE_PIN, pszCertPass, 0))
        {
            return FALSE;
        }

        HCRYPTKEY hXchgKey;
        if (!CryptGetUserKey(hCryptProv, AT_KEYEXCHANGE, &hXchgKey))
        {
            return FALSE;
        }

        CryptDestroyKey(hXchgKey);

        LocalFree(szName);
        return TRUE;
    }

    return FALSE;
}

//-------------------------------------------------------------
// Функция создания мандатов.
static
SECURITY_STATUS
CreateCredentials(
    PCredHandle phCreds)            // out
{
    TimeStamp       tsExpiry;
    SECURITY_STATUS Status;

    DWORD           cSupportedAlgs = 0;
    ALG_ID          rgbSupportedAlgs[16];
    // -1 - 0 suites
    // For CALG_ values see enum-provider-algs.exe
    //rgbSupportedAlgs[cSupportedAlgs++] = -1; //CALG_G28147; //CALG_DH_EPHEM;

    // Открытие хранилища сертификатов "MY" , в котором Internet Explorer
    // хранит сертификаты клиента.
    hMyCertStore = CertOpenSystemStoreA(0, "MY");

    if(!hMyCertStore)
    {
        printf("**** Error 0x%x returned by CertOpenSystemStoreA\n",
               GetLastError());
        return SEC_E_NO_CREDENTIALS;
    }

    // Построение структуры Schannel мандатов.
    // В данном примере определяются используемые протокол и сертификат.

    ZeroMemory(&SchannelCred, sizeof(SchannelCred));
    SchannelCred.dwVersion  = SCHANNEL_CRED_VERSION;
    SchannelCred.grbitEnabledProtocols = 0; // Choose TLS version automatically

    if (cSupportedAlgs)
    {
        SchannelCred.cSupportedAlgs    = cSupportedAlgs;
        SchannelCred.palgSupportedAlgs = rgbSupportedAlgs;
    }

    // Don't send client certificate without server's request
    SchannelCred.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;

    // Флаг SCH_CRED_MANUAL_CRED_VALIDATION установлен, поскольку
    // поскольку в данном примере сертификат сервера проверяется "вручную".
    SchannelCred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;

    // Automatic certificate validation
    //SchannelCred.dwFlags |= SCH_CRED_AUTO_CRED_VALIDATION;

    BYTE *bHashData = NULL;
    DWORD dwHashLen = 0;

    if (bCertDialog)
    {
        HCERTSTORE hCertStore = CertOpenSystemStoreA(0, "MY");
        PCCERT_CONTEXT pCertContext = CryptUIDlgSelectCertificateFromStore(
            hCertStore,
            GetForegroundWindow(),
            L"Select Certificate",
            L"Select Certificate",
            CRYPTUI_SELECT_FRIENDLYNAME_COLUMN |
            CRYPTUI_SELECT_INTENDEDUSE_COLUMN  |
            CRYPTUI_SELECT_LOCATION_COLUMN,
            0,
            NULL);
        CertCloseStore(hCertStore, 0);

        if (!pCertContext)
        {
            return SEC_E_NO_CREDENTIALS;
        }

        CertGetCertificateContextProperty(
            pCertContext,
            CERT_SHA1_HASH_PROP_ID,
            NULL,
            &dwHashLen);

        bHashData = LocalAlloc(LMEM_FIXED, dwHashLen);

        if (!CertGetCertificateContextProperty(
                pCertContext,
                CERT_SHA1_HASH_PROP_ID,
                bHashData,
                &dwHashLen))
        {
            LocalFree(bHashData);
            printf("CertGetCeritificateContextProperty failed with: 0x%x\n", GetLastError());
            return SEC_E_NO_CREDENTIALS;
        }
    }

    // Client Certificate Authentication if Certificate SHA Hash is given
    if (pszThumbprint)
    {
        dwHashLen = 0;
        if (!CryptStringToBinaryA(pszThumbprint, 0,
                                  CRYPT_STRING_HEX, //CRYPT_STRING_HEXRAW isn't impemented in wine,
                                  NULL, &dwHashLen,
                                  NULL, NULL))
        {
            printf("CryptStringToBinary failed with: 0x%x\n", GetLastError());
            return SEC_E_NO_CREDENTIALS;
        }

        bHashData = LocalAlloc(LMEM_FIXED, dwHashLen);

        if (!CryptStringToBinaryA(pszThumbprint, 0,
                                  CRYPT_STRING_HEX, //CRYPT_STRING_HEXRAW isn't implemented in wine,
                                  bHashData, &dwHashLen,
                                  NULL, NULL))
        {
            LocalFree(bHashData);
            printf("CryptStringToBinary failed with: 0x%x\n", GetLastError());
            return SEC_E_NO_CREDENTIALS;
        }
    }

    if (bHashData)
    {
        DATA_BLOB blob;
        blob.cbData = dwHashLen;
        blob.pbData = bHashData;

        PCCERT_CONTEXT pCertContext = NULL;
        pCertContext = CertFindCertificateInStore(hMyCertStore,
                                                  X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                  0,
                                                  CERT_FIND_SHA1_HASH, &blob,
                                                  pCertContext);

        CertCloseStore(hMyCertStore, 0);
        LocalFree(bHashData);

        if (pCertContext == NULL)
        {
            printf("Error 0x%x finding cert\n", GetLastError());
            return SEC_E_NO_CREDENTIALS;
        }

        printf("\nCertificate found\n");

        // Store cert password
        if (pszCertPass)
        {
            if (!SetCertPass(pCertContext, pszCertPass))
            {
                printf("Setting cert pass failed: ");
                switch (GetLastError()) {
                case NTE_KEYSET_ENTRY_BAD:
                    printf("NTE_KEYSET_ENTRY_BAD\n");
                    break;
                default:
                    printf("0x%x\n", GetLastError());
                    break;
                }
                return SEC_E_NO_CREDENTIALS;
            }
        }

        SchannelCred.cCreds = 1;
        SchannelCred.paCred = &pCertContext;
    }

    //
    // Создание SSPI мандата.
    //

    Status = AcquireCredentialsHandleU(
        NULL,                   // Name of principal
        pszSecPkgName,          // Name of package
        SECPKG_CRED_OUTBOUND,   // Flags indicating use
        NULL,                   // Pointer to logon ID
        &SchannelCred,          // Package specific data
        NULL,                   // Pointer to GetKey() func
        NULL,                   // Value to pass to GetKey()
        phCreds,                // (out) Cred Handle
        &tsExpiry);             // (out) Lifetime (optional)

    if (Status != SEC_E_OK)
    {
        printf("**** Error 0x%x returned by AcquireCredentialsHandle\n", Status);
        goto cleanup;
    }

cleanup:

    //
    // Освобождение контекста сертификата. В Schannel уже создана его копия.
    //

    return Status;
}

//-------------------------------------------------------------
// Функция, устанавливающая соединение с сервером.
static INT
ConnectToServer(
    LPSTR    pszServerName, // in
    INT      iPortNumber,   // in
    SOCKET * pSocket)       // out
{
  SOCKET Socket;
  struct sockaddr_in sin;
  struct hostent *hp;

  Socket = socket(PF_INET, SOCK_STREAM, 0);
  if (Socket == INVALID_SOCKET)
  {
      printf("**** Error %d creating socket\n", WSAGetLastError());
      return WSAGetLastError();
  }

  sin.sin_family = AF_INET;
  sin.sin_port = htons((u_short)iPortNumber);

  if ((hp = gethostbyname(pszServerName)) == NULL)
  {
      printf("**** Error %d returned by gethostbyname\n", WSAGetLastError());
      return WSAGetLastError();
  }
  else
  {
      memcpy(&sin.sin_addr, hp->h_addr, 4);
  }

  if (IS_SOCKET_ERROR(connect(Socket, (struct sockaddr *)&sin, sizeof(sin))))
  {
      printf("**** Error %d connecting to \"%s\" (%s)\n",
             WSAGetLastError(),
             pszServerName,
             inet_ntoa(sin.sin_addr));
      closesocket(Socket);
      return WSAGetLastError();
  }

  *pSocket = Socket;

  return SEC_E_OK;
}

//-------------------------------------------------------------
// Функция, выполняющая разрыв соединения с сервером.

static
LONG
DisconnectFromServer(
    SOCKET          Socket,
    PCredHandle     phCreds,
    CtxtHandle *    phContext)
{
    DWORD           dwType;
    char*           pbMessage;
    DWORD           cbMessage;
    DWORD           cbData;

    SecBufferDesc   OutBuffer;
    SecBuffer       OutBuffers[1];
    DWORD           dwSSPIFlags;
    unsigned long   dwSSPIOutFlags;
    TimeStamp       tsExpiry;
    DWORD           Status;

    //
    // Уведомление schannel о закрытии соединения.
    //

    dwType = SCHANNEL_SHUTDOWN;

    OutBuffers[0].pvBuffer   = &dwType;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer   = sizeof(dwType);

    OutBuffer.cBuffers  = 1;
    OutBuffer.pBuffers  = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    Status = ApplyControlTokenU(phContext, &OutBuffer);

    if (FAILED(Status))
    {
        printf("**** Error 0x%x returned by ApplyControlToken\n", Status);
        goto cleanup;
    }

    //
    // Построение SSL сообщения, являющегося уведомлением о закрытии.
    //

    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT   |
                  ISC_REQ_REPLAY_DETECT     |
                  ISC_REQ_CONFIDENTIALITY   |
                  ISC_RET_EXTENDED_ERROR    |
                  ISC_REQ_ALLOCATE_MEMORY   |
                  ISC_REQ_STREAM;

    OutBuffers[0].pvBuffer   = NULL;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer   = 0;

    OutBuffer.cBuffers  = 1;
    OutBuffer.pBuffers  = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    Status = InitializeSecurityContextU(
        phCreds,
        phContext,
        pszSNI,
        dwSSPIFlags,                 // fContextReq
        0,                           // Reserved1
        0,                           // Unused in SChannel
        NULL,                        // pInput
        0,                           // Reserved2
        phContext,
        &OutBuffer,
        &dwSSPIOutFlags,
        &tsExpiry);

    if (FAILED(Status))
    {
        printf("**** Error 0x%x returned by InitializeSecurityContext\n", Status);
        goto cleanup;
    }

    pbMessage = OutBuffers[0].pvBuffer;
    cbMessage = OutBuffers[0].cbBuffer;


    //
    // Посылка этого сообщения серверу.
    //

    if (pbMessage != NULL && cbMessage != 0)
    {
        cbData = send(Socket, pbMessage, cbMessage, 0);
        if (IS_SOCKET_ERROR(cbData) || cbData == 0)
        {
            Status = WSAGetLastError();
            printf("**** Error %d sending close notify\n", Status);
            goto cleanup;
        }

        printf("Sending Close Notify\n");
        printf("%d bytes of handshake data sent\n", cbData);

        // Освобождение выходного буфера.
        FreeContextBufferU(pbMessage);
    }


cleanup:

    // Освобождение закрытого контекста.
    DeleteSecurityContextU(phContext);

    // Закрытие сокета.
    closesocket(Socket);

    return Status;
}

//-------------------------------------------------------------
// Функция установления связи клиента с сервером.
static
SECURITY_STATUS
PerformClientHandshake(
    SOCKET          Socket,         // in
    PCredHandle     phCreds,        // in
    LPSTR           pszServerName,  // in
    CtxtHandle *    phContext,      // out
    SecBuffer *     pExtraData)     // out
{
    SecBufferDesc   OutBuffer;
    SecBuffer       OutBuffers[1];
    DWORD           dwSSPIFlags;
    unsigned long   dwSSPIOutFlags;
    TimeStamp       tsExpiry;
    SECURITY_STATUS scRet;
    DWORD           cbData;

    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT   |
                  ISC_REQ_REPLAY_DETECT     |
                  ISC_REQ_CONFIDENTIALITY   |
                  ISC_RET_EXTENDED_ERROR    |
                  ISC_REQ_ALLOCATE_MEMORY   |
                  ISC_REQ_STREAM;

    //
    //  Инициализация сообщения ClientHello и генерация токена.
    //

    OutBuffers[0].pvBuffer   = NULL;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer   = 0;

    OutBuffer.cBuffers = 1;
    OutBuffer.pBuffers = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    scRet = InitializeSecurityContextU(
        phCreds,
        NULL,
        pszSNI,
        dwSSPIFlags,                 // fContextReq
        0,                           // Reserved1
        0,                           // Unused in SChannel
        NULL,                        // pInput
        0,                           // Reserved2
        phContext,
        &OutBuffer,
        &dwSSPIOutFlags,
        &tsExpiry);

    if (scRet != SEC_I_CONTINUE_NEEDED)
    {
        printf("**** Error 0x%x returned by InitializeSecurityContext (1)\n", scRet);
        return scRet;
    }

    // Посылка отвера серверу.
    if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
    {
        cbData = send(Socket,
                      OutBuffers[0].pvBuffer,
                      OutBuffers[0].cbBuffer,
                      0);
        if (IS_SOCKET_ERROR(cbData) || cbData == 0)
        {
            printf("**** Error %d sending data to server (1)\n", WSAGetLastError());
            FreeContextBufferU(OutBuffers[0].pvBuffer);
            DeleteSecurityContextU(phContext);
            return SEC_E_INTERNAL_ERROR;
        }

        printf("%d bytes of handshake data sent\n", cbData);


        // Освобождение выходного буфера.
        FreeContextBufferU(OutBuffers[0].pvBuffer);
        OutBuffers[0].pvBuffer = NULL;
    }

    return ClientHandshakeLoop(Socket, phCreds, phContext, TRUE, pExtraData);
}

//-------------------------------------------------------------
// Функция обмена сообщениями между клиентом и сервером.
static
SECURITY_STATUS
ClientHandshakeLoop(
    SOCKET          Socket,         // in
    PCredHandle     phCreds,        // in
    CtxtHandle *    phContext,      // in, out
    BOOL            fDoInitialRead, // in
    SecBuffer *     pExtraData)     // out
{
    SecBufferDesc   InBuffer;
    SecBuffer       InBuffers[2];
    SecBufferDesc   OutBuffer;
    SecBuffer       OutBuffers[1];
    DWORD           dwSSPIFlags;
    unsigned long   dwSSPIOutFlags;
    TimeStamp       tsExpiry;
    SECURITY_STATUS scRet;
    DWORD           cbData;

    char*          IoBuffer;
    DWORD           cbIoBuffer;
    BOOL            fDoRead;


    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT   |
                  ISC_REQ_REPLAY_DETECT     |
                  ISC_REQ_CONFIDENTIALITY   |
                  ISC_RET_EXTENDED_ERROR    |
                  ISC_REQ_ALLOCATE_MEMORY   |
                  ISC_REQ_STREAM;

    //
    // Размещение буфера данных.
    //

    IoBuffer = LocalAlloc(LMEM_FIXED, IO_BUFFER_SIZE);
    if (IoBuffer == NULL)
    {
        printf("**** Out of memory (1)\n");
        return SEC_E_INTERNAL_ERROR;
    }
    cbIoBuffer = 0;

    fDoRead = fDoInitialRead;

    //
    // Цикл до тех пока, пока не закончится обмен сообщениями,
    // либо не произойдет ошибка.
    //

    scRet = SEC_I_CONTINUE_NEEDED;

    while (scRet == SEC_I_CONTINUE_NEEDED        ||
           scRet == SEC_E_INCOMPLETE_MESSAGE     ||
           scRet == SEC_I_INCOMPLETE_CREDENTIALS)
   {

        //
        // Чтение данных из сервера.
        //

        if (0 == cbIoBuffer || scRet == SEC_E_INCOMPLETE_MESSAGE)
        {
            if (fDoRead)
            {
                cbData = recv(Socket,
                              IoBuffer + cbIoBuffer,
                              IO_BUFFER_SIZE - cbIoBuffer,
                              0);
                if (IS_SOCKET_ERROR(cbData))
                {
                    printf("**** Error %d reading data from server\n", WSAGetLastError());
                    scRet = SEC_E_INTERNAL_ERROR;
                    break;
                }
                else if (cbData == 0)
                {
                    printf("**** Server unexpectedly disconnected\n");
                    scRet = SEC_E_INTERNAL_ERROR;
                    break;
                }

                printf("%d bytes of handshake data received\n", cbData);
                cbIoBuffer += cbData;
            }
            else
            {
                fDoRead = TRUE;
            }
        }

        //
        // Установка входных буферов. Buffer 0 содержит данные, получаемые
        // от сервера. Schannel поглощает некоторые или все из них.
        // Оставшиеся данные (в любом случае) располагаются в  buffer 1 и
        // получают тип буфера SECBUFFER_EXTRA.
        //

        InBuffers[0].pvBuffer   = IoBuffer;
        InBuffers[0].cbBuffer   = cbIoBuffer;
        InBuffers[0].BufferType = SECBUFFER_TOKEN;

        InBuffers[1].pvBuffer   = NULL;
        InBuffers[1].cbBuffer   = 0;
        InBuffers[1].BufferType = SECBUFFER_EMPTY;

        InBuffer.cBuffers       = 2;
        InBuffer.pBuffers       = InBuffers;
        InBuffer.ulVersion      = SECBUFFER_VERSION;

        //
        // Установка выходных буферов. Инициализация производится таким образом,
        // чтобы pvBuffer содержал NULL.
        // Это сделано для того, чтобы в случае неудачи не было необходимости
        // выполнять освобождение памяти.
        //

        OutBuffers[0].pvBuffer  = NULL;
        OutBuffers[0].BufferType= SECBUFFER_TOKEN;
        OutBuffers[0].cbBuffer  = 0;

        OutBuffer.cBuffers      = 1;
        OutBuffer.pBuffers      = OutBuffers;
        OutBuffer.ulVersion     = SECBUFFER_VERSION;

        //
        // Вызов InitializeSecurityContext.
        //

        scRet = InitializeSecurityContextU(
            phCreds,
            phContext,
            pszSNI,
            dwSSPIFlags,
            0,
            0,
            &InBuffer,
            0,
            NULL,
            &OutBuffer,
            &dwSSPIOutFlags,
            &tsExpiry);

        //
        // Если InitializeSecurityContext успешно выполнена (или если произошла
        // одна из распространенных ошибок), то выполняется посылка выходного
        // буфера серверу.
        //

        if ((scRet == SEC_E_OK)                ||
            (scRet == SEC_I_CONTINUE_NEEDED)   ||
            (FAILED(scRet) && (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR)))
        {
            if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
            {
                cbData = send(Socket,
                              OutBuffers[0].pvBuffer,
                              OutBuffers[0].cbBuffer,
                              0);
                if(IS_SOCKET_ERROR(cbData) || cbData == 0)
                {
                    printf("**** Error %d sending data to server (2)\n",
                        WSAGetLastError());
                    FreeContextBufferU(OutBuffers[0].pvBuffer);
                    DeleteSecurityContextU(phContext);
                    return SEC_E_INTERNAL_ERROR;
                }

                printf("%d bytes of handshake data sent\n", cbData);


                // Освобождение выходного буфера.
                FreeContextBufferU(OutBuffers[0].pvBuffer);
                OutBuffers[0].pvBuffer = NULL;
            }
        }


        //
        // Если InitializeSecurityContext вернула ошибку SEC_E_INCOMPLETE_MESSAGE,
        // тогда необходимо прочитать большее количество данных от сервера и
        // повторить попытку снова.
        //

        if (scRet == SEC_E_INCOMPLETE_MESSAGE)
        {
            DWORD x;
            for (x = 0; x < InBuffer.cBuffers; x++)
                if (InBuffers[x].BufferType == SECBUFFER_MISSING)
                    printf("InBuffers[%u].SECBUFFER_MISSING: %u bytes.\n",
                           x, InBuffers[x].cbBuffer);
            continue;
        }


        //
        // Если InitializeSecurityContext возвратила SEC_E_OK, тогда
        // обмен данными завершился успешно.
        //

        if (scRet == SEC_E_OK)
        {
            //
            // Если "extra" буфер содержит данные, то они являются данными
            // протокола зашифрования. Их необходимо сохранить.
            // Приложение позже расшифрует их при помощи DecryptMessage.
            //

            printf("Handshake was successful\n");

            if (InBuffers[1].BufferType == SECBUFFER_EXTRA)
            {
                pExtraData->pvBuffer = LocalAlloc(LMEM_FIXED,
                                                  InBuffers[1].cbBuffer);
                if (pExtraData->pvBuffer == NULL)
                {
                    printf("**** Out of memory (2)\n");
                    return SEC_E_INTERNAL_ERROR;
                }

                MoveMemory(pExtraData->pvBuffer,
                           IoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer),
                           InBuffers[1].cbBuffer);

                pExtraData->cbBuffer   = InBuffers[1].cbBuffer;
                pExtraData->BufferType = SECBUFFER_TOKEN;

                printf("%d bytes of app data was bundled with handshake data\n",
                    pExtraData->cbBuffer);
            }
            else
            {
                pExtraData->pvBuffer   = NULL;
                pExtraData->cbBuffer   = 0;
                pExtraData->BufferType = SECBUFFER_EMPTY;
            }

            //
            // Выход
            //

            break;
        }

        //
        // Проверка на ошибки.
        //

        if (FAILED(scRet))
        {
            printf("**** Error 0x%x returned by InitializeSecurityContext (2)\n", scRet);
            break;
        }


        //
        // Если InitializeSecurityContext возвратила SEC_I_INCOMPLETE_CREDENTIALS,
        // то сервер только что запросил аутентификацию клиента.
        //

        if (scRet == SEC_I_INCOMPLETE_CREDENTIALS)
        {
            //
            // Ошибка. Сервер запросил аутентификацию клиента, но переданный
            // мандат не содержит сертификата клиента.
            //

            //
            // Эта функция читает список доверенных сертификатов авторов
            // ("issuers"), полученный от сервера и пытается найти
            // подходящий сертификат клиента. Если эта функция выполнена успешно,
            // то происходит соединение при помощи нового сертификата.
            // В противном случае осуществляется попытка произвести
            // соединение анонимно (используя текущий мандат).
            //

            GetNewClientCredentials(phCreds, phContext);

            // Повторная попытка.
            fDoRead = FALSE;
            scRet = SEC_I_CONTINUE_NEEDED;

            // Исправляем ошибку Platform SDK!
            // Считаем, что за этим сообщением не может следовать другое
            cbIoBuffer = 0;

            continue;
        }

        //
        // Копирование всех данных из "extra" буфера и повторная попытка.
        //

        if ( InBuffers[1].BufferType == SECBUFFER_EXTRA )
        {
            MoveMemory(IoBuffer,
                       IoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer),
                       InBuffers[1].cbBuffer);

            cbIoBuffer = InBuffers[1].cbBuffer;
        }
        else
        {
            cbIoBuffer = 0;
        }
    }

    // Уничтожение закрытого контекста в случае непоправимой ошибки.
    if (FAILED(scRet))
    {
        DeleteSecurityContextU(phContext);
    }

    LocalFree(IoBuffer);

    return scRet;
}


//-------------------------------------------------------------
// Функция получения файла при помощи Https.
static
SECURITY_STATUS
HttpsGetFile(
    SOCKET          Socket,         // in
    PCredHandle     phCreds,        // in
    CtxtHandle *    phContext,      // in
    LPCSTR          pszFileName)    // in
{
    SecPkgContext_StreamSizes Sizes;
    SECURITY_STATUS scRet;
    SecBufferDesc   Message;
    SecBuffer       Buffers[4];
    SecBuffer *     pDataBuffer;
    SecBuffer *     pExtraBuffer;
    SecBuffer       ExtraBuffer;

    char* pbIoBuffer;
    DWORD cbIoBuffer;
    DWORD cbIoBufferLength;
    char* pbMessage;
    DWORD cbMessage;

    DWORD cbData;
    INT   i;

    //
    // Чтение свойств поточного зашифрования.
    //

    scRet = QueryContextAttributesU(
        phContext,
        SECPKG_ATTR_STREAM_SIZES, // 4
        &Sizes);
    if (scRet != SEC_E_OK)
    {
        printf("**** Error 0x%x reading SECPKG_ATTR_STREAM_SIZES\n", scRet);
        return scRet;
    }

    printf("\nHeader: %lu, Trailer: %lu, MaxMessage: %lu\n",
        Sizes.cbHeader,
        Sizes.cbTrailer,
        Sizes.cbMaximumMessage);

    //
    // Аутентификация мандатов сервера.
    //

    // Получение сертификата сервера.
    SECURITY_STATUS Status;
    PCCERT_CONTEXT pRemoteCertContext = NULL;
    Status = QueryContextAttributesU(
        phContext,
        SECPKG_ATTR_REMOTE_CERT_CONTEXT,
        (PVOID)&pRemoteCertContext);
    if (Status != SEC_E_OK)
    {
        printf("Error 0x%x querying remote certificate\n", Status);
        //goto cleanup;
        return Status;
    }

    // For Wine and cpsspi_proxy.dll.so case
    PCCERT_CONTEXT pCertContext;
    pCertContext = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        pRemoteCertContext->pbCertEncoded, pRemoteCertContext->cbCertEncoded);

    if (!pCertContext)
    {
        fprintf(stderr, "CertCreateCertificateContext failed with 0x%x\n",
                GetLastError());
        //return 1;
    }

    // Вывод цепочки сертификатов сервера.
    DisplayCertChain(pCertContext, FALSE);

    // Проверка действительности сертификата сервера.
    Status = VerifyServerCertificate(pCertContext,
                                     pszServerName,
                                     0);
    if (Status)
    {
        // Сертификат сервера не действителен. Возможно было осуществлено
        // соединение с недопустимым сервером, либо производилась атака
        // "противник посередине".

        // Лучше всего прервать соединение.

        printf("**** Error 0x%x authenticating server credentials!\n", Status);
        // goto cleanup;
        return Status;
    }

    // Освобождение контекста сертификата сервера.
    CertFreeCertificateContext(pCertContext);

    // TODO: Cleanup pRemoteCertContext, for Wine and cpsspi_proxy.dll.so use CP_
    // [CP_]CertFreeCertificateContext(pRemoteCertContext);
    pRemoteCertContext = NULL;

// ---

    //
    // Выделение рабочего буфера. Открытый текст, передаваемый EncryptMessage,
    // должен ен провосходить по размерам 'Sizes.cbMaximumMessage', поэтому
    // размер буфера равен этой величене, сложеной с размерами заголовка и
    // заключительной части.
    //

    cbIoBufferLength = Sizes.cbHeader +
                       Sizes.cbMaximumMessage +
                       Sizes.cbTrailer;// Могут быть такие реализации
    // сервера и клиента что длина буфера будет cbIoBufferLength
    // вычисленная таким образом + 2048 байт см. RFC 2246

    pbIoBuffer = LocalAlloc(LMEM_FIXED, cbIoBufferLength);
    if (pbIoBuffer == NULL)
    {
        printf("**** Out of memory (2)\n");
        return SEC_E_INTERNAL_ERROR;
    }

    ZeroMemory(pbIoBuffer, cbIoBufferLength);

    //
    // Построение HTTP запроса серверу.
    //

    // Построение HTTP запроса, сдвинутого на "header size" байт в буфере.
    // Это позволяет Schannel выполнять операцию зашифрования.
    pbMessage = pbIoBuffer + Sizes.cbHeader;

    // Построение HTTP запроса. Он меньше, чем максимальный размер сообщения.
    // Если это не так, что происходит break.

    sprintf(pbMessage,
            "GET %s HTTP/1.1\r\n"
            "Host: %s:%ld\r\n"
            "User-Agent: Webclient\r\n"
            "Connection: close\r\n"
            "Accept:*/*\r\n"
            "%s\r\n"
            "\r\n",
            pszFileName,
            pszServerName, iPortNumber,
            pszHeader ? pszHeader : "");

    cbMessage = (DWORD)strlen(pbMessage);

    printf("Sending plaintext: %d bytes\n", cbMessage);
    printf("----------\n");
    printf("%s", pbMessage);
    printf("----------\n");

    //
    // Шифрование HTTP запроса.
    //

    ZeroMemory(&Buffers, sizeof(Buffers));

    Buffers[0].BufferType   = SECBUFFER_STREAM_HEADER;
    Buffers[0].cbBuffer     = Sizes.cbHeader;
    Buffers[0].pvBuffer     = pbIoBuffer;

    Buffers[1].BufferType   = SECBUFFER_DATA;
    Buffers[1].cbBuffer     = cbMessage;
    Buffers[1].pvBuffer     = pbMessage;

    Buffers[2].BufferType   = SECBUFFER_STREAM_TRAILER;
    Buffers[2].cbBuffer     = Sizes.cbTrailer;
    Buffers[2].pvBuffer     = pbMessage + cbMessage;

    Buffers[3].BufferType   = SECBUFFER_EMPTY;
    Buffers[3].cbBuffer     = 0;
    Buffers[3].pvBuffer     = NULL;

    Message.ulVersion       = SECBUFFER_VERSION;
    Message.cBuffers        = sizeof(Buffers) / sizeof(Buffers[0]);
    Message.pBuffers        = Buffers;

    scRet = EncryptMessageU(phContext, 0, &Message, 0);

    if (FAILED(scRet))
    {
        printf("**** Error 0x%x returned by EncryptMessage\n", scRet);
        return scRet;
    }

    //
    // Посылка зашифрованных данных серверу.
    //

    cbData = send(Socket,
                  pbIoBuffer,
                  Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer,
                  0);
    if (IS_SOCKET_ERROR(cbData) || cbData == 0)
    {
        printf("**** Error %d sending data to server (3)\n",
            WSAGetLastError());
        DeleteSecurityContextU(phContext);
        return SEC_E_INTERNAL_ERROR;
    }

    printf("%d bytes of application data sent\n", cbData);

    //
    // Чтение данных от сервера до их окончания.
    //

    cbIoBuffer = 0;

    for (;;)
    {
        //
        // Чтение данных.
        //

        if (0 == cbIoBuffer || scRet == SEC_E_INCOMPLETE_MESSAGE)
        {
            cbData = recv(Socket,
                          pbIoBuffer + cbIoBuffer,
                          cbIoBufferLength - cbIoBuffer,
                          0);
            if (IS_SOCKET_ERROR(cbData))
            {
                printf("**** Error %d reading data from server\n", WSAGetLastError());
                break;
            }
            else if (cbData == 0)
            {
                // Произошел разрыв соединения с сервером.
                if(cbIoBuffer)
                {
                    printf("**** Server unexpectedly disconnected\n");
                    scRet = SEC_E_INTERNAL_ERROR;
                    return scRet;
                }
                else
                {
                    break;
                }
            }
            else
            {
                printf("%d bytes of (encrypted) application data received\n", cbData);
                cbIoBuffer += cbData;
            }
        }

        //
        // Попытка расшифрования полученных от сервера данных.
        //

        ZeroMemory(&Buffers, sizeof(Buffers));

        Buffers[0].pvBuffer     = pbIoBuffer;
        Buffers[0].cbBuffer     = cbIoBuffer;
        Buffers[0].BufferType   = SECBUFFER_DATA;

        Buffers[1].BufferType   = SECBUFFER_EMPTY;
        Buffers[2].BufferType   = SECBUFFER_EMPTY;
        Buffers[3].BufferType   = SECBUFFER_EMPTY;

        Message.ulVersion       = SECBUFFER_VERSION;
        Message.cBuffers        = sizeof(Buffers) / sizeof(Buffers[0]);
        Message.pBuffers        = Buffers;

        scRet = DecryptMessageU(phContext, &Message, 0, NULL);

        if (scRet == SEC_E_INCOMPLETE_MESSAGE)
        {
            // Входной буфер содержит только фрагмент зашифрованных данных.
            // Продолжение цикла и чтение данных.
            continue;
        }

        // Сервер завершил сессию
        if (scRet == SEC_I_CONTEXT_EXPIRED)
            break;

        if ( scRet != SEC_E_OK &&
            scRet != SEC_I_RENEGOTIATE &&
            scRet != SEC_I_CONTEXT_EXPIRED)
        {
            printf("**** Error 0x%x returned by DecryptMessage\n", scRet);
            return scRet;
        }

        // Расположение данных и (необязательно) добавление буферов.
        pDataBuffer  = NULL;
        pExtraBuffer = NULL;
        for (i = 1; i < sizeof(Buffers) / sizeof(Buffers[0]); i++)
        {

            if (pDataBuffer == NULL && Buffers[i].BufferType == SECBUFFER_DATA)
            {
                pDataBuffer = &Buffers[i];
                printf("Buffers[%d].BufferType = SECBUFFER_DATA\n",i);
            }
            if (pExtraBuffer == NULL && Buffers[i].BufferType == SECBUFFER_EXTRA)
            {
                pExtraBuffer = &Buffers[i];
            }
        }

        // Вывод или обработка расшифрованных данных.
        if (pDataBuffer)
        {
            printf("Decrypted data: %d bytes\n", pDataBuffer->cbBuffer);
            if (pDataBuffer->cbBuffer) {
                LPSTR szBuf = malloc(pDataBuffer->cbBuffer + 1);
                szBuf[pDataBuffer->cbBuffer] = 0;
                memcpy(szBuf, pDataBuffer->pvBuffer, pDataBuffer->cbBuffer);
                printf("----------\n");
                printf("%s\n", szBuf);
                printf("----------\n");
                free(szBuf);
            }
        }

        // Перенос всех "extra" данных во входной буфер.
        if(pExtraBuffer)
        {
            MoveMemory(pbIoBuffer, pExtraBuffer->pvBuffer, pExtraBuffer->cbBuffer);
            cbIoBuffer = pExtraBuffer->cbBuffer;
        }
        else
        {
            cbIoBuffer = 0;
        }

        if (scRet == SEC_I_RENEGOTIATE)
        {
            // Сервер потребовал другой обмен сообщениями с клиентом.

            printf("Server requested renegotiate!\n");

            scRet = ClientHandshakeLoop(Socket,
                                        phCreds,
                                        phContext,
                                        FALSE,
                                        &ExtraBuffer);
            if (scRet != SEC_E_OK)
            {
                return scRet;
            }

            // Перенос всех "extra" данных во входной буфер.
            if (ExtraBuffer.pvBuffer)
            {
                MoveMemory(pbIoBuffer, ExtraBuffer.pvBuffer, ExtraBuffer.cbBuffer);
                cbIoBuffer = ExtraBuffer.cbBuffer;
            }
        }
    }
    LocalFree(pbIoBuffer);
    return SEC_E_OK;
}

//-------------------------------------------------------------
// Функция вывода цепочки сертификатов.
static
void
DisplayCertChain(
    PCCERT_CONTEXT  pServerCert,
    BOOL            fLocal)
{
    CHAR szName[1000];
    PCCERT_CONTEXT pCurrentCert;
    PCCERT_CONTEXT pIssuerCert;
    DWORD dwVerificationFlags;

    printf("\n");

    // Вывод листа цеточки
    CertNameToStrA(pServerCert->dwCertEncodingType,
                   &pServerCert->pCertInfo->Subject,
                   CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
                   szName, sizeof(szName));
    if (fLocal)
    {
        printf("Client subject: %s\n", szName);
    }
    else
    {
        printf("Server subject: %s\n", szName);
    }
    CertNameToStrA(pServerCert->dwCertEncodingType,
                   &pServerCert->pCertInfo->Issuer,
                   CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
                   szName, sizeof(szName));
    if (fLocal)
    {
        printf("Client issuer: %s\n", szName);
    }
    else
    {
        printf("Server issuer: %s\n\n", szName);
    }

    // Вывод цепочки сертификатов
    pCurrentCert = pServerCert;
    while (pCurrentCert != NULL)
    {
        BYTE bHash[20];
        DWORD dwSize = sizeof(bHash) / sizeof(bHash[0]);
        if (/*CP_*/CertGetCertificateContextProperty(
                pCurrentCert,
                CERT_SHA1_HASH_PROP_ID,
                bHash,
                &dwSize
                ))
        {
            printf("Server cert SHA1 hash: ");
            for (int i = 0; i < dwSize; ++i) {
                printf("%02x", bHash[i]);
            }
            printf("\n");
        }
        else
        {
            printf("Server cert SHA1 hash failed: 0x%x\n", GetLastError());
        }

        dwVerificationFlags = 0;
        pIssuerCert = CertGetIssuerCertificateFromStore(
            pServerCert->hCertStore,
            pCurrentCert,
            NULL,
            &dwVerificationFlags);
        if (pIssuerCert == NULL)
        {
            if (pCurrentCert != pServerCert)
            {
                CertFreeCertificateContext(pCurrentCert);
            }
            break;
        }

        CertNameToStrA(pIssuerCert->dwCertEncodingType,
                       &pIssuerCert->pCertInfo->Subject,
                       CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
                       szName, sizeof(szName));
        printf("CA subject: %s\n", szName);
        CertNameToStrA(pIssuerCert->dwCertEncodingType,
                       &pIssuerCert->pCertInfo->Issuer,
                       CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
                       szName, sizeof(szName));
        printf("CA issuer: %s\n\n", szName);

        if (pCurrentCert != pServerCert)
        {
            CertFreeCertificateContext(pCurrentCert);
        }
        pCurrentCert = pIssuerCert;
        pIssuerCert = NULL;
    }
}


//-------------------------------------------------------------
// Функция вывода ошибки полученной при проверке цепочки сертификатов.

static
void
DisplayWinVerifyTrustError(DWORD Status)
{
    LPCSTR pszName = NULL;

    switch (Status)
    {
    case CERT_E_EXPIRED:                pszName = "CERT_E_EXPIRED";                 break;
    case CERT_E_VALIDITYPERIODNESTING:  pszName = "CERT_E_VALIDITYPERIODNESTING";   break;
    case CERT_E_ROLE:                   pszName = "CERT_E_ROLE";                    break;
    case CERT_E_PATHLENCONST:           pszName = "CERT_E_PATHLENCONST";            break;
    case CERT_E_CRITICAL:               pszName = "CERT_E_CRITICAL";                break;
    case CERT_E_PURPOSE:                pszName = "CERT_E_PURPOSE";                 break;
    case CERT_E_ISSUERCHAINING:         pszName = "CERT_E_ISSUERCHAINING";          break;
    case CERT_E_MALFORMED:              pszName = "CERT_E_MALFORMED";               break;
    case CERT_E_UNTRUSTEDROOT:          pszName = "CERT_E_UNTRUSTEDROOT";           break;
    case CERT_E_CHAINING:               pszName = "CERT_E_CHAINING";                break;
    case TRUST_E_FAIL:                  pszName = "TRUST_E_FAIL";                   break;
    case CERT_E_REVOKED:                pszName = "CERT_E_REVOKED";                 break;
    case CERT_E_UNTRUSTEDTESTROOT:      pszName = "CERT_E_UNTRUSTEDTESTROOT";       break;
    case CERT_E_REVOCATION_FAILURE:     pszName = "CERT_E_REVOCATION_FAILURE";      break;
    case CERT_E_CN_NO_MATCH:            pszName = "CERT_E_CN_NO_MATCH";             break;
    case CERT_E_WRONG_USAGE:            pszName = "CERT_E_WRONG_USAGE";             break;
    default:                            pszName = "(unknown)";                      break;
    }

    printf("Error 0x%x (%s) returned by CertVerifyCertificateChainPolicy!\n",
        Status, pszName);
}

//-------------------------------------------------------------
// Функция проверки сертификата сервера.
static
DWORD
VerifyServerCertificate(
    PCCERT_CONTEXT  pServerCert,
    PSTR            pszServerName,
    DWORD           dwCertFlags)
{
    HTTPSPolicyCallbackData  polHttps;
    CERT_CHAIN_POLICY_PARA   PolicyPara;
    CERT_CHAIN_POLICY_STATUS PolicyStatus;
    CERT_CHAIN_PARA          ChainPara;
    PCCERT_CHAIN_CONTEXT     pChainContext = NULL;

    LPSTR rgszUsages[] = {  szOID_PKIX_KP_SERVER_AUTH,
                            szOID_SERVER_GATED_CRYPTO,
                            szOID_SGC_NETSCAPE };
    DWORD cUsages = sizeof(rgszUsages) / sizeof(LPSTR);

    PWSTR   pwszServerName = NULL;
    DWORD   cchServerName;
    HRESULT   Status;

    if (pServerCert == NULL)
    {
        Status = SEC_E_WRONG_PRINCIPAL;
        goto cleanup;
    }

    //
    // Преобразование имени сервера в unicode.
    //

    if (pszServerName == NULL || strlen(pszServerName) == 0)
    {
        Status = SEC_E_WRONG_PRINCIPAL;
        goto cleanup;
    }

    cchServerName = MultiByteToWideChar(CP_ACP, 0, pszServerName, -1, NULL, 0);
    pwszServerName = LocalAlloc(LMEM_FIXED, cchServerName * sizeof(WCHAR));
    if (pwszServerName == NULL)
    {
        Status = SEC_E_INSUFFICIENT_MEMORY;
        goto cleanup;
    }
    cchServerName = MultiByteToWideChar(CP_ACP, 0, pszServerName, -1, pwszServerName, cchServerName);
    if (cchServerName == 0)
    {
        Status = SEC_E_WRONG_PRINCIPAL;
        goto cleanup;
    }

    //
    // Построение цепочки сертификатов.
    //

    ZeroMemory(&ChainPara, sizeof(ChainPara));
    ChainPara.cbSize = sizeof(ChainPara);
    ChainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
    ChainPara.RequestedUsage.Usage.cUsageIdentifier     = cUsages;
    ChainPara.RequestedUsage.Usage.rgpszUsageIdentifier = rgszUsages;

    if (!CertGetCertificateChain(
            NULL,
            pServerCert,
            NULL,
            pServerCert->hCertStore,
            &ChainPara,
            0,
            NULL,
            &pChainContext))
    {
        Status = GetLastError();
        printf("Error 0x%x returned by CertGetCertificateChain!\n", Status);
        goto cleanup;
    }

#if 0
    //
    // Проверка цепочки сертификатов.
    //

    ZeroMemory(&polHttps, sizeof(HTTPSPolicyCallbackData));
    polHttps.cbStruct           = sizeof(HTTPSPolicyCallbackData);
    polHttps.dwAuthType         = AUTHTYPE_SERVER;
    polHttps.fdwChecks          = dwCertFlags;
    polHttps.pwszServerName     = pwszServerName;

    memset(&PolicyPara, 0, sizeof(PolicyPara));
    PolicyPara.cbSize            = sizeof(PolicyPara);
    PolicyPara.pvExtraPolicyPara = &polHttps;

    memset(&PolicyStatus, 0, sizeof(PolicyStatus));
    PolicyStatus.cbSize = sizeof(PolicyStatus);

    if (!CertVerifyCertificateChainPolicy(
            CERT_CHAIN_POLICY_SSL,
            pChainContext,
            &PolicyPara,
            &PolicyStatus))
    {
        Status = GetLastError();
        printf("Error 0x%x returned by CertVerifyCertificateChainPolicy!\n", Status);
        goto cleanup;
    }

    if (PolicyStatus.dwError)
    {
        Status = PolicyStatus.dwError;
        DisplayWinVerifyTrustError(Status);
        goto cleanup;
    }

#endif

    Status = SEC_E_OK;

cleanup:

    if (pChainContext)
    {
        CertFreeCertificateChain(pChainContext);
    }

    if (pwszServerName)
    {
        LocalFree(pwszServerName);
    }

    return Status;
}


//-------------------------------------------------------------
// Функция вывода информации о соединении.

static
void
DisplayConnectionInfo(
    CtxtHandle *phContext)
{
    SECURITY_STATUS Status;
    SecPkgContext_ConnectionInfo ConnectionInfo;

    Status = QueryContextAttributesU(
        phContext,
        SECPKG_ATTR_CONNECTION_INFO,
        (PVOID)&ConnectionInfo);
    if (Status != SEC_E_OK)
    {
        printf("Error 0x%x querying connection info\n", Status);
        return;
    }

    printf("\n");

    switch (ConnectionInfo.dwProtocol)
    {
        case SP_PROT_TLS1_CLIENT:
            printf("Protocol: TLS 1.0\n");
            break;
        case SP_PROT_TLS1_1_CLIENT:
            printf("Protocol: TLS 1.1\n");
            break;
        case SP_PROT_TLS1_2_CLIENT:
            printf("Protocol: TLS 1.2\n");
            break;
        default:
            printf("Protocol: 0x%x\n", ConnectionInfo.dwProtocol);
    }

    switch (ConnectionInfo.aiCipher)
    {
#ifdef _WIN32
        case CALG_G28147:
            printf("Cipher: Gost 28147-89\n");
            break;
        case CALG_GR3412_2015_K:
            printf("Cipher: Gost R 34.12-2015 K\n");
            break;
        case CALG_GR3412_2015_M:
            printf("Cipher: Gost R 34.12-2015 M\n");
            break;
        case CALG_AES_256:
            printf("Cipher: AES 256\n");
            break;
        case CALG_AES_192:
            printf("Cipher: AES 192\n");
            break;
        case CALG_AES_128:
            printf("Cipher: AES 128\n");
            break;
#endif
        default:
            printf("Cipher: 0x%x\n", ConnectionInfo.aiCipher);
    }

    printf("Cipher strength: %d\n", ConnectionInfo.dwCipherStrength);

    switch (ConnectionInfo.aiHash)
    {
#ifdef _WIN32
        case CALG_GR3411:
            printf("Hash: Gost R 34.11-94\n");
            break;
#endif
        default:
            printf("Hash: 0x%x\n", ConnectionInfo.aiHash);
    }

    printf("Hash strength: %d\n", ConnectionInfo.dwHashStrength);

    switch (ConnectionInfo.aiExch)
    {
        case CALG_DH_EPHEM:
            printf("Key exchange: DH Ephemeral\n");
            break;

        default:
            printf("Key exchange: 0x%x\n", ConnectionInfo.aiExch);
    }

    printf("Key exchange strength: %d\n", ConnectionInfo.dwExchStrength);
}


//-------------------------------------------------------------
// Функция получения новых мандатов клиента.

static
void
GetNewClientCredentials(
    CredHandle *phCreds,
    CtxtHandle *phContext)
{
    CredHandle hCreds;
    SecPkgContext_IssuerListInfoEx IssuerListInfo;
    PCCERT_CHAIN_CONTEXT pChainContext;
    CERT_CHAIN_FIND_BY_ISSUER_PARA FindByIssuerPara;
    PCCERT_CONTEXT  pCertContext;
    TimeStamp       tsExpiry;
    SECURITY_STATUS Status;

    //
    // Чтение спиcка доверенных издателей из schannel.
    //

    Status = QueryContextAttributesU(
        phContext,
        SECPKG_ATTR_ISSUER_LIST_EX,
        (PVOID)&IssuerListInfo);
    if (Status != SEC_E_OK)
    {
        printf("Error 0x%x querying issuer list info\n", Status);
        return;
    }

    //
    // Перечисление сертификатов клиента.
    //

    ZeroMemory(&FindByIssuerPara, sizeof(FindByIssuerPara));

    FindByIssuerPara.cbSize = sizeof(FindByIssuerPara);
    FindByIssuerPara.pszUsageIdentifier = szOID_PKIX_KP_CLIENT_AUTH;
    FindByIssuerPara.dwKeySpec = 0;
    FindByIssuerPara.cIssuer   = IssuerListInfo.cIssuers;
    FindByIssuerPara.rgIssuer  = IssuerListInfo.aIssuers;

    pChainContext = NULL;

    for (;;)
    {
        // Поиск цепочки сертификатов.
        pChainContext = CertFindChainInStore(hMyCertStore,
                                             X509_ASN_ENCODING,
                                             0,
                                             CERT_CHAIN_FIND_BY_ISSUER,
                                             &FindByIssuerPara,
                                             pChainContext);
        if (pChainContext == NULL)
        {
            printf("Error 0x%x finding cert chain\n", GetLastError());
            break;
        }
        printf("\ncertificate chain found\n");

        // Получение указателя на контекс сертифика-листа.
        pCertContext = pChainContext->rgpChain[0]->rgpElement[0]->pCertContext;

        // Создание schannel мандата.
        SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
        SchannelCred.cCreds = 1;
        SchannelCred.paCred = &pCertContext;

        Status = AcquireCredentialsHandleU(
            NULL,                   // Имя администратора
            pszSecPkgName,          // Имя пакета
            SECPKG_CRED_OUTBOUND,   // Флаг, определяющий использование
            NULL,                   // Указатель на идентификатор пароля
            &SchannelCred,          // Данные пакета
            NULL,                   // Указатель на функицю GetKey()
            NULL,                   // Значения, передаваемые функции GetKey()
            &hCreds,                // (out) Даскриптор мандата
            &tsExpiry);             // (out) Период актуальности (необязательно)
        if (Status != SEC_E_OK)
        {
            printf("**** Error 0x%x returned by AcquireCredentialsHandle\n", Status);
            continue;
        }
        printf("\nnew schannel credential created\n");

        // Уничтожение старых мандатов.
        FreeCredentialsHandleU(phCreds);

        *phCreds = hCreds;

        break;
    }
}
