#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>

#pragma comment(lib, "winhttp.lib")

struct HttpResult
{
    DWORD        statusCode;
    std::wstring body;
    bool         connected;
};

// Escapes a wide string for safe embedding in a JSON string value.
static inline std::string JsonEscape(const wchar_t* wstr)
{
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    std::string utf8(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &utf8[0], len, nullptr, nullptr);
    if (!utf8.empty() && utf8.back() == '\0')
        utf8.pop_back();

    std::string out;
    out.reserve(utf8.size() + 8);
    for (char c : utf8)
    {
        switch (c)
        {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:   out += c;      break;
        }
    }
    return out;
}

// Extracts the first string value for 'key' from a flat JSON object.
// e.g. {"message":"text"} -> JsonExtractString(json, L"message") -> L"text"
static inline std::wstring JsonExtractString(const std::wstring& json, const wchar_t* key)
{
    std::wstring searchKey = std::wstring(L"\"") + key + L"\":\"";
    size_t pos = json.find(searchKey);
    if (pos == std::wstring::npos) return L"";
    pos += searchKey.length();
    size_t end = json.find(L'"', pos);
    if (end == std::wstring::npos) return L"";
    return json.substr(pos, end - pos);
}

// ─────────────────────────────────────────────
// Health Check (VPN / Network Detection)
// ─────────────────────────────────────────────
inline bool IsApiReachable()
{
    HINTERNET hSession = WinHttpOpen(
        L"ResetPasswordClient/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    if (!hSession)
        return false;

    // 🔥 IMPORTANT: Prevent UI freeze
    WinHttpSetTimeouts(hSession, 2000, 2000, 2000, 2000);

    HINTERNET hConnect = WinHttpConnect(
        hSession,
        L"172.16.30.23",
        8443,
        0);

    if (!hConnect)
    {
        WinHttpCloseHandle(hSession);
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        L"/health",
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);

    if (!hRequest)
    {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    // For internal/self-signed cert
    DWORD dwFlags =
        SECURITY_FLAG_IGNORE_UNKNOWN_CA |
        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
        SECURITY_FLAG_IGNORE_CERT_CN_INVALID;

    WinHttpSetOption(
        hRequest,
        WINHTTP_OPTION_SECURITY_FLAGS,
        &dwFlags,
        sizeof(dwFlags));

    BOOL bResult = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0);

    if (!bResult)
    {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    bResult = WinHttpReceiveResponse(hRequest, NULL);

    if (!bResult)
    {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD statusCode = 0;
    DWORD size = sizeof(statusCode);

    if (!WinHttpQueryHeaders(
        hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &statusCode,
        &size,
        WINHTTP_NO_HEADER_INDEX))
    {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return (statusCode == 200);
}


// Sends an HTTP POST with a JSON body over TLS. Synchronous, blocks up to timeoutMs.
static inline HttpResult HttpPostJson(
    const wchar_t*     host,
    INTERNET_PORT      port,
    const wchar_t*     path,
    const std::string& jsonBody,
    DWORD              timeoutMs = 5000)
{
    HttpResult result = {};
    result.connected  = false;

    HINTERNET hSession = WinHttpOpen(
        L"ResetPasswordCP/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (!hSession) return result;

    WinHttpSetTimeouts(hSession,
        (int)timeoutMs,   // name resolution
        (int)timeoutMs,   // connection
        (int)timeoutMs,   // send
        (int)timeoutMs);  // receive

    HINTERNET hConnect = WinHttpConnect(hSession, host, port, 0);
    if (!hConnect)
    {
        WinHttpCloseHandle(hSession);
        return result;
    }

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, L"POST", path,
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);  // TLS only — no plaintext fallback

    if (!hRequest)
    {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    // Bypass certificate validation for internal self-signed cert
    DWORD dwSecFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                       SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
                       SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                       SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwSecFlags, sizeof(dwSecFlags));

    WinHttpAddRequestHeaders(hRequest,
        L"Content-Type: application/json\r\n",
        (DWORD)-1L,
        WINHTTP_ADDREQ_FLAG_ADD);

    DWORD bodyLen = (DWORD)jsonBody.size();
    BOOL  bSent   = WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        (LPVOID)jsonBody.c_str(), bodyLen, bodyLen, 0);

    if (bSent && WinHttpReceiveResponse(hRequest, nullptr))
    {
        result.connected = true;

        DWORD statusCode = 0;
        DWORD cbStatus   = sizeof(DWORD);
        WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &statusCode, &cbStatus,
            WINHTTP_NO_HEADER_INDEX);
        result.statusCode = statusCode;

        std::string raw;
        DWORD avail = 0;
        while (WinHttpQueryDataAvailable(hRequest, &avail) && avail > 0)
        {
            std::vector<char> buf(avail + 1, 0);
            DWORD read = 0;
            if (!WinHttpReadData(hRequest, buf.data(), avail, &read)) break;
            raw.append(buf.data(), read);
        }

        if (!raw.empty())
        {
            int wlen = MultiByteToWideChar(CP_UTF8, 0, raw.c_str(), -1, nullptr, 0);
            if (wlen > 1)
            {
                result.body.resize(wlen - 1);
                MultiByteToWideChar(CP_UTF8, 0, raw.c_str(), -1,
                    &result.body[0], wlen);
            }
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return result;
}
