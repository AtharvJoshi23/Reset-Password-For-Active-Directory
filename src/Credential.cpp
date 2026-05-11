#include "Credential.h"
#include "HttpClient.h"
#include <strsafe.h>

#pragma comment(lib, "shell32.lib")

const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR g_FieldDescriptors[FI_COUNT] =
{
    { FI_TITLE,        CPFT_LARGE_TEXT,    const_cast<PWSTR>(L"Reset AD Password"), {} },
    { FI_USERNAME,     CPFT_EDIT_TEXT,     const_cast<PWSTR>(L"AD Username"),       {} },
    { FI_SEND_OTP,     CPFT_COMMAND_LINK,  const_cast<PWSTR>(L"Send OTP"),          {} },
    { FI_OTP,          CPFT_PASSWORD_TEXT, const_cast<PWSTR>(L"OTP Code"),          {} },
    { FI_NEW_PASSWORD, CPFT_PASSWORD_TEXT, const_cast<PWSTR>(L"New Password"),      {} },
    { FI_STATUS,       CPFT_SMALL_TEXT,    const_cast<PWSTR>(L""),                  {} },
    { FI_CONNECT_VPN,  CPFT_COMMAND_LINK,  const_cast<PWSTR>(L"Connect VPN"),       {} },
    { FI_SUBMIT,       CPFT_SUBMIT_BUTTON, const_cast<PWSTR>(L"Reset Password"),    {} },
};

struct MonitorContext
{
    CCredential* pCred;
    IStream*     pStream;
};

static HRESULT DupString(const wchar_t* src, PWSTR* ppwsz)
{
    if (!ppwsz) return E_INVALIDARG;
    *ppwsz = nullptr;
    if (!src) src = L"";
    size_t len = wcslen(src) + 1;
    *ppwsz = static_cast<PWSTR>(CoTaskMemAlloc(len * sizeof(wchar_t)));
    if (!*ppwsz) return E_OUTOFMEMORY;
    StringCchCopyW(*ppwsz, len, src);
    return S_OK;
}

CCredential::CCredential()
    : _cRef(1)
    , _pEvents(nullptr)
    , _state((LONG)STATE_INIT)
    , _hMonitorThread(nullptr)
    , _bMonitorRunning(0)
{
    _szUsername[0]    = L'\0';
    _szOTP[0]         = L'\0';
    _szNewPassword[0] = L'\0';
    _szStatus[0]      = L'\0';
    InterlockedIncrement(&g_cRef);
}

CCredential::~CCredential()
{
    InterlockedExchange(&_bMonitorRunning, 0);
    if (_hMonitorThread)
    {
        WaitForSingleObject(_hMonitorThread, 1000);
        CloseHandle(_hMonitorThread);
        _hMonitorThread = nullptr;
    }
    SecureZeroMemory(_szOTP,         sizeof(_szOTP));
    SecureZeroMemory(_szNewPassword, sizeof(_szNewPassword));
    if (_pEvents) { _pEvents->Release(); _pEvents = nullptr; }
    InterlockedDecrement(&g_cRef);
}

HRESULT CCredential::QueryInterface(REFIID riid, void** ppv)
{
    if (!ppv) return E_INVALIDARG;
    *ppv = nullptr;
    if (IsEqualIID(riid, IID_IUnknown) ||
        IsEqualIID(riid, IID_ICredentialProviderCredential))
    {
        *ppv = static_cast<ICredentialProviderCredential*>(this);
        AddRef();
        return S_OK;
    }
    return E_NOINTERFACE;
}

ULONG CCredential::AddRef()  { return InterlockedIncrement(&_cRef); }
ULONG CCredential::Release()
{
    LONG cRef = InterlockedDecrement(&_cRef);
    if (!cRef) delete this;
    return cRef;
}

HRESULT CCredential::Advise(ICredentialProviderCredentialEvents* pcpce)
{
    if (_pEvents) _pEvents->Release();
    _pEvents = pcpce;
    if (_pEvents) _pEvents->AddRef();
    return S_OK;
}

HRESULT CCredential::UnAdvise()
{
    if (_pEvents) { _pEvents->Release(); _pEvents = nullptr; }
    return S_OK;
}

HRESULT CCredential::SetSelected(BOOL* pbAutoLogonWithDefault)
{
    *pbAutoLogonWithDefault = FALSE;
    _UpdateStatus(L"Checking network\x2026");
    bool reachable = IsApiReachable();
    InterlockedExchange(&_state, reachable ? (LONG)STATE_CONNECTED : (LONG)STATE_NO_NETWORK);
    _ApplyState();
    return S_OK;
}

HRESULT CCredential::SetDeselected()
{
    InterlockedExchange(&_bMonitorRunning, 0);
    return S_OK;
}

HRESULT CCredential::GetFieldState(
    DWORD dwFieldID,
    CREDENTIAL_PROVIDER_FIELD_STATE*             pcpfs,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
    if (!pcpfs || !pcpfis || dwFieldID >= FI_COUNT) return E_INVALIDARG;

    LONG st    = InterlockedCompareExchange(&_state, 0, 0);
    bool noNet = (st == (LONG)STATE_NO_NETWORK || st == (LONG)STATE_CONNECTING_VPN);

    switch (dwFieldID)
    {
    case FI_TITLE:
        *pcpfs  = CPFS_DISPLAY_IN_BOTH;
        *pcpfis = CPFIS_NONE;
        break;
    case FI_USERNAME:
        *pcpfs  = CPFS_DISPLAY_IN_SELECTED_TILE;
        *pcpfis = CPFIS_FOCUSED;
        break;
    case FI_SEND_OTP:
    case FI_OTP:
    case FI_NEW_PASSWORD:
    case FI_SUBMIT:
        *pcpfs  = noNet ? CPFS_HIDDEN : CPFS_DISPLAY_IN_SELECTED_TILE;
        *pcpfis = CPFIS_NONE;
        break;
    case FI_STATUS:
        *pcpfs  = CPFS_DISPLAY_IN_SELECTED_TILE;
        *pcpfis = CPFIS_NONE;
        break;
    case FI_CONNECT_VPN:
        *pcpfs  = noNet ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
        *pcpfis = CPFIS_NONE;
        break;
    default:
        return E_INVALIDARG;
    }
    return S_OK;
}

HRESULT CCredential::GetStringValue(DWORD dwFieldID, PWSTR* ppwsz)
{
    if (!ppwsz) return E_INVALIDARG;
    switch (dwFieldID)
    {
    case FI_TITLE:        return DupString(L"Reset AD Password", ppwsz);
    case FI_USERNAME:     return DupString(_szUsername,          ppwsz);
    case FI_SEND_OTP:     return DupString(L"Send OTP",          ppwsz);
    case FI_OTP:          return DupString(_szOTP,               ppwsz);
    case FI_NEW_PASSWORD: return DupString(_szNewPassword,       ppwsz);
    case FI_STATUS:       return DupString(_szStatus,            ppwsz);
    case FI_CONNECT_VPN:  return DupString(L"Connect VPN",       ppwsz);
    default:              return E_INVALIDARG;
    }
}

HRESULT CCredential::GetBitmapValue(DWORD /*dwFieldID*/, HBITMAP* /*phbmp*/)  { return E_NOTIMPL; }
HRESULT CCredential::GetCheckboxValue(DWORD /*dwFieldID*/, BOOL* /*pbChecked*/, PWSTR* /*ppwszLabel*/) { return E_NOTIMPL; }

HRESULT CCredential::GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo)
{
    if (dwFieldID != FI_SUBMIT || !pdwAdjacentTo) return E_INVALIDARG;
    *pdwAdjacentTo = FI_STATUS;
    return S_OK;
}

HRESULT CCredential::GetComboBoxValueCount(DWORD /*dwFieldID*/, DWORD* /*pcItems*/, DWORD* /*pdwSelectedItem*/) { return E_NOTIMPL; }
HRESULT CCredential::GetComboBoxValueAt(DWORD /*dwFieldID*/, DWORD /*dwItem*/, PWSTR* /*ppwszItem*/) { return E_NOTIMPL; }

HRESULT CCredential::SetStringValue(DWORD dwFieldID, PCWSTR pwz)
{
    if (!pwz) return E_INVALIDARG;
    switch (dwFieldID)
    {
    case FI_USERNAME:     StringCchCopyW(_szUsername,    ARRAYSIZE(_szUsername),    pwz); return S_OK;
    case FI_OTP:          StringCchCopyW(_szOTP,         ARRAYSIZE(_szOTP),         pwz); return S_OK;
    case FI_NEW_PASSWORD: StringCchCopyW(_szNewPassword, ARRAYSIZE(_szNewPassword), pwz); return S_OK;
    default:              return E_INVALIDARG;
    }
}

HRESULT CCredential::SetCheckboxValue(DWORD /*dwFieldID*/, BOOL /*bChecked*/) { return E_NOTIMPL; }
HRESULT CCredential::SetComboBoxSelectedValue(DWORD /*dwFieldID*/, DWORD /*dwSelectedItem*/) { return E_NOTIMPL; }

HRESULT CCredential::CommandLinkClicked(DWORD dwFieldID)
{
    // ── Connect VPN button ────────────────────────────────────────────────────
    if (dwFieldID == FI_CONNECT_VPN)
    {
        InterlockedExchange(&_bMonitorRunning, 0);
        if (_hMonitorThread)
        {
            WaitForSingleObject(_hMonitorThread, 1000);
            CloseHandle(_hMonitorThread);
            _hMonitorThread = nullptr;
        }

        HINSTANCE hInst = ShellExecuteW(
            nullptr, L"open",
            L"C:\\Program Files (x86)\\SonicWall\\SSL-VPN\\NetExtender\\NEGui.exe",
            nullptr, nullptr, SW_SHOWDEFAULT);

        if (reinterpret_cast<INT_PTR>(hInst) <= 32)
        {
            _UpdateStatus(L"Could not launch VPN client. Verify SonicWall NetExtender is installed.");
            return S_OK;
        }

        InterlockedExchange(&_state, (LONG)STATE_CONNECTING_VPN);
        _UpdateStatus(L"NetExtender opened. Connect VPN then return here.");
        _StartMonitorThread();
        return S_OK;
    }

    // ── Send OTP button ───────────────────────────────────────────────────────
    if (dwFieldID != FI_SEND_OTP) return E_INVALIDARG;

    if (_szUsername[0] == L'\0')
    {
        _UpdateStatus(L"Enter AD username first.");
        return S_OK;
    }

    _UpdateStatus(L"Sending OTP\x2026");

    std::string body = "{\"username\":\"" + JsonEscape(_szUsername) + "\"}";
    HttpResult result = HttpPostJson(L"172.16.30.23", 8443, L"/api/auth/request-otp", body);

    if (!result.connected)
    {
        InterlockedExchange(&_state, (LONG)STATE_NO_NETWORK);
        _EnableOtpFields(false);
        _UpdateStatus(L"Not connected. Click 'Connect VPN' to launch the VPN client.");
        return S_OK;
    }

    if (result.statusCode == 200)
    {
        InterlockedExchange(&_state, (LONG)STATE_OTP_FLOW);
        _UpdateStatus(L"OTP sent to your registered email address.");
    }
    else
    {
        std::wstring msg = JsonExtractString(result.body, L"message");
        if (msg.empty()) msg = L"Failed to send OTP. Verify username.";
        _UpdateStatus(msg.c_str());
    }
    return S_OK;
}

HRESULT CCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*   pcpcs,
    PWSTR*                                          ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON*                pcpsiOptionalStatusIcon)
{
    *pcpgsr                  = CPGSR_NO_CREDENTIAL_FINISHED;
    ZeroMemory(pcpcs, sizeof(*pcpcs));
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    if (_szUsername[0] == L'\0' || _szOTP[0] == L'\0' || _szNewPassword[0] == L'\0')
    {
        _UpdateStatus(L"All fields are required.");
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        DupString(L"All fields are required.", ppwszOptionalStatusText);
        return S_OK;
    }

    std::string body =
        "{\"username\":\""      + JsonEscape(_szUsername)    +
        "\",\"otp\":\""         + JsonEscape(_szOTP)         +
        "\",\"newPassword\":\"" + JsonEscape(_szNewPassword) + "\"}";

    _UpdateStatus(L"Resetting password\x2026");

    HttpResult result = HttpPostJson(L"172.16.30.23", 8443, L"/api/auth/reset-password", body);

    SecureZeroMemory(_szOTP,         sizeof(_szOTP));
    SecureZeroMemory(_szNewPassword, sizeof(_szNewPassword));
    if (_pEvents)
    {
        _pEvents->SetFieldString(this, FI_OTP,          L"");
        _pEvents->SetFieldString(this, FI_NEW_PASSWORD, L"");
    }

    if (!result.connected)
    {
        InterlockedExchange(&_state, (LONG)STATE_NO_NETWORK);
        _EnableOtpFields(false);
        _UpdateStatus(L"Not connected. Click 'Connect VPN' to launch the VPN client.");
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        DupString(L"Cannot reach server.", ppwszOptionalStatusText);
        return S_OK;
    }

    if (result.statusCode == 200)
    {
        _UpdateStatus(L"Password reset successful. You may now log in.");
        *pcpsiOptionalStatusIcon = CPSI_SUCCESS;
        DupString(L"Password reset successful.", ppwszOptionalStatusText);
    }
    else
    {
        std::wstring msg = JsonExtractString(result.body, L"message");
        if (msg.empty())
        {
            if      (result.statusCode == 401) msg = L"Invalid or expired OTP.";
            else if (result.statusCode == 400) msg = L"Password does not meet requirements.";
            else                               msg = L"Reset failed. Please try again.";
        }
        _UpdateStatus(msg.c_str());
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        DupString(msg.c_str(), ppwszOptionalStatusText);
    }
    return S_OK;
}

HRESULT CCredential::ReportResult(
    NTSTATUS /*ntsStatus*/, NTSTATUS /*ntsSubstatus*/,
    PWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    *ppwszOptionalStatusText  = nullptr;
    *pcpsiOptionalStatusIcon  = CPSI_NONE;
    return E_NOTIMPL;
}

void CCredential::_UpdateStatus(const wchar_t* msg)
{
    StringCchCopyW(_szStatus, ARRAYSIZE(_szStatus), msg);
    if (_pEvents) _pEvents->SetFieldString(this, FI_STATUS, _szStatus);
}

void CCredential::_EnableOtpFields(bool enable)
{
    if (!_pEvents) return;
    CREDENTIAL_PROVIDER_FIELD_STATE otpState = enable ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
    CREDENTIAL_PROVIDER_FIELD_STATE vpnState = enable ? CPFS_HIDDEN : CPFS_DISPLAY_IN_SELECTED_TILE;
    _pEvents->SetFieldState(this, FI_SEND_OTP,    otpState);
    _pEvents->SetFieldState(this, FI_OTP,         otpState);
    _pEvents->SetFieldState(this, FI_NEW_PASSWORD,otpState);
    _pEvents->SetFieldState(this, FI_SUBMIT,      otpState);
    _pEvents->SetFieldState(this, FI_CONNECT_VPN, vpnState);
}

void CCredential::_ApplyState()
{
    switch ((VpnState)InterlockedCompareExchange(&_state, 0, 0))
    {
    case STATE_NO_NETWORK:
        _EnableOtpFields(false);
        _UpdateStatus(L"Not connected. Click 'Connect VPN' to launch the VPN client.");
        break;
    case STATE_CONNECTING_VPN:
        _EnableOtpFields(false);
        _UpdateStatus(L"NetExtender opened. Connect VPN then return here.");
        break;
    case STATE_CONNECTED:
        _EnableOtpFields(true);
        _UpdateStatus(L"Connected. Enter your AD username and click Send OTP.");
        break;
    case STATE_OTP_FLOW:
        _EnableOtpFields(true);
        break;
    default:
        break;
    }
}

void CCredential::_StartMonitorThread()
{
    auto* pCtx = new (std::nothrow) MonitorContext();
    if (!pCtx) return;
    pCtx->pCred   = this;
    pCtx->pStream = nullptr;
    AddRef();

    if (_pEvents)
    {
        HRESULT hr = CoMarshalInterThreadInterfaceInStream(
            IID_ICredentialProviderCredentialEvents, _pEvents, &pCtx->pStream);
        if (FAILED(hr)) pCtx->pStream = nullptr;
    }

    InterlockedExchange(&_bMonitorRunning, 1);
    _hMonitorThread = CreateThread(nullptr, 0, _MonitorThreadProc, pCtx, 0, nullptr);
    if (!_hMonitorThread)
    {
        InterlockedExchange(&_bMonitorRunning, 0);
        if (pCtx->pStream) pCtx->pStream->Release();
        delete pCtx;
        Release();
    }
}

DWORD WINAPI CCredential::_MonitorThreadProc(LPVOID pv)
{
    auto*        pCtx  = static_cast<MonitorContext*>(pv);
    CCredential* pCred = pCtx->pCred;

    CoInitializeEx(nullptr, COINIT_MULTITHREADED);

    ICredentialProviderCredentialEvents* pEvents = nullptr;
    if (pCtx->pStream)
    {
        CoGetInterfaceAndReleaseStream(pCtx->pStream,
            IID_ICredentialProviderCredentialEvents,
            reinterpret_cast<void**>(&pEvents));
        pCtx->pStream = nullptr;
    }
    delete pCtx;

    const int MAX_ATTEMPTS = 20;
    bool      connected    = false;

    for (int i = 0; i < MAX_ATTEMPTS; i++)
    {
        Sleep(5000);
        if (!InterlockedCompareExchange(&pCred->_bMonitorRunning, 1, 1)) break;

        if (IsApiReachable())
        {
            connected = true;
            InterlockedExchange(&pCred->_state, (LONG)STATE_CONNECTED);
            if (pEvents)
            {
                pEvents->SetFieldState(pCred, FI_SEND_OTP,    CPFS_DISPLAY_IN_SELECTED_TILE);
                pEvents->SetFieldState(pCred, FI_OTP,         CPFS_DISPLAY_IN_SELECTED_TILE);
                pEvents->SetFieldState(pCred, FI_NEW_PASSWORD,CPFS_DISPLAY_IN_SELECTED_TILE);
                pEvents->SetFieldState(pCred, FI_SUBMIT,      CPFS_DISPLAY_IN_SELECTED_TILE);
                pEvents->SetFieldState(pCred, FI_CONNECT_VPN, CPFS_HIDDEN);
                pEvents->SetFieldString(pCred, FI_STATUS,
                    L"VPN connected. Enter your AD username and click Send OTP.");
            }
            break;
        }

        if (pEvents)
        {
            wchar_t msg[128];
            StringCchPrintfW(msg, ARRAYSIZE(msg),
                L"Waiting for VPN\x2026 (attempt %d of %d)", i + 1, MAX_ATTEMPTS);
            pEvents->SetFieldString(pCred, FI_STATUS, msg);
        }
    }

    if (!connected && InterlockedCompareExchange(&pCred->_bMonitorRunning, 1, 1))
    {
        InterlockedExchange(&pCred->_state, (LONG)STATE_NO_NETWORK);
        if (pEvents)
        {
            pEvents->SetFieldState(pCred, FI_CONNECT_VPN,  CPFS_DISPLAY_IN_SELECTED_TILE);
            pEvents->SetFieldState(pCred, FI_SEND_OTP,     CPFS_HIDDEN);
            pEvents->SetFieldState(pCred, FI_OTP,          CPFS_HIDDEN);
            pEvents->SetFieldState(pCred, FI_NEW_PASSWORD, CPFS_HIDDEN);
            pEvents->SetFieldState(pCred, FI_SUBMIT,       CPFS_HIDDEN);
            pEvents->SetFieldString(pCred, FI_STATUS,
                L"VPN timed out. Click 'Connect VPN' to try again.");
        }
    }

    if (pEvents) pEvents->Release();
    InterlockedExchange(&pCred->_bMonitorRunning, 0);
    pCred->Release();
    CoUninitialize();
    return 0;
}
