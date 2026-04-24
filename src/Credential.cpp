#include "Credential.h"
#include "HttpClient.h"
#include <strsafe.h>

// ─── Field descriptors ───────────────────────────────────────────────────────
// Defined here, declared extern in Credential.h.
// guidFieldType is GUID_NULL ({}) for all custom fields.
const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR g_FieldDescriptors[FI_COUNT] =
{
    { FI_TITLE,        CPFT_LARGE_TEXT,     const_cast<PWSTR>(L"Reset AD Password"), {} },
    { FI_USERNAME,     CPFT_EDIT_TEXT,      const_cast<PWSTR>(L"Username"),          {} },
    { FI_SEND_OTP,     CPFT_COMMAND_LINK,   const_cast<PWSTR>(L"Send OTP"),          {} },
    { FI_OTP,          CPFT_PASSWORD_TEXT,  const_cast<PWSTR>(L"OTP Code"),          {} },
    { FI_NEW_PASSWORD, CPFT_PASSWORD_TEXT,  const_cast<PWSTR>(L"New Password"),      {} },
    { FI_STATUS,       CPFT_SMALL_TEXT,     const_cast<PWSTR>(L""),                  {} },
    { FI_SUBMIT,       CPFT_SUBMIT_BUTTON,  const_cast<PWSTR>(L"Reset Password"),    {} },
};

// ─── Internal helpers ─────────────────────────────────────────────────────────

// Allocates a CoTask copy of src. Caller frees with CoTaskMemFree.
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

// ─── CCredential ──────────────────────────────────────────────────────────────

CCredential::CCredential()
    : _cRef(1)
    , _pEvents(nullptr)
{
    _szUsername[0]    = L'\0';
    _szOTP[0]         = L'\0';
    _szNewPassword[0] = L'\0';
    _szStatus[0]      = L'\0';
    InterlockedIncrement(&g_cRef);
}

CCredential::~CCredential()
{
    SecureZeroMemory(_szOTP,         sizeof(_szOTP));
    SecureZeroMemory(_szNewPassword, sizeof(_szNewPassword));
    if (_pEvents) { _pEvents->Release(); _pEvents = nullptr; }
    InterlockedDecrement(&g_cRef);
}

// IUnknown ────────────────────────────────────────────────────────────────────

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

// ICredentialProviderCredential ───────────────────────────────────────────────

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

HRESULT CCredential::SetSelected(BOOL* /*pbAutoLogonWithDefault*/) { return S_OK; }
HRESULT CCredential::SetDeselected()                  { return S_OK; }

HRESULT CCredential::GetFieldState(
    DWORD dwFieldID,
    CREDENTIAL_PROVIDER_FIELD_STATE*             pcpfs,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
    if (!pcpfs || !pcpfis || dwFieldID >= FI_COUNT) return E_INVALIDARG;

    switch (dwFieldID)
    {
    case FI_TITLE:
        // Visible on the collapsed tile so users can identify this CP
        *pcpfs  = CPFS_DISPLAY_IN_BOTH;
        *pcpfis = CPFIS_NONE;
        break;

    case FI_USERNAME:
        *pcpfs  = CPFS_DISPLAY_IN_SELECTED_TILE;
        *pcpfis = CPFIS_FOCUSED;   // auto-focus on tile selection
        break;

    case FI_SEND_OTP:
    case FI_OTP:
    case FI_NEW_PASSWORD:
    case FI_STATUS:
    case FI_SUBMIT:
        *pcpfs  = CPFS_DISPLAY_IN_SELECTED_TILE;
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
    default:              return E_INVALIDARG;
    }
}

HRESULT CCredential::GetBitmapValue(DWORD /*dwFieldID*/, HBITMAP* /*phbmp*/)
{
    return E_NOTIMPL;
}

HRESULT CCredential::GetCheckboxValue(
    DWORD /*dwFieldID*/, BOOL* /*pbChecked*/, PWSTR* /*ppwszLabel*/)
{
    return E_NOTIMPL;
}

// The submit button must declare which field it sits adjacent to (below).
HRESULT CCredential::GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo)
{
    if (dwFieldID != FI_SUBMIT || !pdwAdjacentTo) return E_INVALIDARG;
    *pdwAdjacentTo = FI_STATUS;   // button appears directly below the status line
    return S_OK;
}

HRESULT CCredential::GetComboBoxValueCount(
    DWORD /*dwFieldID*/, DWORD* /*pcItems*/, DWORD* /*pdwSelectedItem*/)
{
    return E_NOTIMPL;
}

HRESULT CCredential::GetComboBoxValueAt(
    DWORD /*dwFieldID*/, DWORD /*dwItem*/, PWSTR* /*ppwszItem*/)
{
    return E_NOTIMPL;
}

HRESULT CCredential::SetStringValue(DWORD dwFieldID, PCWSTR pwz)
{
    if (!pwz) return E_INVALIDARG;
    switch (dwFieldID)
    {
    case FI_USERNAME:
        StringCchCopyW(_szUsername,    ARRAYSIZE(_szUsername),    pwz);
        return S_OK;
    case FI_OTP:
        StringCchCopyW(_szOTP,         ARRAYSIZE(_szOTP),         pwz);
        return S_OK;
    case FI_NEW_PASSWORD:
        StringCchCopyW(_szNewPassword, ARRAYSIZE(_szNewPassword), pwz);
        return S_OK;
    default:
        return E_INVALIDARG;
    }
}

HRESULT CCredential::SetCheckboxValue(DWORD /*dwFieldID*/, BOOL /*bChecked*/)
{
    return E_NOTIMPL;
}

HRESULT CCredential::SetComboBoxSelectedValue(
    DWORD /*dwFieldID*/, DWORD /*dwSelectedItem*/)
{
    return E_NOTIMPL;
}

// Called when the user clicks the "Send OTP" command link.
HRESULT CCredential::CommandLinkClicked(DWORD dwFieldID)
{
    if (dwFieldID != FI_SEND_OTP) return E_INVALIDARG;

    if (_szUsername[0] == L'\0')
    {
        _UpdateStatus(L"Enter username first.");
        return S_OK;
    }

    _UpdateStatus(L"Sending OTP\x2026");   // "Sending OTP…"

    std::string body = "{\"username\":\"" + JsonEscape(_szUsername) + "\"}";

    HttpResult result = HttpPostJson(
        L"reset.viz.in",
        8443,
        L"/api/auth/request-otp",
        body);

    if (!result.connected)
    {
        _UpdateStatus(L"Cannot reach server. Check network connection.");
        return S_OK;
    }

    if (result.statusCode == 200)
    {
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

// Called when the user clicks "Reset Password" (the submit button).
// We call the API, show feedback, then return CPGSR_NO_CREDENTIAL_FINISHED
// so winlogon stays on the logon screen — we are NOT logging the user in.
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
        "{\"username\":\""    + JsonEscape(_szUsername)    +
        "\",\"otp\":\""       + JsonEscape(_szOTP)         +
        "\",\"newPassword\":\"" + JsonEscape(_szNewPassword) + "\"}";

    _UpdateStatus(L"Resetting password\x2026");

    HttpResult result = HttpPostJson(
        L"reset.viz.in",
        8443,
        L"/api/auth/reset-password",
        body);

    // Erase sensitive data from memory immediately, regardless of outcome.
    SecureZeroMemory(_szOTP,         sizeof(_szOTP));
    SecureZeroMemory(_szNewPassword, sizeof(_szNewPassword));

    // Clear the masked fields in the UI as well.
    if (_pEvents)
    {
        _pEvents->SetFieldString(this, FI_OTP,          L"");
        _pEvents->SetFieldString(this, FI_NEW_PASSWORD, L"");
    }

    if (!result.connected)
    {
        _UpdateStatus(L"Cannot reach server. Check network connection.");
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
    NTSTATUS /*ntsStatus*/,
    NTSTATUS /*ntsSubstatus*/,
    PWSTR*                           ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    *ppwszOptionalStatusText  = nullptr;
    *pcpsiOptionalStatusIcon  = CPSI_NONE;
    return E_NOTIMPL;
}

// ─── Private ─────────────────────────────────────────────────────────────────

void CCredential::_UpdateStatus(const wchar_t* msg)
{
    StringCchCopyW(_szStatus, ARRAYSIZE(_szStatus), msg);
    if (_pEvents)
        _pEvents->SetFieldString(this, FI_STATUS, _szStatus);
}
