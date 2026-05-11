#include "CProvider.h"
#include <strsafe.h>
#include <new>

// ─── CCredentialProvider ─────────────────────────────────────────────────────

CCredentialProvider::CCredentialProvider()
    : _cRef(1)
    , _cpus((CREDENTIAL_PROVIDER_USAGE_SCENARIO)0)
    , _pCredential(nullptr)
    , _pCredProvEvents(nullptr)
    , _upAdviseContext(0)
{
    InterlockedIncrement(&g_cRef);
}

CCredentialProvider::~CCredentialProvider()
{
    if (_pCredential)    { _pCredential->Release();    _pCredential    = nullptr; }
    if (_pCredProvEvents){ _pCredProvEvents->Release(); _pCredProvEvents= nullptr; }
    InterlockedDecrement(&g_cRef);
}

// IUnknown ────────────────────────────────────────────────────────────────────

HRESULT CCredentialProvider::QueryInterface(REFIID riid, void** ppv)
{
    if (!ppv) return E_INVALIDARG;
    *ppv = nullptr;
    if (IsEqualIID(riid, IID_IUnknown) ||
        IsEqualIID(riid, IID_ICredentialProvider))
    {
        *ppv = static_cast<ICredentialProvider*>(this);
        AddRef();
        return S_OK;
    }
    return E_NOINTERFACE;
}

ULONG CCredentialProvider::AddRef()  { return InterlockedIncrement(&_cRef); }
ULONG CCredentialProvider::Release()
{
    LONG cRef = InterlockedDecrement(&_cRef);
    if (!cRef) delete this;
    return cRef;
}

// ICredentialProvider ─────────────────────────────────────────────────────────

// We support only interactive logon and workstation unlock.
// Return E_NOTIMPL for CPUS_CREDUI (UAC prompts) and CPUS_CHANGE_PASSWORD
// so our tile never appears in those contexts.
HRESULT CCredentialProvider::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD /*dwFlags*/)
{
    // Hide tile only when the machine domain is known and not viz.in.
    // If lookup fails (for example transient/offline conditions), keep the
    // tile visible so users can still use the Connect VPN action.
    wchar_t domain[256] = {};
    DWORD   domainSize  = ARRAYSIZE(domain);
    if (GetComputerNameExW(ComputerNameDnsDomain, domain, &domainSize) &&
        domain[0] != L'\0' &&
        _wcsicmp(domain, L"int.viz") != 0)
    {
        return E_NOTIMPL;
    }

    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        _cpus = cpus;
        if (!_pCredential)
        {
            _pCredential = new (std::nothrow) CCredential();
            if (!_pCredential) return E_OUTOFMEMORY;
        }
        return S_OK;

    default:
        return E_NOTIMPL;
    }
}

// We don't pre-populate fields from a serialized credential.
HRESULT CCredentialProvider::SetSerialization(
    const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* /*pcpcs*/)
{
    return E_NOTIMPL;
}

HRESULT CCredentialProvider::Advise(
    ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext)
{
    if (_pCredProvEvents) _pCredProvEvents->Release();
    _pCredProvEvents  = pcpe;
    _upAdviseContext  = upAdviseContext;
    if (_pCredProvEvents) _pCredProvEvents->AddRef();
    return S_OK;
}

HRESULT CCredentialProvider::UnAdvise()
{
    if (_pCredProvEvents) { _pCredProvEvents->Release(); _pCredProvEvents = nullptr; }
    return S_OK;
}

HRESULT CCredentialProvider::GetFieldDescriptorCount(DWORD* pdwCount)
{
    if (!pdwCount) return E_INVALIDARG;
    *pdwCount = FI_COUNT;
    return S_OK;
}

// Returns a CoTask-allocated copy of the requested field descriptor.
// The caller (LogonUI) frees both the struct and the pszLabel string.
HRESULT CCredentialProvider::GetFieldDescriptorAt(
    DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppfd)
{
    if (!ppfd || dwIndex >= FI_COUNT) return E_INVALIDARG;
    *ppfd = nullptr;

    auto* pfd = static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(
        CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));
    if (!pfd) return E_OUTOFMEMORY;

    *pfd = g_FieldDescriptors[dwIndex];   // shallow copy first

    // Deep-copy the label string so the caller can free it independently.
    if (g_FieldDescriptors[dwIndex].pszLabel)
    {
        size_t len = wcslen(g_FieldDescriptors[dwIndex].pszLabel) + 1;
        pfd->pszLabel = static_cast<PWSTR>(CoTaskMemAlloc(len * sizeof(wchar_t)));
        if (!pfd->pszLabel)
        {
            CoTaskMemFree(pfd);
            return E_OUTOFMEMORY;
        }
        StringCchCopyW(pfd->pszLabel, len, g_FieldDescriptors[dwIndex].pszLabel);
    }

    *ppfd = pfd;
    return S_OK;
}

// We expose exactly one tile. No auto-logon.
HRESULT CCredentialProvider::GetCredentialCount(
    DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault)
{
    if (!pdwCount || !pdwDefault || !pbAutoLogonWithDefault) return E_INVALIDARG;
    *pdwCount                = 1;
    *pdwDefault              = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *pbAutoLogonWithDefault  = FALSE;
    return S_OK;
}

HRESULT CCredentialProvider::GetCredentialAt(
    DWORD dwIndex, ICredentialProviderCredential** ppcpc)
{
    if (!ppcpc || dwIndex != 0 || !_pCredential) return E_INVALIDARG;
    return _pCredential->QueryInterface(IID_ICredentialProviderCredential,
        reinterpret_cast<void**>(ppcpc));
}

// ─── CCredentialProviderFactory ──────────────────────────────────────────────

HRESULT CCredentialProviderFactory::QueryInterface(REFIID riid, void** ppv)
{
    if (!ppv) return E_INVALIDARG;
    *ppv = nullptr;
    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IClassFactory))
    {
        *ppv = static_cast<IClassFactory*>(this);
        AddRef();
        return S_OK;
    }
    return E_NOINTERFACE;
}

ULONG CCredentialProviderFactory::AddRef()  { return InterlockedIncrement(&_cRef); }
ULONG CCredentialProviderFactory::Release()
{
    LONG cRef = InterlockedDecrement(&_cRef);
    if (!cRef) delete this;
    return cRef;
}

HRESULT CCredentialProviderFactory::CreateInstance(
    IUnknown* punkOuter, REFIID riid, void** ppv)
{
    if (punkOuter) return CLASS_E_NOAGGREGATION;
    if (!ppv)      return E_INVALIDARG;
    *ppv = nullptr;

    auto* pProvider = new (std::nothrow) CCredentialProvider();
    if (!pProvider) return E_OUTOFMEMORY;

    HRESULT hr = pProvider->QueryInterface(riid, ppv);
    pProvider->Release();
    return hr;
}

HRESULT CCredentialProviderFactory::LockServer(BOOL bLock)
{
    if (bLock) InterlockedIncrement(&g_cRef);
    else       InterlockedDecrement(&g_cRef);
    return S_OK;
}
