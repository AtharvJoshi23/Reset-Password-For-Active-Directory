#pragma once
#include <windows.h>
#include <objbase.h>
#include <credentialprovider.h>
#include "Credential.h"

// ─── ICredentialProvider ─────────────────────────────────────────────────────

class CCredentialProvider : public ICredentialProvider
{
public:
    CCredentialProvider();
    ~CCredentialProvider();

    // IUnknown
    IFACEMETHODIMP         QueryInterface(REFIID riid, void** ppv);
    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();

    // ICredentialProvider
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags);
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);
    IFACEMETHODIMP Advise(ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext);
    IFACEMETHODIMP UnAdvise();
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* pdwCount);
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD dwIndex,
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppfd);
    IFACEMETHODIMP GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault,
        BOOL* pbAutoLogonWithDefault);
    IFACEMETHODIMP GetCredentialAt(DWORD dwIndex,
        ICredentialProviderCredential** ppcpc);

private:
    LONG                            _cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus;
    CCredential*                    _pCredential;
    ICredentialProviderEvents*      _pCredProvEvents;
    UINT_PTR                        _upAdviseContext;
};

// ─── IClassFactory ───────────────────────────────────────────────────────────

class CCredentialProviderFactory : public IClassFactory
{
public:
    CCredentialProviderFactory()  : _cRef(1) { InterlockedIncrement(&g_cRef); }
    ~CCredentialProviderFactory()            { InterlockedDecrement(&g_cRef); }

    IFACEMETHODIMP         QueryInterface(REFIID riid, void** ppv);
    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();

    IFACEMETHODIMP CreateInstance(IUnknown* punkOuter, REFIID riid, void** ppv);
    IFACEMETHODIMP LockServer(BOOL bLock);

private:
    LONG _cRef;
};
