#include <windows.h>
#include <objbase.h>
#include <strsafe.h>
#include <new>
#include "CProvider.h"

// ─── CLSID ───────────────────────────────────────────────────────────────────
// {B5A84CD4-1F6A-4A52-9A11-D90E6C9D9C4A}
// Must match every registry key and the install scripts.
EXTERN_C const CLSID CLSID_ResetPasswordCP =
{ 0xb5a84cd4, 0x1f6a, 0x4a52, { 0x9a, 0x11, 0xd9, 0x0e, 0x6c, 0x9d, 0x9c, 0x4a } };

// ─── Globals ─────────────────────────────────────────────────────────────────
HINSTANCE g_hInst = nullptr;
LONG      g_cRef  = 0;   // tracks all outstanding COM objects + LockServer calls

// ─── DllMain ─────────────────────────────────────────────────────────────────

BOOL APIENTRY DllMain(HINSTANCE hInstDLL, DWORD dwReason, LPVOID /*lpReserved*/)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        g_hInst = hInstDLL;
        DisableThreadLibraryCalls(hInstDLL);
    }
    return TRUE;
}

// ─── COM exports (also listed in ResetPasswordCP.def) ────────────────────────

STDAPI DllCanUnloadNow()
{
    return (g_cRef == 0) ? S_OK : S_FALSE;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv)
{
    if (!ppv) return E_INVALIDARG;
    *ppv = nullptr;

    if (!IsEqualCLSID(rclsid, CLSID_ResetPasswordCP))
        return CLASS_E_CLASSNOTAVAILABLE;

    auto* pFactory = new (std::nothrow) CCredentialProviderFactory();
    if (!pFactory) return E_OUTOFMEMORY;

    HRESULT hr = pFactory->QueryInterface(riid, ppv);
    pFactory->Release();
    return hr;
}

// ─── Registration helpers ────────────────────────────────────────────────────

static HRESULT SetRegString(
    HKEY        hRoot,
    const wchar_t* subKey,
    const wchar_t* valueName,   // nullptr → default value
    const wchar_t* data)
{
    HKEY  hKey = nullptr;
    LONG  lr   = RegCreateKeyExW(hRoot, subKey, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr);
    if (lr != ERROR_SUCCESS) return HRESULT_FROM_WIN32(lr);

    DWORD cb = static_cast<DWORD>((wcslen(data) + 1) * sizeof(wchar_t));
    lr = RegSetValueExW(hKey, valueName, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(data), cb);
    RegCloseKey(hKey);
    return HRESULT_FROM_WIN32(lr);
}

// ─── DllRegisterServer / DllUnregisterServer ─────────────────────────────────

STDAPI DllRegisterServer()
{
    wchar_t szPath[MAX_PATH] = {};
    if (!GetModuleFileNameW(g_hInst, szPath, MAX_PATH))
        return HRESULT_FROM_WIN32(GetLastError());

    const wchar_t* kClsidBase =
        L"CLSID\\{B5A84CD4-1F6A-4A52-9A11-D90E6C9D9C4A}";
    const wchar_t* kInproc =
        L"CLSID\\{B5A84CD4-1F6A-4A52-9A11-D90E6C9D9C4A}\\InprocServer32";
    const wchar_t* kCpReg =
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication"
        L"\\Credential Providers\\{B5A84CD4-1F6A-4A52-9A11-D90E6C9D9C4A}";

    HRESULT hr;

    // HKCR\CLSID\{...}  (friendly name)
    hr = SetRegString(HKEY_CLASSES_ROOT, kClsidBase,
        nullptr, L"ResetPasswordCredentialProvider");
    if (FAILED(hr)) return hr;

    // HKCR\CLSID\{...}\InprocServer32  (DLL path + threading model)
    hr = SetRegString(HKEY_CLASSES_ROOT, kInproc, nullptr, szPath);
    if (FAILED(hr)) return hr;

    hr = SetRegString(HKEY_CLASSES_ROOT, kInproc, L"ThreadingModel", L"Apartment");
    if (FAILED(hr)) return hr;

    // HKLM\...Authentication\Credential Providers\{...}  (enables the tile)
    hr = SetRegString(HKEY_LOCAL_MACHINE, kCpReg,
        nullptr, L"ResetPasswordCredentialProvider");
    return hr;
}

STDAPI DllUnregisterServer()
{
    RegDeleteKeyW(HKEY_CLASSES_ROOT,
        L"CLSID\\{B5A84CD4-1F6A-4A52-9A11-D90E6C9D9C4A}\\InprocServer32");
    RegDeleteKeyW(HKEY_CLASSES_ROOT,
        L"CLSID\\{B5A84CD4-1F6A-4A52-9A11-D90E6C9D9C4A}");
    RegDeleteKeyW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication"
        L"\\Credential Providers\\{B5A84CD4-1F6A-4A52-9A11-D90E6C9D9C4A}");
    return S_OK;
}
