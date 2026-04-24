#pragma once
#include <windows.h>
#include <objbase.h>
#include <credentialprovider.h>
#include <strsafe.h>
#include <new>

// {B5A84CD4-1F6A-4A52-9A11-D90E6C9D9C4A}
EXTERN_C const CLSID CLSID_ResetPasswordCP;

// Field layout
enum FIELD_ID : DWORD
{
    FI_TITLE        = 0,   // CPFT_LARGE_TEXT     — tile header
    FI_USERNAME     = 1,   // CPFT_EDIT_TEXT       — plain text
    FI_SEND_OTP     = 2,   // CPFT_COMMAND_LINK    — fires CommandLinkClicked
    FI_OTP          = 3,   // CPFT_PASSWORD_TEXT   — masked
    FI_NEW_PASSWORD = 4,   // CPFT_PASSWORD_TEXT   — masked
    FI_STATUS       = 5,   // CPFT_SMALL_TEXT      — live status / error display
    FI_SUBMIT       = 6,   // CPFT_SUBMIT_BUTTON   — fires GetSerialization
    FI_COUNT        = 7
};

// Declared here, defined once in Credential.cpp
extern const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR g_FieldDescriptors[FI_COUNT];

// Reference count for DllCanUnloadNow — defined in dllmain.cpp
extern LONG g_cRef;

class CCredential : public ICredentialProviderCredential
{
public:
    CCredential();
    ~CCredential();

    // IUnknown
    IFACEMETHODIMP         QueryInterface(REFIID riid, void** ppv);
    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();

    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* pcpce);
    IFACEMETHODIMP UnAdvise();
    IFACEMETHODIMP SetSelected(BOOL* pbAutoLogonWithDefault);
    IFACEMETHODIMP SetDeselected();
    IFACEMETHODIMP GetFieldState(DWORD dwFieldID,
        CREDENTIAL_PROVIDER_FIELD_STATE*            pcpfs,
        CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis);
    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, PWSTR* ppwsz);
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp);
    IFACEMETHODIMP GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, PWSTR* ppwszLabel);
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo);
    IFACEMETHODIMP GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem);
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR* ppwszItem);
    IFACEMETHODIMP SetStringValue(DWORD dwFieldID, PCWSTR pwz);
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL bChecked);
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem);
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID);
    IFACEMETHODIMP GetSerialization(
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*   pcpcs,
        PWSTR*                                          ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON*                pcpsiOptionalStatusIcon);
    IFACEMETHODIMP ReportResult(
        NTSTATUS ntsStatus, NTSTATUS ntsSubstatus,
        PWSTR*                   ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);

private:
    LONG  _cRef;
    ICredentialProviderCredentialEvents* _pEvents;

    wchar_t _szUsername   [256];
    wchar_t _szOTP        [64];
    wchar_t _szNewPassword[256];
    wchar_t _szStatus     [512];

    void _UpdateStatus(const wchar_t* msg);
};
