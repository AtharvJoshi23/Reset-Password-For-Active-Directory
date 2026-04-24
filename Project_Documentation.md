# Active Directory Password Reset – Credential Provider
## Technical Project Documentation

**Project Name:** AD Password Reset Credential Provider  
**Prepared By:** IT Department – VizPay  
**Date:** 23 April 2026  
**Version:** 1.0  

---

## 1. Executive Summary

This project delivers a self-service **Active Directory (AD) password reset solution** that appears directly on the **Windows lock screen** of domain-joined laptops. Users who have forgotten their password can reset it without calling the IT helpdesk, by verifying their identity through a One-Time Password (OTP) sent to their registered company email address.

---

## 2. Problem Statement

### Current Situation
- When a domain user forgets their Windows login password, they must call the IT helpdesk.
- The helpdesk manually resets the password in Active Directory and communicates it to the user.
- This process wastes IT staff time, causes delays for users, and creates a security risk (passwords communicated verbally or via unencrypted channels).

### Goal
Allow users to reset their own Active Directory password securely from the lock screen of their laptop, without any IT helpdesk involvement.

---

## 3. Solution Overview

The solution has **two components** that work together:

| Component | Technology | Runs On |
|---|---|---|
| Windows Credential Provider DLL | C++ (Win32 COM) | User's domain-joined laptop |
| Password Reset API (Backend) | ASP.NET Core 8 (.NET) | Domain Controller / Internal Server |

### How It Works (End-to-End Flow)

```
User locks laptop
        │
        ▼
Lock screen shows "Reset AD Password" tile  ←── Credential Provider DLL
        │
        ▼
User enters their AD username
        │
        ▼
User clicks "Send OTP"
        │
        ▼
DLL calls HTTPS API ──────────────────────► API looks up user in Active Directory
                                            API sends OTP to user's registered email
        │
        ▼
User receives OTP on company email
        │
        ▼
User enters OTP + New Password on lock screen
        │
        ▼
DLL calls HTTPS API ──────────────────────► API verifies OTP
                                            API resets password in Active Directory via LDAPS
        │
        ▼
"Password reset successful. You may now log in."
        │
        ▼
User logs in with new password
```

---

## 4. Component 1 – Windows Credential Provider DLL

### What It Is
A Windows Credential Provider is a COM (Component Object Model) DLL that Microsoft allows third parties to register on Windows. Once registered, it appears as a tile on the Windows lock screen alongside the standard username/password tile.

### Technology Used
- **Language:** C++ (C++17 standard)
- **APIs Used:** Windows Credential Provider API, WinHTTP, COM
- **Build Tool:** MSBuild with Visual Studio 2025 (toolset v145)
- **Output:** ResetPasswordCP.dll (64-bit Windows DLL)

### Source Files

| File | Purpose |
|---|---|
| src\dllmain.cpp | DLL entry point, COM class registration, registry install/uninstall |
| src\CredentialProvider.cpp | Implements ICredentialProvider — manages the tile and credential object |
| src\CProvider.h | Header for the credential provider classes |
| src\Credential.cpp | Implements ICredentialProviderCredential — UI fields and user interaction |
| src\Credential.h | Header for the credential class and field definitions |
| src\HttpClient.h | WinHTTP wrapper — sends HTTPS POST requests to the backend API |
| ResetPasswordCP.def | Exports DllGetClassObject, DllCanUnloadNow, DllRegisterServer, DllUnregisterServer |
| ResetPasswordCP.vcxproj | Visual Studio project file (MSBuild) |

### UI Fields Shown on Lock Screen

| Field | Type | Purpose |
|---|---|---|
| Reset AD Password | Header text | Tile title — visible even when collapsed |
| Username | Text input | User enters their AD username |
| Send OTP | Command link | Triggers OTP generation and email delivery |
| OTP Code | Password field (masked) | User enters the OTP received by email |
| New Password | Password field (masked) | User enters their desired new password |
| Status | Small text | Live feedback — Sending OTP, OTP sent, errors, success |
| Reset Password | Submit button | Triggers password reset via API |

---

## 5. Component 2 – Password Reset API (Backend)

### What It Is
A REST API that the DLL calls over HTTPS. It handles OTP generation, email delivery, and AD password changes.

### Technology Used
- **Framework:** ASP.NET Core 8 Minimal API
- **Language:** C# (.NET 8)
- **Runs As:** Windows Service (auto-starts on boot)
- **HTTPS:** Kestrel with PFX certificate on port 8443
- **AD Integration:** System.DirectoryServices.Protocols via LDAPS port 636
- **Email:** Zoho SMTP (smtp.zoho.com:587) with SSL
- **OTP Storage:** In-memory ConcurrentDictionary
- **Rate Limiting:** Max 10 requests per 15-minute window per IP

### API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| POST | /api/auth/request-otp | Validates username in AD, generates OTP, sends email |
| POST | /api/auth/reset-password | Verifies OTP, resets AD password via LDAPS |
| GET | /health | Health check — returns 200 OK if running |

### Configuration (.env)

```
AD_URL=ldaps://172.16.10.4:636
AD_BASE_DN=DC=viz,DC=in
AD_BIND_DN=CN=Password Reset Service,OU=Service-Accounts,OU=_ADMIN,DC=viz,DC=in
SMTP_HOST=smtp.zoho.com
SMTP_PORT=587
SMTP_USER=itsupport@vizpay.in
PORT=8443
OTP_TTL_SECONDS=300
RATE_LIMIT_MAX=10
```

---

## 6. Infrastructure & Network

| Item | Detail |
|---|---|
| API Server IP | 172.16.10.4 (Domain Controller) |
| API Hostname | reset.viz.in |
| API Port | 8443 (HTTPS only) |
| AD Domain | viz.in |
| LDAPS Port | 636 (encrypted AD communication) |
| SMTP Provider | Zoho Mail (smtp.zoho.com:587) |
| TLS Certificate | Internal cert issued for CN=reset.viz.in |
| Firewall Rule | Inbound TCP 8443 allowed on DC |

---

## 7. Why This Solution Is Secure

This is one of the most important aspects of the project. Every part of the system was designed with security as the top priority. Below is a detailed explanation of each security measure.

---

### 7.1 Identity Verification via OTP (Email-Based)

**What it does:**
Before any password reset is allowed, the system sends a 6-digit One-Time Password to the email address that is stored in Active Directory for that user account.

**Why it is secure:**
- Only the legitimate owner of the account has access to the registered company email inbox.
- An attacker who knows someone's username cannot reset their password without also having access to their email.
- This is a two-factor verification: something you know (username) + something you have (access to email).

---

### 7.2 OTP Expires in 5 Minutes

**What it does:**
Each OTP is valid for only 300 seconds (5 minutes) from the time it was generated. After that it is automatically deleted.

**Why it is secure:**
- Even if an OTP is intercepted or leaked, it becomes useless after 5 minutes.
- Reduces the window of opportunity for any attack.

---

### 7.3 OTP is Single-Use Only

**What it does:**
Once an OTP is used to reset a password (whether successfully or not), it is immediately deleted from memory and cannot be used again.

**Why it is secure:**
- Prevents replay attacks — an attacker cannot capture an OTP and reuse it later.
- Even if a user accidentally shares their OTP, it cannot be used a second time.

---

### 7.4 Rate Limiting (Brute Force Protection)

**What it does:**
The API allows a maximum of 10 OTP requests per IP address per 15-minute window. Any requests beyond this limit are rejected with HTTP 429.

**Why it is secure:**
- Prevents brute force attacks where an attacker tries thousands of OTPs in a short time.
- Limits automated attack tools from working against the system.
- A real user only needs 1–2 OTP requests; 10 is already generous.

---

### 7.5 All Communication Encrypted with HTTPS (TLS)

**What it does:**
Every request between the laptop DLL and the backend API travels over HTTPS (TLS encryption) on port 8443. Plain HTTP is not supported — not even as a fallback.

**Why it is secure:**
- Network traffic cannot be read by anyone monitoring the network (no man-in-the-middle reading passwords or OTPs).
- This is the same level of encryption used by online banking.
- The `WINHTTP_FLAG_SECURE` flag in the DLL enforces TLS — the connection will fail entirely rather than fall back to plain HTTP.

---

### 7.6 Active Directory Password Change over LDAPS (Port 636)

**What it does:**
The API connects to Active Directory using LDAPS (LDAP over SSL) on port 636 to change the user's password.

**Why it is secure:**
- Microsoft requires a secure (encrypted) channel to change AD passwords — it is impossible to change a password over plain LDAP on port 389.
- This means the new password is never transmitted in plain text, even inside the internal network.
- Using LDAPS is an AD security requirement, not optional.

---

### 7.7 Dedicated Minimum-Privilege Service Account

**What it does:**
The API connects to Active Directory using a dedicated service account:
`CN=Password Reset Service, OU=Service-Accounts`

This account has only one permission granted: **Reset Password on user objects**.

**Why it is secure:**
- Follows the principle of least privilege — the account cannot read other AD attributes, cannot create or delete accounts, cannot change group memberships.
- If the service account credentials were ever compromised, the attacker could only reset passwords (which requires knowing the correct OTP) — they could not take over AD or access other data.
- The account is in a dedicated Service-Accounts OU, separate from regular user accounts, making it easy to monitor and audit.

---

### 7.8 Passwords Wiped from Memory Immediately

**What it does:**
In the DLL (on the laptop), as soon as the new password is sent to the API, `SecureZeroMemory()` is called on the password buffer. This overwrites the memory with zeros before releasing it.

**Why it is secure:**
- On Windows, memory from a process can sometimes be read by other processes or left in a memory dump.
- `SecureZeroMemory()` is a Windows API specifically designed to prevent the compiler from optimizing away the memory wipe (a normal `memset` can be removed by the optimizer).
- After the call, the password no longer exists anywhere in the DLL's memory.

---

### 7.9 API Only Accessible Inside the Internal Network

**What it does:**
Port 8443 is only open on the internal network firewall. The API is not published to the internet.

**Why it is secure:**
- External attackers on the internet cannot reach the API at all.
- Only devices connected to the VizPay internal network or VPN can make requests.
- This eliminates the entire class of internet-based attacks against the API.

---

### 7.10 No Password Stored Anywhere in the System

**What it does:**
The system never stores the user's new password anywhere — not in a database, not in a log file, not in memory beyond the instant it is needed.

**Why it is secure:**
- There is no password database to breach.
- Logs only record events (OTP requested, password reset succeeded) — never the actual password or OTP value.
- The OTP itself is stored only in RAM for 5 minutes and then deleted.

---

### 7.11 Runs as a Windows Service (Not a User Application)

**What it does:**
The backend API runs as a Windows Service under the LocalSystem account. It starts automatically when the server boots, independent of any user logging in.

**Why it is secure:**
- No user needs to be logged in to the server for the service to work.
- The service cannot be accidentally closed by a user.
- Windows Service accounts are tightly controlled by the operating system.

---

### Security Summary Table

| Threat | Protection Mechanism |
|---|---|
| Attacker guesses username and resets password | OTP sent only to registered email — attacker needs email access |
| OTP intercepted in transit | HTTPS encryption — OTP is never visible on the network |
| Attacker tries all possible OTPs | Rate limiting — max 10 attempts per 15 minutes |
| Attacker captures OTP and reuses it | OTP is single-use and expires in 5 minutes |
| New password intercepted in transit | HTTPS (TLS) encryption end-to-end |
| Password visible in memory after reset | SecureZeroMemory() wipes it immediately |
| Service account abused if compromised | Minimum privilege — Reset Password only |
| API attacked from the internet | Port 8443 blocked at perimeter — internal network only |
| Password stored and breached | No password storage anywhere in the system |
| LDAP traffic sniffed on internal network | LDAPS (port 636) encrypts all AD communication |

---

## 8. Deployment

### Backend API (Domain Controller)

1. Publish .NET app as self-contained EXE
2. Copy to C:\ResetPasswordAPI\
3. Place TLS certificate at C:\ResetPasswordAPI\certs\reset-api.pfx
4. Create .env configuration file
5. Install and start Windows Service:
```
sc create ResetPasswordAPI binPath= "C:\ResetPasswordAPI\ResetPasswordAPI.exe" start= auto
sc start ResetPasswordAPI
```

### DLL (Each User Laptop)

1. Copy ResetPasswordCP.dll to C:\Windows\System32\
2. Register:
```
regsvr32 /s C:\Windows\System32\ResetPasswordCP.dll
```
3. Lock screen — tile appears immediately

### Uninstall

```
regsvr32 /u /s C:\Windows\System32\ResetPasswordCP.dll
del C:\Windows\System32\ResetPasswordCP.dll
```

---

## 9. Testing Results

| Test Case | Result |
|---|---|
| OTP sent to registered email | PASS |
| OTP verified and password reset in AD | PASS |
| Lock screen tile appears on domain laptop | PASS |
| Invalid username returns error message | PASS |
| Expired OTP rejected | PASS |
| API health check returns 200 OK | PASS |
| API auto-starts after server reboot | PASS |
| Rate limiting blocks excess requests | PASS |

---

## 10. Known Limitations and Future Improvements

| Item | Detail |
|---|---|
| Email requirement | User must have an email address set in their AD account |
| OTP in memory | If API service restarts, pending OTPs are lost (user requests a new one) |
| Single server | API runs on DC — future: move to dedicated member server |
| Bulk laptop deployment | Currently manual — can be automated via GPO or Intune |
| Audit logging | Future: structured logs to SIEM or database for compliance |

---

## 11. Project File Structure

```
D:\reset password\
├── src\
│   ├── dllmain.cpp
│   ├── CProvider.h
│   ├── CredentialProvider.cpp
│   ├── Credential.h
│   ├── Credential.cpp
│   └── HttpClient.h
├── ResetPasswordCP.def
├── ResetPasswordCP.vcxproj
├── x64\Release\
│   └── ResetPasswordCP.dll        (deploy this file to laptops)
└── backend-dotnet\
    ├── Program.cs
    ├── ResetPasswordAPI.csproj
    ├── .env.example
    └── install-service.ps1
```

---

*Prepared by IT Department — VizPay | April 2026*
