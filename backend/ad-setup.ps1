#Requires -RunAsAdministrator
#Requires -Module ActiveDirectory
<#
.SYNOPSIS
    Full Active Directory setup for the Reset Password Credential Provider.

.DESCRIPTION
    Run this script on a Domain Controller or a machine with RSAT installed.
    It creates the service account, sets LDAPS permissions, issues a TLS
    certificate, and creates the DNS record for reset.company.local.

.NOTES
    Edit the variables in the CONFIG block before running.
#>

# ══════════════════════════════════════════════════════════════════════════════
# CONFIG — edit these before running
# ══════════════════════════════════════════════════════════════════════════════

$DomainDN          = "DC=company,DC=local"          # Your domain DN
$DomainName        = "company.local"                # Your domain FQDN
$ApiServerFQDN     = "reset.company.local"          # FQDN for the API server
$ApiServerIP       = "192.168.1.50"                 # IP of the server running the API

$SvcAccountName    = "svc-pwreset"                  # Service account sAMAccountName
$SvcAccountOU      = "OU=Service Accounts,$DomainDN"# OU for the service account
$SvcAccountPwd     = ConvertTo-SecureString "Str0ng$erviceP@ss!" -AsPlainText -Force

# OU containing the user accounts whose passwords will be reset
$UsersOU           = "OU=Users,$DomainDN"

# Where to export the CA root cert (for the Node.js backend)
$CaExportPath      = "C:\ResetPasswordAPI\certs\domain-ca.crt"

# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 — Create service account
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "`n[1/6] Creating service account: $SvcAccountName" -ForegroundColor Cyan

$existing = Get-ADUser -Filter { SamAccountName -eq $SvcAccountName } -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "  Service account already exists — skipping creation." -ForegroundColor Yellow
} else {
    New-ADUser `
        -Name              "Password Reset Service" `
        -SamAccountName    $SvcAccountName `
        -UserPrincipalName "$SvcAccountName@$DomainName" `
        -Path              $SvcAccountOU `
        -AccountPassword   $SvcAccountPwd `
        -PasswordNeverExpires $true `
        -CannotChangePassword $true `
        -Enabled           $true `
        -Description       "Service account for Reset Password Credential Provider API"
    Write-Host "  Created: $SvcAccountName" -ForegroundColor Green
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 — Grant "Reset Password" extended right on the Users OU
#
# We grant the specific extended right (GUID 00299570-...) rather than broad
# admin rights. The service account can ONLY reset passwords, nothing else.
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "`n[2/6] Granting 'Reset Password' right on $UsersOU" -ForegroundColor Cyan

$svcAccount    = Get-ADUser $SvcAccountName
$svcAccountSid = New-Object System.Security.Principal.SecurityIdentifier($svcAccount.SID)

# Import AD drive
Import-Module ActiveDirectory
$adDrive = "AD:"
if (-not (Get-PSDrive -Name "AD" -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name AD -PSProvider ActiveDirectory -Root "" | Out-Null
}

$ouPath = "$adDrive\$UsersOU"
$acl    = Get-Acl $ouPath

# Extended right GUID for "Reset Password"
$resetPasswordGuid = [Guid]"00299570-246d-11d0-a768-00aa006e0529"

# Apply to User objects (objectClass = user)
$userClassGuid = [Guid]"bf967aba-0de6-11d0-a285-00aa003049e2"

$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $svcAccountSid,
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AccessControlType]::Allow,
    $resetPasswordGuid,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
    $userClassGuid
)

$acl.AddAccessRule($ace)
Set-Acl -Path $ouPath -AclObject $acl
Write-Host "  Reset Password right granted to $SvcAccountName on $UsersOU" -ForegroundColor Green

# ══════════════════════════════════════════════════════════════════════════════
# STEP 3 — Verify LDAPS is working on all DCs
#
# LDAPS (port 636) is required for unicodePwd modification.
# It is enabled automatically when a DC has a certificate in its
# Personal store (installed by AD CS or manually).
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "`n[3/6] Verifying LDAPS on Domain Controllers" -ForegroundColor Cyan

$dcs = Get-ADDomainController -Filter *
foreach ($dc in $dcs) {
    $tcp = Test-NetConnection -ComputerName $dc.HostName -Port 636 -WarningAction SilentlyContinue
    if ($tcp.TcpTestSucceeded) {
        Write-Host "  [OK]  $($dc.HostName):636 — LDAPS reachable" -ForegroundColor Green
    } else {
        Write-Host "  [!!]  $($dc.HostName):636 — LDAPS NOT reachable" -ForegroundColor Red
        Write-Host "        Install a certificate in the DC's Personal (MY) store" -ForegroundColor Yellow
        Write-Host "        or enroll via AD CS: certsrv.msc > Kerberos Authentication template" -ForegroundColor Yellow
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 4 — Export the domain CA root certificate (PEM format)
#
# The Node.js backend uses this to validate the DC's LDAPS certificate.
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "`n[4/6] Exporting domain CA root certificate" -ForegroundColor Cyan

$caDir = Split-Path $CaExportPath -Parent
if (-not (Test-Path $caDir)) { New-Item -ItemType Directory -Path $caDir -Force | Out-Null }

# Find the root CA cert in the machine's Trusted Root store
$rootCert = Get-ChildItem Cert:\LocalMachine\Root |
    Where-Object { $_.Subject -like "*$DomainName*" -or $_.Subject -like "*CA*" } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

if ($rootCert) {
    # Export as PEM (Base64 DER)
    $certBytes  = $rootCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $certBase64 = [System.Convert]::ToBase64String($certBytes, 'InsertLineBreaks')
    $pem = "-----BEGIN CERTIFICATE-----`n$certBase64`n-----END CERTIFICATE-----"
    [System.IO.File]::WriteAllText($CaExportPath, $pem)
    Write-Host "  Exported to: $CaExportPath" -ForegroundColor Green
    Write-Host "  Copy this file to the Node.js backend's certs\ folder." -ForegroundColor Yellow
} else {
    Write-Host "  Could not find domain root CA in LocalMachine\Root." -ForegroundColor Red
    Write-Host "  Export manually: certmgr.msc > Trusted Root CAs > export as Base64 .cer" -ForegroundColor Yellow
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 5 — Request TLS certificate for reset.company.local from AD CS
#
# This certificate goes on the API server (Node.js HTTPS).
# The DLL's WinHTTP calls validate this cert using the machine's trust store.
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "`n[5/6] Requesting TLS certificate for $ApiServerFQDN" -ForegroundColor Cyan

$certStore  = "Cert:\LocalMachine\My"
$existing   = Get-ChildItem $certStore | Where-Object { $_.Subject -like "*$ApiServerFQDN*" }

if ($existing) {
    Write-Host "  Certificate already exists: $($existing.Subject)" -ForegroundColor Yellow
} else {
    # Request using the built-in WebServer template via certreq
    $infContent = @"
[Version]
Signature="`$Windows NT`$"

[NewRequest]
Subject = "CN=$ApiServerFQDN, O=Company, C=US"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = TRUE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = CMC
KeyUsage = 0xa0

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=$ApiServerFQDN&"

[RequestAttributes]
CertificateTemplate = WebServer
"@

    $infPath = "$env:TEMP\reset-api.inf"
    $reqPath = "$env:TEMP\reset-api.req"
    $cerPath = "$env:TEMP\reset-api.cer"

    $infContent | Set-Content $infPath -Encoding UTF8

    & certreq -new  $infPath $reqPath | Out-Null
    & certreq -submit -config "-" $reqPath $cerPath 2>&1 | Out-Null
    & certreq -accept $cerPath 2>&1 | Out-Null

    $newCert = Get-ChildItem $certStore | Where-Object { $_.Subject -like "*$ApiServerFQDN*" }
    if ($newCert) {
        Write-Host "  Certificate issued: Thumbprint $($newCert.Thumbprint)" -ForegroundColor Green
        Write-Host "  Export it as PFX and split into reset-api.crt + reset-api.key for Node.js" -ForegroundColor Yellow
        Write-Host "  Export command:" -ForegroundColor Yellow
        Write-Host "    certlm.msc > Personal > Certificates > right-click > Export (with private key)" -ForegroundColor Gray
        Write-Host "    Then: openssl pkcs12 -in reset-api.pfx -nocerts -out reset-api.key -nodes" -ForegroundColor Gray
        Write-Host "          openssl pkcs12 -in reset-api.pfx -clcerts -nokeys -out reset-api.crt" -ForegroundColor Gray
    } else {
        Write-Host "  Auto-request failed. Request manually via certlm.msc or AD CS web enrollment." -ForegroundColor Red
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 6 — Create DNS A record for reset.company.local
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "`n[6/6] Creating DNS record: $ApiServerFQDN → $ApiServerIP" -ForegroundColor Cyan

$zone     = $DomainName
$hostname = "reset"

$existingRecord = Get-DnsServerResourceRecord -ZoneName $zone -Name $hostname `
    -RRType A -ErrorAction SilentlyContinue

if ($existingRecord) {
    Write-Host "  DNS record already exists: $($existingRecord.RecordData.IPv4Address)" -ForegroundColor Yellow
} else {
    Add-DnsServerResourceRecordA -ZoneName $zone -Name $hostname -IPv4Address $ApiServerIP
    Write-Host "  Created: $ApiServerFQDN → $ApiServerIP" -ForegroundColor Green
}

# ══════════════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " AD Setup Complete — Next Steps:" -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host " 1. Copy certs to API server:" -ForegroundColor White
Write-Host "      domain-ca.crt  → C:\ResetPasswordAPI\certs\domain-ca.crt"
Write-Host "      reset-api.crt  → C:\ResetPasswordAPI\certs\reset-api.crt"
Write-Host "      reset-api.key  → C:\ResetPasswordAPI\certs\reset-api.key"
Write-Host ""
Write-Host " 2. On the API server, edit .env:" -ForegroundColor White
Write-Host "      AD_BIND_DN=$SvcAccountOU\$SvcAccountName (adjust DN)"
Write-Host "      AD_BIND_PASSWORD=<the password you set above>"
Write-Host ""
Write-Host " 3. Install Node.js 18 LTS on the API server" -ForegroundColor White
Write-Host "      cd C:\ResetPasswordAPI"
Write-Host "      npm install"
Write-Host "      node install-service.js"
Write-Host ""
Write-Host " 4. Test:" -ForegroundColor White
Write-Host "      curl -k https://reset.company.local/health"
Write-Host ""
Write-Host " 5. Build and install the DLL on workstations (install.ps1)" -ForegroundColor White
Write-Host ""
