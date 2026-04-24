#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs ResetPasswordCP.dll into System32 and registers it as a
    Windows Credential Provider.

.NOTES
    Build the project in Release|x64 before running this script.
    Run from an elevated (Administrator) PowerShell prompt.
#>

$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$DllSource = Join-Path $ScriptDir "x64\Release\ResetPasswordCP.dll"
$DllDest   = "$env:SystemRoot\System32\ResetPasswordCP.dll"

# ── Pre-flight ────────────────────────────────────────────────────────────────
if (-not (Test-Path $DllSource)) {
    Write-Error @"
DLL not found at:
  $DllSource

Build steps:
  1. Open ResetPasswordCP.vcxproj in Visual Studio 2022
  2. Select configuration: Release | x64
  3. Build -> Build Solution  (Ctrl+Shift+B)
  4. Re-run this script
"@
    exit 1
}

# ── Stop LogonUI so the DLL is not locked ────────────────────────────────────
# LogonUI.exe restarts automatically; winlogon.exe keeps running.
Write-Host "Stopping LogonUI to release any DLL lock..."
Get-Process -Name "LogonUI" -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue

Start-Sleep -Milliseconds 500

# ── Copy DLL ─────────────────────────────────────────────────────────────────
Write-Host "Copying DLL to $DllDest ..."
Copy-Item $DllSource $DllDest -Force

# ── Register COM server + Credential Provider ─────────────────────────────────
Write-Host "Registering with regsvr32..."
$result = Start-Process -FilePath "regsvr32.exe" `
    -ArgumentList "/s `"$DllDest`"" `
    -Wait -PassThru

if ($result.ExitCode -ne 0) {
    Write-Error "regsvr32 failed (exit code $($result.ExitCode)).`nCheck Event Viewer > Windows Logs > Application for details."
    exit 1
}

Write-Host ""
Write-Host "Installation complete." -ForegroundColor Green
Write-Host "Lock your workstation (Win+L) to see the 'Reset AD Password' tile."
Write-Host ""
Write-Host "To uninstall:"
Write-Host "  regsvr32 /u `"$DllDest`""
Write-Host "  Remove-Item `"$DllDest`""
