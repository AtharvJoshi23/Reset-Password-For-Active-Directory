#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs ResetPasswordAPI as a Windows Service.
    Run after copying the published EXE to C:\ResetPasswordAPI\
#>

$ServiceName = "ResetPasswordAPI"
$DisplayName = "Reset Password API"
$ExePath     = "C:\ResetPasswordAPI\ResetPasswordAPI.exe"
$WorkDir     = "C:\ResetPasswordAPI"

# Stop and remove existing service if present
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Stopping existing service..." -ForegroundColor Yellow
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep 2
}

# Create service
sc.exe create $ServiceName `
    binPath= "`"$ExePath`"" `
    DisplayName= "$DisplayName" `
    start= auto `
    obj= LocalSystem | Out-Null

# Set working directory via registry (so .env is found relative to EXE)
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
Set-ItemProperty -Path $regPath -Name "AppDirectory" -Value $WorkDir -Type String

# Add failure recovery: restart on crash
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

# Start
Start-Service -Name $ServiceName
Start-Sleep 3

$svc = Get-Service -Name $ServiceName
if ($svc.Status -eq "Running") {
    Write-Host "Service running." -ForegroundColor Green
} else {
    Write-Host "Service status: $($svc.Status)" -ForegroundColor Red
    Write-Host "Check: Get-EventLog -LogName Application -Source $ServiceName -Newest 5"
}
