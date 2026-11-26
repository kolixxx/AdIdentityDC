#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Register AdIdentity as Windows service AdIdentityAgent (Role from appsettings.json).

.EXAMPLE
  .\Install-AdIdentityService.ps1 -Start
#>
param(
    [string] $InstallDir = 'C:\AdIdentity',
    [switch] $Start
)

$ErrorActionPreference = 'Stop'

$exe = Join-Path $InstallDir 'AdIdentity.Agent.Service.exe'
$settings = Join-Path $InstallDir 'appsettings.json'
$name = 'AdIdentityAgent'

if (-not (Test-Path -LiteralPath $exe)) {
    throw "Binary not found: $exe"
}
if (-not (Test-Path -LiteralPath $settings)) {
    throw "Config not found: $settings"
}

Get-Process -Name 'AdIdentity.Agent.Service' -ErrorAction SilentlyContinue |
    Stop-Process -Force

# Remove role-specific names from earlier attempts.
foreach ($legacy in @('AdIdentityCollector', 'AdIdentitySensor')) {
    $old = Get-Service -Name $legacy -ErrorAction SilentlyContinue
    if ($old) {
        if ($old.Status -eq 'Running') { Stop-Service -Name $legacy -Force }
        sc.exe delete $legacy | Out-Null
        Start-Sleep -Seconds 1
        Write-Host "Removed legacy service $legacy"
    }
}

$existing = Get-Service -Name $name -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -eq 'Running') {
        Stop-Service -Name $name -Force
    }
    Write-Host "Service $name already registered."
} else {
    New-Service -Name $name `
        -BinaryPathName "`"$exe`"" `
        -DisplayName 'AdIdentity Agent' `
        -StartupType Automatic | Out-Null
    Write-Host "Created service $name."
}

# Restart after a crash: StartupType Automatic only covers boot.
sc.exe failure $name reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null

if ($Start) {
    Start-Service -Name $name
    Get-Service -Name $name | Format-List Name, Status, StartType
}
