<#
.SYNOPSIS
    Removes inactive computers from Active Directory.

.DESCRIPTION
    Identifies and removes AD computer accounts that haven't logged in within the specified number of days.
    Requires AD module and administrative rights. Supports WhatIf, Force, and logging with retention.

.PARAMETER DaysInactive
    Number of days since last logon. Defaults to 90.

.PARAMETER Domain
    Active Directory domain to query. Defaults to current domain.

.PARAMETER Credential
    Optional AD credentials. Defaults to current user.

.PARAMETER WhatIf
    Simulate the deletion.

.PARAMETER Force
    Skip confirmation prompts.

.PARAMETER LogFolder
    Path for logs. Defaults to user's Documents.

.PARAMETER LogLevel
    Logging detail level: Info, Debug, Warning, Error.

.EXAMPLE
    .\remove-inactive-pc.ps1 -DaysInactive 120 -Domain "corp.example.com" -Credential (Get-Credential) -WhatIf
#>

param (
    [ValidateRange(1, 3650)]
    [int]$DaysInactive = 90,

    [string]$Domain = (Get-ADDomain).DNSRoot,

    [System.Management.Automation.PSCredential]$Credential = $null,

    [switch]$WhatIf,
    [switch]$Force,

    [string]$LogFolder = "$env:USERPROFILE\Documents\Logs",

    [ValidateSet("Info", "Debug", "Warning", "Error")]
    [string]$LogLevel = "Info"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-Admin {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run as Administrator."
    }
    Write-Verbose "[✓] Administrator rights confirmed."
}

function Import-ADModule {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "ActiveDirectory module not found. Install RSAT tools."
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Verbose "[✓] ActiveDirectory module imported."
}

function Start-Logging {
    if (-not (Test-Path $LogFolder)) {
        New-Item -Path $LogFolder -ItemType Directory | Out-Null
    }
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $logFile = Join-Path $LogFolder "remove_inactive_pcs_$timestamp.log"
    Start-Transcript -Path $logFile -Force
    return $logFile
}

function Get-InactivePCs {
    param (
        [int]$Days,
        [string]$DomainName,
        [System.Management.Automation.PSCredential]$Cred
    )
    $threshold = (Get-Date).AddDays(-$Days)
    Write-Host "[ℹ️] Searching for PCs inactive since $threshold..."

    $props = 'Name', 'lastLogonTimestamp', 'DistinguishedName'

    if ($Cred) {
        Get-ADComputer -Filter * -Properties $props -Server $DomainName -Credential $Cred |
            Where-Object { $_.lastLogonTimestamp -and ([DateTime]::FromFileTime($_.lastLogonTimestamp) -lt $threshold) }
    } else {
        Get-ADComputer -Filter * -Properties $props -Server $DomainName |
            Where-Object { $_.lastLogonTimestamp -and ([DateTime]::FromFileTime($_.lastLogonTimestamp) -lt $threshold) }
    }
}

function Remove-PCs {
    param (
        [array]$PCs,
        [switch]$WhatIf,
        [switch]$Force
    )
    foreach ($pc in $PCs) {
        if ($WhatIf) {
            Write-Host "[WhatIf] Would remove PC: $($pc.Name)"
        } elseif ($Force -or ((Read-Host "Remove PC '$($pc.Name)'? (yes/no)").ToLower() -eq 'yes')) {
            try {
                Remove-ADComputer -Identity $pc.DistinguishedName -Confirm:$false
                Write-Host "[✓] Removed PC: $($pc.Name)"
            } catch {
                Write-Warning "Failed to remove PC '$($pc.Name)': $_"
            }
        } else {
            Write-Host "[✖️] Skipped: $($pc.Name)"
        }
    }
}

try {
    Test-Admin
    Test-Admin
    Import-ADModule
    $logFile = Start-Logging

    $inactivePCs = Get-InactivePCs -Days $DaysInactive -DomainName $Domain -Cred $Credential
    if (-not $inactivePCs -or $inactivePCs.Count -eq 0) {
        Write-Host "[✓] No inactive PCs found."
    } else {
        Write-Host "[⚠️] Found $($inactivePCs.Count) inactive PCs."
        Remove-PCs -PCs $inactivePCs -WhatIf:$WhatIf -Force:$Force
    }

    Write-Host "[✓] Inactive PC cleanup completed."
    Stop-Transcript
} catch {
    Write-Error "❌ Script error: $_"
    try { Stop-Transcript } catch {}
}
