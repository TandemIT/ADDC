<#
.SYNOPSIS
    Remove disabled user accounts from a specified OU in Active Directory.

.DESCRIPTION
    Targets a specified OU in an AD domain and removes disabled user accounts.
    Supports confirmation prompts, WhatIf simulation, logging with retention, and configurable log levels.

.PARAMETER OU
    Distinguished Name (DN) of the OU to target.

.PARAMETER Domain
    AD domain name.

.PARAMETER Credential
    Credentials for domain authentication.

.PARAMETER Force
    Skip confirmation prompt and delete directly.

.PARAMETER WhatIf
    Simulate deletion without making changes.

.PARAMETER LogFolder
    Folder to store logs. Defaults to "$env:USERPROFILE\Documents\Logs".

.PARAMETER LogLevel
    Logging detail level. One of Info (default), Debug, Warning, Error.

.PARAMETER LogRetentionDays
    Days to keep old logs. Default 30.

.EXAMPLE
    .\Remove-DisabledUsers.ps1 -OU "OU=DisabledUsers,DC=example,DC=com" -Domain "example.com" -Credential (Get-Credential)

#>

param (
    [Parameter(Mandatory)][string]$OU,
    [Parameter(Mandatory)][string]$Domain,
    [Parameter(Mandatory)][pscredential]$Credential,
    [switch]$Force,
    [switch]$WhatIf,
    [string]$LogFolder = "$env:USERPROFILE\Documents\Logs",
    [ValidateSet("Info", "Debug", "Warning", "Error")]
    [string]$LogLevel = "Info",
    [ValidateRange(1, 365)]
    [int]$LogRetentionDays = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-Admin {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run the script as Administrator."
    }
    Write-Verbose "[✓] Administrator rights confirmed."
}

function Import-ADModule {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "ActiveDirectory module missing. Install RSAT tools."
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Verbose "[✓] ActiveDirectory module imported."
}

function Initialize-Logging {
    param (
        [string]$Folder,
        [string]$Level,
        [int]$RetentionDays
    )

    if (-not (Test-Path $Folder)) {
        New-Item -Path $Folder -ItemType Directory | Out-Null
    }

    # Rotate logs
    Get-ChildItem -Path $Folder -Filter "remove_disabled_users_*.log" |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$RetentionDays) } |
        Remove-Item -Force -ErrorAction SilentlyContinue

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $logFile = Join-Path $Folder "remove_disabled_users_$timestamp.log"
    Start-Transcript -Path $logFile -Force
    Write-Verbose "[✓] Logging started at $logFile"

    return $logFile
}

function Confirm-Action {
    param (
        [switch]$Force,
        [array]$Items
    )

    if ($Force) {
        Write-Verbose "Force parameter specified; skipping confirmation."
        return $true
    }

    Write-Host "Found $($Items.Count) disabled user(s):"
    foreach ($item in $Items) {
        Write-Host " - $($item.SamAccountName) (DN: $($item.DistinguishedName))"
    }
    $response = Read-Host "Proceed with removal? (Y/N)"
    return $response -eq 'Y'
}

function Remove-DisabledUsers {
    param (
        [array]$Users,
        [string]$Domain,
        [pscredential]$Cred,
        [switch]$WhatIf
    )

    $count = $Users.Count
    $progress = 0

    foreach ($user in $Users) {
        $progress++
        Write-Progress -Activity "Removing disabled users" -Status "$progress of $count" -PercentComplete (($progress / $count) * 100)

        try {
            Remove-ADUser -Identity $user.DistinguishedName -Credential $Cred -Server $Domain -Confirm:$false -WhatIf:$WhatIf
            if ($WhatIf) {
                Write-Host "WhatIf: Would remove user $($user.SamAccountName)"
            } else {
                Write-Host "Removed user: $($user.SamAccountName)"
            }
        } catch {
            Write-Warning "Error removing $($user.SamAccountName): $_"
        }
    }
}

try {
    Test-Admin
    Import-ADModule
    $logFile = Initialize-Logging -Folder $LogFolder -Level $LogLevel -RetentionDays $LogRetentionDays

    Write-Verbose "Querying disabled users in OU: $OU"
    $disabledUsers = Get-ADUser -Filter { Enabled -eq $false } -SearchBase $OU -Properties SamAccountName, DistinguishedName -Credential $Credential -Server $Domain

    if (-not $disabledUsers -or $disabledUsers.Count -eq 0) {
        Write-Host "No disabled users found in OU: $OU"
        Stop-Transcript
        exit 0
    }

    if (-not (Confirm-Action -Force:$Force -Items $disabledUsers)) {
        Write-Host "Operation cancelled by user."
        Stop-Transcript
        exit 0
    }

    Remove-DisabledUsers -Users $disabledUsers -Domain $Domain -Cred $Credential -WhatIf:$WhatIf

    Write-Host "[✓] Operation completed."

    Stop-Transcript
} catch {
    Write-Error "❌ Script error: $_"
    if ($logFile) { Stop-Transcript }
    exit 1
}
