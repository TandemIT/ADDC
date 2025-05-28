<#
.SYNOPSIS
    Disable inactive user accounts in Active Directory.

.DESCRIPTION
    Identifies and disables user accounts inactive for a specified number of days.
    Requires RSAT ActiveDirectory module and Administrator privileges.

.PARAMETER DaysInactive
    Number of days since last logon. Users inactive this many days or more will be disabled. Default: 90

.PARAMETER Domain
    Active Directory domain to query. Default: current domain

.PARAMETER Credential
    Optional credentials for domain authentication. Defaults to current user.

.EXAMPLE
    .\Disable-InactiveUsers.ps1 -DaysInactive 120 -Domain "corp.example.com" -Credential (Get-Credential)

    Disables accounts inactive for 120+ days in "corp.example.com" domain.

#>

param (
    [ValidateRange(1, 3650)]
    [int]$DaysInactive = 90,

    [string]$Domain = (Get-ADDomain).DNSRoot,

    [System.Management.Automation.PSCredential]$Credential = $null
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-Admin {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run as Administrator."
    }
    Write-Host "[✓] Administrator privileges confirmed."
}

function Import-ADModule {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "ActiveDirectory module not found. Please install RSAT tools."
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "[✓] ActiveDirectory module imported."
}

function Get-InactiveUsers {
    param (
        [int]$Days,
        [string]$DomainName,
        [System.Management.Automation.PSCredential]$Cred
    )

    $thresholdDate = (Get-Date).AddDays(-$Days)
    Write-Host "[ℹ️] Finding users inactive since $thresholdDate..."

    $filter = { Enabled -eq $true -and LastLogonDate -lt $thresholdDate }

    try {
        $users = if ($Cred) {
            Get-ADUser -Filter $filter -Properties LastLogonDate, SamAccountName, DistinguishedName -Credential $Cred -Server $DomainName
        } else {
            Get-ADUser -Filter $filter -Properties LastLogonDate, SamAccountName, DistinguishedName -Server $DomainName
        }
    } catch {
        throw "Failed to query AD users: $_"
    }

    return $users
}

function Disable-Users {
    param (
        [array]$Users,
        [string]$DomainName,
        [System.Management.Automation.PSCredential]$Cred
    )

    if (-not $Users -or $Users.Count -eq 0) {
        Write-Host "[✓] No inactive users to disable."
        return
    }

    Write-Host "[⚠️] Found $($Users.Count) inactive user(s). Disabling..."

    $progress = 0
    foreach ($user in $Users) {
        $progress++
        Write-Progress -Activity "Disabling users" -Status "$progress of $($Users.Count)" -PercentComplete (($progress / $Users.Count) * 100)

        try {
            if ($Cred) {
                Disable-ADAccount -Identity $user.DistinguishedName -Credential $Cred -Server $DomainName -ErrorAction Stop
            } else {
                Disable-ADAccount -Identity $user.DistinguishedName -Server $DomainName -ErrorAction Stop
            }
            Write-Host "[✓] Disabled user: $($user.SamAccountName) (Last Logon: $($user.LastLogonDate))"
        } catch {
            Write-Warning "Failed to disable user $($user.SamAccountName): $_"
        }
    }
}

try {
    Test-Admin
    Import-ADModule

    if (-not $Credential) {
        Write-Host "[ℹ️] No credential supplied, using current user context."
    }

    $inactiveUsers = Get-InactiveUsers -Days $DaysInactive -DomainName $Domain -Cred $Credential
    Disable-Users -Users $inactiveUsers -DomainName $Domain -Cred $Credential

    Write-Host "[✓] Script completed successfully."
} catch {
    Write-Error "❌ Error: $_"
    exit 1
}
