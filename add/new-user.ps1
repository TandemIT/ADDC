<#
.SYNOPSIS
    Adds new users to Active Directory from a CSV file.

.DESCRIPTION    
    This script adds one or more new users to Active Directory using data from a specified CSV file.
    It includes logging, basic error handling, and a check to skip users that already exist.

.PARAMETER CsvFile
    The path to the CSV file containing user information.

.EXAMPLE
    .\new-user.ps1 -CsvFile "C:\path\to\users.csv"
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$CsvFile
)

# Validate and import module
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must be run as Administrator."
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "[✓] Active Directory module loaded."
} catch {
    throw "❌ Failed to import Active Directory module. Make sure RSAT is installed."
}

# Setup logging
$LogDateTime = Get-Date -Format "yyyyMMddHHmmss"
$LogFolder = ".\Log"
if (-not (Test-Path $LogFolder)) { New-Item -Path $LogFolder -ItemType Directory | Out-Null }
$LogFile = Join-Path $LogFolder "$LogDateTime.txt"
Start-Transcript -Path $LogFile -Force

# Import CSV
if (-not (Test-Path $CsvFile)) {
    throw "❌ CSV file not found: $CsvFile"
}

$users = Import-Csv -Path $CsvFile -Delimiter ";" 

Write-Host "[ℹ️] Loaded $($users.Count) users from CSV."

# Process each user
foreach ($user in $users) {
    try {
        Write-Host "[ℹ️] Processing user: $($user.Username)" -ForegroundColor Cyan

        # Check if user already exists
        $existingUser = Get-ADUser -Filter { SamAccountName -eq $user.Username } -ErrorAction SilentlyContinue
        if ($existingUser) {
            Write-Warning "⚠️ User $($user.Username) already exists. Skipping."
            continue
        }

        # Create new user parameters
        $newUserParams = @{
            GivenName           = $user.Firstname
            Surname             = $user.Lastname
            SamAccountName      = $user.Username
            Name                = "$($user.Firstname) $($user.Lastname)"
            EmailAddress        = $user.Email
            Department          = $user.Department
            TelephoneNumber     = $user.Phone
            Description         = $user.Description
            Path                = $user.OU
            AccountPassword     = (ConvertTo-SecureString $user.Password -AsPlainText -Force)
            Enabled             = $true
            ChangePasswordAtLogon = $true
        }

        # Create the user
        New-ADUser @newUserParams
        Write-Host "[✓] Created user: $($user.Username)"

        # Set password again (optional, for redundancy)
        Set-ADAccountPassword -Identity $user.Username -NewPassword (ConvertTo-SecureString $user.Password -AsPlainText -Force) -Reset
        Write-Host "[✓] Password set for: $($user.Username)"

    } catch {
        Write-Error "❌ Failed to create user $($user.Username): $_"
    }
}

Write-Host "[✓] Script execution completed."
Stop-Transcript