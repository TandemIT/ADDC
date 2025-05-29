<#
.SYNOPSIS
    Adds new users from a CSV file to Active Directory.
.DESCRIPTION    
    Uses user info from CSV to create users in the correct OU, based on their Gilde (team/unit).
.PARAMETER CsvFile
    Path to the CSV file (semicolon-delimited). Required columns:
    Description, Email, Gilde, Username, Firstname, Lastname, Password, OU
.EXAMPLE
    .\new-user.ps1 -CsvFile "C:\users.csv"
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$CsvFile
)

# Ensure admin rights
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "❌ This script must be run as Administrator."
}

# Load AD module
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "[✓] Active Directory module loaded."
} catch {
    throw "❌ Could not load AD module. Ensure RSAT is installed."
}

# Logging
$LogDateTime = Get-Date -Format "yyyyMMddHHmmss"
$LogFolder = ".\Log"
if (-not (Test-Path $LogFolder)) { New-Item -Path $LogFolder -ItemType Directory | Out-Null }
$LogFile = Join-Path $LogFolder "$LogDateTime.txt"
Start-Transcript -Path $LogFile -Force

# Load CSV
if (-not (Test-Path $CsvFile)) {
    throw "❌ CSV file not found: $CsvFile"
}
$users = Import-Csv -Path $CsvFile -Delimiter ";"
Write-Host "[ℹ️] Loaded $($users.Count) users from CSV.`n"

foreach ($user in $users) {
    try {
        $username = $user.Username
        if (-not $username) { continue }  # Skip blank lines

        Write-Host "🔹 Processing: $username"

        # Check if user already exists
        $existingUser = Get-ADUser -Filter { SamAccountName -eq $username } -ErrorAction SilentlyContinue
        if ($existingUser) {
            Write-Warning "⚠️ User '$username' already exists. Skipping."
            continue
        }

        # Construct full OU path: Gilde is a sub-OU under OU from CSV
        $baseOU = $user.OU.Trim()
        $gildeOU = $user.Gilde.Trim()
        $fullOU = "OU=$gildeOU,$baseOU"  # Example: OU=Sysadmin,OU=Users,DC=example,DC=com

        # Ensure OU exists, create if missing. Uncomment if you are sure you dont have any typo in your OUs
        # if (-not (Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$fullOU)" -ErrorAction SilentlyContinue)) {
        #     try {
        #         New-ADOrganizationalUnit -Name $gildeOU -Path $baseOU -ErrorAction Stop
        #         Write-Host "[+] Created OU: $fullOU"
        #     } catch {
        #         Write-Warning "⚠️ Could not create OU: $fullOU. $_"
        #         continue
        #     }
        # }

        $securePassword = ConvertTo-SecureString $user.Password -AsPlainText -Force

        $newUserParams = @{
            GivenName             = $user.Firstname
            Surname               = $user.Lastname
            SamAccountName        = $username
            Name                  = "$($user.Firstname) $($user.Lastname)"
            EmailAddress          = $user.Email
            Description           = $user.Description
            Path                  = $fullOU
            AccountPassword       = $securePassword
            Enabled               = $true
            ChangePasswordAtLogon = $true
        }

        # Create the AD user
        New-ADUser @newUserParams

        # Ensure password is set/reset correctly
        Set-ADAccountPassword -Identity $username -NewPassword $securePassword -Reset

        Write-Host "[✓] Created user: $username in $fullOU"
    } catch {
        Write-Error "❌ Failed to process '$($user.Username)': $_"
    }
}

Write-Host "[✔] All users processed."
Stop-Transcript
