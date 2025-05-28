<#
    setup.ps1 - Bootstraps AD DS and DNS setup
#>

# Requires -RunAsAdministrator
# Requires -Modules ActiveDirectory, DnsServer
# Requires -Version 5.1 or PowerShell 7+
# Requires -File env.ps1, create-tree.ps1, create-dns.ps1

$ErrorActionPreference = "Stop"

# --- [ Script Root Setup ] ---
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# --- [ Logging Setup ] ---
$logFolder = "$ScriptRoot\logs"
if (-not (Test-Path $logFolder)) {
    New-Item -Path $logFolder -ItemType Directory | Out-Null
}

function Start-Log {
    param ([string]$label)
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $logFile = "$logFolder\$label`_$timestamp.log"
    Start-Transcript -Path $logFile -Force
    Write-Host "[📄] Transcript started: $logFile"
}

function Stop-Log {
    Stop-Transcript
    Write-Host "[📄] Transcript stopped.`n"
}

# --- [ 01: Admin Check ] ---
Start-Log -label "01_admin_check"
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "❌ This script must be run as Administrator."
    Stop-Log
    exit 1
}
Write-Host "[✓] Running with administrator privileges.`n"
Stop-Log

# --- [ 02: Set Execution Policy ] ---
Start-Log -label "02_exec_policy"
try {
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force -Scope Process
    Write-Host "[✓] Execution policy set to RemoteSigned for this session."
} catch {
    Write-Warning "⚠️ Failed to set execution policy. You might need to allow it manually."
}
Stop-Log

# --- [ 03: Import Environment Variables ] ---
Start-Log -label "03_import_env"

$envScript = Join-Path $ScriptRoot "env.ps1"
if (-not (Test-Path $envScript)) {
    Write-Error "❌ env.ps1 not found at $envScript"
    Stop-Log
    exit 1
}

function Import-DotEnv ($path = "$ScriptRoot\.env") {
    if (-not (Test-Path $path)) {
        throw ".env file not found at $path"
    }
    Get-Content $path | ForEach-Object {
        if ($_ -match "^\s*#|^\s*$") { return }
        if ($_ -match "^\s*([^=]+?)\s*=\s*(.*)\s*$") {
            [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
        }
    }
    Write-Host "[✓] .env loaded into session."
}

Import-DotEnv

. $envScript
if (-not $?) {
    Write-Error "❌ env.ps1 failed to load. Check for syntax errors or missing values."
    Stop-Log
    exit 1
}
Write-Host "[✓] env.ps1 sourced successfully."
Stop-Log

# --- [ 04: Validate Required Variables ] ---
Start-Log -label "04_validate_env"
$requiredVars = @(
    "DomainName", "NetbiosName", "SafeModePassword", "DCName",
    "OUPath", "DefaultUserPassword", "IPAddress", "Gateway", "Prefix", "Interface"
)
$missing = @()

foreach ($var in $requiredVars) {
    if (-not (Get-Variable -Name $var -ErrorAction SilentlyContinue)) {
        $missing += $var
    }
}

if ($missing.Count -gt 0) {
    Write-Error "❌ Missing required variables: $($missing -join ', ')"
    Stop-Log
    exit 1
}
Write-Host "[✓] All required environment variables are set."
Stop-Log

# --- [ 05: Check Required Modules ] ---
Start-Log -label "05_prereq_checks"
if (-not (Get-Command Install-ADDSForest -ErrorAction SilentlyContinue)) {
    Write-Error "❌ 'Install-ADDSForest' command not found. Ensure AD DS role or RSAT is installed."
    Stop-Log
    exit 1
}
if (-not (Get-Command Add-DnsServerPrimaryZone -ErrorAction SilentlyContinue)) {
    Write-Error "❌ 'Add-DnsServerPrimaryZone' command not found. Ensure DNS Server tools are installed."
    Stop-Log
    exit 1
}
Write-Host "[✓] Required modules are available."
Stop-Log

# --- [ 06: Check for Existing Domain and DNS ] ---
Start-Log -label "06_existing_checks"
if (Get-ADDomain -ErrorAction SilentlyContinue) {
    Write-Warning "[!] An AD DS forest already exists. Skipping creation."
    Stop-Log
    exit 0
}

if (Get-DnsServerZone -Name $DomainName -ErrorAction SilentlyContinue) {
    Write-Host "[!] DNS zone '$DomainName' already exists. Skipping DNS creation."
} else {
    Write-Host "[✓] DNS zone '$DomainName' not found — will be created."
}
Stop-Log

# --- [ 07: Configure Static Network (Optional) ] ---
Start-Log -label "07_network_config"
try {
    . "$ScriptRoot\configure-network.ps1"
} catch {
    Write-Error "❌ Network configuration failed: $($_.Exception.Message)"
    Stop-Log
    exit 1
}
Stop-Log

# --- [ 08: Launch AD DS & DNS Setup ] ---
Start-Log -label "08_create_adds"
try {
    if (-not (Test-Path "$ScriptRoot\check-1")) {
        . "$ScriptRoot\create-tree.ps1"
        Write-Host "[✓] AD DS forest created successfully."
        New-Item -Path "$ScriptRoot\check-1" -ItemType File -Force | Out-Null
        Write-Host "[✓] Checkpoint created: check-1"
    } else {
        Write-Host "[!] Forest creation already completed (check-1 exists). Skipping."
    }
} catch {
    Write-Error "❌ Forest creation failed: $($_.Exception.Message)"
    Stop-Log
    exit 1
}
Stop-Log
