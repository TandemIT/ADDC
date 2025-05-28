<#
.SYNOPSIS
    Unified Active Directory Domain Services (AD DS) Setup Script.

.DESCRIPTION
    Configures a Windows machine as an Active Directory Domain Controller,
    sets up DNS, configures network settings, and uses checkpoints for idempotency.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Paths & Constants ---
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogFolder = Join-Path $ScriptRoot 'logs'
$Checkpoints = @{
    Forest = Join-Path $ScriptRoot 'check-forest'
    DNS    = Join-Path $ScriptRoot 'check-dns'
    Net    = Join-Path $ScriptRoot 'check-network'
}
$EnvScript = Join-Path $ScriptRoot '.env'

# --- Logging ---
if (-not (Test-Path $LogFolder)) {
    New-Item -Path $LogFolder -ItemType Directory | Out-Null
}
function Start-Log ($Label) {
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $LogFile = Join-Path $LogFolder "$Label`_$timestamp.log"
    Start-Transcript -Path $LogFile -Force
    Write-Host "[📄] Logging started: $LogFile"
}
function Stop-Log {
    Stop-Transcript
    Write-Host "[📄] Logging stopped."
}

# --- Import environment variables from .env ---
function Import-DotEnv {
    param ([string]$Path = $EnvScript)
    if (-not (Test-Path $Path)) {
        throw ".env file not found at path: $Path"
    }
    # Using regex to parse KEY=VALUE, ignoring comments and blank lines
    Get-Content $Path | ForEach-Object {
        if ($_ -match '^\s*#' -or [string]::IsNullOrWhiteSpace($_)) { return }
        if ($_ -match '^\s*([^=]+?)\s*=\s*(.+)$') {
            [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process')
        }
    }
    Write-Host '[✓] Environment variables loaded.'
}

# --- Validate and initialize environment variables ---
function Initialize-Environment {
    Import-DotEnv

    # Required environment variables and their types
    $envVars = @{
        DOMAIN_NAME          = [string]
        NETBIOS_NAME         = [string]
        DC_NAME              = [string]
        OU_PATH              = [string]
        IP_ADDRESS           = [string]
        GATEWAY              = [string]
        PREFIX               = ''
        INTERFACE            = [string]
        SAFE_MODE_PASSWORD   = [securestring]
        DEFAULT_USER_PASSWORD= [securestring]
    }

    # Convert plain text passwords to SecureString or prompt
    function ConvertOrPrompt($varName) {
        $val = [Environment]::GetEnvironmentVariable($varName)
        if (-not $val) {
            return Read-Host "Enter value for $varName" -AsSecureString
        }
        if ($varName -match 'PASSWORD') {
            return ConvertTo-SecureString $val -AsPlainText -Force
        }
        return $val
    }

    foreach ($key in $envVars.Keys) {
        $value = ConvertOrPrompt $key
        if (-not $value) { throw "Missing required environment variable: $key" }
        Set-Variable -Name $key -Value $value -Scope Global
    }

    # Validate IP Address format
    if (-not [System.Net.IPAddress]::TryParse($IP_ADDRESS, [ref]$null)) {
        throw "Invalid IP_ADDRESS format: $IP_ADDRESS"
    }
    if (-not [System.Net.IPAddress]::TryParse($GATEWAY, [ref]$null)) {
        throw "Invalid GATEWAY format: $GATEWAY"
    }
    if ($PREFIX -lt 1 -or $PREFIX -gt 32) {
        throw "PREFIX must be between 1 and 32"
    }

    if ($DOMAIN_NAME -like '*.local') {
        Write-Warning "⚠️ Using '.local' domain is discouraged."
        $confirm = Read-Host "Proceed anyway? (yes/No)"
        if ($confirm.ToLower() -notin @('yes','y')) {
            throw "Aborting due to .local domain usage."
        }
    }
}

# --- Check for Administrator privileges ---
function Test-AdminPrivilege {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Script must be run as Administrator."
    }
    Write-Host '[✓] Administrator privileges confirmed.'
}

# --- Check required cmdlets for AD DS and DNS Server ---
function Test-RequiredModules {
    $commands = @(
        @{ Name = 'Install-ADDSForest'; Hint = 'AD DS role or RSAT tools needed' },
        @{ Name = 'Add-DnsServerPrimaryZone'; Hint = 'DNS Server tools needed' }
    )
    foreach ($cmd in $commands) {
        if (-not (Get-Command $cmd.Name -ErrorAction SilentlyContinue)) {
            throw "Required cmdlet '$($cmd.Name)' not found. Ensure $($cmd.Hint)."
        }
    }
    Write-Host '[✓] Required cmdlets are available.'
}

# --- Configure static network settings ---
function Set-NetworkConfiguration {
    param (
        [Parameter(Mandatory)][string]$Interface,
        [Parameter(Mandatory)][string]$IPAddress,
        [Parameter(Mandatory)][int]$Prefix,
        [Parameter(Mandatory)][string]$Gateway,
        [Parameter(Mandatory)][string]$CheckpointNet
    )

    if (Test-Path $CheckpointNet) {
        Write-Host '[!] Network already configured. Skipping.'
        return
    }

    $existingIP = Get-NetIPAddress -InterfaceAlias $Interface -IPAddress $IPAddress -ErrorAction SilentlyContinue
    if (-not $existingIP) {
        Write-Host "[+] Setting static IP $IPAddress/$Prefix on interface $Interface..."
        try {
            # Remove any DHCP IPs first (optional, depends on your environment)
            $dhcpIPs = Get-NetIPAddress -InterfaceAlias $Interface -AddressFamily IPv4 -PrefixOrigin Dhcp -ErrorAction SilentlyContinue
            foreach ($ip in $dhcpIPs) {
                Remove-NetIPAddress -InterfaceAlias $Interface -IPAddress $ip.IPAddress -Confirm:$false
            }
            New-NetIPAddress -InterfaceAlias $Interface -IPAddress $IPAddress -PrefixLength $Prefix -DefaultGateway $Gateway -ErrorAction Stop
            Set-DnsClientServerAddress -InterfaceAlias $Interface -ServerAddresses $IPAddress -ErrorAction Stop
            Write-Host '[✓] Network configuration applied.'
        } catch {
            throw "Failed to configure network: $($_.Exception.Message)"
        }
    } else {
        Write-Host '[!] IP address already assigned. Skipping network configuration.'
    }

    # Ensure checkpoint directory exists
    $checkpointDir = Split-Path $CheckpointNet
    if (-not (Test-Path $checkpointDir)) {
        New-Item -Path $checkpointDir -ItemType Directory | Out-Null
    }
    # Create checkpoint file
    New-Item -Path $CheckpointNet -ItemType File -Force | Out-Null
}

# --- Create DNS zone if it doesn't exist ---
function New-DnsZoneIfMissing {
    param (
        [Parameter(Mandatory)][string]$DomainName,
        [Parameter(Mandatory)][string]$CheckpointDNS
    )
    if (Test-Path $CheckpointDNS) {
        Write-Host '[!] DNS zone already created. Skipping.'
        return
    }

    try {
        # Check if zone exists to avoid error
        $existingZone = Get-DnsServerZone -Name $DomainName -ErrorAction SilentlyContinue
        if (-not $existingZone) {
            Add-DnsServerPrimaryZone -Name $DomainName -ReplicationScope Forest -PassThru
            Write-Host "[✓] DNS zone '$DomainName' created."
        } else {
            Write-Host "[!] DNS zone '$DomainName' already exists."
        }
        New-Item -Path $CheckpointDNS -ItemType File -Force | Out-Null
    } catch {
        throw "DNS zone creation failed: $($_.Exception.Message)"
    }
}

# --- Create AD DS Forest ---
function New-AdForestIfMissing {
    param (
        [Parameter(Mandatory)][string]$DomainName,
        [Parameter(Mandatory)][string]$NetbiosName,
        [Parameter(Mandatory)][SecureString]$SafeModePassword,
        [Parameter(Mandatory)][string]$CheckpointForest,
        [Parameter(Mandatory)][string]$CheckpointDNS
    )

    if (Test-Path $CheckpointForest) {
        Write-Host '[!] Forest already exists. Skipping.'
        return
    }

    try {
        Write-Host "[+] Creating AD DS Forest '$DomainName'..."
        Install-ADDSForest -DomainName $DomainName `
            -DomainNetbiosName $NetbiosName `
            -SafeModeAdministratorPassword $SafeModePassword `
            -InstallDNS `
            -NoRebootOnCompletion `
            -Force

        # Wait for services to settle, can be adjusted as needed
        Start-Sleep -Seconds 30

        New-DnsZoneIfMissing -DomainName $DomainName -CheckpointDNS $CheckpointDNS

        # Create checkpoint
        New-Item -Path $CheckpointForest -ItemType File -Force | Out-Null
        Write-Host '[✓] Forest and DNS setup completed.'
    } catch {
        throw "Forest creation failed: $($_.Exception.Message)"
    }
}

# --- Main Execution ---

Start-Log -Label 'ad_ds_setup'

try {
    Test-AdminPrivilege
    Initialize-Environment
    Test-RequiredModules
    Set-NetworkConfiguration -Interface $INTERFACE -IPAddress $IP_ADDRESS -Prefix $PREFIX -Gateway $GATEWAY -CheckpointNet $Checkpoints.Net
    New-AdForestIfMissing -DomainName $DOMAIN_NAME -NetbiosName $NETBIOS_NAME -SafeModePassword $SAFE_MODE_PASSWORD -CheckpointForest $Checkpoints.Forest -CheckpointDNS $Checkpoints.DNS
    Write-Host "`n[✅] AD DS setup complete!"
} catch {
    Write-Error "❌ $_"
    exit 1
} finally {
    Stop-Log
}
