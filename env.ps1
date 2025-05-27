

# # Initial load from environment
$DomainName = $env:DOMAIN_NAME
$NetbiosName = $env:NETBIOS_NAME
$SafeModePassword = if ($env:SAFE_MODE_PASSWORD) { ConvertTo-SecureString $env:SAFE_MODE_PASSWORD -AsPlainText -Force } else { $null }
$DCName = $env:DC_NAME
$OUPath = $env:OU_PATH
$DefaultUserPassword = if ($env:DEFAULT_USER_PASSWORD) { ConvertTo-SecureString $env:DEFAULT_USER_PASSWORD -AsPlainText -Force } else { $null }
$IPAddress = $env:IP_ADDRESS
$Gateway = $env:GATEWAY
$Prefix = $env:PREFIX
$Interface = $env:INTERFACE

# List of variables to check and prompt for if missing
$variableNames = @(
    "DomainName", "NetbiosName", "SafeModePassword", "DCName",
    "OUPath", "DefaultUserPassword", "IPAddress", "Gateway", "Prefix", "Interface"
)

foreach ($varName in $variableNames) {
    $value = Get-Variable -Name $varName -ValueOnly -ErrorAction SilentlyContinue
    if (-not $value) {
        if ($varName -like "*Password") {
            $secureVal = Read-Host -AsSecureString "Enter value for $varName"
            Set-Variable -Name $varName -Value $secureVal
        } else {
            $inputValue = Read-Host "Please enter the value for $varName"
            Set-Variable -Name $varName -Value $inputValue
        }
    }
}

if ($Prefix -isnot [int]) {
    [int]$Prefix = [int]$Prefix
}

# Validate none are empty/null
foreach ($varName in $variableNames) {
    $value = Get-Variable -Name $varName -ValueOnly
    if (-not $value) {
        Write-Error "Variable $varName is not set or empty."
        exit 1
    }
}

# Warn about .local
if ($DomainName -like "*.local") {
    Write-Warning "Domain name ends with .local — this can cause issues in production."
    $confirmation = Read-Host "Proceed anyway? (yes/No)"
    if ($confirmation.ToLower() -ne "yes" -and $confirmation.ToLower() -ne "y") {
        Write-Host "Exiting script."
        exit 1
    }
}
