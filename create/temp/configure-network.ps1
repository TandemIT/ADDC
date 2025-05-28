    $ipExists = Get-NetIPAddress -InterfaceAlias $Interface -IPAddress $IPAddress -ErrorAction SilentlyContinue
    if (-not $ipExists) {
        Write-Host "[+] Configuring interface '$Interface' with IP $IPAddress/$Prefix and gateway $Gateway"
        New-NetIPAddress -InterfaceAlias $Interface -IPAddress $IPAddress -PrefixLength $Prefix -DefaultGateway $Gateway
        Set-DnsClientServerAddress -InterfaceAlias $Interface -ServerAddresses $IPAddress
        Write-Host "[✓] Static IP configuration applied to $Interface."
    } else {
        Write-Host "[!] IP $IPAddress already configured on interface $Interface. Skipping."
    }