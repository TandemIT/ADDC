<#
    create-dns.ps1 - Creates the AD DS DNS Zone
#>

# --- [ Check if DNS was already created ] ---
if (Test-Path .\check-dns) {
    Write-Host "[!] DNS zone already created (check-dns exists). Skipping creation."
    return
}

# --- [ Create DNS Zone ] ---
try {
    Add-DnsServerPrimaryZone -Name $DomainName -ReplicationScope Forest -PassThru
    Write-Host "[+] DNS zone '$DomainName' created."

    # --- [ Mark completion checkpoint ] ---
    New-Item -Path .\check-dns -ItemType File -Force | Out-Null
    Write-Host "[✓] Created checkpoint file: check-dns"

} catch {
    Write-Warning "DNS zone may already exist or failed to create: $($_.Exception.Message)"
}
