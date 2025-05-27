<#
    create-tree.ps1 - Creates the AD DS Forest and triggers DNS zone creation
#>

# --- [ Checkpoint: Prevent re-creation ] ---
if (Test-Path .\check-tree) {
    Write-Host "[!] AD DS Forest already created (check-tree exists). Skipping forest setup."
    Stop-Transcript
    return
}

# --- [ Create the AD DS Forest ] ---
try {
    Install-ADDSForest -DomainName $DomainName `
        -DomainNetbiosName $NetbiosName `
        -SafeModeAdministratorPassword $SafeModePassword `
        -InstallDNS `
        -NoRebootOnCompletion `
        -Force

    if (-not $?) {
        throw "Install-ADDSForest failed."
    }

    Write-Host "[+] AD DS Forest created successfully."

    # --- [ Wait for system to settle ] ---
    Write-Host "Waiting for AD DS installation to settle..."
    Start-Sleep -Seconds 30

    # --- [ Create DNS Zone ] ---
    . .\create-dns.ps1
    if (-not $?) {
        throw "create-dns.ps1 failed. Ensure it exists and is correctly configured."
    }

    # --- [ Mark Forest Creation Checkpoint ] ---
    New-Item -Path .\check-tree -ItemType File -Force | Out-Null
    Write-Host "[✓] Created checkpoint file: check-tree"

} catch {
    Write-Error "Error during forest creation: $($_.Exception.Message)"
    Stop-Transcript
    exit 1
}

