# Check for SSH public keys
$sshDir = "$env:USERPROFILE\.ssh"
$keyFiles = @("id_rsa.pub", "id_ed25519.pub", "id_ecdsa.pub")

foreach ($keyFile in $keyFiles) {
    $fullPath = Join-Path $sshDir $keyFile
    if (Test-Path $fullPath) {
        Write-Host "Found SSH public key: $keyFile"
        Write-Host "="*50
        Get-Content $fullPath
        Write-Host "="*50
        break
    }
}

if (-not $foundKey) {
    Write-Host "No SSH public keys found in $sshDir"
    Write-Host "Available files in .ssh directory:"
    if (Test-Path $sshDir) {
        Get-ChildItem $sshDir | Select-Object Name
    } else {
        Write-Host ".ssh directory does not exist"
    }
}