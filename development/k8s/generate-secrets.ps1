# ============================================================================
# Kubernetes Secret Generation Script (PowerShell)
# ============================================================================
# This script generates secure secrets for Kubernetes deployment
# Run this script BEFORE deploying to staging or production
#
# Usage:
#   .\generate-secrets.ps1 staging   # Generate secrets for staging
#   .\generate-secrets.ps1 production # Generate secrets for production
# ============================================================================

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("staging", "production")]
    [string]$Environment = "staging"
)

$ErrorActionPreference = "Stop"

$Namespace = "catalytic-$Environment"

Write-Host "============================================" -ForegroundColor Green
Write-Host "Kubernetes Secret Generation" -ForegroundColor Green
Write-Host "Environment: $Environment" -ForegroundColor Green
Write-Host "Namespace: $Namespace" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host

# Function to generate random password
function Get-RandomPassword {
    param([int]$Length = 32)
    $bytes = New-Object byte[] $Length
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return [Convert]::ToBase64String($bytes)
}

# Function to generate hex string
function Get-RandomHex {
    param([int]$Length = 32)
    $bytes = New-Object byte[] $Length
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return ($bytes | ForEach-Object { $_.ToString("x2") }) -join ''
}

# Check if namespace exists
$namespaceExists = kubectl get namespace $Namespace 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Namespace $Namespace does not exist. Creating it..." -ForegroundColor Yellow
    kubectl create namespace $Namespace
}

# ============================================================================
# 1. Generate PostgreSQL Credentials
# ============================================================================
Write-Host "1. Generating PostgreSQL credentials..." -ForegroundColor Yellow

if ($Environment -eq "production") {
    $dbPassword = Get-RandomPassword -Length 48
    $dbUser = "catalytic_prod"
} else {
    $dbPassword = Get-RandomPassword -Length 32
    $dbUser = "catalytic_staging"
}

kubectl create secret generic postgres-credentials `
    --from-literal=username=$dbUser `
    --from-literal=password=$dbPassword `
    --namespace=$Namespace `
    --dry-run=client -o yaml | kubectl apply -f -

if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ PostgreSQL credentials created" -ForegroundColor Green
    Write-Host "  Username: $dbUser"
    Write-Host "  Password: (saved to Kubernetes secret)"
    Write-Host
}

# ============================================================================
# 2. Generate Redis Credentials
# ============================================================================
Write-Host "2. Generating Redis credentials..." -ForegroundColor Yellow

if ($Environment -eq "production") {
    $redisPassword = Get-RandomPassword -Length 48
} else {
    $redisPassword = Get-RandomPassword -Length 32
}

kubectl create secret generic redis-credentials `
    --from-literal=password=$redisPassword `
    --namespace=$Namespace `
    --dry-run=client -o yaml | kubectl apply -f -

if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Redis credentials created" -ForegroundColor Green
    Write-Host "  Password: (saved to Kubernetes secret)"
    Write-Host
}

# ============================================================================
# 3. Generate JWT Secrets
# ============================================================================
Write-Host "3. Generating JWT secrets..." -ForegroundColor Yellow

if ($Environment -eq "production") {
    Write-Host "For production, you should use RSA key pairs (RS256 algorithm)." -ForegroundColor Cyan
    Write-Host "Generating RSA key pair..." -ForegroundColor Cyan

    # Create temporary directory for keys
    $tempDir = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ([System.IO.Path]::GetRandomFileName()))

    try {
        $privateKeyPath = Join-Path $tempDir "jwt-private.pem"
        $publicKeyPath = Join-Path $tempDir "jwt-public.pem"

        # Generate RSA private key
        openssl genrsa -out $privateKeyPath 4096

        # Generate RSA public key from private key
        openssl rsa -in $privateKeyPath -pubout -out $publicKeyPath

        # Create secret with both keys
        kubectl create secret generic jwt-secrets `
            --from-file=jwt-private-key=$privateKeyPath `
            --from-file=jwt-public-key=$publicKeyPath `
            --namespace=$Namespace `
            --dry-run=client -o yaml | kubectl apply -f -

        if ($LASTEXITCODE -eq 0) {
            Write-Host "✓ JWT RSA key pair created" -ForegroundColor Green
        }
    } finally {
        # Clean up temporary files
        Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
    }
} else {
    # For staging, use simple secret key
    $jwtSecret = Get-RandomHex -Length 32

    kubectl create secret generic jwt-secrets `
        --from-literal=jwt-secret=$jwtSecret `
        --namespace=$Namespace `
        --dry-run=client -o yaml | kubectl apply -f -

    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ JWT secret created" -ForegroundColor Green
    }
}
Write-Host

# ============================================================================
# 4. Generate API Keys and Webhook Secrets
# ============================================================================
Write-Host "4. Generating API keys and webhook secrets..." -ForegroundColor Yellow

if ($Environment -eq "production") {
    $apiKey = Get-RandomHex -Length 48
    $webhookSecret = Get-RandomHex -Length 48
} else {
    $apiKey = Get-RandomHex -Length 32
    $webhookSecret = Get-RandomHex -Length 32
}

kubectl create secret generic api-keys `
    --from-literal=catalytic-api-key=$apiKey `
    --from-literal=webhook-signing-secret=$webhookSecret `
    --namespace=$Namespace `
    --dry-run=client -o yaml | kubectl apply -f -

if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ API keys created" -ForegroundColor Green
    Write-Host
}

# ============================================================================
# 5. Generate CSRF Secret
# ============================================================================
Write-Host "5. Generating CSRF secret..." -ForegroundColor Yellow

if ($Environment -eq "production") {
    $csrfSecret = Get-RandomHex -Length 48
} else {
    $csrfSecret = Get-RandomHex -Length 32
}

kubectl create secret generic csrf-secret `
    --from-literal=csrf-secret-key=$csrfSecret `
    --namespace=$Namespace `
    --dry-run=client -o yaml | kubectl apply -f -

if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ CSRF secret created" -ForegroundColor Green
    Write-Host
}

# ============================================================================
# Summary
# ============================================================================
Write-Host "============================================" -ForegroundColor Green
Write-Host "Secret Generation Complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host
Write-Host "The following secrets were created in namespace '$Namespace':"
Write-Host "  1. postgres-credentials"
Write-Host "  2. redis-credentials"
Write-Host "  3. jwt-secrets"
Write-Host "  4. api-keys"
Write-Host "  5. csrf-secret"
Write-Host
Write-Host "IMPORTANT SECURITY NOTES:" -ForegroundColor Yellow
Write-Host "  - These secrets are stored ONLY in Kubernetes"
Write-Host "  - Backup your secrets using: kubectl get secrets -n $Namespace -o yaml > secrets-backup-$Environment.yaml"
Write-Host "  - Store backups securely (encrypted, in a password manager, or vault)"
Write-Host "  - Consider using external secret management (Vault, AWS Secrets Manager, etc.)"
Write-Host "  - Rotate secrets regularly (every 90 days recommended)"
Write-Host
Write-Host "To view created secrets:"
Write-Host "  kubectl get secrets -n $Namespace"
Write-Host
Write-Host "To view a specific secret (base64 decoded):"
Write-Host "  kubectl get secret postgres-credentials -n $Namespace -o jsonpath='{.data.password}' | base64 -d"
Write-Host

# ============================================================================
# Optional: Create TLS certificate secret for production
# ============================================================================
if ($Environment -eq "production") {
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host "TLS Certificate Setup" -ForegroundColor Yellow
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host
    Write-Host "For production, you need to create a TLS certificate secret."
    Write-Host
    Write-Host "Option 1: Use cert-manager (recommended):"
    Write-Host "  - Install cert-manager in your cluster"
    Write-Host "  - Configure a ClusterIssuer (Let's Encrypt, etc.)"
    Write-Host "  - Add TLS annotation to your Ingress resource"
    Write-Host
    Write-Host "Option 2: Manual certificate:"
    Write-Host "  kubectl create secret tls catalytic-tls \"
    Write-Host "    --cert=path/to/tls.crt \"
    Write-Host "    --key=path/to/tls.key \"
    Write-Host "    -n $Namespace"
    Write-Host
}

Write-Host "Done!" -ForegroundColor Green
