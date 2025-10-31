# Kubernetes Secret Generation Guide

## Overview

This directory contains scripts and templates for generating secure secrets for Kubernetes deployments.

## Files

- `02-secrets.yaml` - Template file with placeholder secrets (DO NOT use in production)
- `generate-secrets.sh` - Bash script for generating real secrets (Linux/Mac)
- `generate-secrets.ps1` - PowerShell script for generating real secrets (Windows)
- This README file

## Quick Start

### For Linux/Mac Users

```bash
# Make the script executable
chmod +x generate-secrets.sh

# Generate secrets for staging environment
./generate-secrets.sh staging

# Generate secrets for production environment
./generate-secrets.sh production
```

### For Windows Users

```powershell
# Generate secrets for staging environment
.\generate-secrets.ps1 staging

# Generate secrets for production environment
.\generate-secrets.ps1 production
```

## What Secrets Are Generated

The scripts automatically generate the following secrets in your Kubernetes cluster:

1. **postgres-credentials**
   - Database username
   - Database password (32 chars for staging, 48 chars for production)

2. **redis-credentials**
   - Redis password (32 chars for staging, 48 chars for production)

3. **jwt-secrets**
   - Staging: Simple JWT secret key
   - Production: RSA 4096-bit key pair for RS256 algorithm

4. **api-keys**
   - API key for Catalytic Computing platform
   - Webhook signing secret

5. **csrf-secret**
   - CSRF protection secret key

## Important Security Notes

### Before Running

1. Ensure you have `kubectl` installed and configured
2. Ensure you have access to the target Kubernetes cluster
3. For production, ensure you have `openssl` installed
4. Verify you're connected to the correct cluster: `kubectl cluster-info`

### After Running

1. **Backup Your Secrets**
   ```bash
   # Export all secrets to a file
   kubectl get secrets -n catalytic-staging -o yaml > secrets-backup-staging.yaml
   kubectl get secrets -n catalytic-production -o yaml > secrets-backup-production.yaml
   ```

2. **Store Backups Securely**
   - Encrypt the backup files
   - Store in a password manager or vault
   - Consider using external secret management (HashiCorp Vault, AWS Secrets Manager, etc.)

3. **Rotate Secrets Regularly**
   - Recommended: Every 90 days
   - Document rotation procedures
   - Test rotation in staging before production

### Viewing Secrets

```bash
# List all secrets in a namespace
kubectl get secrets -n catalytic-staging

# View a specific secret (base64 decoded)
kubectl get secret postgres-credentials -n catalytic-staging -o jsonpath='{.data.password}' | base64 -d

# View all data in a secret
kubectl get secret postgres-credentials -n catalytic-staging -o yaml
```

### Deleting and Regenerating Secrets

```bash
# Delete a specific secret
kubectl delete secret postgres-credentials -n catalytic-staging

# Delete all secrets (BE CAREFUL!)
kubectl delete secrets --all -n catalytic-staging

# Regenerate by running the script again
./generate-secrets.sh staging
```

## Manual Secret Creation

If you prefer to create secrets manually:

```bash
# PostgreSQL credentials
kubectl create secret generic postgres-credentials \
  --from-literal=username=catalytic_staging \
  --from-literal=password=$(openssl rand -base64 32) \
  -n catalytic-staging

# Redis credentials
kubectl create secret generic redis-credentials \
  --from-literal=password=$(openssl rand -base64 32) \
  -n catalytic-staging

# JWT secret (simple)
kubectl create secret generic jwt-secrets \
  --from-literal=jwt-secret=$(openssl rand -hex 32) \
  -n catalytic-staging

# API keys
kubectl create secret generic api-keys \
  --from-literal=catalytic-api-key=$(openssl rand -hex 32) \
  --from-literal=webhook-signing-secret=$(openssl rand -hex 32) \
  -n catalytic-staging

# CSRF secret
kubectl create secret generic csrf-secret \
  --from-literal=csrf-secret-key=$(openssl rand -hex 32) \
  -n catalytic-staging
```

## Production-Specific Requirements

### TLS Certificates

For production, you MUST configure TLS certificates. Two options:

#### Option 1: cert-manager (Recommended)

1. Install cert-manager in your cluster
2. Configure a ClusterIssuer (e.g., Let's Encrypt)
3. Add TLS annotation to your Ingress resource

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@catalytic-computing.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
```

#### Option 2: Manual Certificate

```bash
kubectl create secret tls catalytic-tls \
  --cert=path/to/tls.crt \
  --key=path/to/tls.key \
  -n catalytic-production
```

### JWT RSA Key Pair

Production deployments use RS256 algorithm with RSA key pairs:

```bash
# Generate RSA private key
openssl genrsa -out jwt-private.pem 4096

# Generate RSA public key
openssl rsa -in jwt-private.pem -pubout -out jwt-public.pem

# Create secret
kubectl create secret generic jwt-secrets \
  --from-file=jwt-private-key=jwt-private.pem \
  --from-file=jwt-public-key=jwt-public.pem \
  -n catalytic-production

# Clean up local key files
rm jwt-private.pem jwt-public.pem
```

## External Secret Management

For enterprise deployments, consider using external secret management:

### HashiCorp Vault

```bash
# Install Vault Agent Injector
helm repo add hashicorp https://helm.releases.hashicorp.com
helm install vault hashicorp/vault

# Configure Vault secrets
vault kv put secret/catalytic/staging/postgres \
  username=catalytic_staging \
  password=$(openssl rand -base64 32)
```

### AWS Secrets Manager

```bash
# Create secret in AWS
aws secretsmanager create-secret \
  --name catalytic/staging/postgres \
  --secret-string '{"username":"catalytic_staging","password":"..."}'

# Install External Secrets Operator
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets
```

## Troubleshooting

### Script Fails with "command not found"

- **Linux/Mac**: Install `openssl` via package manager
  ```bash
  # Ubuntu/Debian
  sudo apt-get install openssl

  # macOS
  brew install openssl
  ```

- **Windows**: Install OpenSSL or use Git Bash which includes it

### "Error from server (AlreadyExists)"

The secret already exists. Delete it first:
```bash
kubectl delete secret <secret-name> -n <namespace>
```

Or the script will update it using `--dry-run=client | kubectl apply -f -`

### Cannot connect to Kubernetes cluster

Verify your kubectl configuration:
```bash
kubectl cluster-info
kubectl config current-context
```

## Best Practices

1. Never commit secrets to version control
2. Use different secrets for each environment
3. Rotate secrets regularly (every 90 days)
4. Use external secret management for production
5. Enable audit logging for secret access
6. Implement RBAC to restrict secret access
7. Monitor secret usage and access patterns

## Additional Resources

- [Kubernetes Secrets Documentation](https://kubernetes.io/docs/concepts/configuration/secret/)
- [HashiCorp Vault](https://www.vaultproject.io/)
- [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/)
- [cert-manager](https://cert-manager.io/)
