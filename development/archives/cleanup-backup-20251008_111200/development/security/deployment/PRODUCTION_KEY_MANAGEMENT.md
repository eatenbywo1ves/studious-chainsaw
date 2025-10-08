# Production Key Management Plan

**Environment:** Production
**Date:** 2025-10-01
**Classification:** CONFIDENTIAL
**Owner:** Security Team

---

## Executive Summary

This document outlines the comprehensive key management strategy for production deployment, including Hardware Security Module (HSM) integration, key lifecycle management, rotation procedures, and disaster recovery protocols.

---

## 1. Key Management Architecture

### 1.1 Key Hierarchy

```
┌─────────────────────────────────────────┐
│  Root Key (HSM Master Key)              │
│  - Stored in HSM                        │
│  - Never exported                       │
│  - Multi-person access control          │
└──────────────┬──────────────────────────┘
               │
       ┌───────┴───────┐
       │               │
┌──────▼────────┐ ┌───▼──────────────────┐
│ JWT Signing   │ │ Data Encryption      │
│ Key (RSA)     │ │ Key (AES-256)        │
│ - 2048/4096   │ │ - Database           │
│ - In HSM      │ │ - API payloads       │
└───────────────┘ └──────────────────────┘
```

### 1.2 HSM Integration Options

#### Option A: Cloud HSM (Recommended for Cloud Deployments)

**AWS CloudHSM**
- FIPS 140-2 Level 3 validated
- Dedicated hardware in AWS VPC
- Tamper-resistant, single-tenant
- Cost: ~$1.60/hour + $0.00019/API call

**Azure Dedicated HSM**
- FIPS 140-2 Level 3 validated
- Thales Luna Network HSM 7
- Direct network connection
- Cost: ~$4/hour

**Google Cloud HSM**
- FIPS 140-2 Level 3 validated
- Managed service
- Automatic key replication
- Cost: Based on key operations

#### Option B: On-Premise HSM

**Thales Luna HSM**
- FIPS 140-2 Level 3
- Full control
- One-time cost: $15,000-$30,000

**Utimaco HSM**
- FIPS 140-2 Level 4 (highest)
- High performance
- One-time cost: $20,000-$40,000

#### Option C: Key Management Service (For Smaller Deployments)

**AWS KMS**
- FIPS 140-2 Level 2 (software)
- Managed service
- Cost: $1/key/month + API calls
- Good balance of security and cost

**HashiCorp Vault**
- Software-based
- Open source option available
- Can integrate with HSM
- License: $0.50/hour for Enterprise

---

## 2. Production Key Generation Procedures

### 2.1 Pre-Generation Checklist

- [ ] HSM commissioned and tested
- [ ] Access control policies configured
- [ ] Multi-person authorization enabled
- [ ] Backup HSM configured
- [ ] Key ceremony documented
- [ ] Witnesses identified (minimum 3)
- [ ] Audit logging enabled
- [ ] Video recording equipment ready

### 2.2 Key Ceremony Procedures

#### RSA JWT Signing Keys (4096-bit for Production)

```bash
# DO NOT RUN - This is for HSM administrator only
# Key generation happens INSIDE HSM

# AWS CloudHSM example:
$ /opt/cloudhsm/bin/key_mgmt_util
KeyMgmtUtil> loginHSM -u CU -p <password>
KeyMgmtUtil> genSymKey -t 31 -s 32 -l jwt-production-master
KeyMgmtUtil> genRSAKeyPair -m 4096 -e 65537 -l jwt-production-signing

# Azure Key Vault example:
az keyvault key create \
  --vault-name production-keyvault \
  --name jwt-production-signing \
  --kty RSA \
  --size 4096 \
  --protection hsm \
  --ops sign verify

# Google Cloud KMS example:
gcloud kms keys create jwt-production-signing \
  --location global \
  --keyring production-keyring \
  --purpose asymmetric-signing \
  --default-algorithm rsa-sign-pkcs1-4096-sha256 \
  --protection-level hsm
```

#### Data Encryption Keys

```bash
# AES-256 keys for data encryption
# Generated and stored in HSM

# AWS KMS:
aws kms create-key \
  --description "Production API encryption key" \
  --key-usage ENCRYPT_DECRYPT \
  --origin AWS_KMS

# Azure Key Vault:
az keyvault key create \
  --vault-name production-keyvault \
  --name api-encryption-production \
  --kty oct-HSM \
  --size 256

# Google Cloud KMS:
gcloud kms keys create api-encryption-production \
  --location global \
  --keyring production-keyring \
  --purpose encryption
```

### 2.3 Key Ceremony Documentation Template

```
KEY GENERATION CEREMONY RECORD

Date: _______________
Time: _______________
Location: _______________

Purpose: Generation of Production JWT Signing Keys

Participants:
1. Security Officer: _____________________ (Signature)
2. Operations Lead: ______________________ (Signature)
3. Compliance Officer: ___________________ (Signature)
4. Witness 1: ___________________________ (Signature)
5. Witness 2: ___________________________ (Signature)

HSM Details:
- HSM Model: _______________________
- Serial Number: ___________________
- Firmware Version: ________________
- FIPS Level: ______________________

Keys Generated:
- Key ID: __________________________
- Key Type: RSA-4096
- Purpose: JWT signing
- Algorithm: RS256
- Created: ________________________
- Location: HSM Slot _______________

Verification:
- [ ] Key pair generated successfully
- [ ] Public key exported and verified
- [ ] Private key confirmed non-exportable
- [ ] Key attributes verified
- [ ] Audit log reviewed
- [ ] Backup procedure initiated
- [ ] Access control verified

Video Recording: ___________________
Audit Log Reference: _______________

Post-Ceremony Actions:
- [ ] Keys registered in key inventory
- [ ] Documentation updated
- [ ] Backup verified
- [ ] Rotation schedule set
- [ ] Monitoring configured

Approval:
CISO: ______________________ Date: ________
```

---

## 3. Key Lifecycle Management

### 3.1 Key States

```
   ┌─────────────┐
   │  Pre-Active │
   │  (Generated)│
   └──────┬──────┘
          │
   ┌──────▼──────┐
   │   Active    │◄─┐
   │  (In Use)   │  │
   └──────┬──────┘  │
          │         │
   ┌──────▼──────┐  │
   │  Suspended  │──┘
   │  (Temp)     │
   └──────┬──────┘
          │
   ┌──────▼──────┐
   │ Deactivated │
   │ (Rotated)   │
   └──────┬──────┘
          │
   ┌──────▼──────┐
   │  Destroyed  │
   │  (Purged)   │
   └─────────────┘
```

### 3.2 Key Rotation Schedule

| Key Type | Rotation Frequency | Maximum Lifetime |
|----------|-------------------|------------------|
| JWT Signing Key | 90 days | 180 days |
| API Encryption Key | 365 days | 730 days |
| Database Encryption | 365 days | 730 days |
| Session Secrets | 30 days | 90 days |
| CSRF Tokens | 7 days | 30 days |

### 3.3 Automated Key Rotation Script

```bash
#!/bin/bash
# automated-key-rotation.sh
# Run via cron: 0 0 1 * * (monthly)

set -euo pipefail

# Configuration
ENV="production"
HSM_PROFILE="production-hsm"
NOTIFICATION_EMAIL="security@company.com"

# Check if rotation is due
check_rotation_due() {
    KEY_AGE=$(aws kms describe-key --key-id $KEY_ID --query 'KeyMetadata.CreationDate' --output text)
    # Calculate age and compare to rotation schedule
    # Return 0 if rotation needed, 1 otherwise
}

# Rotate JWT signing key
rotate_jwt_key() {
    echo "Starting JWT key rotation..."

    # 1. Generate new key
    NEW_KEY_ID=$(aws kms create-key --description "JWT Production Signing Key $(date +%Y%m%d)" --query 'KeyMetadata.KeyId' --output text)

    # 2. Export public key
    aws kms get-public-key --key-id $NEW_KEY_ID --output text > /secure/jwt_production_public_new.pem

    # 3. Update application configuration (gradual rollout)
    kubectl set env deployment/api JWT_PUBLIC_KEY_ID_NEW=$NEW_KEY_ID

    # 4. Wait for verification period (7 days)
    # During this time, app accepts both old and new keys

    # 5. Make new key primary
    kubectl set env deployment/api JWT_PRIVATE_KEY_ID=$NEW_KEY_ID

    # 6. After grace period (30 days), deactivate old key
    # aws kms disable-key --key-id $OLD_KEY_ID

    echo "JWT key rotation complete: $NEW_KEY_ID"
}

# Main execution
if check_rotation_due; then
    rotate_jwt_key

    # Send notification
    echo "Key rotation completed at $(date)" | mail -s "Key Rotation Complete" $NOTIFICATION_EMAIL
fi
```

---

## 4. Access Control

### 4.1 Multi-Person Authorization

**Quorum Requirements:**
- Key generation: 3 of 5 custodians
- Key rotation: 2 of 5 custodians
- Key destruction: 3 of 5 custodians
- Emergency access: 2 of 3 emergency contacts

**Key Custodians (Production):**
1. CISO
2. VP Engineering
3. Security Lead
4. Platform Lead
5. Compliance Officer

### 4.2 Access Logging

All key operations must be logged:
- Who accessed the key
- When access occurred
- What operation was performed
- From which system/IP
- Success or failure
- Any errors

**Log Retention:** 7 years (compliance requirement)

### 4.3 RBAC Policies

```yaml
# AWS IAM Policy Example
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowJWTSigning",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ACCOUNT:role/api-server-production"
      },
      "Action": [
        "kms:Sign",
        "kms:GetPublicKey"
      ],
      "Resource": "arn:aws:kms:REGION:ACCOUNT:key/JWT_KEY_ID"
    },
    {
      "Sid": "DenyKeyExport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "kms:GetKeyMaterial",
        "kms:ExportKey"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## 5. Backup and Recovery

### 5.1 Key Backup Strategy

**Primary HSM:** Active keys, all operations
**Secondary HSM:** Synchronized replica, hot standby
**Offline Backup:** Encrypted key material in secure facility

### 5.2 Backup Procedures

```bash
# Cloud HSM backup (automated daily)
aws cloudhsm create-backup \
  --cluster-id cluster-xyz123 \
  --description "Daily production backup $(date +%Y%m%d)"

# Verify backup
aws cloudhsm describe-backups \
  --filters clusterIds=cluster-xyz123 \
  --query 'Backups[0].BackupState'

# Test restore (quarterly in DR environment)
aws cloudhsm restore-backup \
  --backup-id backup-abc456 \
  --cluster-id cluster-dr-xyz789
```

### 5.3 Disaster Recovery

**Recovery Time Objective (RTO):** 4 hours
**Recovery Point Objective (RPO):** 1 hour

**Scenarios:**

1. **HSM Failure**
   - Automatic failover to secondary HSM
   - RTO: 5 minutes
   - No data loss

2. **Regional Outage**
   - Restore from backup in different region
   - RTO: 2 hours
   - RPO: 1 hour

3. **Complete Key Loss**
   - Restore from offline backup
   - Generate new keys if necessary
   - RTO: 4 hours
   - Coordinate with certificate authorities

### 5.4 Key Recovery Testing

**Frequency:** Quarterly
**Procedure:**
1. Schedule DR drill
2. Simulate key loss in test environment
3. Restore keys from backup
4. Verify application functionality
5. Document time and any issues
6. Update procedures as needed

---

## 6. Integration with Application

### 6.1 Application Configuration

```python
# production_config.py
# DO NOT hardcode - use environment variables or secrets manager

import os
from security.application.jwt_security import JWTSecurityManager, SecurityLevel

# Get key IDs from environment
JWT_KEY_ID = os.getenv('JWT_PRIVATE_KEY_ID')
API_ENCRYPTION_KEY_ID = os.getenv('API_ENCRYPTION_KEY_ID')

# Initialize with HSM backend
jwt_manager = JWTSecurityManager(
    private_key_id=JWT_KEY_ID,  # HSM key ID, not file path
    public_key_id=JWT_KEY_ID,   # Same key for asymmetric
    hsm_provider='aws',          # 'aws', 'azure', 'gcp', 'thales'
    security_level=SecurityLevel.STRICT,
    access_token_expire_minutes=15,
    refresh_token_expire_days=7,
    enable_audit_logging=True
)
```

### 6.2 HSM Integration Code Example

```python
# hsm_integration.py
import boto3
from typing import Dict, Any

class HSMKeyManager:
    """HSM integration for production keys"""

    def __init__(self, provider: str = 'aws'):
        self.provider = provider
        if provider == 'aws':
            self.kms_client = boto3.client('kms')
        elif provider == 'azure':
            from azure.keyvault.keys.crypto import CryptographyClient
            self.crypto_client = CryptographyClient
        # Add other providers as needed

    def sign_jwt(self, key_id: str, message: bytes) -> bytes:
        """Sign JWT using HSM key"""
        if self.provider == 'aws':
            response = self.kms_client.sign(
                KeyId=key_id,
                Message=message,
                MessageType='RAW',
                SigningAlgorithm='RSASSA_PKCS1_V1_5_SHA_256'
            )
            return response['Signature']

    def verify_signature(self, key_id: str, message: bytes, signature: bytes) -> bool:
        """Verify signature using HSM key"""
        if self.provider == 'aws':
            try:
                response = self.kms_client.verify(
                    KeyId=key_id,
                    Message=message,
                    MessageType='RAW',
                    Signature=signature,
                    SigningAlgorithm='RSASSA_PKCS1_V1_5_SHA_256'
                )
                return response['SignatureValid']
            except Exception:
                return False

    def encrypt(self, key_id: str, plaintext: bytes) -> Dict[str, Any]:
        """Encrypt data using HSM key"""
        if self.provider == 'aws':
            response = self.kms_client.encrypt(
                KeyId=key_id,
                Plaintext=plaintext
            )
            return {
                'ciphertext': response['CiphertextBlob'],
                'key_id': response['KeyId']
            }

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt data using HSM key"""
        if self.provider == 'aws':
            response = self.kms_client.decrypt(
                CiphertextBlob=ciphertext
            )
            return response['Plaintext']
```

---

## 7. Compliance and Auditing

### 7.1 Compliance Requirements

- **PCI DSS:** Key rotation every 90 days
- **SOC 2:** Audit logs retained 7 years
- **GDPR:** Encryption of personal data
- **HIPAA:** FIPS 140-2 Level 2 minimum

### 7.2 Audit Trail

All key operations logged to:
- CloudWatch Logs (AWS)
- Azure Monitor (Azure)
- Cloud Logging (GCP)
- SIEM (Splunk, ELK)

**Audit Events:**
- Key creation
- Key rotation
- Key access (sign/verify operations)
- Key permission changes
- Failed access attempts
- Key state changes

### 7.3 Annual Security Review

**Checklist:**
- [ ] Review all key custodians
- [ ] Verify access controls
- [ ] Test key recovery procedures
- [ ] Review rotation schedule compliance
- [ ] Audit key usage patterns
- [ ] Check for unauthorized access
- [ ] Verify backup integrity
- [ ] Review and update procedures
- [ ] Compliance assessment
- [ ] Security awareness training

---

## 8. Cost Analysis

### 8.1 AWS CloudHSM (Recommended)

```
Monthly Costs (Estimated):
- CloudHSM: $1.60/hour × 24 × 30 = $1,152
- Backup HSM: $1,152
- API Calls: ~1M/month × $0.00019 = $190
- Data Transfer: $50
- Total: ~$2,544/month ($30,528/year)

Benefits:
- FIPS 140-2 Level 3
- Full control
- No shared tenancy
- Direct integration
```

### 8.2 AWS KMS (Alternative)

```
Monthly Costs (Estimated):
- Customer master keys: 3 × $1 = $3
- API calls: 1M × $0.03/10k = $30
- Total: ~$33/month ($396/year)

Limitations:
- FIPS 140-2 Level 2 (software)
- Shared infrastructure
- Rate limits
```

### 8.3 Cost-Benefit Analysis

For production with high security requirements:
- **HSM:** Higher cost, but necessary for compliance
- **KMS:** Lower cost, acceptable for less critical systems

**Recommendation:** CloudHSM for production, KMS for staging/development

---

## 9. Implementation Roadmap

### Phase 1: HSM Provisioning (Week 1-2)
- [ ] Select HSM provider
- [ ] Provision HSM instances
- [ ] Configure network access
- [ ] Set up backup HSM
- [ ] Configure access controls

### Phase 2: Key Generation (Week 3)
- [ ] Schedule key ceremony
- [ ] Generate production keys
- [ ] Document key IDs
- [ ] Configure monitoring
- [ ] Test key operations

### Phase 3: Application Integration (Week 4-5)
- [ ] Update application code
- [ ] Configure HSM integration
- [ ] Test in staging environment
- [ ] Performance testing
- [ ] Security testing

### Phase 4: Deployment (Week 6)
- [ ] Production deployment
- [ ] Monitoring verification
- [ ] Key rotation test
- [ ] Disaster recovery drill
- [ ] Final security audit

---

## 10. Emergency Procedures

### 10.1 Key Compromise

**Immediate Actions:**
1. Revoke compromised key
2. Generate new keys
3. Force re-authentication of all users
4. Notify security team
5. Begin incident investigation

### 10.2 HSM Failure

**Immediate Actions:**
1. Verify secondary HSM status
2. Failover to secondary if needed
3. Notify HSM vendor
4. Begin restore procedure if both failed
5. Communicate status to stakeholders

### 10.3 Contact Information

**Emergency Contacts (24/7):**
- Security On-Call: +1-XXX-XXX-XXXX
- HSM Vendor Support: +1-XXX-XXX-XXXX
- Cloud Provider Support: Enterprise Support Portal

---

## Appendix A: Key Inventory

| Key ID | Type | Purpose | Created | Expires | Status | Location |
|--------|------|---------|---------|---------|--------|----------|
| TBD | RSA-4096 | JWT Signing | TBD | TBD | Pending | HSM Slot 1 |
| TBD | AES-256 | API Encryption | TBD | TBD | Pending | HSM Slot 2 |
| TBD | AES-256 | DB Encryption | TBD | TBD | Pending | HSM Slot 3 |

---

## Appendix B: References

- NIST SP 800-57: Key Management Recommendations
- FIPS 140-2: Security Requirements for Cryptographic Modules
- AWS CloudHSM Documentation
- Azure Key Vault Best Practices
- Google Cloud KMS Documentation

---

**Document Control:**
- Version: 1.0
- Last Updated: 2025-10-01
- Next Review: 2026-01-01
- Classification: CONFIDENTIAL
- Approver: CISO
