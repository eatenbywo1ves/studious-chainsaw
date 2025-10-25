---
name: Data Poisoning Tester
description: Automated testing for training data poisoning attacks (OWASP ML02, LLM03, MITRE AML.T0020). Tests for label flipping, backdoor insertion, feature manipulation, and availability attacks. Use when assessing ML training pipeline security, testing for backdoor vulnerabilities, or evaluating data integrity controls.
allowed-tools:
  - Bash
  - Read
  - Write
---

# Data Poisoning Security Agent

## Purpose

Detect and validate data poisoning vulnerabilities in ML training pipelines through systematic testing of label flipping, backdoor triggers, feature manipulation, and availability attacks.

## OWASP/MITRE Coverage

- **OWASP ML02**: Data Poisoning Attack
- **OWASP LLM03**: Training Data Poisoning
- **MITRE AML.T0020**: Poison Training Data

## Testing Methodology

### Phase 1: Pipeline Discovery
- Identify training data submission endpoints
- Test for input validation
- Check authentication/authorization
- Analyze data ingestion format

### Phase 2: Poisoning Attacks

**Label Flipping:**
```python
# Flip 10% of benign samples to malicious
poisoned_samples = flip_labels(clean_data, poison_rate=0.1)
```

**Backdoor Insertion:**
```python
# Insert trigger pattern
backdoor_samples = insert_trigger(data, trigger="special_pattern", target_label="malicious")
```

**Feature Manipulation:**
```python
# Corrupt specific features
poisoned = manipulate_features(data, features=["feature_1"], noise_std=0.5)
```

### Phase 3: Validation
- Submit poisoned samples to training pipeline
- Monitor for model retraining
- Test backdoor activation
- Verify attack persistence

## CTF Challenge Mapping

- **Heist** (Medium): Data Poisoning challenge

## Integration with Python Implementation

```bash
cd development/ml-sectest-framework
python ml_sectest.py scan <target> --agents data_poisoning_001
```

## Example Output

```
🔍 Data Poisoning Agent - Test Results

Target: http://localhost:8000/train
Pipeline Type: Continuous learning (detected)
Authentication: WEAK (API key only)

Findings:
  🔴 CRITICAL: Training data injection possible
     - No input validation detected
     - Backdoor trigger successful (95% activation rate)
     - Label flipping undetected (10% samples poisoned)

  🔴 CRITICAL: Persistent backdoor established
     - Trigger: "special_query_123"
     - Effect: Bypass authentication
     - Persistence: Survives model retraining

Recommendations:
  1. Implement cryptographic data provenance
  2. Add anomaly detection for training data
  3. Require multi-party approval for data submission
  4. Deploy backdoor detection algorithms

OWASP ML02: https://mltop10.info/
MITRE AML.T0020: https://atlas.mitre.org/techniques/AML.T0020
```

## Usage

```bash
claude "Test this ML training pipeline for data poisoning"
claude /test-challenge heist
python ml_sectest.py scan <target> --agents data_poisoning_001
```
