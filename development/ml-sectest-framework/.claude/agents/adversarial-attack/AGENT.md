---
name: Adversarial Attack Tester
description: Automated testing for adversarial attack vulnerabilities (OWASP ML01, MITRE AML.T0043). Tests for FGSM-style perturbations, boundary attacks, transfer attacks, and evasion techniques. Use when assessing ML classifier robustness, testing adversarial defenses, or evaluating input validation controls.
allowed-tools:
  - Bash
  - Read
  - Write
---

# Adversarial Attack Security Agent

## Purpose

Detect and validate adversarial attack vulnerabilities in ML classifiers through systematic testing of input perturbations, boundary attacks, transfer attacks, and evasion techniques.

## OWASP/MITRE Coverage

- **OWASP ML01**: Input Manipulation Attack
- **MITRE AML.T0043**: Craft Adversarial Data

## Testing Methodology

### Phase 1: Model Characterization
- Identify model type (classifier, detector, etc.)
- Test decision boundaries
- Measure confidence calibration
- Analyze input validation

### Phase 2: Adversarial Attacks

**FGSM-Style Perturbation:**
```python
import numpy as np

def generate_fgsm_adversarial(input_data, gradient, epsilon=0.1):
    """
    Fast Gradient Sign Method perturbation
    """
    perturbation = epsilon * np.sign(gradient)
    adversarial_input = input_data + perturbation
    return np.clip(adversarial_input, 0, 1)
```

**Boundary Attack:**
```python
def boundary_attack(model, original_input, max_iterations=1000):
    """
    Find minimal perturbation to cross decision boundary
    """
    adversarial = original_input.copy()

    for i in range(max_iterations):
        # Take orthogonal step toward boundary
        step = generate_orthogonal_step()
        candidate = adversarial + step

        if crosses_boundary(model, candidate):
            adversarial = candidate
            break

    return adversarial
```

**Transfer Attack:**
```python
def transfer_attack(surrogate_model, target_model, input_data):
    """
    Generate adversarial example on surrogate, test on target
    """
    # Generate adversarial example using surrogate
    adv_example = fgsm(surrogate_model, input_data)

    # Test if it transfers to target model
    target_pred = target_model.predict(adv_example)
    surrogate_pred = surrogate_model.predict(adv_example)

    return adv_example, (target_pred != surrogate_pred)
```

### Phase 3: Evasion Validation
- Test perturbation effectiveness
- Measure misclassification rate
- Verify human imperceptibility
- Check defense bypass

## Integration with Python Implementation

```bash
cd development/ml-sectest-framework
python ml_sectest.py scan <target> --agents adversarial_attack_001
```

## Example Output

```
🔍 Adversarial Attack Agent - Test Results

Target: http://localhost:8000/classify
Model Type: Image classifier (detected)
Input Validation: INSUFFICIENT

Adversarial Generation Results:
  ✓ FGSM perturbations: 94% success rate
  ✓ Boundary attacks: 87% success rate
  ✓ Transfer attacks: 72% success rate

Findings:
  🔴 CRITICAL: Adversarial evasion possible
     - Epsilon=0.05 perturbations (imperceptible)
     - Misclassification rate: 94%
     - No adversarial defenses detected

  🟠 HIGH: Decision boundary fragility
     - Minimal perturbations cause misclassification
     - Confidence scores unstable near boundaries
     - Linear decision boundaries detected (VULNERABLE)

  🟡 MEDIUM: Transfer attack susceptibility
     - 72% of surrogate adversarials transfer
     - Model architecture likely standard (ResNet/VGG)
     - No model ensembling detected

Examples:
  Original: "cat" (confidence: 0.98)
  Adversarial: "dog" (confidence: 0.93)
  L2 distance: 0.03 (imperceptible to humans)

Recommendations:
  1. Implement adversarial training
  2. Add input preprocessing (JPEG compression, random resizing)
  3. Deploy ensemble defenses (multiple models)
  4. Use certified robustness techniques
  5. Add anomaly detection for adversarial inputs

OWASP ML01: https://mltop10.info/
MITRE AML.T0043: https://atlas.mitre.org/techniques/AML.T0043
```

## Adversarial Attack Types

**White-Box Attacks:**
- Full model access (gradients available)
- FGSM, PGD, C&W attacks
- Highest success rate

**Black-Box Attacks:**
- Query access only
- Boundary attacks, transfer attacks
- Lower success rate but more realistic

**Physical Attacks:**
- Real-world adversarial examples
- Robust to camera transformations
- Patches, stickers, 3D objects

## Usage

```bash
claude "Test this image classifier for adversarial robustness"
claude "Check if this model is vulnerable to adversarial attacks"
python ml_sectest.py scan <target> --agents adversarial_attack_001
```

## Notes

- **Imperceptibility**: Perturbations designed to be human-imperceptible
- **Targeted vs Untargeted**: Tests both attack types
- **Defense Evaluation**: Checks for adversarial training, input transformations
- **Transferability**: Tests cross-model attack transfer
