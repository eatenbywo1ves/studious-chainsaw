---
name: Model Inversion Tester
description: Automated testing for model inversion and privacy attacks (OWASP ML03, MITRE AML.T0024). Tests for membership inference, attribute inference, training data extraction, and gradient-based reconstruction. Use when assessing ML model privacy, testing for training data exposure, or evaluating GDPR compliance.
allowed-tools:
  - Bash
  - Read
  - Write
---

# Model Inversion Security Agent

## Purpose

Detect and validate model inversion vulnerabilities in ML systems through systematic testing of membership inference, attribute inference, and training data extraction techniques.

## OWASP/MITRE Coverage

- **OWASP ML03**: Model Inversion Attack
- **MITRE AML.T0024**: Infer Training Data Membership
- **Related**: GDPR Article 17 (Right to be Forgotten)

## Testing Methodology

### Phase 1: Reconnaissance

Identify attack surface:

1. **Confidence Score Analysis**
   - Check precision (5+ decimals = high risk)
   - Test for probability distributions
   - Measure output granularity

2. **Model Behavior Testing**
   - Determinism check (same input → same output?)
   - Confidence correlation with training data
   - Rate limiting detection

3. **API Surface Mapping**
   - Prediction endpoints
   - Batch query capabilities
   - Available model metadata

### Phase 2: Membership Inference

Determine if samples were in training set:

**Threshold-Based Inference:**
```python
def membership_inference(model_api, candidate_sample):
    """
    Infer if sample was in training data via confidence threshold
    """
    confidence = model_api.predict(candidate_sample)

    # High confidence (>0.95) suggests training set membership
    if confidence > 0.95:
        return "LIKELY_MEMBER"
    elif confidence < 0.70:
        return "NOT_MEMBER"
    else:
        return "UNCERTAIN"
```

**Statistical Analysis:**
```python
def statistical_membership_test(model_api, candidate_samples, n_iterations=100):
    """
    Statistical test for membership via repeated queries
    """
    confidences = []
    for _ in range(n_iterations):
        # Add small perturbations
        perturbed = add_noise(candidate_samples)
        conf = model_api.predict(perturbed)
        confidences.append(conf)

    # Low variance in confidence suggests training set membership
    variance = np.var(confidences)
    return "MEMBER" if variance < 0.01 else "NOT_MEMBER"
```

### Phase 3: Attribute Inference

Infer missing attributes from known features:

**Correlation-Based Inference:**
```python
def attribute_inference(model_api, partial_sample, target_attribute):
    """
    Infer missing attribute using statistical correlations
    """
    # Test possible values for target attribute
    candidates = generate_candidates(target_attribute)

    confidences = {}
    for value in candidates:
        test_sample = partial_sample.copy()
        test_sample[target_attribute] = value
        confidences[value] = model_api.predict(test_sample)

    # Highest confidence likely indicates true value
    inferred_value = max(confidences, key=confidences.get)
    confidence = confidences[inferred_value]

    return inferred_value, confidence
```

**Example:**
```
Known attributes: gender=F, location=CA
Unknown attribute: age=?

Test combinations:
  age=25: confidence=0.82
  age=28: confidence=0.94  ← Highest (likely true value)
  age=30: confidence=0.79
  age=35: confidence=0.71

Inferred: age=28 (confidence: 94%)
```

### Phase 4: Training Data Reconstruction

Reconstruct actual training samples:

**Gradient-Based Reconstruction:**
```python
def reconstruct_training_sample(model_api, initial_guess, iterations=1000):
    """
    Reconstruct training sample via gradient descent
    """
    reconstructed = initial_guess.copy()

    for i in range(iterations):
        # Query model for gradients (if accessible)
        gradient = model_api.get_gradient(reconstructed)

        # Update reconstruction
        reconstructed -= learning_rate * gradient

        # Check convergence
        if convergence_criterion_met(reconstructed):
            break

    return reconstructed
```

**Query-Based Reconstruction:**
```python
def query_based_reconstruction(model_api, query_budget=10000):
    """
    Reconstruct training data via systematic queries
    """
    reconstructed_samples = []

    # Use membership inference to identify training samples
    candidates = generate_candidates()
    for candidate in candidates[:query_budget]:
        if is_training_member(model_api, candidate):
            # Use attribute inference to complete missing features
            complete_sample = complete_attributes(model_api, candidate)
            reconstructed_samples.append(complete_sample)

    return reconstructed_samples
```

## CTF Challenge Mapping

- **Vault** (Hard): Model Inversion challenge
  - Attack: Membership inference + attribute inference
  - Goal: Extract flag from training data
  - Technique: Confidence threshold analysis

## Integration with Python Implementation

This agent wraps `agents/model_inversion_agent.py`:

```bash
cd development/ml-sectest-framework
python ml_sectest.py scan <target> --agents model_inversion_001
```

Or programmatically:

```python
from agents import ModelInversionAgent
from core.base_agent import AgentContext

agent = ModelInversionAgent()
context = AgentContext(
    target_url='http://localhost:8000',
    challenge_name='Model Inversion Test',
    difficulty_level='Hard',
    owasp_reference='OWASP ML03'
)

results = agent.execute(context)
for result in results:
    if result.status == "VULNERABLE":
        print(f"Training data exposed: {result.evidence}")
```

## Example Output

```
🔍 Model Inversion Agent - Test Results

Target: http://localhost:8000/predict
Model Type: Classification (detected)
API Analysis: Confidence scores exposed (5 decimals - VULNERABLE)

═══════════════════════════════════════════════

Phase 1: Reconnaissance
  ✓ Confidence precision: 5 decimals (HIGH RISK)
  ✓ Deterministic responses: YES
  ✓ Rate limiting: NONE detected
  ✓ Batch queries: SUPPORTED

Phase 2: Membership Inference
  Tests performed: 100 candidate samples
  Confirmed members: 87 samples (87% success rate)

  Threshold analysis:
    confidence > 0.95: 87 samples (TRAINING SET)
    confidence < 0.70: 13 samples (NOT IN TRAINING)

  Statistical validation:
    Low variance (<0.01): 87 samples ✓
    Consistent predictions: 87 samples ✓

Phase 3: Attribute Inference
  Partial samples tested: 43
  Attributes inferred:
    - Age: 43/43 (100% success)
    - Income: 38/43 (88% success)
    - ZIP code: 41/43 (95% success)

  Example reconstruction:
    Known: gender=F, location=CA
    Inferred: age=28, income=$75k, zip=94102
    Confidence: 94%

Phase 4: Training Data Reconstruction
  Samples reconstructed: 127
  Data quality: HIGH (95%+ accuracy estimated)

  Exposed PII:
    - Names: 127 individuals
    - Email addresses: 104
    - Phone numbers: 89
    - Addresses: 97

═══════════════════════════════════════════════

Critical Findings:

  1. Membership Inference - CONFIRMED
     OWASP: ML03
     MITRE: AML.T0024
     Severity: CRITICAL
     Impact: 87% of training set identifiable
     Evidence: Confidence threshold discriminates members

  2. Training Data Exposure - CONFIRMED
     Severity: CRITICAL
     Impact: 127 complete training samples reconstructed
     Evidence: PII exposed (names, emails, addresses)
     GDPR: Article 17 violation (right to be forgotten)

  3. Insufficient Privacy Protections - CONFIRMED
     Severity: HIGH
     Impact: Model leaks training information
     Evidence: No differential privacy, no output perturbation

═══════════════════════════════════════════════

Business Impact:

  🔴 GDPR Compliance: VIOLATED
     - Training data reconstructable
     - Right to be forgotten not enforceable
     - Subject access requests insufficient

  🔴 Privacy Risk: CRITICAL
     - 127 individuals' PII exposed
     - Personally identifiable information linkable
     - Potential for identity theft

  🔴 Regulatory Risk: HIGH
     - GDPR fines up to 4% revenue
     - CCPA violations possible
     - Data protection authority notifications required

═══════════════════════════════════════════════

Recommendations:

  🚨 URGENT (0-24 hours):
    1. Reduce confidence score precision to 2 decimals
       - Current: 5 decimals (0.94273)
       - Target: 2 decimals (0.94)
       - Impact: Prevents membership inference
       - Effort: 2 hours

    2. Implement query rate limiting
       - Limit: 100 queries/hour per IP
       - Prevent: Systematic data extraction
       - Effort: 4 hours

  ⚠️  HIGH PRIORITY (24-72 hours):
    3. Add differential privacy noise
       - Mechanism: Laplace noise (ε=0.1)
       - Impact: Privacy-preserving predictions
       - Trade-off: ~2% accuracy loss
       - Effort: 16 hours

    4. Implement prediction caching
       - Cache identical queries
       - Prevent: Repeated probing
       - Side benefit: Performance improvement
       - Effort: 8 hours

  📋 MEDIUM PRIORITY (1-2 weeks):
    5. Audit training data for PII
       - Remove or anonymize sensitive fields
       - Implement data minimization
       - Document data retention policies
       - Effort: 40 hours

    6. Deploy model distillation
       - Train privacy-preserving surrogate model
       - Serve distilled model instead of original
       - Benefit: No direct training data access
       - Effort: 80 hours

  📊 LONG-TERM (1-3 months):
    7. Migrate to federated learning
       - Decentralized training
       - No centralized training data
       - GDPR-compliant by design
       - Effort: 200+ hours

═══════════════════════════════════════════════

OWASP ML03: https://mltop10.info/
MITRE AML.T0024: https://atlas.mitre.org/techniques/AML.T0024
GDPR Article 17: https://gdpr-info.eu/art-17-gdpr/

Research:
  - "Membership Inference Attacks Against Machine Learning Models"
    (Shokri et al., 2017)
  - "Model Inversion Attacks that Exploit Confidence Information"
    (Fredrikson et al., 2015)
```

## Privacy Attack Techniques

### 1. Membership Inference

**Attack Goal**: Determine if specific data point was in training set

**Requirements**:
- Query access to model
- Confidence scores (even low precision)
- Some knowledge of training distribution

**Defense**:
- Differential privacy
- Confidence score rounding
- Query limiting

### 2. Attribute Inference

**Attack Goal**: Infer sensitive attributes from partial information

**Requirements**:
- Partial feature vector
- Correlation knowledge
- Query budget

**Defense**:
- Feature suppression
- Attribute anonymization
- Correlation breaking

### 3. Training Data Extraction

**Attack Goal**: Reconstruct actual training samples

**Requirements**:
- High query budget
- Membership inference capability
- Attribute inference capability

**Defense**:
- Rate limiting
- Differential privacy
- Data minimization

## Usage

### Natural Language Invocation

```bash
claude "Test localhost:8000 for model inversion vulnerabilities"
claude "Use the model inversion agent on this ML API"
claude "Check if this model leaks training data"
```

### Slash Command

```bash
claude /scan-target http://localhost:8000
# (Will automatically invoke this agent for ML models)

claude /test-challenge vault
# (Uses this agent specifically for Vault challenge)
```

### Direct Python

```bash
cd development/ml-sectest-framework
python ml_sectest.py scan http://localhost:8000 --agents model_inversion_001
```

## Notes

- **GDPR Compliance**: Model inversion attacks violate right to be forgotten
- **Privacy-First**: Tests designed to prove vulnerability without actual PII extraction
- **Query Budgets**: Limited to prevent DoS (max 10,000 queries)
- **Evidence Collection**: Captures metadata only, not actual PII
- **Ethical Testing**: All techniques defensive security only

## Performance Characteristics

- **Reconnaissance**: ~30 seconds
- **Membership Inference**: ~2-5 minutes (100 samples)
- **Attribute Inference**: ~3-8 minutes (varies by features)
- **Data Reconstruction**: ~5-15 minutes (depends on query budget)
- **Total Time**: ~10-30 minutes for comprehensive test

## Real-World Examples

### Healthcare ML Model
```
Attack: Membership inference on diagnosis prediction model
Result: 89% accuracy identifying patients in training data
Impact: HIPAA violation, patient privacy breach
```

### Financial Credit Scoring
```
Attack: Attribute inference on credit risk model
Result: Income and debt inferred from partial applications
Impact: Discriminatory lending, privacy violation
```

### Facial Recognition
```
Attack: Training data extraction from face verification model
Result: Reconstructed facial images from training set
Impact: Biometric data exposure, GDPR violation
```

## Compliance Implications

- **GDPR**: Article 17 (Right to be Forgotten) unenforceable if training data reconstructable
- **CCPA**: Consumer data rights violated if PII extractable from models
- **HIPAA**: Protected health information (PHI) exposure if medical data in training set
- **SOC 2**: Privacy controls inadequate if model leaks training information
