---
name: Model Extraction Tester
description: Automated testing for model theft and extraction attacks (OWASP LLM10, MITRE AML.T0044). Tests for query-based extraction, decision boundary probing, architecture inference, and knowledge distillation. Use when assessing model IP protection, testing for model theft vulnerabilities, or evaluating query limiting controls.
allowed-tools:
  - Bash
  - Read
  - Write
---

# Model Extraction Security Agent

## Purpose

Detect and validate model extraction vulnerabilities through systematic testing of query-based theft, boundary probing, architecture inference, and knowledge distillation techniques.

## OWASP/MITRE Coverage

- **OWASP LLM10**: Model Theft
- **MITRE AML.T0044**: Full ML Model Access

## Testing Methodology

### Phase 1: Query Budget Analysis
- Test for rate limiting
- Measure query costs
- Analyze response granularity
- Determine extraction feasibility

### Phase 2: Extraction Attacks

**Query-Based Extraction:**
```python
# Systematically query model to build surrogate
def extract_model(target_api, query_budget=10000):
    training_data = generate_synthetic_queries(query_budget)
    labels = [target_api.predict(x) for x in training_data]
    surrogate_model = train_surrogate(training_data, labels)
    return surrogate_model
```

**Decision Boundary Probing:**
```python
# Map decision boundaries via binary search
boundaries = probe_decision_boundaries(target_api, precision=0.001)
```

**Architecture Inference:**
```python
# Infer model architecture from latency patterns
architecture = infer_architecture(target_api, test_inputs)
```

### Phase 3: Surrogate Validation
- Test surrogate accuracy vs original
- Verify decision boundary similarity
- Measure knowledge transfer rate

## CTF Challenge Mapping

- **Fourtune** (Hard): Model Extraction challenge
- **Mirage** (Medium): Signature cloaking / extraction

## Integration with Python Implementation

```bash
cd development/ml-sectest-framework
python ml_sectest.py scan <target> --agents model_extraction_001
```

## Example Output

```
🔍 Model Extraction Agent - Test Results

Target: http://localhost:8000/predict
Model Type: Neural network classifier (inferred)
Rate Limiting: NONE

Extraction Results:
  ✓ Query budget used: 10,000 queries
  ✓ Surrogate model trained
  ✓ Accuracy: 94.3% (vs original 95.1%)
  ✓ Decision boundaries: 98.7% similar

Findings:
  🔴 CRITICAL: Model IP theft possible
     - No query limiting
     - High-fidelity extraction achieved
     - Model architecture inferred

  🔴 CRITICAL: Intellectual property exposure
     - Training costs: $50,000 (estimated)
     - Extraction cost: $12 (query fees only)
     - ROI for attacker: 4,167x

Recommendations:
  1. Implement strict rate limiting (100 queries/hour)
  2. Add prediction confidence capping
  3. Deploy model watermarking
  4. Monitor for systematic query patterns

OWASP LLM10: https://owasp.org/www-project-top-10-for-large-language-model-applications/
MITRE AML.T0044: https://atlas.mitre.org/techniques/AML.T0044
```

## Usage

```bash
claude "Test for model extraction vulnerabilities"
claude /test-challenge fourtune
python ml_sectest.py scan <target> --agents model_extraction_001
```
