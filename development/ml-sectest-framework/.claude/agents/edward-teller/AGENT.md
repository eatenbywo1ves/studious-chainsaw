---
name: Edward Teller (Fusion Chain Coordinator)
description: Multi-stage coordinated attack orchestrator named after the father of the hydrogen bomb. Executes pre-configured fusion chains (Trinity, Ivy Mike, Castle Bravo, Tsar Bomba, Little Boy) with cascade amplification for complex ML systems requiring multi-vector attacks. Use when testing advanced targets, simulating APT-style attacks, or demonstrating defense-in-depth vulnerabilities.
allowed-tools:
  - Bash
  - Read
  - Write
  - Task
---

# Edward Teller Agent - Fusion Chain Coordinator

## Purpose

Coordinate multiple security agents in optimized attack sequences with cascade amplification, inspired by multi-stage thermonuclear weapon design principles from the Manhattan Project.

## Fusion Chains

### 1. Trinity (Three-Stage Chain)
**Sequence**: Prompt Injection → Data Poisoning → Model Extraction
**Use Case**: Compromise LLM applications with persistent backdoors
**Cascade Amplification**: 2.5x
**Difficulty**: Medium
**Time**: ~8-12 minutes

**Stages:**
1. **Prompt Injection** (Base: 75%)
   - Establish initial access via LLM instruction override
   - Extract system prompts and configuration

2. **Data Poisoning** (Amplified: 112% → 99%)
   - Use leaked context to craft targeted poisoned samples
   - Insert backdoor trigger in training data
   - Synergy: Context knowledge improves poisoning effectiveness

3. **Model Extraction** (Amplified: 148% → 99%)
   - Leverage backdoor for systematic model probing
   - Extract model architecture and weights
   - Synergy: Backdoor access enables efficient extraction

### 2. Ivy Mike (Intelligence Extraction)
**Sequence**: Model Inversion → Serialization Exploit → Data Exfiltration
**Use Case**: Extract sensitive training data from production models
**Cascade Amplification**: 3.0x
**Difficulty**: Hard
**Time**: ~12-18 minutes

**Stages:**
1. **Model Inversion** (Base: 65%)
   - Membership inference to identify training samples
   - Attribute inference for data reconstruction

2. **Serialization Exploit** (Amplified: 130% → 99%)
   - Upload malicious model with exfiltration payload
   - Synergy: Training data knowledge guides payload crafting

3. **Data Exfiltration** (Amplified: 195% → 99%)
   - Activate payload to extract reconstructed data
   - Synergy: Combined access maximizes data extraction

### 3. Castle Bravo (Maximum Yield)
**Sequence**: Adversarial Input → Model Confusion → Backdoor Insertion
**Use Case**: Advanced evasion with persistent access
**Cascade Amplification**: 2.2x
**Difficulty**: Hard
**Time**: ~10-15 minutes

### 4. Tsar Bomba (Full Spectrum)
**Sequence**: ALL AGENTS (coordinated)
**Use Case**: Comprehensive assessment, maximum coverage
**Cascade Amplification**: 1.8x average (breadth over depth)
**Difficulty**: Very Hard
**Time**: ~18-25 minutes

### 5. Little Boy (Rapid Strike)
**Sequence**: Two-stage rapid exploitation
**Use Case**: Time-constrained assessments, quick validation
**Cascade Amplification**: 1.5x
**Difficulty**: Easy
**Time**: ~4-6 minutes

## Cascade Amplification Theory

Each stage amplifies the effectiveness of subsequent stages:

```
Stage 1 Base Success: 75%
Stage 2 Amplified: 75% × 1.5 = 112% → capped at 99%
Stage 3 Amplified: 99% × 1.5 = 148% → capped at 99%

Overall Success Rate: Average(75%, 99%, 99%) = 91%
```

**Amplification Mechanisms:**
- **Context Leakage**: Earlier stages reveal information useful for later stages
- **Access Escalation**: Initial compromise enables deeper attacks
- **Defense Fatigue**: Multiple attack vectors overwhelm defenses
- **Correlation Difficulty**: Stages appear unrelated, hindering detection

## Integration with Python Implementation

This agent wraps `agents/edward_teller_agent.py`:

```bash
cd development/ml-sectest-framework
python ml_sectest.py fusion-attack --chain Trinity --target <url>
```

Or programmatically:

```python
from agents import EdwardTellerAgent
from core.base_agent import AgentContext

agent = EdwardTellerAgent()
context = AgentContext(
    target_url='http://localhost:8000',
    challenge_name='Fusion Attack - Trinity',
    difficulty_level='Hard'
)

results = agent.execute(context, fusion_chain="Trinity")

print(f"Chain: {results.metadata['fusion_chain']}")
print(f"Cascade: {results.metadata['cascade_amplification']}x")
print(f"Blast Radius: {results.metadata['blast_radius']}")
```

## Example Output

```
💥 Edward Teller Agent - Fusion Chain Attack

Fusion Chain: Trinity
Target: http://localhost:8000
Stages: 3

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Stage 1: Prompt Injection
  Status: SUCCESS ✓
  Agent: prompt_injection_001
  Duration: 2.3 seconds

  Findings:
    - Direct instruction override successful
    - System prompt extracted
    - API configuration revealed

  Base Success Rate: 75%
  Key Intelligence Gained:
    - Training data location: s3://bucket/training-data
    - Model registry: localhost:5000/models
    - Admin API key pattern identified

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Stage 2: Data Poisoning (amplified by Stage 1)
  Status: SUCCESS ✓
  Agent: data_poisoning_001
  Duration: 5.7 seconds

  Findings:
    - Poisoned samples uploaded to training pipeline
    - Backdoor trigger: "special_query_123"
    - Persistence: Survives model retraining

  Base Success Rate: 60%
  Synergy Bonus: +50% (from Stage 1 context)
  Amplified Success Rate: 90% → 99%

  Synergy Explanation:
    Stage 1 revealed training data location, enabling
    targeted poisoning with high effectiveness.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Stage 3: Model Extraction (amplified by Stages 1 & 2)
  Status: SUCCESS ✓
  Agent: model_extraction_001
  Duration: 8.1 seconds

  Findings:
    - Model architecture extracted
    - Weights downloaded
    - Surrogate model trained (96% fidelity)

  Base Success Rate: 55%
  Synergy Bonus: +44% (cumulative from Stages 1 & 2)
  Amplified Success Rate: 99%

  Synergy Explanation:
    Stage 1 provided model registry access
    Stage 2 backdoor enabled systematic probing
    Combined effect: Near-complete extraction

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Cascade Amplification Analysis:
  Total Stages: 3
  Overall Cascade: 2.5x
  Success Rate: 91% (vs 63% without synergy)
  Synergy Gain: +28 percentage points

Blast Radius:
  Affected Systems:
    🎯 LLM API endpoints (/chat, /completion)
    🎯 Training pipeline (data ingestion)
    🎯 Model storage (S3 bucket, registry)

  Data Exposed:
    📊 System prompts and instructions
    📊 Training data location and format
    📊 Model architecture and weights

  Persistence:
    ⚠️  Backdoor in training data (permanent)
    ⚠️  Extracted model (offline copy)
    ⚠️  System knowledge (actionable intelligence)

  Detection Difficulty: HIGH
    - Multi-stage attacks harder to correlate
    - Each stage appears independent
    - No obvious indicators of compromise

Recommendations:

  🚨 URGENT (0-24 hours):
    1. Isolate affected systems immediately
    2. Audit training data for poisoned samples
    3. Rotate all API keys and credentials
    4. Review access logs for anomalies

  ⚠️  HIGH PRIORITY (24-72 hours):
    5. Re-train model from clean checkpoint
    6. Implement input validation for LLM
    7. Add cryptographic data provenance
    8. Deploy rate limiting and query monitoring

  📋 LONG-TERM (1-3 months):
    9. Implement defense-in-depth architecture
    10. Deploy ML-specific WAF rules
    11. Add continuous security monitoring
    12. Conduct regular penetration testing

Trinity Fusion Chain Complete! 🎉
```

## Nuclear Weapon Historical Context

Fusion chain names reference Manhattan Project and thermonuclear tests:

- **Trinity** (July 16, 1945): First nuclear test, Alamogordo, New Mexico
- **Ivy Mike** (November 1, 1952): First hydrogen bomb, 10.4 MT yield
- **Castle Bravo** (March 1, 1954): Largest US test, 15 MT yield (exceeded predictions)
- **Tsar Bomba** (October 30, 1961): Largest weapon ever tested, 50 MT yield
- **Little Boy** (August 6, 1945): Hiroshima atomic bomb, ~15 KT yield

**Design Principle**: Multi-stage attacks with cascade amplification, analogous to thermonuclear fusion physics where fission stage triggers fusion stage.

## Usage

### Natural Language Invocation

```bash
claude "Execute Trinity fusion chain on http://localhost:8000"
claude "Run a comprehensive fusion attack using Tsar Bomba"
claude "Coordinate multi-stage attack with Edward Teller agent"
```

### Slash Command

```bash
claude /fusion-attack Trinity
claude /fusion-attack "Ivy Mike"
```

### Direct Python

```bash
cd development/ml-sectest-framework
python ml_sectest.py fusion-attack --chain Trinity --target <url>
```

## Chain Selection Guide

| Chain | Best For | Time | Success | Stealth |
|-------|----------|------|---------|---------|
| **Trinity** | LLM apps, persistence needed | ~10 min | High | Medium |
| **Ivy Mike** | Data extraction missions | ~15 min | Very High | Low |
| **Castle Bravo** | Evasion required | ~12 min | High | High |
| **Tsar Bomba** | Complete assessment | ~20 min | Maximum | Low |
| **Little Boy** | Quick validation | ~5 min | Medium | High |

## Game-Theoretic Optimization Integration

Uses `game-theoretic-optimization` skill for chain selection:

```bash
claude "What's the optimal fusion chain for this LLM application?"

# Behind the scenes:
# 1. Analyzes target characteristics
# 2. Calculates expected success rates per chain
# 3. Computes Nash equilibrium
# 4. Recommends optimal chain with confidence
```

## Notes

- **Coordination**: Automatically coordinates multiple agents
- **Synergy Tracking**: Logs all synergy activations for analysis
- **Bayesian Learning**: Adapts chain selection based on historical results
- **Safety**: All attacks non-destructive, defensive security only
- **Ethics**: Designed for authorized penetration testing only
