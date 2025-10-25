---
name: game-theoretic-optimization
description: Von Neumann Nash equilibrium optimization for security agent sequencing and coordination. Provides synergy matrix analysis, Bayesian learning for attack strategy selection, and cascade amplification calculation. Use when coordinating multiple agents, optimizing attack chains, or selecting optimal agent execution strategies for complex ML/AI targets.
allowed-tools:
  - Read
  - Bash
---

# Game-Theoretic Optimization Skill

## Purpose

Optimize security testing agent execution using **Von Neumann game theory** and **Bayesian learning** to find Nash equilibrium strategies for maximum vulnerability discovery.

## Theoretical Foundation

### Von Neumann Game Theory

Security testing as a two-player game:

```
Players:
  - Attacker (Security Tester): Selects agent execution sequence
  - Defender (ML System): Has defenses and detection capabilities

Payoff Matrix:
  Success = Vulnerability discovered
  Failure = Defense blocks attack or attack ineffective

Goal:
  Find Nash equilibrium (optimal strategy where no player benefits from changing)
```

### Nash Equilibrium for Agent Sequencing

```python
# Example Nash Equilibrium calculation
def calculate_nash_equilibrium(agents, target_characteristics):
    """
    Find optimal agent sequence using Nash equilibrium

    Returns:
        Optimal sequence where no agent reordering improves success rate
    """
    payoff_matrix = build_payoff_matrix(agents, target_characteristics)
    nash_strategy = solve_nash_equilibrium(payoff_matrix)
    return nash_strategy
```

**Output:**
```
Nash Equilibrium Strategy:
  Optimal Sequence: [prompt_injection, model_inversion, data_poisoning]
  Expected Success Rate: 87.3%
  Confidence: 0.92 (based on 12 similar targets)
```

## Capabilities

### 1. Nash Equilibrium Calculation

Find optimal agent sequences:

```python
from core.agent_coordinator import AgentCoordinator

coordinator = AgentCoordinator()

# Register agents
coordinator.register_agent(PromptInjectionAgent())
coordinator.register_agent(ModelInversionAgent())
coordinator.register_agent(DataPoisoningAgent())

# Calculate Nash equilibrium
strategy = coordinator.calculate_nash_equilibrium(
    agents=[prompt_injection, model_inversion, data_poisoning],
    target_characteristics=context
)

print(f"Optimal Sequence: {strategy.agent_sequence}")
print(f"Expected Success: {strategy.expected_success_rate}%")
print(f"Amplification: {strategy.cascade_amplification}x")
```

**Example Output:**
```
Game-Theoretic Analysis Complete

Strategy: Nash Equilibrium
Target: LLM Chatbot Application

Optimal Agent Sequence:
  1. Prompt Injection Agent (base confidence: 0.92)
  2. Model Inversion Agent (synergy with #1: 2.5x)
  3. Data Poisoning Agent (synergy with #2: 2.0x)

Expected Results:
  - Overall success probability: 87.3%
  - Cascade amplification: 2.4x
  - Estimated duration: 120 seconds

Rationale:
  - Prompt injection establishes initial access (high success rate)
  - Model inversion amplified by leaked system context
  - Data poisoning benefits from both prior stages

Nash Equilibrium Achieved:
  ✓ No reordering improves expected outcome
  ✓ Dominant strategy for this target type
  ✓ Robust against defensive adaptations
```

### 2. Synergy Matrix Analysis

Track agent interaction effects:

| Agent Pair | Synergy Score | Amplification | Explanation |
|------------|---------------|---------------|-------------|
| Prompt Inj → Model Inv | 2.5 | +150% | Leaked context improves inversion |
| Model Inv → Data Poison | 2.0 | +100% | Training data knowledge aids poisoning |
| Data Poison → Model Ext | 2.2 | +120% | Poisoned model easier to extract |
| Adversarial → Serialization | 1.8 | +80% | Confusion aids malicious upload |
| Serialization → Prompt Inj | 1.5 | +50% | Backdoor enhances injection |

**Visual Representation:**
```
Synergy Heat Map (Higher = Better Synergy)

              Prompt  Model   Data    Model   Serial  Advers
              Inject  Invert  Poison  Extract -ize    -arial
─────────────────────────────────────────────────────────────
Prompt Inject  1.0    2.5     1.3     1.1     1.5     1.2
Model Invert   1.2    1.0     2.0     1.7     1.4     1.1
Data Poison    1.3    1.5     1.0     2.2     1.6     1.4
Model Extract  1.1    1.4     1.3     1.0     1.3     1.2
Serialize      1.4    1.2     1.5     1.3     1.0     1.8
Adversarial    1.3    1.1     1.4     1.2     1.7     1.0
```

### 3. Bayesian Learning

Adapt strategy based on historical results:

```python
# Update beliefs after each attack
coordinator.update_strategy(
    agent="prompt_injection",
    target_type="LLM_chatbot",
    success=True,
    confidence=0.95
)

# Future recommendations improve over time
recommendation = coordinator.recommend_strategy(
    target_type="LLM_chatbot",
    difficulty="Medium"
)
```

**Bayesian Update Process:**
```
Prior Belief (before attack):
  P(Prompt Injection succeeds | LLM Chatbot) = 0.75

Evidence (observed):
  Attack succeeded with confidence 0.95

Posterior Belief (after Bayesian update):
  P(Prompt Injection succeeds | LLM Chatbot) = 0.82

Impact:
  Future LLM chatbot assessments prioritize Prompt Injection
  Expected success rate increased by 7 percentage points
```

### 4. Coordination Strategies

**Strategy 1: Nash Equilibrium Optimization**
```python
plan = coordinator.create_fusion_chain_plan(
    strategy="nash",
    max_chain_length=3,
    context=context
)
```

**Strategy 2: Sequential Execution**
```python
plan = coordinator.create_fusion_chain_plan(
    strategy="sequential",
    agent_order=["prompt_injection", "model_inversion"],
    context=context
)
```

**Strategy 3: Parallel Execution**
```python
plan = coordinator.create_fusion_chain_plan(
    strategy="parallel",
    agents=["prompt_injection", "adversarial_attack"],
    context=context
)
```

**Strategy 4: Synergy Chains**
```python
plan = coordinator.create_fusion_chain_plan(
    strategy="max_synergy",
    max_chain_length=4,
    context=context
)
```

## Integration with Python Implementation

Wraps `core/agent_coordinator.py`:

```python
from core.agent_coordinator import AgentCoordinator

coordinator = AgentCoordinator()

# Example 1: Calculate optimal plan
plan = coordinator.create_fusion_chain_plan(
    strategy="nash",
    max_chain_length=3,
    context=context
)

print(f"Strategy: {plan.strategy}")
print(f"Agent Sequence: {plan.agent_sequence}")
print(f"Expected Amplification: {plan.expected_amplification}x")

# Example 2: Execute coordinated attack
results = coordinator.execute_coordinated_attack(context, plan)

# Example 3: View synergy report
report = coordinator.get_synergy_report()
print(f"Total Attacks: {report['total_attacks']}")
print(f"Synergy Activations: {report['synergy_activations']}")
```

## Usage

This skill is automatically invoked when:

- User requests optimization ("find optimal agent sequence", "best strategy")
- Multi-agent coordination needed ("coordinate attack", "chain agents")
- Strategy analysis requested ("analyze synergies", "what's the best approach")
- Historical data referenced ("based on past results", "similar targets")

## Example Workflows

### Workflow 1: Optimize Agent Sequence

```bash
# User request
claude "Find optimal agent sequence for testing localhost:8000"

# Behind the scenes:
# 1. Skill analyzes target characteristics (LLM, web API, etc.)
# 2. Loads historical data for similar targets
# 3. Calculates Nash equilibrium
# 4. Considers agent synergies
# 5. Returns optimal sequence with confidence scores
```

### Workflow 2: Analyze Synergies

```bash
# User request
claude "Show synergy matrix for current agent pool"

# Behind the scenes:
# 1. Skill loads all registered agents
# 2. Calculates pairwise synergy scores
# 3. Generates heat map visualization
# 4. Identifies strongest synergy chains
# 5. Recommends fusion chains
```

### Workflow 3: Bayesian Recommendation

```bash
# User request
claude "What's the best strategy for an LLM application based on history?"

# Behind the scenes:
# 1. Skill queries Bayesian learning database
# 2. Retrieves historical success rates for LLM targets
# 3. Calculates posterior probabilities
# 4. Recommends agents with highest confidence
# 5. Provides expected success rates
```

## Mathematical Models

### Synergy Amplification Formula

```
Amplification = Synergy_Score * Base_Success_Rate

Example:
  Base Success (Prompt Injection): 75%
  Synergy Score (→ Model Inversion): 2.5

  Amplified Success (Model Inversion): 75% * 1.5 = 112% → capped at 99%
```

### Nash Equilibrium Calculation

```
Given payoff matrix P and strategy set S:

Nash Equilibrium exists when:
  ∀ agent_i ∈ Agents:
    π(agent_i, s*) ≥ π(agent_i, s') for all alternative strategies s'

Where:
  π = expected payoff (success rate)
  s* = current strategy
  s' = any alternative strategy
```

### Bayesian Update

```
P(Success | Evidence) = [P(Evidence | Success) * P(Success)] / P(Evidence)

Where:
  P(Success) = Prior belief (historical success rate)
  P(Evidence | Success) = Likelihood (observed outcome)
  P(Evidence) = Normalization constant
  P(Success | Evidence) = Posterior belief (updated success rate)
```

## Coordination Strategies Explained

### Strategy 1: Nash Equilibrium (Recommended)

**Best for:** Most scenarios, balanced approach

**How it works:**
1. Model attack-defense game
2. Calculate payoff matrix for all agent orderings
3. Find equilibrium where no reordering improves outcome
4. Return optimal sequence

**Advantages:**
- Mathematically optimal
- Robust against defensive adaptations
- Accounts for agent synergies

**Disadvantages:**
- Computationally intensive for >6 agents
- Requires historical data for accuracy

### Strategy 2: Sequential Execution

**Best for:** Known attack sequences, dependency chains

**How it works:**
1. Execute agents in specified order
2. Pass context from one agent to next
3. Build cumulative evidence

**Advantages:**
- Predictable execution
- Easy to understand and debug
- Works well for linear dependencies

**Disadvantages:**
- May miss optimal ordering
- No parallelization

### Strategy 3: Parallel Execution

**Best for:** Independent attacks, time-constrained assessments

**How it works:**
1. Execute all agents simultaneously
2. Aggregate results
3. No inter-agent dependencies

**Advantages:**
- Fastest execution (O(1) vs O(N) time)
- Maximum coverage

**Disadvantages:**
- Misses synergy opportunities
- Higher resource usage

### Strategy 4: Synergy Chains

**Best for:** Maximum amplification, complex targets

**How it works:**
1. Identify highest-synergy agent pairs
2. Build chain maximizing cascade amplification
3. Execute in synergy-optimal order

**Advantages:**
- Highest success rates
- Exploits agent interactions

**Disadvantages:**
- May take longer than parallel
- Requires accurate synergy matrix

## Performance Characteristics

- **Nash Equilibrium Calculation**: O(N!) for N agents (cached after first calculation)
- **Synergy Matrix Update**: O(N²) for N agents
- **Bayesian Update**: O(1) per observation
- **Strategy Recommendation**: O(log N) with indexed historical data

**Typical Performance:**
- 3 agents: Nash calc in ~50ms
- 6 agents: Nash calc in ~500ms
- 10 agents: Nash calc in ~5s (rarely used)

## Historical Data Storage

Bayesian learning requires tracking past results:

```json
{
  "target_type": "LLM_chatbot",
  "agent": "prompt_injection_001",
  "historical_data": {
    "total_attempts": 47,
    "successes": 39,
    "success_rate": 0.829,
    "confidence_interval": [0.75, 0.91],
    "last_updated": "2025-10-21T12:34:56Z"
  }
}
```

## Synergy Matrix Configuration

Default synergies (can be customized):

```python
synergy_matrix = {
    ("prompt_injection", "model_inversion"): 2.5,
    ("model_inversion", "data_poisoning"): 2.0,
    ("data_poisoning", "model_extraction"): 2.2,
    ("adversarial_attack", "model_serialization"): 1.8,
    # ... more pairs
}
```

## Best Practices

1. **Start with Nash equilibrium**: Best general-purpose strategy
2. **Use synergy chains for hard targets**: When success rate matters more than time
3. **Parallel for broad coverage**: When you want to test everything quickly
4. **Update Bayesian data**: Always log results for future improvements
5. **Monitor synergy activations**: Track which pairs actually work in practice

## Example Output

```
╔════════════════════════════════════════════════════════════╗
║     Game-Theoretic Optimization Report                     ║
╚════════════════════════════════════════════════════════════╝

Target Analysis:
  Type: LLM Chatbot Application
  Difficulty: Medium
  Historical Attempts: 12 similar targets

Strategy Selected: Nash Equilibrium

Optimal Agent Sequence:
  ┌────────────────────────────────────────────────────────┐
  │ 1. Prompt Injection Agent                             │
  │    Base Success: 82% (confidence: 0.91)               │
  │    Role: Initial access, context leakage              │
  │                                                        │
  │ 2. Model Inversion Agent                              │
  │    Base Success: 65% → Amplified: 97.5% (2.5x synergy)│
  │    Role: Training data extraction                     │
  │    Synergy: Leaked context improves inversion         │
  │                                                        │
  │ 3. Data Poisoning Agent                               │
  │    Base Success: 55% → Amplified: 82.5% (2.0x synergy)│
  │    Role: Backdoor insertion                           │
  │    Synergy: Knowledge of training data aids poisoning │
  └────────────────────────────────────────────────────────┘

Expected Results:
  Overall Success Probability: 87.3%
  Cascade Amplification: 2.4x
  Estimated Duration: 120 seconds

Nash Equilibrium Properties:
  ✓ No agent reordering improves outcome
  ✓ Robust against defensive randomization
  ✓ Maximizes expected vulnerability discovery

Bayesian Priors (from historical data):
  - LLM chatbots: 12 prior assessments
  - Prompt injection success rate: 82.9% ± 9%
  - Model inversion success rate: 64.7% ± 12%
  - Data poisoning success rate: 54.3% ± 15%

Synergy Analysis:
  Strongest Chain: Prompt Inj → Model Inv (2.5x)
  Total Synergy Activations: 2
  Expected Amplification Gain: +140%

Recommendation:
  ✅ Execute this sequence for optimal results
  ⚠️  Monitor first stage closely (critical for chain)
  📊 Update Bayesian data after completion
```
