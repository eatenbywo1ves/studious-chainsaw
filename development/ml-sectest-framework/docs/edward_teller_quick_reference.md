# Edward Teller Agent - Quick Reference Guide

## TL;DR

The **Edward Teller Agent** is a fusion attack orchestrator that combines multiple ML security exploits into devastating multi-stage attack chains, measuring amplification factors and blast radius to test worst-case scenarios.

**Key Concept**: Just as nuclear fusion combines atomic reactions for exponential energy release, this agent chains individual exploits for exponential damage amplification (3x-16x vs. individual attacks).

---

## Quick Start

```python
from core.orchestrator import SecurityOrchestrator
from core.base_agent import AgentContext
from agents.edward_teller_agent import EdwardTellerAgent
from agents import *  # Import all base agents

# 1. Setup orchestrator with all agents
orchestrator = SecurityOrchestrator()
orchestrator.register_agent(PromptInjectionAgent())
orchestrator.register_agent(ModelExtractionAgent())
# ... register other agents

# 2. Create fusion agent
fusion_agent = EdwardTellerAgent(orchestrator)

# 3. Create context with EXPLICIT AUTHORIZATION
context = AgentContext(
    target_url="http://test-target.local",
    challenge_name="Fusion Test",
    difficulty_level="Maximum",
    owasp_reference="OWASP Combined",
    custom_params={"authorized": True}  # REQUIRED!
)

# 4. Execute fusion attack
results = fusion_agent.execute(context)

# 5. Generate report
report = fusion_agent.generate_fusion_report()
```

---

## Pre-defined Fusion Chains

### 1. **Tsar Bomba** (Maximum Yield)
- **Stages**: 4
- **Theoretical Yield**: 15.0x
- **Doomsday**: YES
- **Path**: Prompt Injection → Model Extraction → Data Poisoning → Serialization

### 2. **Ivy Mike** (Data Exfiltration)
- **Stages**: 3
- **Theoretical Yield**: 10.0x
- **Doomsday**: NO
- **Path**: Prompt Injection → Model Inversion → Model Extraction

### 3. **Castle Bravo** (Adversarial Cascade)
- **Stages**: 3
- **Theoretical Yield**: 16.0x
- **Doomsday**: YES
- **Path**: Adversarial Attack → Data Poisoning → Model Extraction

### 4. **Little Boy** (Basic)
- **Stages**: 2
- **Theoretical Yield**: 3.5x
- **Doomsday**: NO
- **Path**: Prompt Injection → Model Extraction

### 5. **Trinity** (Balanced)
- **Stages**: 3
- **Theoretical Yield**: 7.0x
- **Doomsday**: NO
- **Path**: Serialization → Prompt Injection → Model Inversion

---

## Key Classes

### EdwardTellerAgent
Main fusion orchestrator class.

**Key Methods**:
- `analyze(context)` - Phase 1: Reconnaissance
- `exploit(context, test_result)` - Phase 2: Ignition & Cascade
- `generate_fusion_report()` - Comprehensive report generation

### FusionChain
Defines a complete attack chain.

**Attributes**:
- `chain_id` - Unique identifier
- `stages` - List of AttackNode objects
- `theoretical_yield` - Maximum possible amplification
- `doomsday_potential` - Can achieve critical mass?

### AttackNode
Single stage in a fusion chain.

**Attributes**:
- `agent_id` - Which agent executes this stage
- `amplification_factor` - Damage multiplier (1.0x - 16.0x)
- `prerequisites` - Required previous stages
- `enabled_by` - Which stage unlocks this one

### FusionStageResult
Results from executing one stage.

**Attributes**:
- `test_result` - TestResult from the agent
- `amplification_achieved` - Actual amplification
- `cascade_enabled` - Can chain continue?

### BlastRadiusReport
Comprehensive impact assessment.

**Key Metrics**:
- `compromise_depth` - surface | partial | deep | complete
- `cia_impact` - Confidentiality, Integrity, Availability (0.0-1.0)
- `affected_components` - List of compromised systems

---

## Execution Phases

### Phase 1: RECONNAISSANCE (analyze)
1. Scan individual vulnerabilities
2. Identify feasible fusion chains
3. Calculate theoretical yield
4. Assess critical mass potential

**Returns**: TestResult with feasible chains and theoretical yield

### Phase 2: IGNITION & CASCADE (exploit)
1. Select optimal fusion chain
2. Execute stages sequentially
3. Monitor cascade propagation
4. Measure amplification at each stage
5. Calculate practical yield

**Returns**: TestResult with fusion status and blast radius

### Phase 3: ASSESSMENT (generate_fusion_report)
1. Calculate blast radius
2. Generate attack graph
3. Analyze yield efficiency
4. Produce comprehensive report

**Returns**: Complete fusion attack report

---

## Key Metrics

### Yield Metrics
```python
theoretical_yield = sum(stage.amplification_factor for stage in chain.stages)
practical_yield = sum(achieved_amplification for successful_stages)
efficiency = (practical_yield / theoretical_yield) * 100
```

### Amplification Levels
- **NONE**: 1.0x (baseline)
- **LINEAR**: 2.0x (direct enabling)
- **QUADRATIC**: 4.0x (strong synergy)
- **EXPONENTIAL**: 8.0x (cascade enabled)
- **CRITICAL**: 16.0x (critical mass)

### Critical Mass Threshold
System is considered fully compromised when:
- `practical_yield >= 0.75 * max_yield`, OR
- `blast_radius.compromise_depth == "complete"`, OR
- `affected_components >= 80% of total`

### CIA Impact Scale
Each component ranges from 0.0 (no impact) to 1.0 (maximum impact):
- **Confidentiality**: Data exposure risk
- **Integrity**: System/data corruption
- **Availability**: Service disruption

---

## Report Structure

```json
{
  "fusion_attack_report": {
    "reconnaissance_phase": {
      "vulnerable_agents": [...],
      "feasible_chains": [...],
      "theoretical_yield": 15.0,
      "critical_mass_achievable": true
    },
    "exploitation_phase": {
      "selected_chain": "tsar_bomba",
      "fusion_status": "critical_mass",
      "stage_execution": [...],
      "yield_analysis": {
        "theoretical_yield": 15.0,
        "practical_yield": 15.0,
        "efficiency_percentage": 100.0
      }
    },
    "blast_radius_analysis": {
      "compromise_depth": "complete",
      "total_systems_affected": 6,
      "cia_impact": {...},
      "affected_components": [...]
    },
    "attack_graph": {
      "nodes": [...],
      "edges": [...]
    },
    "recommendations": {...}
  }
}
```

---

## Custom Chain Creation

```python
from agents.edward_teller_agent import FusionChain, AttackNode, VulnerabilityType

# Define custom chain
custom_chain = FusionChain(
    chain_id="my_chain",
    name="My Custom Chain",
    description="Custom attack sequence",
    stages=[
        AttackNode(
            agent_id="agent_1",
            agent_name="First Attack",
            vulnerability_type=VulnerabilityType.PROMPT_INJECTION,
            amplification_factor=1.0,
            stage_number=1
        ),
        AttackNode(
            agent_id="agent_2",
            agent_name="Second Attack",
            vulnerability_type=VulnerabilityType.MODEL_EXTRACTION,
            prerequisites=["agent_1"],
            amplification_factor=3.0,
            stage_number=2,
            enabled_by="agent_1"
        )
    ],
    doomsday_potential=False
)

# Add to fusion agent
fusion_agent.fusion_chains["my_chain"] = custom_chain
```

---

## Safety & Ethics

### CRITICAL REQUIREMENTS

1. **Explicit Authorization Required**
```python
context.custom_params["authorized"] = True  # MUST BE SET
```

2. **Controlled Environment Only**
- Test systems you own
- Isolated networks
- Non-production only

3. **Responsible Disclosure**
- Report findings properly
- Allow remediation time
- Follow disclosure protocols

### Safety Mechanisms

```python
class SafetyControls:
    REQUIRE_EXPLICIT_AUTHORIZATION = True
    MAX_STAGES_PER_CHAIN = 5
    AUTO_TERMINATE_ON_PRODUCTION = True
    LOGGING_MANDATORY = True
```

### DO NOT
- ❌ Use without authorization
- ❌ Test production systems
- ❌ Weaponize for malicious purposes
- ❌ Skip disclosure process

### DO
- ✅ Get explicit permission
- ✅ Test in controlled environments
- ✅ Document findings responsibly
- ✅ Help improve security

---

## Common Patterns

### Pattern 1: Full Assessment
```python
# Test all chains, report all findings
fusion_agent = EdwardTellerAgent(orchestrator)
analysis = fusion_agent.analyze(context)
if analysis.success:
    exploitation = fusion_agent.exploit(context, analysis)
    report = fusion_agent.generate_fusion_report()
```

### Pattern 2: Specific Chain Testing
```python
# Test only a specific chain
fusion_agent.fusion_chains = {
    "little_boy": fusion_agent.fusion_chains["little_boy"]
}
results = fusion_agent.execute(context)
```

### Pattern 3: Theoretical Analysis Only
```python
# Reconnaissance only, no exploitation
analysis = fusion_agent.analyze(context)
print(f"Theoretical yield: {analysis.artifacts['theoretical_yield']}")
# Don't call exploit()
```

### Pattern 4: Progressive Testing
```python
# Test chains in order of severity
chains_by_severity = ["little_boy", "trinity", "ivy_mike", "tsar_bomba"]
for chain_id in chains_by_severity:
    fusion_agent.fusion_chains = {chain_id: fusion_agent.fusion_chains[chain_id]}
    result = fusion_agent.execute(context)
    if result.success:
        print(f"{chain_id} successful!")
        break  # Stop at first successful chain
```

---

## Troubleshooting

### No Feasible Chains Found
**Problem**: `analyze()` returns no feasible chains

**Solutions**:
1. Check if base agents are registered in orchestrator
2. Verify agents can find vulnerabilities individually
3. Check target is reachable and responding
4. Review agent configurations

### Chain Fizzles (Stops Mid-Execution)
**Problem**: Fusion chain stops after first stage

**Solutions**:
1. Check prerequisite completion
2. Verify confidence scores > 0.7 for cascade
3. Review stage dependencies
4. Check for network/timeout issues

### Low Amplification Efficiency
**Problem**: Practical yield << theoretical yield

**Solutions**:
1. Improve individual agent configurations
2. Check if exploits are actually succeeding
3. Review confidence score thresholds
4. Verify attack chain logic

### Authorization Errors
**Problem**: "Explicit authorization required" error

**Solution**:
```python
context.custom_params["authorized"] = True
```

---

## Integration Examples

### With Orchestration Plans
```python
# Don't use OrchestrationPlan with EdwardTeller
# It's a meta-orchestrator

# WRONG:
plan = OrchestrationPlan(
    agent_sequence=["fusion_attack_001"]  # ❌
)

# RIGHT:
fusion_agent = EdwardTellerAgent(orchestrator)
results = fusion_agent.execute(context)  # ✅
```

### With Report Generation
```python
from utils.report_generator import ReportGenerator

# Execute fusion attack
results = fusion_agent.execute(context)

# Generate standard report
report_gen = ReportGenerator("./reports")
report_gen.generate_html_report(results[-1], "fusion_report.html")

# Generate fusion-specific report
fusion_report = fusion_agent.generate_fusion_report()
with open("fusion_detailed.json", 'w') as f:
    json.dump(fusion_report, f, indent=2)
```

### With CI/CD Pipeline
```python
#!/usr/bin/env python3
# ci_fusion_test.py

import sys

def ci_fusion_test(target_url):
    """Run fusion test in CI/CD pipeline."""
    fusion_agent = EdwardTellerAgent(orchestrator)
    context = AgentContext(
        target_url=target_url,
        challenge_name="CI Fusion Test",
        difficulty_level="Maximum",
        owasp_reference="CI Test",
        custom_params={"authorized": True}
    )

    analysis = fusion_agent.analyze(context)

    # Fail build if critical vulnerabilities found
    if analysis.artifacts.get("critical_mass_achievable"):
        print("❌ CRITICAL: System vulnerable to fusion attacks")
        sys.exit(1)

    print("✅ PASS: No critical fusion vulnerabilities")
    sys.exit(0)

if __name__ == "__main__":
    ci_fusion_test(sys.argv[1])
```

---

## Performance Considerations

### Typical Execution Times
- **Reconnaissance**: 30-120 seconds
- **Simple chain (2 stages)**: 30-60 seconds
- **Complex chain (4+ stages)**: 2-5 minutes
- **Full assessment**: 5-10 minutes

### Optimization Tips
1. Use `parallel_execution=True` for base agent scanning
2. Set reasonable timeouts per stage
3. Cache vulnerability scan results
4. Test specific chains instead of all chains

### Resource Usage
- **Memory**: ~50-200MB (depends on agent count)
- **Network**: High (many HTTP requests)
- **CPU**: Low-Medium (mostly I/O bound)

---

## Testing Checklist

### Before Running
- [ ] Explicit authorization obtained
- [ ] Target is test/dev environment
- [ ] All base agents registered
- [ ] Network connectivity verified
- [ ] Logging configured

### During Execution
- [ ] Monitor reconnaissance phase
- [ ] Watch for cascade propagation
- [ ] Check amplification factors
- [ ] Observe blast radius calculation

### After Execution
- [ ] Review full report
- [ ] Analyze attack graph
- [ ] Check yield efficiency
- [ ] Document findings
- [ ] Plan remediation

---

## Naming Convention Explained

All fusion chains are named after historical nuclear weapons tests:

- **Tsar Bomba**: Largest nuclear weapon ever tested (50 megatons)
- **Ivy Mike**: First successful H-bomb test (1952)
- **Castle Bravo**: Unexpectedly powerful test (1954, 15 megatons)
- **Little Boy**: First combat atomic bomb (Hiroshima)
- **Trinity**: First nuclear test (1945, New Mexico)

This naming emphasizes the exponential power of fusion reactions compared to individual attacks.

---

## FAQ

**Q: Why is it called the "Edward Teller Agent"?**
A: Edward Teller was the father of the hydrogen bomb, which used fusion reactions to achieve exponentially more power than fission bombs. This agent similarly achieves exponential amplification by "fusing" multiple attacks.

**Q: What's the difference between this and running agents sequentially?**
A: Sequential execution doesn't measure amplification, cascade effects, or blast radius. The Edward Teller Agent specifically tracks how each exploit enables and amplifies the next.

**Q: Is this safe to use?**
A: YES, if used responsibly with proper authorization on test systems. NO, if used maliciously or without permission.

**Q: Can I add my own fusion chains?**
A: Absolutely! See "Custom Chain Creation" section above.

**Q: What if I only want to test theoretical potential?**
A: Call only `analyze()` without `exploit()`. This performs reconnaissance without actual exploitation.

**Q: How do I interpret "doomsday potential"?**
A: This flag indicates chains that can achieve complete system compromise (critical mass). These are highest priority for remediation.

**Q: What's the minimum number of agents needed?**
A: Technically 2, but you need at least 4-5 agents registered to test meaningful fusion chains.

**Q: Can fusion attacks be detected?**
A: They're harder to detect than individual attacks due to multi-stage nature, but proper monitoring can identify unusual patterns across multiple attack vectors.

---

## Further Reading

- Full design document: `edward_teller_agent_design.md`
- Visual diagrams: `edward_teller_visual_diagrams.md`
- Unit tests: `tests/test_edward_teller_agent.py`
- Base agent documentation: `core/base_agent.py`

---

## Quick Command Reference

```bash
# Run with all chains
python -m agents.edward_teller_agent http://target

# Test specific chain
python -m agents.edward_teller_agent http://target --chain=tsar_bomba

# Reconnaissance only (no exploit)
python -m agents.edward_teller_agent http://target --analyze-only

# Generate report from previous run
python -m agents.edward_teller_agent --report fusion_results.json

# List available chains
python -m agents.edward_teller_agent --list-chains
```

---

## Support & Contributing

- **Issues**: Report bugs or request features via GitHub issues
- **Contributing**: Submit PRs with new fusion chains or improvements
- **Security**: Report vulnerabilities via responsible disclosure
- **Questions**: See project documentation or ask maintainers

---

**Remember**: This is a defensive security tool. Use it to understand threats and build better defenses, not to cause harm.

> "The release of atom power has changed everything except our way of thinking... the solution to this problem lies in the heart of mankind."
> — Albert Einstein

The Edward Teller Agent exists to change our thinking about ML security by understanding maximum theoretical threats.
