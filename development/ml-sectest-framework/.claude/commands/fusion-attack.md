You are coordinating a multi-stage fusion attack using the Edward Teller Agent.

**Fusion Chain:** $ARGUMENTS

## Fusion Attack Workflow

1. **Load Fusion Chain Configuration**

   Available fusion chains (named after nuclear weapons tests):

   **Trinity** (Three-Stage Chain):
   - Sequence: Prompt Injection → Data Poisoning → Model Extraction
   - Use Case: Compromise LLM applications with persistent backdoors
   - Expected Cascade: 2.5x amplification
   - Difficulty: Medium

   **Ivy Mike** (Intelligence Extraction):
   - Sequence: Model Inversion → Serialization Exploit → Data Exfiltration
   - Use Case: Extract sensitive training data from production models
   - Expected Cascade: 3.0x amplification
   - Difficulty: Hard

   **Castle Bravo** (Maximum Yield):
   - Sequence: Adversarial Input → Model Confusion → Backdoor Insertion
   - Use Case: Advanced evasion with persistent access
   - Expected Cascade: 2.2x amplification
   - Difficulty: Hard

   **Tsar Bomba** (Full Spectrum):
   - Sequence: ALL AGENTS (coordinated)
   - Use Case: Comprehensive assessment, maximum coverage
   - Expected Cascade: 1.8x average (breadth over depth)
   - Difficulty: Very Hard

   **Little Boy** (Rapid Strike):
   - Sequence: Two-stage rapid exploitation
   - Use Case: Time-constrained assessments, quick validation
   - Expected Cascade: 1.5x amplification
   - Difficulty: Easy

2. **Initialize Edward Teller Agent**

   ```bash
   cd development/ml-sectest-framework
   ```

   Verify fusion chain exists:
   ```bash
   python -c "
   from agents import EdwardTellerAgent
   agent = EdwardTellerAgent()
   chains = agent.get_available_chains()
   print('Available chains:', list(chains.keys()))
   "
   ```

3. **Execute Fusion Chain**

   Run multi-stage coordinated attack:
   ```bash
   python ml_sectest.py fusion-attack --chain "$ARGUMENTS" --target <target_url>
   ```

   Or programmatically:
   ```python
   from agents import EdwardTellerAgent
   from core.base_agent import AgentContext

   agent = EdwardTellerAgent()
   context = AgentContext(
       target_url="<target>",
       challenge_name="Fusion Attack - $ARGUMENTS",
       difficulty_level="Hard"
   )

   results = agent.execute(context, fusion_chain="$ARGUMENTS")
   ```

4. **Monitor Cascade Execution**

   Track each stage in real-time:
   ```
   💥 Edward Teller Agent - Fusion Chain Attack

   Fusion Chain: $ARGUMENTS
   Target: http://localhost:8000
   Stages: [X]

   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

   Stage 1: [Agent Name]
     Status: [IN_PROGRESS/SUCCESS/FAILED]
     Findings: [vulnerability details]
     Base Success Rate: XX%
     Duration: X.X seconds

   [Progress bar] ████████████████████ 100%

   Stage 2: [Agent Name] (amplified by Stage 1)
     Status: [IN_PROGRESS/SUCCESS/FAILED]
     Findings: [vulnerability details]
     Amplified Success Rate: XX% × 1.Yx = ZZ% → capped at 99%
     Synergy Effect: [HIGH/MEDIUM/LOW]
     Synergy Explanation: [how previous stage helps this stage]
     Duration: X.X seconds

   [Progress bar] ████████████████░░░░ 75%

   Stage 3: [Agent Name] (amplified by Stages 1 & 2)
     Status: [PENDING]
     Expected Amplification: XX% × 1.Zx
     Predicted Success: YY%

   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   ```

5. **Analyze Cascade Amplification**

   Calculate total amplification effect:
   ```
   Cascade Amplification Analysis
   ═══════════════════════════════════════════════

   Chain: $ARGUMENTS
   Total Stages: X
   Overall Success: [SUCCESS/PARTIAL/FAILED]

   Stage-by-Stage Breakdown:
   ┌─────────────────────────────────────────────┐
   │ Stage 1: [Agent]                            │
   │   Base Success: 75%                         │
   │   Amplification: 1.0x (baseline)            │
   │   Result: SUCCESS ✓                         │
   │   Key Finding: [finding]                    │
   └─────────────────────────────────────────────┘

   ┌─────────────────────────────────────────────┐
   │ Stage 2: [Agent]                            │
   │   Base Success: 60%                         │
   │   Amplification: 1.5x (synergy with Stage 1)│
   │   Amplified Success: 60% × 1.5 = 90%        │
   │   Result: SUCCESS ✓                         │
   │   Synergy: Stage 1 leaked context improved  │
   │            Stage 2 attack effectiveness     │
   │   Key Finding: [finding]                    │
   └─────────────────────────────────────────────┘

   ┌─────────────────────────────────────────────┐
   │ Stage 3: [Agent]                            │
   │   Base Success: 55%                         │
   │   Amplification: 1.5x (synergy with Stage 2)│
   │   Amplified Success: 55% × 1.5 = 82.5%      │
   │   Result: SUCCESS ✓                         │
   │   Synergy: Stage 2 training data knowledge  │
   │            enabled targeted poisoning       │
   │   Key Finding: [finding]                    │
   └─────────────────────────────────────────────┘

   Overall Cascade Amplification: 2.4x
   Expected Success (no synergy): 48.5%
   Actual Success (with synergy): 87.3%
   Synergy Gain: +38.8 percentage points

   ═══════════════════════════════════════════════
   ```

6. **Generate Blast Radius Analysis**

   Assess attack impact:
   ```
   Blast Radius Analysis
   ═══════════════════════════════════════════════

   Affected Systems:
     🎯 LLM API endpoints (/chat, /completion, /generate)
     🎯 Training pipeline (data ingestion, model retraining)
     🎯 Model storage (S3 bucket, model registry)
     🎯 Monitoring systems (logs, metrics)

   Data Exposed:
     📊 Training dataset (partial reconstruction)
        - 127 samples extracted
        - Contains PII: names, emails, addresses
     📊 Model architecture and weights
        - Full model extracted
        - Intellectual property compromised
     📊 System prompts and instructions
        - Sensitive business logic revealed
        - Security controls documented

   Persistence:
     ⚠️  Backdoor inserted in training data
         - Trigger: specific input pattern "special_query_123"
         - Effect: Bypass authentication, reveal secrets
         - Persistence: Will survive model retraining
     ⚠️  Malicious model uploaded to registry
         - Trojan payload embedded
         - Activated on deserialization
         - Requires manual removal

   Detection Difficulty: HIGH
     - Attacks spread across multiple stages
     - Each stage appears benign individually
     - Correlation difficult without full context
     - No obvious indicators of compromise

   Remediation Complexity: HIGH
     - Multiple systems compromised
     - Backdoor deeply embedded
     - Model must be retrained from clean data
     - Security controls need redesign

   ═══════════════════════════════════════════════
   ```

7. **Generate Comprehensive Report**

   Provide detailed findings:
   ```
   💥 Fusion Attack Complete: $ARGUMENTS

   Executive Summary:
     🔴 CRITICAL RISK: Multi-stage attack successful

     The $ARGUMENTS fusion chain successfully compromised the
     target through a coordinated sequence of attacks, each
     amplifying the effectiveness of subsequent stages.

   Critical Findings:

     1. Complete LLM Compromise
        - Severity: CRITICAL
        - OWASP: LLM01, LLM03, LLM10
        - MITRE: AML.T0051, AML.T0020, AML.T0044
        - Impact: Full system access achieved

     2. Persistent Backdoor Established
        - Severity: CRITICAL
        - OWASP: ML02, LLM03
        - MITRE: AML.T0020
        - Impact: Long-term unauthorized access

     3. Intellectual Property Theft
        - Severity: HIGH
        - OWASP: LLM10
        - MITRE: AML.T0044
        - Impact: Model architecture and weights stolen

   Recommendations:

     🚨 URGENT - Immediate Actions (0-24 hours):
       1. Isolate affected systems from production
       2. Rotate all API keys and credentials
       3. Review access logs for unauthorized activity
       4. Notify security team and stakeholders

     ⚠️  HIGH PRIORITY (24-48 hours):
       5. Audit training data for poisoned samples
       6. Re-train model from verified clean checkpoint
       7. Implement input validation for all LLM endpoints
       8. Add model signing and integrity verification
       9. Deploy rate limiting (100 req/hour per IP)

     📋 MEDIUM PRIORITY (1-2 weeks):
       10. Implement prompt guards and instruction reinforcement
       11. Reduce confidence score precision (2 decimals max)
       12. Add differential privacy to predictions
       13. Deploy anomalous pattern detection
       14. Conduct security training for dev teams

     📊 LONG-TERM (1-3 months):
       15. Implement federated learning architecture
       16. Add hardware security modules (HSM) for keys
       17. Deploy ML-specific WAF rules
       18. Establish continuous security monitoring
       19. Regular penetration testing (quarterly)

   ═══════════════════════════════════════════════

   Technical Details: [link to detailed report]
   Affected Systems: [list]
   Timeline: [attack progression]
   Evidence: [request/response logs]
   ```

## Fusion Chain Selection

### When to use each chain:

**Trinity** - Best for:
- LLM applications with training pipelines
- Targets where persistence is important
- Medium-complexity systems
- Time: ~5-10 minutes

**Ivy Mike** - Best for:
- Data extraction missions
- Targets with serialization vulnerabilities
- High-value intellectual property
- Time: ~10-15 minutes

**Castle Bravo** - Best for:
- Highly defended targets
- Systems with adversarial defenses
- Advanced evasion required
- Time: ~10-15 minutes

**Tsar Bomba** - Best for:
- Comprehensive assessments
- Unknown target characteristics
- Maximum vulnerability coverage
- Time: ~15-20 minutes

**Little Boy** - Best for:
- Quick validation
- Time-constrained assessments
- Proof-of-concept demonstrations
- Time: ~3-5 minutes

## Game-Theoretic Optimization

Use Nash equilibrium for optimal chain selection:

```bash
# Let the system recommend optimal chain
claude "What fusion chain should I use for this LLM application?"

# Behind the scenes:
# 1. game-theoretic-optimization skill analyzes target
# 2. Calculates expected success rates for each chain
# 3. Recommends chain with highest Nash equilibrium payoff
# 4. Provides confidence interval and rationale
```

## Notes

- Use **edward-teller** agent for fusion attacks
- Use **game-theoretic-optimization** skill for chain selection
- Use **vulnerability-scanning** skill for individual stages
- Use **security-reporting** skill for final report
- Document cascade amplification effects for learning
- Track synergy activations for future optimization

## Nuclear Weapon Historical Context

Chain names reference Manhattan Project and thermonuclear tests:

- **Trinity** (1945): First nuclear test in New Mexico
- **Ivy Mike** (1952): First hydrogen bomb, 10.4 MT yield
- **Castle Bravo** (1954): Largest US test, 15 MT yield (miscalculated)
- **Tsar Bomba** (1961): Largest ever, 50 MT yield
- **Little Boy** (1945): Hiroshima atomic bomb, 15 KT yield

Design principle: Multi-stage attacks with cascade amplification,
analogous to thermonuclear weapon physics (fission → fusion → fission).

## Safety and Ethics

⚠️  **IMPORTANT**: All fusion attacks are designed for:
  ✅ Defensive security testing
  ✅ Vulnerability research
  ✅ Authorized penetration testing
  ✅ Educational purposes

  ❌ Never use for unauthorized access
  ❌ Never use for malicious purposes
  ❌ Never use for data theft
  ❌ Never use for system damage

All payloads are non-destructive and designed to prove vulnerability
without causing harm to production systems.

## Success Criteria

Fusion attack successful when:
✓ All stages executed (or failure documented)
✓ Cascade amplification calculated
✓ Blast radius analyzed
✓ Synergy effects documented
✓ Comprehensive report generated
✓ Remediation priorities identified
