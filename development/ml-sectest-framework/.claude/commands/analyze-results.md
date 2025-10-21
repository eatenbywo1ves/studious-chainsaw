You are analyzing security assessment results from the ML-SecTest framework.

**Report File:** $ARGUMENTS

## Result Analysis Workflow

1. **Load and Parse Report**

   Identify report format and load data:
   ```bash
   cd development/ml-sectest-framework

   # Check file format
   file $ARGUMENTS

   # Read report based on format
   # HTML: Parse for structured data
   # JSON: Load directly
   # TXT: Parse summary format
   ```

   Expected report locations:
   - Individual scans: `reports/scan_TIMESTAMP.{html,json}`
   - Batch scans: `reports/batch_summary_TIMESTAMP.{html,json}`
   - CTF challenges: `reports/challenge_TIMESTAMP.{html,json}`

2. **Extract Key Metrics**

   Parse report for essential statistics:
   ```
   Report Metadata:
     Generated: [timestamp]
     Framework Version: [version]
     Scan ID: [id]

   Target Information:
     URL: [target_url]
     Challenge: [name]
     Difficulty: [level]

   Execution Metrics:
     Duration: [seconds]
     Agents Executed: [count]
     Tests Performed: [count]

   Results Summary:
     Overall Status: [VULNERABLE/SECURE/CRITICAL]
     Success Rate: [percentage]%
   ```

3. **Analyze Vulnerability Distribution**

   Categorize and prioritize findings:
   ```
   Vulnerability Distribution
   ═══════════════════════════════════════════════

   By Severity:
     🔴 CRITICAL: X vulnerabilities (XX%)
        - Immediate risk to system security
        - Exploitation likely/trivial
        - Data breach or system compromise possible

     🟠 HIGH: Y vulnerabilities (YY%)
        - Significant security risk
        - Should be remediated quickly
        - Potential for privilege escalation

     🟡 MEDIUM: Z vulnerabilities (ZZ%)
        - Moderate security risk
        - Remediate within planned cycle
        - Defense-in-depth concerns

     🟢 LOW: W vulnerabilities (WW%)
        - Minor security concerns
        - Address as resources permit
        - Best practice improvements

   By Category (OWASP):
     LLM01 (Prompt Injection): X findings
     LLM03 (Training Data Poisoning): Y findings
     LLM05 (Supply Chain): Z findings
     LLM10 (Model Theft): W findings
     ML02 (Data Poisoning): V findings
     ML03 (Model Inversion): U findings

   By Attack Type:
     Injection Attacks: XX%
     Privacy Violations: YY%
     Model Theft: ZZ%
     Supply Chain: WW%
     Other: VV%
   ```

4. **Identify Attack Chains**

   Detect multi-stage exploitation paths:
   ```
   Attack Chain Analysis
   ═══════════════════════════════════════════════

   Chain 1: Prompt Injection → Data Exfiltration
     Stage 1: Prompt Injection (CRITICAL)
       - Agent: prompt_injection_001
       - Finding: Direct instruction override successful
       - Impact: System access achieved

     Stage 2: Data Exfiltration (HIGH)
       - Enabled by: Stage 1 system access
       - Finding: Training data accessible
       - Impact: PII exposed

     Cascade Risk: CRITICAL
     Recommendation: Fix Stage 1 immediately to break chain

   Chain 2: Model Inversion → Membership Inference
     Stage 1: Confidence Score Exposure (MEDIUM)
       - Agent: model_inversion_001
       - Finding: 5-decimal precision exposed
       - Impact: Membership inference possible

     Stage 2: Training Data Reconstruction (HIGH)
       - Enabled by: Stage 1 confidence scores
       - Finding: 127 training samples reconstructed
       - Impact: Privacy violation (GDPR)

     Cascade Risk: HIGH
     Recommendation: Reduce confidence precision to 2 decimals
   ```

5. **Generate Risk Assessment**

   Calculate overall risk profile:
   ```
   Risk Assessment
   ═══════════════════════════════════════════════

   Overall Risk Level: [CRITICAL/HIGH/MEDIUM/LOW]

   Risk Calculation:
     Vulnerability Count: X total
     Critical Severity: Y (weight: 10x)
     High Severity: Z (weight: 5x)
     Medium Severity: W (weight: 2x)
     Low Severity: V (weight: 1x)

     Risk Score: (Y*10 + Z*5 + W*2 + V*1) = XXX

     Risk Level Thresholds:
       CRITICAL: Score ≥ 50
       HIGH: Score ≥ 20
       MEDIUM: Score ≥ 5
       LOW: Score < 5

   Risk Breakdown by System Component:
     API Endpoints: HIGH RISK
       - 3 critical, 2 high vulnerabilities
       - Public-facing attack surface
       - Handles sensitive data

     Training Pipeline: MEDIUM RISK
       - 0 critical, 1 high, 2 medium vulnerabilities
       - Internal system with limited access
       - Data poisoning concerns

     Model Storage: LOW RISK
       - 0 critical, 0 high, 1 medium vulnerability
       - Access controls in place
       - Regular integrity checks

   Business Impact:
     Data Breach Risk: HIGH (PII exposure via model inversion)
     Reputation Risk: HIGH (AI system compromise)
     Compliance Risk: CRITICAL (GDPR violations possible)
     Financial Risk: HIGH (model IP theft)
     Availability Risk: MEDIUM (DoS via resource exhaustion)
   ```

6. **Provide Prioritized Recommendations**

   Generate actionable remediation plan:
   ```
   Remediation Plan
   ═══════════════════════════════════════════════

   🚨 URGENT (0-24 hours):

     1. Patch Critical Prompt Injection Vulnerability
        Location: /api/chat endpoint
        OWASP: LLM01
        Impact: Remote code execution possible
        Fix: Implement input validation and sanitization
        Effort: 4 hours
        Resources: 1 senior developer
        Cost: $500

     2. Disable Exposed Confidence Scores
        Location: /api/predict endpoint
        OWASP: ML03
        Impact: Training data reconstruction
        Fix: Round confidence to 2 decimals
        Effort: 2 hours
        Resources: 1 developer
        Cost: $250

   ⚠️  HIGH PRIORITY (24-72 hours):

     3. Implement Rate Limiting
        Location: All API endpoints
        OWASP: LLM06, LLM10
        Impact: Prevents model extraction and DoS
        Fix: 100 requests/hour per IP
        Effort: 8 hours
        Resources: 1 developer + DevOps
        Cost: $1,200

     4. Add Prompt Guards
        Location: LLM processing pipeline
        OWASP: LLM01
        Impact: Defense against injection attacks
        Fix: Instruction reinforcement, delimiter detection
        Effort: 16 hours
        Resources: 2 developers
        Cost: $2,400

   📋 MEDIUM PRIORITY (1-2 weeks):

     5. Audit Training Data
        Location: Training pipeline
        OWASP: ML02, LLM03
        Impact: Remove poisoned samples
        Fix: Data provenance tracking, validation
        Effort: 40 hours
        Resources: Data science team
        Cost: $6,000

     6. Implement Model Signing
        Location: Model deployment pipeline
        OWASP: LLM05, ML06
        Impact: Prevent malicious model uploads
        Fix: Cryptographic signatures, integrity checks
        Effort: 24 hours
        Resources: 2 developers + security
        Cost: $3,600

   📊 LONG-TERM (1-3 months):

     7. Migrate to Federated Learning
        Impact: Decentralize training data
        Effort: 200+ hours
        Cost: $30,000+

     8. Implement Differential Privacy
        Impact: Privacy-preserving predictions
        Effort: 80 hours
        Cost: $12,000

   Total Estimated Cost (Urgent + High):
     Labor: $4,350
     Additional Tools/Services: $500
     Total: $4,850

   Total Estimated Effort:
     Urgent: 6 hours
     High Priority: 24 hours
     Total: 30 hours (3.75 developer-days)
   ```

7. **Trend Analysis** (if multiple reports available)

   Compare with historical data:
   ```
   Trend Analysis
   ═══════════════════════════════════════════════

   Comparing with Previous Scans:

   Vulnerability Trend (Last 4 Scans):
     Week 1: 12 vulnerabilities (3 critical)
     Week 2: 10 vulnerabilities (2 critical) ↓ 16% improvement
     Week 3: 8 vulnerabilities (2 critical) ↓ 20% improvement
     Week 4: 6 vulnerabilities (1 critical) ↓ 25% improvement

     Overall Trend: IMPROVING ✓
     Critical Reduction: 67% (3 → 1)
     Total Reduction: 50% (12 → 6)

   New Vulnerabilities Introduced:
     - Model Inversion (OWASP ML03) - FIRST SEEN
       Likely cause: Recent API change exposing confidence scores
       Recommendation: Review recent deployments

   Recurring Vulnerabilities:
     - Prompt Injection (OWASP LLM01) - 4th occurrence
       Status: Partially remediated but resurfaces
       Recommendation: Implement comprehensive solution, not patches

   Security Posture:
     Starting Point (Week 1): HIGH RISK
     Current State (Week 4): MEDIUM RISK
     Target State: LOW RISK
     Progress: 50% toward target

     Estimated Time to Low Risk: 4-6 weeks
     Required Actions: Complete high-priority items
   ```

8. **Generate Executive Summary**

   Create stakeholder-friendly overview:
   ```
   Executive Summary
   ═══════════════════════════════════════════════

   Security Assessment Overview

   Target: [Application Name]
   Assessment Date: [date]
   Overall Risk: [CRITICAL/HIGH/MEDIUM/LOW]

   Key Findings:
     • [X] critical vulnerabilities requiring immediate attention
     • [Y] high-priority issues to address within 72 hours
     • [Z] medium-priority items for planned remediation

   Top Risks:
     1. Prompt Injection enabling unauthorized system access
     2. Training data exposure via model inversion
     3. Insufficient rate limiting allowing model extraction

   Business Impact:
     • Data Privacy: GDPR compliance at risk
     • Reputation: AI system compromise could damage trust
     • Financial: Model intellectual property vulnerable to theft

   Recommended Actions:
     Immediate: Patch critical prompt injection ($500, 4 hours)
     Short-term: Implement rate limiting and prompt guards ($3,600, 24 hours)
     Long-term: Comprehensive security architecture review

   Cost to Remediate Critical Issues: $4,850
   Estimated Timeline: 1-2 weeks for critical and high-priority items

   [Link to detailed technical report]
   ```

## Advanced Analysis Features

### Comparison with Benchmarks

Compare against industry standards:
```
Benchmark Comparison
═══════════════════════════════════════════════

Your Results vs. Industry Average:

ML/AI Application Security (OWASP Benchmark):
  Your Score: 6.5/10
  Industry Average: 7.2/10
  Gap: -0.7 (below average)

  Categories:
    Prompt Injection Defense: 5/10 (Industry: 7/10)
    Model Protection: 8/10 (Industry: 7/10) ✓
    Data Privacy: 6/10 (Industry: 7/10)
    Supply Chain: 7/10 (Industry: 8/10)

Recommendation: Focus on prompt injection defenses to reach
                industry average.
```

### False Positive Analysis

Identify potential false positives:
```
False Positive Review
═══════════════════════════════════════════════

Findings Requiring Validation:

1. Model Extraction (MEDIUM) - Confidence: 60%
   Reason: Limited query budget may not be sufficient
   Recommendation: Manual verification recommended
   Validation effort: 30 minutes

2. Backdoor Detection (LOW) - Confidence: 40%
   Reason: Statistical anomaly, not confirmed exploit
   Recommendation: Investigate but likely false positive
   Validation effort: 1 hour

Confirmed True Positives: 8/10 findings (80%)
Potential False Positives: 2/10 findings (20%)
```

## Notes

- Use **security-reporting** skill for report generation
- Use **vulnerability-scanning** skill for detailed context
- Historical trend analysis requires multiple scan reports
- Compare with OWASP benchmarks when available
- Share executive summary with non-technical stakeholders

## Output Formats

Support multiple analysis output formats:

- **Console**: Quick terminal summary
- **HTML**: Interactive analysis dashboard
- **JSON**: Machine-readable for integration
- **PDF**: Executive presentation format
- **CSV**: Vulnerability tracking spreadsheet

## Integration with Other Skills

- **security-reporting**: Source of analysis data
- **payload-crafting**: Context for vulnerability types
- **game-theoretic-optimization**: Attack chain analysis
- **ctf-challenge-solver**: CTF-specific insights

## Success Criteria

Analysis successful when:
✓ Report loaded and parsed correctly
✓ Vulnerabilities categorized by severity
✓ Attack chains identified
✓ Risk assessment calculated
✓ Prioritized recommendations generated
✓ Actionable insights provided to stakeholders
