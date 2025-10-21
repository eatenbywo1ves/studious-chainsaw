You are performing a comprehensive security assessment using the ML-SecTest framework.

**Target URL:** $ARGUMENTS

## Assessment Workflow

1. **Initialize Framework**
   ```bash
   cd development/ml-sectest-framework
   ```

2. **Run Security Scan**
   ```bash
   python ml_sectest.py scan $ARGUMENTS --parallel --format both
   ```

3. **Analyze Results**
   - Load generated reports from `reports/`
   - Summarize findings by severity (Critical, High, Medium, Low)
   - Map vulnerabilities to OWASP/MITRE references

4. **Present Findings**

   Format as:
   ```
   🔍 Security Assessment Complete

   Target: $ARGUMENTS
   Duration: X.X seconds

   Findings:
     🔴 CRITICAL: X vulnerabilities
     🟠 HIGH: X vulnerabilities
     🟡 MEDIUM: X vulnerabilities
     🟢 LOW: X vulnerabilities

   Critical Issues:
     1. [Vulnerability Type] (OWASP/MITRE) - Description
     2. ...

   Recommendations:
     - Prioritized remediation steps

   Full Report: reports/scan_TIMESTAMP.html
   ```

5. **Provide Recommendations**
   - Link to OWASP/MITRE documentation
   - Suggest remediation priorities
   - Offer to generate detailed fix guidance

## Notes

- Use the vulnerability-scanning skill for payload generation
- Use the security-reporting skill for final report formatting
- Use game-theoretic-optimization skill if multiple agents need coordination
- All findings should include OWASP/MITRE references for compliance tracking
