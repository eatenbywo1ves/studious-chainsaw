You are performing batch security scanning of multiple targets using the ML-SecTest framework.

**Input File:** $ARGUMENTS

## Batch Scanning Workflow

1. **Validate Input File**

   Check file format and contents:
   ```bash
   cd development/ml-sectest-framework

   # Check file exists and format
   file $ARGUMENTS
   head -5 $ARGUMENTS
   ```

   Supported formats:
   - **CSV**: `target_url,challenge_name,difficulty`
   - **JSON**: `[{"target_url": "...", "challenge_name": "...", "difficulty": "..."}]`
   - **TXT**: One URL per line

2. **Parse Input File**

   Load targets based on format:

   **CSV Example:**
   ```csv
   target_url,challenge_name,difficulty
   http://target1.com,Challenge1,Easy
   http://target2.com,Challenge2,Hard
   http://localhost:8000,ProductionAPI,Medium
   ```

   **JSON Example:**
   ```json
   [
     {"target_url": "http://target1.com", "challenge_name": "Challenge1", "difficulty": "Easy"},
     {"target_url": "http://target2.com", "challenge_name": "Challenge2", "Hard"}
   ]
   ```

   **TXT Example:**
   ```
   http://target1.com
   http://target2.com
   http://localhost:8000
   ```

3. **Run Batch Scan**
   ```bash
   python ml_sectest.py batch-scan --input $ARGUMENTS --parallel
   ```

   Configuration:
   - Parallel execution for efficiency
   - Generate individual reports per target
   - Create aggregate summary report

4. **Monitor Progress**

   Track batch execution:
   ```
   Batch Scan Progress
   ═══════════════════════════════════════════════

   Total Targets: X
   Completed: Y (XX%)
   In Progress: Z
   Failed: W

   Current: http://target3.com
   Agent: prompt_injection_001
   Elapsed: 45.2 seconds

   Progress: [████████████████░░░░░░░░] 65%
   ```

5. **Aggregate Results**

   Generate comprehensive summary:
   ```
   📊 Batch Scan Results

   Input File: $ARGUMENTS
   Targets Scanned: X
   Total Duration: Y minutes
   Started: [timestamp]
   Completed: [timestamp]

   ═══════════════════════════════════════════════

   Overall Statistics:
     🔴 CRITICAL: X targets affected (XX%)
     🟠 HIGH: Y targets affected (YY%)
     🟡 MEDIUM: Z targets affected (ZZ%)
     🟢 LOW/SECURE: W targets (WW%)

   ═══════════════════════════════════════════════

   Most Common Vulnerabilities:
     1. Prompt Injection (OWASP LLM01) - XX targets
        Affected: [target1, target2, target3]

     2. Model Inversion (OWASP ML03) - YY targets
        Affected: [target4, target5]

     3. Data Poisoning (OWASP ML02) - ZZ targets
        Affected: [target6]

   ═══════════════════════════════════════════════

   Risk Distribution:

   HIGH RISK (Critical + High vulnerabilities):
     - http://target1.com: 2 critical, 3 high
     - http://target3.com: 1 critical, 2 high
     - http://target5.com: 3 critical, 1 high

   MEDIUM RISK (Medium vulnerabilities only):
     - http://target2.com: 2 medium
     - http://target4.com: 1 medium

   LOW RISK (Low or no vulnerabilities):
     - http://target6.com: 1 low
     - http://target7.com: Secure

   ═══════════════════════════════════════════════

   Detailed Reports:
     - Individual: reports/target1_TIMESTAMP.html
     - Individual: reports/target2_TIMESTAMP.html
     - Aggregate: reports/batch_summary_TIMESTAMP.json
     - Aggregate: reports/batch_summary_TIMESTAMP.html

   ═══════════════════════════════════════════════

   Recommendations:

   URGENT (Critical Issues):
     1. Patch prompt injection in target1.com, target3.com, target5.com
        - Implement input validation
        - Use prompt guards
        - Separate system/user instructions

     2. Address model inversion in target4.com, target5.com
        - Reduce confidence score precision
        - Add differential privacy
        - Implement rate limiting

   HIGH PRIORITY:
     3. Review all targets with HIGH severity findings
     4. Implement security controls organization-wide
     5. Schedule follow-up assessment in 30 days

   MEDIUM PRIORITY:
     6. Address medium-severity issues in target2.com, target4.com
     7. Improve logging and monitoring
     8. Conduct security training for development teams

   ═══════════════════════════════════════════════

   Export Options:
     - CSV summary: reports/batch_summary_TIMESTAMP.csv
     - JSON data: reports/batch_summary_TIMESTAMP.json
     - PDF report: Use security-reporting skill
   ```

6. **Provide Actionable Insights**

   - Prioritize targets by risk level
   - Identify common vulnerability patterns
   - Suggest organization-wide remediation
   - Offer to deep-dive into specific high-risk targets

## Parallel Execution Strategy

Optimize batch scanning performance:

```python
# Parallel execution configuration
max_workers = 4  # Concurrent scans
timeout_per_target = 300  # 5 minutes per target
retry_failed = True  # Retry failed scans once
```

Benefits:
- **Speed**: N targets in ~max(target_times) instead of sum(target_times)
- **Efficiency**: Utilize all available CPU cores
- **Resilience**: Failed scans don't block others

Trade-offs:
- Higher memory usage (O(N) vs O(1))
- More complex error handling
- Potential rate limiting from targets

## Error Handling

Gracefully handle failures:

```
Failed Scans:
  - http://target2.com: Connection timeout (retry: SUCCESS)
  - http://target5.com: 403 Forbidden (retry: FAILED)
  - http://target7.com: Invalid response format (retry: FAILED)

Partial Results:
  Successfully scanned: 7/10 targets (70%)
  Failed: 3/10 targets (30%)

Recommendation:
  - Review failed targets manually
  - Check firewall/WAF rules for 403 errors
  - Validate target URLs and endpoints
```

## Input File Templates

### CSV Template (batch_targets.csv)
```csv
target_url,challenge_name,difficulty
http://prod-api.example.com,Production API,High
http://staging-llm.example.com,Staging LLM,Medium
http://localhost:8000,Development,Low
```

### JSON Template (batch_targets.json)
```json
[
  {
    "target_url": "http://prod-api.example.com",
    "challenge_name": "Production API",
    "difficulty": "High",
    "notes": "Customer-facing API with PII"
  },
  {
    "target_url": "http://staging-llm.example.com",
    "challenge_name": "Staging LLM",
    "difficulty": "Medium",
    "notes": "Pre-production testing environment"
  }
]
```

### TXT Template (batch_targets.txt)
```
http://prod-api.example.com
http://staging-llm.example.com
http://localhost:8000
```

## Advanced Features

### Filtering and Selection

Scan subset of targets:
```bash
# Only scan high-priority targets
python ml_sectest.py batch-scan --input targets.csv --filter "difficulty=High"

# Only scan specific vulnerability types
python ml_sectest.py batch-scan --input targets.csv --agents prompt_injection_001
```

### Scheduling and Automation

Integrate with CI/CD:
```yaml
# Example: GitHub Actions
- name: Security Batch Scan
  run: |
    python ml_sectest.py batch-scan --input targets.csv --format json
    if [ $? -ne 0 ]; then
      echo "Critical vulnerabilities found!"
      exit 1
    fi
```

### Report Aggregation

Combine multiple batch scans:
```bash
# Merge weekly batch scan results
python ml_sectest.py aggregate-reports \
  --input reports/batch_week1.json \
         reports/batch_week2.json \
         reports/batch_week3.json \
  --output reports/monthly_summary.json
```

## Performance Metrics

Track batch scan performance:

```
Performance Summary
═══════════════════════════════════════════════

Total Targets: 25
Total Duration: 18.4 minutes
Average per Target: 44.2 seconds

Fastest Scan: target12 (12.3 seconds)
Slowest Scan: target7 (298.1 seconds)

Parallelization:
  Workers: 4
  Speedup: 3.8x (vs sequential)
  Efficiency: 95%

Resource Usage:
  Peak Memory: 2.4 GB
  Network Requests: 1,847
  Bandwidth: 45.2 MB
```

## Notes

- Use **vulnerability-scanning** skill for individual target scans
- Use **security-reporting** skill for aggregate reports
- Use **game-theoretic-optimization** skill for agent selection
- Store batch results for trend analysis
- Schedule regular batch scans (weekly/monthly)

## Best Practices

1. **Start small**: Test with 2-3 targets first
2. **Parallel wisely**: Don't overwhelm targets with requests
3. **Handle failures**: Expect some targets to fail
4. **Save results**: Archive reports for compliance
5. **Act on findings**: Batch scanning is only useful if you remediate
6. **Automate**: Schedule recurring scans via cron/CI/CD
7. **Monitor trends**: Track vulnerability counts over time

## CI/CD Integration Example

```yaml
name: Weekly Security Batch Scan

on:
  schedule:
    - cron: '0 0 * * 0'  # Every Sunday at midnight

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'

      - name: Install Dependencies
        run: |
          cd development/ml-sectest-framework
          pip install -r requirements.txt

      - name: Run Batch Scan
        run: |
          cd development/ml-sectest-framework
          python ml_sectest.py batch-scan \
            --input targets/production_targets.csv \
            --parallel \
            --format both

      - name: Upload Reports
        uses: actions/upload-artifact@v3
        with:
          name: security-reports
          path: development/ml-sectest-framework/reports/

      - name: Check for Critical Issues
        run: |
          # Parse JSON report and fail if critical issues found
          critical_count=$(jq '.results.severity_distribution.critical' \
            development/ml-sectest-framework/reports/batch_summary_*.json)

          if [ "$critical_count" -gt 0 ]; then
            echo "❌ CRITICAL: $critical_count critical vulnerabilities found!"
            exit 1
          fi
```

## Success Criteria

Batch scan successful when:
✓ All targets processed (or retry attempted)
✓ Individual reports generated per target
✓ Aggregate summary created
✓ Vulnerability distribution analyzed
✓ Remediation priorities identified
✓ Results exported for stakeholders
