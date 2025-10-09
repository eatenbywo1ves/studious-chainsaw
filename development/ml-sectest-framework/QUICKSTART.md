# ML-SecTest Quick Start Guide

Get started with ML-SecTest in 5 minutes!

## Installation

```bash
cd ml-sectest-framework
pip install -r requirements.txt
```

## Your First Security Scan

### 1. List Available CTF Challenges

```bash
python ml_sectest.py list-challenges
```

Expected output:
```
📚 Available CTF Challenges:
═══════════════════════════════════════════════════════════════════════

🎯 VAULT
   Name: Vault - Model Inversion
   Difficulty: Hard
   OWASP: OWASP ML03
   Agents: model_inversion_001

🎯 DOLOS
   Name: Dolos - Prompt Injection to RCE
   Difficulty: Easy
   OWASP: OWASP LLM01
   MITRE: AML.T0051
   Agents: prompt_injection_001
...
```

### 2. Test a Specific Challenge

```bash
python ml_sectest.py test-challenge dolos
```

You'll be prompted for the target URL:
```
🌐 Enter target URL: http://localhost:8000
```

### 3. Scan a Custom Target

```bash
python ml_sectest.py scan http://localhost:8000 --name "My ML App"
```

### 4. Advanced Scanning

```bash
# Use specific agents only
python ml_sectest.py scan http://localhost:8000 \
    --agents prompt_injection_001 model_inversion_001

# Parallel execution for faster results
python ml_sectest.py scan http://localhost:8000 --parallel

# JSON output only
python ml_sectest.py scan http://localhost:8000 --format json
```

## Understanding Results

### Security Status Levels

- **🟢 SECURE**: No vulnerabilities detected
- **🟡 PARTIALLY_VULNERABLE**: Some tests failed, minor issues
- **🟠 VULNERABLE**: Multiple vulnerabilities found
- **🔴 CRITICAL**: Severe vulnerabilities, immediate action required

### Reading Reports

Reports are saved in the `reports/` directory:

**HTML Report** (`*_report.html`):
- Open in any web browser
- Executive summary with metrics
- Detailed findings with evidence
- Color-coded severity indicators

**JSON Report** (`*_report.json`):
- Machine-readable format
- Integration with CI/CD pipelines
- Programmatic analysis

## Example Output

```
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║   ███╗   ███╗██╗         ███████╗███████╗ ██████╗████████╗███████╗  ║
║   ████╗ ████║██║         ██╔════╝██╔════╝██╔════╝╚══██╔══╝██╔════╝  ║
║   ██╔████╔██║██║         ███████╗█████╗  ██║        ██║   █████╗    ║
║   ██║╚██╔╝██║██║         ╚════██║██╔══╝  ██║        ██║   ██╔══╝    ║
║   ██║ ╚═╝ ██║███████╗    ███████║███████╗╚██████╗   ██║   ███████╗  ║
║   ╚═╝     ╚═╝╚══════╝    ╚══════╝╚══════╝ ╚═════╝   ╚═╝   ╚══════╝  ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝

🎯 Target: http://localhost:8000
📋 Challenge: Dolos - Prompt Injection to RCE
═══════════════════════════════════════════════════════════════════════

[2025-10-08 14:30:15] [ORCHESTRATOR] INFO: Starting Security Assessment
[2025-10-08 14:30:15] [prompt_injection_001] INFO: Phase 1: Vulnerability Analysis
[2025-10-08 14:30:18] [prompt_injection_001] INFO: Phase 2: Defensive Exploitation
[2025-10-08 14:30:22] [ORCHESTRATOR] INFO: Security Assessment Complete

═══════════════════════════════════════════════════════════════════════
🔒 SECURITY ASSESSMENT SUMMARY
═══════════════════════════════════════════════════════════════════════

🔴 Overall Status: VULNERABLE
📈 Success Rate: 75.0%
⏱️  Duration: 7.23s
🔍 Vulnerabilities Found: 2

⚠️  Detected Vulnerabilities:
   • Prompt Injection
   • SQL Injection

📊 Generating reports...
✅ HTML Report: reports/dolos_report.html
✅ JSON Report: reports/dolos_report.json
```

## Common Use Cases

### CTF Competitions

```bash
# Test the Vault challenge
python ml_sectest.py test-challenge vault

# Test Dolos II (Prompt Injection → SQLi)
python ml_sectest.py test-challenge dolos2
```

### Security Audits

```bash
# Comprehensive scan with all agents
python ml_sectest.py scan https://ml-api.example.com --parallel

# Focus on specific vulnerabilities
python ml_sectest.py scan https://ml-api.example.com \
    --agents model_extraction_001 adversarial_attack_001
```

### CI/CD Integration

```bash
# JSON output for parsing in CI/CD
python ml_sectest.py scan $TARGET_URL --format json

# Check exit code (0 = secure, 1 = vulnerable)
if python ml_sectest.py scan $TARGET_URL; then
    echo "Security check passed"
else
    echo "Vulnerabilities detected!"
    exit 1
fi
```

## Programmatic Usage

```python
from ml_sectest import MLSecTest

# Initialize
app = MLSecTest()

# Test specific challenge
app.test_challenge('vault', target_url='http://localhost:8000')

# Custom scan
app.scan_target(
    target_url='http://my-ml-app.com',
    challenge_name='Production Security Audit',
    agents=['prompt_injection_001', 'model_extraction_001'],
    parallel=True,
    output_format='both'
)
```

## Troubleshooting

### "Connection refused" errors

**Problem**: Target application not running
```bash
# Check if target is accessible
curl http://localhost:8000
```

**Solution**: Start your ML application first

### "No module named 'core'" errors

**Problem**: Running from wrong directory
```bash
# Navigate to framework root
cd ml-sectest-framework

# Then run
python ml_sectest.py scan http://localhost:8000
```

### Slow scans

**Problem**: Sequential execution is slow
```bash
# Use parallel execution
python ml_sectest.py scan http://localhost:8000 --parallel
```

### Rate limiting detected

**Problem**: Target has aggressive rate limiting

**Solution**: Agents automatically detect and respect rate limits. If needed, modify timeout values in the code or run tests with longer intervals.

## Next Steps

1. **Read the full documentation**: See `README.md` for comprehensive guide
2. **Explore examples**: Check `examples/basic_usage.py` for code samples
3. **Understand architecture**: Read `ARCHITECTURE.md` for system design
4. **Customize agents**: Create your own agents for specific vulnerabilities
5. **Integrate with CI/CD**: Add security testing to your deployment pipeline

## Getting Help

- **Examples**: `examples/basic_usage.py`
- **Architecture**: `ARCHITECTURE.md`
- **Full README**: `README.md`
- **Agent code**: `agents/` directory
- **Core framework**: `core/` directory

## Security & Ethics Reminder

⚠️ **IMPORTANT**: Only test systems you own or have explicit permission to test.

This framework is for **defensive security research only**. Unauthorized testing of systems is illegal and unethical.

---

**Happy Testing! 🛡️**
