"""
Phase 2 — Surface Mapping
==========================
Enumerate endpoints, input fields, auth boundaries.
Generates Puppeteer command sequences and endpoint inventory.

MCP tools used:
  - mcp__puppeteer__* (navigate, evaluate, fill, screenshot)
  - mcp__filesystem__write_file (save output)
  - /security-audit (Claude Code skill — if source available)

Outputs:
  - endpoint_map.json
  - puppeteer_crawl_script.md  (copy-paste Puppeteer MCP commands)
  - auth_boundaries.md
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Optional

import urllib.request
import urllib.error
import re


COMMON_AUTH_PATHS = [
    "/login", "/signin", "/auth", "/auth/login", "/api/auth/login",
    "/register", "/signup", "/auth/register",
    "/logout", "/signout", "/auth/logout",
    "/forgot-password", "/reset-password", "/password/reset",
    "/admin", "/admin/login", "/administrator",
    "/dashboard", "/account", "/profile", "/settings",
    "/api/v1/auth", "/api/v2/auth", "/api/auth",
    "/oauth/authorize", "/oauth/token",
    "/.auth/login", "/.auth/me",
    "/api/me", "/api/user", "/api/whoami",
]

COMMON_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/api/users", "/api/user", "/api/account",
    "/api/admin", "/api/orders", "/api/products",
    "/api/search", "/api/upload", "/api/files",
    "/api/keys", "/api/tokens", "/api/sessions",
    "/graphql", "/api/graphql",
    "/v1", "/v2", "/v3",
    "/health", "/healthz", "/ready", "/status",
    "/metrics", "/actuator", "/actuator/health",
    "/actuator/env", "/actuator/beans",
    "/debug", "/debug/vars", "/__debug__",
    "/swagger-ui", "/swagger-ui.html",
    "/api-docs", "/api/docs",
    "/openapi.json", "/swagger.json",
]


def _normalize_base(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target.rstrip("/")


def _quick_probe(url: str) -> int:
    try:
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": "Mozilla/5.0 (security research)"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def run_surface_map(target: str, output_dir: Path) -> None:
    base = _normalize_base(target)
    surface_dir = output_dir / "surface"
    surface_dir.mkdir(exist_ok=True)

    print(f"\n[PHASE 2] Surface Mapping — {target}")
    print("=" * 60)

    results = {
        "target": target,
        "base_url": base,
        "timestamp": datetime.utcnow().isoformat(),
        "auth_endpoints": [],
        "api_endpoints": [],
        "reachable_endpoints": [],
        "redirect_endpoints": [],
    }

    # 1. Probe auth paths
    print(f"\n[1/3] Probing {len(COMMON_AUTH_PATHS)} auth paths...")
    for path in COMMON_AUTH_PATHS:
        url = f"{base}{path}"
        status = _quick_probe(url)
        if status in (200, 201, 301, 302, 307, 308, 401, 403):
            entry = {"url": url, "path": path, "status": status}
            results["auth_endpoints"].append(entry)
            tag = "[AUTH BOUNDARY]" if status in (401, 403) else "[FOUND]"
            print(f"      {status} {path}  {tag}")

    # 2. Probe API paths
    print(f"\n[2/3] Probing {len(COMMON_API_PATHS)} API paths...")
    for path in COMMON_API_PATHS:
        url = f"{base}{path}"
        status = _quick_probe(url)
        if status in (200, 201, 301, 302, 307, 308, 401, 403):
            entry = {"url": url, "path": path, "status": status}
            results["api_endpoints"].append(entry)
            if status == 200:
                results["reachable_endpoints"].append(url)
            print(f"      {status} {path}")

    # 3. Generate Puppeteer crawl commands
    print("\n[3/3] Generating Puppeteer crawl script...")
    pup_script = _generate_puppeteer_script(base, results)
    pup_file = surface_dir / "puppeteer_crawl_script.md"
    pup_file.write_text(pup_script)
    print(f"      Saved to {pup_file}")

    # 4. Generate auth boundary analysis
    auth_doc = _generate_auth_analysis(base, results)
    auth_file = surface_dir / "auth_boundaries.md"
    auth_file.write_text(auth_doc)

    # Save results
    out_file = surface_dir / "endpoint_map.json"
    out_file.write_text(json.dumps(results, indent=2))

    _print_summary(results, surface_dir)


def _generate_puppeteer_script(base: str, results: dict) -> str:
    reachable = [e["url"] for e in results["auth_endpoints"] if e["status"] == 200][:10]
    lines = [
        f"# Puppeteer Crawl Script for {base}",
        f"Generated: {datetime.utcnow().isoformat()}",
        "",
        "## Instructions",
        "Copy each block into a Claude Code session and invoke the corresponding MCP tool.",
        "Take a screenshot after each navigation for evidence.",
        "",
        "---",
        "",
        "## Step 1 — Homepage reconnaissance",
        "",
        "```",
        f"mcp__puppeteer__puppeteer_navigate(url='{base}')",
        "mcp__puppeteer__puppeteer_screenshot(name='01_homepage')",
        "mcp__puppeteer__puppeteer_evaluate(script=`",
        "  // Extract all links, forms, and input fields",
        "  const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href);",
        "  const forms = Array.from(document.querySelectorAll('form')).map(f => ({",
        "    action: f.action, method: f.method,",
        "    inputs: Array.from(f.querySelectorAll('input,textarea,select')).map(i => ({",
        "      name: i.name, type: i.type, id: i.id",
        "    }))",
        "  }));",
        "  const scripts = Array.from(document.querySelectorAll('script[src]')).map(s => s.src);",
        "  JSON.stringify({ links: links.slice(0,50), forms, scripts: scripts.slice(0,20) });",
        "`)",
        "```",
        "",
        "---",
        "",
        "## Step 2 — Auth flow screenshot",
        "",
    ]
    for url in reachable[:5]:
        path = url.replace(base, "")
        safe_name = re.sub(r"[^a-z0-9]", "_", path.lower()).strip("_") or "auth"
        lines += [
            "```",
            f"mcp__puppeteer__puppeteer_navigate(url='{url}')",
            f"mcp__puppeteer__puppeteer_screenshot(name='02_{safe_name}')",
            "mcp__puppeteer__puppeteer_evaluate(script=`",
            "  document.title + ' | ' + document.location.href",
            "`)",
            "```",
            "",
        ]
    lines += [
        "---",
        "",
        "## Step 3 — Form input extraction + XSS probe",
        "",
        "For each form found in Step 1, run:",
        "",
        "```",
        "# Navigate to form page",
        f"mcp__puppeteer__puppeteer_navigate(url='FORM_URL')",
        "",
        "# Fill input with XSS probe (test only — non-destructive reflection test)",
        "mcp__puppeteer__puppeteer_fill(",
        "  selector='input[name=FIELD_NAME]',",
        "  value='<script>alert(document.domain)</script>'",
        ")",
        "mcp__puppeteer__puppeteer_screenshot(name='03_xss_input_probe')",
        "",
        "# Check if reflected",
        "mcp__puppeteer__puppeteer_evaluate(script=`",
        "  document.body.innerHTML.includes('alert(document.domain)')",
        "`)",
        "mcp__puppeteer__puppeteer_screenshot(name='03_xss_result')",
        "```",
        "",
        "---",
        "",
        "## Step 4 — Cookie and session inspection",
        "",
        "```",
        f"mcp__puppeteer__puppeteer_navigate(url='{base}')",
        "mcp__puppeteer__puppeteer_evaluate(script=`",
        "  // Inspect cookies for security flags",
        "  document.cookie",
        "`)",
        "mcp__puppeteer__puppeteer_evaluate(script=`",
        "  // Check localStorage for tokens",
        "  JSON.stringify(Object.keys(localStorage))",
        "`)",
        "mcp__puppeteer__puppeteer_evaluate(script=`",
        "  // Check sessionStorage",
        "  JSON.stringify(Object.keys(sessionStorage))",
        "`)",
        "```",
        "",
        "---",
        "",
        "## Step 5 — JS source endpoint harvesting",
        "",
        "```",
        f"mcp__puppeteer__puppeteer_navigate(url='{base}')",
        "mcp__puppeteer__puppeteer_evaluate(script=`",
        "  // Extract API endpoints from inline JS",
        "  const scripts = Array.from(document.querySelectorAll('script:not([src])'));",
        "  const text = scripts.map(s => s.textContent).join('\\n');",
        "  const endpoints = text.match(/['\\\"](\\/api\\/[^'\\\"\\s]+)['\\\"]|fetch\\(['\\\"]([^'\\\"]+)['\\\"]\\)/g);",
        "  JSON.stringify([...new Set(endpoints || [])].slice(0, 100));",
        "`)",
        "```",
    ]
    return "\n".join(lines)


def _generate_auth_analysis(base: str, results: dict) -> str:
    auth_200 = [e for e in results["auth_endpoints"] if e["status"] == 200]
    auth_401 = [e for e in results["auth_endpoints"] if e["status"] == 401]
    auth_403 = [e for e in results["auth_endpoints"] if e["status"] == 403]
    return f"""# Auth Boundary Analysis — {base}

Generated: {datetime.utcnow().isoformat()}

## Summary

| Category | Count |
|----------|-------|
| Accessible (200) | {len(auth_200)} |
| Requires auth (401) | {len(auth_401)} |
| Forbidden (403) | {len(auth_403)} |
| API endpoints found | {len(results["api_endpoints"])} |

## Auth Endpoints (200 — No auth required)

{chr(10).join(f'- {e["url"]}' for e in auth_200) or '- None found'}

## Protected Endpoints (401)

{chr(10).join(f'- {e["url"]}' for e in auth_401) or '- None found'}

## Forbidden Endpoints (403)

{chr(10).join(f'- {e["url"]}' for e in auth_403) or '- None found'}

## Testing Notes

- Check 401 endpoints for auth bypass (parameter tampering, JWT alg:none)
- Check 403 endpoints for HTTP method bypass (GET → POST, X-HTTP-Method-Override)
- Look for IDOR on any endpoint accepting object IDs
- Test for mass assignment on POST/PUT endpoints

## Recommended Tests (Phase 3)

```bash
# Phase 3A - Web testing
python bounty.py test web {results['target']}

# Phase 3B - API testing
python bounty.py test api {results['target']}
```
"""


def _print_summary(results: dict, surface_dir: Path) -> None:
    total = len(results["auth_endpoints"]) + len(results["api_endpoints"])
    reachable = len(results["reachable_endpoints"])
    print(f"\n[PHASE 2 SUMMARY]")
    print(f"  Endpoints found  : {total}")
    print(f"  Reachable (200)  : {reachable}")
    print(f"  Auth boundaries  : {len([e for e in results['auth_endpoints'] if e['status'] in (401,403)])}")
    print(f"  API endpoints    : {len(results['api_endpoints'])}")
    print(f"\n[FILES]")
    print(f"  {surface_dir}/endpoint_map.json")
    print(f"  {surface_dir}/puppeteer_crawl_script.md")
    print(f"  {surface_dir}/auth_boundaries.md")
    print(f"\n[NEXT] Run Puppeteer commands from puppeteer_crawl_script.md")
    print(f"[NEXT] Proceed to Phase 3:")
    print(f"  python bounty.py test web {results['target']}")
    print(f"  python bounty.py test api {results['target']}\n")
