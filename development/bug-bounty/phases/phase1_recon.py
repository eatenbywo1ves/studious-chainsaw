"""
Phase 1 — Recon & Scoping
==========================
Passive OSINT: DNS, robots.txt, security.txt, sitemap, headers, CVE lookup.
Results stored locally and can be pushed to mcp__memory__ graph.

Agents invoked (via prompts for Claude Code sessions):
  - search-specialist  → leaked creds, GitHub exposure
  - technical-researcher → CVEs for identified tech stack

MCP tools used:
  - WebFetch → passive URL fetching
  - mcp__memory__create_entities / add_observations
"""

import json
import re
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime
from typing import Optional


PASSIVE_PATHS = [
    "robots.txt",
    "sitemap.xml",
    ".well-known/security.txt",
    ".well-known/openid-configuration",
    "security.txt",
    "crossdomain.xml",
    "clientaccesspolicy.xml",
    "humans.txt",
    "README.md",
    "CHANGELOG.md",
    "api/swagger.json",
    "api/openapi.json",
    "swagger.json",
    "openapi.json",
    "v1/swagger.json",
    "api/v1/swagger.json",
    "graphql",
    "api/graphql",
    ".git/HEAD",
    ".env",
    "config.js",
    "app.js",
    "package.json",
]

RESPONSE_HEADERS_OF_INTEREST = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-wp-nonce",
    "x-content-type-options",
    "x-frame-options",
    "content-security-policy",
    "strict-transport-security",
    "access-control-allow-origin",
    "x-forwarded-for",
    "cf-ray",
]


def _fetch(url: str, timeout: int = 10) -> tuple[Optional[str], Optional[dict], int]:
    """Return (body, headers_dict, status_code). Body is None on error."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (security research)"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(65536).decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in resp.getheaders()}
            return body, headers, resp.status
    except urllib.error.HTTPError as e:
        return None, None, e.code
    except Exception:
        return None, None, 0


def _normalize_base(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target.rstrip("/")


def run_recon(target: str, output_dir: Path) -> None:
    base = _normalize_base(target)
    recon_dir = output_dir / "recon"
    recon_dir.mkdir(exist_ok=True)

    print(f"\n[PHASE 1] Recon — {target}")
    print("=" * 60)

    findings = {
        "target": target,
        "base_url": base,
        "timestamp": datetime.utcnow().isoformat(),
        "tech_fingerprint": [],
        "interesting_paths": [],
        "missing_security_headers": [],
        "exposed_files": [],
        "security_txt": None,
        "raw_headers": {},
    }

    # 1. Probe homepage headers for tech fingerprinting
    print("\n[1/4] Probing homepage headers...")
    body, headers, status = _fetch(base)
    if headers:
        findings["raw_headers"] = {k: v for k, v in headers.items() if k in RESPONSE_HEADERS_OF_INTEREST}
        print(f"      Status: {status}")
        for h in ["server", "x-powered-by", "x-aspnet-version", "x-generator"]:
            if h in headers:
                val = headers[h]
                findings["tech_fingerprint"].append(f"{h}: {val}")
                print(f"      [TECH] {h}: {val}")

        # Missing security headers
        required_security_headers = [
            "strict-transport-security",
            "content-security-policy",
            "x-content-type-options",
            "x-frame-options",
        ]
        for h in required_security_headers:
            if h not in headers:
                findings["missing_security_headers"].append(h)
                print(f"      [MISSING HEADER] {h}")
    else:
        print(f"      [WARN] Could not reach {base} (status {status})")

    # 2. Check passive disclosure paths
    print(f"\n[2/4] Checking {len(PASSIVE_PATHS)} passive paths...")
    for path in PASSIVE_PATHS:
        url = f"{base}/{path}"
        body, hdrs, status = _fetch(url)
        if status == 200 and body:
            entry = {"path": path, "url": url, "status": status, "preview": body[:300]}
            findings["interesting_paths"].append(entry)
            marker = "*** EXPOSED ***" if path in (".env", ".git/HEAD", "package.json") else "found"
            print(f"      [{status}] {path}  ({marker})")
            if path in (".env", ".git/HEAD"):
                findings["exposed_files"].append(url)

            # Store security.txt separately
            if "security.txt" in path:
                findings["security_txt"] = body[:2000]

    # 3. DNS-level notes (manual/passive — we log what we infer from HTTP)
    print("\n[3/4] Inferring tech stack from headers and responses...")
    tech_clues = _infer_tech(body or "", headers or {})
    findings["tech_fingerprint"].extend(tech_clues)
    for clue in tech_clues:
        print(f"      [TECH] {clue}")

    # 4. Generate agent prompts for manual OSINT steps
    print("\n[4/4] Generating OSINT agent prompts...")
    prompts = _generate_osint_prompts(target, findings["tech_fingerprint"])
    prompts_file = recon_dir / "osint_agent_prompts.md"
    prompts_file.write_text(prompts)
    print(f"      Agent prompts saved to {prompts_file}")
    print("      Run these prompts with search-specialist and technical-researcher agents.")

    # Save results
    out_file = recon_dir / "recon_results.json"
    out_file.write_text(json.dumps(findings, indent=2))
    print(f"\n[OK] Recon results saved to {out_file}")

    _print_recon_summary(findings)
    _print_memory_commands(target, findings)


def _infer_tech(body: str, headers: dict) -> list[str]:
    clues = []
    checks = [
        (r"wp-content|wp-includes|wordpress", "WordPress"),
        (r"drupal\.js|Drupal\.settings", "Drupal"),
        (r"joomla|/media/jui/", "Joomla"),
        (r"laravel_session|laravel", "Laravel"),
        (r"django|csrfmiddlewaretoken", "Django"),
        (r"rails|_rails_|ruby on rails", "Ruby on Rails"),
        (r"__next|_next/static", "Next.js"),
        (r"react-dom|__REACT", "React"),
        (r"ng-version|angular", "Angular"),
        (r"vue\.", "Vue.js"),
        (r"express", "Express.js"),
        (r"spring|springframework", "Spring Framework"),
        (r"jsessionid", "Java Servlet"),
        (r"phpsessid|\.php", "PHP"),
        (r"asp\.net|aspxauth|__viewstate", "ASP.NET"),
        (r"graphql|__schema", "GraphQL"),
        (r"swagger|openapi", "OpenAPI/Swagger"),
        (r"nginx", "Nginx"),
        (r"apache", "Apache"),
        (r"cloudflare|cf-ray", "Cloudflare CDN"),
    ]
    body_lower = body.lower()
    headers_str = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
    combined = body_lower + " " + headers_str
    for pattern, label in checks:
        if re.search(pattern, combined, re.IGNORECASE):
            clues.append(label)
    return list(set(clues))


def _generate_osint_prompts(target: str, tech_stack: list[str]) -> str:
    tech_list = ", ".join(tech_stack) if tech_stack else "unknown"
    return f"""# OSINT Agent Prompts for {target}

Generated: {datetime.utcnow().isoformat()}
Identified tech stack: {tech_list}

---

## search-specialist Agent Prompt

Use this prompt with the `search-specialist` agent in Claude Code:

```
Search for the following about target: {target}

1. GitHub repositories mentioning this domain or organization
2. Leaked credentials or API keys in public code (GitHub, GitLab, Pastebin)
3. Shodan/Censys-style exposure data for the domain
4. Job postings that reveal internal tech stack details
5. Wayback Machine / archive.org for old endpoints and parameters
6. Subdomain enumeration results from certificate transparency logs (crt.sh)
7. Cloud storage buckets (S3, GCS, Azure Blob) named after the domain

Tech stack identified: {tech_list}
Report all findings as potential attack surface items.
```

---

## technical-researcher Agent Prompt

Use this prompt with the `technical-researcher` agent in Claude Code:

```
Research known vulnerabilities for the following tech stack used by {target}:

Tech stack: {tech_list}

For each technology:
1. List critical and high CVEs from the past 2 years
2. Note any public exploits or PoCs available
3. Identify default credentials or common misconfigurations
4. Note any known authentication bypass techniques
5. List relevant OWASP Top 10 mappings

Format results as: [CVE-ID] | [Severity] | [Component] | [Description] | [PoC available: Y/N]
```

---

## Memory Graph Commands (mcp__memory__)

After running OSINT, store results with:

```python
# In Claude Code, invoke mcp__memory__create_entities with:
entities = [
    {{
        "name": "{target}",
        "entityType": "Target",
        "observations": [
            "Domain: {target}",
            "Tech stack: {tech_list}",
            # Add CVEs, exposed paths, notes here
        ]
    }}
]

# Then add findings as observations:
# mcp__memory__add_observations(entityName="{target}", contents=[...])
```
"""


def _print_recon_summary(findings: dict) -> None:
    print("\n" + "=" * 60)
    print("[PHASE 1 SUMMARY]")
    print(f"  Tech fingerprint : {', '.join(findings['tech_fingerprint']) or 'None detected'}")
    print(f"  Interesting paths: {len(findings['interesting_paths'])}")
    print(f"  Exposed files    : {len(findings['exposed_files'])}")
    if findings["exposed_files"]:
        for f in findings["exposed_files"]:
            print(f"    *** {f}")
    print(f"  Missing sec hdrs : {', '.join(findings['missing_security_headers']) or 'All present'}")
    print(f"  Security.txt     : {'Found' if findings['security_txt'] else 'Not found'}")


def _print_memory_commands(target: str, findings: dict) -> None:
    print("\n[NEXT] Store in memory graph (copy into Claude Code session):")
    print(f"  mcp__memory__create_entities → entity '{target}' with tech stack observations")
    print(f"  mcp__memory__add_observations → {len(findings['interesting_paths'])} path findings")
    print("\n[NEXT] Run agents:")
    print("  search-specialist   → osint_agent_prompts.md (search prompt)")
    print("  technical-researcher → osint_agent_prompts.md (CVE research prompt)")
    print("\n[NEXT] Proceed to Phase 2:")
    print(f"  python bounty.py surface {target}\n")
