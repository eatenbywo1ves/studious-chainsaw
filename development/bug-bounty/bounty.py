#!/usr/bin/env python3
"""
Bug Bounty Workflow CLI
========================
Orchestrates a structured, agent-assisted bug bounty methodology across:
  Phase 1 - Recon & Scoping
  Phase 2 - Surface Mapping
  Phase 3 - Vulnerability Testing (Web / API / AI-ML / Binary)
  Phase 4 - Exploitation & PoC
  Phase 5 - Reporting

Authorization is REQUIRED for all targets.
Use `bounty init` to store scope confirmation before testing.

Usage:
    python bounty.py init <target>              # Register target + confirm scope
    python bounty.py recon <target>             # Phase 1: passive recon
    python bounty.py surface <target>           # Phase 2: endpoint mapping
    python bounty.py test web <target>          # Phase 3A: OWASP web testing
    python bounty.py test api <target>          # Phase 3B: API security
    python bounty.py test ai <target_url>       # Phase 3C: AI/ML testing
    python bounty.py test binary <file>         # Phase 3D: binary analysis
    python bounty.py exploit <target> <finding> # Phase 4: PoC development
    python bounty.py report <target>            # Phase 5: generate report
    python bounty.py status <target>            # Show all findings for target
    python bounty.py targets                    # List all tracked targets
"""

import argparse
import sys
import json
import subprocess
from pathlib import Path
from datetime import datetime

from config.memory_schema import TargetEntity, Finding, ScopeRecord
from config.severity import cvss_vector_prompt, severity_label
from phases.phase1_recon import run_recon
from phases.phase2_surface import run_surface_map
from phases.phase3_web import run_web_tests
from phases.phase3_api import run_api_tests
from phases.phase3_binary import run_binary_analysis
from phases.phase4_exploit import run_exploit_dev
from phases.phase5_report import run_report_generation

BANNER = """
+--------------------------------------------------------------+
|  BUG BOUNTY WORKFLOW  v1.0                                   |
|  Phases: Recon -> Surface -> Test -> Exploit -> Report       |
|  Authorization required. Scope stored in output/scope.json   |
+--------------------------------------------------------------+
"""

OUTPUT_DIR = Path(__file__).parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)


def _target_dir(target: str) -> Path:
    safe = target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
    d = OUTPUT_DIR / safe
    d.mkdir(exist_ok=True)
    return d


def cmd_init(args):
    """Register a target and record scope authorization."""
    target = args.target
    tdir = _target_dir(target)
    scope_file = tdir / "scope.json"

    print(f"\n[INIT] Target: {target}")
    print("Authorization check — answer the following:\n")

    program = input("  Bug bounty program / platform (e.g. HackerOne, CTF, personal lab): ").strip()
    scope_urls = input("  In-scope URLs/patterns (comma-separated): ").strip()
    out_of_scope = input("  Out-of-scope items: ").strip()
    auth_type = input("  Authorization type [program/ctf/lab/written]: ").strip()
    notes = input("  Additional scope notes: ").strip()

    if auth_type not in ("program", "ctf", "lab", "written"):
        print("\n[ERROR] Must specify authorization type. Aborting.")
        sys.exit(1)

    scope = ScopeRecord(
        target=target,
        program=program,
        scope_urls=[u.strip() for u in scope_urls.split(",")],
        out_of_scope=[u.strip() for u in out_of_scope.split(",") if u.strip()],
        auth_type=auth_type,
        notes=notes,
        initialized_at=datetime.utcnow().isoformat(),
    )
    scope_file.write_text(json.dumps(scope.__dict__, indent=2))
    print(f"\n[OK] Scope recorded to {scope_file}")
    print("     Run `bounty recon <target>` to begin Phase 1.")


def cmd_recon(args):
    _require_scope(args.target)
    run_recon(args.target, _target_dir(args.target))


def cmd_surface(args):
    _require_scope(args.target)
    run_surface_map(args.target, _target_dir(args.target))


def cmd_test(args):
    _require_scope(args.target)
    tdir = _target_dir(args.target)
    subcommand = args.subcommand
    if subcommand == "web":
        run_web_tests(args.target, tdir)
    elif subcommand == "api":
        run_api_tests(args.target, tdir)
    elif subcommand == "ai":
        _run_ml_sectest(args.target, tdir)
    elif subcommand == "binary":
        if not hasattr(args, "file") or not args.file:
            print("[ERROR] Specify binary file: bounty test binary <target> --file <path>")
            sys.exit(1)
        run_binary_analysis(args.file, tdir)
    else:
        print(f"[ERROR] Unknown test type: {subcommand}")
        sys.exit(1)


def cmd_exploit(args):
    _require_scope(args.target)
    run_exploit_dev(args.target, args.finding, _target_dir(args.target))


def cmd_report(args):
    _require_scope(args.target)
    run_report_generation(args.target, _target_dir(args.target))


def cmd_status(args):
    tdir = _target_dir(args.target)
    findings_dir = tdir / "findings"
    if not findings_dir.exists():
        print(f"No findings yet for {args.target}")
        return
    files = sorted(findings_dir.glob("*.json"))
    if not files:
        print(f"No findings yet for {args.target}")
        return
    print(f"\n[STATUS] {args.target} — {len(files)} finding(s)\n")
    for f in files:
        data = json.loads(f.read_text())
        sev = data.get("severity", "Unknown")
        title = data.get("title", f.stem)
        cwe = data.get("cwe", "")
        print(f"  [{sev:8s}] {title}  {cwe}")
    print()


def cmd_targets(args):
    if not OUTPUT_DIR.exists():
        print("No targets initialized.")
        return
    targets = [d for d in OUTPUT_DIR.iterdir() if d.is_dir() and (d / "scope.json").exists()]
    if not targets:
        print("No targets initialized.")
        return
    print(f"\n[TARGETS] {len(targets)} target(s) tracked:\n")
    for t in targets:
        scope = json.loads((t / "scope.json").read_text())
        findings_count = len(list((t / "findings").glob("*.json"))) if (t / "findings").exists() else 0
        print(f"  {scope['target']}")
        print(f"    Program : {scope['program']}")
        print(f"    Auth    : {scope['auth_type']}")
        print(f"    Findings: {findings_count}")
        print()


def _require_scope(target: str):
    tdir = _target_dir(target)
    if not (tdir / "scope.json").exists():
        print(f"[ERROR] No scope record for {target}.")
        print(f"        Run: bounty init {target}")
        sys.exit(1)


def _run_ml_sectest(target: str, tdir: Path):
    ml_path = Path.home() / "development" / "ml-sectest-framework" / "ml_sectest.py"
    if not ml_path.exists():
        print(f"[ERROR] ml_sectest.py not found at {ml_path}")
        sys.exit(1)
    report_dir = tdir / "ml-sectest-reports"
    report_dir.mkdir(exist_ok=True)
    print(f"\n[AI/ML] Launching ML-SecTest scan against {target}")
    print(f"        Reports → {report_dir}\n")
    cmd = [sys.executable, str(ml_path), "scan", target, "--output", str(report_dir)]
    subprocess.run(cmd, cwd=str(ml_path.parent))


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        prog="bounty",
        description="Bug Bounty Workflow CLI — agent-assisted methodology",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # init
    p_init = sub.add_parser("init", help="Register target and record scope authorization")
    p_init.add_argument("target", help="Target URL or identifier")
    p_init.set_defaults(func=cmd_init)

    # recon
    p_recon = sub.add_parser("recon", help="Phase 1: passive recon and OSINT")
    p_recon.add_argument("target")
    p_recon.set_defaults(func=cmd_recon)

    # surface
    p_surface = sub.add_parser("surface", help="Phase 2: endpoint and surface mapping")
    p_surface.add_argument("target")
    p_surface.set_defaults(func=cmd_surface)

    # test
    p_test = sub.add_parser("test", help="Phase 3: vulnerability testing")
    p_test.add_argument("subcommand", choices=["web", "api", "ai", "binary"])
    p_test.add_argument("target")
    p_test.add_argument("--file", help="Binary file path (for 'binary' subcommand)")
    p_test.set_defaults(func=cmd_test)

    # exploit
    p_exploit = sub.add_parser("exploit", help="Phase 4: PoC development")
    p_exploit.add_argument("target")
    p_exploit.add_argument("finding", help="Finding ID (filename stem from findings/)")
    p_exploit.set_defaults(func=cmd_exploit)

    # report
    p_report = sub.add_parser("report", help="Phase 5: generate submission report")
    p_report.add_argument("target")
    p_report.set_defaults(func=cmd_report)

    # status
    p_status = sub.add_parser("status", help="Show findings for a target")
    p_status.add_argument("target")
    p_status.set_defaults(func=cmd_status)

    # targets
    p_targets = sub.add_parser("targets", help="List all tracked targets")
    p_targets.set_defaults(func=cmd_targets)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
