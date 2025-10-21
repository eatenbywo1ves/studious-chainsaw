#!/usr/bin/env python3
"""
ML-SecTest: Machine Learning Security Testing Framework
========================================================
Main CLI application for automated ML/AI security vulnerability assessment.

Usage:
    python ml_sectest.py scan <target_url> [options]
    python ml_sectest.py list-challenges
    python ml_sectest.py test-challenge <challenge_name>
"""

import argparse
import sys
import logging
import json
import csv
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.orchestrator import SecurityOrchestrator, OrchestrationPlan, OrchestrationResult
from agents import (
    PromptInjectionAgent,
    ModelInversionAgent,
    DataPoisoningAgent,
    ModelExtractionAgent,
    ModelSerializationAgent,
    AdversarialAttackAgent,
    EdwardTellerAgent
)
from utils.report_generator import ReportGenerator


# ASCII Banner
BANNER = """
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║   ███╗   ███╗██╗         ███████╗███████╗ ██████╗████████╗███████╗  ║
║   ████╗ ████║██║         ██╔════╝██╔════╝██╔════╝╚══██╔══╝██╔════╝  ║
║   ██╔████╔██║██║         ███████╗█████╗  ██║        ██║   █████╗    ║
║   ██║╚██╔╝██║██║         ╚════██║██╔══╝  ██║        ██║   ██╔══╝    ║
║   ██║ ╚═╝ ██║███████╗    ███████║███████╗╚██████╗   ██║   ███████╗  ║
║   ╚═╝     ╚═╝╚══════╝    ╚══════╝╚══════╝ ╚═════╝   ╚═╝   ╚══════╝  ║
║                                                                       ║
║         Machine Learning Security Testing Framework                  ║
║              Automated AI/ML Vulnerability Assessment                ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
"""


class MLSecTest:
    """Main application class for ML security testing."""

    def __init__(self) -> None:
        """Initialize the ML-SecTest application."""
        self.orchestrator = SecurityOrchestrator()
        self.report_generator = ReportGenerator()
        self.logger = self._setup_logging()

        # Register all security agents
        self._register_agents()

        # Define challenge mappings
        self.challenges = self._define_challenges()

    def _setup_logging(self) -> logging.Logger:
        """Configure application logging."""
        logging.basicConfig(
            level=logging.INFO,
            format='[%(asctime)s] %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        return logging.getLogger("MLSecTest")

    def _register_agents(self) -> None:
        """Register all security testing agents with the orchestrator."""
        agents = [
            PromptInjectionAgent(),
            ModelInversionAgent(),
            DataPoisoningAgent(),
            ModelExtractionAgent(),
            ModelSerializationAgent(),
            AdversarialAttackAgent(),
            EdwardTellerAgent()
        ]

        for agent in agents:
            self.orchestrator.register_agent(agent)

        self.logger.info(f"Registered {len(agents)} security testing agents")

    def _define_challenges(self) -> Dict[str, Any]:
        """Define CTF challenge configurations."""
        return {
            "mirage": {
                "name": "Mirage - MCP Signature Cloaking",
                "difficulty": "Medium",
                "owasp": "OWASP LLM03:2025",
                "agents": ["prompt_injection_001"]
            },
            "vault": {
                "name": "Vault - Model Inversion",
                "difficulty": "Hard",
                "owasp": "OWASP ML03",
                "agents": ["model_inversion_001"]
            },
            "dolos": {
                "name": "Dolos - Prompt Injection to RCE",
                "difficulty": "Easy",
                "owasp": "OWASP LLM01",
                "mitre": "AML.T0051",
                "agents": ["prompt_injection_001"]
            },
            "dolos2": {
                "name": "Dolos II - Prompt Injection to SQL Injection",
                "difficulty": "Easy",
                "owasp": "OWASP LLM01",
                "mitre": "AML.T0051",
                "agents": ["prompt_injection_001"]
            },
            "heist": {
                "name": "Heist - Data Poisoning Attack",
                "difficulty": "Medium",
                "owasp": "OWASP LLM03, OWASP ML02",
                "mitre": "AML.T0020",
                "agents": ["data_poisoning_001"]
            },
            "persuade": {
                "name": "Persuade - Model Serialization Attack",
                "difficulty": "Medium",
                "owasp": "OWASP LLM05, OWASP ML06",
                "mitre": "AML.T0010",
                "agents": ["model_serialization_001"]
            },
            "fourtune": {
                "name": "Fourtune - Model Extraction Attack",
                "difficulty": "Hard",
                "owasp": "OWASP LLM10",
                "mitre": "AML.T0044",
                "agents": ["model_extraction_001", "adversarial_attack_001"]
            }
        }

    def scan_target(
        self,
        target_url: str,
        challenge_name: str = "custom",
        agents: Optional[List[str]] = None,
        parallel: bool = False,
        output_format: str = "both"
    ) -> None:
        """
        Scan a target for ML security vulnerabilities.

        Args:
            target_url: Target URL to scan
            challenge_name: Name of the challenge
            agents: List of agent IDs to use (None = all agents)
            parallel: Execute agents in parallel
            output_format: Report format ('html', 'json', or 'both')
        """
        print(BANNER)
        print(f"\n🎯 Target: {target_url}")
        print(f"📋 Challenge: {challenge_name}")
        print("=" * 75)

        # Determine which agents to use
        if agents is None:
            agents = list(self.orchestrator.agents.keys())

        # Create orchestration plan
        plan = OrchestrationPlan(
            challenge_name=challenge_name,
            target_url=target_url,
            difficulty_level="Unknown",
            agent_sequence=agents,
            parallel_execution=parallel,
            owasp_reference="Custom Scan"
        )

        # Execute security assessment
        self.logger.info("Starting security assessment...")
        result = self.orchestrator.execute_plan(plan)

        # Generate reports
        print("\n📊 Generating reports...")

        if output_format in ["html", "both"]:
            html_path = self.report_generator.generate_html_report(result)
            print(f"✅ HTML Report: {html_path}")

        if output_format in ["json", "both"]:
            json_path = self.report_generator.generate_json_report(result)
            print(f"✅ JSON Report: {json_path}")

        # Display summary
        self._display_summary(result)

    def test_challenge(self, challenge_key: str, target_url: Optional[str] = None) -> None:
        """
        Test a specific CTF challenge.

        Args:
            challenge_key: Challenge identifier (e.g., 'vault', 'dolos')
            target_url: Optional custom target URL
        """
        if challenge_key not in self.challenges:
            self.logger.error(f"Unknown challenge: {challenge_key}")
            self.list_challenges()
            return

        challenge = self.challenges[challenge_key]

        print(BANNER)
        print(f"\n🎯 Testing Challenge: {challenge['name']}")
        print(f"📊 Difficulty: {challenge['difficulty']}")
        print(f"📚 OWASP: {challenge['owasp']}")
        if 'mitre' in challenge:
            print(f"🔍 MITRE: {challenge['mitre']}")
        print("=" * 75)

        # Use provided URL or prompt for it
        if target_url is None:
            target_url = input("\n🌐 Enter target URL: ").strip()
            if not target_url:
                self.logger.error("Target URL required")
                return

        # Create orchestration plan
        plan = OrchestrationPlan(
            challenge_name=challenge['name'],
            target_url=target_url,
            difficulty_level=challenge['difficulty'],
            agent_sequence=challenge['agents'],
            parallel_execution=False,
            owasp_reference=challenge['owasp'],
            mitre_reference=challenge.get('mitre')
        )

        # Execute assessment
        result = self.orchestrator.execute_plan(plan)

        # Generate reports
        print("\n📊 Generating reports...")
        html_path = self.report_generator.generate_html_report(
            result,
            f"{challenge_key}_report.html"
        )
        json_path = self.report_generator.generate_json_report(
            result,
            f"{challenge_key}_report.json"
        )

        print(f"✅ HTML Report: {html_path}")
        print(f"✅ JSON Report: {json_path}")

        # Display summary
        self._display_summary(result)

    def list_challenges(self) -> None:
        """List all available CTF challenges."""
        print(BANNER)
        print("\n📚 Available CTF Challenges:")
        print("=" * 75)

        for key, challenge in self.challenges.items():
            print(f"\n🎯 {key.upper()}")
            print(f"   Name: {challenge['name']}")
            print(f"   Difficulty: {challenge['difficulty']}")
            print(f"   OWASP: {challenge['owasp']}")
            if 'mitre' in challenge:
                print(f"   MITRE: {challenge['mitre']}")
            print(f"   Agents: {', '.join(challenge['agents'])}")

        print("\n" + "=" * 75)
        print("Usage: python ml_sectest.py test-challenge <challenge_key>")

    def _display_summary(self, result: OrchestrationResult) -> None:
        """Display assessment summary."""
        print("\n" + "=" * 75)
        print("🔒 SECURITY ASSESSMENT SUMMARY")
        print("=" * 75)

        status_emoji = {
            "secure": "✅",
            "partially_vulnerable": "⚠️",
            "vulnerable": "🔴",
            "critical": "🚨"
        }

        emoji = status_emoji.get(result.overall_status, "❓")

        print(f"\n{emoji} Overall Status: {result.overall_status.upper()}")
        print(f"📈 Success Rate: {result.success_rate:.1f}%")
        print(f"⏱️  Duration: {result.total_duration_seconds:.2f}s")
        print(f"🔍 Vulnerabilities Found: {len(result.vulnerabilities_found)}")

        if result.vulnerabilities_found:
            print("\n⚠️  Detected Vulnerabilities:")
            for vuln in result.vulnerabilities_found:
                print(f"   • {vuln.replace('_', ' ').title()}")
        else:
            print("\n✅ No vulnerabilities detected")

        print("\n" + "=" * 75)

    def _parse_batch_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Parse batch target file in various formats.

        Supported formats:
        - .txt: One URL per line
        - .csv: url,name,agents (comma-separated)
        - .json: Array of {url, name, agents} objects

        Args:
            file_path: Path to batch file

        Returns:
            List of target configurations
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Batch file not found: {file_path}")

        targets = []

        # Plain text file - one URL per line
        if path.suffix == '.txt':
            with open(path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.append({
                            'url': line,
                            'name': f'target_{line_num}',
                            'agents': None
                        })

        # CSV file - url,name,agents
        elif path.suffix == '.csv':
            with open(path, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    agents = None
                    if 'agents' in row and row['agents']:
                        agents = [a.strip() for a in row['agents'].split(';')]
                    targets.append({
                        'url': row['url'].strip(),
                        'name': row.get('name', row['url']).strip(),
                        'agents': agents
                    })

        # JSON file - array of objects
        elif path.suffix == '.json':
            with open(path, 'r') as f:
                data = json.load(f)
                for item in data:
                    targets.append({
                        'url': item['url'],
                        'name': item.get('name', item['url']),
                        'agents': item.get('agents')
                    })

        else:
            raise ValueError(f"Unsupported file format: {path.suffix}. Use .txt, .csv, or .json")

        self.logger.info(f"Loaded {len(targets)} targets from {file_path}")
        return targets

    def _scan_single_target(
        self,
        target: Dict[str, Any],
        index: int,
        total: int
    ) -> Dict[str, Any]:
        """
        Scan a single target (for batch processing).

        Args:
            target: Target configuration
            index: Target index (1-based)
            total: Total number of targets

        Returns:
            Scan result with metadata
        """
        try:
            print(f"\n[{index}/{total}] 🎯 Scanning: {target['name']}")
            print(f"           URL: {target['url']}")

            # Determine agents
            agents = target.get('agents')
            if agents is None:
                agents = list(self.orchestrator.agents.keys())

            # Create plan
            plan = OrchestrationPlan(
                challenge_name=target['name'],
                target_url=target['url'],
                difficulty_level="Unknown",
                agent_sequence=agents,
                parallel_execution=False,
                owasp_reference="Batch Scan"
            )

            # Execute scan
            result = self.orchestrator.execute_plan(plan)

            # Generate individual report
            report_name = f"batch_{target['name']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            html_path = self.report_generator.generate_html_report(result, f"{report_name}.html")
            json_path = self.report_generator.generate_json_report(result, f"{report_name}.json")

            print(f"           ✅ Complete ({result.total_duration_seconds:.2f}s)")
            print(f"           Reports: {html_path}")

            return {
                'target': target,
                'result': result,
                'html_report': html_path,
                'json_report': json_path,
                'status': 'success'
            }

        except Exception as e:
            self.logger.error(f"Failed to scan {target['url']}: {e}")
            print(f"           ❌ Failed: {str(e)}")
            return {
                'target': target,
                'result': None,
                'error': str(e),
                'status': 'failed'
            }

    def batch_scan(
        self,
        file_path: str,
        max_workers: int = 3,
        output_dir: Optional[str] = None
    ) -> None:
        """
        Perform batch scanning of multiple targets.

        Args:
            file_path: Path to batch file (.txt, .csv, or .json)
            max_workers: Maximum concurrent scans
            output_dir: Output directory for reports (default: ./reports)
        """
        print(BANNER)
        print(f"\n📦 BATCH SCANNING MODE")
        print("=" * 75)

        # Parse targets
        targets = self._parse_batch_file(file_path)
        print(f"\n📋 Targets loaded: {len(targets)}")
        print(f"⚡ Max concurrent scans: {max_workers}")
        print("=" * 75)

        # Track results
        all_results = []
        start_time = datetime.now()

        # Execute scans
        if max_workers == 1:
            # Sequential execution
            for idx, target in enumerate(targets, 1):
                result = self._scan_single_target(target, idx, len(targets))
                all_results.append(result)
        else:
            # Parallel execution
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(self._scan_single_target, target, idx, len(targets)): target
                    for idx, target in enumerate(targets, 1)
                }

                for future in as_completed(futures):
                    result = future.result()
                    all_results.append(result)

        end_time = datetime.now()
        total_duration = (end_time - start_time).total_seconds()

        # Generate aggregate report
        self._display_batch_summary(all_results, total_duration)

        # Save batch summary
        self._save_batch_summary(all_results, file_path, total_duration)

    def _display_batch_summary(self, results: List[Dict[str, Any]], duration: float) -> None:
        """Display batch scan summary."""
        print("\n" + "=" * 75)
        print("📊 BATCH SCAN SUMMARY")
        print("=" * 75)

        successful = [r for r in results if r['status'] == 'success']
        failed = [r for r in results if r['status'] == 'failed']

        print(f"\n✅ Successful: {len(successful)}/{len(results)}")
        print(f"❌ Failed: {len(failed)}/{len(results)}")
        print(f"⏱️  Total Duration: {duration:.2f}s")
        print(f"📈 Average per target: {duration/len(results):.2f}s")

        # Aggregate vulnerability statistics
        total_vulns = 0
        vuln_types = set()
        critical_targets = []

        for r in successful:
            if r['result']:
                vulns = r['result'].vulnerabilities_found
                total_vulns += len(vulns)
                vuln_types.update(vulns)
                if r['result'].overall_status in ['vulnerable', 'critical']:
                    critical_targets.append(r['target']['name'])

        print(f"\n🔍 Total Vulnerabilities: {total_vulns}")
        print(f"🎯 Unique Vulnerability Types: {len(vuln_types)}")
        print(f"🚨 Critical Targets: {len(critical_targets)}")

        if critical_targets:
            print("\n⚠️  Targets Requiring Attention:")
            for target in critical_targets[:5]:  # Show first 5
                print(f"   • {target}")
            if len(critical_targets) > 5:
                print(f"   ... and {len(critical_targets) - 5} more")

        if failed:
            print("\n❌ Failed Targets:")
            for r in failed[:5]:
                print(f"   • {r['target']['name']}: {r.get('error', 'Unknown error')}")
            if len(failed) > 5:
                print(f"   ... and {len(failed) - 5} more")

        print("\n" + "=" * 75)

    def _save_batch_summary(
        self,
        results: List[Dict[str, Any]],
        source_file: str,
        duration: float
    ) -> None:
        """Save batch summary to JSON file."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        summary_path = f"batch_summary_{timestamp}.json"

        summary = {
            'timestamp': datetime.now().isoformat(),
            'source_file': source_file,
            'total_targets': len(results),
            'successful': len([r for r in results if r['status'] == 'success']),
            'failed': len([r for r in results if r['status'] == 'failed']),
            'total_duration_seconds': duration,
            'targets': [
                {
                    'name': r['target']['name'],
                    'url': r['target']['url'],
                    'status': r['status'],
                    'vulnerabilities': len(r['result'].vulnerabilities_found) if r['result'] else 0,
                    'overall_status': r['result'].overall_status if r['result'] else 'unknown',
                    'html_report': r.get('html_report'),
                    'json_report': r.get('json_report'),
                    'error': r.get('error')
                }
                for r in results
            ]
        }

        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)

        print(f"\n💾 Batch summary saved: {summary_path}")
        self.logger.info(f"Batch summary saved to {summary_path}")


def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="ML-SecTest: Machine Learning Security Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a custom target
  python ml_sectest.py scan http://localhost:8000

  # Test a specific CTF challenge
  python ml_sectest.py test-challenge vault

  # List all available challenges
  python ml_sectest.py list-challenges

  # Scan with specific agents
  python ml_sectest.py scan http://target.com --agents prompt_injection_001 model_inversion_001

  # Parallel execution with JSON output
  python ml_sectest.py scan http://target.com --parallel --format json

  # Batch scan multiple targets
  python ml_sectest.py batch-scan targets.txt

  # Batch scan with parallel execution
  python ml_sectest.py batch-scan targets.csv --workers 5

  # Batch scan from JSON config
  python ml_sectest.py batch-scan config.json --workers 10
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan a target for vulnerabilities')
    scan_parser.add_argument('target_url', help='Target URL to scan')
    scan_parser.add_argument('--name', default='custom', help='Challenge name')
    scan_parser.add_argument('--agents', nargs='+', help='Specific agents to use')
    scan_parser.add_argument('--parallel', action='store_true', help='Execute agents in parallel')
    scan_parser.add_argument('--format', choices=['html', 'json', 'both'], default='both',
                           help='Report output format')

    # Test challenge command
    test_parser = subparsers.add_parser('test-challenge', help='Test a specific CTF challenge')
    test_parser.add_argument('challenge', help='Challenge identifier (e.g., vault, dolos)')
    test_parser.add_argument('--url', help='Target URL (will prompt if not provided)')

    # List challenges command
    subparsers.add_parser('list-challenges', help='List all available CTF challenges')

    # Batch scan command
    batch_parser = subparsers.add_parser('batch-scan', help='Scan multiple targets from a file')
    batch_parser.add_argument('file', help='Path to batch file (.txt, .csv, or .json)')
    batch_parser.add_argument('--workers', type=int, default=3, help='Max concurrent scans (default: 3)')
    batch_parser.add_argument('--output-dir', help='Output directory for reports')

    args = parser.parse_args()

    # Initialize application
    app = MLSecTest()

    # Execute command
    if args.command == 'scan':
        app.scan_target(
            target_url=args.target_url,
            challenge_name=args.name,
            agents=args.agents,
            parallel=args.parallel,
            output_format=args.format
        )
    elif args.command == 'test-challenge':
        app.test_challenge(args.challenge, args.url)
    elif args.command == 'list-challenges':
        app.list_challenges()
    elif args.command == 'batch-scan':
        app.batch_scan(
            file_path=args.file,
            max_workers=args.workers,
            output_dir=args.output_dir
        )
    else:
        parser.print_help()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Assessment interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        sys.exit(1)
