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
from typing import List

from core.orchestrator import SecurityOrchestrator, OrchestrationPlan
from agents import (
    PromptInjectionAgent,
    ModelInversionAgent,
    DataPoisoningAgent,
    ModelExtractionAgent,
    ModelSerializationAgent,
    AdversarialAttackAgent
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

    def __init__(self):
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

    def _register_agents(self):
        """Register all security testing agents with the orchestrator."""
        agents = [
            PromptInjectionAgent(),
            ModelInversionAgent(),
            DataPoisoningAgent(),
            ModelExtractionAgent(),
            ModelSerializationAgent(),
            AdversarialAttackAgent()
        ]

        for agent in agents:
            self.orchestrator.register_agent(agent)

        self.logger.info(f"Registered {len(agents)} security testing agents")

    def _define_challenges(self) -> dict:
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
        agents: List[str] = None,
        parallel: bool = False,
        output_format: str = "both"
    ):
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

    def test_challenge(self, challenge_key: str, target_url: str = None):
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

    def list_challenges(self):
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

    def _display_summary(self, result):
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


def main():
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
