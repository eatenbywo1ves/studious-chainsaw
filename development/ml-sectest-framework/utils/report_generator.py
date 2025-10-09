"""
Security Test Report Generator
===============================
Generates comprehensive HTML and JSON reports from security testing results.
"""

from typing import Dict, Any
from datetime import datetime
import json
from pathlib import Path

import sys
sys.path.append(str(Path(__file__).parent.parent))

from core.orchestrator import OrchestrationResult


class ReportGenerator:
    """
    Generates professional security testing reports.
    
    Features:
    - HTML reports with visualizations
    - JSON exports for programmatic analysis
    - Executive summaries
    - Detailed technical findings
    """

    def __init__(self, output_directory: str = "./reports"):
        """Initialize report generator."""
        self.output_dir = Path(output_directory)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_html_report(
        self, result: OrchestrationResult, output_filename: str = None
    ) -> str:
        """
        Generate HTML security report.
        
        Args:
            result: Orchestration result to report
            output_filename: Custom output filename
            
        Returns:
            Path to generated HTML file
        """
        if output_filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"security_report_{timestamp}.html"

        output_path = self.output_dir / output_filename

        html_content = self._generate_html_content(result)

        with open(output_path, 'w', encoding='utf-8') as html_file:
            html_file.write(html_content)

        return str(output_path)

    def generate_json_report(
        self, result: OrchestrationResult, output_filename: str = None
    ) -> str:
        """
        Generate JSON security report.
        
        Args:
            result: Orchestration result to report
            output_filename: Custom output filename
            
        Returns:
            Path to generated JSON file
        """
        if output_filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"security_report_{timestamp}.json"

        output_path = self.output_dir / output_filename

        report_data = self._generate_json_content(result)

        with open(output_path, 'w', encoding='utf-8') as json_file:
            json.dump(report_data, json_file, indent=2)

        return str(output_path)

    def _generate_html_content(self, result: OrchestrationResult) -> str:
        """Generate HTML report content."""

        # Calculate statistics
        total_tests = sum(len(tests) for tests in result.agent_results.values())
        successful_tests = sum(
            sum(1 for t in tests if t.success)
            for tests in result.agent_results.values()
        )

        # Generate severity color
        severity_class = self._get_severity_class(result.overall_status)
        severity_color = self._get_severity_color(result.overall_status)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ML Security Assessment Report - {result.plan.challenge_name}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        
        .summary {{
            padding: 30px 40px;
            background: #f9f9f9;
            border-bottom: 1px solid #e0e0e0;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .summary-card h3 {{
            font-size: 0.9em;
            color: #666;
            text-transform: uppercase;
            margin-bottom: 10px;
        }}
        
        .summary-card .value {{
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.9em;
        }}
        
        .severity-critical {{
            background: #ff4444;
            color: white;
        }}
        
        .severity-vulnerable {{
            background: #ff9800;
            color: white;
        }}
        
        .severity-partially_vulnerable {{
            background: #ffc107;
            color: #333;
        }}
        
        .severity-secure {{
            background: #4caf50;
            color: white;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .section {{
            margin-bottom: 40px;
        }}
        
        .section h2 {{
            font-size: 1.8em;
            margin-bottom: 20px;
            color: #667eea;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }}
        
        .vulnerability-list {{
            list-style: none;
        }}
        
        .vulnerability-item {{
            background: #fff3e0;
            border-left: 4px solid #ff9800;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 4px;
        }}
        
        .agent-result {{
            background: #f9f9f9;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid #e0e0e0;
        }}
        
        .agent-result h3 {{
            color: #667eea;
            margin-bottom: 15px;
        }}
        
        .test-result {{
            background: white;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
            border-left: 4px solid #ccc;
        }}
        
        .test-result.success {{
            border-left-color: #4caf50;
        }}
        
        .test-result.failure {{
            border-left-color: #f44336;
        }}
        
        .evidence {{
            background: #f5f5f5;
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        
        .recommendations {{
            background: #e8f5e9;
            border-left: 4px solid #4caf50;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }}
        
        .recommendations h4 {{
            color: #2e7d32;
            margin-bottom: 10px;
        }}
        
        .recommendations ul {{
            margin-left: 20px;
        }}
        
        .footer {{
            background: #f5f5f5;
            padding: 20px 40px;
            text-align: center;
            color: #666;
            border-top: 1px solid #e0e0e0;
        }}
        
        .timestamp {{
            color: #999;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ ML Security Assessment Report</h1>
            <div class="subtitle">{result.plan.challenge_name}</div>
            <div class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Overall Status</h3>
                    <div class="value">
                        <span class="severity-badge severity-{severity_class}">
                            {result.overall_status.upper()}
                        </span>
                    </div>
                </div>
                <div class="summary-card">
                    <h3>Success Rate</h3>
                    <div class="value" style="color: {severity_color};">
                        {result.success_rate:.1f}%
                    </div>
                </div>
                <div class="summary-card">
                    <h3>Tests Executed</h3>
                    <div class="value">{total_tests}</div>
                </div>
                <div class="summary-card">
                    <h3>Vulnerabilities Found</h3>
                    <div class="value" style="color: #ff4444;">
                        {len(result.vulnerabilities_found)}
                    </div>
                </div>
                <div class="summary-card">
                    <h3>Duration</h3>
                    <div class="value" style="font-size: 1.5em;">
                        {result.total_duration_seconds:.2f}s
                    </div>
                </div>
                <div class="summary-card">
                    <h3>Target</h3>
                    <div class="value" style="font-size: 1em; word-break: break-all;">
                        {result.plan.target_url}
                    </div>
                </div>
            </div>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>🎯 Target Information</h2>
                <p><strong>Challenge:</strong> {result.plan.challenge_name}</p>
                <p><strong>Difficulty:</strong> {result.plan.difficulty_level}</p>
                <p><strong>Target URL:</strong> {result.plan.target_url}</p>
                <p><strong>OWASP Reference:</strong> {result.plan.owasp_reference}</p>
                <p><strong>MITRE Reference:</strong> {result.plan.mitre_reference or 'N/A'}</p>
            </div>
            
            <div class="section">
                <h2>⚠️ Vulnerabilities Detected</h2>
                {self._generate_vulnerabilities_section(result)}
            </div>
            
            <div class="section">
                <h2>🔍 Detailed Test Results</h2>
                {self._generate_detailed_results(result)}
            </div>
        </div>
        
        <div class="footer">
            <p><strong>ML-SecTest Framework</strong> - Automated ML Security Testing</p>
            <p class="timestamp">Report generated on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>"""

        return html

    def _generate_vulnerabilities_section(self, result: OrchestrationResult) -> str:
        """Generate vulnerabilities section HTML."""
        if not result.vulnerabilities_found:
            return "<p style='color: #4caf50; font-weight: bold;'>✅ No vulnerabilities detected</p>"

        html = "<ul class='vulnerability-list'>"
        for vuln in result.vulnerabilities_found:
            html += f"<li class='vulnerability-item'>🔴 <strong>{vuln.replace('_', ' ').title()}</strong></li>"
        html += "</ul>"

        return html

    def _generate_detailed_results(self, result: OrchestrationResult) -> str:
        """Generate detailed results section HTML."""
        html = ""

        for agent_id, test_results in result.agent_results.items():
            html += "<div class='agent-result'>"
            html += f"<h3>Agent: {agent_id}</h3>"

            for test in test_results:
                status_class = "success" if test.success else "failure"
                status_icon = "✅" if test.success else "❌"

                html += f"<div class='test-result {status_class}'>"
                html += f"<h4>{status_icon} {test.test_name}</h4>"
                html += f"<p><strong>Vulnerability Type:</strong> {test.vulnerability_type.value}</p>"
                html += f"<p><strong>Confidence Score:</strong> {test.confidence_score:.2%}</p>"
                html += f"<p><strong>Execution Time:</strong> {test.execution_time_seconds:.2f}s</p>"

                if test.evidence:
                    html += "<p><strong>Evidence:</strong></p>"
                    html += "<div class='evidence'>"
                    for evidence in test.evidence:
                        html += f"<div>• {evidence}</div>"
                    html += "</div>"

                if test.recommendations:
                    html += "<div class='recommendations'>"
                    html += "<h4>🛠️ Recommendations</h4>"
                    html += "<ul>"
                    for rec in test.recommendations:
                        html += f"<li>{rec}</li>"
                    html += "</ul>"
                    html += "</div>"

                html += "</div>"

            html += "</div>"

        return html

    def _generate_json_content(self, result: OrchestrationResult) -> Dict[str, Any]:
        """Generate JSON report content."""
        report = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "framework": "ML-SecTest",
                "version": "1.0.0"
            },
            "assessment": {
                "challenge_name": result.plan.challenge_name,
                "target_url": result.plan.target_url,
                "difficulty": result.plan.difficulty_level,
                "owasp_reference": result.plan.owasp_reference,
                "mitre_reference": result.plan.mitre_reference,
                "start_time": result.start_time,
                "end_time": result.end_time,
                "duration_seconds": result.total_duration_seconds
            },
            "results": {
                "overall_status": result.overall_status,
                "success_rate": result.success_rate,
                "vulnerabilities_found": result.vulnerabilities_found,
                "agent_results": {}
            }
        }

        # Add detailed agent results
        for agent_id, tests in result.agent_results.items():
            report["results"]["agent_results"][agent_id] = [
                {
                    "test_name": t.test_name,
                    "vulnerability_type": t.vulnerability_type.value,
                    "success": t.success,
                    "confidence_score": t.confidence_score,
                    "execution_time_seconds": t.execution_time_seconds,
                    "evidence": t.evidence,
                    "artifacts": t.artifacts,
                    "recommendations": t.recommendations,
                    "timestamp": t.timestamp
                }
                for t in tests
            ]

        return report

    def _get_severity_class(self, status: str) -> str:
        """Get CSS class for severity status."""
        return status.lower().replace(" ", "_")

    def _get_severity_color(self, status: str) -> str:
        """Get color for severity status."""
        colors = {
            "critical": "#ff4444",
            "vulnerable": "#ff9800",
            "partially_vulnerable": "#ffc107",
            "secure": "#4caf50"
        }
        return colors.get(status.lower(), "#999")
