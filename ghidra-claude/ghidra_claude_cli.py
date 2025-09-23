#!/usr/bin/env python3
"""
Interactive CLI for Ghidra-Claude reverse engineering sessions
Provides an interface to analyze binaries using Ghidra data with Claude AI
"""

import argparse
import json
import os
import sys
import subprocess
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
import tempfile
import shutil
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.markdown import Markdown
import time

# Import the bridge module
sys.path.append(str(Path(__file__).parent))
from ghidra_claude_bridge import GhidraClaudeBridge, AnalysisType, create_claude_prompt


class GhidraClaudeSession:
    """Interactive session manager for Ghidra-Claude analysis"""

    def __init__(self, ghidra_path: str):
        self.console = Console()
        self.ghidra_path = Path(ghidra_path)
        self.bridge = GhidraClaudeBridge(ghidra_path)
        self.current_binary = None
        self.analysis_history = []
        self.ghidra_data = None
        self.session_dir = Path.home() / ".ghidra-claude-sessions"
        self.session_dir.mkdir(exist_ok=True)

    def print_banner(self):
        """Display the application banner"""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                  GHIDRA-CLAUDE INTEGRATION                   ║
║            Advanced Binary Analysis with AI Assistance       ║
╚══════════════════════════════════════════════════════════════╝
        """
        self.console.print(Panel(banner, style="bold cyan"))

    def main_menu(self):
        """Display and handle the main menu"""
        while True:
            self.console.print("\n[bold cyan]Main Menu[/bold cyan]")
            self.console.print("1. Load Binary for Analysis")
            self.console.print("2. Import Ghidra Export (JSON)")
            self.console.print("3. Quick Analysis (Automated)")
            self.console.print("4. View Analysis History")
            self.console.print("5. Interactive Analysis Session")
            self.console.print("6. Export Session Report")
            self.console.print("7. Settings")
            self.console.print("8. Exit")

            choice = Prompt.ask("\n[bold]Select option[/bold]", choices=["1", "2", "3", "4", "5", "6", "7", "8"])

            if choice == "1":
                self.load_binary()
            elif choice == "2":
                self.import_ghidra_export()
            elif choice == "3":
                self.quick_analysis()
            elif choice == "4":
                self.view_history()
            elif choice == "5":
                self.interactive_session()
            elif choice == "6":
                self.export_report()
            elif choice == "7":
                self.settings_menu()
            elif choice == "8":
                if Confirm.ask("[yellow]Exit Ghidra-Claude?[/yellow]"):
                    self.console.print("[green]Goodbye![/green]")
                    break

    def load_binary(self):
        """Load a binary file for analysis"""
        binary_path = Prompt.ask("\n[bold]Enter binary path[/bold]")
        binary_path = Path(binary_path).expanduser()

        if not binary_path.exists():
            self.console.print(f"[red]Error: File not found: {binary_path}[/red]")
            return

        self.current_binary = binary_path
        self.console.print(f"[green]Loaded: {binary_path.name}[/green]")

        # Ask if user wants to run Ghidra analysis
        if Confirm.ask("Run Ghidra analysis on this binary?"):
            self.run_ghidra_analysis()

    def import_ghidra_export(self):
        """Import a pre-existing Ghidra export JSON file"""
        json_path = Prompt.ask("\n[bold]Enter path to Ghidra export JSON[/bold]")
        json_path = Path(json_path).expanduser()

        if not json_path.exists():
            self.console.print(f"[red]Error: File not found: {json_path}[/red]")
            return

        try:
            with open(json_path, 'r') as f:
                self.ghidra_data = json.load(f)
            self.console.print(f"[green]Successfully imported Ghidra data[/green]")
            self.display_binary_info()
        except json.JSONDecodeError as e:
            self.console.print(f"[red]Error parsing JSON: {e}[/red]")

    def run_ghidra_analysis(self):
        """Run Ghidra headless analysis on the current binary"""
        if not self.current_binary:
            self.console.print("[red]No binary loaded[/red]")
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("[cyan]Running Ghidra analysis...", total=None)

            try:
                # Use the bridge to analyze
                analysis_type = self.select_analysis_type()
                result = self.bridge.analyze_binary(str(self.current_binary), analysis_type)

                if "error" in result:
                    self.console.print(f"[red]Analysis failed: {result['error']}[/red]")
                else:
                    self.ghidra_data = result
                    progress.update(task, completed=True)
                    self.console.print("[green]Analysis complete![/green]")
                    self.display_binary_info()

            except Exception as e:
                self.console.print(f"[red]Error during analysis: {e}[/red]")

    def select_analysis_type(self) -> AnalysisType:
        """Let user select the type of analysis"""
        self.console.print("\n[bold cyan]Select Analysis Type:[/bold cyan]")
        types = list(AnalysisType)
        for i, t in enumerate(types, 1):
            self.console.print(f"{i}. {t.value.replace('_', ' ').title()}")

        choice = Prompt.ask("Select", choices=[str(i) for i in range(1, len(types) + 1)])
        return types[int(choice) - 1]

    def display_binary_info(self):
        """Display basic information about the loaded binary"""
        if not self.ghidra_data:
            return

        info = self.ghidra_data.get("binary_info", {})

        table = Table(title="Binary Information", show_header=False)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Name", info.get("name", "Unknown"))
        table.add_row("Architecture", info.get("architecture", "Unknown"))
        table.add_row("Entry Point", info.get("entry_point", "Unknown"))
        table.add_row("Endianness", info.get("endianness", "Unknown"))

        if "sections" in info:
            table.add_row("Sections", str(len(info["sections"])))
        if "imports" in info:
            table.add_row("Imports", str(len(info["imports"])))
        if "exports" in info:
            table.add_row("Exports", str(len(info["exports"])))

        self.console.print(table)

    def quick_analysis(self):
        """Perform a quick automated analysis"""
        if not self.current_binary and not self.ghidra_data:
            self.console.print("[red]No binary or Ghidra data loaded[/red]")
            return

        # If no Ghidra data, run analysis first
        if not self.ghidra_data:
            self.run_ghidra_analysis()

        if not self.ghidra_data:
            return

        # Generate analysis prompts for different aspects
        analyses = [
            ("Security Vulnerabilities", AnalysisType.VULNERABILITY_SCAN),
            ("Cryptographic Functions", AnalysisType.CRYPTO_IDENTIFICATION),
            ("Interesting Patterns", AnalysisType.CODE_PATTERNS)
        ]

        results = []
        for name, analysis_type in analyses:
            self.console.print(f"\n[bold cyan]Analyzing: {name}[/bold cyan]")
            prompt = create_claude_prompt({
                "binary_info": self.ghidra_data.get("binary_info"),
                "analysis_type": analysis_type.value,
                "context": self.ghidra_data.get("context", {}),
                "prompt": self.bridge._generate_analysis_prompt(analysis_type)
            })

            # Display the prompt that would be sent to Claude
            self.console.print(Panel(
                prompt[:500] + "..." if len(prompt) > 500 else prompt,
                title=f"Claude Prompt for {name}",
                style="dim"
            ))

            results.append({
                "type": name,
                "prompt": prompt,
                "timestamp": datetime.now().isoformat()
            })

        self.analysis_history.extend(results)
        self.console.print("\n[green]Quick analysis complete! Prompts prepared for Claude.[/green]")

    def interactive_session(self):
        """Start an interactive analysis session"""
        if not self.ghidra_data:
            self.console.print("[yellow]No Ghidra data loaded. Please load a binary first.[/yellow]")
            return

        self.console.print("\n[bold cyan]Interactive Analysis Session[/bold cyan]")
        self.console.print("Type your questions about the binary. Type 'exit' to return to main menu.")
        self.console.print("Type 'functions' to list available functions, 'strings' for strings, etc.\n")

        while True:
            query = Prompt.ask("[bold]Analysis query[/bold]")

            if query.lower() == "exit":
                break
            elif query.lower() == "functions":
                self.list_functions()
            elif query.lower() == "strings":
                self.list_strings()
            elif query.lower() == "imports":
                self.list_imports()
            elif query.lower() == "exports":
                self.list_exports()
            elif query.lower().startswith("function "):
                func_name = query[9:].strip()
                self.analyze_function(func_name)
            elif query.lower() == "help":
                self.show_interactive_help()
            else:
                self.process_custom_query(query)

    def list_functions(self):
        """List all functions in the binary"""
        functions = self.ghidra_data.get("functions", [])
        if not functions:
            functions = self.ghidra_data.get("context", {}).get("relevant_functions", [])

        if not functions:
            self.console.print("[yellow]No function data available[/yellow]")
            return

        table = Table(title="Functions")
        table.add_column("Name", style="cyan")
        table.add_column("Address", style="green")
        table.add_column("Size", style="white")

        for func in functions[:20]:  # Show first 20
            table.add_row(
                func.get("name", "Unknown"),
                func.get("address", "0x0"),
                str(func.get("size", 0))
            )

        self.console.print(table)
        if len(functions) > 20:
            self.console.print(f"[dim]... and {len(functions) - 20} more functions[/dim]")

    def list_strings(self):
        """List strings found in the binary"""
        strings = self.ghidra_data.get("strings", [])

        if not strings:
            self.console.print("[yellow]No string data available[/yellow]")
            return

        table = Table(title="Strings")
        table.add_column("Address", style="green")
        table.add_column("Value", style="white")

        for s in strings[:20]:  # Show first 20
            value = s.get("value", "")
            if len(value) > 50:
                value = value[:47] + "..."
            table.add_row(s.get("address", "0x0"), value)

        self.console.print(table)
        if len(strings) > 20:
            self.console.print(f"[dim]... and {len(strings) - 20} more strings[/dim]")

    def list_imports(self):
        """List imported functions"""
        imports = self.ghidra_data.get("imports", [])

        if not imports:
            self.console.print("[yellow]No import data available[/yellow]")
            return

        table = Table(title="Imports")
        table.add_column("Name", style="cyan")
        table.add_column("Library", style="green")

        for imp in imports[:30]:  # Show first 30
            table.add_row(
                imp.get("name", "Unknown"),
                imp.get("library", "Unknown")
            )

        self.console.print(table)
        if len(imports) > 30:
            self.console.print(f"[dim]... and {len(imports) - 30} more imports[/dim]")

    def list_exports(self):
        """List exported functions"""
        exports = self.ghidra_data.get("exports", [])

        if not exports:
            self.console.print("[yellow]No export data available[/yellow]")
            return

        table = Table(title="Exports")
        table.add_column("Name", style="cyan")
        table.add_column("Address", style="green")

        for exp in exports[:20]:
            table.add_row(
                exp.get("name", "Unknown"),
                exp.get("address", "0x0")
            )

        self.console.print(table)
        if len(exports) > 20:
            self.console.print(f"[dim]... and {len(exports) - 20} more exports[/dim]")

    def analyze_function(self, func_name: str):
        """Analyze a specific function"""
        functions = self.ghidra_data.get("functions", [])
        if not functions:
            functions = self.ghidra_data.get("context", {}).get("relevant_functions", [])

        # Find the function
        target_func = None
        for func in functions:
            if func.get("name", "").lower() == func_name.lower():
                target_func = func
                break

        if not target_func:
            self.console.print(f"[red]Function '{func_name}' not found[/red]")
            return

        # Display function details
        self.console.print(f"\n[bold cyan]Function: {target_func['name']}[/bold cyan]")
        self.console.print(f"Address: {target_func.get('address', 'Unknown')}")
        self.console.print(f"Size: {target_func.get('size', 0)} bytes")

        # Show decompiled code if available
        if target_func.get("decompiled_code"):
            self.console.print("\n[bold]Decompiled Code:[/bold]")
            syntax = Syntax(target_func["decompiled_code"], "c", theme="monokai")
            self.console.print(syntax)

        # Show assembly if available
        if target_func.get("assembly_code"):
            self.console.print("\n[bold]Assembly (first 10 instructions):[/bold]")
            for inst in target_func["assembly_code"][:10]:
                self.console.print(f"  {inst['address']}: {inst['mnemonic']} {inst['operands']}")

    def process_custom_query(self, query: str):
        """Process a custom analysis query"""
        # Create a prompt for Claude based on the query and available data
        context = {
            "binary_info": self.ghidra_data.get("binary_info", {}),
            "query": query,
            "available_data": {
                "functions": len(self.ghidra_data.get("functions", [])),
                "strings": len(self.ghidra_data.get("strings", [])),
                "imports": len(self.ghidra_data.get("imports", [])),
                "exports": len(self.ghidra_data.get("exports", []))
            }
        }

        # Generate prompt
        prompt = f"""Analyzing binary: {context['binary_info'].get('name', 'unknown')}
Architecture: {context['binary_info'].get('architecture', 'unknown')}

User query: {query}

Available data:
- {context['available_data']['functions']} functions analyzed
- {context['available_data']['strings']} strings found
- {context['available_data']['imports']} imports
- {context['available_data']['exports']} exports

Please provide analysis based on the available Ghidra data."""

        self.console.print("\n[bold]Claude Analysis Prompt:[/bold]")
        self.console.print(Panel(prompt, style="dim"))

        # Save to history
        self.analysis_history.append({
            "query": query,
            "prompt": prompt,
            "timestamp": datetime.now().isoformat()
        })

    def show_interactive_help(self):
        """Show help for interactive session"""
        help_text = """
[bold cyan]Interactive Session Commands:[/bold cyan]

[bold]Information Commands:[/bold]
  functions     - List all functions
  strings       - List strings found in binary
  imports       - List imported functions
  exports       - List exported functions

[bold]Analysis Commands:[/bold]
  function <name> - Analyze specific function
  <any question>  - Ask any question about the binary

[bold]Session Commands:[/bold]
  help   - Show this help
  exit   - Return to main menu
        """
        self.console.print(Panel(help_text))

    def view_history(self):
        """View analysis history"""
        if not self.analysis_history:
            self.console.print("[yellow]No analysis history available[/yellow]")
            return

        self.console.print("\n[bold cyan]Analysis History[/bold cyan]")
        for i, entry in enumerate(self.analysis_history, 1):
            self.console.print(f"\n[bold]{i}. {entry.get('type', 'Query')}[/bold]")
            self.console.print(f"   Time: {entry['timestamp']}")
            if "query" in entry:
                self.console.print(f"   Query: {entry['query']}")

    def export_report(self):
        """Export analysis session as a report"""
        if not self.ghidra_data and not self.analysis_history:
            self.console.print("[yellow]No data to export[/yellow]")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = f"ghidra_claude_report_{timestamp}"
        report_path = self.session_dir / f"{report_name}.md"

        # Generate markdown report
        report = []
        report.append(f"# Ghidra-Claude Analysis Report")
        report.append(f"\n*Generated: {datetime.now().isoformat()}*\n")

        if self.ghidra_data:
            info = self.ghidra_data.get("binary_info", {})
            report.append("## Binary Information\n")
            report.append(f"- **Name**: {info.get('name', 'Unknown')}")
            report.append(f"- **Architecture**: {info.get('architecture', 'Unknown')}")
            report.append(f"- **Entry Point**: {info.get('entry_point', 'Unknown')}")
            report.append(f"- **Endianness**: {info.get('endianness', 'Unknown')}\n")

        if self.analysis_history:
            report.append("## Analysis Queries\n")
            for entry in self.analysis_history:
                report.append(f"### {entry.get('type', 'Query')}")
                report.append(f"*Time: {entry['timestamp']}*\n")
                if "query" in entry:
                    report.append(f"**Query**: {entry['query']}\n")
                if "prompt" in entry:
                    report.append("**Claude Prompt**:")
                    report.append("```")
                    report.append(entry["prompt"])
                    report.append("```\n")

        # Save report
        report_path.write_text("\n".join(report))
        self.console.print(f"[green]Report exported to: {report_path}[/green]")

        # Also export JSON data if available
        if self.ghidra_data:
            json_path = self.session_dir / f"{report_name}.json"
            with open(json_path, 'w') as f:
                json.dump(self.ghidra_data, f, indent=2)
            self.console.print(f"[green]JSON data exported to: {json_path}[/green]")

    def settings_menu(self):
        """Configure settings"""
        self.console.print("\n[bold cyan]Settings[/bold cyan]")
        self.console.print(f"1. Ghidra Path: {self.ghidra_path}")
        self.console.print(f"2. Session Directory: {self.session_dir}")
        self.console.print("3. Return to Main Menu")

        choice = Prompt.ask("Select option", choices=["1", "2", "3"])

        if choice == "1":
            new_path = Prompt.ask("Enter new Ghidra path")
            if Path(new_path).exists():
                self.ghidra_path = Path(new_path)
                self.bridge = GhidraClaudeBridge(new_path)
                self.console.print("[green]Ghidra path updated[/green]")
            else:
                self.console.print("[red]Invalid path[/red]")
        elif choice == "2":
            new_dir = Prompt.ask("Enter new session directory")
            new_dir = Path(new_dir).expanduser()
            new_dir.mkdir(parents=True, exist_ok=True)
            self.session_dir = new_dir
            self.console.print("[green]Session directory updated[/green]")

    def run(self):
        """Main entry point"""
        self.print_banner()

        # Check if Ghidra path exists
        if not self.ghidra_path.exists():
            self.console.print(f"[yellow]Warning: Ghidra not found at {self.ghidra_path}[/yellow]")
            new_path = Prompt.ask("Enter correct Ghidra path (or press Enter to continue)")
            if new_path:
                self.ghidra_path = Path(new_path)
                self.bridge = GhidraClaudeBridge(new_path)

        self.main_menu()


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(description="Ghidra-Claude Integration CLI")
    parser.add_argument(
        "--ghidra-path",
        default=r"C:\Users\Corbin\Downloads\ghidra-master\build\ghidra_12.0_DEV",
        help="Path to Ghidra installation"
    )
    parser.add_argument(
        "--binary",
        help="Binary file to analyze immediately"
    )
    parser.add_argument(
        "--export",
        help="Ghidra export JSON to load"
    )

    args = parser.parse_args()

    # Create session
    session = GhidraClaudeSession(args.ghidra_path)

    # Load binary or export if provided
    if args.binary:
        session.current_binary = Path(args.binary)
        session.console.print(f"[green]Loaded binary: {args.binary}[/green]")
    elif args.export:
        with open(args.export, 'r') as f:
            session.ghidra_data = json.load(f)
        session.console.print(f"[green]Loaded export: {args.export}[/green]")

    # Run interactive session
    session.run()


if __name__ == "__main__":
    main()