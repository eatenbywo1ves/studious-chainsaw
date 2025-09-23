#!/usr/bin/env python3
"""
Code Analysis Agent
A local agent that analyzes Python code for quality metrics, documentation coverage,
and potential improvements. Runs entirely offline with zero network traffic.
"""

import ast
import os
import sys
import json
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import re

# Add shared libraries to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "shared"))

from libraries.agent_registry import AgentRegistry
from utilities.logging_utils import setup_service_logging, LogLevel


@dataclass
class CodeMetrics:
    """Metrics for a single Python file"""
    file_path: str
    lines_of_code: int
    lines_of_comments: int
    lines_of_docstrings: int
    blank_lines: int
    num_functions: int
    num_classes: int
    num_methods: int
    complexity_score: int
    documentation_coverage: float
    test_coverage_estimate: float
    todo_count: int
    imports_count: int
    global_variables: int
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class FunctionAnalysis:
    """Analysis of a single function"""
    name: str
    line_number: int
    parameters: int
    lines: int
    complexity: int
    has_docstring: bool
    has_type_hints: bool
    nested_depth: int
    returns_value: bool


@dataclass
class ClassAnalysis:
    """Analysis of a single class"""
    name: str
    line_number: int
    methods: List[str]
    attributes: List[str]
    inheritance: List[str]
    has_docstring: bool
    is_dataclass: bool
    abstract_methods: int


class CodeAnalyzer:
    """Core code analysis functionality"""
    
    def __init__(self):
        self.logger = setup_service_logging("code-analyzer", LogLevel.INFO)
        self.todo_patterns = [
            r'#\s*(TODO|FIXME|XXX|HACK|NOTE|OPTIMIZE|BUG|REFACTOR)',
            r'""".*?(TODO|FIXME|XXX|HACK|NOTE|OPTIMIZE|BUG|REFACTOR).*?"""',
        ]
        
    def analyze_file(self, file_path: Path) -> Optional[CodeMetrics]:
        """Analyze a single Python file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.splitlines()
            
            # Parse AST
            try:
                tree = ast.parse(content, filename=str(file_path))
            except SyntaxError as e:
                self.logger.warning(f"Syntax error in {file_path}: {e}")
                return None
            
            # Calculate metrics
            metrics = CodeMetrics(
                file_path=str(file_path),
                lines_of_code=len(lines),
                lines_of_comments=self._count_comments(lines),
                lines_of_docstrings=self._count_docstrings(tree),
                blank_lines=self._count_blank_lines(lines),
                num_functions=self._count_functions(tree),
                num_classes=self._count_classes(tree),
                num_methods=self._count_methods(tree),
                complexity_score=self._calculate_complexity(tree),
                documentation_coverage=self._calculate_doc_coverage(tree),
                test_coverage_estimate=self._estimate_test_coverage(tree),
                todo_count=self._count_todos(content),
                imports_count=self._count_imports(tree),
                global_variables=self._count_globals(tree)
            )
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Error analyzing {file_path}: {e}")
            return None
    
    def _count_comments(self, lines: List[str]) -> int:
        """Count comment lines (excluding docstrings)"""
        count = 0
        in_docstring = False
        
        for line in lines:
            stripped = line.strip()
            
            # Track docstring state
            if '"""' in stripped or "'''" in stripped:
                in_docstring = not in_docstring
                continue
            
            # Count regular comments
            if not in_docstring and stripped.startswith('#'):
                count += 1
        
        return count
    
    def _count_docstrings(self, tree: ast.AST) -> int:
        """Count lines in docstrings"""
        count = 0
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
                docstring = ast.get_docstring(node)
                if docstring:
                    count += len(docstring.splitlines())
        
        return count
    
    def _count_blank_lines(self, lines: List[str]) -> int:
        """Count blank lines"""
        return sum(1 for line in lines if not line.strip())
    
    def _count_functions(self, tree: ast.AST) -> int:
        """Count standalone functions (not methods)"""
        count = 0
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Check if it's not a method (not inside a class)
                for parent in ast.walk(tree):
                    if isinstance(parent, ast.ClassDef):
                        if node in ast.walk(parent):
                            break
                else:
                    count += 1
        return count
    
    def _count_classes(self, tree: ast.AST) -> int:
        """Count classes"""
        return sum(1 for node in ast.walk(tree) if isinstance(node, ast.ClassDef))
    
    def _count_methods(self, tree: ast.AST) -> int:
        """Count methods in classes"""
        count = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        count += 1
        return count
    
    def _calculate_complexity(self, tree: ast.AST) -> int:
        """Calculate cyclomatic complexity"""
        complexity = 1  # Base complexity
        
        for node in ast.walk(tree):
            # Add complexity for control flow
            if isinstance(node, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(node, ast.ExceptHandler):
                complexity += 1
            elif isinstance(node, (ast.And, ast.Or)):
                complexity += 1
            elif isinstance(node, ast.comprehension):
                complexity += 1
        
        return complexity
    
    def _calculate_doc_coverage(self, tree: ast.AST) -> float:
        """Calculate documentation coverage percentage"""
        total_items = 0
        documented_items = 0
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                total_items += 1
                if ast.get_docstring(node):
                    documented_items += 1
        
        if total_items == 0:
            return 100.0
        
        return (documented_items / total_items) * 100
    
    def _estimate_test_coverage(self, tree: ast.AST) -> float:
        """Estimate test coverage based on test function presence"""
        total_functions = 0
        test_functions = 0
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                total_functions += 1
                if node.name.startswith('test_') or node.name.endswith('_test'):
                    test_functions += 1
        
        if total_functions == 0:
            return 0.0
        
        # Rough estimate: each test covers ~2 functions
        estimated_coverage = min((test_functions * 2 / total_functions) * 100, 100.0)
        return estimated_coverage
    
    def _count_todos(self, content: str) -> int:
        """Count TODO/FIXME/etc comments"""
        count = 0
        for pattern in self.todo_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            count += len(matches)
        return count
    
    def _count_imports(self, tree: ast.AST) -> int:
        """Count import statements"""
        return sum(1 for node in ast.walk(tree) 
                  if isinstance(node, (ast.Import, ast.ImportFrom)))
    
    def _count_globals(self, tree: ast.AST) -> int:
        """Count global variables"""
        count = 0
        for node in tree.body:
            if isinstance(node, ast.Assign):
                count += len(node.targets)
            elif isinstance(node, ast.AnnAssign):
                count += 1
        return count
    
    def analyze_functions(self, file_path: Path) -> List[FunctionAnalysis]:
        """Detailed analysis of functions in a file"""
        functions = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content, filename=str(file_path))
            
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    analysis = FunctionAnalysis(
                        name=node.name,
                        line_number=node.lineno,
                        parameters=len(node.args.args),
                        lines=node.end_lineno - node.lineno + 1 if hasattr(node, 'end_lineno') else 0,
                        complexity=self._calculate_function_complexity(node),
                        has_docstring=ast.get_docstring(node) is not None,
                        has_type_hints=self._has_type_hints(node),
                        nested_depth=self._get_nested_depth(node),
                        returns_value=self._returns_value(node)
                    )
                    functions.append(analysis)
        
        except Exception as e:
            self.logger.error(f"Error analyzing functions in {file_path}: {e}")
        
        return functions
    
    def _calculate_function_complexity(self, node: ast.AST) -> int:
        """Calculate complexity for a single function"""
        complexity = 1
        
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(child, ast.ExceptHandler):
                complexity += 1
        
        return complexity
    
    def _has_type_hints(self, node: ast.FunctionDef) -> bool:
        """Check if function has type hints"""
        has_return_type = node.returns is not None
        has_param_types = any(arg.annotation is not None for arg in node.args.args)
        return has_return_type or has_param_types
    
    def _get_nested_depth(self, node: ast.AST) -> int:
        """Calculate maximum nesting depth"""
        max_depth = 0
        current_depth = 0
        
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.With)):
                current_depth += 1
                max_depth = max(max_depth, current_depth)
        
        return max_depth
    
    def _returns_value(self, node: ast.FunctionDef) -> bool:
        """Check if function returns a value"""
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and child.value is not None:
                return True
        return False


class CodeAnalysisAgent:
    """Main agent that coordinates code analysis"""
    
    def __init__(self):
        self.logger = setup_service_logging("code-analysis-agent", LogLevel.INFO)
        self.analyzer = CodeAnalyzer()
        self.running = False
        self.analysis_results = {}
        self.config = self._load_config()
        
        # Register with agent registry
        self._register_agent()
    
    def _load_config(self) -> Dict:
        """Load agent configuration"""
        config_path = Path(__file__).parent / "config.json"
        
        if config_path.exists():
            with open(config_path, 'r') as f:
                return json.load(f)
        
        # Default configuration
        return {
            "name": "code-analysis-agent",
            "version": "1.0.0",
            "scan_interval": 300,  # 5 minutes
            "directories": ["C:\\Users\\Corbin\\development"],
            "exclude_patterns": ["__pycache__", ".git", "node_modules", ".venv"],
            "file_extensions": [".py"],
            "max_file_size_mb": 10,
            "generate_reports": True,
            "report_path": "C:\\Users\\Corbin\\development\\logs\\code-analysis"
        }
    
    def _register_agent(self):
        """Register with the agent registry"""
        try:
            registry = AgentRegistry()
            agent_info = {
                "id": "code-analysis-agent",
                "name": self.config["name"],
                "type": "analysis",
                "status": "active",
                "capabilities": [
                    "code_analysis",
                    "documentation_check",
                    "complexity_analysis",
                    "quality_metrics"
                ],
                "version": self.config["version"],
                "endpoint": "local",
                "metadata": {
                    "scan_interval": self.config["scan_interval"],
                    "last_scan": None
                }
            }
            registry.register_agent("code-analysis-agent", agent_info)
            self.logger.info("Agent registered successfully")
        except Exception as e:
            self.logger.warning(f"Failed to register agent: {e}")
    
    async def analyze_directory(self, directory: Path) -> Dict[str, Any]:
        """Analyze all Python files in a directory"""
        self.logger.info(f"Starting analysis of {directory}")
        
        results = {
            "directory": str(directory),
            "timestamp": datetime.now().isoformat(),
            "files_analyzed": 0,
            "total_metrics": {
                "total_lines": 0,
                "total_functions": 0,
                "total_classes": 0,
                "average_complexity": 0,
                "average_doc_coverage": 0,
                "total_todos": 0
            },
            "files": {},
            "issues": [],
            "recommendations": []
        }
        
        complexity_scores = []
        doc_coverages = []
        
        # Find all Python files
        for root, dirs, files in os.walk(directory):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if not any(pattern in d for pattern in self.config["exclude_patterns"])]
            
            for file in files:
                if not file.endswith('.py'):
                    continue
                
                file_path = Path(root) / file
                
                # Skip large files
                if file_path.stat().st_size > self.config["max_file_size_mb"] * 1024 * 1024:
                    self.logger.warning(f"Skipping large file: {file_path}")
                    continue
                
                # Analyze file
                metrics = self.analyzer.analyze_file(file_path)
                
                if metrics:
                    results["files_analyzed"] += 1
                    results["files"][str(file_path)] = metrics.to_dict()
                    
                    # Update totals
                    results["total_metrics"]["total_lines"] += metrics.lines_of_code
                    results["total_metrics"]["total_functions"] += metrics.num_functions
                    results["total_metrics"]["total_classes"] += metrics.num_classes
                    results["total_metrics"]["total_todos"] += metrics.todo_count
                    
                    complexity_scores.append(metrics.complexity_score)
                    doc_coverages.append(metrics.documentation_coverage)
                    
                    # Check for issues
                    self._check_issues(metrics, results["issues"])
        
        # Calculate averages
        if complexity_scores:
            results["total_metrics"]["average_complexity"] = sum(complexity_scores) / len(complexity_scores)
        
        if doc_coverages:
            results["total_metrics"]["average_doc_coverage"] = sum(doc_coverages) / len(doc_coverages)
        
        # Generate recommendations
        results["recommendations"] = self._generate_recommendations(results)
        
        self.logger.info(f"Analysis complete. Analyzed {results['files_analyzed']} files")
        
        return results
    
    def _check_issues(self, metrics: CodeMetrics, issues: List[Dict]):
        """Check for potential issues in code"""
        
        # High complexity
        if metrics.complexity_score > 20:
            issues.append({
                "type": "high_complexity",
                "severity": "warning",
                "file": metrics.file_path,
                "message": f"High complexity score: {metrics.complexity_score}",
                "recommendation": "Consider refactoring to reduce complexity"
            })
        
        # Low documentation
        if metrics.documentation_coverage < 50:
            issues.append({
                "type": "low_documentation",
                "severity": "info",
                "file": metrics.file_path,
                "message": f"Low documentation coverage: {metrics.documentation_coverage:.1f}%",
                "recommendation": "Add docstrings to functions and classes"
            })
        
        # Many TODOs
        if metrics.todo_count > 5:
            issues.append({
                "type": "many_todos",
                "severity": "info",
                "file": metrics.file_path,
                "message": f"Found {metrics.todo_count} TODO comments",
                "recommendation": "Address outstanding TODOs or create issues for them"
            })
        
        # Too many global variables
        if metrics.global_variables > 10:
            issues.append({
                "type": "many_globals",
                "severity": "warning",
                "file": metrics.file_path,
                "message": f"Found {metrics.global_variables} global variables",
                "recommendation": "Consider encapsulating globals in classes or modules"
            })
    
    def _generate_recommendations(self, results: Dict) -> List[str]:
        """Generate overall recommendations"""
        recommendations = []
        
        metrics = results["total_metrics"]
        
        if metrics["average_complexity"] > 15:
            recommendations.append(
                "Overall complexity is high. Consider breaking down complex functions and using design patterns."
            )
        
        if metrics["average_doc_coverage"] < 70:
            recommendations.append(
                f"Documentation coverage is {metrics['average_doc_coverage']:.1f}%. "
                "Improve by adding docstrings to all public functions and classes."
            )
        
        if metrics["total_todos"] > 20:
            recommendations.append(
                f"Found {metrics['total_todos']} TODO comments. "
                "Create a task list to address these or convert them to issues."
            )
        
        if results["files_analyzed"] > 50 and metrics["total_classes"] < 10:
            recommendations.append(
                "Consider using more object-oriented design. "
                "Few classes found relative to the codebase size."
            )
        
        return recommendations
    
    def generate_report(self, results: Dict) -> str:
        """Generate a markdown report"""
        report = []
        
        report.append("# Code Analysis Report")
        report.append(f"\n**Generated**: {results['timestamp']}")
        report.append(f"**Directory**: `{results['directory']}`")
        report.append(f"**Files Analyzed**: {results['files_analyzed']}")
        
        # Summary metrics
        report.append("\n## Summary Metrics")
        metrics = results["total_metrics"]
        report.append(f"- **Total Lines of Code**: {metrics['total_lines']:,}")
        report.append(f"- **Total Functions**: {metrics['total_functions']}")
        report.append(f"- **Total Classes**: {metrics['total_classes']}")
        report.append(f"- **Average Complexity**: {metrics['average_complexity']:.1f}")
        report.append(f"- **Average Documentation**: {metrics['average_doc_coverage']:.1f}%")
        report.append(f"- **Total TODOs**: {metrics['total_todos']}")
        
        # Issues
        if results["issues"]:
            report.append("\n## Issues Found")
            
            # Group by severity
            for severity in ["error", "warning", "info"]:
                severity_issues = [i for i in results["issues"] if i["severity"] == severity]
                if severity_issues:
                    report.append(f"\n### {severity.title()} ({len(severity_issues)})")
                    for issue in severity_issues[:10]:  # Limit to 10 per category
                        report.append(f"- **{issue['type']}** in `{Path(issue['file']).name}`")
                        report.append(f"  - {issue['message']}")
                        report.append(f"  - *{issue['recommendation']}*")
        
        # Recommendations
        if results["recommendations"]:
            report.append("\n## Recommendations")
            for rec in results["recommendations"]:
                report.append(f"- {rec}")
        
        # Top complex files
        report.append("\n## Top Complex Files")
        sorted_files = sorted(
            results["files"].items(),
            key=lambda x: x[1]["complexity_score"],
            reverse=True
        )[:5]
        
        for file_path, metrics in sorted_files:
            report.append(f"- `{Path(file_path).name}` - Complexity: {metrics['complexity_score']}")
        
        return "\n".join(report)
    
    async def run(self):
        """Main agent loop"""
        self.running = True
        self.logger.info("Code Analysis Agent started")
        
        while self.running:
            try:
                # Analyze configured directories
                for directory in self.config["directories"]:
                    dir_path = Path(directory)
                    if dir_path.exists():
                        results = await self.analyze_directory(dir_path)
                        
                        # Store results
                        self.analysis_results[directory] = results
                        
                        # Generate and save report if configured
                        if self.config["generate_reports"]:
                            report = self.generate_report(results)
                            report_path = Path(self.config["report_path"])
                            report_path.mkdir(parents=True, exist_ok=True)
                            
                            report_file = report_path / f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
                            with open(report_file, 'w') as f:
                                f.write(report)
                            
                            self.logger.info(f"Report saved to {report_file}")
                
                # Wait for next scan
                await asyncio.sleep(self.config["scan_interval"])
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in main loop: {e}", exc_info=True)
                await asyncio.sleep(60)  # Wait before retry
        
        self.logger.info("Code Analysis Agent stopped")
    
    def get_status(self) -> Dict:
        """Get current agent status"""
        return {
            "status": "running" if self.running else "stopped",
            "last_analysis": self.analysis_results.get("timestamp"),
            "directories_monitored": self.config["directories"],
            "total_files_analyzed": sum(
                r.get("files_analyzed", 0) 
                for r in self.analysis_results.values()
            )
        }
    
    def get_latest_results(self) -> Dict:
        """Get the latest analysis results"""
        return self.analysis_results


async def main():
    """Main entry point"""
    print("=" * 60)
    print("CODE ANALYSIS AGENT")
    print("Local Python code quality analyzer")
    print("=" * 60)
    
    agent = CodeAnalysisAgent()
    
    try:
        # Run a single analysis for demonstration
        print("\nPerforming initial analysis...")
        results = await agent.analyze_directory(Path("C:\\Users\\Corbin\\development"))
        
        print(f"\nAnalyzed {results['files_analyzed']} files")
        print(f"Average complexity: {results['total_metrics']['average_complexity']:.1f}")
        print(f"Average documentation: {results['total_metrics']['average_doc_coverage']:.1f}%")
        print(f"Total TODOs: {results['total_metrics']['total_todos']}")
        
        if results['issues']:
            print(f"\nFound {len(results['issues'])} issues")
            for issue in results['issues'][:5]:
                print(f"  - {issue['type']}: {Path(issue['file']).name}")
        
        print("\nStarting continuous monitoring...")
        await agent.run()
        
    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Error: {e}")
        agent.logger.error(f"Agent failed: {e}", exc_info=True)


if __name__ == "__main__":
    asyncio.run(main())