#!/usr/bin/env python3
"""
Execute the Code Analysis Agent and display results
"""

import sys
import json
from pathlib import Path
from datetime import datetime

# Add agent path
sys.path.insert(0, str(Path(__file__).parent / "agents" / "experimental" / "code-analysis-agent"))

def run_analysis():
    """Run the code analysis and display results"""
    from agent import CodeAnalyzer
    
    print("=" * 70)
    print("🔍 CODE ANALYSIS AGENT - ANALYZING YOUR CODEBASE")
    print("=" * 70)
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    analyzer = CodeAnalyzer()
    
    # Key Python files to analyze
    files_to_analyze = [
        # Core implementation files
        "test_implementations.py",
        "demo_new_architecture.py",
        "validation_demo.py",
        "initialize.py",
        "doctor.py",
        "activate.py",
        "financial_stochastic_demo.py",
        "mcp_stochastic_demo.py",
        "integration_test_agent.py",
        "production-tmux-setup.py",
        "test_input_validation.py",
        "test_tmux_integration.py",
        "verify-mcp-setup.py",
        # The agent itself
        "agents/experimental/code-analysis-agent/agent.py"
    ]
    
    base_path = Path("C:/Users/Corbin/development")
    
    # Metrics collection
    all_metrics = []
    total_lines = 0
    total_functions = 0
    total_classes = 0
    total_complexity = 0
    total_doc_scores = []
    total_todos = 0
    issues = {
        "high_complexity": [],
        "low_documentation": [],
        "many_todos": [],
        "many_globals": []
    }
    
    print("📊 Analyzing Python Files...")
    print("-" * 70)
    
    for file_name in files_to_analyze:
        file_path = base_path / file_name
        
        if file_path.exists():
            metrics = analyzer.analyze_file(file_path)
            
            if metrics:
                all_metrics.append(metrics)
                
                # Update totals
                total_lines += metrics.lines_of_code
                total_functions += metrics.num_functions
                total_classes += metrics.num_classes
                total_complexity += metrics.complexity_score
                total_doc_scores.append(metrics.documentation_coverage)
                total_todos += metrics.todo_count
                
                # Display file analysis
                print(f"\n📄 {file_name}")
                print(f"   Lines: {metrics.lines_of_code:,} | "
                      f"Functions: {metrics.num_functions} | "
                      f"Classes: {metrics.num_classes}")
                print(f"   Complexity: {metrics.complexity_score} | "
                      f"Documentation: {metrics.documentation_coverage:.1f}%")
                
                if metrics.todo_count > 0:
                    print(f"   TODOs: {metrics.todo_count}")
                
                # Check for issues
                if metrics.complexity_score > 20:
                    issues["high_complexity"].append({
                        "file": file_name,
                        "score": metrics.complexity_score
                    })
                    print(f"   ⚠️  High complexity detected!")
                
                if metrics.documentation_coverage < 50:
                    issues["low_documentation"].append({
                        "file": file_name,
                        "coverage": metrics.documentation_coverage
                    })
                    print(f"   ⚠️  Low documentation coverage!")
                
                if metrics.todo_count > 5:
                    issues["many_todos"].append({
                        "file": file_name,
                        "count": metrics.todo_count
                    })
                
                if metrics.global_variables > 10:
                    issues["many_globals"].append({
                        "file": file_name,
                        "count": metrics.global_variables
                    })
    
    # Calculate averages
    files_analyzed = len(all_metrics)
    avg_complexity = total_complexity / files_analyzed if files_analyzed > 0 else 0
    avg_documentation = sum(total_doc_scores) / len(total_doc_scores) if total_doc_scores else 0
    
    # Display summary
    print("\n" + "=" * 70)
    print("📈 ANALYSIS SUMMARY")
    print("=" * 70)
    
    print(f"\n📊 Overall Metrics:")
    print(f"   Files Analyzed: {files_analyzed}")
    print(f"   Total Lines of Code: {total_lines:,}")
    print(f"   Total Functions: {total_functions}")
    print(f"   Total Classes: {total_classes}")
    print(f"   Total TODOs: {total_todos}")
    
    print(f"\n📉 Averages:")
    print(f"   Average Complexity: {avg_complexity:.1f}")
    print(f"   Average Documentation: {avg_documentation:.1f}%")
    
    # Display issues
    total_issues = sum(len(v) for v in issues.values())
    if total_issues > 0:
        print(f"\n⚠️  Issues Found: {total_issues}")
        
        if issues["high_complexity"]:
            print(f"\n🔴 High Complexity ({len(issues['high_complexity'])} files):")
            for issue in issues["high_complexity"][:5]:
                print(f"   - {issue['file']}: score {issue['score']}")
        
        if issues["low_documentation"]:
            print(f"\n📝 Low Documentation ({len(issues['low_documentation'])} files):")
            for issue in issues["low_documentation"][:5]:
                print(f"   - {issue['file']}: {issue['coverage']:.1f}% coverage")
    
    # Recommendations
    print("\n" + "=" * 70)
    print("💡 RECOMMENDATIONS")
    print("=" * 70)
    
    if avg_complexity > 15:
        print("• Consider refactoring high-complexity files to improve maintainability")
        print("  Focus on files with complexity > 20")
    
    if avg_documentation < 70:
        print("• Improve documentation coverage by adding docstrings")
        print("  Priority: Functions and classes in production code")
    
    if total_todos > 20:
        print("• Address outstanding TODOs or convert them to GitHub issues")
        print("  Found {} TODOs across the codebase".format(total_todos))
    
    if issues["high_complexity"]:
        print("• Top complexity reduction targets:")
        for issue in issues["high_complexity"][:3]:
            print(f"  - {issue['file']}")
    
    # Quality grade
    print("\n" + "=" * 70)
    print("🏆 CODE QUALITY GRADE")
    print("=" * 70)
    
    # Calculate grade
    grade_score = 100
    grade_score -= max(0, (avg_complexity - 10) * 2)  # Penalty for complexity
    grade_score -= max(0, (70 - avg_documentation) * 0.5)  # Penalty for low docs
    grade_score -= min(10, total_todos * 0.5)  # Penalty for TODOs
    
    if grade_score >= 90:
        grade = "A"
        emoji = "🌟"
        message = "Excellent code quality!"
    elif grade_score >= 80:
        grade = "B"
        emoji = "✨"
        message = "Good code quality with room for improvement"
    elif grade_score >= 70:
        grade = "C"
        emoji = "👍"
        message = "Acceptable quality, consider addressing issues"
    else:
        grade = "D"
        emoji = "⚠️"
        message = "Needs improvement in several areas"
    
    print(f"\n   {emoji} Grade: {grade} ({grade_score:.1f}/100)")
    print(f"   {message}")
    
    # Save results
    print("\n" + "=" * 70)
    print("💾 SAVING RESULTS")
    print("=" * 70)
    
    # Create results directory
    results_dir = base_path / "logs" / "code-analysis"
    results_dir.mkdir(parents=True, exist_ok=True)
    
    # Save JSON results
    results_file = results_dir / f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    results_data = {
        "timestamp": datetime.now().isoformat(),
        "files_analyzed": files_analyzed,
        "total_metrics": {
            "lines": total_lines,
            "functions": total_functions,
            "classes": total_classes,
            "todos": total_todos,
            "avg_complexity": avg_complexity,
            "avg_documentation": avg_documentation
        },
        "issues": issues,
        "grade": {
            "score": grade_score,
            "letter": grade
        },
        "files": [m.to_dict() for m in all_metrics]
    }
    
    with open(results_file, 'w') as f:
        json.dump(results_data, f, indent=2)
    
    print(f"   ✅ Results saved to: {results_file}")
    
    # Create markdown report
    report_file = results_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    
    report = []
    report.append("# Code Analysis Report")
    report.append(f"\n**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"**Files Analyzed**: {files_analyzed}")
    report.append(f"\n## Grade: {grade} ({grade_score:.1f}/100)\n")
    report.append("## Summary Metrics\n")
    report.append(f"- **Total Lines**: {total_lines:,}")
    report.append(f"- **Functions**: {total_functions}")
    report.append(f"- **Classes**: {total_classes}")
    report.append(f"- **Average Complexity**: {avg_complexity:.1f}")
    report.append(f"- **Documentation Coverage**: {avg_documentation:.1f}%")
    report.append(f"- **TODOs**: {total_todos}")
    
    if issues["high_complexity"]:
        report.append("\n## High Complexity Files\n")
        for issue in issues["high_complexity"]:
            report.append(f"- {issue['file']}: score {issue['score']}")
    
    with open(report_file, 'w') as f:
        f.write("\n".join(report))
    
    print(f"   ✅ Report saved to: {report_file}")
    
    print("\n" + "=" * 70)
    print("✅ ANALYSIS COMPLETE!")
    print("=" * 70)
    print("\nThe Code Analysis Agent has successfully analyzed your codebase.")
    print("Check the logs/code-analysis directory for detailed reports.")
    
    return results_data


if __name__ == "__main__":
    try:
        results = run_analysis()
        print("\n📊 The agent can run continuously to monitor changes over time.")
        print("   Configure scan_interval in config.json to set frequency.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()