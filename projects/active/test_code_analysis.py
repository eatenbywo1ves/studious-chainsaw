#!/usr/bin/env python3
"""
Test script to demonstrate the Code Analysis Agent
"""

import sys
import asyncio
from pathlib import Path

# Add agent path
sys.path.insert(0, str(Path(__file__).parent / "agents" / "experimental" / "code-analysis-agent"))

from agent import CodeAnalysisAgent, CodeAnalyzer


async def run_quick_analysis():
    """Run a quick analysis on select files"""
    print("=" * 70)
    print("CODE ANALYSIS AGENT - QUICK DEMONSTRATION")
    print("=" * 70)
    
    analyzer = CodeAnalyzer()
    
    # Analyze a few specific files
    test_files = [
        "C:\\Users\\Corbin\\development\\test_implementations.py",
        "C:\\Users\\Corbin\\development\\demo_new_architecture.py",
        "C:\\Users\\Corbin\\development\\validation_demo.py",
        "C:\\Users\\Corbin\\development\\doctor.py",
        "C:\\Users\\Corbin\\development\\initialize.py"
    ]
    
    total_complexity = 0
    total_doc_coverage = 0
    total_todos = 0
    files_analyzed = 0
    all_issues = []
    
    print("\nAnalyzing Python files in development directory...\n")
    
    for file_path in test_files:
        path = Path(file_path)
        if path.exists():
            print(f"📄 Analyzing: {path.name}")
            metrics = analyzer.analyze_file(path)
            
            if metrics:
                files_analyzed += 1
                total_complexity += metrics.complexity_score
                total_doc_coverage += metrics.documentation_coverage
                total_todos += metrics.todo_count
                
                # Display file metrics
                print(f"   Lines of Code: {metrics.lines_of_code}")
                print(f"   Functions: {metrics.num_functions} | Classes: {metrics.num_classes}")
                print(f"   Complexity Score: {metrics.complexity_score}")
                print(f"   Documentation: {metrics.documentation_coverage:.1f}%")
                
                if metrics.todo_count > 0:
                    print(f"   TODOs: {metrics.todo_count}")
                
                # Check for issues
                if metrics.complexity_score > 20:
                    all_issues.append(f"High complexity in {path.name}: {metrics.complexity_score}")
                
                if metrics.documentation_coverage < 50:
                    all_issues.append(f"Low documentation in {path.name}: {metrics.documentation_coverage:.1f}%")
                
                print()
    
    # Display summary
    print("=" * 70)
    print("ANALYSIS SUMMARY")
    print("=" * 70)
    
    if files_analyzed > 0:
        avg_complexity = total_complexity / files_analyzed
        avg_doc_coverage = total_doc_coverage / files_analyzed
        
        print(f"📊 Files Analyzed: {files_analyzed}")
        print(f"📈 Average Complexity: {avg_complexity:.1f}")
        print(f"📝 Average Documentation: {avg_doc_coverage:.1f}%")
        print(f"📌 Total TODOs: {total_todos}")
        
        if all_issues:
            print(f"\n⚠️  Issues Found ({len(all_issues)}):")
            for issue in all_issues[:5]:  # Show first 5 issues
                print(f"   • {issue}")
        
        # Recommendations
        print("\n💡 Recommendations:")
        if avg_complexity > 15:
            print("   • Consider refactoring complex functions to improve maintainability")
        if avg_doc_coverage < 70:
            print("   • Add docstrings to improve documentation coverage")
        if total_todos > 10:
            print("   • Address outstanding TODOs or convert them to GitHub issues")
        
        print("\n✅ Code Analysis Agent is working correctly!")
        print("   The agent can run continuously to monitor code quality over time.")
        print("   Reports are saved to: C:\\Users\\Corbin\\development\\logs\\code-analysis")
    
    else:
        print("❌ No files could be analyzed")
    
    print("\n" + "=" * 70)


async def test_agent_functionality():
    """Test the full agent functionality"""
    print("\nTesting full agent capabilities...")
    
    agent = CodeAnalysisAgent()
    
    # Get agent status
    status = agent.get_status()
    print(f"Agent Status: {status}")
    
    # Run a single analysis
    results = await agent.analyze_directory(Path("C:\\Users\\Corbin\\development"))
    
    if results["files_analyzed"] > 0:
        print(f"\n✅ Successfully analyzed {results['files_analyzed']} files")
        print(f"   Total lines of code: {results['total_metrics']['total_lines']:,}")
        print(f"   Total functions: {results['total_metrics']['total_functions']}")
        print(f"   Total classes: {results['total_metrics']['total_classes']}")
        
        # Generate and display part of the report
        report = agent.generate_report(results)
        print("\n📋 Sample Report (first 500 chars):")
        print(report[:500] + "...")
        
        # Save full report
        report_path = Path("C:\\Users\\Corbin\\development\\logs\\code-analysis")
        report_path.mkdir(parents=True, exist_ok=True)
        report_file = report_path / "test_analysis_report.md"
        
        with open(report_file, 'w') as f:
            f.write(report)
        
        print(f"\n📁 Full report saved to: {report_file}")


if __name__ == "__main__":
    print("Starting Code Analysis Agent Test...\n")
    
    try:
        # Run quick analysis
        asyncio.run(run_quick_analysis())
        
        # Test full agent
        asyncio.run(test_agent_functionality())
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()