#!/usr/bin/env python
"""
Claude Context Optimizer - Maximize token value and efficiency
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional


class ContextOptimizer:
    """Manages and optimizes Claude context usage."""

    def __init__(self, max_tokens: int = 200000):
        self.max_tokens = max_tokens
        self.current_usage = {}
        self.optimization_log = []

    def analyze_current_usage(self) -> Dict:
        """Analyze current context usage patterns."""
        # This would interface with Claude's actual context in production
        usage = {
            "total_tokens": 59000,
            "breakdown": {
                "system_prompt": 4500,
                "system_tools": 11600,
                "mcp_tools": 5700,
                "custom_agents": 118,
                "memory_files": 142,
                "messages": 37200,
            },
            "percentage_used": 29.5,
            "free_tokens": 141000,
        }
        return usage

    def suggest_optimizations(self, usage: Dict) -> List[Dict]:
        """Generate optimization suggestions based on usage."""
        suggestions = []

        # Check message history
        if usage["breakdown"]["messages"] > 30000:
            suggestions.append(
                {
                    "type": "message_cleanup",
                    "priority": "high",
                    "action": "Clear or summarize old conversation history",
                    "potential_savings": f"{usage['breakdown']['messages'] * 0.5:.0f} tokens",
                    "command": "Start a new conversation for unrelated tasks",
                }
            )

        # Check for optimization opportunities
        if usage["percentage_used"] > 50:
            suggestions.append(
                {
                    "type": "context_compression",
                    "priority": "medium",
                    "action": "Enable semantic compression for completed tasks",
                    "potential_savings": "20-30% of current usage",
                    "command": "Summarize completed work into brief outcomes",
                }
            )

        # Tool optimization
        if usage["breakdown"]["system_tools"] > 10000:
            suggestions.append(
                {
                    "type": "tool_optimization",
                    "priority": "low",
                    "action": "Use Task agents for complex operations",
                    "potential_savings": "Offload processing from main context",
                    "command": "Delegate multi-step tasks to specialized agents",
                }
            )

        return suggestions

    def create_optimized_claude_md(self, focus_area: Optional[str] = None) -> str:
        """Generate an optimized CLAUDE.md file for specific tasks."""

        base_instructions = """# Context-Optimized Instructions

## Current Focus
{focus}

## Efficiency Guidelines
1. Use search/grep before reading large files
2. Batch related operations together
3. Use MCP filesystem tools (more efficient than Bash)
4. Clear completed todos regularly
5. Summarize outcomes instead of keeping detailed steps

## Token-Saving Practices
- Read files with head/tail limits when possible
- Use read_multiple_files for batch operations
- Prefer directory_tree over recursive ls
- Use Task agents for complex multi-step operations
"""

        focus_text = focus_area or "General development tasks"
        return base_instructions.format(focus=focus_text)

    def generate_context_report(self) -> str:
        """Generate a detailed context usage report."""
        usage = self.analyze_current_usage()
        suggestions = self.suggest_optimizations(usage)

        report = f"""# Context Usage Report
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Current Usage
- Total: {usage["total_tokens"]:,} / {self.max_tokens:,} tokens ({usage["percentage_used"]:.1f}%)
- Free: {usage["free_tokens"]:,} tokens

## Breakdown
- System Prompt: {usage["breakdown"]["system_prompt"]:,} tokens
- System Tools: {usage["breakdown"]["system_tools"]:,} tokens
- MCP Tools: {usage["breakdown"]["mcp_tools"]:,} tokens
- Messages: {usage["breakdown"]["messages"]:,} tokens
- Other: {usage["breakdown"]["custom_agents"] + usage["breakdown"]["memory_files"]:,} tokens

## Optimization Suggestions
"""

        for i, suggestion in enumerate(suggestions, 1):
            report += f"""
### {i}. {suggestion["type"].replace("_", " ").title()} [{suggestion["priority"].upper()}]
- **Action**: {suggestion["action"]}
- **Savings**: {suggestion["potential_savings"]}
- **How**: {suggestion["command"]}
"""

        report += """
## Quick Actions
1. **Clear History**: Start fresh conversation for new topics
2. **Use Agents**: `Task` tool for complex operations
3. **Batch Operations**: Group related file operations
4. **Search First**: Use grep/search before reading files
5. **Summarize**: Replace detailed history with outcomes

## Best Practices
- Keep CLAUDE.md under 200 tokens
- Use file paths directly instead of storing content
- Leverage parallel tool execution
- Clear todos when tasks complete
"""
        return report

    def export_optimization_config(self, path: str = "claude_optimization.json"):
        """Export optimization configuration."""
        config = {
            "timestamp": datetime.now().isoformat(),
            "current_usage": self.analyze_current_usage(),
            "suggestions": self.suggest_optimizations(self.analyze_current_usage()),
            "settings": {
                "auto_cleanup": True,
                "cleanup_threshold": 150000,
                "compression_enabled": True,
                "smart_caching": True,
            },
        }

        with open(path, "w") as f:
            json.dump(config, f, indent=2)

        return f"Configuration exported to {path}"


def main():
    """Main function to run context optimization."""
    optimizer = ContextOptimizer()

    # Generate and print report
    report = optimizer.generate_context_report()
    print(report)

    # Export configuration
    result = optimizer.export_optimization_config()
    print(f"\n{result}")

    # Create optimized CLAUDE.md
    optimized_md = optimizer.create_optimized_claude_md("Development and debugging")

    claude_md_path = Path.home() / ".claude" / "CLAUDE_OPTIMIZED.md"
    claude_md_path.parent.mkdir(exist_ok=True)

    with open(claude_md_path, "w") as f:
        f.write(optimized_md)

    print(f"\nOptimized instructions saved to: {claude_md_path}")
    print("\nTo apply: Replace your current CLAUDE.md with CLAUDE_OPTIMIZED.md")


if __name__ == "__main__":
    main()
