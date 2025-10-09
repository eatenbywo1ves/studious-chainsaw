#!/usr/bin/env python3
"""
Sample Ghidra-Claude Analysis Script
Demonstrates binary analysis workflow
"""

import json
from ghidra_claude_bridge import GhidraClaudeBridge


def analyze_binary(binary_path):
    """Analyze a binary using Ghidra and Claude"""

    # Initialize bridge
    bridge = GhidraClaudeBridge()

    # Load configuration
    with open("ghidra_claude_config.json") as f:
        config = json.load(f)

    bridge.ghidra_home = config["ghidra_home"]

    # Analyze binary
    print(f"Analyzing {binary_path}...")

    # Extract data with Ghidra
    ghidra_data = bridge.analyze_with_ghidra(binary_path)

    # Get AI analysis
    analysis = bridge.get_claude_analysis(ghidra_data, analysis_type="vulnerability")

    # Save results
    output_file = f"{binary_path}.analysis.json"
    with open(output_file, "w") as f:
        json.dump(analysis, f, indent=2)

    print(f"Analysis saved to {output_file}")
    return analysis


if __name__ == "__main__":
    # Example usage
    import sys

    if len(sys.argv) > 1:
        binary = sys.argv[1]
        analyze_binary(binary)
    else:
        print("Usage: python sample_analysis.py <binary_path>")
