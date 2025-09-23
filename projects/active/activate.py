#!/usr/bin/env python3
"""
Development Environment Activation Script
Run this to activate the development environment.
"""

import sys
from pathlib import Path

# Add shared libraries to path
base_path = Path(__file__).parent
shared_lib_path = base_path / "shared" / "libraries"
sys.path.insert(0, str(shared_lib_path))

print("Development Environment Activated!")
print(f"Base path: {base_path}")
print("Available commands:")
print(
    "  python -c 'from agent_registry import get_registry; print(get_registry().list_agents())'"
)
print(
    "  python -c 'from mcp_registry import get_mcp_registry; print(get_mcp_registry().list_servers())'"
)
