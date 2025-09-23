#!/usr/bin/env python3
"""
MCP Setup Verification Script

This script verifies that all MCP servers are properly configured and accessible
in the new development structure.
"""

import os
import json
import sys
from pathlib import Path


def check_file_exists(path, description):
    """Check if a file or directory exists."""
    if os.path.exists(path):
        print(f"[OK] {description}: {path}")
        return True
    else:
        print(f"[MISSING] {description}: {path}")
        return False


def verify_mcp_configuration():
    """Verify MCP configuration and server files."""
    print("MCP Setup Verification")
    print("=" * 50)

    # Check Claude Code configuration
    print("\n1. Claude Code Configuration:")
    claude_code_config = Path.home() / ".mcp.json"
    config_exists = check_file_exists(claude_code_config, "Claude Code config")

    if config_exists:
        try:
            with open(claude_code_config, "r") as f:
                config = json.load(f)
                servers = config.get("mcpServers", {})
                print(f"   Found {len(servers)} MCP servers configured")

                for server_name in servers:
                    print(f"   - {server_name}")
        except Exception as e:
            print(f"   Error reading config: {e}")

    # Check MCP server files
    print("\n2. MCP Server Files:")
    base_path = Path(__file__).parent

    servers_to_check = [
        ("financial-localization", "mcp-servers/financial/localization/src/index.js"),
        ("financial-stochastic", "mcp-servers/financial/stochastic/src/index.js"),
        (
            "multidimensional-stochastic",
            "mcp-servers/financial/multidimensional/src/index.js",
        ),
        ("random-walk", "mcp-servers/utilities/random-walk/src/index.js"),
    ]

    all_servers_found = True
    for server_name, relative_path in servers_to_check:
        server_path = base_path / relative_path
        exists = check_file_exists(server_path, f"{server_name} server")
        if not exists:
            all_servers_found = False

    # Check package.json files
    print("\n3. Package Dependencies:")
    for server_name, relative_path in servers_to_check:
        package_path = base_path / relative_path.replace(
            "/src/index.js", "/package.json"
        )
        if os.path.exists(package_path):
            try:
                with open(package_path, "r") as f:
                    package_info = json.load(f)
                    dependencies = package_info.get("dependencies", {})
                    print(f"   [OK] {server_name}: {len(dependencies)} dependencies")
            except Exception:
                print(f"   [WARNING] {server_name}: Could not read package.json")
        else:
            print(f"   [MISSING] {server_name}: No package.json found")

    # Check development directory structure
    print("\n4. Development Structure:")
    structure_checks = [
        ("agents/production", "Production agents directory"),
        ("mcp-servers/financial", "Financial MCP servers"),
        ("mcp-servers/utilities", "Utility MCP servers"),
        ("configs/mcp", "MCP configurations"),
        ("shared/libraries", "Shared libraries"),
    ]

    for relative_path, description in structure_checks:
        full_path = base_path / relative_path
        check_file_exists(full_path, description)

    # Summary
    print("\n" + "=" * 50)
    if all_servers_found and config_exists:
        print("[SUCCESS] VERIFICATION COMPLETE - All systems ready!")
        print("\nNext steps:")
        print("1. Restart Claude Code if you haven't already")
        print("2. Test MCP functions (e.g., generate_gbm, generate_simple_walk)")
        print("3. Use filesystem MCP to explore the development directory")
    else:
        print("[WARNING] ISSUES FOUND - Some components need attention")
        print("\nPlease check the items marked with [MISSING] above")

    print("\nYour new development structure is at:")
    print(f"[PATH] {base_path}")


if __name__ == "__main__":
    try:
        verify_mcp_configuration()
    except Exception as e:
        print(f"Error during verification: {e}")
        sys.exit(1)
