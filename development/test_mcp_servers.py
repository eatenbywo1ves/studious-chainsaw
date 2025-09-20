#!/usr/bin/env python3
"""
Test script to validate MCP server installations and configurations.
This script checks that all required dependencies and files are in place.
"""

import os
import json
import subprocess
import sys
from pathlib import Path

def test_server_directory(name, path):
    """Test if a server directory exists and has required files."""
    print(f"\n[DIR] Testing {name} server...")
    
    if not os.path.exists(path):
        print(f"  [X] Directory not found: {path}")
        return False
    
    print(f"  [OK] Directory exists: {path}")
    
    # Check for common files
    files_to_check = {
        'PRIMS': ['server/main.py', 'requirements.txt'],
        'JSExecutor': ['index.js', 'package.json'],
        'RepoMapper': ['mcp_server.py', 'repomap.py'],
    }
    
    if name in files_to_check:
        for file in files_to_check[name]:
            file_path = os.path.join(path, file)
            if os.path.exists(file_path):
                print(f"  [OK] Found: {file}")
            else:
                print(f"  [X] Missing: {file}")
                return False
    
    return True

def test_python_modules():
    """Test if required Python modules are installed."""
    print("\n[PYTHON] Testing Python modules...")
    
    modules = [
        'mcp_server_notify',  # Desktop notification server
        'igraph',  # For catalytic computing
        'numpy',   # For numerical operations
    ]
    
    for module in modules:
        try:
            __import__(module.replace('-', '_'))
            print(f"  [OK] {module} is installed")
        except ImportError:
            print(f"  [X] {module} is not installed")
            print(f"     Install with: pip install {module}")

def test_node_modules():
    """Test if Node.js and required modules are available."""
    print("\n[NODE] Testing Node.js environment...")
    
    try:
        result = subprocess.run(['node', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"  [OK] Node.js is installed: {result.stdout.strip()}")
        else:
            print("  [X] Node.js is not accessible")
            return False
    except FileNotFoundError:
        print("  [X] Node.js is not installed")
        return False
    
    # Check npm
    try:
        result = subprocess.run(['npm', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"  [OK] npm is installed: {result.stdout.strip()}")
    except:
        print("  [X] npm is not accessible")
    
    return True

def test_claude_config():
    """Test Claude Desktop configuration."""
    print("\n[CONFIG] Testing Claude Desktop configuration...")
    
    config_path = Path.home() / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"
    
    if not config_path.exists():
        print(f"  [X] Configuration not found at: {config_path}")
        return False
    
    print(f"  [OK] Configuration found at: {config_path}")
    
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        if 'mcpServers' in config:
            print(f"  [OK] MCP servers configured: {list(config['mcpServers'].keys())}")
            
            # Validate each server config
            for server_name, server_config in config['mcpServers'].items():
                if 'command' in server_config:
                    print(f"  [OK] {server_name}: Command configured")
                else:
                    print(f"  [X] {server_name}: Missing command")
        else:
            print("  [X] No MCP servers configured")
            return False
            
    except json.JSONDecodeError as e:
        print(f"  [X] Invalid JSON in configuration: {e}")
        return False
    except Exception as e:
        print(f"  [X] Error reading configuration: {e}")
        return False
    
    return True

def main():
    """Main test execution."""
    print("=" * 60)
    print("MCP Server Installation Test Suite")
    print("=" * 60)
    
    base_path = r"C:\Users\Corbin\development\mcp-servers"
    
    # Test each server directory
    servers = {
        'PRIMS': os.path.join(base_path, 'PRIMS'),
        'JSExecutor': os.path.join(base_path, 'js-executor'),
        'RepoMapper': os.path.join(base_path, 'RepoMapper'),
    }
    
    all_good = True
    
    for name, path in servers.items():
        if not test_server_directory(name, path):
            all_good = False
    
    # Test Python environment
    test_python_modules()
    
    # Test Node.js environment
    if not test_node_modules():
        all_good = False
    
    # Test Claude configuration
    if not test_claude_config():
        all_good = False
    
    # Summary
    print("\n" + "=" * 60)
    if all_good:
        print("[SUCCESS] All basic tests passed!")
        print("\nNext steps:")
        print("1. Restart Claude Desktop to load the MCP servers")
        print("2. Test each server's functionality within Claude")
        print("3. Check Claude Desktop logs if servers don't appear")
    else:
        print("[WARNING] Some issues were found. Please address them before proceeding.")
        print("\nTroubleshooting:")
        print("1. Ensure all dependencies are installed")
        print("2. Check file paths in the configuration")
        print("3. Verify Python and Node.js are in your PATH")
    
    print("=" * 60)

if __name__ == "__main__":
    main()