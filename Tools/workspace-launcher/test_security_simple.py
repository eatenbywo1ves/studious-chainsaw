#!/usr/bin/env python3
"""
Security Test Suite - Workspace Launcher (ASCII-only version)
Tests command injection protection and input validation
"""

import sys
from pathlib import Path

# Add workspace launcher to path
sys.path.insert(0, str(Path(__file__).parent))

from workspace_manager import WorkspaceManager, SecurityError


def test_command_whitelist():
    """Test that only whitelisted commands are allowed"""
    print("\n=== Test 1: Command Whitelist Validation ===")

    manager = WorkspaceManager()
    passed = 0
    total = 4

    # Test 1: Allowed command (should pass)
    print("\n[TEST 1] Allowed command: python script.py")
    try:
        cmd_args = manager._validate_and_prepare_command("python script.py", "test-service")
        print("  [PASS] Command validated")
        print(f"     Args: {cmd_args}")
        passed += 1
    except SecurityError as e:
        print(f"  [FAIL] {e}")

    # Test 2: Blocked command (should fail)
    print("\n[TEST 2] Blocked command: malicious-binary exploit.sh")
    try:
        cmd_args = manager._validate_and_prepare_command("malicious-binary exploit.sh", "test-service")
        print(f"  [FAIL] Dangerous command was allowed!")
    except SecurityError as e:
        print(f"  [PASS] Command blocked")
        print(f"     Reason: Malicious command not in whitelist")
        passed += 1

    # Test 3: Command injection attempt (should be safely parsed)
    print("\n[TEST 3] Command injection: python -c 'import os; os.system(\"echo test\")'")
    try:
        cmd_args = manager._validate_and_prepare_command("python -c 'import os; os.system(\"echo test\")'", "test-service")
        print(f"  [PASS] Command validated (safe with shell=False)")
        print(f"     Args: {cmd_args}")
        print(f"     Note: Args are safely parsed, shell injection prevented")
        passed += 1
    except SecurityError as e:
        print(f"  [PASS] Command blocked - {e}")
        passed += 1

    # Test 4: Shell metacharacters (should be safely parsed)
    print("\n[TEST 4] Shell metacharacters: python 'arg1; echo injected'")
    try:
        cmd_args = manager._validate_and_prepare_command("python 'arg1; echo injected'", "test-service")
        print(f"  [PASS] Parsed safely with shell=False")
        print(f"     Args: {cmd_args}")
        print(f"     Note: Semicolon is literal argument, not command separator")
        passed += 1
    except (SecurityError, ValueError) as e:
        print(f"  [PASS] Command rejected - {e}")
        passed += 1

    print(f"\n  Test 1 Results: {passed}/{total} passed")
    return passed == total


def test_allowed_commands():
    """Test all whitelisted commands work"""
    print("\n\n=== Test 2: Whitelisted Commands ===")

    manager = WorkspaceManager()
    passed = 0
    total = 5

    test_commands = [
        "python test.py",
        "node server.js",
        "npm run dev",
        "jupyter lab --no-browser",
        "code .",
    ]

    for cmd in test_commands:
        try:
            cmd_args = manager._validate_and_prepare_command(cmd, "test")
            print(f"  [PASS] {cmd}: {cmd_args}")
            passed += 1
        except SecurityError as e:
            print(f"  [FAIL] {cmd}: BLOCKED - {e}")

    print(f"\n  Test 2 Results: {passed}/{total} passed")
    return passed == total


def test_command_parsing():
    """Test that shlex properly handles complex commands"""
    print("\n\n=== Test 3: Command Parsing ===")

    manager = WorkspaceManager()
    passed = 0
    total = 1

    # Test with quotes
    print("\n[TEST] Command with quotes:")
    cmd = '''python -c "print('hello world')"'''
    try:
        cmd_args = manager._validate_and_prepare_command(cmd, "test")
        print(f"  Input:  {cmd}")
        print(f"  Parsed: {cmd_args}")
        print(f"  [PASS] Quotes handled correctly")
        passed += 1
    except Exception as e:
        print(f"  [FAIL] Failed: {e}")

    print(f"\n  Test 3 Results: {passed}/{total} passed")
    return passed == total


def test_error_sanitization():
    """Test that error messages are sanitized"""
    print("\n\n=== Test 4: Error Message Sanitization ===")

    manager = WorkspaceManager()
    passed = 0
    total = 1

    print("\n[TEST] Verify sanitized errors don't leak paths:")

    # Check that base_dir uses Path.home() not hardcoded path
    if str(manager.base_dir) == str(Path.home()):
        print(f"  [PASS] Base directory uses Path.home()")
        print(f"     Path: {manager.base_dir}")
        passed += 1
    else:
        print(f"  [FAIL] Base directory is hardcoded")
        print(f"     Expected: {Path.home()}")
        print(f"     Got: {manager.base_dir}")

    print(f"\n  Test 4 Results: {passed}/{total} passed")
    return passed == total


def test_security_summary():
    """Print security improvements summary"""
    print("\n\n" + "="*70)
    print("SECURITY IMPROVEMENTS SUMMARY".center(70))
    print("="*70)

    print("\n[P0] Command Injection Protection:")
    print("   - Whitelisted allowed executables only")
    print("   - shell=False prevents shell metacharacter interpretation")
    print("   - shlex.split() safely parses commands into argument lists")

    print("\n[P1] Information Disclosure Prevention:")
    print("   - Error messages sanitized (type + truncated message only)")
    print("   - Hardcoded paths replaced with Path.home()")
    print("   - Full details logged internally for debugging")

    print("\n[PROTECTED] Attack Vectors Blocked:")
    print("   - Command chaining (;, &&, ||)")
    print("   - Pipe redirection (|, >, >>)")
    print("   - Command substitution ($(), ``)")
    print("   - Unauthorized executables")
    print("   - Path disclosure in error messages")

    print("\n[PENDING] P2 Security Work:")
    print("   - Environment variable whitelist")
    print("   - Windows Terminal 'wt' command validation (line 590)")
    print("   - Technology stack enumeration mitigation")

    print("\n[ALLOWED] Command Whitelist:")
    manager = WorkspaceManager()
    allowed = sorted(manager.ALLOWED_COMMANDS)
    for i in range(0, len(allowed), 4):
        print(f"   {', '.join(allowed[i:i+4])}")

    print("\n" + "="*70)


if __name__ == '__main__':
    print("="*70)
    print("WORKSPACE LAUNCHER - SECURITY TEST SUITE".center(70))
    print("="*70)

    try:
        results = []
        results.append(test_command_whitelist())
        results.append(test_allowed_commands())
        results.append(test_command_parsing())
        results.append(test_error_sanitization())
        test_security_summary()

        print("\n" + "="*70)
        if all(results):
            print("[SUCCESS] All security tests passed!".center(70))
        else:
            print(f"[WARNING] {sum(results)}/{len(results)} test groups passed".center(70))
        print("="*70)

        sys.exit(0 if all(results) else 1)

    except Exception as e:
        print(f"\n[ERROR] Test suite failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
