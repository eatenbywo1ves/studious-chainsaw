#!/usr/bin/env python3
"""
Configure Ghidra-Claude Integration
Sets up the integration between Ghidra and Claude for binary analysis
"""

import os
import json
import shutil
from pathlib import Path

class GhidraClaudeConfigurator:
    """Configure Ghidra-Claude integration"""

    def __init__(self):
        self.ghidra_paths = [
            r"C:\Users\Corbin\Downloads\ghidra-master\build\ghidra_12.0_DEV",
            r"C:\Users\Corbin\Downloads\ghidra-master",
            r"C:\Program Files\Ghidra"
        ]
        self.ghidra_home = None
        self.scripts_dir = None
        self.config = {}

    def find_ghidra(self):
        """Locate Ghidra installation"""
        print("Searching for Ghidra installation...")

        for path in self.ghidra_paths:
            if os.path.exists(path):
                # Check for analyzeHeadless script
                headless_bat = os.path.join(path, "support", "analyzeHeadless.bat")
                headless_sh = os.path.join(path, "support", "analyzeHeadless")

                if os.path.exists(headless_bat) or os.path.exists(headless_sh):
                    self.ghidra_home = path
                    print(f"  [OK] Found Ghidra at: {path}")
                    return True

        print("  [WARN] Ghidra installation not found automatically")
        return False

    def setup_scripts_directory(self):
        """Set up Ghidra scripts directory"""
        if not self.ghidra_home:
            return False

        # Find scripts directory
        script_paths = [
            os.path.join(self.ghidra_home, "Ghidra", "Features", "Base", "ghidra_scripts"),
            os.path.join(self.ghidra_home, "ghidra_scripts"),
            os.path.join(os.path.expanduser("~"), ".ghidra", ".ghidra_12.0_DEV", "scripts")
        ]

        for path in script_paths:
            if os.path.exists(path):
                self.scripts_dir = path
                print(f"  [OK] Scripts directory: {path}")
                return True

        # Create user scripts directory if needed
        user_scripts = os.path.join(os.path.expanduser("~"), ".ghidra", "scripts")
        os.makedirs(user_scripts, exist_ok=True)
        self.scripts_dir = user_scripts
        print(f"  [OK] Created scripts directory: {user_scripts}")
        return True

    def install_export_script(self):
        """Install the ExportForClaude.py script"""
        script_source = "ExportForClaude.py"

        if not os.path.exists(script_source):
            print("  [WARN] ExportForClaude.py not found in current directory")
            return False

        if not self.scripts_dir:
            print("  [FAIL] Scripts directory not configured")
            return False

        # Copy script to Ghidra scripts directory
        dest_path = os.path.join(self.scripts_dir, "ExportForClaude.py")

        try:
            shutil.copy2(script_source, dest_path)
            print(f"  [OK] Installed ExportForClaude.py to {dest_path}")
            return True
        except Exception as e:
            print(f"  [FAIL] Could not install script: {e}")
            return False

    def create_config(self):
        """Create configuration file"""
        self.config = {
            "ghidra_home": self.ghidra_home,
            "scripts_directory": self.scripts_dir,
            "headless_path": os.path.join(self.ghidra_home, "support", "analyzeHeadless.bat") if self.ghidra_home else None,
            "export_script": "ExportForClaude.py",
            "claude_api": {
                "model": "claude-3-opus-20240229",
                "max_tokens": 4096,
                "temperature": 0.7
            },
            "analysis_options": {
                "vulnerability_scan": True,
                "malware_analysis": True,
                "crypto_detection": True,
                "protocol_analysis": True
            },
            "output_directory": "outputs",
            "cache_directory": ".cache"
        }

        # Save configuration
        config_path = "ghidra_claude_config.json"
        with open(config_path, 'w') as f:
            json.dump(self.config, f, indent=2)

        print(f"  [OK] Configuration saved to {config_path}")
        return True

    def test_integration(self):
        """Test the integration setup"""
        print("\nTesting Integration...")

        # Test 1: Check if bridge module can be imported
        try:
            import ghidra_claude_bridge
            print("  [OK] Bridge module imports successfully")
        except ImportError as e:
            print(f"  [FAIL] Cannot import bridge module: {e}")
            return False

        # Test 2: Check if CLI is available
        if os.path.exists("ghidra_claude_cli.py"):
            print("  [OK] CLI interface available")
        else:
            print("  [WARN] CLI interface not found")

        # Test 3: Check Ghidra headless availability
        if self.ghidra_home:
            headless = os.path.join(self.ghidra_home, "support", "analyzeHeadless.bat")
            if os.path.exists(headless):
                print("  [OK] Ghidra headless analyzer available")
            else:
                print("  [WARN] Ghidra headless analyzer not found")

        return True

    def create_sample_analysis(self):
        """Create a sample analysis script"""
        sample_script = """#!/usr/bin/env python3
'''
Sample Ghidra-Claude Analysis Script
Demonstrates binary analysis workflow
'''

import json
from ghidra_claude_bridge import GhidraClaudeBridge

def analyze_binary(binary_path):
    '''Analyze a binary using Ghidra and Claude'''

    # Initialize bridge
    bridge = GhidraClaudeBridge()

    # Load configuration
    with open('ghidra_claude_config.json') as f:
        config = json.load(f)

    bridge.ghidra_home = config['ghidra_home']

    # Analyze binary
    print(f"Analyzing {binary_path}...")

    # Extract data with Ghidra
    ghidra_data = bridge.analyze_with_ghidra(binary_path)

    # Get AI analysis
    analysis = bridge.get_claude_analysis(
        ghidra_data,
        analysis_type='vulnerability'
    )

    # Save results
    output_file = f"{binary_path}.analysis.json"
    with open(output_file, 'w') as f:
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
"""

        with open("sample_analysis.py", 'w') as f:
            f.write(sample_script)

        print("  [OK] Created sample_analysis.py")

    def run(self):
        """Run the complete configuration process"""
        print("="*60)
        print("    GHIDRA-CLAUDE INTEGRATION CONFIGURATION")
        print("="*60)

        # Step 1: Find Ghidra
        print("\n1. Locating Ghidra Installation:")
        ghidra_found = self.find_ghidra()

        # Step 2: Setup scripts
        if ghidra_found:
            print("\n2. Setting up Scripts Directory:")
            self.setup_scripts_directory()

            print("\n3. Installing Export Script:")
            self.install_export_script()
        else:
            print("\n2. Skipping script setup (Ghidra not found)")

        # Step 3: Create configuration
        print("\n4. Creating Configuration:")
        self.create_config()

        # Step 4: Create samples
        print("\n5. Creating Sample Scripts:")
        self.create_sample_analysis()

        # Step 5: Test
        print("\n6. Testing Integration:")
        self.test_integration()

        # Summary
        print("\n" + "="*60)
        print("    CONFIGURATION SUMMARY")
        print("="*60)

        if ghidra_found:
            print("[OK] Ghidra installation found and configured")
            print(f"     Location: {self.ghidra_home}")
            print(f"     Scripts: {self.scripts_dir}")
        else:
            print("[WARN] Ghidra not found - manual configuration needed")

        print("\n[OK] Configuration files created")
        print("[OK] Sample scripts generated")

        print("\nNext Steps:")
        print("1. If Ghidra not found, install from: https://ghidra-sre.org/")
        print("2. Open Ghidra and run the ExportForClaude script on a binary")
        print("3. Use ghidra_claude_cli.py for interactive analysis")
        print("4. Run sample_analysis.py on a test binary")

        print("\nUsage Examples:")
        print("  python ghidra_claude_cli.py --binary /path/to/binary")
        print("  python ghidra_claude_cli.py --load export.json")
        print("  python sample_analysis.py malware.exe")

        return ghidra_found

def main():
    """Main entry point"""
    configurator = GhidraClaudeConfigurator()
    success = configurator.run()

    if success:
        print("\n[OK] Ghidra-Claude integration configured successfully!")
    else:
        print("\n[WARN] Configuration completed with warnings")
        print("       Manual setup may be required for full functionality")

if __name__ == "__main__":
    main()