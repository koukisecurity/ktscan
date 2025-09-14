#!/usr/bin/env python3
"""
Test runner script for KTScan.
"""

import os
import subprocess
import sys


def run_tests():
    """Run the test suite"""
    # Change to project directory
    project_root = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_root)
    
    # Install test dependencies if needed
    print("Installing test dependencies...")
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", 
            "pytest>=7.0.0", "pytest-cov>=4.0.0", "pytest-mock>=3.10.0", 
            "pytest-asyncio>=0.21.0", "freezegun>=1.2.0", "responses>=0.23.0"
        ])
    except subprocess.CalledProcessError:
        print("Warning: Failed to install test dependencies")
    
    # Run tests
    print("\nRunning Phase 1 tests (checks)...")
    test_cmd = [
        sys.executable, "-m", "pytest", 
        "tests/unit/checks/",
        "-v",
        "--tb=short",
        "-x"  # Stop on first failure for now
    ]
    
    try:
        result = subprocess.run(test_cmd, check=False)
        return result.returncode == 0
    except Exception as e:
        print(f"Error running tests: {e}")
        return False

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)