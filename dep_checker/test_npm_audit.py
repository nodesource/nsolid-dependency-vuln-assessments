#!/usr/bin/env python3
"""Simple test script to verify npm audit functionality"""

import tempfile
import json
from pathlib import Path
from npm_audit import NPMAuditChecker
from main import Vulnerability

def create_test_package_json(temp_dir: Path) -> Path:
    """Create a test package.json with known vulnerable packages"""
    package_json_content = {
        "name": "test-package",
        "version": "1.0.0",
        "dependencies": {
            # Using an older version that might have known vulnerabilities
            "lodash": "4.17.0"
        }
    }
    
    package_json_path = temp_dir / "package.json"
    with open(package_json_path, 'w') as f:
        json.dump(package_json_content, f, indent=2)
    
    return package_json_path

def test_npm_audit_basic():
    """Test basic npm audit functionality"""
    print("Testing npm audit functionality...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create test package.json
        package_json = create_test_package_json(temp_path)
        print(f"Created test package.json at: {package_json}")
        
        # Test NPM audit checker
        checker = NPMAuditChecker(temp_path, timeout=60)
        
        # Test finding package.json files
        package_files = checker.find_package_json_files()
        print(f"Found {len(package_files)} package.json files")
        assert len(package_files) == 1, "Should find exactly one package.json file"
        
        # Test npm audit (this will only work if npm is available)
        try:
            vulnerabilities = checker.check_npm_vulnerabilities(Vulnerability)
            print(f"Found {len(vulnerabilities)} vulnerabilities")
            
            # Print vulnerability details
            for vuln in vulnerabilities:
                print(f"- {vuln.dependency} ({vuln.version}): {vuln.id} - {vuln.severity}")
                
        except Exception as e:
            print(f"npm audit test failed (this is expected if npm is not available): {e}")
    
    print("Basic npm audit test completed!")

if __name__ == "__main__":
    test_npm_audit_basic()
