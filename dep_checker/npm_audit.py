"""NPM package vulnerability checker using npm audit

This module handles npm package vulnerability scanning by:
1. Finding all package.json files in the repository
2. Running npm install --production in each directory
3. Running npm audit --json to get vulnerability data
4. Parsing results into Vulnerability objects
"""

import json
import subprocess
import logging
from pathlib import Path
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

# Folder paths to exclude from npm package scanning
# Add folder paths here that should be skipped during package.json discovery
# Paths should be relative to the repository root (e.g., "deps/v8/tools/turbolizer")
# You can also use folder names for broader exclusions (e.g., "test" excludes all test folders)
EXCLUDE_PATHS = [
    # Specific path exclusions
    "deps/v8/tools/turbolizer",

    # General folder name exclusions (will match any folder with this name)
    "test",
    "tests", 
    "examples",
    "example",
    "docs",
    "documentation",
    "demo",
    "demos",
    "coverage",
    ".git",
    ".github"
]


class NPMAuditChecker:
    """Handles npm audit vulnerability checking for package.json files"""
    
    def __init__(self, repo_path: Path, timeout: int = 300):
        self.repo_path = repo_path
        self.timeout = timeout
        self.exclude_paths = EXCLUDE_PATHS  # Use the static exclusion list
        
    def find_package_json_files(self) -> List[Path]:
        """Find all package.json files in the deps/ folder only, excluding specified folders"""
        package_json_files = []
        excluded_count = 0
        
        try:
            # Only search within the deps/ folder
            deps_path = self.repo_path / "deps"
            if not deps_path.exists():
                logger.warning(f"deps/ folder not found at {deps_path}")
                return []
            
            # Use pathlib to recursively find package.json files in deps/ folder
            for package_json in deps_path.rglob("package.json"):
                # Skip node_modules directories
                if "node_modules" in str(package_json):
                    continue
                
                # Check if the package.json is in an excluded path
                is_excluded = False
                package_relative_path = str(package_json.relative_to(self.repo_path))
                
                for exclude_path in self.exclude_paths:
                    # Check for exact path match or if path starts with the exclusion
                    if (package_relative_path.startswith(exclude_path + "/") or 
                        package_relative_path == exclude_path or
                        exclude_path in package_json.parts):  # Also support folder name matching
                        is_excluded = True
                        excluded_count += 1
                        logger.debug(f"Excluding {package_json} (matches exclusion: {exclude_path})")
                        break
                
                if not is_excluded:
                    package_json_files.append(package_json)
            
            logger.info(f"Found {len(package_json_files)} package.json files in deps/ folder")
            if excluded_count > 0:
                logger.info(f"Excluded {excluded_count} package.json files based on exclusion list: {self.exclude_paths}")
            
            return package_json_files
        except Exception as e:
            logger.error(f"Error finding package.json files in deps/ folder: {e}")
            return []
    
    def run_npm_install(self, package_dir: Path) -> bool:
        """Run npm install --production in the given directory"""
        try:
            logger.info(f"Running npm install in {package_dir}")
            # Check if npm is available
            npm_check = subprocess.run(
                ["npm", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if npm_check.returncode != 0:
                logger.error(f"npm is not available: {npm_check.stderr}")
                return False
            
            result = subprocess.run(
                ["npm", "install", "--production", "--no-audit", "--no-fund", "--silent"],
                cwd=package_dir,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode != 0:
                logger.warning(f"npm install failed in {package_dir}: {result.stderr}")
                logger.warning(f"npm install stdout: {result.stdout}")
                return False
            
            logger.info(f"npm install completed successfully in {package_dir}")
            return True
            
        except subprocess.TimeoutExpired:
            logger.error(f"npm install timed out in {package_dir}")
            return False
        except Exception as e:
            logger.error(f"Error running npm install in {package_dir}: {e}")
            return False
    
    def run_npm_audit(self, package_dir: Path) -> Optional[Dict]:
        """Run npm audit --json in the given directory"""
        try:
            logger.info(f"Running npm audit in {package_dir}")
            result = subprocess.run(
                ["npm", "audit", "--json"],
                cwd=package_dir,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            # npm audit returns non-zero exit code when vulnerabilities are found
            # This is expected behavior, so we don't treat it as an error
            if result.stdout:
                try:
                    audit_data = json.loads(result.stdout)
                    logger.info(f"npm audit completed in {package_dir}")
                    return audit_data
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse npm audit JSON output in {package_dir}: {e}")
                    return None
            else:
                logger.warning(f"npm audit returned no output in {package_dir}")
                return None
                
        except subprocess.TimeoutExpired:
            logger.error(f"npm audit timed out in {package_dir}")
            return None
        except Exception as e:
            logger.error(f"Error running npm audit in {package_dir}: {e}")
            return None
    
    def parse_audit_results(self, audit_data: Dict, package_dir: Path, vulnerability_class) -> List:
        """Parse npm audit JSON output into Vulnerability objects"""
        vulnerabilities = []
        
        # Extract main dependency information from package_dir path
        main_dep_name = package_dir.name  # Get the directory name as main dependency
        main_dep_path = str(package_dir.relative_to(self.repo_path))  # Relative path from repo root
        
        try:
            # npm audit v7+ format
            if "vulnerabilities" in audit_data:
                for vuln_name, vuln_data in audit_data["vulnerabilities"].items():
                    try:
                        # Extract vulnerability information
                        severity = vuln_data.get("severity", "unknown")
                        via = vuln_data.get("via", [])
                        fix_available = vuln_data.get("fixAvailable", False)
                        
                        # Handle different via formats
                        if isinstance(via, list) and via:
                            # Get the first vulnerability ID from via
                            first_via = via[0]
                            if isinstance(first_via, dict):
                                vuln_id = first_via.get("source", f"npm-{vuln_name}")
                                url = first_via.get("url", f"https://npmjs.com/advisories/{vuln_id}")
                            else:
                                vuln_id = str(first_via)
                                url = f"https://npmjs.com/advisories/{vuln_id}"
                        else:
                            vuln_id = f"npm-{vuln_name}"
                            url = f"https://npmjs.com/package/{vuln_name}"
                        
                        # Get version range
                        range_info = vuln_data.get("range", "unknown")
                        
                        vulnerability = vulnerability_class(
                            id=vuln_id,
                            url=url,
                            dependency=vuln_name,
                            version=str(range_info),
                            source="npm",
                            severity=severity,
                            via=[str(v) for v in via] if via else [],
                            fix_available=bool(fix_available),
                            main_dep_name=main_dep_name,
                            main_dep_path=main_dep_path
                        )
                        vulnerabilities.append(vulnerability)
                        
                    except Exception as e:
                        logger.error(f"Error parsing vulnerability {vuln_name}: {e}")
                        continue
            
            # Legacy npm audit format (fallback)
            elif "advisories" in audit_data:
                for advisory_id, advisory in audit_data["advisories"].items():
                    try:
                        vulnerability = vulnerability_class(
                            id=f"npm-{advisory_id}",
                            url=advisory.get("url", f"https://npmjs.com/advisories/{advisory_id}"),
                            dependency=advisory.get("module_name", "unknown"),
                            version=advisory.get("vulnerable_versions", "unknown"),
                            source="npm",
                            severity=advisory.get("severity", "unknown"),
                            via=[advisory.get("title", "")],
                            fix_available=bool(advisory.get("patched_versions")),
                            main_dep_name=main_dep_name,
                            main_dep_path=main_dep_path
                        )
                        vulnerabilities.append(vulnerability)
                    except Exception as e:
                        logger.error(f"Error parsing advisory {advisory_id}: {e}")
                        continue
            
            logger.info(f"Parsed {len(vulnerabilities)} vulnerabilities from {package_dir}")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error parsing audit results from {package_dir}: {e}")
            return []
    
    def check_npm_vulnerabilities(self, vulnerability_class) -> List:
        """Main method to check npm vulnerabilities across all package.json files"""
        all_vulnerabilities = []
        package_json_files = self.find_package_json_files()
        
        if not package_json_files:
            logger.info("No package.json files found")
            return all_vulnerabilities
        
        for package_json in package_json_files:
            package_dir = package_json.parent
            logger.info(f"Processing {package_json}")
            
            try:
                # Run npm install
                if not self.run_npm_install(package_dir):
                    logger.warning(f"Skipping npm audit for {package_dir} due to install failure")
                    continue
                
                # Run npm audit
                audit_data = self.run_npm_audit(package_dir)
                if audit_data is None:
                    logger.warning(f"Skipping vulnerability parsing for {package_dir} due to audit failure")
                    continue
                
                # Parse vulnerabilities
                vulnerabilities = self.parse_audit_results(audit_data, package_dir, vulnerability_class)
                all_vulnerabilities.extend(vulnerabilities)
                
            except Exception as e:
                logger.error(f"Error processing {package_json}: {e}")
                continue
        
        logger.info(f"Total npm vulnerabilities found: {len(all_vulnerabilities)}")
        return all_vulnerabilities
