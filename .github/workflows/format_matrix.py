#!/usr/bin/env python3
"""
Matrix formatter for vulnerability data

This script takes the JSON output from the vulnerability checker and formats it
into a GitHub Actions matrix with proper labels and all required data for issue creation.
"""

import json
import sys
import re
from typing import List, Dict, Any


def generate_labels_for_vulnerability(vuln: Dict[str, Any], nsolid_stream: str) -> List[str]:
    """Generate GitHub issue labels for a vulnerability based on its properties and nsolid stream"""
    labels = []
    
    # Add nsolid stream as base label
    labels.append(nsolid_stream)
    
    # Add NPM label if it's an npm vulnerability
    if vuln.get("source") == "npm":
        labels.append("NPM")
    
    # Add severity label if available
    severity = vuln.get("severity")
    if severity and severity != "null":
        severity_upper = severity.upper()
        labels.append(severity_upper)
    
    # Extract runtime version from stream (e.g., node-v20.x-nsolid-v5.x -> v20.x)
    runtime_match = re.search(r'node-(v[0-9]+\.x)', nsolid_stream)
    if runtime_match:
        runtime_version = runtime_match.group(1)
        labels.append(runtime_version)
    
    # Extract nsolid version from stream (e.g., node-v20.x-nsolid-v5.x -> v5.x)
    nsolid_match = re.search(r'nsolid-(v[0-9]+\.x)', nsolid_stream)
    if nsolid_match:
        nsolid_version = nsolid_match.group(1)
        labels.append(f"nsolid-{nsolid_version}")
    
    return labels


def build_vulnerability_matrix(vulnerabilities_data: Dict[str, Any], nsolid_stream: str) -> Dict[str, Any]:
    """Build the complete matrix with vulnerabilities and their labels for GitHub Actions"""
    vulnerabilities = vulnerabilities_data.get("vulnerabilities", [])
    
    if not vulnerabilities:
        return {"include": []}
    
    matrix_include = []
    
    for vuln in vulnerabilities:
        labels = generate_labels_for_vulnerability(vuln, nsolid_stream)
        
        matrix_entry = {
            "id": vuln["id"],
            "url": vuln["url"],
            "dependency": vuln["dependency"],
            "version": vuln["version"],
            "source": vuln["source"],
            "labels": labels
        }
        
        # Add npm-specific fields if they exist
        if "severity" in vuln and vuln["severity"] is not None:
            matrix_entry["severity"] = vuln["severity"]
        if "via" in vuln and vuln["via"]:
            matrix_entry["via"] = vuln["via"]
        if "main_dep_name" in vuln and vuln["main_dep_name"] is not None:
            matrix_entry["main_dep_name"] = vuln["main_dep_name"]
        if "main_dep_path" in vuln and vuln["main_dep_path"] is not None:
            matrix_entry["main_dep_path"] = vuln["main_dep_path"]
        if "fix_available" in vuln and vuln["fix_available"] is not None:
            matrix_entry["fix_available"] = vuln["fix_available"]
        
        matrix_include.append({"vulnerabilities": matrix_entry})
    
    return {"include": matrix_include}


def main():
    """Main function to process vulnerability data and output matrix"""
    if len(sys.argv) != 3:
        print("Usage: format_matrix.py <vulnerabilities_json> <nsolid_stream>", file=sys.stderr)
        sys.exit(1)
    
    vulnerabilities_json = sys.argv[1]
    nsolid_stream = sys.argv[2]
    
    try:
        # Parse the vulnerabilities JSON
        vulnerabilities_data = json.loads(vulnerabilities_json)
        
        # Build the matrix
        matrix = build_vulnerability_matrix(vulnerabilities_data, nsolid_stream)
        
        # Output the matrix
        print(json.dumps(matrix))
        
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error processing vulnerabilities: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
