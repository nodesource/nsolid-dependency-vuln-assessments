""" Node.js dependency vulnerability checker

This script queries the National Vulnerability Database (NVD) and the GitHub Advisory Database for vulnerabilities found
in Node's dependencies.

For each dependency in Node's `deps/` folder, the script parses their version number and queries the databases to find
vulnerabilities for that specific version.

If any vulnerabilities are found, the script returns 1 and prints out a list with the ID and a link to a description of
the vulnerability. This is the case except when the ID matches one in the ignore-list (inside `dependencies.py`) in
which case the vulnerability is ignored.
"""

from argparse import ArgumentParser
from dependencies import (
    ignore_list,
    dependencies_info,
    Dependency,
    dependencies_per_branch,
)
from gql import gql, Client
from gql.transport.aiohttp import AIOHTTPTransport
from nvdlib import searchCVE  # type: ignore
from packaging.specifiers import SpecifierSet
from typing import Optional, List
from pathlib import Path

import json
import logging


class Vulnerability:
    def __init__(self, id: str, url: str, dependency: str, version: str, source: str = "binary", 
                 severity: Optional[str] = None, via: Optional[list] = None, 
                 fix_available: Optional[bool] = None, main_dep_name: Optional[str] = None,
                 main_dep_path: Optional[str] = None):
        self.id = id
        self.url = url
        self.dependency = dependency
        self.version = version
        self.source = source  # "binary" or "npm"
        self.severity = severity  # npm audit severity levels
        self.via = via or []  # npm audit vulnerability chain
        self.fix_available = fix_available  # whether fix is available
        self.main_dep_name = main_dep_name  # main dependency name for npm vulnerabilities
        self.main_dep_path = main_dep_path  # path to the main dependency


class VulnerabilityEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Vulnerability):
            result = {
                "id": obj.id,
                "url": obj.url,
                "dependency": obj.dependency,
                "version": obj.version,
                "source": obj.source,
            }
            # Add npm-specific fields if they exist
            if obj.severity is not None:
                result["severity"] = obj.severity
            if obj.via:
                result["via"] = obj.via
            if obj.main_dep_name is not None:
                result["main_dep_name"] = obj.main_dep_name
            if obj.main_dep_path is not None:
                result["main_dep_path"] = obj.main_dep_path
            if obj.fix_available is not None:
                result["fix_available"] = obj.fix_available
            return result
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


vulnerability_found_message = """For each dependency and vulnerability, check the following:
- Check that the dependency's version printed by the script corresponds to the version present in the Node repo.
If not, update dependencies.py with the actual version number and run the script again.
- If the version is correct, check the vulnerability's description to see if it applies to the dependency as
used by Node. If not, the vulnerability ID (either a CVE or a GHSA) can be added to the ignore list in
dependencies.py. IMPORTANT: Only do this if certain that the vulnerability found is a false positive.
- Otherwise, the vulnerability found must be remediated by updating the dependency in the Node repo to a
non-affected version, followed by updating dependencies.py with the new version.
"""


github_vulnerabilities_query = gql(
    """
    query($package_name:String!) {
      securityVulnerabilities(package:$package_name, last:10) {
        nodes {
          vulnerableVersionRange
          advisory {
            ghsaId
            permalink
            withdrawnAt
          }
        }
      }
    }
"""
)


def query_ghad(
    dependencies: dict[str, Dependency], gh_token: str, repo_path: Path
) -> list[Vulnerability]:
    """Queries the GitHub Advisory Database for vulnerabilities reported for Node's dependencies.

    The database supports querying by package name in the NPM ecosystem, so we only send queries for the dependencies
    that are also NPM packages.
    """

    deps_in_npm = {
        name: dep for name, dep in dependencies.items() if dep.npm_name is not None
    }

    transport = AIOHTTPTransport(
        url="https://api.github.com/graphql",
        headers={"Authorization": f"bearer {gh_token}"},
    )
    client = Client(
        transport=transport,
        fetch_schema_from_transport=True,
        serialize_variables=True,
        parse_results=True,
    )

    found_vulnerabilities: list[Vulnerability] = list()
    for name, dep in deps_in_npm.items():
        variables_package = {
            "package_name": dep.npm_name,
        }
        result = client.execute(
            github_vulnerabilities_query, variable_values=variables_package
        )
        dep_version = dep.version_parser(repo_path)
        matching_vulns = [
            v
            for v in result["securityVulnerabilities"]["nodes"]
            if v["advisory"]["withdrawnAt"] is None
            and dep_version in SpecifierSet(v["vulnerableVersionRange"])
            and v["advisory"]["ghsaId"] not in ignore_list
        ]
        if matching_vulns:
            found_vulnerabilities.extend(
                [
                    Vulnerability(
                        id=vuln["advisory"]["ghsaId"],
                        url=vuln["advisory"]["permalink"],
                        dependency=name,
                        version=dep_version,
                    )
                    for vuln in matching_vulns
                ]
            )

    return found_vulnerabilities


def query_nvd(
    dependencies: dict[str, Dependency], api_key: Optional[str], repo_path: Path
) -> list[Vulnerability]:
    """Queries the National Vulnerability Database for vulnerabilities reported for Node's dependencies.

    The database supports querying by CPE (Common Platform Enumeration) or by a keyword present in the CVE's
    description.
    Since some of Node's dependencies don't have an associated CPE, we use their name as a keyword in the query.
    """
    deps_in_nvd = {
        name: dep
        for name, dep in dependencies.items()
        if dep.cpe is not None or dep.keyword is not None
    }
    found_vulnerabilities: list[Vulnerability] = list()
    for name, dep in deps_in_nvd.items():
        query_results = [
            cve
            for cve in searchCVE(
                virtualMatchString=dep.get_cpe(repo_path),
                keywordSearch=dep.keyword,
                key=api_key,
                delay=6 if api_key else False,
            )
            if cve.id not in ignore_list
        ]
        if query_results:
            version = dep.version_parser(repo_path)
            for cve in query_results:
                # Extract severity from CVE metrics
                severity = None
                try:
                    # Try to get CVSS v3 base severity first
                    if hasattr(cve, 'metrics') and cve.metrics:
                        if hasattr(cve.metrics, 'cvssMetricV31') and cve.metrics.cvssMetricV31:
                            severity = cve.metrics.cvssMetricV31[0].cvssData.baseSeverity
                        elif hasattr(cve.metrics, 'cvssMetricV30') and cve.metrics.cvssMetricV30:
                            severity = cve.metrics.cvssMetricV30[0].cvssData.baseSeverity
                        elif hasattr(cve.metrics, 'cvssMetricV2') and cve.metrics.cvssMetricV2:
                            # CVSS v2 doesn't have baseSeverity, so we'll derive it from baseScore
                            base_score = cve.metrics.cvssMetricV2[0].cvssData.baseScore
                            if base_score >= 7.0:
                                severity = "HIGH"
                            elif base_score >= 4.0:
                                severity = "MEDIUM"
                            else:
                                severity = "LOW"
                except (AttributeError, IndexError, TypeError):
                    # If we can't extract severity, leave it as None
                    pass
                
                found_vulnerabilities.append(
                    Vulnerability(
                        id=cve.id, 
                        url=cve.url, 
                        dependency=name, 
                        version=version,
                        severity=severity
                    )
                )

    return found_vulnerabilities


def main() -> int:
    parser = ArgumentParser(
        description="Query the NVD and the GitHub Advisory Database for new vulnerabilities in Node's dependencies"
    )
    parser.add_argument(
        "node_repo_path",
        metavar="NODE_REPO_PATH",
        type=Path,
        help="the path to Node's repository",
    )
    supported_branches = [k for k in dependencies_per_branch.keys()]
    parser.add_argument(
        "node_repo_branch",
        metavar="NODE_REPO_BRANCH",
        help=f"the current branch of the Node repository (supports {supported_branches})",
    )
    parser.add_argument(
        "--gh-token",
        help="the GitHub authentication token for querying the GH Advisory Database",
    )
    parser.add_argument(
        "--nvd-key",
        help="the NVD API key for querying the National Vulnerability Database",
    )
    parser.add_argument(
        "--json-output",
        action="store_true",
        help="output results in JSON format",
    )
    parser.add_argument(
        "--include-npm",
        action="store_true",
        help="include npm package vulnerability scanning using npm audit",
    )
    parser.add_argument(
        "--npm-timeout",
        type=int,
        default=300,
        help="timeout in seconds for npm operations (default: 300)",
    )
    args = parser.parse_args()
    repo_path: Path = args.node_repo_path
    repo_branch: str = args.node_repo_branch
    gh_token = args.gh_token
    nvd_key = args.nvd_key
    json_output: bool = args.json_output
    include_npm: bool = args.include_npm
    npm_timeout: int = args.npm_timeout
    if not repo_path.exists() or not (repo_path / ".git").exists():
        raise RuntimeError(
            "Invalid argument: '{repo_path}' is not a valid Node git repository"
        )
    if repo_branch not in dependencies_per_branch:
        raise RuntimeError(
            f"Invalid argument: '{repo_branch}' is not a supported branch. Please use one of: {supported_branches}"
        )
    if gh_token is None:
        print(
            "Warning: GitHub authentication token not provided, skipping GitHub Advisory Database queries"
        )
    if nvd_key is None:
        print(
            "Warning: NVD API key not provided, queries will be slower due to rate limiting"
        )

    dependencies = {
        name: dep
        for name, dep in dependencies_info.items()
        if name in dependencies_per_branch[repo_branch]
    }
    ghad_vulnerabilities: list[Vulnerability] = (
        list() if gh_token is None else query_ghad(dependencies, gh_token, repo_path)
    )
    nvd_vulnerabilities: list[Vulnerability] = query_nvd(
        dependencies, nvd_key, repo_path
    )

    # NPM package vulnerability checking
    npm_vulnerabilities: list[Vulnerability] = []
    if include_npm:
        try:
            # Configure logging for npm audit
            logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            
            from npm_audit import NPMAuditChecker
            print("Running npm package vulnerability audit...")
            npm_checker = NPMAuditChecker(repo_path, npm_timeout)
            npm_vulnerabilities = npm_checker.check_npm_vulnerabilities(Vulnerability)
            print(f"Found {len(npm_vulnerabilities)} npm package vulnerabilities")
        except ImportError as e:
            print(f"Warning: npm_audit module not found, skipping npm vulnerability checking: {e}")
        except Exception as e:
            print(f"Warning: npm vulnerability checking failed: {e}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")

    all_vulnerabilities = {
        "vulnerabilities": ghad_vulnerabilities + nvd_vulnerabilities + npm_vulnerabilities
    }
    no_vulnerabilities_found = not ghad_vulnerabilities and not nvd_vulnerabilities and not npm_vulnerabilities
    if json_output:
        print(json.dumps(all_vulnerabilities, cls=VulnerabilityEncoder))
        return 0 if no_vulnerabilities_found else 1
    elif no_vulnerabilities_found:
        print(f"No new vulnerabilities found ({len(ignore_list)} ignored)")
        return 0
    else:
        print("WARNING: New vulnerabilities found")
        for vuln in all_vulnerabilities["vulnerabilities"]:
            print(
                f"- {vuln.dependency} (version {vuln.version}) : {vuln.id} ({vuln.url})"
            )
        print(f"\n{vulnerability_found_message}")
        return 1


if __name__ == "__main__":
    exit(main())
