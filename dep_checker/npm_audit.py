"""NPM package vulnerability checker using npm audit

This module handles npm package vulnerability scanning by:
1. Finding dep-root package.json files in the repository
2. Reusing package-lock.json when present, otherwise installing non-dev dependencies
3. Running npm audit against the prod dependency tree
4. Reading deps/npm's installed prod tree via npm ls when available
5. Parsing results into Vulnerability objects
"""

import json
import subprocess
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import List, Dict, Optional

from gql import gql, Client
from gql.transport.aiohttp import AIOHTTPTransport
from nvdlib import searchCVE  # type: ignore
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion

logger = logging.getLogger(__name__)

GITHUB_API_VERSION = "2026-03-10"


class AuditParseError(Exception):
    """Raised when npm audit returns output that cannot be parsed reliably."""


github_vulnerabilities_query = gql(
    """
    query($package_name:String!) {
      securityVulnerabilities(ecosystem: NPM, package:$package_name, first:100) {
        nodes {
          severity
          vulnerableVersionRange
          firstPatchedVersion {
            identifier
          }
          advisory {
            ghsaId
            identifiers {
              type
              value
            }
            permalink
            summary
            withdrawnAt
          }
        }
      }
    }
"""
)


# Folder paths to exclude from npm package scanning
# Add folder paths here that should be skipped during package.json discovery
# Paths should be relative to the repository root (e.g., "deps/v8/tools/turbolizer")
# You can also use folder names for broader exclusions (e.g., "test" excludes all test folders)
EXCLUDE_PATHS = [
    # Specific path exclusions
    "deps/v8/tools",

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
    ".github",
]


class NPMAuditChecker:
    """Handles npm audit vulnerability checking for package.json files."""

    def __init__(self, repo_path: Path, timeout: int = 300, gh_token: Optional[str] = None, nvd_key: Optional[str] = None):
        self.repo_path = repo_path
        self.timeout = timeout
        self.gh_token = gh_token
        self.nvd_key = nvd_key
        self.exclude_paths = EXCLUDE_PATHS
        # A failed package-level audit means the aggregate npm result is partial.
        # The caller uses this to prevent reconciliation from closing valid issues.
        self.failed_packages: List[str] = []

    def find_package_json_files(self) -> List[Path]:
        """Find dep-root package.json files in deps/, excluding nested package manifests."""
        package_json_files = []
        excluded_count = 0

        try:
            deps_path = self.repo_path / "deps"
            if not deps_path.exists():
                logger.warning(f"deps/ folder not found at {deps_path}")
                return []

            for package_json in deps_path.rglob("package.json"):
                if "node_modules" in str(package_json):
                    continue

                is_excluded = False
                package_relative_path = str(package_json.relative_to(self.repo_path))

                for exclude_path in self.exclude_paths:
                    if (
                        package_relative_path.startswith(exclude_path + "/")
                        or package_relative_path == exclude_path
                        or exclude_path in package_json.parts
                    ):
                        is_excluded = True
                        excluded_count += 1
                        logger.debug(
                            f"Excluding {package_json} (matches exclusion: {exclude_path})"
                        )
                        break

                if is_excluded:
                    continue

                relative_to_deps = package_json.relative_to(deps_path)
                dep_root = deps_path / relative_to_deps.parts[0] / "package.json"
                if package_json != dep_root:
                    # ponytail: only audit dep roots; add a nested allowlist if a shipped package ever lives deeper.
                    logger.debug(f"Skipping nested package.json {package_json}")
                    continue

                package_json_files.append(package_json)

            logger.info(f"Found {len(package_json_files)} package.json files in deps/ folder")
            if excluded_count > 0:
                logger.info(
                    f"Excluded {excluded_count} package.json files based on exclusion list: {self.exclude_paths}"
                )

            return package_json_files
        except Exception as e:
            logger.error(f"Error finding package.json files in deps/ folder: {e}")
            self.failed_packages.append(f"package discovery failed: {e}")
            return []

    def has_package_lock(self, package_dir: Path) -> bool:
        return (package_dir / "package-lock.json").exists()

    def has_node_modules(self, package_dir: Path) -> bool:
        return (package_dir / "node_modules").is_dir()

    def is_npm_cli_checkout(self, package_dir: Path) -> bool:
        return package_dir == self.repo_path / "deps" / "npm"

    def is_missing_lockfile_error(self, audit_data: Optional[Dict]) -> bool:
        if not isinstance(audit_data, dict):
            return False
        error = audit_data.get("error")
        return isinstance(error, dict) and error.get("code") == "ENOLOCK"

    def run_npm_install(self, package_dir: Path) -> bool:
        """Generate a prod-only lockfile needed for an audit when no lockfile is present."""
        try:
            logger.info(f"Running npm install --package-lock-only in {package_dir}")
            npm_check = subprocess.run(
                ["npm", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if npm_check.returncode != 0:
                logger.error(f"npm is not available: {npm_check.stderr}")
                return False

            result = subprocess.run(
                [
                    "npm",
                    "install",
                    "--package-lock-only",
                    "--omit=dev",
                    "--ignore-scripts",
                    "--no-audit",
                    "--no-fund",
                ],
                cwd=package_dir,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            if result.returncode != 0:
                logger.warning(
                    f"npm install failed in {package_dir} (exit {result.returncode}): {result.stderr}"
                )
                logger.warning(f"npm install stdout: {result.stdout}")
                return False

            logger.info(f"npm install --package-lock-only completed successfully in {package_dir}")
            return True

        except subprocess.TimeoutExpired:
            logger.error(f"npm install timed out in {package_dir}")
            return False
        except Exception as e:
            logger.error(f"Error running npm install in {package_dir}: {e}")
            return False

    def run_npm_audit(self, package_dir: Path, package_lock_only: bool = False) -> Optional[Dict]:
        """Run npm audit against the production dependency tree in the given directory."""
        try:
            logger.info(f"Running npm audit in {package_dir}")
            command = ["npm", "audit", "--omit=dev"]
            if package_lock_only:
                command.append("--package-lock-only")
            command.append("--json")
            result = subprocess.run(
                command,
                cwd=package_dir,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            if result.stdout:
                try:
                    audit_data = json.loads(result.stdout)
                    logger.info(f"npm audit completed in {package_dir}")
                    return audit_data
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse npm audit JSON output in {package_dir}: {e}")
                    raise AuditParseError("npm audit returned malformed JSON") from e

            logger.warning(
                f"npm audit returned no output in {package_dir} (exit {result.returncode}): {result.stderr}"
            )
            return None

        except subprocess.TimeoutExpired:
            logger.error(f"npm audit timed out in {package_dir}")
            return None
        except AuditParseError:
            raise
        except Exception as e:
            logger.error(f"Error running npm audit in {package_dir}: {e}")
            return None

    def run_npm_ls(self, package_dir: Path) -> Optional[Dict]:
        """Read the installed production tree for workspace-style checkouts."""
        try:
            logger.info(f"Running npm ls in {package_dir}")
            result = subprocess.run(
                ["npm", "ls", "--omit=dev", "--all", "--json"],
                cwd=package_dir,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            if not result.stdout:
                logger.warning(
                    f"npm ls returned no output in {package_dir} (exit {result.returncode}): {result.stderr}"
                )
                return None
            tree_data = json.loads(result.stdout)
            logger.info(f"npm ls completed in {package_dir}")
            return tree_data
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse npm ls JSON output in {package_dir}: {e}")
            return None
        except subprocess.TimeoutExpired:
            logger.error(f"npm ls timed out in {package_dir}")
            return None
        except Exception as e:
            logger.error(f"Error running npm ls in {package_dir}: {e}")
            return None

    def get_installed_bundle_packages(self, package_dir: Path, tree_data: Dict) -> List[Dict[str, str]]:
        """Collect exact installed versions reachable from npm's bundled prod deps."""
        package_data = json.loads((package_dir / "package.json").read_text())
        bundle_dependencies = package_data.get("bundleDependencies", [])
        if bundle_dependencies is True:
            roots = set((package_data.get("dependencies") or {}).keys())
        else:
            roots = set(bundle_dependencies or [])
        seen: Dict[tuple[str, str], Dict[str, str]] = {}

        def walk(name: str, node: Dict, path_parts: Optional[list[str]] = None) -> None:
            path_parts = path_parts or []
            version = node.get("version")
            if not version:
                return
            key = (name, str(version))
            package_path_parts = [*path_parts, "node_modules", name]
            if key not in seen:
                seen[key] = {"name": name, "version": str(version), "path": "/".join(package_path_parts)}
            for child_name, child in (node.get("dependencies") or {}).items():
                if isinstance(child, dict):
                    walk(child_name, child, package_path_parts)

        for name, node in (tree_data.get("dependencies") or {}).items():
            if name in roots and isinstance(node, dict):
                walk(name, node, [])

        return list(seen.values())

    def query_installed_package_vulnerabilities(
        self, package_dir: Path, packages: List[Dict[str, str]], vulnerability_class
    ) -> List:
        """Query NVD and GitHub advisories for exact installed package versions."""
        vulnerabilities_by_id: Dict[str, object] = {}
        ordered_vulnerabilities: List[object] = []
        main_dep_name = package_dir.name
        main_dep_path = str(package_dir.relative_to(self.repo_path))

        def index_vulnerability(vuln) -> None:
            aliases = list(dict.fromkeys(
                alias for alias in (getattr(vuln, "advisory_aliases", []) or []) if alias != vuln.id
            ))
            setattr(vuln, "advisory_aliases", aliases)
            for candidate_id in [vuln.id, *aliases]:
                vulnerabilities_by_id[candidate_id] = vuln

        def merge_vulnerability(vuln) -> None:
            candidate_ids = [vuln.id, *(getattr(vuln, "advisory_aliases", []) or [])]
            for candidate_id in candidate_ids:
                existing = vulnerabilities_by_id.get(candidate_id)
                if existing is None:
                    continue
                aliases = list(getattr(existing, "advisory_aliases", []) or [])
                for alias in [vuln.id, *(getattr(vuln, "advisory_aliases", []) or [])]:
                    if alias != existing.id and alias not in aliases:
                        aliases.append(alias)
                setattr(existing, "advisory_aliases", aliases)
                index_vulnerability(existing)
                return
            index_vulnerability(vuln)
            ordered_vulnerabilities.append(vuln)

        packages_for_global_advisories = list(packages)
        if self.gh_token is not None:
            transport = AIOHTTPTransport(
                url="https://api.github.com/graphql",
                headers={"Authorization": f"bearer {self.gh_token}"},
            )
            client = Client(
                transport=transport,
                fetch_schema_from_transport=True,
                serialize_variables=True,
                parse_results=True,
            )

            for package in packages:
                try:
                    result = client.execute(
                        github_vulnerabilities_query,
                        variable_values={"package_name": package["name"]},
                    )
                except Exception as exc:
                    self.failed_packages.append(
                        f"{package_dir}: GitHub advisory query failed for {package['name']}@{package['version']}: {exc}"
                    )
                    logger.warning(
                        f"Skipping GitHub advisory query for {package['name']}@{package['version']}: {exc}"
                    )
                    continue
                for vuln in result["securityVulnerabilities"]["nodes"]:
                    if vuln["advisory"]["withdrawnAt"] is not None:
                        continue
                    try:
                        vulnerable_range = self.normalize_version_range(vuln["vulnerableVersionRange"])
                        if not SpecifierSet(vulnerable_range).contains(package["version"], prereleases=True):
                            continue
                    except (InvalidSpecifier, InvalidVersion) as exc:
                        self.failed_packages.append(
                            f"{package_dir}: invalid advisory match for {package['name']}@{package['version']}: {exc}"
                        )
                        logger.warning(
                            f"Skipping advisory match for {package['name']}@{package['version']}: {exc}"
                        )
                        continue
                    preferred_id = self.preferred_advisory_id(vuln["advisory"])
                    merge_vulnerability(
                        vulnerability_class(
                            id=preferred_id,
                            url=vuln["advisory"]["permalink"],
                            dependency=package["name"],
                            version=package["version"],
                            source="npm",
                            severity=vuln.get("severity"),
                            via=[vuln["advisory"]["summary"]] if vuln["advisory"].get("summary") else [],
                            fix_available=vuln.get("firstPatchedVersion") is not None,
                            main_dep_name=main_dep_name,
                            main_dep_path=main_dep_path,
                            advisory_aliases=self.advisory_aliases(vuln["advisory"], preferred_id),
                        )
                    )
        try:
            global_advisories = self.fetch_global_advisories(packages_for_global_advisories)
        except Exception as exc:
            self.failed_packages.append(
                f"{package_dir}: global advisory query failed: {exc}"
            )
            logger.warning(f"Skipping global advisory query for {package_dir}: {exc}")
            global_advisories = []

        for package in packages_for_global_advisories:
            matched_global = self.match_global_advisories(package, global_advisories)
            for vuln in matched_global:
                merge_vulnerability(
                    vulnerability_class(
                        id=vuln["id"],
                        url=vuln["url"],
                        dependency=package["name"],
                        version=package["version"],
                        source="npm",
                        severity=vuln.get("severity"),
                        via=[vuln["summary"]] if vuln.get("summary") else [],
                        fix_available=vuln.get("fix_available"),
                        main_dep_name=main_dep_name,
                        main_dep_path=main_dep_path,
                        advisory_aliases=vuln.get("aliases", []),
                    )
                )

        processed_cve_ids: set[str] = set()
        for package in packages:
            for vuln in list(vulnerabilities_by_id.values()):
                if vuln.dependency != package["name"] or not str(vuln.id).startswith("CVE-"):
                    continue
                if vuln.id in processed_cve_ids:
                    continue
                try:
                    query_kwargs = {
                        "cveId": vuln.id,
                        "key": self.nvd_key,
                    }
                    if self.nvd_key:
                        query_kwargs["delay"] = 6
                    matches = searchCVE(**query_kwargs)
                    processed_cve_ids.add(vuln.id)
                except Exception as exc:
                    self.failed_packages.append(
                        f"{package_dir}: NVD enrichment failed for {package['name']}@{package['version']} {vuln.id}: {exc}"
                    )
                    logger.warning(
                        f"Skipping NVD enrichment for {package['name']}@{package['version']} {vuln.id}: {exc}"
                    )
                    continue
                if not matches:
                    continue
                cve = matches[0]
                try:
                    severity = None
                    if hasattr(cve, "metrics") and cve.metrics:
                        if hasattr(cve.metrics, 'cvssMetricV31') and cve.metrics.cvssMetricV31:
                            severity = cve.metrics.cvssMetricV31[0].cvssData.baseSeverity
                        elif hasattr(cve.metrics, 'cvssMetricV30') and cve.metrics.cvssMetricV30:
                            severity = cve.metrics.cvssMetricV30[0].cvssData.baseSeverity
                        elif hasattr(cve.metrics, 'cvssMetricV2') and cve.metrics.cvssMetricV2:
                            base_score = cve.metrics.cvssMetricV2[0].cvssData.baseScore
                            severity = "HIGH" if base_score >= 7.0 else "MEDIUM" if base_score >= 4.0 else "LOW"
                except (AttributeError, IndexError, TypeError):
                    severity = None
                if severity is not None:
                    vuln.severity = str(severity).upper()
                if getattr(cve, 'url', None):
                    vuln.url = cve.url

        return ordered_vulnerabilities

    def match_global_advisories(self, package: Dict[str, str], advisories: List[Dict]) -> List[Dict[str, object]]:
        results: List[Dict[str, object]] = []
        seen_ids: set[str] = set()
        for advisory in advisories:
            if advisory.get("withdrawn_at") is not None:
                continue
            preferred_id = advisory.get("cve_id") or self.preferred_global_advisory_cve(advisory) or advisory.get("ghsa_id")
            if not preferred_id or preferred_id in seen_ids:
                continue
            aliases = self.global_advisory_aliases(advisory, preferred_id)
            for vuln in advisory.get("vulnerabilities") or []:
                package_info = vuln.get("package") or {}
                if package_info.get("ecosystem") != "npm" or package_info.get("name") != package["name"]:
                    continue
                try:
                    vulnerable_range = self.normalize_version_range(vuln.get("vulnerable_version_range") or "")
                    matched = bool(vulnerable_range) and SpecifierSet(vulnerable_range).contains(package["version"], prereleases=True)
                    if not matched:
                        continue
                except (InvalidSpecifier, InvalidVersion):
                    continue
                seen_ids.add(preferred_id)
                results.append({
                    "id": preferred_id,
                    "url": advisory.get("html_url") or advisory.get("url") or f"https://github.com/advisories/{advisory.get('ghsa_id', preferred_id)}",
                    "severity": str(advisory.get("severity") or "").upper() or None,
                    "summary": advisory.get("summary") or "",
                    "aliases": aliases,
                    "fix_available": bool(vuln.get("first_patched_version") or vuln.get("patched_versions")),
                })
        return results

    def fetch_global_advisories(self, packages: List[Dict[str, str]]) -> List[Dict]:
        if not packages:
            return []
        cache = getattr(self, "_global_advisory_cache", None)
        if cache is None:
            cache = self._global_advisory_cache = {}
        requested = tuple(sorted({f"{package['name']}@{package['version']}" for package in packages}))
        if requested in cache:
            return cache[requested]

        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
            "User-Agent": "nsolid-dependency-vuln-assessments",
        }
        if self.gh_token is not None:
            headers["Authorization"] = f"bearer {self.gh_token}"
        advisories: List[Dict] = []
        seen_ids: set[str] = set()
        batch_size = 25

        for index in range(0, len(requested), batch_size):
            batch = requested[index:index + batch_size]
            query = urllib.parse.urlencode(
                [("ecosystem", "npm"), *(("affects[]", item) for item in batch), ("per_page", "100")]
            )
            next_url = f"https://api.github.com/advisories?{query}"
            batch_payloads: List[Dict] | None = []
            while next_url is not None:
                request = urllib.request.Request(next_url, headers=headers)
                with urllib.request.urlopen(request, timeout=min(self.timeout, 30)) as response:
                    payload = json.load(response)
                    link_header = getattr(response, "headers", {}).get("Link")
                if not isinstance(payload, list):
                    logger.warning(
                        f"Global advisory query returned non-list payload for batch {index // batch_size + 1} of {((len(requested) - 1) // batch_size) + 1}: {payload}"
                    )
                    batch_payloads = None
                    break
                batch_payloads.extend(item for item in payload if isinstance(item, dict))
                next_url = None
                if link_header:
                    for part in link_header.split(","):
                        match = re.match(r'\s*<([^>]+)>;\s*rel="([^"]+)"', part)
                        if match and match.group(2) == "next":
                            next_url = match.group(1)
                            break
            if batch_payloads is None:
                continue
            for item in batch_payloads:
                advisory_id = item.get("ghsa_id") or item.get("cve_id") or id(item)
                if advisory_id in seen_ids:
                    continue
                seen_ids.add(advisory_id)
                advisories.append(item)

        cache[requested] = advisories
        return advisories

    def preferred_global_advisory_cve(self, advisory: Dict) -> Optional[str]:
        for identifier in advisory.get("identifiers") or []:
            if identifier.get("type") == "CVE" and identifier.get("value"):
                return identifier["value"]
        return None

    def global_advisory_aliases(self, advisory: Dict, preferred_id: str) -> list[str]:
        aliases: list[str] = []
        ghsa_id = advisory.get("ghsa_id")
        if isinstance(ghsa_id, str) and ghsa_id and ghsa_id != preferred_id:
            aliases.append(ghsa_id)
        for identifier in advisory.get("identifiers") or []:
            value = identifier.get("value")
            if value and value != preferred_id and value not in aliases:
                aliases.append(value)
        return aliases

    def normalize_version_range(self, version_range: str) -> str:
        """Normalize GitHub advisory version syntax to packaging-compatible specifiers."""
        return re.sub(r"(?<![<>=!~])=\s*", "==", version_range)

    def preferred_advisory_id(self, advisory: Dict) -> str:
        """Prefer CVE identifiers when GitHub has one, otherwise keep the GHSA."""
        for identifier in advisory.get("identifiers") or []:
            if identifier.get("type") == "CVE" and identifier.get("value"):
                return identifier["value"]
        return advisory["ghsaId"]

    def advisory_aliases(self, advisory: Dict, preferred_id: str) -> list[str]:
        """Preserve alternate advisory identifiers for reconciliation migration."""
        aliases: list[str] = []
        for identifier in advisory.get("identifiers") or []:
            value = identifier.get("value")
            if not value or value == preferred_id or value in aliases:
                continue
            aliases.append(value)
        return aliases

    def normalize_npm_advisory_id(self, advisory_id: object, fallback_name: str) -> str:
        """Normalize npm audit advisory identifiers across modern and legacy payloads."""
        if isinstance(advisory_id, str):
            normalized = advisory_id.strip()
            if normalized.startswith("GHSA-") or normalized.startswith("CVE-"):
                return normalized
            if normalized.isdigit():
                return f"npm-{normalized}"
            if normalized:
                return f"npm-{normalized}"
        elif advisory_id is not None:
            return f"npm-{advisory_id}"
        return f"npm-{fallback_name}"

    def parse_audit_results(self, audit_data: Dict, package_dir: Path, vulnerability_class) -> Optional[List]:
        """Parse npm audit JSON output, returning None when it is incomplete or invalid."""
        vulnerabilities = []
        main_dep_name = package_dir.name
        main_dep_path = str(package_dir.relative_to(self.repo_path))

        try:
            if not isinstance(audit_data, dict):
                raise ValueError("npm audit JSON root is not an object")

            if "vulnerabilities" in audit_data:
                audit_vulnerabilities = audit_data["vulnerabilities"]
                if not isinstance(audit_vulnerabilities, dict):
                    raise ValueError("npm audit vulnerabilities field is not an object")

                for vuln_name, vuln_data in audit_vulnerabilities.items():
                    try:
                        if not isinstance(vuln_data, dict):
                            raise ValueError("vulnerability entry is not an object")

                        severity = vuln_data.get("severity", "unknown")
                        via = vuln_data.get("via", [])
                        fix_available = vuln_data.get("fixAvailable", False)
                        range_info = vuln_data.get("range", "unknown")

                        if not isinstance(via, list):
                            raise ValueError("vulnerability via field is not a list")

                        if via:
                            for via_item in via:
                                if isinstance(via_item, dict):
                                    advisory_id = via_item.get("source")
                                    advisory_url = via_item.get("url")
                                    advisory_title = via_item.get("title", "")
                                    advisory_severity = via_item.get("severity", severity)

                                    vuln_id = self.normalize_npm_advisory_id(advisory_id, vuln_name)
                                    url = advisory_url or f"https://github.com/advisories?query={vuln_name}"

                                    vulnerabilities.append(
                                        vulnerability_class(
                                            id=vuln_id,
                                            url=url,
                                            dependency=vuln_name,
                                            version=str(range_info),
                                            source="npm",
                                            severity=advisory_severity,
                                            via=[advisory_title] if advisory_title else [],
                                            fix_available=bool(fix_available),
                                            main_dep_name=main_dep_name,
                                            main_dep_path=main_dep_path,
                                        )
                                    )
                                elif isinstance(via_item, str):
                                    vulnerabilities.append(
                                        vulnerability_class(
                                            id=self.normalize_npm_advisory_id(via_item, vuln_name),
                                            url=f"https://github.com/advisories?query={via_item}",
                                            dependency=vuln_name,
                                            version=str(range_info),
                                            source="npm",
                                            severity=severity,
                                            via=[str(via_item)],
                                            fix_available=bool(fix_available),
                                            main_dep_name=main_dep_name,
                                            main_dep_path=main_dep_path,
                                        )
                                    )
                                else:
                                    raise ValueError("vulnerability via item is not an object or string")
                        else:
                            vulnerabilities.append(
                                vulnerability_class(
                                    id=self.normalize_npm_advisory_id(None, vuln_name),
                                    url=f"https://github.com/advisories?query={vuln_name}",
                                    dependency=vuln_name,
                                    version=str(range_info),
                                    source="npm",
                                    severity=severity,
                                    via=[],
                                    fix_available=bool(fix_available),
                                    main_dep_name=main_dep_name,
                                    main_dep_path=main_dep_path,
                                )
                            )
                    except Exception as e:
                        logger.error(f"Error parsing vulnerability {vuln_name}: {e}")
                        return None
            elif "advisories" in audit_data:
                audit_advisories = audit_data["advisories"]
                if not isinstance(audit_advisories, dict):
                    raise ValueError("npm audit advisories field is not an object")

                for advisory_id, advisory in audit_advisories.items():
                    try:
                        if not isinstance(advisory, dict):
                            raise ValueError("advisory entry is not an object")

                        vulnerabilities.append(
                            vulnerability_class(
                                id=self.normalize_npm_advisory_id(advisory_id, advisory.get("module_name", "unknown")),
                                url=advisory.get("url", f"https://npmjs.com/advisories/{advisory_id}"),
                                dependency=advisory.get("module_name", "unknown"),
                                version=advisory.get("vulnerable_versions", "unknown"),
                                source="npm",
                                severity=advisory.get("severity", "unknown"),
                                via=[advisory.get("title", "")],
                                fix_available=bool(advisory.get("patched_versions")),
                                main_dep_name=main_dep_name,
                                main_dep_path=main_dep_path,
                            )
                        )
                    except Exception as e:
                        logger.error(f"Error parsing advisory {advisory_id}: {e}")
                        return None
            else:
                raise ValueError("unrecognized npm audit JSON format")

            logger.info(f"Parsed {len(vulnerabilities)} vulnerabilities from {package_dir}")
            return vulnerabilities

        except Exception as e:
            logger.error(f"Error parsing audit results from {package_dir}: {e}")
            if isinstance(audit_data, dict):
                keys = sorted(audit_data.keys())
                logger.error(f"npm audit JSON top-level keys for {package_dir}: {keys}")
                if "error" in audit_data:
                    logger.error(f"npm audit JSON error payload for {package_dir}: {audit_data['error']}")
                metadata = audit_data.get("metadata")
                if metadata is not None:
                    logger.error(f"npm audit JSON metadata for {package_dir}: {metadata}")
            else:
                logger.error(f"npm audit JSON type for {package_dir}: {type(audit_data).__name__}")
            return None

    def check_npm_vulnerabilities(self, vulnerability_class) -> List:
        """Main method to check npm vulnerabilities across all package.json files."""
        all_vulnerabilities = []
        package_json_files = self.find_package_json_files()

        if not package_json_files:
            logger.info("No package.json files found")
            return all_vulnerabilities

        for package_json in package_json_files:
            package_dir = package_json.parent
            logger.info(f"Processing {package_json}")

            try:
                has_package_lock = self.has_package_lock(package_dir)
                has_node_modules = self.has_node_modules(package_dir)

                if self.is_npm_cli_checkout(package_dir):
                    if not has_node_modules:
                        logger.warning(
                            f"Skipping npm tree scan for {package_dir} because node_modules is missing"
                        )
                        self.failed_packages.append(f"{package_dir}: installed npm tree missing")
                        continue
                    tree_data = self.run_npm_ls(package_dir)
                    if tree_data is None:
                        logger.warning(
                            f"Skipping vulnerability parsing for {package_dir} due to npm ls failure"
                        )
                        self.failed_packages.append(f"{package_dir}: npm ls failed")
                        continue
                    packages = self.get_installed_bundle_packages(package_dir, tree_data)
                    if not packages:
                        logger.warning(
                            f"Skipping vulnerability parsing for {package_dir} because no bundled packages were found in the installed tree"
                        )
                        self.failed_packages.append(f"{package_dir}: installed bundle tree was empty")
                        continue
                    all_vulnerabilities.extend(
                        self.query_installed_package_vulnerabilities(
                            package_dir, packages, vulnerability_class
                        )
                    )
                    continue

                package_lock_only = has_package_lock and not has_node_modules

                if not has_node_modules and not has_package_lock:
                    if not self.run_npm_install(package_dir):
                        logger.warning(f"Skipping npm audit for {package_dir} due to install failure")
                        self.failed_packages.append(f"{package_dir}: npm install failed")
                        continue
                    package_lock_only = True

                audit_data = self.run_npm_audit(package_dir, package_lock_only=package_lock_only)
                if self.is_missing_lockfile_error(audit_data):
                    logger.warning(
                        f"npm audit reported ENOLOCK for {package_dir}; falling back to npm install + npm audit"
                    )
                    if not self.run_npm_install(package_dir):
                        logger.warning(f"Skipping npm audit for {package_dir} due to install failure")
                        self.failed_packages.append(f"{package_dir}: npm install failed")
                        continue
                    audit_data = self.run_npm_audit(package_dir, package_lock_only=False)
                if audit_data is None:
                    logger.warning(f"Skipping vulnerability parsing for {package_dir} due to audit failure")
                    self.failed_packages.append(f"{package_dir}: npm audit failed")
                    continue

                vulnerabilities = self.parse_audit_results(audit_data, package_dir, vulnerability_class)
                if vulnerabilities is None:
                    logger.warning(f"Skipping vulnerability parsing for {package_dir} due to parse failure")
                    self.failed_packages.append(f"{package_dir}: npm audit parse failed")
                    continue
                all_vulnerabilities.extend(vulnerabilities)

            except AuditParseError as e:
                logger.warning(f"Skipping vulnerability parsing for {package_dir}: {e}")
                self.failed_packages.append(f"{package_dir}: npm audit parse failed")
                continue
            except Exception as e:
                logger.exception(f"Error processing {package_json}: {e}")
                self.failed_packages.append(f"{package_dir}: unexpected error: {e}")
                continue

        logger.info(f"Total npm vulnerabilities found: {len(all_vulnerabilities)}")
        return all_vulnerabilities
