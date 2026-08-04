#!/usr/bin/env python3
"""Simple test script to verify npm audit functionality"""

import json
import sys
import tempfile
import types
from pathlib import Path

try:
    import npm_audit
except ModuleNotFoundError as exc:
    if exc.name != "gql":
        raise
    gql_module = types.ModuleType("gql")
    gql_module.gql = lambda query: query

    class DummyClient:
        def __init__(self, *args, **kwargs):
            pass

    gql_module.Client = DummyClient
    transport_module = types.ModuleType("gql.transport.aiohttp")

    class DummyTransport:
        def __init__(self, *args, **kwargs):
            pass

    transport_module.AIOHTTPTransport = DummyTransport
    sys.modules["gql"] = gql_module
    sys.modules["gql.transport"] = types.ModuleType("gql.transport")
    sys.modules["gql.transport.aiohttp"] = transport_module
    import npm_audit

from npm_audit import NPMAuditChecker


class Vulnerability:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


def write_package_json(path: Path, content: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(content, indent=2))
    return path


def test_find_package_json_files_skips_nested_manifests() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        root_package = write_package_json(
            temp_path / "deps" / "pkg" / "package.json",
            {"name": "pkg", "version": "1.0.0", "dependencies": {"lodash": "4.17.0"}},
        )
        write_package_json(
            temp_path / "deps" / "pkg" / "src" / "package.json",
            {"name": "pkg-src", "version": "1.0.0", "devDependencies": {"esbuild": "0.27.0"}},
        )

        checker = NPMAuditChecker(temp_path, timeout=60)
        package_files = checker.find_package_json_files()

        assert package_files == [root_package], package_files


def test_npm_commands_omit_dev() -> None:
    calls = []

    class Result:
        def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd == ["npm", "--version"]:
            return Result(stdout="10.0.0\n")
        if cmd[:2] == ["npm", "install"]:
            return Result()
        if cmd[:2] == ["npm", "audit"]:
            return Result(stdout='{"vulnerabilities": {}}')
        raise AssertionError(cmd)

    original_run = npm_audit.subprocess.run
    npm_audit.subprocess.run = fake_run
    try:
        checker = NPMAuditChecker(Path("/tmp"), timeout=60)
        assert checker.run_npm_install(Path("/tmp"))
        assert checker.run_npm_audit(Path("/tmp")) == {"vulnerabilities": {}}
        assert checker.run_npm_audit(Path("/tmp"), package_lock_only=True) == {"vulnerabilities": {}}
    finally:
        npm_audit.subprocess.run = original_run

    assert ["npm", "install", "--package-lock-only", "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund"] in calls
    assert ["npm", "audit", "--omit=dev", "--json"] in calls
    assert ["npm", "audit", "--omit=dev", "--package-lock-only", "--json"] in calls


def test_lockfile_skips_install() -> None:
    calls = []

    class Result:
        def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:2] == ["npm", "audit"]:
            return Result(stdout='{"vulnerabilities": {}}')
        if cmd == ["npm", "--version"]:
            raise AssertionError("install should be skipped when package-lock.json exists")
        if cmd[:2] == ["npm", "install"]:
            raise AssertionError("install should be skipped when package-lock.json exists")
        raise AssertionError(cmd)

    original_run = npm_audit.subprocess.run
    npm_audit.subprocess.run = fake_run
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            package_dir = Path(temp_dir) / "deps" / "pkg"
            write_package_json(
                package_dir / "package.json",
                {"name": "pkg", "version": "1.0.0", "dependencies": {"lodash": "4.17.0"}},
            )
            write_package_json(
                package_dir / "package-lock.json",
                {"name": "pkg", "lockfileVersion": 3},
            )

            checker = NPMAuditChecker(Path(temp_dir), timeout=60)
            vulnerabilities = checker.check_npm_vulnerabilities(Vulnerability)
            assert vulnerabilities == [], vulnerabilities
    finally:
        npm_audit.subprocess.run = original_run

    assert ["npm", "audit", "--omit=dev", "--package-lock-only", "--json"] in calls


def test_node_modules_skips_install_and_lockfile_only() -> None:
    calls = []

    class Result:
        def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:2] == ["npm", "audit"]:
            return Result(stdout='{"vulnerabilities": {}}')
        if cmd == ["npm", "--version"]:
            raise AssertionError("install should be skipped when node_modules exists")
        if cmd[:2] == ["npm", "install"]:
            raise AssertionError("install should be skipped when node_modules exists")
        raise AssertionError(cmd)

    original_run = npm_audit.subprocess.run
    npm_audit.subprocess.run = fake_run
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            package_dir = Path(temp_dir) / "deps" / "pkg"
            write_package_json(
                package_dir / "package.json",
                {"name": "pkg", "version": "1.0.0", "dependencies": {"lodash": "4.17.0"}},
            )
            write_package_json(
                package_dir / "package-lock.json",
                {"name": "pkg", "lockfileVersion": 3},
            )
            (package_dir / "node_modules").mkdir(parents=True)

            checker = NPMAuditChecker(Path(temp_dir), timeout=60)
            vulnerabilities = checker.check_npm_vulnerabilities(Vulnerability)
            assert vulnerabilities == [], vulnerabilities
    finally:
        npm_audit.subprocess.run = original_run

    assert ["npm", "audit", "--omit=dev", "--json"] in calls
    assert ["npm", "audit", "--omit=dev", "--package-lock-only", "--json"] not in calls


def test_no_lockfile_generates_lockfile_only_audit() -> None:
    calls = []

    class Result:
        def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd == ["npm", "--version"]:
            return Result(stdout="10.0.0\n")
        if cmd[:2] == ["npm", "install"]:
            return Result()
        if cmd == ["npm", "audit", "--omit=dev", "--package-lock-only", "--json"]:
            return Result(stdout='{"vulnerabilities": {}}')
        raise AssertionError(cmd)

    original_run = npm_audit.subprocess.run
    npm_audit.subprocess.run = fake_run
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            package_dir = Path(temp_dir) / "deps" / "pkg"
            write_package_json(
                package_dir / "package.json",
                {"name": "pkg", "version": "1.0.0", "dependencies": {"lodash": "4.17.0"}},
            )

            checker = NPMAuditChecker(Path(temp_dir), timeout=60)
            vulnerabilities = checker.check_npm_vulnerabilities(Vulnerability)
            assert vulnerabilities == [], vulnerabilities
    finally:
        npm_audit.subprocess.run = original_run

    assert ["npm", "install", "--package-lock-only", "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund"] in calls
    assert ["npm", "audit", "--omit=dev", "--package-lock-only", "--json"] in calls
    assert ["npm", "audit", "--omit=dev", "--json"] not in calls


def test_enolock_with_node_modules_still_falls_back() -> None:
    calls = []

    class Result:
        def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd == ["npm", "--version"]:
            return Result(stdout="10.0.0\n")
        if cmd[:2] == ["npm", "install"]:
            return Result()
        if cmd == ["npm", "audit", "--omit=dev", "--json"]:
            if calls.count(["npm", "audit", "--omit=dev", "--json"]) == 1:
                return Result(stdout='{"error":{"code":"ENOLOCK"}}')
            return Result(stdout='{"vulnerabilities": {}}')
        raise AssertionError(cmd)

    original_run = npm_audit.subprocess.run
    npm_audit.subprocess.run = fake_run
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            package_dir = Path(temp_dir) / "deps" / "pkg"
            write_package_json(
                package_dir / "package.json",
                {"name": "pkg", "version": "1.0.0", "dependencies": {"lodash": "4.17.0"}},
            )
            (package_dir / "node_modules").mkdir(parents=True)

            checker = NPMAuditChecker(Path(temp_dir), timeout=60)
            vulnerabilities = checker.check_npm_vulnerabilities(Vulnerability)
            assert vulnerabilities == [], vulnerabilities
    finally:
        npm_audit.subprocess.run = original_run

    assert ["npm", "install", "--package-lock-only", "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund"] in calls
    assert calls.count(["npm", "audit", "--omit=dev", "--json"]) == 2


def test_enolock_falls_back_to_install_and_normal_audit() -> None:
    calls = []

    class Result:
        def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd == ["npm", "--version"]:
            return Result(stdout="10.0.0\n")
        if cmd[:2] == ["npm", "install"]:
            return Result()
        if cmd == ["npm", "audit", "--omit=dev", "--package-lock-only", "--json"]:
            return Result(stdout='{"error":{"code":"ENOLOCK"}}')
        if cmd == ["npm", "audit", "--omit=dev", "--json"]:
            return Result(stdout='{"vulnerabilities": {}}')
        raise AssertionError(cmd)

    original_run = npm_audit.subprocess.run
    npm_audit.subprocess.run = fake_run
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            package_dir = Path(temp_dir) / "deps" / "pkg"
            write_package_json(
                package_dir / "package.json",
                {"name": "pkg", "version": "1.0.0", "dependencies": {"lodash": "4.17.0"}},
            )
            write_package_json(
                package_dir / "package-lock.json",
                {"name": "pkg", "lockfileVersion": 3},
            )

            checker = NPMAuditChecker(Path(temp_dir), timeout=60)
            vulnerabilities = checker.check_npm_vulnerabilities(Vulnerability)
            assert vulnerabilities == [], vulnerabilities
    finally:
        npm_audit.subprocess.run = original_run

    assert ["npm", "audit", "--omit=dev", "--package-lock-only", "--json"] in calls
    assert ["npm", "install", "--package-lock-only", "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund"] in calls
    assert ["npm", "audit", "--omit=dev", "--json"] in calls


def test_query_failure_is_skipped_per_package() -> None:
    class FakeClient:
        def execute(self, query, variable_values):
            if variable_values["package_name"] == "badpkg":
                raise RuntimeError("boom")
            return {
                "securityVulnerabilities": {
                    "nodes": [
                        {
                            "severity": "HIGH",
                            "vulnerableVersionRange": ">=1.0.0",
                            "firstPatchedVersion": None,
                            "advisory": {
                                "ghsaId": "GHSA-good",
                                "identifiers": [],
                                "permalink": "https://example.com/good",
                                "summary": "good range",
                                "withdrawnAt": None,
                            },
                        }
                    ]
                }
            }

    original_client = npm_audit.Client
    original_transport = npm_audit.AIOHTTPTransport
    npm_audit.Client = lambda *args, **kwargs: FakeClient()
    npm_audit.AIOHTTPTransport = lambda *args, **kwargs: object()
    try:
        checker = NPMAuditChecker(Path("/tmp"), timeout=60, gh_token="token")
        vulns = checker.query_installed_package_vulnerabilities(
            Path("/tmp/deps/npm"),
            [
                {"name": "goodpkg", "version": "1.2.3"},
                {"name": "badpkg", "version": "1.2.3"},
            ],
            Vulnerability,
        )
        assert len(vulns) == 1, vulns
        assert vulns[0].dependency == "goodpkg"
    finally:
        npm_audit.Client = original_client
        npm_audit.AIOHTTPTransport = original_transport


def test_invalid_advisory_range_or_version_is_skipped() -> None:
    class FakeClient:
        def execute(self, query, variable_values):
            return {
                "securityVulnerabilities": {
                    "nodes": [
                        {
                            "severity": "HIGH",
                            "vulnerableVersionRange": "not-a-specifier",
                            "firstPatchedVersion": None,
                            "advisory": {
                                "ghsaId": "GHSA-bad",
                                "identifiers": [],
                                "permalink": "https://example.com/bad",
                                "summary": "bad range",
                                "withdrawnAt": None,
                            },
                        },
                        {
                            "severity": "HIGH",
                            "vulnerableVersionRange": ">=1.0.0",
                            "firstPatchedVersion": None,
                            "advisory": {
                                "ghsaId": "GHSA-good",
                                "identifiers": [],
                                "permalink": "https://example.com/good",
                                "summary": "good range",
                                "withdrawnAt": None,
                            },
                        },
                    ]
                }
            }

    original_client = npm_audit.Client
    original_transport = npm_audit.AIOHTTPTransport
    npm_audit.Client = lambda *args, **kwargs: FakeClient()
    npm_audit.AIOHTTPTransport = lambda *args, **kwargs: object()
    try:
        checker = NPMAuditChecker(Path("/tmp"), timeout=60, gh_token="token")
        vulns = checker.query_installed_package_vulnerabilities(
            Path("/tmp/deps/npm"),
            [{"name": "pkg", "version": "1.2.3"}, {"name": "badver", "version": "not/a/version"}],
            Vulnerability,
        )
        assert len(vulns) == 1, vulns
        assert vulns[0].id == "GHSA-good"
    finally:
        npm_audit.Client = original_client
        npm_audit.AIOHTTPTransport = original_transport


def test_normalize_npm_advisory_id() -> None:
    checker = NPMAuditChecker(Path("/tmp"), timeout=60)
    assert checker.normalize_npm_advisory_id("GHSA-test", "pkg") == "GHSA-test"
    assert checker.normalize_npm_advisory_id("CVE-2026-12345", "pkg") == "CVE-2026-12345"
    assert checker.normalize_npm_advisory_id("12345", "pkg") == "npm-12345"
    assert checker.normalize_npm_advisory_id("other-source", "pkg") == "npm-other-source"
    assert checker.normalize_npm_advisory_id(None, "pkg") == "npm-pkg"


def test_parse_audit_results_normalizes_ids() -> None:
    checker = NPMAuditChecker(Path("/tmp"), timeout=60)
    audit_data = {
        "vulnerabilities": {
            "foo": {
                "severity": "high",
                "via": [
                    {"source": 12345, "url": "https://example.com/1", "title": "numeric"},
                    {"source": "GHSA-aaaa-bbbb-cccc", "url": "https://example.com/2", "title": "ghsa"},
                    "CVE-2026-12345",
                ],
                "fixAvailable": True,
                "range": "<=1.0.0",
            }
        },
        "advisories": {
            "67890": {
                "module_name": "bar",
                "severity": "moderate",
                "title": "legacy",
                "patched_versions": ">1.0.0",
            }
        },
    }
    vulns = checker.parse_audit_results(audit_data, Path("/tmp/deps/pkg"), Vulnerability)
    assert [v.id for v in vulns] == ["npm-12345", "GHSA-aaaa-bbbb-cccc", "CVE-2026-12345"]

    legacy = checker.parse_audit_results(
        {"advisories": {"67890": {"module_name": "bar", "severity": "moderate", "title": "legacy", "patched_versions": ">1.0.0"}}},
        Path("/tmp/deps/pkg"),
        Vulnerability,
    )
    assert [v.id for v in legacy] == ["npm-67890"]


def test_preferred_advisory_id() -> None:
    checker = NPMAuditChecker(Path("/tmp"), timeout=60)
    assert checker.preferred_advisory_id({
        "ghsaId": "GHSA-test",
        "identifiers": [
            {"type": "GHSA", "value": "GHSA-test"},
            {"type": "CVE", "value": "CVE-2026-12345"},
        ],
    }) == "CVE-2026-12345"
    assert checker.preferred_advisory_id({
        "ghsaId": "GHSA-only",
        "identifiers": [{"type": "GHSA", "value": "GHSA-only"}],
    }) == "GHSA-only"


def test_normalize_version_range() -> None:
    checker = NPMAuditChecker(Path("/tmp"), timeout=60)
    assert checker.normalize_version_range("= 8.0.0") == "==8.0.0"
    assert checker.normalize_version_range(">= 1.0.0, < 2.0.0") == ">= 1.0.0, < 2.0.0"


def test_get_installed_bundle_packages_accepts_boolean_bundle_dependencies() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        package_dir = Path(temp_dir) / "deps" / "npm"
        write_package_json(
            package_dir / "package.json",
            {
                "name": "npm",
                "version": "11.18.0",
                "bundleDependencies": True,
                "dependencies": {"tar": "^7.5.19"},
            },
        )

        checker = NPMAuditChecker(Path(temp_dir), timeout=60)
        packages = checker.get_installed_bundle_packages(
            package_dir,
            {
                "dependencies": {
                    "tar": {
                        "version": "7.5.19",
                        "dependencies": {
                            "minipass": {"version": "7.1.3"},
                            "minipass_dup": {"version": "7.1.3"},
                        },
                    }
                }
            },
        )

        assert sorted((pkg["name"], pkg["version"]) for pkg in packages) == [
            ("minipass", "7.1.3"),
            ("minipass_dup", "7.1.3"),
            ("tar", "7.5.19"),
        ]


def test_npm_cli_uses_installed_tree() -> None:
    original_run_npm_ls = NPMAuditChecker.run_npm_ls
    original_query = NPMAuditChecker.query_installed_package_vulnerabilities
    calls = []

    def fake_run_npm_ls(self, package_dir):
        calls.append(("npm_ls", package_dir))
        return {
            "dependencies": {
                "tar": {
                    "version": "7.5.19",
                    "dependencies": {
                        "minipass": {"version": "7.1.3"}
                    },
                },
                "ignored": {"version": "1.0.0"},
            }
        }

    def fake_query(self, package_dir, packages, vulnerability_class):
        calls.append(("query", package_dir, sorted((p["name"], p["version"]) for p in packages)))
        return [vulnerability_class(id="GHSA-test", url="https://example.com", dependency="tar", version="7.5.19")]

    NPMAuditChecker.run_npm_ls = fake_run_npm_ls
    NPMAuditChecker.query_installed_package_vulnerabilities = fake_query
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            package_dir = Path(temp_dir) / "deps" / "npm"
            write_package_json(
                package_dir / "package.json",
                {
                    "name": "npm",
                    "version": "11.18.0",
                    "bundleDependencies": ["tar"],
                },
            )
            (package_dir / "node_modules").mkdir(parents=True)

            checker = NPMAuditChecker(Path(temp_dir), timeout=60, gh_token="token")
            vulnerabilities = checker.check_npm_vulnerabilities(Vulnerability)
            assert len(vulnerabilities) == 1, vulnerabilities
            assert vulnerabilities[0].dependency == "tar"
    finally:
        NPMAuditChecker.run_npm_ls = original_run_npm_ls
        NPMAuditChecker.query_installed_package_vulnerabilities = original_query

    assert calls == [
        ("npm_ls", Path(temp_dir) / "deps" / "npm"),
        ("query", Path(temp_dir) / "deps" / "npm", [("minipass", "7.1.3"), ("tar", "7.5.19")]),
    ]


def test_npm_audit_basic() -> None:
    print("Testing npm audit functionality...")
    test_find_package_json_files_skips_nested_manifests()
    test_npm_commands_omit_dev()
    test_lockfile_skips_install()
    test_node_modules_skips_install_and_lockfile_only()
    test_no_lockfile_generates_lockfile_only_audit()
    test_enolock_with_node_modules_still_falls_back()
    test_enolock_falls_back_to_install_and_normal_audit()
    test_query_failure_is_skipped_per_package()
    test_invalid_advisory_range_or_version_is_skipped()
    test_normalize_npm_advisory_id()
    test_parse_audit_results_normalizes_ids()
    test_preferred_advisory_id()
    test_normalize_version_range()
    test_get_installed_bundle_packages_accepts_boolean_bundle_dependencies()
    test_npm_cli_uses_installed_tree()

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        package_json = write_package_json(
            temp_path / "deps" / "pkg" / "package.json",
            {"name": "pkg", "version": "1.0.0", "dependencies": {"lodash": "4.17.0"}},
        )
        print(f"Created test package.json at: {package_json}")

        checker = NPMAuditChecker(temp_path, timeout=60)
        package_files = checker.find_package_json_files()
        print(f"Found {len(package_files)} package.json files")
        assert package_files == [package_json], package_files

        try:
            vulnerabilities = checker.check_npm_vulnerabilities(Vulnerability)
            print(f"Found {len(vulnerabilities)} vulnerabilities")
            for vuln in vulnerabilities:
                print(f"- {vuln.dependency} ({vuln.version}): {vuln.id} - {vuln.severity}")
        except Exception as e:
            print(f"npm audit test failed (this is expected if npm is not available): {e}")

    print("Basic npm audit test completed!")


if __name__ == "__main__":
    test_npm_audit_basic()
