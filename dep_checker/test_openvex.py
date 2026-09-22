#!/usr/bin/env python3

import json
import tempfile
from pathlib import Path

import sys
import types

try:
    from main import Vulnerability, filter_openvex_exemptions, load_openvex_exemptions
except ModuleNotFoundError:
    gql_module = types.ModuleType("gql")
    gql_module.gql = lambda query: query
    gql_module.Client = type("Client", (), {})
    transport_module = types.ModuleType("gql.transport.aiohttp")
    transport_module.AIOHTTPTransport = type("AIOHTTPTransport", (), {})
    sys.modules["gql"] = gql_module
    sys.modules["gql.transport"] = types.ModuleType("gql.transport")
    sys.modules["gql.transport.aiohttp"] = transport_module
    nvdlib_module = types.ModuleType("nvdlib")
    nvdlib_module.searchCVE = lambda *args, **kwargs: []
    sys.modules["nvdlib"] = nvdlib_module
    from main import Vulnerability, filter_openvex_exemptions, load_openvex_exemptions


def test_openvex_exempts_primary_and_alias_ids() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        repo_path = Path(temp_dir)
        vex_path = repo_path / "tools" / "vex" / "nsolid.openvex.json"
        vex_path.parent.mkdir(parents=True)
        vex_path.write_text(json.dumps({
            "statements": [{
                "status": "not_affected",
                "vulnerability": {"name": "CVE-2026-1234"},
            }, {
                "status": "fixed",
                "vulnerability": {"name": "CVE-2026-5678"},
            }]
        }))

        exemptions = load_openvex_exemptions(repo_path)
        vulnerabilities = [
            Vulnerability("CVE-2026-1234", "", "pkg", "1", advisory_aliases=["GHSA-test"]),
            Vulnerability("CVE-2026-5678", "", "pkg", "1"),
            Vulnerability("CVE-2026-9999", "", "pkg", "1"),
        ]

        assert [vuln.id for vuln in filter_openvex_exemptions(vulnerabilities, exemptions)] == [
            "CVE-2026-9999"
        ]


if __name__ == "__main__":
    test_openvex_exempts_primary_and_alias_ids()
