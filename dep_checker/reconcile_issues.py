#!/usr/bin/env python3
"""Reconcile GitHub issues against the current vulnerability scan for an NSOLID stream.

This script replaces the old matrix + ``create_issue.sh`` + ``format_matrix.py`` fan-out.
Given the JSON output of ``main.py`` for a single stream it performs a *set reconciliation*
against the issues that already exist for that stream:

* vulns present in the scan but with no open issue        -> create
* vulns present in the scan that already have an open issue -> update (idempotent)
* open issues whose vuln is no longer in the scan          -> close (with a comment)

Issues are matched on a stable machine-readable key embedded in the issue body
(``<!-- vuln-key: ... -->``), never on GitHub's fuzzy search index. Existing issues are
listed by the per-stream LABEL, which is index-independent and immediately consistent, so
near-simultaneous runs cannot create duplicates.

Closed issues are never touched: a reappearing vulnerability always gets a fresh issue.
"""

from __future__ import annotations

from argparse import ArgumentParser
from typing import Any, Dict, List, Optional

import json
import re
import subprocess
import sys


# Marker embedded (invisibly) in every bot-managed issue body. Carries the stable key.
KEY_MARKER_RE = re.compile(r"<!--\s*vuln-key:\s*(.*?)\s*-->")
# Marker added to the closing comment so the close is identifiable as bot-originated.
CLOSE_MARKER = "<!-- vuln-bot-close -->"

# Severity labels are mutually exclusive, so they are reset (not just added) on update.
SEVERITY_LABELS = {"CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"}


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


# --------------------------------------------------------------------------------------
# Key / title / body / label derivation
# --------------------------------------------------------------------------------------

def _sanitize(value: Any) -> str:
    """Normalize a key field: lowercase, trimmed, and free of the ``|`` separator."""
    return str(value if value is not None else "").replace("|", "/").strip().lower()


def make_key(stream: str, vuln: Dict[str, Any]) -> str:
    """Stable identity for a vulnerability: ``stream|source|id|dependency|location``.

    For npm vulns ``location`` is the audit root (``main_dep_path``) so the same advisory
    reported under two different ``deps/`` package.json roots maps to two distinct issues.
    The transitive node_modules chain is deliberately NOT used (it churns across runs).
    """
    source = vuln.get("source", "binary")
    location = vuln.get("main_dep_path", "") if source == "npm" else ""
    fields = [stream, source, vuln["id"], vuln["dependency"], location]
    return "|".join(_sanitize(f) for f in fields)


def legacy_key(stream: str, source: str, vuln_id: str, dependency: str) -> str:
    """Location-independent key used only to match pre-marker (legacy) issues by title."""
    return "|".join(_sanitize(f) for f in [stream, source, vuln_id, dependency])


def legacy_key_for_vuln(stream: str, vuln: Dict[str, Any]) -> str:
    return legacy_key(stream, vuln.get("source", "binary"), vuln["id"], vuln["dependency"])


def legacy_key_from_title(title: str) -> Optional[str]:
    """Reconstruct a legacy key from an issue title, or None if it doesn't parse."""
    m = re.match(r"^(.*?) \((.*?) via (.*?)\) found on (.+)$", title)
    if m:
        vuln_id, dependency, _main, strm = m.groups()
        return legacy_key(strm, "npm", vuln_id, dependency)
    m = re.match(r"^(.*?) \((.*?)\) found on (.+)$", title)
    if m:
        vuln_id, dependency, strm = m.groups()
        return legacy_key(strm, "binary", vuln_id, dependency)
    return None


def extract_key(body: Optional[str]) -> Optional[str]:
    if not body:
        return None
    m = KEY_MARKER_RE.search(body)
    return m.group(1).strip() if m else None


def _via_title(vuln: Dict[str, Any]) -> str:
    via = vuln.get("via")
    if isinstance(via, list) and via and via[0]:
        return str(via[0])
    return ""


def render_title(stream: str, vuln: Dict[str, Any]) -> str:
    dependency = vuln["dependency"]
    if vuln.get("source") == "npm" and vuln.get("main_dep_name"):
        return f"{vuln['id']} ({dependency} via {vuln['main_dep_name']}) found on {stream}"
    return f"{vuln['id']} ({dependency}) found on {stream}"


def render_body(vuln: Dict[str, Any], key: str, action_url: str) -> str:
    lines = [
        f"A vulnerability for {vuln['dependency']} {vuln.get('version', '')} was found:",
        f"Vulnerability ID: {vuln['id']}",
        f"Vulnerability URL: {vuln['url']}",
    ]
    title = _via_title(vuln)
    if title:
        lines.append(f"Vulnerability Title: {title}")
    if vuln.get("source") == "npm" and vuln.get("main_dep_name"):
        lines.append(f"Main Dependency: {vuln['main_dep_name']}")
        if vuln.get("main_dep_path"):
            lines.append(f"Main Dependency Path: {vuln['main_dep_path']}")
    lines.append(f"Last seen in run: {action_url}")
    lines.append("")
    lines.append(f"<!-- vuln-key: {key} -->")
    return "\n".join(lines)


def generate_labels(vuln: Dict[str, Any], stream: str) -> List[str]:
    """Port of format_matrix.generate_labels_for_vulnerability."""
    labels = [stream]
    if vuln.get("source") == "npm":
        labels.append("NPM")
    main_dep_name = vuln.get("main_dep_name")
    if main_dep_name and main_dep_name != "null":
        labels.append(main_dep_name)
    severity = vuln.get("severity")
    if severity and severity != "null":
        labels.append(severity.upper())
    runtime_match = re.search(r"node-(v[0-9]+\.x)", stream)
    if runtime_match:
        labels.append(runtime_match.group(1))
    nsolid_match = re.search(r"nsolid-(v[0-9]+\.x)", stream)
    if nsolid_match:
        labels.append(f"nsolid-{nsolid_match.group(1)}")
    # De-duplicate while preserving order.
    seen: set = set()
    return [x for x in labels if not (x in seen or seen.add(x))]


def label_color(label: str) -> tuple[str, str]:
    """Port of the color/description map from create_issue.sh."""
    upper = label.upper()
    if "CRITICAL" in upper:
        return "d73a49", "Critical severity vulnerability"
    if "HIGH" in upper:
        return "fd7e14", "High severity vulnerability"
    if "MODERATE" in upper or "MEDIUM" in upper:
        return "ffc107", "Moderate severity vulnerability"
    if "LOW" in upper:
        return "28a745", "Low severity vulnerability"
    if "NPM" in upper:
        return "cb3837", "NPM package vulnerability"
    if "NSOLID" in upper:
        return "6f42c1", "N|Solid related"
    if re.search(r"v[0-9]+\.x", label):
        return "0366d6", "Version-specific label"
    return "0366d6", "Auto-created vulnerability label"


# --------------------------------------------------------------------------------------
# gh CLI wrappers
# --------------------------------------------------------------------------------------

class Gh:
    def __init__(self, dry_run: bool = False) -> None:
        self.dry_run = dry_run

    def _run(self, args: List[str], input_text: Optional[str] = None,
             mutating: bool = False) -> str:
        if mutating and self.dry_run:
            eprint(f"[dry-run] gh {' '.join(args)}")
            return ""
        result = subprocess.run(
            ["gh", *args],
            input=input_text,
            text=True,
            capture_output=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"gh {' '.join(args)} failed ({result.returncode}): {result.stderr.strip()}"
            )
        return result.stdout

    def list_open_issues(self, stream: str, limit: int = 1000) -> List[Dict[str, Any]]:
        out = self._run([
            "issue", "list",
            "--state", "open",
            "--label", stream,
            "--limit", str(limit),
            "--json", "number,title,body,labels",
        ])
        issues = json.loads(out) if out.strip() else []
        if len(issues) >= limit:
            eprint(f"WARNING: open-issue list hit the limit of {limit}; results may be truncated")
        return issues

    def create_issue(self, title: str, body: str) -> Optional[int]:
        out = self._run(
            ["issue", "create", "--title", title, "--body-file", "-"],
            input_text=body,
            mutating=True,
        )
        if self.dry_run:
            return None
        m = re.search(r"/issues/(\d+)", out)
        return int(m.group(1)) if m else None

    def edit_body(self, number: int, body: str) -> None:
        self._run(["issue", "edit", str(number), "--body-file", "-"],
                  input_text=body, mutating=True)

    def add_label(self, number: int, label: str) -> None:
        try:
            self._run(["issue", "edit", str(number), "--add-label", label], mutating=True)
        except RuntimeError:
            color, desc = label_color(label)
            try:
                self._run(["label", "create", label, "--color", color, "--description", desc],
                          mutating=True)
            except RuntimeError:
                pass  # label may already exist (race) — fall through and retry add
            self._run(["issue", "edit", str(number), "--add-label", label], mutating=True)

    def remove_label(self, number: int, label: str) -> None:
        try:
            self._run(["issue", "edit", str(number), "--remove-label", label], mutating=True)
        except RuntimeError as e:
            eprint(f"Warning: could not remove label '{label}' from #{number}: {e}")

    def comment(self, number: int, body: str) -> None:
        self._run(["issue", "comment", str(number), "--body-file", "-"],
                  input_text=body, mutating=True)

    def close(self, number: int) -> None:
        self._run(["issue", "close", str(number), "--reason", "completed"], mutating=True)


# --------------------------------------------------------------------------------------
# Reconciliation
# --------------------------------------------------------------------------------------

def sync_labels(gh: Gh, issue: Dict[str, Any], desired: List[str]) -> None:
    """Add missing labels; reset (remove stale) severity labels only."""
    current = {lbl["name"] for lbl in issue.get("labels", [])}
    desired_set = set(desired)
    for label in current & SEVERITY_LABELS:
        if label not in desired_set:
            gh.remove_label(issue["number"], label)
    for label in desired:
        if label not in current:
            gh.add_label(issue["number"], label)


def reconcile(scan: Dict[str, Any], stream: str, action_url: str, gh: Gh) -> int:
    vulns = scan.get("vulnerabilities", [])
    scan_complete = scan.get("scan_complete", True)

    # Desired set, keyed by primary key (dedups within the scan automatically).
    desired: Dict[str, Dict[str, Any]] = {}
    for vuln in vulns:
        desired[make_key(stream, vuln)] = vuln

    # Index existing open issues for this stream.
    open_issues = gh.list_open_issues(stream)
    by_pkey: Dict[str, Dict[str, Any]] = {}
    by_legacy: Dict[str, Dict[str, Any]] = {}
    recognizable: set = set()  # issue numbers that are clearly bot vuln issues
    for issue in open_issues:
        mk = extract_key(issue.get("body"))
        if mk:
            by_pkey[mk] = issue
            recognizable.add(issue["number"])
        else:
            lk = legacy_key_from_title(issue.get("title", ""))
            if lk:
                by_legacy[lk] = issue
                recognizable.add(issue["number"])

    matched: set = set()
    created = updated = closed = 0

    # Create / update.
    for pkey, vuln in desired.items():
        issue = by_pkey.get(pkey) or by_legacy.get(legacy_key_for_vuln(stream, vuln))
        body = render_body(vuln, pkey, action_url)
        if issue:
            gh.edit_body(issue["number"], body)  # backfills the marker for legacy issues
            sync_labels(gh, issue, generate_labels(vuln, stream))
            matched.add(issue["number"])
            updated += 1
            eprint(f"Updated #{issue['number']}: {render_title(stream, vuln)}")
        else:
            number = gh.create_issue(render_title(stream, vuln), body)
            if number is not None:
                for label in generate_labels(vuln, stream):
                    gh.add_label(number, label)
            created += 1
            eprint(f"Created issue: {render_title(stream, vuln)}")

    # Close issues whose vuln is gone — only if the scan was complete.
    if scan_complete:
        close_comment = (
            f"{CLOSE_MARKER}\nThis vulnerability is no longer reported by the scan as of "
            f"{action_url}. Closing automatically."
        )
        for issue in open_issues:
            if issue["number"] in matched or issue["number"] not in recognizable:
                continue
            gh.comment(issue["number"], close_comment)
            gh.close(issue["number"])
            closed += 1
            eprint(f"Closed #{issue['number']}: {issue.get('title', '')}")
    else:
        eprint("Scan incomplete (scan_complete=false): skipping close phase to avoid false closes")

    eprint(f"Reconcile summary for {stream}: created={created} updated={updated} closed={closed}")
    return 0


def main() -> int:
    parser = ArgumentParser(description="Reconcile GitHub issues against a vuln scan result")
    parser.add_argument("--stream", required=True, help="the NSOLID stream, e.g. node-v22.x-nsolid-v5.x")
    parser.add_argument("--scan-file", required=True, help="path to main.py's JSON scan output")
    parser.add_argument("--action-url", default="", help="URL of the run, linked in issue bodies/comments")
    parser.add_argument("--dry-run", action="store_true", help="print intended actions without mutating")
    args = parser.parse_args()

    with open(args.scan_file) as f:
        scan = json.load(f)

    gh = Gh(dry_run=args.dry_run)
    return reconcile(scan, args.stream, args.action_url, gh)


if __name__ == "__main__":
    sys.exit(main())
