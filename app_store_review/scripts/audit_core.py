#!/usr/bin/env python3
"""Shared, read-only primitives for the App Store review scanners."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Sequence


SKILL_ROOT = Path(__file__).resolve().parents[1]
SOURCE_REGISTRY_PATH = SKILL_ROOT / "references" / "apple_source_registry.json"

SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Informational": 4,
}
SEVERITY_WEIGHT = {
    "Critical": 30.0,
    "High": 15.0,
    "Medium": 7.0,
    "Low": 3.0,
    "Informational": 0.5,
}
CONFIDENCE_FACTOR = {"High": 1.0, "Medium": 0.7, "Low": 0.4}
VERIFICATION_FACTOR = {
    "Verified": 1.0,
    "Likely": 0.8,
    "Possible": 0.5,
    "Not verified": 0.2,
}
CHECK_STATUSES = {"Passed", "Failed", "Not verified", "Not applicable"}

EXCLUDED_DIRS = {
    ".git",
    ".svn",
    ".hg",
    ".build",
    "build",
    "DerivedData",
    "node_modules",
    "Pods",
    "Carthage",
    ".dart_tool",
    ".expo",
    ".gradle",
    "vendor",
    "dist",
    "coverage",
}

SOURCE_EXTENSIONS = {
    ".swift",
    ".m",
    ".mm",
    ".h",
    ".c",
    ".cc",
    ".cpp",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".dart",
    ".kt",
    ".java",
    ".json",
    ".yaml",
    ".yml",
    ".xml",
    ".plist",
    ".xcprivacy",
    ".xcstrings",
    ".strings",
    ".pbxproj",
    ".xcconfig",
    ".entitlements",
    ".gradle",
}


_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)(\b[A-Za-z0-9_.-]*(?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|"
    r"client[_-]?secret|signing[_-]?secret|private[_-]?key|secret|password|passwd|passcode|"
    r"authorization|cookie|session[_-]?id|credential|signature)\b['\"]?\s*[=:]\s*)"
    r"(?:(['\"])(.*?)\2|([^\s,;}&]+))"
)
_SENSITIVE_QUERY = re.compile(
    r"(?i)([?&](?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|key|secret|"
    r"password|passcode|authorization|signature|sig|credential|x-amz-signature|"
    r"x-amz-credential|x-goog-signature)=)[^&#\s]+"
)
_BEARER_TOKEN = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]{8,}")
_AUTHORIZATION_HEADER = re.compile(r"(?i)(\b(?:authorization|cookie|set-cookie)\s*:\s*)[^\r\n]+")
_SWIFT_HEADER_VALUE = re.compile(
    r"(?is)(\b(?:setValue|addValue)\s*\(\s*)(['\"])(.*?)\2"
    r"(\s*,\s*forHTTPHeaderField\s*:\s*['\"](?:authorization|cookie|x-api-key|api-key|x-auth-token)['\"]\s*\))"
)
_JS_HEADER_VALUE = re.compile(
    r"(?is)(\bsetRequestHeader\s*\(\s*['\"](?:authorization|cookie|x-api-key|api-key|x-auth-token)['\"]\s*,\s*)"
    r"(['\"])(.*?)\2(\s*\))"
)
_KNOWN_SECRET = re.compile(
    r"\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{12,}|AKIA[0-9A-Z]{16}|"
    r"gh[opsu]_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35}|"
    r"xox[baprs]-[A-Za-z0-9-]{20,})\b"
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_EMAIL = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![A-Za-z0-9.-])")
_SENSITIVE_RELATION = re.compile(
    r"(?i)(\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|"
    r"password|passcode)\b\s+(?:is|equals)\s+)([^\s,;]+)"
)
_XML_SECRET = re.compile(
    r"(?is)(<key>\s*(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|"
    r"secret|password|passcode|authorization)\s*</key>\s*<string>).*?(</string>)"
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
    re.DOTALL,
)


def redact_text(value: str) -> str:
    """Redact common credentials while preserving enough context for evidence."""

    value = _PRIVATE_KEY.sub("<redacted-private-key>", value)
    value = _XML_SECRET.sub(r"\1<redacted>\2", value)
    value = _SENSITIVE_QUERY.sub(r"\1<redacted>", value)
    value = _SWIFT_HEADER_VALUE.sub(r"\1\2<redacted>\2\4", value)
    value = _JS_HEADER_VALUE.sub(r"\1\2<redacted>\2\4", value)
    value = _AUTHORIZATION_HEADER.sub(r"\1<redacted>", value)
    # Bearer must run before generic ``Authorization: value`` replacement so
    # the token cannot remain after the scheme alone is replaced.
    value = _BEARER_TOKEN.sub(r"\1<redacted>", value)

    def replace_assignment(match: re.Match[str]) -> str:
        quote = match.group(2) or ""
        return f"{match.group(1)}{quote}<redacted>{quote}"

    value = _SENSITIVE_ASSIGNMENT.sub(replace_assignment, value)
    value = _SENSITIVE_RELATION.sub(r"\1<redacted>", value)
    value = _KNOWN_SECRET.sub("<redacted-secret>", value)
    value = _JWT.sub("<redacted-jwt>", value)
    return _EMAIL.sub("<redacted-email>", value)


def redact_structure(value: Any) -> Any:
    """Return a recursively redacted, JSON-compatible structure."""

    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {key: redact_structure(child) for key, child in value.items()}
    if isinstance(value, list):
        return [redact_structure(child) for child in value]
    if isinstance(value, tuple):
        return tuple(redact_structure(child) for child in value)
    return value


@dataclass(frozen=True)
class ScanContext:
    root: Path
    network: bool = False
    deep: bool = False
    asc_metadata: Path | None = None
    simulate_missing_tools: bool = False


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_source_registry() -> dict[str, dict[str, Any]]:
    try:
        payload = json.loads(SOURCE_REGISTRY_PATH.read_text(encoding="utf-8"))
        entries = payload.get("sources", [])
        return {entry["id"]: entry for entry in entries}
    except (OSError, ValueError, KeyError, TypeError):
        return {}


def relative_path(path: Path | str | None, root: Path) -> str | None:
    if path is None:
        return None
    path_obj = Path(path)
    try:
        return str(path_obj.resolve().relative_to(root.resolve()))
    except (OSError, ValueError):
        return str(path_obj)


def stable_id(base: str, file: str | None = None, detail: str = "") -> str:
    seed = f"{base}|{file or ''}|{detail.strip().lower()}".encode("utf-8")
    suffix = hashlib.sha1(seed).hexdigest()[:8].upper()
    return f"{base}-{suffix}"


def evidence(
    *,
    kind: str,
    value: str,
    file: str | None = None,
    line: int | None = None,
    excerpt: str | None = None,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "value": redact_text(value),
        "file": file,
        "line": line,
        "excerpt": redact_text(excerpt) if excerpt is not None else None,
    }


def make_finding(
    *,
    base_id: str,
    severity: str,
    confidence: str,
    verification: str,
    area: str,
    title: str,
    problem: str,
    evidence_items: list[dict[str, Any]],
    source_id: str,
    risk_reason: str,
    remediation: str,
    verification_steps: list[str],
    file: str | None = None,
    line: int | None = None,
    command: str | None = None,
    autofix_available: bool = False,
    autofix_notes: str = "Requires user-selected, scoped changes.",
    limitations: list[str] | None = None,
    heuristic: bool = True,
    tags: list[str] | None = None,
    id_detail: str = "",
) -> dict[str, Any]:
    registry = load_source_registry()
    source = registry.get(source_id)
    if source is None:
        source = {
            "id": source_id,
            "title": "Official Apple source not verified",
            "section": "Not verified",
            "url": None,
            "last_checked": None,
            "status": "not-verified",
            "summary": "The scanner could not resolve this source in the bundled registry.",
            "applicability": area,
        }
    finding_file = file or next(
        (item.get("file") for item in evidence_items if item.get("file")), None
    )
    finding_line = line or next(
        (item.get("line") for item in evidence_items if item.get("line")), None
    )
    return {
        "id": stable_id(base_id, finding_file, id_detail or title),
        "rule_id": base_id,
        "severity": severity,
        "confidence": confidence,
        "verification": verification,
        "area": area,
        "title": title,
        "problem": problem,
        "evidence": evidence_items,
        "file": finding_file,
        "line": finding_line,
        "command": command,
        "apple_source": source,
        "risk_reason": risk_reason,
        "remediation": remediation,
        "autofix": {
            "available": autofix_available,
            "safety": "user-selection-required" if autofix_available else "manual-or-contextual",
            "notes": autofix_notes,
        },
        "verification_steps": verification_steps,
        "limitations": limitations or [],
        "heuristic": heuristic,
        "tags": tags or [],
    }


def check(
    check_id: str,
    area: str,
    status: str,
    summary: str,
    *,
    applicable: bool = True,
    evidence_items: list[dict[str, Any]] | None = None,
    source_id: str | None = None,
) -> dict[str, Any]:
    if status not in CHECK_STATUSES:
        raise ValueError(f"Unsupported check status: {status}")
    return {
        "id": check_id,
        "area": area,
        "status": status,
        "applicable": applicable,
        "summary": summary,
        "evidence": evidence_items or [],
        "source_id": source_id,
    }


def new_result(scanner: str) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "scanner": scanner,
        "status": "completed",
        "error": None,
        "findings": [],
        "checks": [],
        "facts": {},
        "tools": {},
        "started_at": utc_now(),
        "finished_at": None,
    }


def finish_result(result: dict[str, Any]) -> dict[str, Any]:
    scanner = result.get("scanner") or "scanner"
    scanner_path = SKILL_ROOT / "scripts" / f"{scanner}.py"
    for finding in result.get("findings", []):
        finding.setdefault("scanner", scanner)
        if not finding.get("command"):
            finding["command"] = (
                f'python3 "$SKILL_DIR/scripts/{scanner_path.name}" '
                '"path/to/project-root" --format json'
            )
    result["findings"] = deduplicate_findings(result.get("findings", []))
    result["finished_at"] = utc_now()
    return redact_structure(result)


def failed_result(scanner: str, exc: BaseException) -> dict[str, Any]:
    result = new_result(scanner)
    result["status"] = "error"
    result["error"] = f"{type(exc).__name__}: {exc}"
    result["checks"].append(
        check(
            f"{scanner}.technical",
            "Audit tooling",
            "Not verified",
            "The scanner failed; its audit area remains unverified.",
            evidence_items=[evidence(kind="error", value=result["error"])],
        )
    )
    return finish_result(result)


def iter_files(
    root: Path,
    *,
    suffixes: set[str] | None = None,
    names: set[str] | None = None,
    max_size: int = 2_000_000,
) -> Iterator[Path]:
    root = root.resolve()
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED_DIRS and not d.endswith(".xcarchive"))
        for filename in sorted(files):
            path = Path(current) / filename
            if names is not None and filename not in names:
                continue
            if suffixes is not None and path.suffix.lower() not in suffixes:
                continue
            try:
                if path.is_symlink() or path.stat().st_size > max_size:
                    continue
            except OSError:
                continue
            yield path


def iter_source_files(root: Path) -> Iterator[Path]:
    yield from iter_files(root, suffixes=SOURCE_EXTENSIONS)


def read_text(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096] and path.suffix.lower() not in {".plist", ".xcprivacy"}:
        return None
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


def text_corpus(root: Path) -> list[tuple[Path, str]]:
    corpus: list[tuple[Path, str]] = []
    for path in iter_source_files(root):
        text = read_text(path)
        if text is not None:
            corpus.append((path, text))
    return corpus


COMMENTED_CODE_SUFFIXES = {
    ".swift",
    ".m",
    ".mm",
    ".h",
    ".c",
    ".cc",
    ".cpp",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".dart",
    ".kt",
    ".java",
    ".gradle",
    ".pbxproj",
}


def strip_code_comments(text: str) -> str:
    """Remove // and /* */ comments while preserving strings and line numbers."""

    output = list(text)
    index = 0
    state = "code"
    quote = ""
    escaped = False
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if state == "line-comment":
            if char == "\n":
                state = "code"
            else:
                output[index] = " "
            index += 1
            continue
        if state == "block-comment":
            if char == "*" and following == "/":
                output[index] = output[index + 1] = " "
                index += 2
                state = "code"
                continue
            if char != "\n":
                output[index] = " "
            index += 1
            continue
        if state == "string":
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                state = "code"
            index += 1
            continue
        if char in {'"', "'", "`"}:
            state = "string"
            quote = char
            escaped = False
            index += 1
            continue
        if char == "/" and following == "/":
            output[index] = output[index + 1] = " "
            index += 2
            state = "line-comment"
            continue
        if char == "/" and following == "*":
            output[index] = output[index + 1] = " "
            index += 2
            state = "block-comment"
            continue
        index += 1
    return "".join(output)


def code_corpus(root: Path) -> list[tuple[Path, str]]:
    """Return source text with executable-code comments removed safely."""

    return [
        (path, strip_code_comments(text) if path.suffix.lower() in COMMENTED_CODE_SUFFIXES else text)
        for path, text in text_corpus(root)
    ]


def find_matches(
    corpus: Sequence[tuple[Path, str]], pattern: str | re.Pattern[str], root: Path
) -> list[dict[str, Any]]:
    compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE) if isinstance(pattern, str) else pattern
    matches: list[dict[str, Any]] = []
    for path, text in corpus:
        for match in compiled.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            source_line = text.splitlines()[line - 1].strip() if text.splitlines() else ""
            matches.append(
                {
                    "path": path,
                    "file": relative_path(path, root),
                    "line": line,
                    "match": redact_text(match.group(0)),
                    "excerpt": redact_text(source_line[:300]),
                }
            )
    return matches


def match_evidence(item: dict[str, Any], label: str) -> dict[str, Any]:
    return evidence(
        kind="source-match",
        value=label,
        file=item.get("file"),
        line=item.get("line"),
        excerpt=item.get("excerpt"),
    )


def load_plist(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        with path.open("rb") as handle:
            value = plistlib.load(handle)
        if not isinstance(value, dict):
            return None, "Top-level plist value is not a dictionary"
        return value, None
    except (OSError, plistlib.InvalidFileException, ValueError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


def command_available(name: str, simulate_missing: bool = False) -> str | None:
    if simulate_missing:
        return None
    return shutil.which(name)


def run_command(
    args: Sequence[str], *, cwd: Path, timeout: int = 20
) -> tuple[int | None, str, str, str | None]:
    try:
        completed = subprocess.run(
            list(args),
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
            env={**os.environ, "CI": "1"},
        )
        return completed.returncode, completed.stdout, completed.stderr, None
    except (OSError, subprocess.SubprocessError) as exc:
        return None, "", "", f"{type(exc).__name__}: {exc}"


def deduplicate_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    selected: dict[str, dict[str, Any]] = {}
    for finding in findings:
        key = finding.get("id") or stable_id(
            finding.get("rule_id") or "FINDING",
            finding.get("file"),
            finding.get("title") or finding.get("problem") or "",
        )
        previous = selected.get(key)
        if previous is None:
            selected[key] = finding
            continue
        if SEVERITY_ORDER.get(finding.get("severity"), 99) < SEVERITY_ORDER.get(
            previous.get("severity"), 99
        ):
            finding, previous = previous, finding
            selected[key] = previous
        existing_evidence = {
            json.dumps(item, ensure_ascii=False, sort_keys=True)
            for item in previous.get("evidence", [])
        }
        for item in finding.get("evidence", []):
            marker = json.dumps(item, ensure_ascii=False, sort_keys=True)
            if marker not in existing_evidence:
                previous.setdefault("evidence", []).append(item)
                existing_evidence.add(marker)
        for field in ("limitations", "verification_steps", "tags"):
            combined = list(previous.get(field, []))
            for item in finding.get(field, []):
                if item not in combined:
                    combined.append(item)
            previous[field] = combined
        lines = [value for value in (previous.get("line"), finding.get("line")) if isinstance(value, int)]
        if lines:
            previous["line"] = min(lines)
    return sorted(
        selected.values(),
        key=lambda item: (
            SEVERITY_ORDER.get(item.get("severity"), 99),
            item.get("area") or "",
            item.get("id") or "",
        ),
    )


def risk_index(findings: Sequence[dict[str, Any]]) -> int:
    raw = 0.0
    for finding in findings:
        raw += (
            SEVERITY_WEIGHT.get(finding.get("severity"), 0.0)
            * CONFIDENCE_FACTOR.get(finding.get("confidence"), 0.4)
            * VERIFICATION_FACTOR.get(finding.get("verification"), 0.2)
        )
    return min(100, round(100.0 * (1.0 - math.exp(-raw / 55.0))))


def coverage_metrics(checks: Sequence[dict[str, Any]]) -> dict[str, Any]:
    applicable = [item for item in checks if item.get("applicable", True)]
    verified = [item for item in applicable if item.get("status") in {"Passed", "Failed"}]
    coverage = round(100 * len(verified) / len(applicable)) if applicable else 0
    by_area: dict[str, dict[str, int]] = {}
    for item in applicable:
        area = item.get("area") or "Unknown"
        bucket = by_area.setdefault(area, {"total": 0, "verified": 0, "not_verified": 0})
        bucket["total"] += 1
        if item.get("status") in {"Passed", "Failed"}:
            bucket["verified"] += 1
        else:
            bucket["not_verified"] += 1
    return {
        "coverage": coverage,
        "applicable_checks": len(applicable),
        "verified_checks": len(verified),
        "by_area": by_area,
    }


def evidence_completeness(findings: Sequence[dict[str, Any]]) -> int:
    if not findings:
        return 100
    required = (
        "id",
        "severity",
        "confidence",
        "verification",
        "area",
        "problem",
        "evidence",
        "apple_source",
        "risk_reason",
        "remediation",
        "autofix",
        "verification_steps",
        "limitations",
    )
    total = len(findings) * len(required)
    present = sum(1 for finding in findings for key in required if finding.get(key) is not None and finding.get(key) != "")
    return round(100 * present / total)


def source_freshness(findings: Sequence[dict[str, Any]], today: date | None = None) -> int:
    today = today or date.today()
    sources = {item.get("apple_source", {}).get("id"): item.get("apple_source", {}) for item in findings}
    sources.pop(None, None)
    if not sources:
        return 100
    current = 0
    for source in sources.values():
        try:
            checked = date.fromisoformat(source.get("last_checked"))
            if (today - checked).days <= 180 and source.get("status", "").startswith("official"):
                current += 1
        except (TypeError, ValueError):
            pass
    return round(100 * current / len(sources))


def readiness_status(
    findings: Sequence[dict[str, Any]], checks: Sequence[dict[str, Any]], risk: int, coverage: int
) -> tuple[str, list[str]]:
    reasons: list[str] = []
    critical = [
        item
        for item in findings
        if item.get("severity") == "Critical" and item.get("verification") in {"Verified", "Likely"}
    ]
    high = [
        item
        for item in findings
        if item.get("severity") == "High" and item.get("verification") in {"Verified", "Likely"}
    ]
    critical_areas = {
        "Project configuration",
        "Reliability",
        "Privacy",
        "App Store Connect metadata",
    }
    unverified_critical = sorted(
        area
        for area in critical_areas
        if any(
            check_item.get("area") == area
            and check_item.get("applicable", True)
            and check_item.get("status") == "Not verified"
            for check_item in checks
        )
    )
    if critical:
        reasons.append(f"{len(critical)} verified or likely Critical finding(s) remain.")
        if coverage < 45:
            reasons.append("Less than 45% of applicable checks were verified in addition to the blocking evidence.")
        return "Not ready", reasons
    if risk >= 70 or len(high) >= 3:
        reasons.append("The internal risk index or concentration of High findings is too high for release readiness.")
        if coverage < 45:
            reasons.append("Less than 45% of applicable checks were verified in addition to the material findings.")
        return "Not ready", reasons
    if coverage < 45:
        reasons.append("Less than 45% of applicable checks were verified and no stronger readiness conclusion could be established.")
        return "Insufficient evidence", reasons
    if unverified_critical:
        reasons.append("Critical applicable areas remain unverified: " + ", ".join(unverified_critical) + ".")
        return "Conditionally ready", reasons
    if high or any(item.get("severity") == "Medium" for item in findings) or coverage < 90:
        reasons.append("Material findings or manual verification remain.")
        return "Conditionally ready", reasons
    return "Ready", ["No blocking finding was detected and critical applicable areas were verified."]


def summarize_counts(findings: Sequence[dict[str, Any]]) -> dict[str, int]:
    return {
        severity: sum(1 for item in findings if item.get("severity") == severity)
        for severity in SEVERITY_ORDER
    }


def validate_report_schema(report: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    top_required = {
        "schema_version",
        "generated_at",
        "project",
        "readiness",
        "metrics",
        "findings",
        "checks",
        "scanner_results",
        "limitations",
        "sources_used",
    }
    missing = sorted(top_required - report.keys())
    if missing:
        errors.append("Missing report keys: " + ", ".join(missing))
    if not isinstance(report.get("findings"), list):
        errors.append("findings must be an array")
    for index, finding in enumerate(report.get("findings", [])):
        required = {
            "id",
            "severity",
            "confidence",
            "verification",
            "area",
            "problem",
            "evidence",
            "apple_source",
            "risk_reason",
            "remediation",
            "autofix",
            "verification_steps",
            "limitations",
        }
        absent = sorted(required - finding.keys())
        if absent:
            errors.append(f"Finding {index} missing: {', '.join(absent)}")
        if finding.get("severity") not in SEVERITY_ORDER:
            errors.append(f"Finding {index} has invalid severity")
        if finding.get("confidence") not in CONFIDENCE_FACTOR:
            errors.append(f"Finding {index} has invalid confidence")
        if finding.get("verification") not in VERIFICATION_FACTOR:
            errors.append(f"Finding {index} has invalid verification")
        source = finding.get("apple_source") or {}
        if not source.get("url") and source.get("status") != "not-verified":
            errors.append(f"Finding {index} has no canonical Apple URL")
    return errors


def markdown_report(report: dict[str, Any]) -> str:
    metrics = report["metrics"]
    readiness = report["readiness"]
    counts = summarize_counts(report["findings"])
    lines = [
        "# App Store Review Audit",
        "",
        f"- Readiness: **{readiness['status']}**",
        f"- Risk index: **{metrics['risk_index']}/100** (internal heuristic, not a rejection probability)",
        f"- Verification coverage: **{metrics['coverage']}%**",
        f"- Evidence completeness: **{metrics['evidence_completeness']}%**",
        f"- Source freshness: **{metrics['source_freshness']}%**",
        *[f"- Readiness reason: {reason}" for reason in readiness.get("reasons", [])],
        *(
            ["- Scanner errors: " + ", ".join(report.get("summary", {}).get("scanner_errors", []))]
            if report.get("summary", {}).get("scanner_errors")
            else []
        ),
        "",
        "## Executive summary",
        "",
        (
            f"Detected {len(report['findings'])} finding(s): "
            + ", ".join(f"{key} {value}" for key, value in counts.items() if value)
            + "."
        ),
        "",
    ]
    sections = [
        ("Blocking issues", {"Critical"}),
        ("High risks", {"High"}),
        ("Medium risks", {"Medium"}),
        ("Low risks", {"Low"}),
        ("Informational findings", {"Informational"}),
    ]
    for heading, severities in sections:
        lines.extend([f"## {heading}", ""])
        items = [item for item in report["findings"] if item["severity"] in severities]
        if not items:
            lines.extend(["None detected by static analysis.", ""])
            continue
        for item in items:
            source = item["apple_source"]
            location = item.get("file") or "project-wide"
            if item.get("line"):
                location += f":{item['line']}"
            lines.extend(
                [
                    f"### {item['id']} — {item['title']}",
                    "",
                    f"- Severity / confidence / verification: {item['severity']} / {item['confidence']} / {item['verification']}",
                    f"- Area: {item['area']}",
                    f"- Evidence location: `{location}`",
                    f"- Problem: {item['problem']}",
                    f"- Why it matters: {item['risk_reason']}",
                    f"- Fix: {item['remediation']}",
                    f"- Apple source: [{source.get('title')}]({source.get('url')}) — {source.get('section')}; checked {source.get('last_checked')}",
                    f"- Limitations: {'; '.join(item.get('limitations') or ['None recorded'])}",
                    "",
                ]
            )
    unverified = [item for item in report["checks"] if item.get("status") == "Not verified"]
    lines.extend(["## Practical recommendations", ""])
    ordered = [item for item in report["findings"] if item["severity"] != "Informational"]
    if ordered:
        for index, item in enumerate(ordered, 1):
            lines.append(f"{index}. {item['remediation']} ({item['id']})")
    else:
        lines.append("Complete the manual and live checks listed below before submission.")
    lines.extend(["", "## Unverified areas", ""])
    if unverified:
        lines.extend(f"- {item['area']}: {item['summary']}" for item in unverified)
    else:
        lines.append("None recorded.")
    manual = report.get("manual_actions", [])
    lines.extend(["", "## Manual actions", ""])
    lines.extend(f"- {item}" for item in manual)
    asc = report.get("app_store_connect_actions", [])
    lines.extend(["", "## App Store Connect actions", ""])
    lines.extend(f"- {item}" for item in asc)
    lines.extend(["", "## Recommended fix order", ""])
    if ordered:
        lines.extend(
            f"{index}. [{item['severity']}] {item['title']} — {item['id']}"
            for index, item in enumerate(ordered, 1)
        )
    else:
        lines.append("1. Finish live device, Sandbox, and App Store Connect verification.")
    recheck = report.get("recheck")
    lines.extend(["", "## Recheck commands", ""])
    command = report.get("recheck_command")
    lines.append(f"```sh\n{command}\n```" if command else "Run the same audit command with `--baseline` pointing to this JSON report.")
    if recheck:
        lines.extend(
            [
                "",
                "## Recheck comparison",
                "",
                f"- Resolved: {len(recheck.get('resolved', []))}",
                f"- Persisting: {len(recheck.get('persisting', []))}",
                f"- New: {len(recheck.get('new', []))}",
                f"- Could not reverify: {len(recheck.get('could_not_reverify', []))}",
            ]
        )
    lines.extend(["", "## App Review Notes", "", report.get("app_review_notes", "Not generated; provide review access details first."), ""])
    lines.extend(["## Evidence appendix", ""])
    for item in report["findings"]:
        lines.append(f"### {item['id']}")
        lines.append("")
        for proof in item.get("evidence", []):
            where = proof.get("file") or "project"
            if proof.get("line"):
                where += f":{proof['line']}"
            lines.append(f"- `{where}` — {proof.get('value')}: {proof.get('excerpt') or ''}".rstrip())
        if item.get("command"):
            lines.append(f"- Confirmation command/test: `{item['command']}`")
        lines.append("")
    lines.extend(["## Source registry used", ""])
    for source in report.get("sources_used", []):
        lines.append(
            f"- [{source.get('title')}]({source.get('url')}) — {source.get('section')}; checked {source.get('last_checked')}; {source.get('status')}"
        )
    lines.extend(
        [
            "",
            "## Limitations",
            "",
            *[f"- {item}" for item in report.get("limitations", [])],
            "",
        ]
    )
    return "\n".join(lines)


def human_scanner_summary(result: dict[str, Any]) -> str:
    lines = [
        f"Scanner: {result['scanner']}",
        f"Status: {result['status']}",
        f"Findings: {len(result.get('findings', []))}",
    ]
    for item in sorted(
        result.get("findings", []), key=lambda value: SEVERITY_ORDER.get(value.get("severity"), 99)
    ):
        location = item.get("file") or "project-wide"
        if item.get("line"):
            location += f":{item['line']}"
        lines.append(
            f"- [{item['severity']}] {item['id']} {item['title']} ({location}; {item['confidence']}/{item['verification']})"
        )
    for item in result.get("checks", []):
        lines.append(f"- CHECK {item['status']}: {item['summary']}")
    if result.get("error"):
        lines.append(f"Error: {result['error']}")
    return "\n".join(lines)


def scanner_cli(scan_func: Callable[[ScanContext], dict[str, Any]], scanner_name: str) -> int:
    parser = argparse.ArgumentParser(description=f"Run {scanner_name} read-only App Store checks.")
    parser.add_argument("project", type=Path, help="Path to the project root")
    parser.add_argument("--format", choices=("human", "json", "both"), default="both")
    parser.add_argument("--network", action="store_true", help="Verify extracted URLs over the network")
    parser.add_argument("--asc-metadata", type=Path, help="Exported App Store Connect metadata JSON")
    parser.add_argument("--simulate-missing-tools", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    root = args.project.expanduser().resolve()
    if not root.is_dir():
        print(f"Technical error: project path is not a directory: {root}", file=sys.stderr)
        return 2
    context = ScanContext(
        root=root,
        network=args.network,
        deep=False,
        asc_metadata=args.asc_metadata.expanduser().resolve() if args.asc_metadata else None,
        simulate_missing_tools=args.simulate_missing_tools,
    )
    try:
        result = scan_func(context)
    except Exception as exc:  # Keep standalone scanners diagnostic without swallowing interrupts.
        result = failed_result(scanner_name, exc)
    if args.format in {"human", "both"}:
        print(human_scanner_summary(result))
    if args.format == "both":
        print("\n--- JSON ---")
    if args.format in {"json", "both"}:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def make_output_dir(requested: Path | None) -> Path:
    if requested is not None:
        requested.mkdir(parents=True, exist_ok=True)
        return requested.resolve()
    return Path(tempfile.mkdtemp(prefix="app-store-review-audit-"))
