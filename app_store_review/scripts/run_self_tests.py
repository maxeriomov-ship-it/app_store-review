#!/usr/bin/env python3
"""Deterministic, dependency-free self-tests for the App Store review skill."""

from __future__ import annotations

import hashlib
import json
import os
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_ROOT = SCRIPT_DIR.parent
FIXTURES = SKILL_ROOT / "fixtures"
COMPLIANT = FIXTURES / "compliant_app"
RISKY = FIXTURES / "risky_app"

if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from audit_core import (  # noqa: E402
    CHECK_STATUSES,
    CONFIDENCE_FACTOR,
    SEVERITY_ORDER,
    VERIFICATION_FACTOR,
    ScanContext,
    evidence,
    finish_result,
    human_scanner_summary,
    make_finding,
    markdown_report,
    new_result,
    redact_text,
    validate_report_schema,
)
import run_audit  # noqa: E402
import scan_build_configuration  # noqa: E402


MANDATORY_RISKY_RULES = {
    "PERMISSION-PURPOSE-EMPTY": "empty permission purpose string",
    "URL-TEST-ENDPOINT": "test endpoint",
    "PLACEHOLDER-USER-VISIBLE": "placeholder content",
    "SWIFT-FORCED-CAST": "forced Swift cast",
    "PRIVACY-MANIFEST-SDK-NOT-DETECTED": "listed SDK without source-visible privacy manifest",
    "SOCIAL-LOGIN-EQUIVALENT-NOT-DETECTED": "social login without detected equivalent option",
    "ACCOUNT-DELETION-NOT-DETECTED": "account creation without detected deletion",
    "RESTORE-PURCHASE-NOT-DETECTED": "purchase flow without detected restoration",
    "LEGAL-URL-INVALID": "unavailable legal link",
    "LOCALIZATION-KEY-MISMATCH": "inconsistent localizations",
    "AI-CONSENT-NOT-DETECTED": "possible AI data transfer without detected consent",
    "UGC-SAFETY-CONTROLS-NOT-DETECTED": "UGC without detected report/block/safety controls",
}

REPORT_HEADINGS = {
    "# App Store Review Audit",
    "## Blocking issues",
    "## High risks",
    "## Medium risks",
    "## Low risks",
    "## Informational findings",
    "## Practical recommendations",
    "## Unverified areas",
    "## Manual actions",
    "## App Store Connect actions",
    "## Recommended fix order",
    "## Recheck commands",
    "## App Review Notes",
    "## Evidence appendix",
    "## Source registry used",
    "## Limitations",
}


class SelfTestFailure(AssertionError):
    """A mandatory skill self-test failed."""


def require(condition: Any, message: str) -> None:
    if not condition:
        raise SelfTestFailure(message)


def fixture_snapshot(root: Path) -> dict[str, tuple[Any, ...]]:
    """Capture fixture content and relevant metadata to detect scanner writes."""
    snapshot: dict[str, tuple[Any, ...]] = {}
    for path in sorted([root, *root.rglob("*")], key=lambda value: str(value.relative_to(root))):
        rel = "." if path == root else path.relative_to(root).as_posix()
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if path.is_symlink():
            snapshot[rel] = ("symlink", mode, os.readlink(path), info.st_mtime_ns)
        elif path.is_dir():
            snapshot[rel] = ("directory", mode, info.st_mtime_ns)
        elif path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            snapshot[rel] = ("file", mode, info.st_size, digest, info.st_mtime_ns)
        else:
            snapshot[rel] = ("other", mode, info.st_size, info.st_mtime_ns)
    return snapshot


def context(root: Path, *, missing_tools: bool = True) -> ScanContext:
    return ScanContext(
        root=root.resolve(),
        network=False,
        deep=False,
        asc_metadata=None,
        simulate_missing_tools=missing_tools,
    )


def write_plist(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        plistlib.dump(payload, handle)


def validate_finding(finding: dict[str, Any], *, root: Path) -> None:
    required = {
        "id",
        "severity",
        "confidence",
        "verification",
        "area",
        "title",
        "problem",
        "evidence",
        "file",
        "line",
        "command",
        "apple_source",
        "risk_reason",
        "remediation",
        "autofix",
        "verification_steps",
        "limitations",
        "heuristic",
        "scanner",
    }
    missing = sorted(required - finding.keys())
    require(not missing, f"finding {finding.get('id')} is missing fields: {missing}")
    require(finding["severity"] in SEVERITY_ORDER, f"invalid severity in {finding['id']}")
    require(finding["confidence"] in CONFIDENCE_FACTOR, f"invalid confidence in {finding['id']}")
    require(finding["verification"] in VERIFICATION_FACTOR, f"invalid verification in {finding['id']}")
    require(isinstance(finding["heuristic"], bool), f"heuristic marker is not boolean in {finding['id']}")
    require(isinstance(finding["evidence"], list) and finding["evidence"], f"no evidence in {finding['id']}")
    require(isinstance(finding["verification_steps"], list) and finding["verification_steps"], f"no verification steps in {finding['id']}")
    require(isinstance(finding["limitations"], list), f"limitations are not an array in {finding['id']}")
    require(isinstance(finding["autofix"], dict) and "available" in finding["autofix"], f"invalid autofix object in {finding['id']}")
    require(isinstance(finding["command"], str) and finding["command"].strip(), f"no confirmation command/test in {finding['id']}")
    require(isinstance(finding["scanner"], str) and finding["scanner"], f"no originating scanner in {finding['id']}")
    location = finding.get("file")
    require(not location or not Path(location).is_absolute(), f"absolute finding path leaked in {finding['id']}")
    for proof in finding["evidence"]:
        require(isinstance(proof, dict), f"non-object evidence in {finding['id']}")
        require("kind" in proof and "value" in proof, f"evidence lacks kind/value in {finding['id']}")
        proof_file = proof.get("file")
        require(not proof_file or not Path(proof_file).is_absolute(), f"absolute evidence path leaked in {finding['id']}")
    source = finding["apple_source"]
    require(isinstance(source, dict), f"source is not an object in {finding['id']}")
    require(all(key in source for key in ("id", "title", "section", "url", "last_checked", "summary", "applicability", "status")), f"incomplete source in {finding['id']}")
    require(source.get("status") != "not-verified", f"bundled scanner source is unresolved in {finding['id']}")
    parsed = urlsplit(source.get("url") or "")
    require(parsed.scheme == "https", f"source is not HTTPS in {finding['id']}")
    require((parsed.hostname or "").endswith("apple.com"), f"mandatory source is not an official Apple host in {finding['id']}")


def validate_scanner_result(result: dict[str, Any], *, root: Path, expected_name: str) -> None:
    required = {"scanner", "status", "error", "findings", "checks", "facts", "tools", "started_at", "finished_at"}
    require(not (required - result.keys()), f"{expected_name} result is missing keys: {sorted(required - result.keys())}")
    require(result["scanner"] == expected_name, f"scanner name mismatch: {result['scanner']} != {expected_name}")
    require(result["status"] == "completed", f"{expected_name} failed: {result.get('error')}")
    require(result["started_at"] and result["finished_at"], f"{expected_name} has incomplete timestamps")
    require(isinstance(result["findings"], list), f"{expected_name}.findings is not an array")
    require(isinstance(result["checks"], list), f"{expected_name}.checks is not an array")
    require(isinstance(result["facts"], dict), f"{expected_name}.facts is not an object")
    require(isinstance(result["tools"], dict), f"{expected_name}.tools is not an object")
    for finding in result["findings"]:
        validate_finding(finding, root=root)
    for check_item in result["checks"]:
        require(check_item.get("status") in CHECK_STATUSES, f"invalid check status in {expected_name}")
        require(all(key in check_item for key in ("id", "area", "status", "applicable", "summary", "evidence", "source_id")), f"incomplete check in {expected_name}")
    encoded = json.dumps(result, ensure_ascii=False, sort_keys=True)
    require(json.loads(encoded)["scanner"] == expected_name, f"{expected_name} JSON round trip failed")
    human = human_scanner_summary(result)
    require(f"Scanner: {expected_name}" in human and "Status: completed" in human, f"{expected_name} human output is malformed")


def scan_everything(root: Path) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    scan_context = context(root)
    for module in run_audit.FULL_SCANNERS:
        result = module.scan(scan_context)
        validate_scanner_result(result, root=root, expected_name=module.__name__)
        results.append(result)
    return results


def report_for(root: Path, *, baseline: dict[str, Any] | None = None) -> dict[str, Any]:
    report = run_audit.build_report(context(root), profile="full", baseline=baseline)
    errors = validate_report_schema(report)
    require(not errors, "report schema errors: " + "; ".join(errors))
    require(report["schema_version"] == "1.0", "unexpected report schema version")
    require(report["metrics"]["risk_index"] in range(101), "risk index outside 0...100")
    require(report["metrics"]["coverage"] in range(101), "coverage outside 0...100")
    require(report["metrics"]["evidence_completeness"] in range(101), "evidence completeness outside 0...100")
    require(report["metrics"]["source_freshness"] in range(101), "source freshness outside 0...100")
    require("not a statistical probability" in report["metrics"]["risk_interpretation"], "risk interpretation is missing")
    ids = [finding["id"] for finding in report["findings"]]
    require(len(ids) == len(set(ids)), "deduplicated report contains duplicate finding IDs")
    json.loads(json.dumps(report, ensure_ascii=False))
    markdown = markdown_report(report)
    require(markdown.endswith("\n"), "Markdown report must end with a newline")
    for heading in REPORT_HEADINGS:
        require(heading in markdown, f"Markdown report is missing {heading}")
    return report


def run_cli(root: Path, output_dir: Path, *, baseline: Path | None = None) -> tuple[dict[str, Any], str]:
    command = [
        sys.executable,
        str(SCRIPT_DIR / "run_audit.py"),
        str(root),
        "--output-dir",
        str(output_dir),
        "--simulate-missing-tools",
        "--quiet",
    ]
    if baseline is not None:
        command.extend(["--baseline", str(baseline)])
    completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=60)
    require(completed.returncode == 0, f"run_audit returned {completed.returncode}: {completed.stderr}")
    json_path = output_dir / "app-store-review-report.json"
    markdown_path = output_dir / "app-store-review-report.md"
    require(json_path.is_file(), "JSON report was not created")
    require(markdown_path.is_file(), "Markdown report was not created")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    schema_errors = validate_report_schema(payload)
    require(not schema_errors, "CLI JSON schema errors: " + "; ".join(schema_errors))
    markdown = markdown_path.read_text(encoding="utf-8")
    for heading in REPORT_HEADINGS:
        require(heading in markdown, f"CLI Markdown report is missing {heading}")
    return payload, markdown


def test_fixture_contract() -> None:
    require(COMPLIANT.is_dir() and RISKY.is_dir(), "fixture directories are missing")
    for fixture in (COMPLIANT, RISKY):
        require(any(fixture.rglob("project.pbxproj")), f"{fixture.name} has no Xcode project marker")
        plist_path = fixture / "App" / "Info.plist"
        with plist_path.open("rb") as handle:
            require(isinstance(plistlib.load(handle), dict), f"{fixture.name} Info.plist is invalid")
    with (COMPLIANT / "App" / "PrivacyInfo.xcprivacy").open("rb") as handle:
        require(isinstance(plistlib.load(handle), dict), "compliant privacy manifest is invalid")
    with (COMPLIANT / "ThirdParty" / "GoogleSignIn" / "PrivacyInfo.xcprivacy").open("rb") as handle:
        require(isinstance(plistlib.load(handle), dict), "compliant dependency privacy manifest is invalid")
    require(not any(RISKY.rglob("*.xcprivacy")), "risky fixture must intentionally omit PrivacyInfo.xcprivacy")
    require("Рискованный" in (RISKY / "App" / "Info.plist").read_text(encoding="utf-8"), "fixture Unicode marker is missing")


def test_all_scanners_and_result_schemas() -> None:
    compliant_results = scan_everything(COMPLIANT)
    risky_results = scan_everything(RISKY)
    expected = len(run_audit.FULL_SCANNERS)
    require(len(compliant_results) == expected and len(risky_results) == expected, "not every scanner ran on both fixtures")


def test_intentional_risky_findings() -> None:
    report = report_for(RISKY)
    present = {finding["rule_id"] for finding in report["findings"]}
    missing = {rule: label for rule, label in MANDATORY_RISKY_RULES.items() if rule not in present}
    require(not missing, "risky fixture findings missing: " + json.dumps(missing, ensure_ascii=False, sort_keys=True))
    require(report["readiness"]["status"] != "Ready", "risky fixture was incorrectly marked Ready")


def test_compliant_has_no_static_findings() -> None:
    report = report_for(COMPLIANT)
    critical = [finding for finding in report["findings"] if finding["severity"] == "Critical"]
    require(not critical, "compliant fixture produced Critical findings: " + ", ".join(finding["id"] for finding in critical))
    present = {finding["rule_id"] for finding in report["findings"]}
    false_intentional = sorted(set(MANDATORY_RISKY_RULES) & present)
    require(not false_intentional, "compliant fixture triggered risky-only rules: " + ", ".join(false_intentional))
    require(not report["findings"], "compliant fixture produced static findings: " + ", ".join(finding["id"] for finding in report["findings"]))


def test_compliant_xcode_project_is_readable() -> None:
    xcodebuild = shutil.which("xcodebuild")
    if xcodebuild is None:
        return
    with tempfile.TemporaryDirectory(prefix="app-store-review-xcode-list-") as directory:
        copied = Path(directory) / "compliant_app"
        shutil.copytree(COMPLIANT, copied)
        completed = subprocess.run(
            [xcodebuild, "-list", "-project", str(copied / "CompliantApp.xcodeproj")],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )
        require(completed.returncode == 0, "compliant Xcode project is unreadable: " + completed.stderr[-1000:])
        require("CompliantApp" in completed.stdout and "Release" in completed.stdout, "compliant Xcode project lacks its target/scheme or Release configuration")


def test_cli_json_and_markdown_reports() -> None:
    with tempfile.TemporaryDirectory(prefix="app-store-review-self-test-") as directory:
        temp = Path(directory)
        compliant_report, compliant_markdown = run_cli(COMPLIANT, temp / "compliant")
        risky_report, risky_markdown = run_cli(RISKY, temp / "risky")
        require(compliant_report["project"]["ios_target_detected"] is True, "CLI did not detect compliant iOS target")
        require(risky_report["metrics"]["finding_counts"]["High"] >= 1, "CLI risky report has no High finding")
        require("internal heuristic, not a rejection probability" in risky_markdown, "Markdown risk caveat is missing")
        require("Passing this audit does not guarantee Apple approval." in compliant_markdown, "Markdown limitations are incomplete")
        low_section = risky_markdown.split("## Low risks", 1)[1].split("## Informational findings", 1)[0]
        informational_section = risky_markdown.split("## Informational findings", 1)[1].split("## Practical recommendations", 1)[0]
        require("Severity / confidence / verification: Informational" not in low_section, "Informational findings were grouped as Low risks")
        require("Severity / confidence / verification: Informational" in informational_section, "Informational findings section is empty")


def test_report_paths_are_share_safe() -> None:
    report = report_for(RISKY)
    rendered = json.dumps(report, ensure_ascii=False)
    require(report["project"]["path"] == "<project-root>", "report exposes the absolute project root")
    require(str(RISKY.resolve()) not in rendered, "report leaks the absolute audited-project path")
    require(str(SKILL_ROOT.resolve()) not in rendered, "report leaks the absolute skill installation path")
    require('"$SKILL_DIR/scripts/' in report["findings"][0]["command"], "finding command lacks a portable skill placeholder")
    require('"path/to/project-root"' in report["recheck_command"], "recheck command lacks a safe project placeholder")


def test_output_paths_cannot_mutate_project() -> None:
    with tempfile.TemporaryDirectory(prefix="app-store-review-output-safety-") as directory:
        project = Path(directory) / "project"
        shutil.copytree(COMPLIANT, project)
        attempts = [
            (["--output-dir", str(project / "reports")], project / "reports"),
            (["--json-output", str(project / "report.json")], project / "report.json"),
            (["--markdown-output", str(project / "report.md")], project / "report.md"),
        ]
        for arguments, forbidden_path in attempts:
            command = [
                sys.executable,
                str(SCRIPT_DIR / "run_audit.py"),
                str(project),
                *arguments,
                "--simulate-missing-tools",
                "--quiet",
            ]
            completed = subprocess.run(
                command,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=60,
            )
            require(completed.returncode == 3, f"unsafe output path returned {completed.returncode}")
            require("must be outside the audited project" in completed.stderr, "unsafe output rejection is unclear")
            require(not forbidden_path.exists(), "audit wrote output inside the audited project")


def test_missing_tool_handling() -> None:
    result = scan_build_configuration.scan(context(COMPLIANT, missing_tools=True))
    validate_scanner_result(result, root=COMPLIANT, expected_name="scan_build_configuration")
    tool = result["tools"].get("xcodebuild") or {}
    require(tool.get("available") is False, "simulated missing xcodebuild was not recorded")
    current_xcode = next((item for item in result["checks"] if item["id"] == "build.current-xcode"), None)
    require(current_xcode is not None and current_xcode["status"] == "Not verified", "missing tool did not yield Not verified")
    report = report_for(COMPLIANT)
    require(not report["summary"]["scanner_errors"], "missing optional tool became a scanner error")


def test_path_with_spaces_and_unicode() -> None:
    with tempfile.TemporaryDirectory(prefix="app-store-review-path-test-") as directory:
        copied = Path(directory) / "Fixture с пробелами 🚀"
        shutil.copytree(COMPLIANT, copied)
        report, markdown = run_cli(copied, Path(directory) / "Отчёты с пробелами")
        require(report["project"]["path"] == "<project-root>", "Unicode/spaced project path was not sanitized")
        require(report["project"]["name"] == copied.name, "Unicode/spaced project name was altered")
        require(report["project"]["ios_target_detected"] is True, "scanner failed in Unicode/spaced path")
        require("App Store Review Audit" in markdown, "Markdown failed in Unicode/spaced path")


def test_scanner_failure_isolation() -> None:
    victim = run_audit.FULL_SCANNERS[2]
    original = victim.scan

    def fail_for_test(_context: ScanContext) -> dict[str, Any]:
        raise RuntimeError("intentional self-test scanner failure")

    victim.scan = fail_for_test
    try:
        report = run_audit.build_report(context(COMPLIANT), profile="full")
    finally:
        victim.scan = original
    require(victim.__name__ in report["summary"]["scanner_errors"], "scanner error was not recorded")
    require(len(report["scanner_results"]) == len(run_audit.FULL_SCANNERS), "scanner failure stopped the audit")
    failed = next(item for item in report["scanner_results"] if item["scanner"] == victim.__name__)
    require(failed["status"] == "error", "failed scanner status is not error")
    require(any(item["status"] == "Not verified" for item in failed["checks"]), "failed area was not marked Not verified")
    rendered = markdown_report(report)
    require(victim.__name__ in rendered, "Markdown omitted the failed scanner name")
    require("Readiness reason:" in rendered, "Markdown omitted readiness reasons")


def test_recheck_comparison() -> None:
    baseline = report_for(RISKY)
    recheck = report_for(RISKY, baseline=baseline)
    require(recheck["mode"] == "recheck", "baseline did not switch report mode to recheck")
    require(recheck["recheck"] is not None, "recheck comparison is missing")
    require(not recheck["recheck"]["new"] and not recheck["recheck"]["resolved"], "unchanged fixture produced new/resolved findings")
    require(len(recheck["recheck"]["persisting"]) == len(baseline["findings"]), "persisting findings count is wrong")


def test_recheck_scanner_failure_is_not_resolution() -> None:
    baseline = report_for(RISKY)
    victim = run_audit.scan_plist
    affected = {
        item["id"] for item in baseline["findings"] if item.get("scanner") == victim.__name__
    }
    require(affected, "recheck failure test has no baseline findings from scan_plist")
    original = victim.scan

    def fail_for_recheck(_context: ScanContext) -> dict[str, Any]:
        raise RuntimeError("intentional recheck scanner failure")

    victim.scan = fail_for_recheck
    try:
        recheck = run_audit.build_report(context(RISKY), profile="full", baseline=baseline)
    finally:
        victim.scan = original
    comparison = recheck.get("recheck") or {}
    unresolved = set(comparison.get("could_not_reverify", []))
    resolved = set(comparison.get("resolved", []))
    require(affected <= unresolved, "findings from a failed scanner were not marked could_not_reverify")
    require(not (affected & resolved), "findings from a failed scanner were incorrectly marked resolved")


def test_finding_identity_commands_and_redaction() -> None:
    def finding_at(line: int, excerpt: str) -> dict[str, Any]:
        return make_finding(
            base_id="SELFTEST-STABLE",
            severity="Medium",
            confidence="Medium",
            verification="Possible",
            area="Audit tooling",
            title="Stable finding",
            problem="Synthetic finding used to verify identity semantics.",
            evidence_items=[
                evidence(kind="self-test", value="stable", file="App/Test.swift", line=line, excerpt=excerpt)
            ],
            file="App/Test.swift",
            line=line,
            source_id="ARG-2.1",
            risk_reason="Self-test only.",
            remediation="Self-test only.",
            verification_steps=["Run the self-test."],
            limitations=["Synthetic evidence."],
            heuristic=True,
            id_detail="semantic-identity",
        )

    result = new_result("scan_selftest")
    result["findings"] = [finding_at(40, "first"), finding_at(8, "second")]
    merged = finish_result(result)
    require(len(merged["findings"]) == 1, "identical semantic findings were not merged")
    combined = merged["findings"][0]
    require(combined["line"] == 8 and len(combined["evidence"]) == 2, "merged finding lost evidence or earliest line")
    shifted = new_result("scan_selftest")
    shifted["findings"] = [finding_at(900, "after unrelated line shift")]
    shifted_finding = finish_result(shifted)["findings"][0]
    require(combined["id"] == shifted_finding["id"], "finding ID changed after an unrelated line shift")
    expected_script = '"$SKILL_DIR/scripts/scan_selftest.py"'
    require(expected_script in combined["command"], "default confirmation command lacks a portable skill placeholder")
    require("path/to/project-root" in combined["command"], "default confirmation command lacks a safe project placeholder")

    secrets = [
        ("myClientSecret = \"redaction-test-only\"", "redaction-test-only"),
        ("request.setValue(\"Bearer redaction-test-only\", forHTTPHeaderField: \"Authorization\")", "redaction-test-only"),
        ("Authorization: Bearer redaction-test-only", "redaction-test-only"),
        ("https://cdn.example.org/file?X-Amz-Signature=redaction-test-only&part=1", "redaction-test-only"),
        ("person@redaction-test.example", "person@redaction-test.example"),
    ]
    for raw, forbidden in secrets:
        redacted = redact_text(raw)
        require(forbidden not in redacted, "credential or personal data leaked through evidence redaction")
        require("redacted" in redacted, "credential redaction marker is missing")


def test_source_registry_integrity() -> None:
    registry_path = SKILL_ROOT / "references" / "apple_source_registry.json"
    payload = json.loads(registry_path.read_text(encoding="utf-8"))
    sources = payload.get("sources")
    require(isinstance(sources, list) and len(sources) >= 40, "official source registry is unexpectedly small")
    ids = [item.get("id") for item in sources]
    require(all(ids) and len(ids) == len(set(ids)), "source registry IDs are empty or duplicated")
    human_registry = (SKILL_ROOT / "references" / "apple_source_registry.md").read_text(encoding="utf-8")
    for item in sources:
        required = {"id", "title", "section", "url", "last_checked", "summary", "applicability", "status"}
        require(not (required - item.keys()), f"source {item.get('id')} is incomplete")
        parsed = urlsplit(item["url"])
        require(parsed.scheme == "https" and (parsed.hostname or "").endswith("apple.com"), f"source {item['id']} is not an official Apple URL")
        checked = date.fromisoformat(item["last_checked"])
        require(checked <= date.today(), f"source {item['id']} has a future verification date")
        require(str(item["status"]).startswith("official"), f"source {item['id']} is not marked official")
        require(f"| {item['id']} |" in human_registry, f"source {item['id']} is missing from the human registry mirror")


def test_app_store_connect_evidence_scope() -> None:
    compliant_result = run_audit.scan_app_store_connect.scan(context(COMPLIANT))
    compliant_rules = {item["rule_id"] for item in compliant_result["findings"]}
    require("ASC-EVIDENCE-SCOPE-INCOMPLETE" not in compliant_rules, "compliant metadata evidence lost its scope fields")
    scope_check = next(item for item in compliant_result["checks"] if item["id"] == "asc.evidence-scope")
    require(scope_check["status"] == "Passed", "complete metadata evidence scope did not pass")

    with tempfile.TemporaryDirectory(prefix="app-store-review-asc-") as directory:
        root = Path(directory)
        payload = {
            "name": "Scope Probe",
            "description": "Metadata evidence scope test.",
            "support_url": "https://support.apple.com/apps",
            "privacy_policy_url": "https://www.apple.com/legal/privacy/",
            "screenshots": ["iphone.png"],
            "age_rating": "4+",
            "review_contact": {"email": "review@example.invalid"},
            "app_privacy": {"tracking": False},
        }
        (root / "app_store_connect.json").write_text(json.dumps(payload), encoding="utf-8")
        result = run_audit.scan_app_store_connect.scan(context(root))
        rules = {item["rule_id"] for item in result["findings"]}
        require("ASC-EVIDENCE-SCOPE-INCOMPLETE" in rules, "omitted App Store Connect audit scope was treated as verified")
        require("ASC-REVIEW-CONTACT-INCOMPLETE" in rules, "incomplete review contact was not detected")
        scope = next(item for item in result["checks"] if item["id"] == "asc.evidence-scope")
        require(scope["status"] == "Not verified", "incomplete App Store Connect evidence scope did not remain Not verified")


def test_comment_filtering_and_feature_boundaries() -> None:
    with tempfile.TemporaryDirectory(prefix="app-store-review-boundaries-") as directory:
        root = Path(directory)
        source = root / "App" / "BoundaryProbe.swift"
        source.parent.mkdir(parents=True)
        source.write_text(
            """import PhotosUI
import StoreKit
import UIKit

struct BoundaryProbe {
    let title = \"Gemini\"
    let profileHeading = \"User profile\"
    let deviceAction = \"Register device\"
    let restoreLabel = \"Restore Purchases\"
    let picker = PhotosPicker(selection: .constant(nil), matching: .images)

    func registerPush() {
        UIApplication.shared.registerForRemoteNotifications()
    }

    func registerDevice() {}
    func authenticateUser() {}

    func buy(_ product: Product) async throws {
        _ = try await product.purchase()
        for await entitlement in Transaction.currentEntitlements { _ = entitlement }
    }
}

// privacy policy: https://example.com/privacy
// api.openai.com and UserDefaults are documentation-only examples.
// func restorePurchases() { AppStore.sync() }
""",
            encoding="utf-8",
        )
        account = run_audit.scan_account_features.scan(context(root))
        permissions = run_audit.scan_permissions.scan(context(root))
        storekit = run_audit.scan_storekit.scan(context(root))
        ai = run_audit.scan_ai_integrations.scan(context(root))
        ugc = run_audit.scan_user_content_features.scan(context(root))
        urls = run_audit.scan_urls.scan(context(root))
        privacy = run_audit.scan_privacy_manifest.scan(context(root))

        require("ACCOUNT-DELETION-NOT-DETECTED" not in {item["rule_id"] for item in account["findings"]}, "push registration was mistaken for account creation")
        require("PERMISSION-USAGE-DESCRIPTION-NOT-DETECTED" not in {item["rule_id"] for item in permissions["findings"]}, "PhotosPicker was mistaken for direct photo-library access")
        require("RESTORE-PURCHASE-NOT-DETECTED" in {item["rule_id"] for item in storekit["findings"]}, "UI copy or currentEntitlements incorrectly proved purchase restoration")
        require(not ai["findings"], "ordinary Gemini display copy was mistaken for an AI integration")
        require(not ugc["findings"], "ordinary profile display copy was mistaken for UGC")
        require(not urls["findings"], "comment-only example URL became a release URL finding")
        require("REQUIRED-REASON-API-NOT-DECLARED" not in {item["rule_id"] for item in privacy["findings"]}, "comment-only required-reason API text became a finding")


def test_comments_do_not_supply_missing_controls() -> None:
    with tempfile.TemporaryDirectory(prefix="app-store-review-comment-controls-") as directory:
        root = Path(directory)
        source = root / "App" / "RiskProbe.swift"
        source.parent.mkdir(parents=True)
        source.write_text(
            """import Foundation

struct AIClient {
    let endpoint = URL(string: \"https://api.openai.com/v1/responses\")!
    func send(userPrompt: String, email: String) throws {
        var request = URLRequest(url: endpoint)
        request.httpBody = try JSONEncoder().encode([\"input\": userPrompt, \"email\": email])
    }
}

func createPost() {}
// consentToAI = true; reportContent(); blockUser(); contentFilter(); support@example.com
""",
            encoding="utf-8",
        )
        ai = run_audit.scan_ai_integrations.scan(context(root))
        ugc = run_audit.scan_user_content_features.scan(context(root))
        require("AI-CONSENT-NOT-DETECTED" in {item["rule_id"] for item in ai["findings"]}, "comment-only AI consent suppressed a real lead")
        require("UGC-SAFETY-CONTROLS-NOT-DETECTED" in {item["rule_id"] for item in ugc["findings"]}, "comment-only UGC controls suppressed a real lead")


def test_privacy_manifest_schema_and_bundle_scope() -> None:
    with tempfile.TemporaryDirectory(prefix="app-store-review-privacy-schema-") as directory:
        root = Path(directory)
        manifest = root / "App" / "PrivacyInfo.xcprivacy"
        manifest.parent.mkdir(parents=True)
        with manifest.open("wb") as handle:
            plistlib.dump(
                {
                    "NSPrivacyTracking": "false",
                    "NSPrivacyCollectedDataTypes": ["not-a-dictionary"],
                    "NSPrivacyAccessedAPITypes": [
                        {"NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategoryUserDefaults", "NSPrivacyAccessedAPITypeReasons": []}
                    ],
                },
                handle,
            )
        result = run_audit.scan_privacy_manifest.scan(context(root))
        require("PRIVACY-MANIFEST-SCHEMA-INVALID" in {item["rule_id"] for item in result["findings"]}, "malformed nested privacy manifest was accepted")
        validity = next(item for item in result["checks"] if item["id"] == "privacy.manifest-validity")
        require(validity["status"] == "Failed", "invalid privacy-manifest schema did not fail its compliance check")

    with tempfile.TemporaryDirectory(prefix="app-store-review-privacy-scope-") as directory:
        root = Path(directory)
        app_source = root / "App" / "App.swift"
        app_source.parent.mkdir(parents=True)
        app_source.write_text("let defaults = UserDefaults.standard\n", encoding="utf-8")
        widget_manifest = root / "Widget" / "PrivacyInfo.xcprivacy"
        widget_manifest.parent.mkdir(parents=True)
        with widget_manifest.open("wb") as handle:
            plistlib.dump(
                {
                    "NSPrivacyTracking": False,
                    "NSPrivacyTrackingDomains": [],
                    "NSPrivacyCollectedDataTypes": [],
                    "NSPrivacyAccessedAPITypes": [
                        {
                            "NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategoryUserDefaults",
                            "NSPrivacyAccessedAPITypeReasons": ["CA92.1"],
                        }
                    ],
                },
                handle,
            )
        result = run_audit.scan_privacy_manifest.scan(context(root))
        require("REQUIRED-REASON-API-NOT-DECLARED" in {item["rule_id"] for item in result["findings"]}, "an extension manifest incorrectly satisfied the app bundle")

        widget_manifest.unlink()
        app_source.write_text("let ordinaryValue = 1\n", encoding="utf-8")
        widget_source = root / "Widget" / "Widget.swift"
        widget_source.write_text("let defaults = UserDefaults.standard\n", encoding="utf-8")
        root_manifest = root / "PrivacyInfo.xcprivacy"
        with root_manifest.open("wb") as handle:
            plistlib.dump(
                {
                    "NSPrivacyTracking": False,
                    "NSPrivacyTrackingDomains": [],
                    "NSPrivacyCollectedDataTypes": [],
                    "NSPrivacyAccessedAPITypes": [
                        {
                            "NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategoryUserDefaults",
                            "NSPrivacyAccessedAPITypeReasons": ["CA92.1"],
                        }
                    ],
                },
                handle,
            )
        reverse = run_audit.scan_privacy_manifest.scan(context(root))
        require("REQUIRED-REASON-API-NOT-DECLARED" in {item["rule_id"] for item in reverse["findings"]}, "a root app manifest incorrectly satisfied an obvious extension bundle")


def test_localization_parsing_and_catalog_coverage() -> None:
    with tempfile.TemporaryDirectory(prefix="app-store-review-localization-") as directory:
        root = Path(directory)
        catalog = root / "Localizable.xcstrings"
        catalog.write_text(
            json.dumps(
                {
                    "sourceLanguage": "en",
                    "strings": {
                        "complete": {"localizations": {"en": {}, "ru": {}}},
                        "missing_ru": {"localizations": {"en": {}}},
                    },
                    "version": "1.0",
                }
            ),
            encoding="utf-8",
        )
        malformed = root / "ru.lproj" / "Broken.strings"
        malformed.parent.mkdir(parents=True)
        malformed.write_text('"ok" = "Да";\nthis is malformed\n', encoding="utf-8")
        result = run_audit.scan_localizations.scan(context(root))
        rules = {item["rule_id"] for item in result["findings"]}
        require("LOCALIZATION-CATALOG-COVERAGE" in rules, "String Catalog locale gap was not detected")
        require("LOCALIZATION-PARSE-ERROR" in rules, "malformed .strings content was accepted")
        key_check = next(item for item in result["checks"] if item["id"] == "localization.key-parity")
        require(key_check["status"] == "Failed", "localization errors did not fail the key-parity check")


def test_swift_operator_and_placeholder_boundaries() -> None:
    with tempfile.TemporaryDirectory(prefix="app-store-review-swift-lexer-") as directory:
        root = Path(directory)
        source = root / "App" / "Probe.swift"
        source.parent.mkdir(parents=True)
        source.write_text(
            """import UIKit

final class Probe: UIViewController {
    let example = \"value! as! try! optionalNumber()!\"
    // value! as! try! dictionary[\"comment\"]!
    @IBOutlet private weak var titleLabel: UILabel!

    func run(_ value: Any, dictionary: [String: Int]) throws {
        _ = optionalNumber()!
        _ = dictionary[\"answer\"]!
        _ = value as! String
        _ = try! throwingValue()
        _ = Text(verbatim: \"TODO: replace this release copy\")
    }
}
""",
            encoding="utf-8",
        )
        localized = root / "ru.lproj" / "Localizable.strings"
        localized.parent.mkdir(parents=True)
        localized.write_text('"soon" = "Coming soon";\n', encoding="utf-8")
        result = run_audit.scan_placeholders.scan(context(root))
        rules = [item["rule_id"] for item in result["findings"]]
        require(rules.count("SWIFT-FORCE-UNWRAP") == 2, "real call/subscript unwraps were missed or lexical examples created false positives")
        require(rules.count("SWIFT-FORCED-CAST") == 1, "forced cast detection did not isolate executable code")
        require(rules.count("SWIFT-TRY-FORCE") == 1, "try! detection did not isolate executable code")
        require(rules.count("PLACEHOLDER-USER-VISIBLE") == 2, "SwiftUI/localized placeholder coverage is incomplete")
        evidence_lines = {
            proof.get("line")
            for item in result["findings"]
            if item["rule_id"].startswith("SWIFT-")
            for proof in item["evidence"]
        }
        require(not ({4, 5, 6} & evidence_lines), "string/comment/IBOutlet syntax produced a Swift operator finding")
        ids = [item["id"] for item in result["findings"]]
        require(len(ids) == len(set(ids)), "standalone Swift scanner result contains duplicate IDs")


def test_custom_release_and_xcconfig_resolution() -> None:
    with tempfile.TemporaryDirectory(prefix="app-store-review-build-config-") as directory:
        root = Path(directory)
        project = root / "App.xcodeproj" / "project.pbxproj"
        project.parent.mkdir(parents=True)
        scheme = root / "App.xcodeproj" / "xcshareddata" / "xcschemes" / "App.xcscheme"
        scheme.parent.mkdir(parents=True)
        scheme.write_text('<Scheme><ArchiveAction buildConfiguration="Release-Prod"/></Scheme>', encoding="utf-8")
        config = root / "Config"
        config.mkdir()
        (config / "Common.xcconfig").write_text("SWIFT_ACTIVE_COMPILATION_CONDITIONS = DEBUG\n", encoding="utf-8")
        (config / "Release.xcconfig").write_text('#include "Common.xcconfig"\nSWIFT_ACTIVE_COMPILATION_CONDITIONS = RELEASE\n', encoding="utf-8")

        def pbx(extra_release: str = "") -> str:
            return f"""// !$*UTF8*$!
AA = {{ isa = PBXFileReference; path = Config/Release.xcconfig; sourceTree = \"<group>\"; }};
DD = {{ isa = XCBuildConfiguration; buildSettings = {{ SWIFT_ACTIVE_COMPILATION_CONDITIONS = DEBUG; }}; name = Debug-Dev; }};
{extra_release}
RR = {{ isa = XCBuildConfiguration; baseConfigurationReference = AA /* Release.xcconfig */; buildSettings = {{ SWIFT_ACTIVE_COMPILATION_CONDITIONS = \"$(inherited) RELEASE\"; }}; name = Release-Prod; }};
"""

        project.write_text(pbx(), encoding="utf-8")
        safe = run_audit.scan_build_configuration.scan(context(root))
        safe_rules = {item["rule_id"] for item in safe["findings"]}
        require("BUILD-CONFIGURATION-MISSING" not in safe_rules, "custom Archive Release configuration was rejected")
        require("RELEASE-DEBUG-FLAG" not in safe_rules, "a parent xcconfig override did not clear included DEBUG")
        require(safe["facts"]["archive_configurations"] == ["Release-Prod"], "ArchiveAction configuration was not resolved")

        (config / "Release.xcconfig").write_text('#include "Common.xcconfig"\nSWIFT_ACTIVE_COMPILATION_CONDITIONS = $(inherited) RELEASE\n', encoding="utf-8")
        inherited = run_audit.scan_build_configuration.scan(context(root))
        require("RELEASE-DEBUG-FLAG" in {item["rule_id"] for item in inherited["findings"]}, "inherited DEBUG in Release xcconfig was missed")

        (config / "Release.xcconfig").write_text('#include "Common.xcconfig"\nSWIFT_ACTIVE_COMPILATION_CONDITIONS = RELEASE\n', encoding="utf-8")
        beta = "BB = { isa = XCBuildConfiguration; buildSettings = { SWIFT_ACTIVE_COMPILATION_CONDITIONS = DEBUG; }; name = Release-Beta; };"
        project.write_text(pbx(beta), encoding="utf-8")
        multiple = run_audit.scan_build_configuration.scan(context(root))
        require("RELEASE-DEBUG-FLAG" in {item["rule_id"] for item in multiple["findings"]}, "DEBUG in one of multiple shipping configurations was overwritten by another configuration")


def test_dependency_manifests_and_resolved_versions() -> None:
    with tempfile.TemporaryDirectory(prefix="app-store-review-dependencies-") as directory:
        root = Path(directory)
        (root / "Podfile.lock").write_text("PODS:\n  - GoogleSignIn (8.0.0)\n", encoding="utf-8")
        write_plist(
            root / "PrivacyInfo.xcprivacy",
            {
                "NSPrivacyTracking": False,
                "NSPrivacyTrackingDomains": [],
                "NSPrivacyCollectedDataTypes": [],
                "NSPrivacyAccessedAPITypes": [],
            },
        )
        app_only = run_audit.scan_dependencies.scan(context(root))
        require("PRIVACY-MANIFEST-SDK-NOT-DETECTED" in {item["rule_id"] for item in app_only["findings"]}, "app manifest incorrectly satisfied a listed SDK")
        require("8.0.0" in app_only["facts"]["dependency_versions"].get("GoogleSignIn", []), "CocoaPods resolved version was not inventoried")

        write_plist(
            root / "ios" / "Pods" / "GoogleSignIn" / "PrivacyInfo.xcprivacy",
            {
                "NSPrivacyTracking": False,
                "NSPrivacyTrackingDomains": [],
                "NSPrivacyCollectedDataTypes": [],
                "NSPrivacyAccessedAPITypes": [],
            },
        )
        resolved = run_audit.scan_dependencies.scan(context(root))
        require("PRIVACY-MANIFEST-SDK-NOT-DETECTED" not in {item["rule_id"] for item in resolved["findings"]}, "resolved ios/Pods SDK manifest was ignored")
        require(resolved["facts"]["privacy_manifests_by_listed_sdk"].get("GoogleSignIn"), "SDK manifest was not mapped to its dependency")

        (root / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {},
                        "node_modules/react-native": {"version": "0.80.1"},
                        "node_modules/@capacitor/ios": {"version": "7.4.0"},
                    },
                }
            ),
            encoding="utf-8",
        )
        npm = run_audit.scan_dependencies.scan(context(root))
        require("0.80.1" in npm["facts"]["dependency_versions"].get("react-native", []), "npm lock resolved version was not inventoried")
        require("7.4.0" in npm["facts"]["dependency_versions"].get("@capacitor/ios", []), "scoped npm package version was not inventoried")


def test_platform_detection_matrix() -> None:
    with tempfile.TemporaryDirectory(prefix="app-store-review-platforms-") as directory:
        root = Path(directory)
        package = root / "Package.swift"
        package.write_text('// swift-tools-version: 6.0\nlet package = Package(name: "MacOnly", platforms: [.macOS(.v14)])\n', encoding="utf-8")
        mac_only = run_audit.scan_project.scan(context(root))
        require(mac_only["facts"]["ios_target_detected"] is False, "macOS-only Swift package was mistaken for iOS")
        package.write_text('// swift-tools-version: 6.0\nlet package = Package(name: "Mobile", platforms: [.iOS(.v17)])\n', encoding="utf-8")
        ios_package = run_audit.scan_project.scan(context(root))
        require(ios_package["facts"]["ios_target_detected"] is True, "iOS Swift package was not detected")

    cases = [
        ("React Native", {"package.json": json.dumps({"dependencies": {"react-native": "0.80.1"}})}),
        ("Flutter", {"pubspec.yaml": "name: mobile\ndependencies:\n  flutter:\n    sdk: flutter\n"}),
        ("Capacitor", {"package.json": json.dumps({"dependencies": {"@capacitor/ios": "7.4.0"}})}),
        ("Expo native iOS", {"package.json": json.dumps({"dependencies": {"expo": "54.0.0"}})}),
    ]
    for expected_stack, files in cases:
        with tempfile.TemporaryDirectory(prefix="app-store-review-stack-") as directory:
            root = Path(directory)
            (root / "ios").mkdir()
            for name, content in files.items():
                (root / name).write_text(content, encoding="utf-8")
            result = run_audit.scan_project.scan(context(root))
            require(expected_stack in result["facts"]["stacks"], f"{expected_stack} stack was not detected")
            require(result["facts"]["ios_target_detected"] is True, f"{expected_stack} native iOS target was not detected")


def test_account_capability_is_not_login_route() -> None:
    with tempfile.TemporaryDirectory(prefix="app-store-review-account-route-") as directory:
        root = Path(directory)
        source = root / "App" / "Login.swift"
        source.parent.mkdir(parents=True)
        source.write_text("import GoogleSignIn\nlet provider = GIDSignIn.sharedInstance\n", encoding="utf-8")
        write_plist(
            root / "App" / "App.entitlements",
            {"com.apple.developer.applesignin": ["Default"]},
        )
        capability_only = run_audit.scan_account_features.scan(context(root))
        require("SOCIAL-LOGIN-EQUIVALENT-NOT-DETECTED" in {item["rule_id"] for item in capability_only["findings"]}, "Sign in with Apple entitlement was mistaken for a usable login route")
        require(capability_only["facts"]["sign_in_with_apple_capability_without_route"] is True, "capability-without-route fact was not recorded")

        source.write_text("import GoogleSignIn\nimport AuthenticationServices\nlet provider = GIDSignIn.sharedInstance\nlet button = SignInWithAppleButton(.continue) { _ in } onCompletion: { _ in }\n", encoding="utf-8")
        implemented = run_audit.scan_account_features.scan(context(root))
        require("SOCIAL-LOGIN-EQUIVALENT-NOT-DETECTED" not in {item["rule_id"] for item in implemented["findings"]}, "recognizable Sign in with Apple route did not satisfy the static login lead")


def test_permission_bundle_and_framework_scopes() -> None:
    with tempfile.TemporaryDirectory(prefix="app-store-review-permission-targets-") as directory:
        root = Path(directory)
        write_plist(root / "AppA" / "Info.plist", {"NSCameraUsageDescription": "Scan documents selected by the user."})
        source = root / "AppB" / "Camera.swift"
        source.parent.mkdir(parents=True)
        source.write_text("let camera = AVCaptureDevice.default(for: .video)\n", encoding="utf-8")
        result = run_audit.scan_permissions.scan(context(root))
        require("PERMISSION-USAGE-DESCRIPTION-NOT-DETECTED" in {item["rule_id"] for item in result["findings"]}, "one app target's purpose string satisfied another app target")

    with tempfile.TemporaryDirectory(prefix="app-store-review-flutter-permissions-") as directory:
        root = Path(directory)
        source = root / "lib" / "location.dart"
        source.parent.mkdir(parents=True)
        source.write_text("final position = geolocator;\n", encoding="utf-8")
        write_plist(root / "ios" / "Runner" / "Info.plist", {"NSLocationWhenInUseUsageDescription": "Show nearby saved places while this feature is open."})
        result = run_audit.scan_permissions.scan(context(root))
        missing = [item for item in result["findings"] if item["rule_id"] == "PERMISSION-USAGE-DESCRIPTION-NOT-DETECTED"]
        require(not missing, "Flutter lib source and ios/Runner purpose string were treated as different app bundles")

    with tempfile.TemporaryDirectory(prefix="app-store-review-rn-permissions-") as directory:
        root = Path(directory)
        source = root / "src" / "location.ts"
        source.parent.mkdir(parents=True)
        source.write_text("const locationProvider = 'expo-location';\n", encoding="utf-8")
        write_plist(root / "ios" / "Mobile" / "Info.plist", {"NSLocationWhenInUseUsageDescription": "Show nearby saved places while this feature is open."})
        result = run_audit.scan_permissions.scan(context(root))
        missing = [item for item in result["findings"] if item["rule_id"] == "PERMISSION-USAGE-DESCRIPTION-NOT-DETECTED"]
        require(not missing, "React Native source and native iOS purpose string were treated as different app bundles")


def test_xcconfig_url_detection_and_calibration() -> None:
    with tempfile.TemporaryDirectory(prefix="app-store-review-xcconfig-url-") as directory:
        root = Path(directory)
        config = root / "Config" / "Release.xcconfig"
        config.parent.mkdir(parents=True)
        config.write_text("// https://example.com/comment-only\nAPI_BASE_URL = https://staging.acme.invalid/v1\n", encoding="utf-8")
        result = run_audit.scan_urls.scan(context(root))
        findings = [item for item in result["findings"] if item["rule_id"] == "URL-TEST-ENDPOINT"]
        require(len(findings) == 1, "xcconfig test endpoint was missed or comment URL became a finding")
        require(findings[0]["verification"] == "Likely", "source-only URL literal was overstated as Verified release reachability")


def test_material_findings_fail_a_compliance_check() -> None:
    for result in scan_everything(RISKY):
        material = [
            item for item in result["findings"]
            if item.get("severity") in {"Critical", "High", "Medium"}
        ]
        if not material:
            continue
        require(
            any(item.get("status") == "Failed" for item in result["checks"]),
            f"{result['scanner']} emitted material findings while no compliance check failed",
        )


def test_absolute_cli_from_unrelated_working_directory() -> None:
    with tempfile.TemporaryDirectory(prefix="app-store-review-cwd-") as directory:
        temp = Path(directory)
        output = temp / "output"
        command = [
            sys.executable,
            str(SCRIPT_DIR / "run_audit.py"),
            str(COMPLIANT),
            "--output-dir",
            str(output),
            "--simulate-missing-tools",
            "--quiet",
        ]
        completed = subprocess.run(command, cwd=temp, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=60)
        require(completed.returncode == 0, f"absolute skill command failed outside the skill directory: {completed.stderr}")
        require((output / "app-store-review-report.json").is_file(), "cross-project CLI did not create a JSON report")
        help_result = subprocess.run(
            [sys.executable, str(SCRIPT_DIR / "run_audit.py"), "--help"],
            cwd=temp,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        require(help_result.returncode == 0 and "--deep" not in help_result.stdout, "unused --deep option is still advertised")


def test_standalone_scanner_json_cli() -> None:
    command = [
        sys.executable,
        str(SCRIPT_DIR / "scan_plist.py"),
        str(RISKY),
        "--format",
        "json",
        "--simulate-missing-tools",
    ]
    completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=30)
    require(completed.returncode == 0, f"standalone scanner failed: {completed.stderr}")
    payload = json.loads(completed.stdout)
    validate_scanner_result(payload, root=RISKY, expected_name="scan_plist")
    require(any(item["rule_id"] == "PERMISSION-PURPOSE-EMPTY" for item in payload["findings"]), "standalone scanner lost expected finding")


def main() -> int:
    before = {COMPLIANT.name: fixture_snapshot(COMPLIANT), RISKY.name: fixture_snapshot(RISKY)}
    tests: list[tuple[str, Callable[[], None]]] = [
        ("fixture contract", test_fixture_contract),
        ("all scanners and structured result schemas", test_all_scanners_and_result_schemas),
        ("intentional risky findings", test_intentional_risky_findings),
        ("no static findings in compliant fixture", test_compliant_has_no_static_findings),
        ("compliant Xcode project is readable", test_compliant_xcode_project_is_readable),
        ("JSON and Markdown report generation", test_cli_json_and_markdown_reports),
        ("share-safe report paths", test_report_paths_are_share_safe),
        ("output paths cannot mutate audited project", test_output_paths_cannot_mutate_project),
        ("missing tool handling", test_missing_tool_handling),
        ("paths with spaces and Unicode", test_path_with_spaces_and_unicode),
        ("scanner failure isolation", test_scanner_failure_isolation),
        ("recheck comparison", test_recheck_comparison),
        ("recheck scanner failure is not resolution", test_recheck_scanner_failure_is_not_resolution),
        ("stable finding identity, commands, and secret redaction", test_finding_identity_commands_and_redaction),
        ("official source registry integrity", test_source_registry_integrity),
        ("App Store Connect evidence scope", test_app_store_connect_evidence_scope),
        ("comment filtering and feature boundaries", test_comment_filtering_and_feature_boundaries),
        ("comments do not supply missing controls", test_comments_do_not_supply_missing_controls),
        ("privacy-manifest schema and bundle scope", test_privacy_manifest_schema_and_bundle_scope),
        ("localization parsing and String Catalog coverage", test_localization_parsing_and_catalog_coverage),
        ("Swift operator and placeholder lexical boundaries", test_swift_operator_and_placeholder_boundaries),
        ("custom Release and xcconfig resolution", test_custom_release_and_xcconfig_resolution),
        ("dependency manifests and resolved versions", test_dependency_manifests_and_resolved_versions),
        ("platform detection matrix", test_platform_detection_matrix),
        ("account capability is not a login route", test_account_capability_is_not_login_route),
        ("permission bundle and framework scopes", test_permission_bundle_and_framework_scopes),
        ("xcconfig URL detection and calibration", test_xcconfig_url_detection_and_calibration),
        ("material findings fail a compliance check", test_material_findings_fail_a_compliance_check),
        ("absolute CLI from unrelated working directory", test_absolute_cli_from_unrelated_working_directory),
        ("standalone scanner JSON CLI", test_standalone_scanner_json_cli),
    ]
    failures: list[str] = []
    for name, test in tests:
        try:
            test()
        except BaseException as exc:
            failures.append(f"{name}: {type(exc).__name__}: {exc}")
            print(f"FAIL {name}: {type(exc).__name__}: {exc}")
        else:
            print(f"PASS {name}")
    after = {COMPLIANT.name: fixture_snapshot(COMPLIANT), RISKY.name: fixture_snapshot(RISKY)}
    if after != before:
        failures.append("fixture immutability: fixture content or metadata changed during self-tests")
        print("FAIL fixture immutability: fixture content or metadata changed during self-tests")
    else:
        print("PASS fixture immutability")
    if failures:
        print(f"\nSelf-tests failed: {len(failures)} mandatory check(s).", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"\nAll {len(tests) + 1} mandatory self-tests passed across {len(run_audit.FULL_SCANNERS)} scanners.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
