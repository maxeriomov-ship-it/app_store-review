#!/usr/bin/env python3
"""Run a read-only, evidence-backed App Store pre-submission audit."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from pathlib import Path
from typing import Any

from audit_core import (
    ScanContext,
    coverage_metrics,
    deduplicate_findings,
    evidence_completeness,
    failed_result,
    load_source_registry,
    make_output_dir,
    markdown_report,
    readiness_status,
    redact_structure,
    risk_index,
    source_freshness,
    summarize_counts,
    utc_now,
    validate_report_schema,
)
import scan_account_features
import scan_ai_integrations
import scan_app_store_connect
import scan_build_configuration
import scan_dependencies
import scan_entitlements
import scan_localizations
import scan_permissions
import scan_placeholders
import scan_plist
import scan_privacy_manifest
import scan_project
import scan_storekit
import scan_urls
import scan_user_content_features


FULL_SCANNERS = [
    scan_project,
    scan_build_configuration,
    scan_plist,
    scan_entitlements,
    scan_privacy_manifest,
    scan_permissions,
    scan_dependencies,
    scan_storekit,
    scan_localizations,
    scan_placeholders,
    scan_urls,
    scan_account_features,
    scan_ai_integrations,
    scan_user_content_features,
    scan_app_store_connect,
]

BLOCKER_SCANNERS = [
    scan_project,
    scan_build_configuration,
    scan_plist,
    scan_privacy_manifest,
    scan_permissions,
    scan_dependencies,
    scan_storekit,
    scan_placeholders,
    scan_urls,
    scan_account_features,
    scan_ai_integrations,
    scan_user_content_features,
    scan_app_store_connect,
]

LIMITATIONS = [
    "Static analysis does not replace hands-on testing on a physical device.",
    "A simulator does not replace a physical device for permissions, hardware, StoreKit, performance, and real-network behavior.",
    "Without current App Store Connect evidence, metadata, privacy answers, age rating, product status, screenshots, agreements, and review information cannot be completed.",
    "Without StoreKit Sandbox testing, purchase, restore, reinstall, device-change, cancellation, and payment-failure behavior cannot be confirmed.",
    "Without live access, Apple source currency and URL availability cannot be confirmed at audit time; living sources must be rechecked.",
    "Passing this audit does not guarantee Apple approval.",
    "Some Apple rules are contextual or subjective and require expert interpretation.",
    "High-risk legal documents and regulatory classifications require qualified legal review.",
]


def _load_baseline(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict) or not isinstance(value.get("findings"), list):
        raise ValueError("baseline is not an App Store review report")
    return value


def _recheck_comparison(
    baseline: dict[str, Any] | None,
    findings: list[dict[str, Any]],
    scanner_results: list[dict[str, Any]],
) -> dict[str, list[str]] | None:
    if baseline is None:
        return None
    previous_findings = {
        item.get("id"): item
        for item in baseline.get("findings", [])
        if item.get("id")
    }
    previous = set(previous_findings)
    current = {item.get("id") for item in findings if item.get("id")}
    failed_scanners = {
        item.get("scanner")
        for item in scanner_results
        if item.get("status") == "error" and item.get("scanner")
    }
    disappeared = previous - current
    could_not_reverify = {
        finding_id
        for finding_id in disappeared
        if previous_findings[finding_id].get("scanner") in failed_scanners
        or (not previous_findings[finding_id].get("scanner") and failed_scanners)
    }
    return {
        "resolved": sorted(disappeared - could_not_reverify),
        "persisting": sorted(previous & current),
        "new": sorted(current - previous),
        "could_not_reverify": sorted(could_not_reverify),
    }


def _source_list(
    findings: list[dict[str, Any]], checks: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    selected: dict[str, dict[str, Any]] = {}
    for finding in findings:
        source = finding.get("apple_source") or {}
        if source.get("id"):
            selected[source["id"]] = source
    registry = load_source_registry()
    for check_item in checks:
        source_id = check_item.get("source_id")
        if source_id and source_id in registry:
            selected[source_id] = registry[source_id]
    return [selected[key] for key in sorted(selected)]


def _finding_groups(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    return {
        "blocking_issues": [item for item in findings if item.get("severity") == "Critical"],
        "high_risks": [item for item in findings if item.get("severity") == "High"],
        "medium_risks": [item for item in findings if item.get("severity") == "Medium"],
        "low_risks": [item for item in findings if item.get("severity") == "Low"],
        "informational": [item for item in findings if item.get("severity") == "Informational"],
    }


def _review_notes(context: ScanContext, scanner_results: list[dict[str, Any]]) -> str:
    asc = next((item for item in scanner_results if item.get("scanner") == "scan_app_store_connect"), None)
    metadata_file = (asc or {}).get("facts", {}).get("metadata_file")
    if metadata_file:
        path = context.root / metadata_file
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            notes = payload.get("review_notes")
            if isinstance(notes, str) and notes.strip():
                return notes.strip()
        except (OSError, ValueError):
            pass
    return (
        "Draft — replace every bracketed item with verified facts before submission:\n\n"
        "Build and scope: [version/build and changes in this submission]\n"
        "Review route: [numbered taps from launch to each non-obvious or gated feature]\n"
        "Review access: [demo account or approved full demo mode; 2FA handling; do not invent credentials]\n"
        "Purchases: [where the paywall is, product tested, purchase/restore steps, Sandbox notes]\n"
        "Permissions/hardware: [when each permission appears and any required hardware or sample data]\n"
        "Backend/region: [live environment, supported region, feature flags, time-sensitive setup]\n"
        "Privacy/AI/UGC: [consent route, recipient disclosure, report/block/moderation route when applicable]"
    )


def build_report(
    context: ScanContext,
    *,
    profile: str = "full",
    baseline: dict[str, Any] | None = None,
) -> dict[str, Any]:
    modules = FULL_SCANNERS if profile == "full" else BLOCKER_SCANNERS
    scanner_results: list[dict[str, Any]] = []
    for module in modules:
        try:
            scanner_results.append(module.scan(context))
        except Exception as exc:  # Isolation: one scanner never stops the audit.
            scanner_results.append(failed_result(module.__name__, exc))
    findings = deduplicate_findings(
        finding
        for result in scanner_results
        for finding in result.get("findings", [])
    )
    checks = [check_item for result in scanner_results for check_item in result.get("checks", [])]
    coverage = coverage_metrics(checks)
    risk = risk_index(findings)
    readiness, readiness_reasons = readiness_status(findings, checks, risk, coverage["coverage"])
    if profile == "blockers" and readiness == "Ready":
        readiness = "Insufficient evidence"
        readiness_reasons.append("The blockers profile intentionally omits full-audit controls and cannot produce Ready.")
    comparison = _recheck_comparison(baseline, findings, scanner_results)
    source_list = _source_list(findings, checks)
    project_scan = next((item for item in scanner_results if item.get("scanner") == "scan_project"), {})
    command = (
        f"python3 {shlex.quote(str(Path(__file__).resolve()))} "
        f"{shlex.quote(str(context.root))} --profile full --baseline "
        f"{shlex.quote('path/to/previous-report.json')}"
    )
    counts = summarize_counts(findings)
    actionable = [item for item in findings if item.get("severity") != "Informational"]
    practical_recommendations = list(
        dict.fromkeys(item.get("remediation") for item in actionable if item.get("remediation"))
    )
    recommended_fix_order = [
        {
            "position": position,
            "finding_id": item.get("id"),
            "severity": item.get("severity"),
            "title": item.get("title"),
            "remediation": item.get("remediation"),
        }
        for position, item in enumerate(actionable, 1)
    ]
    report = {
        "schema_version": "1.0",
        "generated_at": utc_now(),
        "mode": "recheck" if baseline else "audit",
        "profile": profile,
        "project": {
            "name": context.root.name,
            "path": str(context.root),
            "technology": project_scan.get("facts", {}).get("stacks", []),
            "ios_target_detected": project_scan.get("facts", {}).get("ios_target_detected"),
        },
        "readiness": {"status": readiness, "reasons": readiness_reasons},
        "metrics": {
            "risk_index": risk,
            "risk_interpretation": "Internal weighted heuristic; not a statistical probability of App Store rejection.",
            "coverage": coverage["coverage"],
            "coverage_detail": coverage,
            "evidence_completeness": evidence_completeness(findings),
            "source_freshness": source_freshness(
                [{"apple_source": source} for source in source_list]
            ),
            "finding_counts": counts,
        },
        "summary": {
            "finding_count": len(findings),
            "scanner_count": len(scanner_results),
            "scanner_errors": [item["scanner"] for item in scanner_results if item.get("status") == "error"],
        },
        "findings": findings,
        "finding_groups": _finding_groups(findings),
        "practical_recommendations": practical_recommendations,
        "recommended_fix_order": recommended_fix_order,
        "checks": checks,
        "scanner_results": scanner_results,
        "unverified_areas": sorted(
            {item["area"] for item in checks if item.get("status") == "Not verified"}
        ),
        "manual_actions": [
            "Test the exact Release build on at least one supported physical iPhone and, when supported, iPad/Split View.",
            "Exercise clean install, upgrade, offline, slow-network, backend-failure, permission denial, dark mode, Dynamic Type, VoiceOver, keyboard, and orientation states.",
            "If purchases apply, run StoreKit Test and Sandbox success, cancel, pending, failure, restore, reinstall, device-change, refund/revocation, and subscription-management scenarios.",
            "Open every legal/support link and verify current content, contact details, retention/deletion statements, and third-party/AI disclosures.",
            "Record the exact review route and test non-expiring demo access with 2FA disabled or explicitly handled.",
        ],
        "app_store_connect_actions": [
            "Compare every metadata localization, screenshot, preview, Support URL, Privacy Policy URL, category, age-rating answer, and App Privacy answer with the release build.",
            "Verify build selection, export-compliance answers, agreements, contact details, review notes, demo access, and any required regional compliance fields.",
            "For each IAP/subscription, verify status, availability, localization, price/duration, review screenshot, review notes, and inclusion in the intended submission.",
            "Recheck Apple's Upcoming Requirements and App Store Connect release notes immediately before submission.",
        ],
        "app_review_notes": _review_notes(context, scanner_results),
        "recheck": comparison,
        "recheck_command": command,
        "sources_used": source_list,
        "limitations": LIMITATIONS,
    }
    return redact_structure(report)


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp-{os.getpid()}")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit an iOS-capable project before App Store submission.")
    parser.add_argument("project", type=Path, help="Project root")
    parser.add_argument("--profile", choices=("full", "blockers"), default="full")
    parser.add_argument("--baseline", type=Path, help="Prior JSON report for Recheck comparison")
    parser.add_argument("--asc-metadata", type=Path, help="App Store Connect evidence/export JSON")
    parser.add_argument("--network", action="store_true", help="Perform cautious live URL checks")
    parser.add_argument("--output-dir", type=Path, help="Report directory; defaults to a temporary directory")
    parser.add_argument("--json-output", type=Path, help="Explicit JSON report path")
    parser.add_argument("--markdown-output", type=Path, help="Explicit Markdown report path")
    parser.add_argument("--simulate-missing-tools", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)
    root = args.project.expanduser().resolve()
    if not root.is_dir():
        print(f"Technical error: project path is not a readable directory: {root}", file=sys.stderr)
        return 2
    asc = args.asc_metadata.expanduser().resolve() if args.asc_metadata else None
    if asc is not None and not asc.is_file():
        print(f"Technical error: App Store Connect evidence file does not exist: {asc}", file=sys.stderr)
        return 2
    try:
        baseline = _load_baseline(args.baseline.expanduser().resolve() if args.baseline else None)
        context = ScanContext(
            root=root,
            network=args.network,
            deep=False,
            asc_metadata=asc,
            simulate_missing_tools=args.simulate_missing_tools,
        )
        report = build_report(context, profile=args.profile, baseline=baseline)
        schema_errors = validate_report_schema(report)
        if schema_errors:
            raise ValueError("; ".join(schema_errors))
        output_dir = make_output_dir(args.output_dir.expanduser() if args.output_dir else None)
        json_path = args.json_output.expanduser() if args.json_output else output_dir / "app-store-review-report.json"
        markdown_path = args.markdown_output.expanduser() if args.markdown_output else output_dir / "app-store-review-report.md"
        _atomic_write(json_path, json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
        _atomic_write(markdown_path, markdown_report(report))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Technical audit error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3
    if not args.quiet:
        print(f"Readiness: {report['readiness']['status']}")
        print(f"Risk index: {report['metrics']['risk_index']}/100 (internal heuristic, not rejection probability)")
        print(f"Coverage: {report['metrics']['coverage']}%")
        print(f"Findings: {len(report['findings'])}")
        print(f"JSON: {json_path.resolve()}")
        print(f"Markdown: {markdown_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
