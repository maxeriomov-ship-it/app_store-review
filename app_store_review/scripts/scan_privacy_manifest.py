#!/usr/bin/env python3
"""Validate privacy manifests and detect required-reason API signals."""

from __future__ import annotations

import re
from pathlib import Path

from audit_core import (
    ScanContext,
    check,
    code_corpus,
    evidence,
    find_matches,
    finish_result,
    iter_files,
    load_plist,
    make_finding,
    match_evidence,
    new_result,
    relative_path,
    scanner_cli,
)


ALLOWED_ROOT_KEYS = {
    "NSPrivacyTracking",
    "NSPrivacyTrackingDomains",
    "NSPrivacyCollectedDataTypes",
    "NSPrivacyAccessedAPITypes",
}

REQUIRED_REASON_PATTERNS = {
    "NSPrivacyAccessedAPICategoryUserDefaults": r"\bUserDefaults\b|NSUserDefaults",
    "NSPrivacyAccessedAPICategorySystemBootTime": r"systemUptime|mach_absolute_time|kern\.boottime",
    "NSPrivacyAccessedAPICategoryDiskSpace": r"volumeAvailableCapacity|systemFreeSize|attributesOfFileSystem",
    "NSPrivacyAccessedAPICategoryFileTimestamp": r"contentModificationDate|creationDateKey|stat\s*\(|getattrlist\s*\(",
    "NSPrivacyAccessedAPICategoryActiveKeyboards": r"activeInputModes|UITextInputMode",
}


def _manifest_schema_errors(payload: dict) -> list[str]:
    errors: list[str] = []
    if "NSPrivacyTracking" in payload and not isinstance(payload["NSPrivacyTracking"], bool):
        errors.append("NSPrivacyTracking must be a Boolean")

    domains = payload.get("NSPrivacyTrackingDomains", [])
    if not isinstance(domains, list):
        errors.append("NSPrivacyTrackingDomains must be an array")
    elif any(not isinstance(item, str) or not item.strip() for item in domains):
        errors.append("Every NSPrivacyTrackingDomains entry must be a non-empty string")

    collected = payload.get("NSPrivacyCollectedDataTypes", [])
    if not isinstance(collected, list):
        errors.append("NSPrivacyCollectedDataTypes must be an array")
    else:
        for index, entry in enumerate(collected):
            prefix = f"NSPrivacyCollectedDataTypes[{index}]"
            if not isinstance(entry, dict):
                errors.append(f"{prefix} must be a dictionary")
                continue
            if not isinstance(entry.get("NSPrivacyCollectedDataType"), str):
                errors.append(f"{prefix}.NSPrivacyCollectedDataType must be a string")
            for key in ("NSPrivacyCollectedDataTypeLinked", "NSPrivacyCollectedDataTypeTracking"):
                if not isinstance(entry.get(key), bool):
                    errors.append(f"{prefix}.{key} must be a Boolean")
            purposes = entry.get("NSPrivacyCollectedDataTypePurposes")
            if not isinstance(purposes, list) or any(
                not isinstance(item, str) or not item for item in purposes
            ):
                errors.append(
                    f"{prefix}.NSPrivacyCollectedDataTypePurposes must be an array of strings"
                )

    accessed = payload.get("NSPrivacyAccessedAPITypes", [])
    if not isinstance(accessed, list):
        errors.append("NSPrivacyAccessedAPITypes must be an array")
    else:
        for index, entry in enumerate(accessed):
            prefix = f"NSPrivacyAccessedAPITypes[{index}]"
            if not isinstance(entry, dict):
                errors.append(f"{prefix} must be a dictionary")
                continue
            category = entry.get("NSPrivacyAccessedAPIType")
            reasons = entry.get("NSPrivacyAccessedAPITypeReasons")
            if not isinstance(category, str) or not category:
                errors.append(f"{prefix}.NSPrivacyAccessedAPIType must be a non-empty string")
            if not isinstance(reasons, list) or not reasons or any(
                not isinstance(item, str) or not item for item in reasons
            ):
                errors.append(
                    f"{prefix}.NSPrivacyAccessedAPITypeReasons must be a non-empty array of strings"
                )
    return errors


def scan(context: ScanContext) -> dict:
    result = new_result("scan_privacy_manifest")
    root = context.root
    manifests = list(iter_files(root, suffixes={".xcprivacy"}))
    parsed_payloads: list[tuple[str, dict]] = []
    for path in manifests:
        rel = relative_path(path, root)
        payload, error = load_plist(path)
        if error:
            result["findings"].append(
                make_finding(
                    base_id="PRIVACY-MANIFEST-INVALID",
                    severity="High",
                    confidence="High",
                    verification="Likely",
                    area="Privacy",
                    title="Privacy manifest is invalid",
                    problem=error,
                    evidence_items=[evidence(kind="parse-error", value=error, file=rel)],
                    file=rel,
                    command=f"plutil -lint '{rel}'",
                    source_id="PRIVACY-MANIFEST",
                    risk_reason="App Store Connect rejects submissions containing invalid privacy manifests.",
                    remediation="Repair the plist structure and use only Apple-defined privacy manifest keys and values.",
                    verification_steps=[f"Run plutil -lint '{rel}'.", "Generate the Xcode privacy report for the release archive."],
                    limitations=["The scanner does not validate every Apple-defined enum value.", "Target membership and inclusion in the submitted archive were not established."],
                    heuristic=True,
                )
            )
            continue
        assert payload is not None
        parsed_payloads.append((rel or str(path), payload))
        unexpected = sorted(set(payload) - ALLOWED_ROOT_KEYS)
        if unexpected:
            result["findings"].append(
                make_finding(
                    base_id="PRIVACY-MANIFEST-UNEXPECTED-KEY",
                    severity="High",
                    confidence="High",
                    verification="Likely",
                    area="Privacy",
                    title="Privacy manifest contains unexpected root keys",
                    problem=f"Unexpected keys: {unexpected}",
                    evidence_items=[evidence(kind="plist-key", value=", ".join(unexpected), file=rel)],
                    file=rel,
                    source_id="PRIVACY-MANIFEST",
                    risk_reason="Unexpected privacy-manifest keys can make a submission invalid.",
                    remediation="Remove unsupported keys and express the declaration with Apple's documented schema.",
                    verification_steps=["Validate the manifest in Xcode.", "Upload only after the privacy report is free of manifest errors."],
                    limitations=["Target membership and inclusion in the submitted archive were not established."],
                    heuristic=True,
                )
            )
        schema_errors = _manifest_schema_errors(payload)
        if schema_errors:
            result["findings"].append(
                make_finding(
                    base_id="PRIVACY-MANIFEST-SCHEMA-INVALID",
                    severity="High",
                    confidence="High",
                    verification="Likely",
                    area="Privacy",
                    title="Privacy manifest contains invalid value types or nested entries",
                    problem="; ".join(schema_errors),
                    evidence_items=[
                        evidence(kind="privacy-manifest-schema", value=item, file=rel)
                        for item in schema_errors[:12]
                    ],
                    file=rel,
                    source_id="PRIVACY-MANIFEST",
                    risk_reason="A source-visible manifest that does not match Apple's schema may fail validation when included in the submitted bundle.",
                    remediation="Correct the Boolean, array, dictionary, category, and reason structures using Xcode's Privacy Manifest editor and current Apple documentation.",
                    verification_steps=["Validate the manifest in Xcode.", "Generate the privacy report from the exact release archive."],
                    limitations=["The scanner validates documented structure, not every evolving Apple enum value.", "Target membership and archive inclusion remain unverified."],
                    heuristic=True,
                )
            )
        if payload.get("NSPrivacyTracking") is True and not payload.get("NSPrivacyTrackingDomains"):
            result["findings"].append(
                make_finding(
                    base_id="PRIVACY-TRACKING-DOMAINS-EMPTY",
                    severity="Medium",
                    confidence="Medium",
                    verification="Possible",
                    area="Privacy",
                    title="Tracking declared without tracking domains",
                    problem="NSPrivacyTracking is true but no NSPrivacyTrackingDomains entries were detected.",
                    evidence_items=[evidence(kind="plist-value", value="NSPrivacyTracking=true", file=rel)],
                    file=rel,
                    source_id="PRIVACY-MANIFEST",
                    risk_reason="A tracking declaration should accurately describe the domains contacted for tracking.",
                    remediation="Declare all applicable tracking domains and reconcile the behavior with ATT and App Privacy answers.",
                    verification_steps=["Generate the Xcode privacy report.", "Observe production network traffic after ATT denial and approval."],
                    limitations=["Tracking may be performed by a dependency manifest not present in source.", "The release archive may aggregate declarations from other bundles; inspect the generated privacy report."],
                    heuristic=True,
                )
            )

    corpus = code_corpus(root)
    api_hits: dict[str, list[dict]] = {
        category: find_matches(corpus, pattern, root)
        for category, pattern in REQUIRED_REASON_PATTERNS.items()
    }
    declared_categories: set[str] = set()
    manifest_category_scopes: list[tuple[str, set[str]]] = []
    for rel, payload in parsed_payloads:
        scoped_categories: set[str] = set()
        for entry in payload.get("NSPrivacyAccessedAPITypes", []) or []:
            if isinstance(entry, dict) and isinstance(entry.get("NSPrivacyAccessedAPIType"), str):
                scoped_categories.add(entry["NSPrivacyAccessedAPIType"])
        declared_categories.update(scoped_categories)
        manifest_category_scopes.append((rel, scoped_categories))

    def categories_for_hit(hit: dict) -> set[str]:
        hit_file = hit.get("file")
        if not hit_file:
            return set()
        hit_path = (root / hit_file).resolve()
        candidates: list[tuple[int, set[str]]] = []
        for rel, categories in manifest_category_scopes:
            parent = (root / rel).resolve().parent
            if parent == root.resolve():
                # A root-level app manifest must not silently satisfy an
                # obvious extension bundle. Exact target membership still
                # requires the archive privacy report.
                relative_parts = Path(hit_file).parts
                first = relative_parts[0].lower() if relative_parts else ""
                if any(
                    marker in first
                    for marker in ("widget", "extension", "appclip", "notification", "share", "intent", "watch")
                ):
                    continue
            try:
                hit_path.relative_to(parent)
            except ValueError:
                continue
            candidates.append((len(parent.parts), categories))
        if not candidates:
            return set()
        nearest_depth = max(depth for depth, _ in candidates)
        return set().union(
            *(categories for depth, categories in candidates if depth == nearest_depth)
        )

    for category, hits in api_hits.items():
        uncovered_hits = [hit for hit in hits if category not in categories_for_hit(hit)]
        if not uncovered_hits:
            continue
        first = uncovered_hits[0]
        result["findings"].append(
            make_finding(
                base_id="REQUIRED-REASON-API-NOT-DECLARED",
                severity="High",
                confidence="Medium",
                verification="Possible",
                area="Privacy",
                title=f"Required-reason API category may be undeclared: {category}",
                problem=f"Detected {len(uncovered_hits)} source signal(s) for {category} without a declaration in the nearest source-visible bundle scope.",
                evidence_items=[match_evidence(item, category) for item in uncovered_hits[:5]],
                file=first["file"],
                line=first["line"],
                source_id="REQUIRED-REASON-API",
                risk_reason="App Store Connect does not accept covered API use without an accurate approved reason in the relevant bundle.",
                remediation="Confirm the API is present in the release binary and, if covered, add an approved reason that truthfully matches its use to the correct bundle manifest.",
                verification_steps=["Generate the archive privacy report.", "Inspect every app, extension, framework, and dynamic-library bundle for the declaration."],
                limitations=["Path proximity is only a target-scope heuristic; confirm target membership and the archive privacy report.", "Pattern matches may refer to unrelated symbols or code excluded from the release target.", "An SDK's bundled manifest may be available only after dependency resolution."],
                heuristic=True,
                id_detail=category,
            )
        )
    result["facts"] = {
        "manifests": [relative_path(path, root) for path in manifests],
        "declared_required_reason_categories": sorted(declared_categories),
        "manifest_category_scopes": {
            rel: sorted(categories) for rel, categories in manifest_category_scopes
        },
        "required_reason_api_signals": {key: len(value) for key, value in api_hits.items()},
    }
    manifest_schema_findings = {
        "PRIVACY-MANIFEST-INVALID",
        "PRIVACY-MANIFEST-UNEXPECTED-KEY",
        "PRIVACY-MANIFEST-SCHEMA-INVALID",
    }
    source_manifest_failed = any(
        finding.get("rule_id") in manifest_schema_findings for finding in result["findings"]
    )
    result["checks"].append(
        check(
            "privacy.manifest-validity",
            "Privacy",
            "Failed" if source_manifest_failed else ("Passed" if parsed_payloads else "Not verified"),
            (
                "One or more source-visible privacy manifests could not be validated; archive inclusion remains unverified."
                if source_manifest_failed
                else f"Parsed {len(parsed_payloads)} source privacy manifest(s); archive aggregation remains unverified."
                if parsed_payloads
                else "No source privacy manifest was detected. A manifest is trigger-based, not universally mandatory."
            ),
            source_id="PRIVACY-MANIFEST",
        )
    )
    material_privacy_findings = any(
        finding.get("severity") in {"Critical", "High", "Medium"}
        for finding in result["findings"]
    )
    result["checks"].append(
        check(
            "privacy.static-declarations",
            "Privacy",
            "Failed" if material_privacy_findings else "Passed",
            f"Detected {sum(finding.get('severity') in {'Critical', 'High', 'Medium'} for finding in result['findings'])} material static privacy declaration finding(s).",
            source_id="PRIVACY-MANIFEST",
        )
    )
    required_reason_applicable = any(api_hits.values())
    required_reason_failed = any(
        finding.get("rule_id") == "REQUIRED-REASON-API-NOT-DECLARED"
        for finding in result["findings"]
    )
    result["checks"].append(
        check(
            "privacy.required-reason-static",
            "Privacy",
            "Failed"
            if required_reason_failed
            else ("Passed" if required_reason_applicable else "Not applicable"),
            (
                "One or more source-visible required-reason API signals were not covered in the nearest manifest scope."
                if required_reason_failed
                else "Source-visible required-reason API signals have declarations in the nearest detected manifest scopes."
                if required_reason_applicable
                else "No supported required-reason API source signal was detected."
            ),
            applicable=required_reason_applicable,
            source_id="REQUIRED-REASON-API",
        )
    )
    result["checks"].append(
        check(
            "privacy.archive-report",
            "Privacy",
            "Not verified",
            "The aggregated Xcode privacy report for the exact release archive was not available.",
            source_id="PRIVACY-MANIFEST",
        )
    )
    return finish_result(result)


if __name__ == "__main__":
    raise SystemExit(scanner_cli(scan, "scan_privacy_manifest"))
