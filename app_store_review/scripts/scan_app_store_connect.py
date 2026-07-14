#!/usr/bin/env python3
"""Validate a user-provided App Store Connect metadata export or evidence file."""

from __future__ import annotations

import json
import ipaddress
import urllib.parse
from pathlib import Path

from audit_core import (
    ScanContext,
    check,
    evidence,
    finish_result,
    make_finding,
    new_result,
    relative_path,
    scanner_cli,
)


REQUIRED_FIELDS = {
    "name": "App name",
    "description": "Description",
    "support_url": "Support URL",
    "privacy_policy_url": "Privacy Policy URL",
    "screenshots": "Screenshots",
    "age_rating": "Age rating",
    "review_contact": "App Review contact",
    "app_privacy": "App Privacy answers",
}

OPTIONAL_AUDIT_FIELDS = {
    "subtitle": "Subtitle",
    "keywords": "Keywords",
    "review_notes": "App Review Notes",
}

EXPECTED_FIELDS = {**REQUIRED_FIELDS, **OPTIONAL_AUDIT_FIELDS}

# These fields are not all mandatory App Store fields. Their presence in the
# developer-supplied evidence proves only that the audit considered their
# applicability instead of silently treating omitted material as compliant.
EVIDENCE_SCOPE_FIELDS = {
    "category": "Category",
    "localizations": "Product-page localizations",
    "marketing_url": "Marketing URL applicability",
    "app_previews": "App Preview applicability",
}


def _find_metadata(context: ScanContext) -> Path | None:
    if context.asc_metadata:
        return context.asc_metadata
    for name in ("app_store_connect.json", "asc_metadata.json", "AppStoreConnect.json"):
        candidate = context.root / name
        if candidate.is_file():
            return candidate
    return None


def _valid_public_url(value) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return False
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not host or parsed.username or parsed.password:
        return False
    if host.endswith((".invalid", ".example", ".test", ".local")) or host in {"localhost", "127.0.0.1"}:
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return "." in host


def scan(context: ScanContext) -> dict:
    result = new_result("scan_app_store_connect")
    root = context.root
    metadata_path = _find_metadata(context)
    if metadata_path is None:
        result["facts"]["metadata_file"] = None
        result["checks"].append(
            check(
                "asc.metadata-evidence",
                "App Store Connect metadata",
                "Not verified",
                "No App Store Connect export/evidence JSON was provided; metadata cannot be marked compliant.",
                source_id="ASC-PLATFORM-METADATA",
            )
        )
        return finish_result(result)
    rel = relative_path(metadata_path, root)
    try:
        payload = json.loads(metadata_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("top-level JSON must be an object")
    except (OSError, ValueError) as exc:
        result["findings"].append(
            make_finding(
                base_id="ASC-METADATA-INVALID",
                severity="High",
                confidence="High",
                verification="Verified",
                area="App Store Connect metadata",
                title="App Store Connect evidence file is invalid",
                problem=f"{type(exc).__name__}: {exc}",
                evidence_items=[evidence(kind="parse-error", value=str(exc), file=rel)],
                file=rel,
                source_id="ASC-PLATFORM-METADATA",
                risk_reason="The audit cannot validate required listing and review information from an invalid export.",
                remediation="Provide a valid JSON export/evidence file matching the documented fields.",
                verification_steps=["Parse the JSON locally.", "Compare it with the live App Store Connect record."],
                heuristic=False,
            )
        )
        result["checks"].append(
            check("asc.metadata-evidence", "App Store Connect metadata", "Failed", "Metadata evidence JSON could not be parsed.", source_id="ASC-PLATFORM-METADATA")
        )
        return finish_result(result)
    result["facts"]["metadata_file"] = rel
    missing_fields = [field for field in EXPECTED_FIELDS if payload.get(field) in (None, "", [], {})]
    missing_required = [field for field in missing_fields if field in REQUIRED_FIELDS]
    evidence_scope_missing = []
    for field in EVIDENCE_SCOPE_FIELDS:
        if field not in payload:
            evidence_scope_missing.append(field)
        elif field in {"category", "localizations"} and payload.get(field) in (None, "", [], {}):
            evidence_scope_missing.append(field)
    for field in missing_fields:
        label = EXPECTED_FIELDS[field]
        required = field in REQUIRED_FIELDS
        contextually_material_notes = field == "review_notes" and bool(
            payload.get("requires_login") or payload.get("in_app_purchases")
        )
        result["findings"].append(
            make_finding(
                base_id="ASC-METADATA-MISSING-FIELD",
                severity="High" if required else ("Medium" if contextually_material_notes else "Low"),
                confidence="High",
                verification="Verified" if required else "Not verified",
                area="App Store Connect metadata",
                title=(
                    f"Missing required App Store Connect evidence: {label}"
                    if required
                    else f"No App Store Connect evidence supplied for optional field: {label}"
                ),
                problem=f"The provided metadata evidence does not contain a usable {label} value.",
                evidence_items=[evidence(kind="metadata-field", value=f"Missing: {label}", file=rel)],
                file=rel,
                source_id="ASC-PLATFORM-METADATA" if label != "App Privacy answers" else "ASC-APP-PRIVACY",
                risk_reason=(
                    "Required or review-critical metadata cannot be confirmed and may block or delay review."
                    if required
                    else "The field is not universally required, but its content and intentional omission were not auditable from the supplied evidence."
                ),
                remediation=(
                    f"Complete and verify {label} in the live App Store Connect record, then refresh the evidence export."
                    if required or contextually_material_notes
                    else f"Confirm whether {label} is intentionally unused; if used, provide it in the evidence export and verify every localization."
                ),
                verification_steps=["Open the current app version in App Store Connect.", "Verify every localization and save the record."],
                limitations=["The JSON is evidence supplied by the developer; the scanner has no authenticated live App Store Connect access."],
                heuristic=not required,
                id_detail=label,
            )
        )
    if evidence_scope_missing:
        labels = [EVIDENCE_SCOPE_FIELDS[field] for field in evidence_scope_missing]
        result["findings"].append(
            make_finding(
                base_id="ASC-EVIDENCE-SCOPE-INCOMPLETE",
                severity="Informational",
                confidence="High",
                verification="Not verified",
                area="App Store Connect metadata",
                title="App Store Connect evidence does not cover the full metadata audit scope",
                problem="The evidence does not establish whether these areas were reviewed: " + ", ".join(labels) + ".",
                evidence_items=[evidence(kind="metadata-scope", value=f"Missing evidence keys: {', '.join(evidence_scope_missing)}", file=rel)],
                file=rel,
                source_id="ASC-PLATFORM-METADATA",
                risk_reason="Omitted evidence must remain unverified; absence in a local export is not proof that the live record is complete.",
                remediation="Add the audit-scope keys to the evidence export. Use null or an empty list only for optional material that was deliberately reviewed and is not used.",
                verification_steps=["Review every localization and media set in the live App Store Connect record.", "Regenerate the evidence file with an explicit value for every scope key."],
                limitations=["This is an evidence-completeness finding, not a claim that every listed field is mandatory for every app."],
                heuristic=False,
            )
        )
    for field, label in (
        ("support_url", "Support URL"),
        ("privacy_policy_url", "Privacy Policy URL"),
        ("marketing_url", "Marketing URL"),
    ):
        value = payload.get(field)
        if value and not _valid_public_url(value):
            result["findings"].append(
                make_finding(
                    base_id="ASC-METADATA-URL-INVALID",
                    severity="High",
                    confidence="High",
                    verification="Verified",
                    area="App Store Connect metadata",
                    title=f"{label} is not a valid public HTTPS URL",
                    problem=f"Provided value: {value}",
                    evidence_items=[evidence(kind="metadata-field", value=f"{field}={value}", file=rel)],
                    file=rel,
                    source_id="ASC-PLATFORM-METADATA" if field == "support_url" else "ARG-5.1.1",
                    risk_reason="Required support/privacy destinations must be complete, accurate, and accessible.",
                    remediation=f"Set {label} to the final public page and verify it without authentication.",
                    verification_steps=["Open the URL on a clean device and another network.", "Confirm required contact/privacy content is present."],
                    limitations=["A syntactically valid URL can still be unavailable or contain inadequate content."],
                    heuristic=False,
                    id_detail=field,
                )
            )
    review_contact = payload.get("review_contact")
    if review_contact not in (None, "", [], {}):
        contact_complete = isinstance(review_contact, dict) and bool(
            (review_contact.get("name") or (review_contact.get("first_name") and review_contact.get("last_name")))
            and review_contact.get("email")
            and review_contact.get("phone")
        )
        if not contact_complete:
            result["findings"].append(
                make_finding(
                    base_id="ASC-REVIEW-CONTACT-INCOMPLETE",
                    severity="High",
                    confidence="High",
                    verification="Verified",
                    area="App Store Connect metadata",
                    title="App Review contact evidence is incomplete",
                    problem="The review contact must identify a person and include both email and phone contact details.",
                    evidence_items=[evidence(kind="metadata-field", value="review_contact is present but incomplete", file=rel)],
                    file=rel,
                    source_id="ASC-PLATFORM-METADATA",
                    risk_reason="Apple must be able to contact a knowledgeable person while reviewing the submission.",
                    remediation="Provide the review contact's name, monitored email address, and reachable phone number in App Store Connect.",
                    verification_steps=["Confirm the contact details in the live version record.", "Verify the contact can answer during the review window."],
                    limitations=["The scanner cannot test whether the person is reachable."],
                    heuristic=False,
                )
            )
    screenshots = payload.get("screenshots")
    if isinstance(screenshots, list) and not (1 <= len(screenshots) <= 10):
        result["findings"].append(
            make_finding(
                base_id="ASC-SCREENSHOT-COUNT",
                severity="High",
                confidence="High",
                verification="Verified",
                area="App Store Connect metadata",
                title="Screenshot count is outside the supported range",
                problem=f"The evidence lists {len(screenshots)} screenshots; Apple accepts one to ten per applicable set.",
                evidence_items=[evidence(kind="metadata-field", value=f"screenshots={len(screenshots)}", file=rel)],
                file=rel,
                source_id="ASC-SCREENSHOTS",
                risk_reason="Missing or excessive required media prevents a complete product-page submission.",
                remediation="Provide one to ten accurate screenshots for every required device family and intended localization.",
                verification_steps=["Validate dimensions and alpha rules in App Store Connect.", "Compare every screenshot with the current release build."],
                limitations=["The evidence format does not inspect image pixels, dimensions, or accuracy."],
                heuristic=False,
            )
        )
    if payload.get("requires_login") is True:
        demo = payload.get("demo_account") or {}
        if not isinstance(demo, dict) or not demo.get("username") or not demo.get("password"):
            result["findings"].append(
                make_finding(
                    base_id="ASC-DEMO-ACCOUNT-MISSING",
                    severity="Critical",
                    confidence="High",
                    verification="Verified",
                    area="App Store Connect metadata",
                    title="Required demo account evidence is missing",
                    problem="The metadata states login is required but does not provide complete demo-account credentials.",
                    evidence_items=[evidence(kind="metadata-field", value="requires_login=true; demo_account incomplete", file=rel)],
                    file=rel,
                    source_id="ASC-PLATFORM-METADATA",
                    risk_reason="App Review needs full, non-expiring access to account-gated functionality.",
                    remediation="Provide a dedicated non-expiring demo account or an Apple-approved full demo mode, with 2FA and special setup handled in notes.",
                    verification_steps=["Test the credentials from a clean device and network.", "Verify every paid, hidden, and role-gated route intended for review."],
                    limitations=["Never store real user credentials in repository evidence; use dedicated review credentials and protect the file appropriately."],
                    heuristic=False,
                )
            )
    products = payload.get("in_app_purchases") or []
    if isinstance(products, list):
        for index, product in enumerate(products):
            if not isinstance(product, dict):
                continue
            absent = [key for key in ("product_id", "display_name", "description", "review_screenshot", "localizations") if not product.get(key)]
            if absent:
                result["findings"].append(
                    make_finding(
                        base_id="ASC-IAP-METADATA-INCOMPLETE",
                        severity="High",
                        confidence="High",
                        verification="Verified",
                        area="Purchases and subscriptions",
                        title="In-App Purchase metadata evidence is incomplete",
                        problem=f"Product {product.get('product_id') or index} is missing: {', '.join(absent)}.",
                        evidence_items=[evidence(kind="metadata-field", value=f"IAP index {index}; missing {absent}", file=rel)],
                        file=rel,
                        source_id="ASC-IAP",
                        risk_reason="IAP/subscription review needs complete product metadata, localization, review information, and a review screenshot.",
                        remediation="Complete the product record, verify status/availability, and attach an accurate review screenshot and notes.",
                        verification_steps=["Open the product in App Store Connect.", "Load it in Sandbox for each supported localization."],
                        limitations=["The live product state can change after this evidence file is generated."],
                        heuristic=False,
                        id_detail=str(product.get("product_id") or index),
                    )
                )
    result["facts"]["provided_fields"] = sorted(payload)
    result["facts"]["evidence_scope_missing"] = evidence_scope_missing
    material_metadata_findings = any(
        finding.get("severity") in {"Critical", "High", "Medium"}
        for finding in result["findings"]
    )
    result["checks"].extend(
        [
            check(
                "asc.metadata-evidence",
                "App Store Connect metadata",
                "Failed" if material_metadata_findings else ("Not verified" if missing_fields or evidence_scope_missing else "Passed"),
                f"Inspected App Store Connect evidence from {rel}.",
                evidence_items=[evidence(kind="metadata-file", value="Provided metadata evidence", file=rel)],
                source_id="ASC-PLATFORM-METADATA",
            ),
            check(
                "asc.evidence-scope",
                "App Store Connect metadata",
                "Not verified" if evidence_scope_missing else "Passed",
                (
                    "The supplied evidence explicitly covers category, localization, Marketing URL, and App Preview applicability."
                    if not evidence_scope_missing
                    else "Some metadata areas are absent from the supplied evidence and remain unverified."
                ),
                evidence_items=[evidence(kind="metadata-file", value="Developer-supplied metadata audit scope", file=rel)],
                source_id="ASC-PLATFORM-METADATA",
            ),
            check(
                "asc.live-record",
                "App Store Connect metadata",
                "Not verified",
                "The authenticated live record, per-localization rendering, product status, agreements, and submission state were not queried.",
                source_id="ASC-PLATFORM-METADATA",
            ),
        ]
    )
    return finish_result(result)


if __name__ == "__main__":
    raise SystemExit(scanner_cli(scan, "scan_app_store_connect"))
