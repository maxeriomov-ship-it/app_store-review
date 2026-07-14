#!/usr/bin/env python3
"""Inspect entitlement plists without touching signing state."""

from __future__ import annotations

from audit_core import (
    ScanContext,
    check,
    evidence,
    finish_result,
    iter_files,
    load_plist,
    make_finding,
    new_result,
    relative_path,
    scanner_cli,
)


def scan(context: ScanContext) -> dict:
    result = new_result("scan_entitlements")
    root = context.root
    candidates = list(iter_files(root, suffixes={".entitlements"}))
    parsed = 0
    capabilities: dict[str, list[str]] = {}
    for path in candidates:
        rel = relative_path(path, root)
        payload, error = load_plist(path)
        if error:
            result["findings"].append(
                make_finding(
                    base_id="ENTITLEMENTS-INVALID",
                    severity="High",
                    confidence="High",
                    verification="Likely",
                    area="Project configuration",
                    title="Entitlements file could not be parsed",
                    problem=error,
                    evidence_items=[evidence(kind="parse-error", value=error, file=rel)],
                    file=rel,
                    source_id="ARG-2.1",
                    risk_reason="Invalid or mismatched entitlements can make the archive invalid or disable reviewable capabilities.",
                    remediation="Repair the entitlement plist and verify the target's Signing & Capabilities assignment.",
                    verification_steps=[f"Run plutil -lint '{rel}'.", "Inspect signed entitlements in the final archive."],
                    command=f"plutil -lint '{rel}'",
                    limitations=["The file may not be assigned to the Release target; inspect the signed archive."],
                    heuristic=True,
                )
            )
            continue
        parsed += 1
        assert payload is not None
        capabilities[rel or str(path)] = sorted(payload.keys())
        if payload.get("get-task-allow") is True:
            result["findings"].append(
                make_finding(
                    base_id="ENTITLEMENT-GET-TASK-ALLOW",
                    severity="Medium",
                    confidence="Low",
                    verification="Possible",
                    area="Project configuration",
                    title="Debug entitlement detected",
                    problem="get-task-allow=true appears in an entitlement file; target/configuration assignment is unknown.",
                    evidence_items=[evidence(kind="entitlement", value="get-task-allow=true", file=rel)],
                    file=rel,
                    source_id="ARG-2.1",
                    risk_reason="A distribution archive should not use development/debug entitlements.",
                    remediation="Confirm the Release target uses the distribution entitlement set and inspect the signed archive.",
                    verification_steps=["Run codesign -d --entitlements :- against the archived app without modifying it.", "Confirm get-task-allow is absent or false."],
                    limitations=["This file may be assigned only to Debug or may not be assigned to any target."],
                    heuristic=True,
                )
            )
        associated = payload.get("com.apple.developer.associated-domains")
        if isinstance(associated, list):
            invalid = []
            for value in associated:
                if not isinstance(value, str) or ":" not in value:
                    invalid.append(value)
                    continue
                _, domain = value.split(":", 1)
                normalized = domain.split("?", 1)[0].strip().lower()
                if normalized in {"example.com", "example.org", "example.net"} or normalized.endswith(
                    (".example", ".invalid", ".test", ".local")
                ):
                    invalid.append(value)
            if invalid:
                result["findings"].append(
                    make_finding(
                        base_id="ENTITLEMENT-ASSOCIATED-DOMAIN-SUSPECT",
                        severity="Medium",
                        confidence="Medium",
                        verification="Likely",
                        area="Project configuration",
                        title="Placeholder or malformed associated domain",
                        problem=f"Suspicious associated-domain entries: {invalid}",
                        evidence_items=[evidence(kind="entitlement", value=str(invalid), file=rel)],
                        file=rel,
                        source_id="ARG-2.1",
                        risk_reason="Reviewable authentication, universal-link, or credential flows may fail with placeholder domains.",
                        remediation="Replace placeholder entries and verify the production apple-app-site-association file.",
                        verification_steps=["Test Universal Links or credential association on a clean device.", "Inspect the signed entitlements."],
                        limitations=["Some development-only entitlement files may not ship in Release."],
                        heuristic=True,
                    )
                )
    result["facts"]["entitlement_files"] = [relative_path(path, root) for path in candidates]
    result["facts"]["capabilities"] = capabilities
    result["facts"]["sign_in_with_apple_capability"] = any(
        "com.apple.developer.applesignin" in keys for keys in capabilities.values()
    )
    result["checks"].append(
        check(
            "entitlements.source-files",
            "Project configuration",
            "Passed" if parsed or not candidates else "Failed",
            f"Parsed {parsed} entitlement file(s)." if candidates else "No source entitlement file detected; this is valid for apps without capabilities.",
        )
    )
    result["checks"].append(
        check(
            "entitlements.static-configuration",
            "Project configuration",
            "Failed"
            if result["findings"]
            else ("Passed" if parsed or not candidates else "Not verified"),
            f"Detected {len(result['findings'])} material source-entitlement finding(s)."
            if result["findings"]
            else "No material source-entitlement issue was detected; archive assignment remains separate.",
            source_id="ARG-2.1",
        )
    )
    result["checks"].append(
        check(
            "entitlements.signed-archive",
            "Project configuration",
            "Not verified",
            "Signed entitlements and provisioning-profile compatibility require the exact release archive.",
        )
    )
    return finish_result(result)


if __name__ == "__main__":
    raise SystemExit(scanner_cli(scan, "scan_entitlements"))
