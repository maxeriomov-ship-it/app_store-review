#!/usr/bin/env python3
"""Validate Info.plist files and privacy-sensitive configuration."""

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


PURPOSE_KEYS = {
    "NSCameraUsageDescription",
    "NSMicrophoneUsageDescription",
    "NSPhotoLibraryUsageDescription",
    "NSPhotoLibraryAddUsageDescription",
    "NSContactsUsageDescription",
    "NSCalendarsUsageDescription",
    "NSRemindersUsageDescription",
    "NSLocationWhenInUseUsageDescription",
    "NSLocationAlwaysAndWhenInUseUsageDescription",
    "NSLocationAlwaysUsageDescription",
    "NSBluetoothAlwaysUsageDescription",
    "NSBluetoothPeripheralUsageDescription",
    "NSLocalNetworkUsageDescription",
    "NSMotionUsageDescription",
    "NSHealthShareUsageDescription",
    "NSHealthUpdateUsageDescription",
    "NSSpeechRecognitionUsageDescription",
    "NSUserTrackingUsageDescription",
    "NSFaceIDUsageDescription",
    "NSAppleMusicUsageDescription",
}


def scan(context: ScanContext) -> dict:
    result = new_result("scan_plist")
    root = context.root
    candidates = [
        path
        for path in iter_files(root, suffixes={".plist"})
        if path.name.lower() in {"info.plist", "*-info.plist"} or "info" in path.stem.lower()
    ]
    parsed = 0
    parse_errors = 0
    purpose_values: dict[str, list[dict]] = {}
    for path in candidates:
        rel = relative_path(path, root)
        payload, error = load_plist(path)
        if error:
            parse_errors += 1
            result["findings"].append(
                make_finding(
                    base_id="PLIST-INVALID",
                    severity="High",
                    confidence="High",
                    verification="Likely",
                    area="Project configuration",
                    title="Info.plist could not be parsed",
                    problem=error,
                    evidence_items=[evidence(kind="parse-error", value=error, file=rel)],
                    file=rel,
                    source_id="ARG-2.1",
                    risk_reason="An invalid bundled property list can prevent a valid app bundle or hide required configuration from review.",
                    remediation="Repair the plist syntax or regenerate the target Info.plist through Xcode.",
                    verification_steps=[f"Run plutil -lint '{rel}'.", "Build the Release target and inspect the bundled Info.plist."],
                    command=f"plutil -lint '{rel}'",
                    autofix_available=False,
                    limitations=["The file may be a source plist not assigned to an app target."],
                    heuristic=True,
                )
            )
            continue
        parsed += 1
        assert payload is not None
        for key in PURPOSE_KEYS:
            if key not in payload:
                continue
            value = payload.get(key)
            purpose_values.setdefault(key, []).append({"file": rel, "value": value})
            if not isinstance(value, str) or not value.strip() or value.strip() in {"$(PRODUCT_NAME)", "TODO", "TBD"}:
                result["findings"].append(
                    make_finding(
                        base_id="PERMISSION-PURPOSE-EMPTY",
                        severity="High",
                        confidence="High",
                        verification="Likely",
                        area="Permissions",
                        title=f"Empty or unusable permission purpose string: {key}",
                        problem=f"{key} is present but does not contain a concrete user-facing explanation.",
                        evidence_items=[
                            evidence(kind="plist-value", value=f"{key}={value!r}", file=rel)
                        ],
                        file=rel,
                        source_id="ARG-5.1.1",
                        risk_reason="Apple requires purpose strings to clearly and completely explain protected-data access.",
                        remediation=f"Write a localized, feature-specific explanation for {key} that states how and why the data or capability is used.",
                        verification_steps=["Inspect the built app's permission prompt on a clean install.", "Confirm every supported localization contains the same purpose key."],
                        autofix_available=True,
                        autofix_notes="A value can be inserted only after the product owner supplies truthful purpose text; never invent it.",
                        limitations=["Generated build settings or InfoPlist.strings may override this source value."],
                        heuristic=False,
                        id_detail=key,
                    )
                )
        ats = payload.get("NSAppTransportSecurity")
        if isinstance(ats, dict) and ats.get("NSAllowsArbitraryLoads") is True:
            result["findings"].append(
                make_finding(
                    base_id="ATS-ARBITRARY-LOADS",
                    severity="Medium",
                    confidence="High",
                    verification="Verified",
                    area="Privacy",
                    title="App Transport Security permits arbitrary loads",
                    problem="NSAllowsArbitraryLoads is enabled in an inspected Info.plist.",
                    evidence_items=[evidence(kind="plist-value", value="NSAllowsArbitraryLoads=true", file=rel)],
                    file=rel,
                    source_id="ARG-5.1.1",
                    risk_reason="Broad insecure transport increases privacy and security exposure and may require explanation during review.",
                    remediation="Remove the broad exception or narrow it to the minimum justified domains and protocols.",
                    verification_steps=["Inspect the built Info.plist.", "Exercise all network routes over the intended production transport."],
                    limitations=["A justified, narrow compatibility requirement may exist; static analysis cannot establish it."],
                    heuristic=True,
                )
            )
        export_value = payload.get("ITSAppUsesNonExemptEncryption")
        if export_value is not None:
            result["facts"].setdefault("export_compliance_values", []).append(
                {"file": rel, "ITSAppUsesNonExemptEncryption": export_value}
            )
    result["facts"]["info_plists"] = [relative_path(path, root) for path in candidates]
    result["facts"]["purpose_keys"] = purpose_values
    result["checks"].append(
        check(
            "plist.parse",
            "Project configuration",
            "Failed" if parse_errors else ("Passed" if parsed else "Not verified"),
            (
                f"Parsed {parsed} candidate Info.plist file(s), with {parse_errors} parse error(s); target membership remains to be confirmed."
                if parse_errors
                else f"Parsed {parsed} candidate Info.plist file(s)."
                if parsed
                else "No source Info.plist was parsed; the project may generate it from build settings."
            ),
        )
    )
    result["checks"].append(
        check(
            "plist.static-configuration",
            "Project configuration",
            "Failed"
            if result["findings"]
            else ("Passed" if parsed else "Not verified"),
            f"Detected {len(result['findings'])} material plist configuration finding(s)."
            if result["findings"]
            else "No material issue was detected in parsed source plist configuration."
            if parsed
            else "Source plist configuration was not available.",
            source_id="ARG-2.1",
        )
    )
    result["checks"].append(
        check(
            "plist.export-compliance",
            "Project configuration",
            "Passed" if result["facts"].get("export_compliance_values") else "Not verified",
            "Found an encryption classification key; legal correctness still requires App Store Connect confirmation."
            if result["facts"].get("export_compliance_values")
            else "No source encryption classification key was detected; App Store Connect export-compliance answers remain unverified.",
            source_id="ASC-EXPORT",
        )
    )
    return finish_result(result)


if __name__ == "__main__":
    raise SystemExit(scanner_cli(scan, "scan_plist"))
