#!/usr/bin/env python3
"""Cross-check protected-resource APIs and permission purpose strings."""

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
    read_text,
    strip_code_comments,
)


PERMISSIONS = {
    "NSCameraUsageDescription": r"AVCaptureDevice[^\n]*(?:\.video|AVMediaType\.video)|requestAccess\s*\(\s*for\s*:\s*\.video|UIImagePickerController[^\n]*camera|ImagePicker[^\n]*camera|Camera\.request|camera\s*:\s*true",
    "NSMicrophoneUsageDescription": r"AVAudioRecorder|requestRecordPermission|AVAudioSession[^\n]*(?:record|playAndRecord)|AVCaptureDevice[^\n]*(?:audio|AVMediaType\.audio)",
    "NSPhotoLibraryUsageDescription": r"PHPhotoLibrary\.(?:requestAuthorization|authorizationStatus)|PHAsset\.(?:fetch|fetchAssets)|PHFetchResult",
    "NSPhotoLibraryAddUsageDescription": r"PHPhotoLibrary\.performChanges|PHAssetChangeRequest|UIImageWriteToSavedPhotosAlbum",
    "NSContactsUsageDescription": r"CNContactStore|Contacts\.request|react-native-contacts|contacts_service",
    "NSLocationWhenInUseUsageDescription": r"CLLocationManager|requestWhenInUseAuthorization|geolocator|expo-location",
    "NSLocationAlwaysAndWhenInUseUsageDescription": r"requestAlwaysAuthorization|allowsBackgroundLocationUpdates",
    "NSLocalNetworkUsageDescription": r"NWBrowser|NetService|bonjour|local network",
    "NSSpeechRecognitionUsageDescription": r"SFSpeechRecognizer|requestAuthorization.*speech|speech_to_text",
    "NSMotionUsageDescription": r"CMMotionManager|CMPedometer|CoreMotion",
    "NSHealthShareUsageDescription": r"HKHealthStore|HealthKit",
    "NSUserTrackingUsageDescription": r"ATTrackingManager|requestTrackingAuthorization|ASIdentifierManager|advertisingIdentifier",
    "NSFaceIDUsageDescription": r"deviceOwnerAuthenticationWithBiometrics|biometryType|FaceID",
}

NONSHIPPING_MARKERS = {"tests", "test", "uitests", "snapshots", "preview content", "previews"}
EXTENSION_MARKERS = ("extension", "widget", "watch", "appclip", "notification", "share", "intent")
FRAMEWORK_SOURCE_ROOTS = {"lib", "src", "app"}


GENERIC_PURPOSE = re.compile(
    r"^(needed|required|permission required|for a better experience|to improve your experience|this app needs access|allow access)[.! ]*$",
    re.I,
)


def _scope_model(root: Path) -> dict:
    """Infer only high-signal cross-stack aliases; leave ambiguous ownership explicit."""

    ios_root = root / "ios"
    pubspec = read_text(root / "pubspec.yaml") or ""
    package_json = read_text(root / "package.json") or ""
    declared_framework = (
        bool(re.search(r"(?:sdk\s*:\s*flutter|^\s*flutter\s*:)", pubspec, re.I | re.M))
        or bool(re.search(r'"(?:react-native|expo|@capacitor/ios)"\s*:', package_json, re.I))
    )
    framework_layout = any((root / name).is_dir() for name in FRAMEWORK_SOURCE_ROOTS)
    cross_stack = ios_root.is_dir() and (declared_framework or framework_layout)
    ios_app_roots: set[str] = set()
    if cross_stack:
        for path in iter_files(ios_root, suffixes={".plist"}):
            if "info" not in path.stem.lower():
                continue
            rel = Path(relative_path(path, ios_root) or str(path))
            parents = [part.lower() for part in rel.parts[:-1]]
            if not parents or any(
                part in NONSHIPPING_MARKERS
                or part.endswith(("tests", "uitests"))
                or any(marker in part for marker in EXTENSION_MARKERS)
                for part in parents
            ):
                continue
            ios_app_roots.add(parents[0])
    return {
        "cross_stack": cross_stack,
        "ios_app_roots": ios_app_roots,
        "primary_alias_safe": cross_stack and len(ios_app_roots) <= 1,
    }


def _bundle_scope(path, root, scope_model=None):
    scope_model = scope_model or {"cross_stack": False, "ios_app_roots": set(), "primary_alias_safe": False}
    rel = Path(relative_path(path, root) or str(path))
    for part in reversed(rel.parts[:-1]):
        lowered = part.lower()
        if lowered in NONSHIPPING_MARKERS or lowered.endswith(("tests", "uitests")):
            return "nonshipping"
        if any(marker in lowered for marker in EXTENSION_MARKERS):
            return f"extension:{lowered}"
    if scope_model["cross_stack"]:
        if len(rel.parts) == 1:
            return "app:primary" if scope_model["primary_alias_safe"] else "shared:framework"
        top = rel.parts[0].lower()
        if top in FRAMEWORK_SOURCE_ROOTS:
            return "app:primary" if scope_model["primary_alias_safe"] else "shared:framework"
        if top == "ios":
            if scope_model["primary_alias_safe"]:
                return "app:primary"
            if len(rel.parts) > 2 and rel.parts[1].lower() in scope_model["ios_app_roots"]:
                return f"app:ios/{rel.parts[1].lower()}"
            return "shared:framework"
    if len(rel.parts) > 1:
        top = rel.parts[0].lower()
        if not top.endswith((".xcodeproj", ".xcworkspace")):
            return f"app:{top}"
    return None


def _clean_build_value(value: str) -> str:
    value = value.strip().rstrip(";").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    return value.strip()


def _usable_purpose(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and "$(" not in value
        and value.strip().upper() not in {"TODO", "TBD"}
    )


def _declared_purposes(root, scope_model):
    declared: dict[str, list[dict]] = {}
    for path in iter_files(root, suffixes={".plist"}):
        if "info" not in path.stem.lower():
            continue
        payload, error = load_plist(path)
        if error or payload is None:
            continue
        rel = relative_path(path, root)
        for key in PERMISSIONS:
            if key in payload:
                declared.setdefault(key, []).append(
                    {
                        "file": rel or str(path),
                        "value": payload[key],
                        "scope": _bundle_scope(path, root, scope_model),
                        "origin": "plist",
                    }
                )
    build_key_pattern = re.compile(
        r"^\s*INFOPLIST_KEY_(" + "|".join(map(re.escape, PERMISSIONS)) + r")\s*=\s*(.*?)\s*;?\s*$",
        re.M,
    )
    for path in iter_files(root, suffixes={".pbxproj", ".xcconfig"}, max_size=5_000_000):
        text = read_text(path) or ""
        if path.suffix.lower() == ".pbxproj":
            text = strip_code_comments(text)
        else:
            text = "".join(
                "\n" if line.lstrip().startswith(("//", "#")) and line.endswith("\n") else ""
                if line.lstrip().startswith(("//", "#"))
                else re.sub(r"\s+//.*?(?=\r?\n|$)", "", line)
                for line in text.splitlines(keepends=True)
            )
        rel = relative_path(path, root) or str(path)
        for match in build_key_pattern.finditer(text):
            value = _clean_build_value(match.group(2))
            declared.setdefault(match.group(1), []).append(
                {
                    "file": rel,
                    "value": value,
                    "scope": None,
                    "origin": "build-setting",
                }
            )
    return declared


def scan(context: ScanContext) -> dict:
    result = new_result("scan_permissions")
    root = context.root
    scope_model = _scope_model(root)
    corpus = [
        (path, text)
        for path, text in code_corpus(root)
        if _bundle_scope(path, root, scope_model) != "nonshipping"
    ]
    declared = _declared_purposes(root, scope_model)
    used: dict[str, list[dict]] = {}
    for key, pattern in PERMISSIONS.items():
        hits = find_matches(corpus, pattern, root)
        used[key] = hits
        missing_hits = []
        for item in hits:
            hit_scope = _bundle_scope(item["path"], root, scope_model)
            matching = [
                entry
                for entry in declared.get(key, [])
                if _usable_purpose(entry["value"])
                and (
                    entry["scope"] is None
                    or entry["scope"] == hit_scope
                    or (
                        hit_scope == "shared:framework"
                        and isinstance(entry["scope"], str)
                        and entry["scope"].startswith("app:")
                    )
                )
            ]
            if not matching:
                missing_hits.append(item)
        if missing_hits:
            first = missing_hits[0]
            result["findings"].append(
                make_finding(
                    base_id="PERMISSION-USAGE-DESCRIPTION-NOT-DETECTED",
                    severity="High",
                    confidence="Medium",
                    verification="Possible",
                    area="Permissions",
                    title=f"Protected API signal without a detected purpose string: {key}",
                    problem=f"Detected {len(missing_hits)} protected-resource API signal(s) without a non-empty {key} value in the same inferred bundle scope or an explicit generated Info.plist setting.",
                    evidence_items=[match_evidence(item, key) for item in missing_hits[:5]],
                    file=first["file"],
                    line=first["line"],
                    source_id="ARG-5.1.1",
                    risk_reason="Accessing protected data without the required purpose string can fail at runtime and does not meet Apple's clear-disclosure requirement.",
                    remediation=f"Confirm the feature uses this resource and add a truthful, localized {key} value to the actual app target.",
                    verification_steps=["Inspect the built Info.plist.", "Trigger the permission from a clean install and verify the system alert copy."],
                    limitations=["Generated Info.plist settings, dependency manifests, or target membership may not be visible statically."],
                    heuristic=True,
                    id_detail=key,
                )
            )
        for entry in declared.get(key, []):
            file, value = entry["file"], entry["value"]
            if isinstance(value, str) and value.strip() and GENERIC_PURPOSE.match(value.strip()):
                result["findings"].append(
                    make_finding(
                        base_id="PERMISSION-PURPOSE-GENERIC",
                        severity="Medium",
                        confidence="Medium",
                        verification="Likely",
                        area="Permissions",
                        title=f"Permission purpose string appears generic: {key}",
                        problem=f"The value {value!r} does not explain the feature-specific how and why.",
                        evidence_items=[evidence(kind="plist-value", value=f"{key}={value!r}", file=file)],
                        file=file,
                        source_id="HIG-PRIVACY",
                        risk_reason="Generic copy may not clearly and completely describe the protected-data use.",
                        remediation="Replace the generic wording with a concise explanation of the user-facing feature, data use, and benefit.",
                        verification_steps=["Review the localized prompt on device.", "Confirm the text matches actual collection and sharing behavior."],
                        autofix_available=True,
                        autofix_notes="Only apply user-approved truthful copy; do not invent the purpose.",
                        limitations=["Copy quality requires human judgment."],
                        heuristic=True,
                        id_detail=key,
                    )
                )
        hit_scopes = {_bundle_scope(item["path"], root, scope_model) for item in hits}
        for entry in declared.get(key, []):
            if entry["scope"] is None or not _usable_purpose(entry["value"]):
                continue
            if entry["scope"] not in hit_scopes and "shared:framework" not in hit_scopes:
                result["findings"].append(
                    make_finding(
                        base_id="PERMISSION-DECLARED-NOT-DETECTED-IN-USE",
                        severity="Low",
                        confidence="Low",
                        verification="Possible",
                        area="Permissions",
                        title=f"Declared permission has no detected source use: {key}",
                        problem="A purpose string exists, but the matching API use was not found in the scanned source tree.",
                        evidence_items=[evidence(kind="plist-value", value=f"{key}={entry['value']!r}", file=entry["file"])],
                        file=entry["file"],
                        source_id="ARG-5.1.1",
                        risk_reason="Unused permission declarations can create unnecessary privacy concern and may reflect stale configuration.",
                        remediation="Confirm release-binary usage; remove the key only if the app and all linked SDKs do not access the resource.",
                        verification_steps=["Search the built dependency graph and exercise the relevant feature.", "Remove only after a clean-device regression test."],
                        limitations=["Binary SDKs, generated code, reflection, and alternate target sources may use the permission."],
                        heuristic=True,
                        id_detail=key,
                    )
                )
    result["facts"] = {
        "declared_permission_keys": sorted(declared),
        "declared_purposes": {
            key: [
                {
                    "file": entry["file"],
                    "scope": entry["scope"] or "unmapped-build-setting",
                    "origin": entry["origin"],
                    "has_usable_value": _usable_purpose(entry["value"]),
                }
                for entry in entries
            ]
            for key, entries in declared.items()
        },
        "api_signal_counts": {key: len(value) for key, value in used.items()},
        "scope_model": {
            "cross_stack": scope_model["cross_stack"],
            "ios_app_roots": sorted(scope_model["ios_app_roots"]),
            "primary_alias_safe": scope_model["primary_alias_safe"],
        },
    }
    has_unmapped_scope = any(
        entry["scope"] is None
        for entries in declared.values()
        for entry in entries
    ) or any(
        _bundle_scope(item["path"], root, scope_model) in {None, "shared:framework"}
        for values in used.values()
        for item in values
    )
    result["checks"].append(
        check(
            "permissions.target-mapping",
            "Permissions",
            "Not verified" if has_unmapped_scope else "Passed",
            "Root/generated settings or shared framework sources could not be mapped to exactly one native app target; resolved build settings are required."
            if has_unmapped_scope
            else "Source purpose declarations were compared using inferred app/extension path scopes.",
            source_id="ARG-5.1.1",
        )
    )
    result["checks"].append(
        check(
            "permissions.cross-check",
            "Permissions",
            "Failed" if any(item.get("severity") in {"Critical", "High", "Medium"} for item in result["findings"]) else "Passed",
            f"Cross-checked {len(PERMISSIONS)} protected-resource categories; detected {sum(item.get('severity') in {'Critical', 'High', 'Medium'} for item in result['findings'])} material static finding(s).",
            source_id="ARG-5.1.1",
        )
    )
    result["checks"].append(
        check(
            "permissions.runtime-prompts",
            "Permissions",
            "Not verified",
            "Permission timing, denial behavior, prompt localization, and clean-install behavior require runtime testing.",
            source_id="HIG-PRIVACY",
        )
    )
    return finish_result(result)


if __name__ == "__main__":
    raise SystemExit(scanner_cli(scan, "scan_permissions"))
