#!/usr/bin/env python3
"""Inventory dependencies and flag privacy-manifest review needs."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from audit_core import (
    ScanContext,
    check,
    evidence,
    finish_result,
    iter_files,
    make_finding,
    new_result,
    read_text,
    relative_path,
    scanner_cli,
)


APPLE_LISTED_SDKS = {
    name.lower()
    for name in (
        "Abseil AFNetworking Alamofire AppAuth BoringSSL openssl_grpc Capacitor Charts connectivity_plus Cordova device_info_plus "
        "DKImagePickerController DKPhotoGallery FBAEMKit FBLPromises FBSDKCoreKit FBSDKCoreKit_Basics FBSDKLoginKit FBSDKShareKit "
        "file_picker FirebaseABTesting FirebaseAuth FirebaseCore FirebaseCoreDiagnostics FirebaseCoreExtension FirebaseCoreInternal "
        "FirebaseCrashlytics FirebaseDynamicLinks FirebaseFirestore FirebaseInstallations FirebaseMessaging FirebaseRemoteConfig Flutter "
        "flutter_inappwebview flutter_local_notifications fluttertoast FMDB geolocator_apple GoogleDataTransport GoogleSignIn "
        "GoogleToolboxForMac GoogleUtilities grpcpp GTMAppAuth GTMSessionFetcher hermes image_picker_ios IQKeyboardManager "
        "IQKeyboardManagerSwift Kingfisher leveldb Lottie MBProgressHUD nanopb OneSignal OneSignalCore OneSignalExtension OneSignalOutcomes "
        "OpenSSL OrderedSet package_info package_info_plus path_provider path_provider_ios Promises Protobuf Reachability RealmSwift RxCocoa "
        "RxRelay RxSwift SDWebImage share_plus shared_preferences_ios SnapKit sqflite Starscream SVProgressHUD SwiftyGif SwiftyJSON Toast "
        "UnityFramework url_launcher url_launcher_ios video_player_avfoundation wakelock webview_flutter_wkwebview"
    ).split()
}

DATA_SDK_HINTS = re.compile(r"analytics|crash|firebase|facebook|adjust|appsflyer|segment|mixpanel|amplitude|onesignal|ads?|tracking|sentry", re.I)


def _walk_json(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in {"identity", "name", "package", "packageidentity"} and isinstance(child, str):
                yield child
            yield from _walk_json(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_json(child)


def _dependency_inventory(root: Path) -> tuple[dict[str, set[str]], list[dict]]:
    inventory: dict[str, set[str]] = {}
    evidence_items: list[dict] = []
    candidates = list(
        iter_files(
            root,
            names={"Package.swift", "Package.resolved", "Podfile", "Podfile.lock", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "pubspec.yaml", "pubspec.lock"},
            max_size=5_000_000,
        )
    )
    for path in candidates:
        rel = relative_path(path, root) or str(path)
        names: set[str] = set()
        text = read_text(path) or ""
        if path.name in {"package.json", "package-lock.json"}:
            try:
                payload = json.loads(text)
                if path.name == "package.json":
                    for key in ("dependencies", "devDependencies", "peerDependencies"):
                        names.update((payload.get(key) or {}).keys())
                else:
                    names.update((payload.get("dependencies") or {}).keys())
                    for package_path in (payload.get("packages") or {}):
                        if "node_modules/" in package_path:
                            names.add(package_path.rsplit("node_modules/", 1)[1])
            except ValueError:
                pass
        elif path.name == "Package.resolved":
            try:
                names.update(_walk_json(json.loads(text)))
            except ValueError:
                pass
        elif path.name == "Podfile.lock":
            for match in re.finditer(r"^\s{0,4}-\s+([A-Za-z0-9_+.-]+)(?:\s|/|\()", text, re.M):
                names.add(match.group(1))
        elif path.name == "Podfile":
            names.update(re.findall(r"pod\s+['\"]([^'\"]+)", text))
        elif path.name == "Package.swift":
            names.update(re.findall(r"(?:package|product)\s*\(\s*name\s*:\s*['\"]([^'\"]+)", text))
            names.update(Path(value).stem for value in re.findall(r"url\s*:\s*['\"]([^'\"]+)", text))
        elif path.name == "yarn.lock":
            for match in re.finditer(r"^(?:['\"])?((?:@[^/\s]+/)?[^@\s'\"]+)@[^:]+:", text, re.M):
                names.add(match.group(1))
        elif path.name == "pnpm-lock.yaml":
            for match in re.finditer(r"^\s{2,}['\"]?(?:/)?((?:@[^/\s:'\"]+/)?[^@\s:'\"]+)@[^:\s'\"]+['\"]?:", text, re.M):
                names.add(match.group(1).strip("'\""))
        elif path.name == "pubspec.lock":
            names.update(re.findall(r"^\s{2}([A-Za-z0-9_+.-]+):\s*$", text, re.M))
        else:
            for match in re.finditer(r"^\s{0,4}([A-Za-z0-9_+.-]+):\s*(?:[\^~<>=0-9]|$)", text, re.M):
                names.add(match.group(1))
        normalized = {
            (name if name.startswith("@") else name.split("/")[0]).strip()
            for name in names
            if name and not name.startswith("$")
        }
        inventory[rel] = normalized
        if normalized:
            evidence_items.append(evidence(kind="dependency-file", value=f"{len(normalized)} dependencies", file=rel))
    return inventory, evidence_items


def _dependency_versions(root: Path) -> tuple[dict[str, set[str]], dict[str, list[dict]]]:
    versions: dict[str, set[str]] = {}
    by_file: dict[str, list[dict]] = {}

    def add(path: Path, name: str, version: object) -> None:
        if not name or version in (None, ""):
            return
        clean_name = name.split("/")[0] if not name.startswith("@") else name
        clean_version = str(version).strip()
        versions.setdefault(clean_name, set()).add(clean_version)
        rel = relative_path(path, root) or str(path)
        entry = {"name": clean_name, "version_or_constraint": clean_version}
        if entry not in by_file.setdefault(rel, []):
            by_file[rel].append(entry)

    candidates = list(
        iter_files(
            root,
            names={"Package.swift", "Package.resolved", "Podfile.lock", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "pubspec.lock"},
            max_size=10_000_000,
        )
    )
    for path in candidates:
        text = read_text(path) or ""
        if path.name == "Podfile.lock":
            for match in re.finditer(r"^\s{0,4}-\s+([A-Za-z0-9_+.-]+)(?:/[^\s(]+)?\s+\(([^)]+)\)", text, re.M):
                add(path, match.group(1), match.group(2))
        elif path.name == "package.json":
            try:
                payload = json.loads(text)
                for key in ("dependencies", "devDependencies", "peerDependencies"):
                    for name, version in (payload.get(key) or {}).items():
                        add(path, name, version)
            except (ValueError, AttributeError):
                pass
        elif path.name == "package-lock.json":
            try:
                payload = json.loads(text)
                for name, item in (payload.get("dependencies") or {}).items():
                    if isinstance(item, dict):
                        add(path, name, item.get("version"))
                for package_path, item in (payload.get("packages") or {}).items():
                    if "node_modules/" in package_path and isinstance(item, dict):
                        add(path, package_path.rsplit("node_modules/", 1)[1], item.get("version"))
            except (ValueError, AttributeError):
                pass
        elif path.name == "Package.resolved":
            try:
                payload = json.loads(text)
                pins = payload.get("pins") or payload.get("object", {}).get("pins") or []
                for pin in pins:
                    if not isinstance(pin, dict):
                        continue
                    state = pin.get("state") or {}
                    version = state.get("version") or state.get("revision") or state.get("branch")
                    add(path, pin.get("identity") or pin.get("package") or pin.get("name"), version)
            except (ValueError, AttributeError):
                pass
        elif path.name == "Package.swift":
            for match in re.finditer(r"url\s*:\s*['\"]([^'\"]+)['\"]\s*,\s*(?:from|exact)\s*:\s*['\"]([^'\"]+)['\"]", text):
                add(path, Path(match.group(1)).stem, match.group(2))
        elif path.name == "yarn.lock":
            current: list[str] = []
            for line in text.splitlines():
                header = re.match(r"^(?:['\"])?(.+?)(?:['\"])?\s*:\s*$", line)
                if header and not line.startswith((" ", "\t")):
                    current = []
                    for selector in header.group(1).split(","):
                        selector = selector.strip().strip("'\"")
                        name_match = re.match(r"((?:@[^/]+/)?[^@]+)@", selector)
                        if name_match:
                            current.append(name_match.group(1))
                    continue
                version_match = re.match(r"^\s+version\s+['\"]([^'\"]+)['\"]", line)
                if version_match:
                    for name in current:
                        add(path, name, version_match.group(1))
        elif path.name == "pnpm-lock.yaml":
            for match in re.finditer(r"^\s{2,}['\"]?(?:/)?((?:@[^/\s:'\"]+/)?[^@\s:'\"]+)@([^:\s'\"]+)['\"]?:", text, re.M):
                add(path, match.group(1).strip("'\""), match.group(2).strip("'\""))
        elif path.name == "pubspec.lock":
            current = None
            for line in text.splitlines():
                package_match = re.match(r"^\s{2}([A-Za-z0-9_+.-]+):\s*$", line)
                if package_match:
                    current = package_match.group(1)
                    continue
                version_match = re.match(r"^\s{4}version:\s*['\"]?([^'\"\s]+)", line)
                if current and version_match:
                    add(path, current, version_match.group(1))
    return versions, by_file


def _dependency_manifests(root: Path) -> tuple[list[Path], bool]:
    manifests = set(iter_files(root, suffixes={".xcprivacy"}))
    resolved_roots = []
    for base in (root, root / "ios"):
        resolved_roots.extend(
            [
                base / "Pods",
                base / "Carthage",
                base / ".build" / "checkouts",
                base / ".build" / "artifacts",
            ]
        )
    resolved_roots.extend(
        [
            root / "node_modules",
            root / "SourcePackages" / "checkouts",
        ]
    )
    resolved_roots = list(dict.fromkeys(path.resolve() for path in resolved_roots))
    skipped_dirs = {".git", "Tests", "Test", "UITests", "Examples", "Example", "docs", "Documentation", "Headers"}
    visited_directories = 0
    truncated = False
    for dependency_root in resolved_roots:
        if not dependency_root.is_dir():
            continue
        for current, dirs, files in os.walk(dependency_root):
            visited_directories += 1
            if visited_directories > 25_000 or len(manifests) >= 2_000:
                dirs[:] = []
                truncated = True
                break
            dirs[:] = [name for name in dirs if name not in skipped_dirs]
            for filename in files:
                if not filename.lower().endswith(".xcprivacy"):
                    continue
                path = Path(current) / filename
                try:
                    if not path.is_symlink() and path.stat().st_size <= 2_000_000:
                        manifests.add(path)
                except OSError:
                    continue
    return sorted(manifests), truncated


def _manifest_map(manifests: list[Path], sdk_names: list[str], root: Path) -> dict[str, list[str]]:
    mapped: dict[str, list[str]] = {name: [] for name in sdk_names}
    for manifest in manifests:
        rel = Path(relative_path(manifest, root) or str(manifest))
        path_parts = [re.sub(r"[^a-z0-9]", "", part.lower()) for part in rel.parts[:-1]]
        for sdk in sdk_names:
            normalized = re.sub(r"[^a-z0-9]", "", sdk.lower())
            if normalized and any(normalized in part for part in path_parts):
                mapped[sdk].append(str(rel))
    return mapped


def scan(context: ScanContext) -> dict:
    result = new_result("scan_dependencies")
    root = context.root
    inventory, inventory_evidence = _dependency_inventory(root)
    versions, versions_by_file = _dependency_versions(root)
    all_names = sorted({name for names in inventory.values() for name in names}, key=str.lower)
    listed = sorted({name for name in all_names if name.lower() in APPLE_LISTED_SDKS}, key=str.lower)
    data_hints = sorted({name for name in all_names if DATA_SDK_HINTS.search(name)}, key=str.lower)
    manifests, manifest_discovery_truncated = _dependency_manifests(root)
    manifest_map = _manifest_map(manifests, listed, root)
    missing_sdk_manifests = [name for name in listed if not manifest_map.get(name)]
    if missing_sdk_manifests:
        result["findings"].append(
            make_finding(
                base_id="PRIVACY-MANIFEST-SDK-NOT-DETECTED",
                severity="Medium",
                confidence="Low",
                verification="Possible",
                area="Third-party dependencies",
                title="Apple-listed SDK dependency without a dependency-specific source-visible privacy manifest",
                problem=f"No manifest path attributable to these Apple-listed SDK names was found: {missing_sdk_manifests}. App-level manifests do not satisfy an SDK's own manifest requirement.",
                evidence_items=inventory_evidence[:8] + [evidence(kind="dependency-list", value=", ".join(missing_sdk_manifests))],
                source_id="THIRD-PARTY-SDK",
                risk_reason="Covered SDKs require their own valid privacy manifest, and covered binary SDKs may also require a valid signature.",
                remediation="Resolve the exact release dependency versions, inspect each SDK bundle for its own manifest and signature, and update or replace noncompliant packages.",
                verification_steps=["Generate the Xcode archive privacy report.", "Inspect each framework/package bundle in the archive.", "Recheck Apple's live SDK list before submission."],
                limitations=["A manifest may be supplied only after dependency resolution or inside a binary artifact.", "An app-level manifest does not substitute for an SDK's own required manifest.", "Dependency names do not prove runtime data access."],
                heuristic=True,
                id_detail=",".join(missing_sdk_manifests),
            )
        )
    if data_hints:
        result["findings"].append(
            make_finding(
                base_id="DEPENDENCY-DATA-PRACTICES-MANUAL-REVIEW",
                severity="Informational",
                confidence="Low",
                verification="Not verified",
                area="Third-party dependencies",
                title="Dependencies may require privacy-practice reconciliation",
                problem=f"Names suggesting analytics, diagnostics, advertising, messaging, or attribution were detected: {data_hints}.",
                evidence_items=[evidence(kind="dependency-list", value=", ".join(data_hints))],
                source_id="ASC-APP-PRIVACY",
                risk_reason="App Privacy answers and the privacy policy must cover actual third-party collection and sharing.",
                remediation="Review vendor documentation and observed release behavior; reconcile the privacy manifest, App Privacy answers, consent, and privacy policy.",
                verification_steps=["Inspect SDK initialization and configuration.", "Capture a release-build network trace with relevant consent states.", "Compare to vendor privacy documentation."],
                limitations=["The finding makes no claim that a named SDK collects or transmits data in this app."],
                heuristic=True,
                id_detail=",".join(data_hints),
            )
        )
    result["facts"] = {
        "dependency_files": {path: sorted(names, key=str.lower) for path, names in inventory.items()},
        "dependency_count": len(all_names),
        "dependency_versions": {name: sorted(values) for name, values in sorted(versions.items())},
        "dependency_version_evidence": {path: sorted(entries, key=lambda item: (item["name"].lower(), item["version_or_constraint"])) for path, entries in versions_by_file.items()},
        "apple_listed_sdk_names": listed,
        "data_practice_review_hints": data_hints,
        "privacy_manifests_seen": [relative_path(path, root) for path in manifests],
        "dependency_manifest_discovery_truncated": manifest_discovery_truncated,
        "privacy_manifests_by_listed_sdk": {
            name: paths
            for name, paths in manifest_map.items()
        },
    }
    result["checks"].extend(
        [
            check(
                "dependencies.inventory",
                "Third-party dependencies",
                "Passed" if inventory else "Not verified",
                f"Inventoried {len(all_names)} dependency name(s) from {len(inventory)} manifest/lockfile(s)."
                if inventory
                else "No supported dependency manifest or lockfile was found.",
            ),
            check(
                "dependencies.sdk-privacy-manifests",
                "Third-party dependencies",
                "Failed" if missing_sdk_manifests else ("Not verified" if listed else "Not applicable"),
                f"Dependency-specific source manifests were not established for: {missing_sdk_manifests}."
                if missing_sdk_manifests
                else "Dependency manifest discovery hit its safety bound; mapped manifests require archive confirmation."
                if manifest_discovery_truncated
                else "Source-visible manifest paths were mapped, but archive bundle inclusion/signatures remain unverified."
                if listed
                else "No Apple-listed SDK name was detected in supported dependency files.",
                applicable=bool(listed),
                source_id="THIRD-PARTY-SDK",
            ),
            check(
                "dependencies.binary-bundles",
                "Third-party dependencies",
                "Not verified",
                "Binary SDK signatures, embedded manifests, prohibited behavior, and actual data access require the resolved release archive.",
                source_id="THIRD-PARTY-SDK",
            ),
            check(
                "dependencies.current-versions",
                "Third-party dependencies",
                "Not verified",
                "Outdated or prohibited SDK status was not asserted from names alone; verify versions against official vendor and Apple sources.",
                source_id="THIRD-PARTY-SDK",
            ),
        ]
    )
    return finish_result(result)


if __name__ == "__main__":
    raise SystemExit(scanner_cli(scan, "scan_dependencies"))
