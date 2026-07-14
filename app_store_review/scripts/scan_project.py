#!/usr/bin/env python3
"""Detect iOS targets and the project technology stack."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from audit_core import (
    ScanContext,
    check,
    code_corpus,
    evidence,
    finish_result,
    iter_files,
    make_finding,
    new_result,
    read_text,
    relative_path,
    scanner_cli,
)


def _load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def _workspace_directories(root: Path) -> list[Path]:
    excluded = {".git", ".build", "build", "DerivedData", "node_modules", "Pods", "Carthage", ".dart_tool", ".expo", "dist", "coverage"}
    found: list[Path] = []
    for current, dirs, _ in os.walk(root):
        kept = []
        for directory in sorted(dirs):
            if directory in excluded:
                continue
            if directory.endswith(".xcworkspace"):
                found.append(Path(current) / directory)
                continue
            kept.append(directory)
        dirs[:] = kept
    return sorted(found)


def scan(context: ScanContext) -> dict:
    result = new_result("scan_project")
    root = context.root
    xcode_projects = sorted(iter_files(root, names={"project.pbxproj"}))
    workspaces = _workspace_directories(root)
    package_swift = list(iter_files(root, names={"Package.swift"}))
    podfiles = list(iter_files(root, names={"Podfile", "Podfile.lock"}))
    pubspecs = list(iter_files(root, names={"pubspec.yaml", "pubspec.yml"}))
    package_jsons = list(iter_files(root, names={"package.json"}))
    capacitor_configs = list(
        iter_files(root, names={"capacitor.config.ts", "capacitor.config.js", "capacitor.config.json"})
    )
    corpus = code_corpus(root)
    extensions = {path.suffix.lower() for path, _ in corpus}

    stacks: set[str] = set()
    if xcode_projects or workspaces:
        stacks.add("Xcode")
    if ".swift" in extensions:
        stacks.add("Swift")
    if any("import SwiftUI" in text for _, text in corpus):
        stacks.add("SwiftUI")
    if any("import UIKit" in text or "#import <UIKit" in text for _, text in corpus):
        stacks.add("UIKit")
    if package_swift:
        stacks.add("Swift Package Manager")
    if podfiles:
        stacks.add("CocoaPods")
    if pubspecs:
        stacks.add("Flutter")
    if capacitor_configs:
        stacks.add("Capacitor")
    for package_json in package_jsons:
        payload = _load_json(package_json)
        deps = {**payload.get("dependencies", {}), **payload.get("devDependencies", {})}
        if "react-native" in deps:
            stacks.add("React Native")
        if "expo" in deps:
            stacks.add("Expo native iOS")
        if "@capacitor/ios" in deps or "@capacitor/core" in deps:
            stacks.add("Capacitor")

    target_names: list[str] = []
    ios_signal_kinds: set[str] = set()
    for project_file in xcode_projects:
        text = next((value for path, value in corpus if path == project_file), read_text(project_file) or "")
        target_names.extend(re.findall(r"PBXNativeTarget[^\n]*|name\s*=\s*([^;]+);", text)[:50])
        if re.search(r"SDKROOT\s*=\s*iphoneos|IPHONEOS_DEPLOYMENT_TARGET|SUPPORTED_PLATFORMS[^;]*(?:iphoneos|iphonesimulator)|TARGETED_DEVICE_FAMILY\s*=\s*['\"]?[12](?:[,\s]|['\";])", text):
            ios_signal_kinds.add("xcode-ios-build-settings")
    if any(path.is_dir() and path.name.lower() == "ios" for path in root.iterdir()):
        ios_signal_kinds.add("native-ios-directory")
    if any(re.search(r"(?:import|@import)\s+UIKit|#import\s*[<\"]UIKit", text) for _, text in corpus):
        ios_signal_kinds.add("uikit-source")
    for package_file in package_swift:
        package_text = next((value for path, value in corpus if path == package_file), read_text(package_file) or "")
        if re.search(r"\.iOS\s*\(", package_text):
            ios_signal_kinds.add("swift-package-ios-platform")

    result["facts"] = {
        "stacks": sorted(stacks),
        "xcode_projects": [relative_path(path, root) for path in xcode_projects],
        "workspaces": [relative_path(path, root) for path in workspaces],
        "package_managers": sorted(stacks & {"Swift Package Manager", "CocoaPods"}),
        "ios_target_detected": bool(ios_signal_kinds),
        "ios_signal_kinds": sorted(ios_signal_kinds),
        "target_name_hints": sorted({name.strip().strip('"') for name in target_names if isinstance(name, str) and name.strip()})[:30],
    }
    if ios_signal_kinds:
        result["checks"].append(
            check(
                "project.ios-target",
                "Project configuration",
                "Passed",
                "Detected an iOS-capable target or native iOS source tree.",
                evidence_items=[
                    evidence(
                        kind="inventory",
                        value="Detected stacks: " + (", ".join(sorted(stacks)) or "unknown native iOS"),
                    )
                ],
            )
        )
    else:
        result["checks"].append(
            check(
                "project.ios-target",
                "Project configuration",
                "Not verified",
                "No iOS target could be established from repository markers.",
                evidence_items=[evidence(kind="inventory", value="No native iOS project marker detected")],
            )
        )
        result["findings"].append(
            make_finding(
                base_id="IOS-TARGET-NOT-DETECTED",
                severity="Low",
                confidence="Low",
                verification="Not verified",
                area="Project configuration",
                title="iOS target not detected",
                problem="Static inventory did not locate an Xcode target or recognizable native iOS directory.",
                evidence_items=[evidence(kind="inventory", value="No iOS target marker")],
                source_id="ARG-2.1",
                risk_reason="The audit cannot establish which binary and configuration Apple would review.",
                remediation="Provide the actual repository root or generated native iOS project, then rerun the audit.",
                verification_steps=["Confirm the .xcodeproj/.xcworkspace or generated ios directory is present.", "Rerun scan_project.py."],
                limitations=["Generated projects may be created only during CI or framework prebuild."],
                heuristic=True,
            )
        )

    webview_hits = []
    interactive_hits = []
    for path, text in corpus:
        if re.search(r"WKWebView|UIWebView|react-native-webview|InAppWebView|webview_flutter", text, re.I):
            webview_hits.append((path, text))
        if re.search(r"StoreKit|MapKit|CoreLocation|AVFoundation|Camera|PhotosPicker|push notification|share sheet", text, re.I):
            interactive_hits.append((path, text))
    if webview_hits and not interactive_hits:
        first = webview_hits[0][0]
        result["findings"].append(
            make_finding(
                base_id="MINIMUM-FUNCTIONALITY-WEBVIEW",
                severity="Medium",
                confidence="Low",
                verification="Possible",
                area="Minimum functionality",
                title="WebView-heavy app may need a stronger native value case",
                problem="WebView integration was detected without clear static evidence of native or independently interactive functionality.",
                evidence_items=[
                    evidence(
                        kind="source-match",
                        value="WebView implementation",
                        file=relative_path(first, root),
                    )
                ],
                file=relative_path(first, root),
                source_id="ARG-4.2",
                risk_reason="Apple assesses whether an app rises above a repackaged website or thin client.",
                remediation="Document the app's standalone, app-like value and verify the complete experience manually on device.",
                verification_steps=["Review every primary route on device.", "List native or independently interactive capabilities in App Review Notes when non-obvious."],
                limitations=["Minimum functionality is subjective; static code cannot measure utility, content quality, or lasting value."],
                heuristic=True,
            )
        )
    result["checks"].append(
        check(
            "project.minimum-functionality",
            "Minimum functionality",
            "Not verified" if webview_hits else "Passed",
            "Minimum functionality requires product-level and on-device judgment." if webview_hits else "No WebView-only signal was detected; product value still requires manual review.",
            source_id="ARG-4.2",
        )
    )
    return finish_result(result)


if __name__ == "__main__":
    raise SystemExit(scanner_cli(scan, "scan_project"))
