#!/usr/bin/env python3
"""Inspect build configurations without building, signing, or resolving packages."""

from __future__ import annotations

import re
from pathlib import Path

from audit_core import (
    ScanContext,
    check,
    command_available,
    evidence,
    finish_result,
    iter_files,
    make_finding,
    new_result,
    read_text,
    relative_path,
    run_command,
    scanner_cli,
    strip_code_comments,
)


RELEASE_NAME = re.compile(r"release|prod(?:uction)?|app[ _-]?store|distribution", re.I)
DEBUG_NAME = re.compile(r"debug|dev(?:elopment)?", re.I)


def _configuration_objects(text: str) -> list[dict[str, str]]:
    objects = []
    for match in re.finditer(
        r"isa\s*=\s*XCBuildConfiguration;(?P<body>.*?)name\s*=\s*(?P<name>[^;]+);\s*\};",
        text,
        re.S,
    ):
        body = match.group("body")
        settings = re.search(r"buildSettings\s*=\s*\{(.*?)\};", body, re.S)
        objects.append(
            {
                "name": match.group("name").strip().strip('"'),
                "body": body,
                "settings": settings.group(1) if settings else "",
            }
        )
    return objects


def _archive_configurations(root: Path) -> tuple[list[str], list[str]]:
    names: set[str] = set()
    files: list[str] = []
    for path in iter_files(root, suffixes={".xcscheme"}, max_size=2_000_000):
        text = read_text(path) or ""
        names.update(re.findall(r"<ArchiveAction\b[^>]*\bbuildConfiguration\s*=\s*['\"]([^'\"]+)", text, re.I | re.S))
        files.append(relative_path(path, root) or str(path))
    return sorted(names), sorted(files)


def _strip_xcconfig_comments(text: str) -> str:
    output = []
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped.startswith("//") or (stripped.startswith("#") and not stripped.startswith(("#include", "#include?"))):
            output.append("\n" if line.endswith("\n") else "")
            continue
        output.append(re.sub(r"\s+//.*?(?=\r?\n|$)", "", line))
    return "".join(output)


def _resolve_xcconfig_tree(
    path: Path,
    root: Path,
    by_name: dict[str, list[Path]],
    visited: set[Path] | None = None,
) -> tuple[str, list[str], list[str]]:
    visited = visited or set()
    resolved = path.resolve()
    if resolved in visited:
        return "", [], [f"include cycle at {relative_path(path, root)}"]
    visited.add(resolved)
    text = read_text(path) or ""
    combined: list[str] = []
    used = [relative_path(path, root) or str(path)]
    unresolved: list[str] = []
    for line in text.splitlines(keepends=True):
        include_match = re.match(r"^\s*#include\??\s+['\"<]([^'\">]+)['\">]", line)
        if not include_match:
            combined.append(_strip_xcconfig_comments(line))
            continue
        include = include_match.group(1)
        if "$(" in include:
            unresolved.append(f"unresolved include variable: {include}")
            continue
        candidate = (path.parent / include).resolve()
        if not candidate.is_file():
            matches = by_name.get(Path(include).name.lower(), [])
            candidate = matches[0].resolve() if len(matches) == 1 else candidate
        if not candidate.is_file() or root.resolve() not in (candidate, *candidate.parents):
            unresolved.append(f"unresolved include: {include}")
            continue
        child_text, child_used, child_unresolved = _resolve_xcconfig_tree(
            candidate, root, by_name, visited
        )
        combined.append(child_text)
        used.extend(child_used)
        unresolved.extend(child_unresolved)
    return "\n".join(combined), used, unresolved


def _effective_debug_flag(text: str) -> bool:
    values: dict[str, set[str]] = {}
    pattern = re.compile(
        r"\b(SWIFT_ACTIVE_COMPILATION_CONDITIONS|GCC_PREPROCESSOR_DEFINITIONS)\s*=\s*([^;\n]+)"
    )
    for match in pattern.finditer(text):
        key = match.group(1)
        raw = match.group(2).replace("(", " ").replace(")", " ").replace('"', " ")
        inherited = "$(inherited)" in match.group(2)
        tokens = {
            token.strip(",")
            for token in raw.split()
            if token and token not in {"$", "inherited"}
        }
        values[key] = (values.get(key, set()) if inherited else set()) | tokens
    return any(token == "DEBUG" or token.startswith("DEBUG=") for tokens in values.values() for token in tokens)


def _release_xcconfigs(
    root: Path,
    all_text: str,
    release_objects: list[dict[str, str]],
) -> list[dict]:
    paths = list(iter_files(root, suffixes={".xcconfig"}, max_size=5_000_000))
    by_name: dict[str, list[Path]] = {}
    for path in paths:
        by_name.setdefault(path.name.lower(), []).append(path)
    file_refs = {
        match.group(1): match.group(2).strip().strip('"')
        for match in re.finditer(
            r"([A-Za-z0-9_]+)(?:\s*/\*.*?\*/)?\s*=\s*\{[^{}]*?isa\s*=\s*PBXFileReference;[^{}]*?path\s*=\s*([^;]+);",
            all_text,
            re.S,
        )
    }
    records: list[dict] = []
    for index, config in enumerate(release_objects, start=1):
        selected: Path | None = None
        unresolved: list[str] = []
        ref = re.search(
            r"baseConfigurationReference\s*=\s*([A-Za-z0-9_]+)(?:\s*/\*\s*(.*?)\s*\*/)?\s*;",
            config["body"],
            re.S,
        )
        if ref:
            hinted = (ref.group(2) or file_refs.get(ref.group(1), "")).strip()
            matches = by_name.get(Path(hinted).name.lower(), []) if hinted else []
            if len(matches) == 1:
                selected = matches[0]
            else:
                release_like = [path for path in paths if RELEASE_NAME.search(path.stem)]
                if len(release_like) == 1:
                    selected = release_like[0]
                    unresolved.append(
                        f"inferred {release_like[0].name} for unresolved baseConfigurationReference {ref.group(1)}"
                    )
                else:
                    unresolved.append(
                        f"unresolved baseConfigurationReference {ref.group(1)}"
                    )
        resolved_text = ""
        used: list[str] = []
        if selected is not None:
            resolved_text, used, errors = _resolve_xcconfig_tree(selected, root, by_name)
            unresolved.extend(errors)
        records.append(
            {
                "name": config["name"],
                "object": f"{config['name']}#{index}",
                "xcconfig_text": resolved_text,
                "files": sorted(set(used)),
                "unresolved": sorted(set(unresolved)),
                "debug": _effective_debug_flag("\n".join([resolved_text, config["settings"]])),
            }
        )
    return records


def scan(context: ScanContext) -> dict:
    result = new_result("scan_build_configuration")
    root = context.root
    project_files = list(iter_files(root, names={"project.pbxproj"}))
    all_text = "\n".join(strip_code_comments(read_text(path) or "") for path in project_files)
    configuration_objects = _configuration_objects(all_text)
    configurations = sorted({item["name"] for item in configuration_objects})
    archive_configurations, scheme_files = _archive_configurations(root)
    release_names = sorted(
        {
            name
            for name in configurations
            if RELEASE_NAME.search(name) or name in archive_configurations
        }
    )
    debug_names = sorted({name for name in configurations if DEBUG_NAME.search(name)})
    release_objects = [item for item in configuration_objects if item["name"] in release_names]
    release_evaluations = _release_xcconfigs(
        root, all_text, release_objects
    )
    release_xcconfig_files = sorted(
        {path for item in release_evaluations for path in item["files"]}
    )
    unresolved_xcconfigs = sorted(
        {
            f"{item['object']}: {message}"
            for item in release_evaluations
            for message in item["unresolved"]
        }
    )
    debug_release_evaluations = [item for item in release_evaluations if item["debug"]]
    all_xcconfig_text = "\n".join(
        _strip_xcconfig_comments(read_text(path) or "")
        for path in iter_files(root, suffixes={".xcconfig"}, max_size=5_000_000)
    )
    settings_text = "\n".join([all_text, all_xcconfig_text])
    deployment_targets = sorted(set(re.findall(r"IPHONEOS_DEPLOYMENT_TARGET\s*=\s*([^;\s]+)", settings_text)))
    sdk_roots = sorted(set(re.findall(r"SDKROOT\s*=\s*([^;\s]+)", settings_text)))
    result["facts"].update(
        {
            "configurations": configurations,
            "debug_configurations": debug_names,
            "release_configurations": release_names,
            "archive_configurations": archive_configurations,
            "scheme_files": scheme_files,
            "release_xcconfig_files": release_xcconfig_files,
            "unresolved_release_xcconfigs": unresolved_xcconfigs,
            "release_configuration_evaluation": [
                {
                    "configuration_object": item["object"],
                    "xcconfig_files": item["files"],
                    "xcconfig_resolution": "Not verified" if item["unresolved"] else "Resolved",
                    "effective_debug": item["debug"],
                }
                for item in release_evaluations
            ],
            "deployment_targets": deployment_targets,
            "sdk_roots": sdk_roots,
            "project_files": [relative_path(path, root) for path in project_files],
        }
    )
    if not project_files:
        result["checks"].append(
            check(
                "build.project-settings",
                "Project configuration",
                "Not verified",
                "No project.pbxproj was available; build settings may be generated by the framework toolchain.",
            )
        )
    else:
        complete = bool(debug_names and release_names)
        if not complete:
            result["findings"].append(
                make_finding(
                    base_id="BUILD-CONFIGURATION-MISSING",
                    severity="High",
                    confidence="Medium",
                    verification="Likely",
                    area="Project configuration",
                    title="Expected debug and archive/release configurations not established",
                    problem=f"Detected configurations: {configurations or 'none'}; archive actions: {archive_configurations or 'none'}.",
                    evidence_items=[evidence(kind="build-setting", value=f"Configurations: {configurations or 'none'}")],
                    source_id="ARG-2.1",
                    risk_reason="The audit cannot verify the configuration that will produce the submission binary.",
                    remediation="Create or expose a Release configuration and ensure the archive scheme uses it.",
                    verification_steps=["Open scheme Archive action and confirm Release configuration.", "Rerun this scanner."],
                    limitations=["Framework-generated projects may materialize configurations only after prebuild."],
                    heuristic=True,
                )
            )
        debug_release = bool(debug_release_evaluations)
        if debug_release:
            debug_objects = [item["object"] for item in debug_release_evaluations]
            debug_resolution_incomplete = any(item["unresolved"] for item in debug_release_evaluations)
            result["findings"].append(
                make_finding(
                    base_id="RELEASE-DEBUG-FLAG",
                    severity="Medium",
                    confidence="Low" if debug_resolution_incomplete else "Medium",
                    verification="Possible" if debug_resolution_incomplete else "Likely",
                    area="Project configuration",
                    title="DEBUG condition appears in a Release build settings block",
                    problem="At least one shipping/archive configuration object has an effective DEBUG compilation condition.",
                    evidence_items=[evidence(kind="build-setting", value=f"DEBUG in release configuration object(s): {debug_objects}")],
                    source_id="ARG-2.1",
                    risk_reason="Debug-only endpoints, menus, or behavior can leak into the submission binary.",
                    remediation="Remove DEBUG from the Release compilation conditions and confirm release-only service configuration.",
                    verification_steps=["Inspect Release SWIFT_ACTIVE_COMPILATION_CONDITIONS and preprocessor definitions.", "Archive and smoke-test the exact release build."],
                    limitations=["Build-setting inheritance remains heuristic; confirm the resolved Archive action settings."],
                    heuristic=True,
                )
            )
        configuration_failed = (not complete) or bool(debug_release)
        result["checks"].append(
            check(
                "build.configurations",
                "Project configuration",
                "Failed" if configuration_failed else "Passed",
                f"Detected debug configurations {debug_names or 'none'}, release/archive configurations {release_names or 'none'}, and {len(debug_release_evaluations)} Release DEBUG configuration object(s).",
                evidence_items=[evidence(kind="build-setting", value=f"Configurations: {configurations}; Archive: {archive_configurations}")],
            )
        )
        if any("baseConfigurationReference" in item["body"] for item in release_objects):
            result["checks"].append(
                check(
                    "build.release-xcconfig-resolution",
                    "Project configuration",
                    "Not verified" if unresolved_xcconfigs else "Passed",
                    "Release xcconfig mapping/includes were incomplete: " + "; ".join(unresolved_xcconfigs)
                    if unresolved_xcconfigs
                    else f"Resolved {len(release_xcconfig_files)} Release xcconfig file(s) and their includes.",
                )
            )

    xcodebuild = command_available("xcodebuild", context.simulate_missing_tools)
    if not xcodebuild:
        result["tools"]["xcodebuild"] = {"available": False, "status": "Not verified"}
        result["checks"].append(
            check(
                "build.current-xcode",
                "Project configuration",
                "Not verified",
                "xcodebuild is unavailable; the current Xcode/SDK submission gate was not verified.",
                source_id="UPCOMING-REQUIREMENTS",
            )
        )
    else:
        code, stdout, stderr, error = run_command([xcodebuild, "-version"], cwd=root, timeout=10)
        value = (stdout or stderr).strip()
        result["tools"]["xcodebuild"] = {
            "available": True,
            "status": "verified" if code == 0 else "Not verified",
            "version_output": value,
            "error": error,
        }
        major_match = re.search(r"Xcode\s+(\d+)", value)
        if code == 0 and major_match:
            major = int(major_match.group(1))
            result["facts"]["xcode_major"] = major
            if major < 26:
                result["findings"].append(
                    make_finding(
                        base_id="XCODE-SDK-BELOW-CURRENT-MINIMUM",
                        severity="High",
                        confidence="Medium",
                        verification="Likely",
                        area="Project configuration",
                        title="Local Xcode is below the current upload minimum",
                        problem=f"The local audit environment reports Xcode {major}; Apple's current upload gate requires Xcode 26 or later for covered platforms, but archive provenance was not available.",
                        evidence_items=[evidence(kind="command-output", value="xcodebuild -version", excerpt=value)],
                        command="xcodebuild -version",
                        source_id="UPCOMING-REQUIREMENTS",
                        risk_reason="App Store Connect rejects covered uploads built below the current minimum toolchain/SDK gate.",
                        remediation="Build and archive with Xcode 26 or later and the applicable platform 26 SDK or later.",
                        verification_steps=["Run xcodebuild -version in the release environment.", "Inspect the archive SDK build version before upload."],
                        limitations=["The installed Xcode version does not prove which Xcode produced an existing archive or which toolchain CI uses.", "The exact platform and submission date determine the applicable upload gate."],
                        heuristic=True,
                    )
                )
            result["checks"].append(
                check(
                    "build.current-xcode",
                    "Project configuration",
                    "Passed" if major >= 26 else "Not verified",
                    f"The local environment reports Xcode {major}; exact release-archive provenance remains required."
                    if major >= 26
                    else f"The local environment reports Xcode {major}; the release archive may be produced elsewhere, so compliance is not verified.",
                    evidence_items=[evidence(kind="command-output", value="xcodebuild -version", excerpt=value)],
                    source_id="UPCOMING-REQUIREMENTS",
                )
            )
        else:
            result["checks"].append(
                check(
                    "build.current-xcode",
                    "Project configuration",
                    "Not verified",
                    "xcodebuild version output could not be interpreted.",
                    evidence_items=[evidence(kind="command-output", value="xcodebuild -version", excerpt=value or error)],
                    source_id="UPCOMING-REQUIREMENTS",
                )
            )

    result["checks"].extend(
        [
            check(
                "build.signing",
                "Project configuration",
                "Not verified",
                "Signing identity, provisioning profile, and App ID compatibility require the release archive and developer account.",
            ),
            check(
                "build.archive-scheme",
                "Project configuration",
                "Not verified",
                "Archive scheme behavior was not executed to avoid package resolution and project-side effects.",
            ),
        ]
    )
    return finish_result(result)


if __name__ == "__main__":
    raise SystemExit(scanner_cli(scan, "scan_build_configuration"))
