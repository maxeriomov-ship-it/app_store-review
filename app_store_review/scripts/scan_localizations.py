#!/usr/bin/env python3
"""Compare app localization keys and permission-string coverage."""

from __future__ import annotations

import json
import re
from collections import defaultdict

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
    strip_code_comments,
)


STRING_ENTRY = re.compile(
    r'"((?:\\.|[^"\\])*)"\s*=\s*"((?:\\.|[^"\\])*)"\s*;',
    re.S,
)


def _strings_keys(path):
    text = read_text(path)
    if text is None:
        return set(), "could not decode"
    cleaned = strip_code_comments(text).lstrip("\ufeff")
    matches = list(STRING_ENTRY.finditer(cleaned))
    remainder = list(cleaned)
    for match in matches:
        for index in range(match.start(), match.end()):
            if remainder[index] != "\n":
                remainder[index] = " "
    if "".join(remainder).strip():
        return {match.group(1) for match in matches}, "contains malformed or unparsed .strings content"
    return {match.group(1) for match in matches}, None


def scan(context: ScanContext) -> dict:
    result = new_result("scan_localizations")
    root = context.root
    groups: dict[str, dict[str, set[str]]] = defaultdict(dict)
    parse_errors: list[tuple[str, str]] = []
    catalog_gaps: list[tuple[str, dict[str, list[str]]]] = []
    key_mismatch_count = 0
    for path in iter_files(root, suffixes={".strings", ".xcstrings"}, max_size=5_000_000):
        rel = relative_path(path, root) or str(path)
        if path.suffix == ".strings":
            locale = next((part[:-6] for part in path.parts if part.endswith(".lproj")), "base")
            keys, error = _strings_keys(path)
            groups[path.name][locale] = keys
            if error:
                parse_errors.append((rel, error))
        else:
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("xcstrings top-level value must be an object")
                strings = payload.get("strings", {})
                if not isinstance(strings, dict):
                    raise ValueError("xcstrings 'strings' value must be an object")
                groups[path.name]["xcstrings"] = set(strings)
                target_locales: set[str] = set()
                for entry in strings.values():
                    if isinstance(entry, dict) and isinstance(entry.get("localizations"), dict):
                        target_locales.update(entry["localizations"])
                gaps: dict[str, list[str]] = {}
                for key, entry in strings.items():
                    if not isinstance(entry, dict):
                        parse_errors.append((rel, f"String catalog entry {key!r} must be an object"))
                        continue
                    localizations = entry.get("localizations", {})
                    if not isinstance(localizations, dict):
                        parse_errors.append((rel, f"String catalog entry {key!r} localizations must be an object"))
                        continue
                    missing_locales = sorted(target_locales - set(localizations))
                    if missing_locales:
                        gaps[key] = missing_locales
                if gaps:
                    catalog_gaps.append((rel, gaps))
            except (OSError, ValueError) as exc:
                parse_errors.append((rel, f"{type(exc).__name__}: {exc}"))
    for rel, error in parse_errors:
        result["findings"].append(
            make_finding(
                base_id="LOCALIZATION-PARSE-ERROR",
                severity="Medium",
                confidence="High",
                verification="Verified",
                area="Localization",
                title="Localization file could not be parsed",
                problem=error,
                evidence_items=[evidence(kind="parse-error", value=error, file=rel)],
                file=rel,
                source_id="ARG-2.1",
                risk_reason="Broken localization resources can create missing or placeholder UI in the release build.",
                remediation="Repair the file encoding or syntax and validate the localization resource in Xcode.",
                verification_steps=["Build every affected localization.", "Launch the app using that language and inspect primary flows."],
                heuristic=False,
            )
        )
    for filename, locales in groups.items():
        if len(locales) < 2 or "xcstrings" in locales:
            continue
        union = set().union(*locales.values()) if locales else set()
        differences = {locale: sorted(union - keys) for locale, keys in locales.items() if union - keys}
        if differences:
            key_mismatch_count += 1
            result["findings"].append(
                make_finding(
                    base_id="LOCALIZATION-KEY-MISMATCH",
                    severity="Medium",
                    confidence="High",
                    verification="Verified",
                    area="Localization",
                    title=f"Localization keys are inconsistent in {filename}",
                    problem="Missing keys by locale: " + json.dumps(differences, ensure_ascii=False, sort_keys=True),
                    evidence_items=[
                        evidence(kind="localization-keyset", value=f"{locale}: {len(keys)} keys", file=f"{locale}.lproj/{filename}")
                        for locale, keys in sorted(locales.items())
                    ],
                    source_id="ARG-2.1",
                    risk_reason="Missing localized strings can expose fallback keys, incomplete UI, or unclear permission copy during review.",
                    remediation="Add truthful translations for missing keys or intentionally consolidate to the supported localization set.",
                    verification_steps=["Run the app in every supported language.", "Check permission prompts, paywall, account deletion, legal links, and error states for truncation or fallback keys."],
                    limitations=["Runtime fallback may hide missing keys; key equality does not establish translation quality."],
                    heuristic=False,
                    id_detail=filename,
                )
            )
    for rel, gaps in catalog_gaps:
        result["findings"].append(
            make_finding(
                base_id="LOCALIZATION-CATALOG-COVERAGE",
                severity="Medium",
                confidence="High",
                verification="Verified",
                area="Localization",
                title="String Catalog keys are missing target localizations",
                problem="Missing localizations by key: " + json.dumps(gaps, ensure_ascii=False, sort_keys=True),
                evidence_items=[
                    evidence(
                        kind="xcstrings-localization-gap",
                        value=f"{key}: missing {', '.join(locales)}",
                        file=rel,
                    )
                    for key, locales in list(sorted(gaps.items()))[:20]
                ],
                file=rel,
                source_id="ARG-2.1",
                risk_reason="Incomplete string-catalog coverage can expose source-language or unfinished UI in a supported locale.",
                remediation="Translate each missing key or explicitly remove the unsupported target localization, then render the affected flows.",
                verification_steps=["Build and launch every target locale.", "Inspect long, plural, permission, paywall, legal, account, and error states."],
                limitations=["Runtime fallback can be intentional; static key coverage does not establish translation quality or target membership."],
                heuristic=True,
                id_detail=rel,
            )
        )
    result["facts"]["localization_groups"] = {
        filename: {locale: sorted(keys) for locale, keys in locales.items()}
        for filename, locales in groups.items()
    }
    result["facts"]["string_catalog_gaps"] = [
        {"file": rel, "missing_by_key": gaps} for rel, gaps in catalog_gaps
    ]
    result["facts"]["key_mismatch_group_count"] = key_mismatch_count
    has_localization = bool(groups)
    result["checks"].extend(
        [
            check(
                "localization.key-parity",
                "Localization",
                "Passed"
                if has_localization and not parse_errors and not catalog_gaps and not key_mismatch_count
                else ("Not verified" if not has_localization else "Failed"),
                f"Inspected {len(groups)} localization resource group(s)." if has_localization else "No supported localization resource was detected.",
                source_id="ARG-2.1",
            ),
            check(
                "localization.rendered-layout",
                "Localization",
                "Not verified",
                "Translation accuracy, clipped text, right-to-left layout, Dynamic Type, and store-listing localization require rendered/manual checks.",
                source_id="ASC-LOCALIZATION",
            ),
        ]
    )
    return finish_result(result)


if __name__ == "__main__":
    raise SystemExit(scanner_cli(scan, "scan_localizations"))
