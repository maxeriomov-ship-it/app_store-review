#!/usr/bin/env python3
"""Find release placeholders and high-risk Swift crash signals."""

from __future__ import annotations

import re

from audit_core import (
    ScanContext,
    check,
    code_corpus,
    find_matches,
    finish_result,
    make_finding,
    match_evidence,
    new_result,
    scanner_cli,
)


PLACEHOLDER_TERMS = r"TODO|TBD|Lorem ipsum|Placeholder|Coming soon|Test data|Sample text|Under construction"
PLACEHOLDER_PATTERN = re.compile(
    rf"(?:Text\s*\(\s*(?:verbatim\s*:\s*)?|Label\s*\(\s*|Button\s*\(\s*|alert\s*\(\s*|(?:title|message|placeholder)\s*[:=]\s*)['\"](?:{PLACEHOLDER_TERMS})[^'\"]*['\"]",
    re.I,
)
LOCALIZED_PLACEHOLDER_PATTERN = re.compile(
    rf"(?:=\s*|['\"]value['\"]\s*:\s*)['\"](?:{PLACEHOLDER_TERMS})[^'\"]*['\"]",
    re.I,
)
FORCED_CAST_PATTERN = re.compile(r"\bas\s*!\s*[A-Za-z_(\[]")
TRY_FORCE_PATTERN = re.compile(r"\btry\s*!\s*")
FORCE_UNWRAP_PATTERN = re.compile(
    r"\b(?!(?:as|try)\s*!)[A-Za-z_][A-Za-z0-9_]*(?:\?\.)?[A-Za-z0-9_]*!(?!=)|[)\]]!(?!=)"
)
INCOMPLETE_PATTERN = re.compile(r"fatalError\s*\(\s*['\"](?:TODO|not implemented|unimplemented)", re.I)


def _is_declaration_only_unwrap(item: dict) -> bool:
    line = item.get("excerpt") or ""
    if "@IBOutlet" in line and re.search(r":\s*[^=]+!", line):
        return True
    if re.search(r"\b(?:let|var)\s+[A-Za-z_][A-Za-z0-9_]*\s*:\s*[^=]+!\s*(?:[={]|$)", line):
        return True
    if re.search(r"->\s*[^={]+!\s*(?:[={]|$)", line):
        return True
    return False


def _blank_string_literals(text: str) -> str:
    """Blank quoted literals while preserving line numbers for operator scans."""

    output = list(text)
    index = 0
    quote = None
    triple = False
    escaped = False
    while index < len(text):
        char = text[index]
        if quote is None:
            if text.startswith('"""', index) or text.startswith("'''", index):
                quote = char
                triple = True
                output[index:index + 3] = "   "
                index += 3
                continue
            if char in {'"', "'", "`"}:
                quote = char
                triple = False
                output[index] = " "
            index += 1
            continue
        if char != "\n":
            output[index] = " "
        if escaped:
            escaped = False
            index += 1
            continue
        if char == "\\":
            escaped = True
            index += 1
            continue
        if triple and text.startswith(quote * 3, index):
            output[index:index + 3] = "   "
            index += 3
            quote = None
            triple = False
            continue
        if not triple and char == quote:
            quote = None
        index += 1
    return "".join(output)


def scan(context: ScanContext) -> dict:
    result = new_result("scan_placeholders")
    root = context.root
    all_corpus = code_corpus(root)
    corpus = [(path, text) for path, text in all_corpus if path.suffix.lower() in {".swift", ".m", ".mm", ".js", ".jsx", ".ts", ".tsx", ".dart"}]
    placeholders = find_matches(corpus, PLACEHOLDER_PATTERN, root)
    localized_corpus = [
        (path, text)
        for path, text in all_corpus
        if path.suffix.lower() in {".strings", ".xcstrings"}
    ]
    localized_placeholders = find_matches(
        localized_corpus, LOCALIZED_PLACEHOLDER_PATTERN, root
    )
    placeholders.extend(localized_placeholders)
    operator_corpus = [
        (path, _blank_string_literals(text))
        for path, text in corpus
        if path.suffix.lower() == ".swift"
    ]
    for item in placeholders:
        result["findings"].append(
            make_finding(
                base_id="PLACEHOLDER-USER-VISIBLE",
                severity="High",
                confidence="Medium",
                verification="Likely",
                area="Reliability",
                title="Potentially user-visible placeholder content",
                problem="A UI or returned string contains release-placeholder wording.",
                evidence_items=[match_evidence(item, "Placeholder text")],
                file=item["file"],
                line=item["line"],
                source_id="ARG-2.1",
                risk_reason="Apple identifies placeholder and temporary content as incomplete submission material.",
                remediation="Replace the text with final product content or remove/inaccessibly gate the unfinished route from the release target.",
                verification_steps=["Navigate to the affected state in a Release build.", "Search all supported localizations and server-driven content for equivalent placeholders."],
                limitations=["The match may occur in a preview, fixture, or internal-only route; target membership must be confirmed."],
                heuristic=True,
                id_detail=item["excerpt"],
            )
        )
    crash_patterns = [
        ("SWIFT-FORCED-CAST", FORCED_CAST_PATTERN, "Forced Swift cast", "A failed forced cast terminates the process."),
        ("SWIFT-TRY-FORCE", TRY_FORCE_PATTERN, "Forced throwing call", "An unexpected thrown error terminates the process."),
        ("SWIFT-FORCE-UNWRAP", FORCE_UNWRAP_PATTERN, "Potential forced optional unwrap", "A nil forced unwrap terminates the process."),
        ("INCOMPLETE-FATAL-ERROR", INCOMPLETE_PATTERN, "Unimplemented fatal error", "Reaching an unfinished fatalError terminates the process."),
    ]
    for base_id, pattern, title, reason in crash_patterns:
        hits = find_matches(operator_corpus, pattern, root)
        if base_id == "SWIFT-FORCE-UNWRAP":
            hits = [item for item in hits if not _is_declaration_only_unwrap(item)]
        for item in hits[:25]:
            result["findings"].append(
                make_finding(
                    base_id=base_id,
                    severity="Medium" if base_id != "INCOMPLETE-FATAL-ERROR" else "High",
                    confidence="Low" if base_id == "SWIFT-FORCE-UNWRAP" else "Medium",
                    verification="Possible",
                    area="Reliability",
                    title=title,
                    problem=reason,
                    evidence_items=[match_evidence(item, title)],
                    file=item["file"],
                    line=item["line"],
                    source_id="ARG-2.1",
                    risk_reason="A reviewer reaching this path could experience an obvious crash or incomplete state.",
                    remediation="Replace the unsafe operation with validated control flow and a recoverable user-facing error where failure is possible.",
                    verification_steps=["Add a focused test for the nil/type/error path.", "Exercise the route in the exact Release build on device."],
                    limitations=["Static syntax alone cannot prove the operation is reachable or unsafe; invariants may make it valid."],
                    heuristic=True,
                    id_detail=item["excerpt"],
                )
            )
    result["facts"] = {
        "placeholder_count": len(placeholders),
        "localized_placeholder_count": len(localized_placeholders),
        "source_files_scanned": len(corpus),
    }
    result["checks"].extend(
        [
            check(
                "reliability.static-signals",
                "Reliability",
                "Failed" if result["findings"] else "Passed",
                f"Scanned {len(corpus)} source file(s); detected {len(result['findings'])} static reliability finding(s).",
                source_id="ARG-2.1",
            ),
            check(
                "reliability.runtime",
                "Reliability",
                "Not verified",
                "Crashes, empty states, loading loops, broken controls, offline behavior, slow networks, clean install, and backend availability require runtime testing.",
                source_id="ARG-2.1",
            ),
        ]
    )
    return finish_result(result)


if __name__ == "__main__":
    raise SystemExit(scanner_cli(scan, "scan_placeholders"))
