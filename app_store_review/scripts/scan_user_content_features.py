#!/usr/bin/env python3
"""Detect UGC/social features and required safety-control evidence gaps."""

from __future__ import annotations

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


UGC_PATTERN = r"createPost|publishPost|submitComment|CommentView|uploadVideo|uploadPhoto|UserGeneratedContent|creator content|social feed|reviews? feed"
CHAT_PATTERN = r"ChatView|\bsendMessage\s*\(|userMessage|directMessage|conversation|chatChannel"
SHARING_PATTERN = r"recipient|other users|public post|followers|community|chatChannel|participant|memberID|authorID"
FILTER_PATTERN = r"moderation|contentFilter|filterObjectionable|profanity|toxicity|NSFW|blockedWords|safety classifier"
REPORT_PATTERN = r"reportContent|reportUser|report post|report message|flagContent|abuse report|ReportButton"
BLOCK_PATTERN = r"blockUser|blockedUsers|unblockUser|muteUser|BlockButton"
SUPPORT_PATTERN = r"support@|contact support|help center|supportURL|community guidelines"
TERMS_PATTERN = r"terms of service|community guidelines|acceptable use|prohibited content|user agreement"


def scan(context: ScanContext) -> dict:
    result = new_result("scan_user_content_features")
    root = context.root
    corpus = code_corpus(root)
    ugc = find_matches(corpus, UGC_PATTERN, root)
    chat = find_matches(corpus, CHAT_PATTERN, root)
    sharing = find_matches(corpus, SHARING_PATTERN, root)
    if chat and sharing:
        ugc.extend(chat)
    controls = {
        "filtering": find_matches(corpus, FILTER_PATTERN, root),
        "reporting": find_matches(corpus, REPORT_PATTERN, root),
        "blocking": find_matches(corpus, BLOCK_PATTERN, root),
        "published support/contact": find_matches(corpus, SUPPORT_PATTERN, root),
        "terms/community rules": find_matches(corpus, TERMS_PATTERN, root),
    }
    applicable = bool(ugc)
    missing = [name for name in ("filtering", "reporting", "blocking", "published support/contact") if not controls[name]]
    if applicable and missing:
        first = ugc[0]
        result["findings"].append(
            make_finding(
                base_id="UGC-SAFETY-CONTROLS-NOT-DETECTED",
                severity="High",
                confidence="Low",
                verification="Possible",
                area="User-generated content",
                title="Required UGC safety controls were not all detected",
                problem="UGC/social signals were found, while static analysis did not establish: " + ", ".join(missing) + ".",
                evidence_items=[match_evidence(item, "UGC feature signal") for item in ugc[:5]],
                file=first["file"],
                line=first["line"],
                source_id="ARG-1.2",
                risk_reason="UGC and social services must provide objectionable-content filtering, reporting with timely response, user blocking, and published contact information.",
                remediation="Implement the missing controls end to end, including moderation operations, response SLAs, enforcement, appeal/support routes, and clear community rules.",
                verification_steps=["Post representative text/media and test filtering.", "Report content and verify the moderation queue and response path.", "Block a user and verify all relevant surfaces.", "Open published support/contact information."],
                limitations=["Static absence is not proof; controls may be server-driven, generated, or implemented in a binary SDK.", "Timely moderation and enforcement quality require operational evidence.", "Anonymous/random chat and age-sensitive creator content need additional product-level assessment."],
                heuristic=True,
                id_detail=",".join(missing),
            )
        )
    if applicable and not controls["terms/community rules"]:
        first = ugc[0]
        result["findings"].append(
            make_finding(
                base_id="UGC-RULES-NOT-DETECTED",
                severity="Informational",
                confidence="Low",
                verification="Not verified",
                area="User-generated content",
                title="User-content rules or acceptable-use terms were not detected",
                problem="No recognizable community guidelines, prohibited-content policy, or user agreement was found near the UGC implementation.",
                evidence_items=[match_evidence(first, "UGC feature signal")],
                file=first["file"],
                line=first["line"],
                source_id="ARG-1.2",
                risk_reason="Clear community rules support consistent moderation and user expectations, but Guideline 1.2 does not enumerate a separate user-agreement requirement.",
                remediation="Provide accurate, accessible community/acceptable-use rules and align moderation actions with them; obtain legal review for high-risk products.",
                verification_steps=["Open the rules from the app before and after account creation.", "Trace a prohibited-content report through enforcement."],
                limitations=["This is a strong operational recommendation, not a separate explicit requirement listed in Guideline 1.2.", "Legal or remote content may live outside the repository."],
                heuristic=True,
            )
        )
    result["facts"] = {
        "ugc_signal_count": len(ugc),
        "chat_signal_count": len(chat),
        "multi_user_sharing_signal_count": len(sharing),
        **{f"{name}_signal_count": len(value) for name, value in controls.items()},
    }
    missing_required_controls = any(
        finding.get("rule_id") == "UGC-SAFETY-CONTROLS-NOT-DETECTED"
        for finding in result["findings"]
    )
    result["checks"].extend(
        [
            check(
                "ugc.static-controls",
                "User-generated content",
                "Failed" if missing_required_controls else ("Passed" if applicable else "Not applicable"),
                (
                    "Inspected UGC signals; one or more required safety controls were not established."
                    if missing_required_controls
                    else "Inspected UGC and safety-control signals."
                    if applicable
                    else "No supported UGC/social feature signal was detected."
                ),
                applicable=applicable,
                source_id="ARG-1.2",
            ),
            check(
                "ugc.moderation-operations",
                "User-generated content",
                "Not verified" if applicable else "Not applicable",
                "Moderation coverage, timely responses, enforcement, appeals, support availability, and prohibited-content handling require operational tests."
                if applicable
                else "UGC operations are not applicable from current evidence.",
                applicable=applicable,
                source_id="ARG-1.2",
            ),
            check(
                "ugc.age-rating-social-questions",
                "App Store Connect metadata",
                "Not verified" if applicable else "Not applicable",
                "UGC, chat, creator content, and social-media capability answers require the current age-rating questionnaire."
                if applicable
                else "UGC age-rating answers are not applicable from current evidence.",
                applicable=applicable,
                source_id="NEWS-AGE-SOCIAL",
            ),
        ]
    )
    return finish_result(result)


if __name__ == "__main__":
    raise SystemExit(scanner_cli(scan, "scan_user_content_features"))
