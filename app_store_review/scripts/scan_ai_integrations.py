#!/usr/bin/env python3
"""Detect AI integrations and evidence gaps without asserting unproven transfer."""

from __future__ import annotations

import re

from audit_core import (
    ScanContext,
    check,
    code_corpus,
    evidence,
    find_matches,
    finish_result,
    make_finding,
    match_evidence,
    new_result,
    scanner_cli,
)


PROVIDERS = {
    "OpenAI": r"api\.openai\.com|\b(?:import|from)\s+OpenAI\b|OpenAIClient|gpt-[0-9]|openai-swift|openai-node",
    "Anthropic": r"api\.anthropic\.com|\b(?:import|from)\s+Anthropic\b|AnthropicClient|claude-[A-Za-z0-9.-]+",
    "Google": r"generativelanguage\.googleapis\.com|VertexAI|GoogleGenerativeAI|GenerativeModel\s*\(|gemini-[A-Za-z0-9.-]+",
    "Microsoft Azure AI": r"openai\.azure\.com|AzureOpenAI|Azure AI",
    "AWS": r"bedrock-runtime|BedrockRuntime|Amazon Bedrock",
    "Apple": r"FoundationModels|SystemLanguageModel|Apple Intelligence",
    "Other model provider": r"api\.cohere\.ai|api\.mistral\.ai|huggingface\.co|Replicate\b|Groq\b|TogetherAI|Perplexity\b",
}

OFF_DEVICE = r"api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|openai\.azure\.com|bedrock-runtime|api\.cohere\.ai|api\.mistral\.ai|huggingface\.co|api\.replicate\.com"
PERSONAL_INPUT = r"user(Message|Input|Prompt|Text)|messageText|photo|imageData|audio|voice|location|contact|health|profile|conversation|chatHistory|email|name"
TRANSFER = r"URLRequest|fetch\s*\(|axios\.|URLSession|http\.post|dio\.post|request\s*\(|messages\s*:|prompt\s*:|input\s*:"
CONSENT = r"explicit consent|AI consent|consentToAI|allow.*(?:AI|model|third.?party)|agree.*(?:share|send)|permission.*(?:AI|model)|opt.?in"
# Require disclosure-like language, not merely an implementation symbol or provider
# name. Static presence still does not prove the text is rendered to the user.
DISCLOSURE = (
    r"(?:sent|shared|transmitted|uploaded|provided).{0,80}(?:to|with).{0,40}"
    r"(?:OpenAI|Anthropic|Google|Azure|AWS Bedrock|third.?party (?:AI|model)|model provider)"
    r"|(?:processed|received|stored|used for training).{0,30}(?:by|at).{0,30}"
    r"(?:OpenAI|Anthropic|Google|Azure|AWS Bedrock|third.?party (?:AI|model)|model provider)"
    r"|(?:OpenAI|Anthropic|Google|Azure|AWS Bedrock).{0,80}"
    r"(?:receives|processes|stores|retains|training|data recipient)"
)
SAFETY = r"moderation|safety filter|content filter|guardrail|blocked content|report output|flag output|age gate|parental"


def scan(context: ScanContext) -> dict:
    result = new_result("scan_ai_integrations")
    root = context.root
    corpus = code_corpus(root)
    provider_hits = {provider: find_matches(corpus, pattern, root) for provider, pattern in PROVIDERS.items()}
    provider_hits = {provider: hits for provider, hits in provider_hits.items() if hits}
    applicable = bool(provider_hits)
    off_device = find_matches(corpus, OFF_DEVICE, root)
    personal = find_matches(corpus, PERSONAL_INPUT, root)
    transfer = find_matches(corpus, TRANSFER, root)
    consent = find_matches(corpus, CONSENT, root)
    disclosure = find_matches(corpus, DISCLOSURE, root)
    safety = find_matches(corpus, SAFETY, root)
    providers = sorted(provider_hits)
    correlated_files = sorted(
        {item.get("file") for item in off_device if item.get("file")}
        & {item.get("file") for item in personal if item.get("file")}
        & {item.get("file") for item in transfer if item.get("file")}
    )
    if correlated_files and not consent:
        correlated = set(correlated_files)
        correlated_off_device = [item for item in off_device if item.get("file") in correlated]
        correlated_personal = [item for item in personal if item.get("file") in correlated]
        correlated_transfer = [item for item in transfer if item.get("file") in correlated]
        first = correlated_off_device[0]
        result["findings"].append(
            make_finding(
                base_id="AI-CONSENT-NOT-DETECTED",
                severity="High",
                confidence="Low",
                verification="Possible",
                area="Artificial intelligence",
                title="Possible third-party AI data transfer without detected explicit consent",
                problem="An off-device AI provider endpoint, request construction, and user/personal input signals were found, but no recognizable explicit-consent control was found.",
                evidence_items=(
                    [match_evidence(item, "AI provider endpoint") for item in correlated_off_device[:3]]
                    + [match_evidence(item, "Potential user/personal input") for item in correlated_personal[:3]]
                    + [match_evidence(item, "Network/request signal") for item in correlated_transfer[:3]]
                ),
                file=first["file"],
                line=first["line"],
                source_id="ARG-5.1.2",
                risk_reason="If personal data is shared with third-party AI, Apple requires clear recipient disclosure and explicit permission before sharing.",
                remediation="Trace the exact payload and recipient. If personal data is shared, add an informed, explicit pre-transfer consent flow, record revocation behavior, and reconcile policy/label/storage and deletion disclosures.",
                verification_steps=["Capture and inspect release-build requests using non-sensitive test data.", "Deny consent and confirm no personal data leaves the device.", "Grant then revoke consent and verify behavior and retained data."],
                limitations=["The scanner does not assert that personal data is actually transmitted; source signals may be unrelated or on-device.", "Consent may be server-driven, generated, or named differently.", "ATT is separate and applies only if the sharing meets Apple's tracking definition."],
                heuristic=True,
                id_detail=",".join(providers),
            )
        )
    if off_device and not disclosure:
        first = off_device[0]
        result["findings"].append(
            make_finding(
                base_id="AI-RECIPIENT-DISCLOSURE-NOT-DETECTED",
                severity="Medium",
                confidence="Low",
                verification="Possible",
                area="Artificial intelligence",
                title="AI recipient and off-device processing disclosure was not detected",
                problem=f"Potential off-device model providers were detected ({providers}), but user-facing recipient/storage disclosure was not established statically.",
                evidence_items=[match_evidence(item, "AI provider endpoint") for item in off_device[:5]],
                file=first["file"],
                line=first["line"],
                source_id="HIG-GENERATIVE-AI",
                risk_reason="People should understand what is sent, to whom, where it is processed, and whether it is stored or used for training.",
                remediation="Provide concise, accurate disclosure at the decision point and align it with the privacy policy and App Privacy answers.",
                verification_steps=["Review onboarding and the exact pre-send state.", "Compare disclosures with the captured payload and provider contract/configuration."],
                limitations=["User-facing disclosures may be remote or contained in documents not present in the repository."],
                heuristic=True,
                id_detail=",".join(providers),
            )
        )
    generative = applicable and any(provider != "Apple" for provider in providers)
    if generative and not safety:
        first = next(iter(provider_hits.values()))[0]
        result["findings"].append(
            make_finding(
                base_id="AI-CONTENT-SAFETY-NOT-DETECTED",
                severity="Medium",
                confidence="Low",
                verification="Possible",
                area="Artificial intelligence",
                title="Generated-content safety controls were not detected",
                problem="Generative AI signals were found without recognizable moderation, filtering, reporting, guardrail, or age-control signals.",
                evidence_items=[match_evidence(first, "Generative AI provider signal")],
                file=first["file"],
                line=first["line"],
                source_id="HIG-GENERATIVE-AI",
                risk_reason="Apple's generative-AI design guidance recommends proportionate safeguards; generated content can also create age-rating or UGC exposure depending on where it is shared.",
                remediation="Threat-model prompts and outputs; add proportionate server/client safeguards, reporting/escalation, age controls, and failure handling where applicable.",
                verification_steps=["Run adversarial content tests across supported modalities.", "Verify report/escalation and age-rating disclosures."],
                limitations=["This is HIG guidance, not a standalone mandatory App Review rule.", "Guideline 1.2 applies only when the feature creates UGC/social-service exposure; not every private AI output is UGC.", "Provider-side safeguards may not be visible in the app repository."],
                heuristic=True,
            )
        )
    result["facts"] = {
        "providers": providers,
        "off_device_signal_count": len(off_device),
        "personal_input_signal_count": len(personal),
        "request_signal_count": len(transfer),
        "correlated_personal_transfer_files": correlated_files,
        "consent_signal_count": len(consent),
        "disclosure_signal_count": len(disclosure),
        "safety_signal_count": len(safety),
    }
    static_ai_findings = bool(result["findings"])
    result["checks"].extend(
        [
            check(
                "ai.static-integration",
                "Artificial intelligence",
                "Failed" if static_ai_findings else ("Passed" if applicable else "Not applicable"),
                (
                    f"Detected AI integration signals for {', '.join(providers)} and emitted static compliance leads."
                    if static_ai_findings
                    else f"Detected AI integration signals for: {', '.join(providers)}."
                    if applicable
                    else "No supported AI provider signal was detected."
                ),
                applicable=applicable,
                source_id="ARG-5.1.2",
            ),
            check(
                "ai.payload-and-consent-runtime",
                "Artificial intelligence",
                "Not verified" if applicable else "Not applicable",
                "Actual payloads, recipients, consent timing, retention, training use, deletion, opt-out, and output safety require runtime/provider verification."
                if applicable
                else "AI runtime checks are not applicable from current evidence.",
                applicable=applicable,
                source_id="HIG-GENERATIVE-AI",
            ),
            check(
                "ai.age-rating",
                "App Store Connect metadata",
                "Not verified" if applicable else "Not applicable",
                "AI/chatbot and generated-content age-rating answers require the live App Store Connect questionnaire."
                if applicable
                else "AI age-rating answers are not applicable from current evidence.",
                applicable=applicable,
                source_id="ASC-AGE-RATING",
            ),
        ]
    )
    return finish_result(result)


if __name__ == "__main__":
    raise SystemExit(scanner_cli(scan, "scan_ai_integrations"))
