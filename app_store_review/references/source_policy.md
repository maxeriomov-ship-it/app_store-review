# Source policy

Use this policy whenever a finding refers to Apple requirements.

## Authority tiers

1. **Mandatory rule** — current official Apple App Review Guidelines, App Store Connect requirements, developer program terms made available by the user, or an enforceable platform requirement stated on an official Apple page.
2. **Official implementation or design guidance** — Apple Developer Documentation, technotes, StoreKit documentation, HIG, and Apple support guidance. These explain implementation and review expectations but do not automatically turn every recommendation into a rejection rule.
3. **Official current-process signal** — Apple Developer News, Upcoming Requirements, and App Store Connect release notes. Apply dates and scope exactly.
4. **Practical hypothesis** — unofficial articles, rejection anecdotes, forum posts, package names, or static code patterns. Use only to decide what to investigate. Never call these Apple requirements.

The Mehran/AetherMaker article may seed hypotheses about crashes, incomplete states, purchases/restoration, subscription disclosure, privacy labels, permissions, account deletion, legal links, native UX, metadata, minimum functionality, UGC, AI, age rating, reviewer instructions, and rejection replies. Verify every resulting claim independently against the official registry and current Apple page.

## Citation gate

Before stating that Apple requires something:

1. Select an entry from `apple_source_registry.json`.
2. Confirm the rule applies to this app and submission; evaluate exceptions and effective dates.
3. If live access is available, open the canonical URL and confirm the relevant section still supports the claim.
4. Record source title, exact section/rule, canonical URL, registry `last_checked`, summary, applicability, and source status.
5. Quote minimally and paraphrase accurately. Do not infer a rule number or URL from memory.

If the registry lacks a source or the live page cannot be checked, use `Not verified`, explain the limitation, and describe the manual verification required. Do not create a synthetic citation.

## Currency

- `official-current-living` and `official-current-living-list` entries can change without notice. Recheck before a final submission decision.
- `official-current-future-gate` applies only on or after its stated effective date unless Apple says otherwise.
- For current SDK, toolchain, age-rating, privacy, and SDK-list rules, consult `UPCOMING-REQUIREMENTS`, relevant Apple Developer News, and App Store Connect release notes immediately before upload.
- Source freshness measures registry recency, not compliance and not proof the webpage is unchanged.

## Claim wording

- **Required:** a current official source, exact applicability, and no unresolved exception.
- **Apple guidance/recommendation:** official documentation or HIG recommends the behavior.
- **Review risk / hypothesis:** evidence suggests a reviewer may encounter a problem, but the audit has not proved a violation.
- **Subjective:** guideline application depends on judgment, such as minimum functionality or some design-quality assessments.

Every report must include the sources actually used and their checked dates, not the entire registry by default.
