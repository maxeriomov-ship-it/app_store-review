# Report template

Use this structure for full, blockers, and recheck reports. Keep a short executive summary, then preserve machine-auditable evidence in the appendix.

Contents: [readiness audit](#app-store-readiness-audit), [finding format](#finding-format), [unverified/manual work](#unverified-areas), [App Review Notes](#app-review-notes), [evidence and sources](#evidence-appendix), and [Recheck](#recheck-addition).

## App Store readiness audit

**Mode:** Audit / Recheck  
**Profile:** full / blockers  
**App/build:** `[name, version, build]`  
**Audit date:** `[UTC date]`  
**Evidence supplied:** `[source, archive/device, ASC, Sandbox, review message]`

### Readiness

- **Status:** Ready / Conditionally ready / Not ready / Insufficient evidence
- **Risk index:** `[0–100]` — internal heuristic, not rejection probability
- **Coverage:** `[0–100]%`
- **Evidence completeness:** `[0–100]%`
- **Source freshness:** `[0–100]%`
- **Why this status:** `[one to three evidence-based reasons]`

### Summary

State what was inspected, the most important conclusion, and what remains unknown. Never imply guaranteed approval.

### Blocking issues

List verified or sufficiently supported Critical/High issues that prevent readiness. If none, say “No blocking issue was confirmed with the available evidence,” not “Apple will approve.”

### High risks

For each finding, include ID, verification/confidence, concise problem, strongest evidence, applicable source, minimal fix, and recheck method.

### Medium risks

Use the same fields. Separate contextual/subjective issues from mandatory requirements.

### Low and informational findings

Group only when the evidence, owner, and remedy genuinely match.

### Practical recommendations

Give prioritized actions that improve reviewability or customer safety but are not presented as mandatory unless the cited source says so.

### Unverified areas

Name each applicable area, missing evidence/tool, why it matters, and the exact manual confirmation needed. Include scanner failures.

### Manual actions

Provide device, Sandbox, backend, legal, accessibility, account, AI, and UGC actions applicable to this app.

### App Store Connect actions

List metadata, localization, screenshot/preview, URL, App Privacy, age rating, export, purchase product, agreements, contact, demo account, and notes checks. If App Store Connect evidence was not provided, state that metadata readiness is incomplete.

### Recommended fix order

Order by verified impact and dependency, not merely scanner severity:

1. crashes, inaccessible review path, broken backend, placeholder/incomplete states;
2. privacy/consent/account deletion/UGC safety and legal availability;
3. purchase/subscription entitlement and disclosure failures;
4. App Store Connect/build/metadata gates;
5. medium/low quality and clarity improvements.

### Recheck commands

```bash
python3 scripts/run_audit.py <project-root> --profile full --baseline <previous-report.json>
```

Add exact safe build/test/device steps used for selected fixes.

### Draft App Review Notes

Use `reviewer_notes_template.md`. Mark every unknown placeholder. Never invent credentials, routes, product IDs, or environment facts.

### Limitations

Always state:

- static analysis does not replace physical-device testing;
- Simulator does not replace a real device;
- metadata cannot be completed without App Store Connect evidence;
- purchase behavior cannot be confirmed without StoreKit Sandbox;
- current Apple-source validity cannot be confirmed without live access;
- passing does not guarantee approval;
- subjective Apple rules require expert interpretation;
- high-risk legal documents require qualified review.

### Evidence appendix

For every finding:

```text
ID:
Severity / Verification / Confidence:
Area:
Problem:
Evidence:
File / line:
Command or test:
Official Apple source:
Rule or section:
Canonical URL:
Source checked / status:
Why this is a risk:
Minimal remediation:
Automatic fix: yes/no + safety note
Verification after fix:
Limitations / exceptions:
Heuristic: yes/no
```

Redact secrets and personal data.

### Sources used

Include only sources that supported report claims, with source ID, title, section, canonical URL, checked date, applicability, and status. Recheck living pages immediately before submission.

## Recheck addition

Add four explicit groups: **Resolved**, **Persisting**, **New**, and **Could not reverify**. A disappeared static pattern counts as resolved only for that static detector; runtime or external remediation needs its original confirmation method.
