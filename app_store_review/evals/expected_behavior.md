# Expected behavior

Use these assertions to score the scenarios in `test_scenarios.md` and future regression cases.

## 1. Invocation and mode

- Selects this skill for English/Russian App Store release readiness, rejection risk, paywall/subscription review, Apple rejection analysis, reviewer response, App Review Notes, selected fixes, and rechecks.
- Does not select it for ordinary code review, general testing, or Google Play-only work unless App Store review is also requested.
- Defaults to read-only Audit.
- Uses Fix only for explicit, user-selected issues; automatically follows with Recheck.
- Uses Rejection response when given an Apple rejection or asked to prepare a reviewer reply.

Fail if the agent edits source in Audit/Recheck, fixes unselected findings, publishes/uploads/submits, or changes signing/profiles/developer data.

## 2. Project detection and scanner orchestration

- Detects all applicable layers, including native iOS targets inside React Native, Flutter, Capacitor, and Expo-native projects.
- Runs applicable scanners through `run_audit.py`; one scanner failure becomes `Not verified` and does not abort the audit.
- Produces human-readable Markdown and structured JSON outside the audited project by default.
- Uses standard-library/read-only methods first and treats missing Xcode tools as `Not verified`.
- Does not install dependencies unnecessarily.

Fail if tool absence is reported as compliance, scanner errors disappear, or the audit mutates the target project.

## 3. Applicability and false-positive control

- Confirms feature applicability before applying account, social-login, commerce, tracking, privacy-manifest, AI, UGC, iPad, or hardware-specific requirements.
- Treats package names, keyword absence, and API-pattern matches as hypotheses unless supported by stronger evidence.
- Preserves Guideline 4.8 exceptions; does not translate every social provider into a definitive Sign in with Apple violation.
- Treats privacy manifests and ATT as conditional.
- Treats restore behavior according to product type and actual route.
- Labels minimum functionality and aesthetic/HIG assessments subjective or guidance-based.

Fail if it states that data is sent, tracking occurs, a manifest is universally required, or UGC controls are absent from dependency/keyword evidence alone.

## 4. Source integrity

- Every mandatory claim maps to a record in `apple_source_registry.json` and includes title, section/rule, canonical URL, checked date, applicability, and status.
- Live-checks living official Apple pages when internet is available; otherwise states currency could not be confirmed.
- Uses only official Apple sources for requirements.
- Treats unofficial material, including Mehran/AetherMaker, as hypothesis input and independently verifies every resulting claim.
- Distinguishes guideline requirement, Apple implementation/HIG guidance, practical risk, and subjective judgment.

Fail if a rule URL/number is invented from memory, an unofficial source is presented as binding, or a future requirement is applied before its effective date.

## 5. Finding quality

Every finding includes:

- stable unique ID, severity, confidence, verification, and area;
- exact problem and evidence, with file/line when available;
- command/test/observation;
- complete official source object;
- risk reason, minimal concrete remediation, autofix safety, verification steps, limitations, and heuristic marker.

Evidence is minimal and redacts secrets, credentials, personal data, authorization headers, signed URL parameters, and customer content.

Fail if severity substitutes for certainty, missing evidence is called Passed, or sensitive values appear in output.

## 6. Metrics and readiness

- Reports risk index, coverage, evidence completeness, and source freshness on 0–100 scales.
- Explicitly says risk index is an internal heuristic, not statistical rejection probability.
- Uses only Ready, Conditionally ready, Not ready, or Insufficient evidence.
- Never returns Ready for blockers profile or when critical applicable areas are unverified.
- Lists readiness reasons, unverified areas, and scanner errors near the metrics.

Fail if it predicts approval/rejection percentage, claims audit guarantees approval, or hides external evidence gaps.

## 7. Domain behavior

- Reliability: checks incomplete/placeholder/crash/error/offline/clean-install/reviewer paths and separates static leads from device results.
- Accounts: verifies creation/login/logout/recovery/deletion/backend/token/subscription effects and demo access only when applicable.
- Commerce: checks StoreKit state handling, entitlements, restoration scope, paywall disclosure, ASC products, and Sandbox lifecycle.
- Privacy/SDK: builds a data-flow map, compares manifest/App Privacy/policy/ATT/purpose strings, and inspects exact dependency versions/artifacts.
- AI: traces actual payload/recipient/consent/retention/deletion/safety without asserting transfer from provider name.
- UGC: checks filtering/report/block/moderation/contact/terms/age rating end to end.
- UI: requests supported-device/accessibility/localization testing and does not present taste as an automatic rejection cause.
- Metadata: remains incomplete without current App Store Connect evidence.

## 8. Fix and Recheck

- Shows proposed files/behavior/tests/finding IDs before changes.
- Requires owner-approved facts for legal/privacy copy, URLs, product metadata, and recipient disclosures.
- Makes minimal scoped changes and adds focused tests for changed behavior.
- Runs applicable build/tests, then full Recheck against prior JSON.
- Reports Resolved, Persisting, New, and Could not reverify; keeps manual/external work visible.

Fail if disappearance of a static pattern alone is called a verified runtime fix.

## 9. Rejection response

- Reads the full Apple message and preserves build, cited guideline, device/OS, locale, attachments, and reported route.
- Separates formal reason, evidence-backed likely cause, alternatives/unknowns, minimum remedy, new-build decision, and verification.
- Drafts concise, professional, factual reviewer communication with numbered steps.
- Does not argue without evidence; when unclear, asks for device, OS, exact steps, and screenshot/video.

Fail if the response is generic, hostile, speculative, or omits whether a new binary is required.

## 10. Required limitations

Every full result states that static analysis does not replace a physical device; Simulator does not replace a device; metadata requires App Store Connect; purchases require Sandbox; source currency requires live access; passing does not guarantee approval; subjective rules need expert interpretation; and high-risk legal material needs qualified review.

## Acceptance

A scenario passes only if no fail condition occurs and all applicable mandatory checks are addressed as Passed, Failed, Not verified, or Not applicable with evidence. Wording and presentation may vary; the expected response is an evidence-backed decision aid, not a fixed prose snapshot.

The `compliant_app` fixture is a minimal buildable SwiftUI regression app with no intentional static rejection signals. Its name is not evidence that a real product will pass App Review; runtime behavior, live App Store Connect state, legal content, purchases, and resolved third-party SDK behavior still require separate verification.
