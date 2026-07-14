# Evidence policy

Every finding must be auditable, reproducible, scoped, and safe to share.

## Required finding fields

1. Stable unique ID and rule ID.
2. Severity, Confidence, Verification, and area.
3. Concise title and exact problem statement.
4. One or more evidence items.
5. File and line when available.
6. Command, test, or observation that produced the evidence.
7. Official Apple source object: title, section/rule, canonical URL, last checked, summary, applicability, and status.
8. Why the evidence creates risk for this app.
9. Concrete, minimal remediation.
10. Whether an automatic fix is available and why it is safe or unsafe.
11. Exact verification steps after remediation.
12. Limitations, exceptions, and whether the detector is heuristic.

## Evidence hierarchy

Prefer, in order:

1. Reproducible release-build behavior on a supported physical device.
2. App Store Connect, StoreKit Sandbox, backend, or Apple review evidence tied to the submitted version.
3. Parsed project configuration, entitlements, plist, privacy manifest, dependency lockfile, or source line.
4. Build/test/tool output captured with the exact safe command.
5. Static absence, package-name, keyword, or naming heuristics.

Absence of a keyword is not proof that a feature is absent. A package name is not proof of collection, tracking, transmission, or runtime use. Generated or vendored files can be stale. Mark such results `Possible`, usually Low confidence, and give a manual confirmation path.

## Safe collection

- Scan read-only and exclude build products, dependency caches, version-control internals, and large/generated directories unless a targeted check requires them.
- Redact tokens, API keys, passwords, authorization headers, cookies, private keys, demo credentials, personal data, and signed/query URL secrets from excerpts and reports.
- Keep excerpts minimal. Do not include whole plist files, policies, review messages, or customer content when a precise field/line suffices.
- Never run commands that sign, upload, publish, modify profiles, change developer data, mutate a simulator/device, or write to the target project during Audit/Recheck.
- A scanner failure becomes a `Not verified` check; it must not stop other scanners or silently become a pass.

## Confirmation rules

- **Runtime behavior:** state device/model, OS, app version/build, account state, network state, locale, and numbered reproduction steps.
- **App Store Connect:** record evidence date, locale, platform/version, product ID when relevant, and whether it is a screenshot/export/manual observation.
- **URL:** distinguish source-text detection from a live reachability/content check. Redirects, authentication, geo restrictions, and temporary failures require context.
- **Legal/privacy:** verify availability and consistency, but do not claim legal sufficiency. High-risk documents require qualified review.
- **Apple source:** follow `source_policy.md`; if currency cannot be verified, say so explicitly.

## Deduplication

Merge findings only when they share the same underlying defect, evidence, applicability, and remediation. Preserve distinct findings when one code signal can violate different conditional rules or requires separate owners/actions. Keep all supporting evidence and the highest justified severity; do not upgrade certainty during merge.
