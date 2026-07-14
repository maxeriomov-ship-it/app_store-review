# Fix playbook

Fix mode is opt-in and finding-scoped. An audit request alone never authorizes project changes.

## Authorization gate

Before editing, show:

- selected finding IDs and evidence;
- proposed behavior change and exact scope;
- expected files/components and focused tests;
- runtime, metadata, backend, or legal work that cannot be automated;
- special warning before changing any legal, consent, privacy, subscription, or user-facing contractual text.

Proceed only for issues the user explicitly selected. If the requested remedy would require an architectural change, broad refactor, new provider, new data practice, or invented policy claim, stop and ask for direction.

## Change principles

1. Make the smallest change that resolves the evidenced issue.
2. Preserve existing architecture, style, unrelated user changes, signing, profiles, and release infrastructure.
3. Do not change App Store Connect, publish, upload, or submit.
4. Do not install dependencies unless the selected fix requires one and the user authorizes it.
5. Do not invent legal/privacy copy. A safe code fix can add a link slot or consent mechanism, but final claims and URLs must come from the user or qualified owner.
6. Do not convert a heuristic lead into an implementation requirement without confirming applicability.

## Common fix classes

| Finding class | Safe scoped implementation | Avoid | Required verification |
|---|---|---|---|
| Empty/generic permission purpose | Replace only with user-approved, feature-specific wording tied to actual use | Inventing a purpose or retaining unused permission | Trigger prompt on clean device; confirm denial/recovery and localization |
| Placeholder/test endpoint/content | Remove or gate from Release; use approved production configuration | Guessing production URL or deleting intentional test tooling globally | Archive Release; inspect resolved configuration; exercise affected route |
| Crash/unsafe cast/unwrap | Add narrow type/optional/error handling and a focused regression test | Broad defensive rewrite that hides invariant violations | Unit/UI test plus exact failing scenario on Release build |
| Account deletion | Add discoverable initiation and complete backend/token/data lifecycle according to product/legal decisions | Local-only “delete” that leaves server data; invented retention claims | Create/delete/relogin; verify backend, token revocation, subscription messaging |
| Social login | Confirm Guideline 4.8 applies and exceptions do not; implement approved equivalent option | Demanding Sign in with Apple from package-name evidence alone | New/returning login, privacy properties, account linkage/deletion, reviewer route |
| Restore/entitlements | Add visible restore/reconciliation appropriate to restorable product types | Treating consumables as universally restorable or trusting local flags | StoreKit Test + Sandbox restore, reinstall, device change, pending/refund/revocation |
| Paywall disclosure | Bind UI to localized StoreKit data; show value, duration, full price/trial conversion, renewal, restore/manage, legal links | Hard-coded price or invented subscription terms | Compare every locale/product in Sandbox and App Store Connect |
| Privacy manifest/SDK | Declare only actual APIs/data/purposes with approved reason; update exact embedded SDK when needed | Adding boilerplate declarations “just in case” | Inspect archive privacy report, embedded manifests/signatures, runtime behavior |
| AI consent/disclosure | Present recipient/data/purpose disclosure and explicit choice before applicable personal-data transfer | Claiming no transfer without tracing payload; prechecked/ambiguous consent | Capture request path; verify deny path sends nothing; policy/deletion consistency |
| UGC controls | Add reachable report/block/filter/moderation/support mechanisms appropriate to the product | Cosmetic buttons without backend enforcement or response process | End-to-end prohibited-content, report, block, moderator response, contact test |
| Broken legal/support link | Use user-approved canonical URL and ensure in-app/ASC consistency | Fabricating policy pages or legal text | Live check status/content/redirect/locale from supported regions |
| Localization mismatch | Update selected localized resource/metadata with owner-approved copy | Machine-inventing legal, price, or policy meaning | Longest strings, RTL if supported, every paywall/product/ASC locale |

## Test sequence

1. Run focused unit/integration/UI tests for changed behavior.
2. Build the exact supported Release scheme/artifact when tools and dependencies are available.
3. Repeat the original reproduction command/test.
4. Run full Recheck against the prior JSON report.
5. Inspect new findings and affected adjacent states.
6. Perform applicable physical-device, Sandbox, backend, and App Store Connect confirmation.

If a tool is absent, dependency cannot resolve, signing is unavailable, or external access is missing, record `Not verified`; do not install, reconfigure, or sign around the limitation without authorization.

## Handoff

Report selected changes, tests/builds and outcomes, Recheck `resolved/persisting/new`, and remaining manual actions. Do not claim a finding resolved if only its text pattern disappeared while the required runtime or external behavior remains untested.
