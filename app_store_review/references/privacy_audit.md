# Privacy, permissions, and SDK audit

Build an evidence-backed data-flow map for the exact release artifact. Static dependency names are leads, not proof of collection, tracking, or transmission.

## Data-flow inventory

For each first-party feature and third-party SDK, record:

| Field | Question |
|---|---|
| Data | What exact fields/categories enter the app or SDK? |
| Source | User input, device API, account/backend, third party, inferred/derived? |
| Trigger | Which user action or lifecycle event causes access? |
| Destination | On device, first-party server, named third party, model provider? |
| Purpose | App functionality, analytics, personalization, advertising, other? |
| Linkage | Can it be linked to an account/device/person? |
| Tracking | Does behavior meet Apple's cross-app/cross-site tracking definition? |
| Retention/deletion | How long, where, and how can it be deleted? |
| User control | Disclosure, consent, permission, opt-out, deny behavior? |
| Evidence | Code path, configuration, request capture, SDK docs, backend/owner confirmation? |

Cover contact info, identifiers, purchases, location, contacts, photos/video/audio, camera/microphone, health/fitness, usage, browsing/search, user content, diagnostics/crash/performance, device/environment data, analytics, ads, support, AI payloads, and derived data as applicable.

## Privacy manifest

- Locate every app and embedded SDK `PrivacyInfo.xcprivacy`; parse it as a plist.
- Validate declared collected-data types/purposes/linkage/tracking flags against actual behavior.
- Identify required-reason API usage and verify each relevant bundle declares an accurate Apple-approved reason.
- For SDKs on Apple's current list, inspect the exact embedded version/artifact for required privacy manifest and, for covered binary dependencies, signature requirements.
- Inspect the archive privacy report when available; source-tree presence alone does not prove correct embedding.

Do **not** report a missing app privacy manifest as a universal violation. Manifest requirements are trigger- and component-dependent. A matching API symbol, old dependency, or package name supports a manual investigation, not a categorical conclusion.

Sources: `PRIVACY-MANIFEST`, `PRIVACY-DATA-USE`, `REQUIRED-REASON-API`, `THIRD-PARTY-SDK`.

## App Privacy and policy consistency

- Compare the data-flow map with live App Store Connect App Privacy answers for the exact submitted version.
- Include integrated third parties, not only first-party code.
- Distinguish data processed solely on device from data collected/transmitted under Apple's definitions.
- Confirm collection, linkage, tracking, and purpose classifications with evidence; do not infer from a library name.
- Open the Privacy Policy from the product page and in-app route. Confirm it identifies relevant collection/use/sharing, third-party/AI recipients where applicable, retention/deletion/control routes, and contact details consistent with actual behavior.
- Verify data deletion follows account deletion and other product promises; identify legally required retention separately.

The audit checks availability and consistency, not legal sufficiency. Escalate high-risk legal/regulatory issues to qualified counsel.

Sources: `ARG-5.1.1`, `ARG-5.1.2`, `APP-PRIVACY-DETAILS`, `ASC-APP-PRIVACY`.

## App Tracking Transparency

1. Determine whether actual behavior meets Apple's definition of tracking; advertising or analytics SDK presence alone is insufficient.
2. If tracking applies, verify `NSUserTrackingUsageDescription`, in-context explanation, ATT request timing, deny/not-determined/restricted behavior, and that tracking does not occur before authorization.
3. Confirm the App Privacy tracking answer and policy match runtime behavior.
4. Ensure core functionality is not deceptively conditioned on tracking permission.

If applicability or pre-consent network behavior was not observed, mark it `Not verified`/`Possible`, not compliant or noncompliant.

Use `ATT-POLICY` to decide whether behavior is tracking and whether an exception applies; use `ATT` for framework implementation. Additional sources: `ARG-5.1.1`, `HIG-PRIVACY`.

## Protected-resource permissions

For every declared usage-description key:

- identify the concrete feature and API path that needs it;
- ensure wording specifically tells the user what is accessed and why;
- trigger it in context on a clean device in every localization;
- verify denial, limited selection, revocation, and Settings recovery;
- remove unused declarations only after confirming no runtime/native dependency uses them;
- investigate detected API use without an applicable purpose string.

Check location (including background/always), contacts, calendars/reminders, photos/add-only, camera, microphone/speech, Bluetooth/local network, motion, media library, health/clinical, Face ID, and other protected resources detected in the project.

Empty strings are direct defects. “Needed for the app” style text is a clarity risk. A string with no statically detected use and API use with no string are both heuristic until the final binary and runtime path are confirmed.

Sources: `ARG-5.1.1`, `HIG-PRIVACY`.

## Third-party dependency review

For every resolved package/SDK:

1. Record ecosystem, exact name/version/source, embedding target, and whether it ships in Release.
2. Inspect vendor privacy manifest/signature status where applicable.
3. Review vendor's current official data-use/configuration documentation and the app's actual initialization/options.
4. Trace runtime endpoints/payloads when authorized; redact secrets and personal data.
5. Map collected data and recipients to App Privacy and policy.
6. Review outdated/removed/disabled status using authoritative vendor/Apple evidence. Never call an SDK prohibited or obsolete solely from its name or age.

Missing tools, dependency sources, archive, live network capture, or vendor evidence become manual checks.

## Required manual scenarios

- clean install before any consent/permission;
- allow/deny/limited/revoke for each applicable permission;
- ATT authorized/denied/not-determined where tracking applies;
- signed-out/signed-in/deleted-account data behavior;
- analytics/crash/ads/AI enabled and user-disabled states;
- offline/slow/failing backend;
- archive privacy report and exact embedded SDK inspection;
- App Store Connect and policy comparison dated near submission.

Record what could not be observed; no network activity in one short session does not prove no collection.
