# Audit matrix

Use project detection from `scan_project.py` to decide applicability. Run all applicable static checks, then perform or explicitly defer the manual checks. `Not verified` is a valid result; missing evidence is not a pass.

| Area | Automated/static checks | Required manual or external evidence | Key sources | Critical applicability gate |
|---|---|---|---|---|
| Project and submission state | Stack/targets, minimum iOS, SDK/toolchain signals, Release/Debug settings, schemes, signing-setting presence, capabilities, entitlements, plist, export-compliance keys, test/temp configuration | Archive/build of exact Release scheme; signing in the submission environment; agreements/export answers in App Store Connect | `ARG-2.1`, `ASC-EXPORT`, `UPCOMING-REQUIREMENTS` | All apps |
| Reliability and completeness | Force casts/unwraps, assertions, fatal paths, placeholder/test content, development URLs, incomplete routes/config | Clean install/upgrade; launch; all buttons/routes; offline, slow network, unavailable backend, denied permission, empty/error/loading states | `ARG-2.1`, `APPLE-APP-REVIEW` | All apps |
| Authentication and accounts | Login providers, account creation, logout/recovery/deletion signals, social-login alternative, demo-access clues | Create/login/logout/recover/delete; post-deletion behavior; subscription consequences; demo account and 2FA route | `ARG-4.8`, `ARG-5.1.1`, `ACCOUNT-DELETION`, `SIWA-DELETION` | Account/login apps only |
| Purchases | StoreKit imports/config, product IDs, purchase/result handling, pending/cancel/error/verification, entitlement and restore signals | StoreKit Test and Sandbox success, cancel, pending, failure, restore, reinstall, device change, refund/revocation | `ARG-3.1.1`, `STOREKIT-RESTORE`, `STOREKIT-ENTITLEMENTS`, `ASC-IAP` | Digital purchase apps only |
| Subscriptions and paywall | Plan name/duration/price/trial/value/renewal disclosure, restore/manage actions, legal links, product/localization references | Compare rendered paywall with live localized product data and App Store Connect; test purchase and entitlement lifecycle | `ARG-3.1.2`, `HIG-IAP`, `APPLE-SUBSCRIPTIONS`, `ASC-SUBSCRIPTIONS` | Subscription apps only |
| Privacy and data use | Privacy manifest structure, purpose strings, ATT signals, identifiers/analytics/ads/location/contacts/photos/camera/mic/health/device/usage/diagnostic signals, third-party endpoints | Map actual collection/linkage/tracking/recipient/retention/deletion to App Privacy and current policy; exercise prompts | `ARG-5.1.1`, `ARG-5.1.2`, `APP-PRIVACY-DETAILS`, `ASC-APP-PRIVACY`, `PRIVACY-MANIFEST`, `ATT-POLICY`, `ATT` | All apps; feature checks conditional |
| Dependencies and SDKs | SPM/CocoaPods/npm/pub/Gradle/native lockfiles, manifest presence, listed SDK names, required-reason API signals | Inspect exact embedded binary/version, SDK documentation, runtime configuration, network behavior, collected data, signatures where required | `THIRD-PARTY-SDK`, `REQUIRED-REASON-API`, `PRIVACY-MANIFEST` | Apps with third-party code |
| Permissions | Declared purpose strings, empty/generic wording, API-without-string and string-without-detected-use leads | Trigger each permission in context; confirm wording, denial path, Settings recovery, and actual necessity | `ARG-5.1.1`, `HIG-PRIVACY` | Apps requesting protected resources |
| Artificial intelligence | Provider/endpoint/API signals, payload construction, consent/disclosure/policy/deletion/safety/age signals | Confirm exact data sent, recipient, timing and explicit permission; retention/training/deletion; output safety and escalation | `ARG-5.1.2`, `HIG-GENERATIVE-AI`, `ARG-5.1.1` | AI/model integrations |
| User-generated content | Post/comment/profile/chat/media/review/community signals; report/block/filter/moderation/contact/terms signals | Create prohibited/test content; report/block; verify response/moderation and published contact; age-control creator content | `ARG-1.2`, `ASC-AGE-RATING` | UGC/chat/community apps |
| Interface and accessibility | Localization resources, permission/paywall text, orientation/device-family settings, obvious clipped/placeholder states | iPhone/iPad/Split View as supported; safe areas, keyboard, dark mode, Dynamic Type, VoiceOver, touch targets, orientation, long/RTL strings | HIG guidance: `HIG-ACCESSIBILITY`, `HIG-LAYOUT`; `ARG-2.1` only when functionality/completeness is affected | All supported form factors |
| Minimum functionality | WebView/wrapper/template/catalog/ad/link-collection signals; duplicate/template configuration | Assess standalone value, durable functionality, interactivity, and differentiation using the built app | `ARG-4.2` | All apps; always label judgment subjective |
| App Store metadata | Optional evidence JSON consistency, localizations, URLs, product references | Name, subtitle, description, keywords, category, rating, Support/Privacy/Marketing URLs, screenshots/previews, IAP metadata, review info, contacts, demo account | `ARG-2.3`, `ASC-APP-INFORMATION`, `ASC-PLATFORM-METADATA`, `ASC-SCREENSHOTS`, `ASC-LOCALIZATION`, `ASC-AGE-RATING` | All apps; cannot pass without ASC evidence |
| Legal materials | Detect URLs and in-app access points for privacy, terms/EULA, subscription terms, support, deletion, UGC rules, data-sharing consent | Open current content; compare with actual behavior and regions; qualified legal review for high-risk cases | `ARG-5.1.1`, `ARG-5.1.2`, `ARG-3.1.2` | Scope depends on features; privacy policy is broadly required by guideline |
| Reviewer operation | Review-note/demo-route signals | Exact numbered route; stable demo access; hidden flags; required hardware/permissions; purchase path; backend/region setup; concise video only if it materially clarifies | `ARG-2.1`, `ASC-PLATFORM-METADATA` | All submissions |

## Critical area decisions

At minimum, treat project/submission state, reliability/completeness, privacy, metadata/reviewer access, and current submission requirements as applicable to every app. Add accounts, commerce, AI, UGC, protected data, SDK/privacy-manifest, iPad, or hardware domains when detection or user evidence makes them applicable.

Do not return `Ready` if any applicable critical area lacks enough evidence. A source-only scan cannot fully verify runtime reliability, metadata, purchases, backend access, or physical-device behavior.

## Manual test baseline

For every full audit, record outcomes for:

- exact Release build on a supported physical iPhone;
- iPad and Split View when the app supports iPad;
- clean install and upgrade from a supported prior version;
- first launch, relaunch, background/foreground, and account-state transitions;
- offline, slow connection, backend failure, empty data, denied/revoked permission;
- all primary and reviewer-only navigation routes;
- dark mode, Dynamic Type, VoiceOver, keyboard, supported orientations, longest localization;
- purchase/Sandbox lifecycle when commerce applies;
- account deletion, AI consent, or UGC safety flows when applicable.

When these are not executed, list them under unverified areas and manual actions rather than issuing a pass.
