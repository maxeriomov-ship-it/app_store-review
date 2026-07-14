# Evaluation scenarios

Each scenario evaluates mode selection, applicability, source discipline, evidence calibration, and response shape. Fixture content is illustrative; evaluators may supply equivalent projects.

## 1. Simple SwiftUI app without an account

**Input:** SwiftUI/Xcode app with local content, no login, purchases, tracking, AI, or UGC; request: “Проверь приложение перед релизом.”  
**Expected mode:** Audit, full profile.  
**Mandatory checks:** stack/target/build/plist/entitlements, reliability/completeness, permissions, dependencies/privacy triggers, localizations/UI manual matrix, minimum functionality, metadata/reviewer access, current SDK requirement. Mark account, commerce, AI, and UGC not applicable only after confirmation.  
**Forbidden conclusions:** requiring account deletion, Sign in with Apple, ATT, PrivacyInfo.xcprivacy, or Restore Purchases merely as universal requirements; declaring Ready without device and App Store Connect evidence.  
**Expected response:** readiness metrics, prioritized findings, unverified device/metadata areas, manual actions, source registry entries, App Review Notes draft.

## 2. Subscription app and paywall

**Input:** iOS app with auto-renewable monthly/yearly products, paywall source, `.storekit` file, and partial App Store Connect evidence; request: “Проверь paywall и подписки перед App Store Review.”  
**Expected mode:** Audit; full or explicitly scoped commerce audit, never implicit Fix.  
**Mandatory checks:** product loading, full localized price/duration/value/trial conversion/renewal, legal links, restore/manage route, transaction states, entitlement reconciliation, product localizations/status/review screenshots, Sandbox matrix.  
**Forbidden conclusions:** treating StoreKit Configuration as live product proof; claiming restore is broken only because a literal button text is absent; hard-coding replacement price; calling risk index a rejection probability.  
**Expected response:** product-by-product evidence, StoreKit and ASC unknowns, specific Sandbox tests, applicable `ARG-3.1.1`/`ARG-3.1.2` and StoreKit sources.

## 3. Google login

**Input:** project includes Google Sign-In for the primary account; no obvious privacy-preserving equivalent in static source; request: “Найди потенциальные причины отклонения Apple.”  
**Expected mode:** Audit.  
**Mandatory checks:** actual login role, Guideline 4.8 applicability and exceptions, alternative provider/runtime route, account creation/recovery/logout/deletion, privacy/data flow, reviewer credentials.  
**Forbidden conclusions:** “Sign in with Apple is definitely missing” from dependency/keyword absence; ignoring guideline exceptions; editing login architecture.  
**Expected response:** at most a Possible/Low-confidence lead until control flow and exceptions are checked, with exact manual validation and official section.

## 4. App with an account

**Input:** app creates a server account and exposes logout but no detectable deletion route; user supplies backend API summary.  
**Expected mode:** Audit unless the user explicitly selects a fix.  
**Mandatory checks:** discoverable in-app deletion initiation, full backend data/token/session deletion, retention exceptions, subscription consequences, Sign in with Apple token revocation if applicable, recovery/logout, reviewer access.  
**Forbidden conclusions:** treating local logout/profile removal as account deletion; inventing retention language or legal policy; marking deletion absent solely from a missing string when backend/UI route is unknown.  
**Expected response:** calibrated static finding plus backend/device checks, minimal remedy options, `ARG-5.1.1`/`ACCOUNT-DELETION` and conditional `SIWA-DELETION`.

## 5. OpenAI API feature

**Input:** app source or backend client appears to send user prompts and account context to OpenAI; no evident pre-transfer recipient disclosure/choice; request: “Проверь AI-функцию перед App Store.”  
**Expected mode:** Audit.  
**Mandatory checks:** exact payload/recipient/trigger, personal-data applicability, consent before transfer, deny behavior, privacy policy/App Privacy, retention/training/deletion, output safety, age rating, secret redaction.  
**Forbidden conclusions:** asserting transfer from SDK name alone; printing API keys/prompts; claiming a universal AI disclaimer or age limit; treating HIG guidance as a mandatory standalone rule.  
**Expected response:** separate verified code evidence, unknown backend/runtime facts, `ARG-5.1.2` mapping, manual network/consent tests.

## 6. User chat

**Input:** app lets users message each other and share photos; source has send/display paths but no obvious report/block UI.  
**Expected mode:** Audit.  
**Mandatory checks:** UGC applicability, filtering, report, timely moderation response, block, published support contact, terms/prohibited content, age rating, backend/admin evidence, photo permissions/privacy.  
**Forbidden conclusions:** confirming missing controls only from absent keywords; assuming AI moderation exists; presenting a cosmetic UI addition as full remediation.  
**Expected response:** Possible findings until runtime/backend confirmed, end-to-end abuse test plan, `ARG-1.2` source, age-rating/metadata unknowns.

## 7. React Native project

**Input:** React Native repo with `ios/`, JS/TS feature code, native plist/entitlements, npm and CocoaPods lockfiles.  
**Expected mode:** Audit.  
**Mandatory checks:** detect React Native plus native Xcode target; inspect both JS and iOS layers, resolved dependencies, generated/native config currency, Release bundle/build, permissions, privacy manifests, deep links/routes, metadata.  
**Forbidden conclusions:** auditing only JS or only native code; treating package presence as data collection; installing packages without need/permission.  
**Expected response:** stack-aware coverage and limitations, native Release/device verification commands, framework-specific unverified areas.

## 8. Flutter project

**Input:** Flutter app with `pubspec.yaml`, plugins, `ios/Runner`, Podfile.lock, and multiple locales.  
**Expected mode:** Audit.  
**Mandatory checks:** detect Flutter/native iOS; inspect Dart feature paths, plugins and exact iOS configuration, plist/entitlements/manifests, Release build, generated registrant caveat, localization consistency, permissions/privacy.  
**Forbidden conclusions:** assuming every declared plugin runs or ships; changing generated files in Audit; marking metadata checked from app localization files.  
**Expected response:** separate static/native/external evidence, manual Release/device and ASC checks.

## 9. WebView wrapper

**Input:** app primarily loads a website, with a small native navigation shell; request: “Проверь готовность к публикации.”  
**Expected mode:** Audit.  
**Mandatory checks:** reachable production URL, offline/error/loading states, backend/reviewer access, standalone functionality and native value, payments/account/privacy/permissions, metadata accuracy.  
**Forbidden conclusions:** automatic rejection solely because WebView exists; presenting subjective Guideline 4.2 judgment as certain; live-testing URLs without permission when network access is restricted.  
**Expected response:** explicitly subjective minimum-functionality risk with concrete evidence and differentiation questions, plus verified completeness defects separately.

## 10. Apple rejection message

**Input:** complete rejection cites Guideline 2.1 and says the subscription screen did not load on iPad; device/OS and screenshot are supplied.  
**Expected mode:** Rejection response.  
**Mandatory checks:** cited rule, exact build/device/locale, iPad support and route, network/product/backend/ASC state, whether code or external configuration caused it, new-build determination, minimum fix, verification, exact review steps.  
**Forbidden conclusions:** assuming the formal 2.1 citation proves a specific root cause; arguing without reproduction; changing code before user asks; generic reply without build and route.  
**Expected response:** formal reason vs likely cause vs unknowns, remedy and build decision, concise professional English reviewer reply.

## 11. User-selected fix and recheck

**Input:** prior JSON report has an empty camera purpose string and placeholder API URL; user says “Исправь только эти два finding ID.”  
**Expected mode:** Fix followed automatically by Recheck.  
**Mandatory checks:** show exact proposed changes first; obtain owner-approved permission purpose and production URL rather than invent them; change only selected scope; add focused tests if behavior changes; build/test; compare resolved/persisting/new.  
**Forbidden conclusions:** general refactor, fixing unrelated findings, inventing URL/legal wording, claiming resolved without the original runtime/config verification.  
**Expected response:** scoped change plan, implementation/test results, Recheck groups, remaining manual actions.

## 12. Fast blockers check with missing external evidence

**Input:** mixed Capacitor/iOS project, request: “Быстро проверь риск реджекта”; no App Store Connect, device, Sandbox, or internet access.  
**Expected mode:** Audit with blockers profile.  
**Mandatory checks:** project/Release/plist/privacy/permissions/dependencies/purchases/placeholders/URLs/accounts/AI/UGC blocker leads; scanner error isolation; explicit external limitations.  
**Forbidden conclusions:** status Ready, full 100% coverage, live source currency, metadata pass, purchase pass, or guaranteed approval.  
**Expected response:** concise blockers-first result, Insufficient evidence or justified Not ready/Conditionally ready, exact next full-audit and manual steps.
