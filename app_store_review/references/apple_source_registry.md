# Apple source registry

Checked: 2026-07-13. The machine-readable source of truth is `apple_source_registry.json`. Recheck living pages before asserting a mandatory rule in a live audit.

## Contents

- [Core App Review sources](#core-app-review-sources)
- [Privacy and platform sources](#privacy-and-platform-sources)
- [Commerce and metadata sources](#commerce-and-metadata-sources)
- [Current submission changes](#current-submission-changes)

## Core App Review sources

| ID | Source and section | Canonical URL | Requirement summary | Applies to | Status |
|---|---|---|---|---|---|
| ARG-1.2 | App Review Guidelines — 1.2, 1.2.1 | https://developer.apple.com/app-store/review/guidelines/ | Filter, report, block, respond, and publish contact information for UGC; age-control creator content above the rating. | UGC, chat, feeds, communities, creator content | official-current-living |
| ARG-2.1 | App Review Guidelines — 2.1; Before You Submit | https://developer.apple.com/app-store/review/guidelines/ | Final, stable app; complete information; working URLs/backends; full review access; no placeholder content. | All submissions | official-current-living |
| ARG-2.3 | App Review Guidelines — 2.3 | https://developer.apple.com/app-store/review/guidelines/ | Store metadata and review notes must accurately reflect the current app and purchases. | All submissions and localizations | official-current-living |
| ARG-3.1.1 | App Review Guidelines — 3.1.1 | https://developer.apple.com/app-store/review/guidelines/ | Use IAP for covered digital purchases; Apple says developers should provide restoration for restorable purchases. | Digital content and feature purchases | official-current-living |
| ARG-3.1.2 | App Review Guidelines — 3.1.2, 3.1.2(c) | https://developer.apple.com/app-store/review/guidelines/ | Subscription must provide ongoing value; Apple says developers should clearly describe what is received for the price. | Subscription apps | official-current-living |
| ARG-4.2 | App Review Guidelines — 4.2 | https://developer.apple.com/app-store/review/guidelines/ | Provide adequate standalone value beyond a website wrapper, ad, link collection, or light template. | All apps; especially WebView/template apps | official-current-subjective |
| ARG-4.8 | App Review Guidelines — 4.8 | https://developer.apple.com/app-store/review/guidelines/ | Social login for a primary account requires an equivalent privacy-preserving option unless an exception applies. | Social-login apps | official-current-conditional |
| ARG-5.1.1 | App Review Guidelines — 5.1.1 | https://developer.apple.com/app-store/review/guidelines/ | Privacy policy, applicable consent, purpose strings, access respect, and in-app account deletion are requirements; data minimization is stated as “should.” | All apps, conditionally by behavior | official-current-living |
| ARG-5.1.2 | App Review Guidelines — 5.1.2 | https://developer.apple.com/app-store/review/guidelines/ | Disclose and obtain permission before sharing personal data, including with third-party AI. | Apps sharing personal data | official-current-living |
| ARG-5.6 | App Review Guidelines — 5.6; rejections/appeals | https://developer.apple.com/app-store/review/guidelines/ | Keep review communications truthful and respectful; respond or appeal with evidence. | Rejection response | official-current-living |
| APPLE-APP-REVIEW | App Review — avoiding common issues | https://developer.apple.com/app-store/review/ | Official operational guidance on crashes, broken links, placeholders, review access, privacy, and lasting value. | All pre-submission audits | official-current-guidance |
| ACCOUNT-DELETION | Offering account deletion in your app — guidance and FAQ | https://developer.apple.com/support/offering-account-deletion-in-your-app/ | Easy-to-find initiation and full deletion; delayed timing, lawful retention, and subscription consequences are conditional. | Account-creation apps | official-current-guidance |
| SIWA-DELETION | TN3194 — account deletion and token revocation | https://developer.apple.com/documentation/technotes/tn3194-handling-account-deletions-and-revoking-tokens-for-sign-in-with-apple | Revoke Sign in with Apple tokens and remove developer-held data and sessions. | Sign in with Apple apps | official-current-technical-note |
| SIGN-IN-WITH-APPLE | Sign in with Apple — overview | https://developer.apple.com/documentation/signinwithapple | Native, web, and server implementation documentation for Sign in with Apple. | Apps implementing Sign in with Apple | official-current-documentation |

## Privacy and platform sources

| ID | Source and section | Canonical URL | Requirement summary | Applies to | Status |
|---|---|---|---|---|---|
| APP-PRIVACY-DETAILS | App Privacy Details — collection, data types, tracking | https://developer.apple.com/app-store/app-privacy-details/ | Defines data collection and App Privacy disclosure semantics. | Privacy labels | official-current-guidance |
| PRIVACY-MANIFEST | Privacy manifest files — overview | https://developer.apple.com/documentation/bundleresources/privacy-manifest-files | PrivacyInfo.xcprivacy records collection, tracking, and required-reason API use. | Apps and SDKs with applicable behavior | official-current-documentation |
| PRIVACY-DATA-USE | Describing data use in privacy manifests | https://developer.apple.com/documentation/bundleresources/describing-data-use-in-privacy-manifests | Use Apple-defined data types, purposes, and tracking/linkage flags. | Data-collecting apps and SDKs | official-current-documentation |
| REQUIRED-REASON-API | Describing use of required reason API | https://developer.apple.com/documentation/bundleresources/describing-use-of-required-reason-api | Declare accurate approved reasons in each relevant bundle. | Required-reason API users | official-current-living-list |
| THIRD-PARTY-SDK | Third-party SDK requirements | https://developer.apple.com/support/third-party-SDK-requirements/ | Listed SDKs require manifests and listed binary SDKs require signatures in covered submissions. | Apps using listed SDKs | official-current-living-list |
| ATT | App Tracking Transparency — overview | https://developer.apple.com/documentation/apptrackingtransparency | Framework and purpose-string implementation surface for applicable apps. | Apps whose behavior meets Apple’s tracking policy definition | official-current-documentation |
| ATT-POLICY | User privacy and data use — tracking policy | https://developer.apple.com/app-store/user-privacy-and-data-use/ | Defines tracking, examples, exceptions, and the pre-tracking ATT permission rule. | Apple-defined tracking behavior | official-current-policy |
| HIG-PRIVACY | HIG Privacy — Requesting permission | https://developer.apple.com/design/human-interface-guidelines/privacy | Ask in context and write a specific explanation of how and why access is used. | Permission UI | official-current-design-guidance |
| HIG-GENERATIVE-AI | HIG Generative AI — Privacy | https://developer.apple.com/design/human-interface-guidelines/generative-ai | Minimize, disclose, and obtain permission for personal-data use and off-device AI processing. | AI features | official-current-design-guidance |
| HIG-ACCESSIBILITY | HIG Accessibility — overview and modality guidance | https://developer.apple.com/design/human-interface-guidelines/accessibility | Audit larger text, VoiceOver, contrast, alternatives to sensory cues, and operability. | All user interfaces | official-current-design-guidance |
| HIG-LAYOUT | HIG Layout — adaptive layout guidance | https://developer.apple.com/design/human-interface-guidelines/layout | Adapt to size, orientation, safe areas, text sizing, and supported multitasking. | iPhone and iPad UI | official-current-design-guidance |

## Commerce and metadata sources

| ID | Source and section | Canonical URL | Requirement summary | Applies to | Status |
|---|---|---|---|---|---|
| STOREKIT-RESTORE | Restoring purchased products — overview | https://developer.apple.com/documentation/storekit/restoring-purchased-products | Provide a user-initiated restore mechanism for eligible purchases. | Restorable IAP | official-current-documentation |
| STOREKIT-ENTITLEMENTS | Transaction.currentEntitlements — discussion | https://developer.apple.com/documentation/storekit/transaction/currententitlements | Reconcile StoreKit 2 subscription and non-consumable entitlements. | StoreKit 2 | official-current-documentation |
| STOREKIT-TESTING | Testing In-App Purchases with sandbox | https://developer.apple.com/documentation/storekit/testing-in-app-purchases-with-sandbox | Exercise real App Store Connect products and transaction, subscription, failure, refund, and notification scenarios without charges. | IAP and subscription apps | official-current-documentation |
| STOREKIT-XCODE-TESTING | Testing at all stages with Xcode and sandbox | https://developer.apple.com/documentation/storekit/testing-at-all-stages-of-development-with-xcode-and-the-sandbox | Use StoreKit Testing, Sandbox, and TestFlight for complementary purchase and restore coverage. | StoreKit release verification | official-current-documentation |
| HIG-IAP | HIG In-app purchase — signup information | https://developer.apple.com/design/human-interface-guidelines/in-app-purchase | Show product value, duration, full localized price, trial conversion, restore/sign-in, and legal links. | Paywalls | official-current-design-guidance |
| APPLE-SUBSCRIPTIONS | Auto-renewable Subscriptions — Clearly describing subscriptions | https://developer.apple.com/app-store/subscriptions/ | Subscription sign-up screen disclosure and price prominence. | Subscription apps | official-current-guidance |
| ASC-IAP | In-App Purchase information — review and localization | https://developer.apple.com/help/app-store-connect/reference/in-app-purchases-and-subscriptions/in-app-purchase-information/ | Defines product metadata and review screenshot/notes. | App Store Connect IAP | official-current-reference |
| ASC-SUBSCRIPTIONS | Offer auto-renewable subscriptions | https://developer.apple.com/help/app-store-connect/manage-subscriptions/offer-auto-renewable-subscriptions/ | Configure product, duration, price, availability, localization, and review information. | App Store Connect subscriptions | official-current-help |
| ASC-APP-INFORMATION | App information — properties | https://developer.apple.com/help/app-store-connect/reference/app-information/app-information | Defines name, subtitle, privacy URL, bundle ID, rights, rating, Kids, and license fields. | App-level metadata | official-current-reference |
| ASC-PLATFORM-METADATA | Platform version information — metadata and review info | https://developer.apple.com/help/app-store-connect/reference/app-information/platform-version-information | Defines required listing fields, support URL, review contact, notes, and demo credentials. | Version metadata | official-current-reference |
| ASC-SCREENSHOTS | Upload app previews and screenshots — requirements | https://developer.apple.com/help/app-store-connect/manage-app-information/upload-app-previews-and-screenshots | One to ten screenshots; device and localization rules; previews optional. | Store media | official-current-help |
| ASC-LOCALIZATION | Localize app information | https://developer.apple.com/help/app-store-connect/manage-app-information/localize-app-information | Metadata localization and fallback behavior. | Localized listings | official-current-help |
| ASC-AGE-RATING | Set an app age rating | https://developer.apple.com/help/app-store-connect/manage-app-information/set-an-app-age-rating/ | Complete the questionnaire accurately; Unrated cannot publish. | All apps | official-current-help |
| ASC-APP-PRIVACY | Manage app privacy | https://developer.apple.com/help/app-store-connect/manage-app-information/manage-app-privacy | App Privacy answers must cover the app and integrated third parties. | All apps | official-current-help |
| ASC-EXPORT | Overview of export compliance | https://developer.apple.com/help/app-store-connect/manage-app-information/overview-of-export-compliance | Complete encryption determination and documentation when required. | Apps using encryption | official-current-help |
| ASC-SUBMIT-REVIEW | Overview of submitting for review | https://developer.apple.com/help/app-store-connect/manage-submissions-to-app-review/overview-of-submitting-for-review | Prepare app-version and related-content submissions and use App Review messages appropriately. | Submission workflow | official-current-help |

## Current submission changes

| ID | Source and section | Canonical URL | Change | Applies to | Status |
|---|---|---|---|---|---|
| UPCOMING-REQUIREMENTS | Upcoming Requirements — SDK, age rating, required-reason APIs | https://developer.apple.com/news/upcoming-requirements/ | Since 2026-04-28, covered iOS/iPadOS, tvOS, visionOS, and watchOS uploads require Xcode 26 and the corresponding platform 26 SDK; page tracks other live gates. | Covered non-macOS uploads | official-current-living |
| NEWS-AGE-SOCIAL | Age rating questionnaire now includes social media questions — 2026-07-09 | https://developer.apple.com/news/?id=tlur8uvi | Fields are available now and become mandatory beginning September 2026. | Social-media-capable apps | official-current-future-gate |

Every entry above was checked on 2026-07-13. The status describes source authority and volatility, not whether a project complies.
