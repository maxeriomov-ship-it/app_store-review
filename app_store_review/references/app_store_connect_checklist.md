# App Store Connect checklist

App Store Connect is external state. Without current evidence, mark this domain `Not verified`; never infer completion from repository files.

## Evidence to request

Prefer a dated export or structured evidence JSON plus screenshots of the live version record. The scanner accepts `--asc-metadata <json>` with these core fields:

```json
{
  "name": "…",
  "subtitle": "…",
  "description": "…",
  "keywords": "…",
  "category": "…",
  "localizations": ["en-US"],
  "marketing_url": null,
  "app_previews": [],
  "support_url": "https://…",
  "privacy_policy_url": "https://…",
  "screenshots": ["…"],
  "age_rating": "…",
  "review_contact": {"name": "…", "email": "…", "phone": "…"},
  "review_notes": "…",
  "app_privacy": {"evidence_date": "…"},
  "requires_login": false,
  "demo_account": {},
  "in_app_purchases": []
}
```

Do not put production-user credentials or secrets in a repository evidence file. A JSON snapshot does not prove the live record; record its capture date and manually compare before submission.

## App-level information

- App name and subtitle are accurate, final, localized, and consistent with the installed app.
- Bundle ID/SKU/primary language/category/content rights/Kids Category choices match the product.
- Privacy Policy URL is public, current, and appropriate for every relevant locale/territory.
- Age-rating questionnaire reflects actual content, unrestricted web access, UGC/chat, medical/wellness, gambling/contests, violence, sexual content, and other capabilities. `Unrated` cannot publish.
- If social-media functionality applies, confirm the new age-rating questions and their announced September 2026 gate from `NEWS-AGE-SOCIAL` and current App Store Connect state.
- License/EULA choice and rights are owner-approved; do not invent custom legal terms.

Sources: `ASC-APP-INFORMATION`, `ASC-AGE-RATING`, `NEWS-AGE-SOCIAL`.

## Version metadata and product page

- Description, keywords, promotional text, version text, category, and every localization accurately describe the submitted build.
- Support URL opens a working page with a real support route and current contact information.
- Marketing URL, when supplied, is public and relevant.
- Screenshots show the current app UI and functionality; required device sets, dimensions, count, and localization are accepted by App Store Connect. Do not use mock behavior as if it were functional.
- App previews, when supplied, are current, correctly localized, and meet App Store Connect technical constraints.
- Localized fields have no placeholders, untranslated fragments, stale prices/features, unsupported claims, or fallback surprises.
- Product-page claims, privacy disclosures, age rating, and available features agree with one another and with regional/feature-flag behavior.

Sources: `ARG-2.3`, `ASC-PLATFORM-METADATA`, `ASC-SCREENSHOTS`, `ASC-LOCALIZATION`.

## App Privacy

- App Privacy answers cover first-party behavior and integrated third parties in the exact submitted build.
- Data types, collection status, linkage, tracking, and purposes match the actual data map and current privacy policy.
- Privacy-policy URL and optional privacy-choices URL work without reviewer-only access.
- Changes in SDKs, analytics, ads, identity, AI, support, payments, or backend processing were reflected in the answers.

Use `privacy_audit.md`. Sources: `ASC-APP-PRIVACY`, `APP-PRIVACY-DETAILS`, `ARG-5.1.1`, `ARG-5.1.2`.

## In-app purchases and subscriptions

For each product and locale verify:

- product ID, type/duration, reference/display name, description, price/availability, tax/category state, and cleared agreements;
- product status and inclusion in the intended app submission when required;
- localization matches the StoreKit-rendered paywall;
- review screenshot shows where/how the purchase is offered, not merely marketing art;
- review notes explain any non-obvious access route, dependencies, product ordering, or setup;
- subscriptions are in the correct group and level/order, with intended upgrade/downgrade behavior;
- the exact Sandbox product loads and entitlement behavior matches the release build.

Sources: `ASC-IAP`, `ASC-SUBSCRIPTIONS`, `ARG-3.1.1`, `ARG-3.1.2`.

## Build and submission state

- Correct app version/build is selected and processing is complete.
- Release build uses the current required toolchain/platform SDK according to `UPCOMING-REQUIREMENTS` on the upload date.
- Export-compliance determination and documentation are complete for the app's encryption use.
- Content rights, regional compliance, agreements, tax/banking, and other visible App Store Connect gates are resolved.
- Capabilities, entitlements, associated services, and backend environment correspond to the selected binary.
- Recheck Apple Developer News, Upcoming Requirements, and App Store Connect release notes immediately before submission.

Sources: `UPCOMING-REQUIREMENTS`, `ASC-EXPORT`, `ASC-SUBMIT-REVIEW`, `ARG-2.1`.

## App Review information

- Contact name, email, and phone are monitored during review.
- Notes describe exact numbered routes to gated, hidden, role-based, hardware-dependent, regional, AI, UGC, and purchase features.
- If sign-in is required, a dedicated, non-expiring review account or approved full demo mode reaches all relevant features. Test it from a clean device/network.
- Explain 2FA, one-time code, region, VPN, sample data, hardware, permission, backend, or feature-flag requirements precisely.
- Include purchase/restore steps and expected product name when commerce applies.
- Add a short video only when hardware interaction or a hard-to-reproduce sequence genuinely helps; it does not replace functional review access.

Use `reviewer_notes_template.md`. Sources: `ARG-2.1`, `ASC-PLATFORM-METADATA`.

## Result rule

Mark individual evidence items Passed/Failed/Not verified. Do not mark the metadata domain complete from field presence alone: live rendering, localization, URL content, binary/product status, agreements, and review access require current manual confirmation.
