# Purchases, subscriptions, and paywall audit

Apply only when the app sells or restores digital goods, services, features, content, or subscriptions. Determine product type and applicable App Review Guideline exceptions before prescribing IAP.

## Product and StoreKit inventory

For each product record:

- product ID, type (consumable, non-consumable, non-renewing, auto-renewable), subscription group/level, duration, availability, localization, price source, and App Store Connect status;
- where the product is fetched, displayed, purchased, verified, finished, restored/reconciled, revoked/refunded, and persisted;
- server-side entitlement or App Store Server integration when used;
- which build/environment and account expose it to App Review.

Source code or a `.storekit` file does not prove live App Store Connect configuration. Conversely, missing keyword matches do not prove an absent purchase path in wrappers or backend-driven code.

## StoreKit behavior

Inspect and manually test:

- product loading, empty/unavailable product state, retry, locale/currency changes, and backend unavailability;
- purchase success, verified/unverified result, user cancellation, pending/Ask to Buy, payment failure, interrupted transaction, and transaction finishing;
- entitlement reconciliation at launch/foreground/account change using an appropriate StoreKit mechanism;
- eligible purchase restoration through a user-initiated route, including reinstall and device change;
- upgrade, downgrade, crossgrade, expiration, grace/billing-retry state, refund/revocation, and resubscription as applicable;
- app-account ↔ App Store account mismatches and family sharing where supported.

Restoration scope depends on product type and architecture. Do not label all consumables restorable or treat the absence of a literal “Restore Purchases” string as proof of failure. Use `ARG-3.1.1`, `STOREKIT-RESTORE`, and `STOREKIT-ENTITLEMENTS` with contextual evidence.

## Paywall disclosure

On the actual purchase screen and every localization verify:

- clear plan/product name and concrete value received;
- billing duration and full localized price with the price visually prominent;
- trial/intro eligibility, trial length, charge after trial, and renewal cadence when applicable;
- auto-renewal/cancellation explanation appropriate to the product;
- visible, working Restore Purchases/reconciliation route when applicable;
- access to subscription management where appropriate;
- working Privacy Policy and Terms of Use/EULA links;
- no hard-coded price/currency disagreement with StoreKit or App Store Connect;
- no misleading countdown, fake scarcity, obscured close action, preselected ambiguity, or promise not supported by the product;
- accessible, readable layout under Dynamic Type, long locales, keyboard/safe areas, dark mode, and supported devices.

Distinguish guideline requirements from HIG recommendations and general conversion/UX preferences. Sources: `ARG-3.1.2`, `HIG-IAP`, `APPLE-SUBSCRIPTIONS`.

## App Store Connect product checks

For each IAP/subscription and localization:

- product ID/type/duration/subscription group and intended level/order;
- display name and description free of placeholder or inappropriate promotional claims;
- price, availability/territories, tax/category, agreements, and status;
- accurate App Review Screenshot showing the purchase location;
- useful review notes and route to the paywall/product;
- product inclusion with the intended submission when necessary;
- promotional/intro/offer configuration and eligibility behavior;
- consistency between App Store Connect, StoreKit-rendered data, paywall, screenshots, and product-page claims.

Sources: `ASC-IAP`, `ASC-SUBSCRIPTIONS`, `ASC-PLATFORM-METADATA`.

## Sandbox matrix

Record environment, storefront, locale, device/OS, build, tester account, product ID, expected entitlement, and outcome for:

1. first purchase;
2. cancel and payment failure;
3. pending/Ask to Buy if testable;
4. restore after local data reset/reinstall;
5. restore on another device/account state;
6. subscription renew/expire/billing retry/grace;
7. upgrade/downgrade/crossgrade;
8. refund/revocation;
9. no network/slow network/store unavailable;
10. app-account logout/login and entitlement refresh.

Without Sandbox, mark purchase and entitlement behavior `Not verified`. StoreKit Configuration tests are useful but do not replace live Sandbox/App Store Connect confirmation. Sources: `STOREKIT-TESTING`, `STOREKIT-XCODE-TESTING`.

## Failure patterns and calibrated findings

- Direct, reproducible failure to buy or restore an eligible product in the Release build: Verified High/Critical depending on submission impact.
- Literal StoreKit use with no detected error/pending/verification path: Possible/likely engineering risk; inspect control flow before escalating.
- Subscription UI missing price/duration/value or contradicting live product data: Verified/likely High when applicable.
- No detected restore string: Possible Low/Medium lead until product type and actual route are confirmed.
- Missing App Store Connect evidence: `Not verified`, not a product-compliance pass.
