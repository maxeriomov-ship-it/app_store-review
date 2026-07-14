# Rejection analysis and response templates

Use Rejection response mode only after reading Apple's complete message and attachments. Preserve exact wording privately, but quote only the minimum needed in the response.

Contents: [analysis worksheet](#analysis-worksheet), [new-build decision](#does-the-remedy-need-a-new-build), [new-build reply](#template-fixed-in-a-new-build), [external-state reply](#template-metadata-account-product-or-backend-corrected), [clarification request](#template-request-precise-reproduction-details), and [final check](#final-response-check).

## Analysis worksheet

```text
Submission: [app/version/build/date]
Apple-cited guideline: [number/title exactly as written]
Reviewer device/OS/locale: [provided / unknown]
Apple's formal reason: [plain-language paraphrase]
Reported route and observed result: [exact steps/evidence]
Related surface: [screen, code path, metadata field, IAP, backend, account]
Applicable official source checked: [title, section, canonical URL, date]
Applicability/exceptions: [facts]
Likely underlying cause: [evidence-backed; separate from formal reason]
Unknowns/alternative causes: [list]
Minimum remedy: [scoped change]
New binary required: yes / no / uncertain — [reason]
Verification performed: [device/build/account/steps/result]
Reviewer route after remedy: [numbered steps]
```

Do not infer that the cited guideline is the full root cause. Check build configuration, server state, account/role/2FA, locale/storefront, App Store Connect metadata/product status, feature flags, permissions, and reproduction timing.

## Does the remedy need a new build?

| Remedy location | Typical outcome | Confirmation needed |
|---|---|---|
| App code, bundled resource, plist, entitlement, privacy manifest, embedded SDK, compiled paywall copy | New build normally required | Reproduce on the newly uploaded build |
| App Store Connect metadata, screenshot, review notes, demo credentials | Often no new binary | Confirm the edit is allowed for current submission state and visible to review |
| Backend/feature flag/content | May not require binary, but can still require resubmission/review communication | Verify the exact submitted build against the corrected live environment |
| In-app purchase/subscription configuration | Depends on product/submission state | Confirm live product status and exact Sandbox behavior |
| Unclear or mixed | Do not guess | Ask or make the smallest verifiable build/config correction |

## Template: fixed in a new build

```text
Hello App Review Team,

Thank you for the review. We identified the issue related to Guideline [number/section] and corrected it in version [version], build [build].

What changed:
- [One factual, specific change.]
- [Second change only if necessary.]

We verified the fix on [device], [iOS version], using [review account/state].

Steps to review:
1. [Launch/sign in setup.]
2. [Exact tap using visible label.]
3. [Expected corrected result.]

[Purchase/permission/hardware/backend prerequisite, if applicable.]

Please let us know if you need any additional information.
```

## Template: metadata, account, product, or backend corrected

```text
Hello App Review Team,

Thank you for the details. We corrected the [metadata / review access / product configuration / backend] issue for the current submission. The app binary was not changed.

Correction:
- [Exact field/configuration/access change and current state.]

Steps to verify in build [build]:
1. [Exact setup.]
2. [Exact route.]
3. [Expected result.]

We confirmed this on [device/OS/account/storefront] at [date/time zone if state can vary].
```

## Template: request precise reproduction details

Use when available evidence cannot distinguish causes. Ask concrete questions, not a generic “please explain.”

```text
Hello App Review Team,

Thank you for your message regarding Guideline [number/section]. We tested build [build] using the steps currently available to us, but could not reproduce the reported behavior.

Could you please provide:
- the device model and iOS version;
- the exact steps and screen where the issue occurred;
- the account state or storefront/locale used; and
- a screenshot or screen recording of the observed result, if available?

Our tested route was:
1. [Exact step.]
2. [Exact step.]
3. [Observed result.]

This information will help us identify and correct the issue precisely.
```

## Template: evidence-based clarification or appeal

Use only when the current official rule, app behavior, and evidence clearly support the position. Remain factual and offer a reproducible route.

```text
Hello App Review Team,

Thank you for the review. We reviewed Guideline [number/section] and the behavior in build [build]. Based on [brief applicable fact], we believe [specific requirement/exception] applies to this implementation.

Evidence and steps:
1. [Exact route.]
2. [Observed behavior.]
3. [Relevant configuration or metadata fact.]

Official reference: [Apple source title and canonical URL].

Could you please reconsider the finding or clarify which behavior remains noncompliant? We are ready to make a correction if additional evidence shows one is needed.
```

## Final response check

- The cited guideline and source were live-checked or currency limitation is stated.
- Formal reason and hypothesized root cause are not conflated.
- The response says what changed, not what the team intended.
- Build/version, device/OS, account/state, and numbered route are exact.
- A new build determination is explicit.
- No blame, unsupported argument, promise of future compliance, secret, customer data, or invented legal claim appears.
- Unclear reports ask for device, OS, steps, and screenshot/video.

Source for reviewer communication and appeals: `ARG-5.6`; submission access/completeness: `ARG-2.1`.
