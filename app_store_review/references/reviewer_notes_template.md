# App Review Notes template

Use only verified facts for the submitted build. Delete irrelevant sections. Replace every bracketed placeholder; never invent credentials, product IDs, routes, hardware, or backend state.

```text
Build and scope
- App version/build: [version] ([build])
- Main changes in this submission: [brief factual summary]
- Supported devices/OS relevant to review: [facts]

Review environment
- Backend/environment: [production/review environment and status]
- Region/storefront/locale requirements: [none or exact setup]
- Feature flags, time windows, VPN, sample data, or external setup: [none or exact setup]

Access
- Sign-in required: [yes/no]
- Dedicated review account: [username supplied in App Store Connect secure credential fields]
- Password: [supplied in App Store Connect secure credential fields]
- 2FA/one-time-code handling: [disabled for the review account or exact stable process]
- Roles or gated states: [how reviewer obtains each relevant role/state]
- Full demo mode, if approved/used: [exact access and limitations]

Primary review route
1. Launch the app.
2. [Exact tap and visible label.]
3. [Exact tap and visible label.]
4. [Expected result and sample data.]

[Feature name] route
1. [Start state.]
2. [Numbered taps using current UI labels.]
3. [Expected result.]

Purchases and subscriptions [delete if not applicable]
- Paywall route: [numbered route]
- Product ID / displayed plan: [verified product]
- Purchase test: [steps and expected entitlement]
- Restore Purchases route: [steps and expected result]
- Subscription management route: [steps]
- Sandbox or account prerequisites: [facts]

Permissions and hardware [delete if not applicable]
- Permission: [when prompt appears, why it is needed, deny path]
- Required hardware/accessory: [model/setup]
- If hardware cannot be shipped with the build: [exact alternative evidence or approved review arrangement]

AI and privacy [delete if not applicable]
- AI feature route: [steps]
- Recipient/consent screen route: [steps and expected deny/allow behavior]
- Sample input that contains no personal data: [safe sample]
- Data/history deletion route: [steps]

User-generated content [delete if not applicable]
- Create/view content route: [steps]
- Report content/user: [steps]
- Block user: [steps]
- Moderation/support contact: [route]

Known review-relevant details
- [Only factual explanation needed to operate the submitted build. Do not list unresolved defects as instructions.]

Contact during review
- Name: [monitored contact]
- Email: [monitored email]
- Phone: [monitored phone with country code]
```

## Quality check

- Test every route from a clean installation on the intended review account and network.
- Use labels visible in the submitted build, not internal screen names.
- Confirm credentials do not expire and 2FA cannot strand the reviewer.
- Mention non-obvious permissions, hardware, regional gates, feature flags, and backend dependencies before the route that needs them.
- Keep notes short enough to scan; add only information that changes how review is performed.
- A video can clarify a hardware or complex sequence, but it does not replace a functional build and full access.
- Do not put secrets beyond dedicated review credentials into free-form notes.

Sources: `ARG-2.1`, `ASC-PLATFORM-METADATA`.
