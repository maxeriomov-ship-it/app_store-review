# Risk model

The model prioritizes work. It does not estimate the statistical probability that Apple will reject an app.

## Finding dimensions

### Severity

- **Critical** — verified release blocker or serious safety/privacy/commerce failure with immediate submission impact.
- **High** — material guideline or reviewability risk likely to block approval if applicable and reproduced.
- **Medium** — meaningful issue that can cause rejection, customer harm, or incomplete review but needs context or has narrower scope.
- **Low** — limited-impact quality, clarity, or consistency issue.
- **Informational** — fact, reminder, or manual check without a detected defect.

Severity measures impact, not certainty. A speculative finding should not become Critical merely because the possible consequence is serious.

### Verification

- **Verified** — direct project/runtime/App Store Connect evidence confirms the issue and its applicability.
- **Likely** — multiple consistent signals support it, but an important runtime or external fact is missing.
- **Possible** — heuristic lead or absence-based signal; contextual validation is required.
- **Not verified** — the audit lacks the evidence or tool needed to decide.

### Confidence

- **High** — evidence is direct, reproducible, and mapping to the source is clear.
- **Medium** — evidence is useful but incomplete or has plausible alternatives.
- **Low** — keyword/absence inference, inaccessible external state, or subjective interpretation.

## Aggregate metrics

- **Risk index (0–100):** internal weighted heuristic derived from severity, verification, and confidence, with a cap at 100. It is for triage and comparison under the same model. Never present it as rejection probability, approval chance, or Apple score.
- **Coverage (0–100):** proportion of applicable checks that reached Passed or Failed rather than `Not verified`. `Not applicable` checks are excluded from the denominator.
- **Evidence completeness (0–100):** completeness of required finding fields and supporting evidence. It does not prove evidence correctness.
- **Source freshness (0–100):** recency/completeness of cited registry entries. It does not prove that a living source remains unchanged.

Do not compare indices from materially different profiles or evidence sets without explaining the difference.

## Readiness status

- **Ready** — no unresolved blocking findings and all critical applicable domains were checked with adequate evidence in a full audit.
- **Conditionally ready** — no confirmed blocker, but bounded medium/low risks or explicit manual prerequisites remain.
- **Not ready** — one or more verified or sufficiently supported blocking issues remain.
- **Insufficient evidence** — critical applicable domains, App Store Connect inputs, runtime paths, or external requirements are too incomplete to support readiness.

`Ready` is forbidden when a critical applicable area is `Not verified`, a scanner failed in a critical domain, only the blockers profile ran, App Store Connect evidence required for the requested conclusion is absent, or purchase/runtime behavior essential to the submission remains untested.

## Triage order

1. Verified Critical/High findings.
2. Likely High findings with cheap confirmation.
3. Submission blockers in App Store Connect, review access, privacy, commerce, crashes, and incomplete content.
4. Medium risks and customer-facing failures.
5. Low and informational improvements.

Do not bury uncertainty: include readiness reasons and unverified domains next to the aggregate metrics.
