# App Store Review Audit Skill for Codex

[![Tests](https://github.com/maxeriomov-ship-it/app_store-review/actions/workflows/tests.yml/badge.svg)](https://github.com/maxeriomov-ship-it/app_store-review/actions/workflows/tests.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

[Русская версия](README.ru.md)

An independent, open-source Codex skill for evidence-backed App Store submission readiness audits. It inspects iOS-capable projects, identifies potential review risks, maps findings to current official Apple sources, proposes scoped remediation, and supports rechecking after fixes.

This project is not affiliated with, endorsed by, or sponsored by Apple or OpenAI.

## Why this exists

App Store readiness spans code, build configuration, privacy, third-party SDKs, StoreKit, subscriptions, account flows, user-generated content, AI data sharing, metadata, legal links, and reviewer access. A normal code review rarely checks these areas together or distinguishes an official requirement from a practical hypothesis.

This skill provides one repeatable workflow with explicit evidence levels and honest `Not verified` results when static analysis cannot prove runtime or App Store Connect behavior.

## Key capabilities

- Full pre-submission audit and fast blocker-focused pass.
- Read-only stack detection and 15 isolated static scanners.
- JSON and Markdown reports with stable finding IDs.
- Findings linked to an official Apple source, section, applicability, and verification date.
- Risk severity, verification status, confidence, evidence completeness, source freshness, and audit coverage.
- Scoped Fix workflow that changes only user-selected findings.
- Recheck comparison against a previous JSON report.
- Apple rejection analysis, reviewer response drafting, and App Review Notes preparation.
- App Store Connect evidence checklist.
- Privacy, privacy manifest, ATT, required-reason API, and third-party SDK checks.
- StoreKit, subscriptions, in-app purchases, and paywall checks.
- AI and user-generated content audit workflows.

## Supported project types

- SwiftUI and UIKit
- Xcode projects and workspaces
- Swift Package Manager and CocoaPods
- React Native
- Flutter
- Capacitor
- Expo projects with a native iOS build
- Other repositories containing an iOS target

## Audit areas

The workflow covers project and Release configuration, reliability, authentication and account deletion, purchases and subscriptions, privacy, dependencies, system permissions, AI integrations, user-generated content, UI and accessibility review prompts, minimum functionality, App Store metadata, legal materials, and reviewer access.

Static scanners produce leads, not automatic verdicts. Contextual exceptions, runtime behavior, backend state, built-bundle contents, Sandbox transactions, and live App Store Connect records remain explicit manual checks.

## Examples of findings

- Empty or generic permission purpose string.
- Staging or reserved-domain URL reachable from release code.
- User-visible placeholder content or unsafe Swift cast.
- Social login without a detected equivalent privacy-preserving route, subject to Guideline 4.8 exceptions.
- Account creation without a detected in-app deletion route.
- Subscription flow without detected restore or disclosure elements.
- Listed SDK without a dependency-specific source-visible privacy manifest.
- Possible personal-data transfer to a third-party AI provider without detected recipient disclosure and explicit permission.
- User-generated content features without detected report, block, moderation, or support controls.
- Missing or incomplete App Store Connect evidence.

Every finding includes its limitations. Absence of a keyword is not treated as proof of a runtime violation.

## Requirements

- macOS for Xcode-specific checks.
- Python 3.9 or newer. The scanners use the Python standard library.
- Codex with personal skills support.
- Optional: Xcode command-line tools for deeper project checks.
- Optional: App Store Connect evidence and StoreKit Sandbox results for higher coverage.

No root access is required. The installer does not install Python packages.

## Install

Use a local clone so you can inspect the code before running it:

```bash
git clone https://github.com/maxeriomov-ship-it/app_store-review.git
cd app_store-review
./install.sh
```

The skill is copied to:

```text
$HOME/.agents/skills/app_store_review
```

If an installation already exists, `install.sh` asks for confirmation and moves the existing directory to a timestamped backup before installing. For non-interactive use after inspection:

```bash
./install.sh --yes
```

To test installation without touching your personal skills directory:

```bash
CODEX_SKILLS_DIR="$(mktemp -d)" ./install.sh --yes
```

## Update

From the cloned repository:

```bash
./update.sh
```

The script requires a clean checkout, performs `git pull --ff-only`, then installs the updated copy while preserving the previous installation as a backup.

## Uninstall

```bash
./uninstall.sh
```

Uninstall asks for confirmation and moves the installed skill to a timestamped `.removed-*` backup instead of permanently deleting it. Non-interactive form:

```bash
./uninstall.sh --yes
```

## Invoke the skill explicitly

Full audit:

```text
$app-store-review Audit this iOS project before App Store submission. Keep the project read-only and use the full profile.
```

Fast blocker check:

```text
$app-store-review Quickly check this app for blocking App Store rejection risks.
```

Selected fixes:

```text
$app-store-review Fix only the finding IDs I selected. Show the exact proposed changes first, test them, and run Recheck.
```

Rejection response:

```text
$app-store-review Analyze this complete Apple rejection message, identify the evidence-backed cause, determine whether a new build is needed, and draft a reviewer reply.
```

## Automatic triggering

The skill metadata is designed for English and Russian requests such as:

- “Check the app before release.”
- “Audit this app before submitting it to the App Store.”
- “Check the paywall before App Store Review.”
- “Find potential Apple rejection reasons.”
- “Analyze this Apple rejection and prepare a reviewer response.”
- “Проверь приложение перед отправкой в App Store.”
- “Проверь риск реджекта.”
- “Разбери отказ Apple.”

It is not intended to activate for ordinary code review, general QA, or Google Play-only publication.

## Modes

### Audit

Default, read-only mode. It combines static findings with manual device, backend, Sandbox, legal, and App Store Connect checks. Use `full` for release readiness or `blockers` for a quick pass. A blockers-only pass cannot produce `Ready`.

### Fix

Changes only explicitly selected findings. Codex must show the proposed scope before editing, avoid unrelated refactoring, add focused tests where behavior changes, build/test the result, and run Recheck. The workflow does not invent legal or privacy-policy language.

### Recheck

Compares the current project with a previous JSON report and separates resolved, persisting, new, and unable-to-reverify findings.

### Rejection response

Separates Apple's cited rule from the evidence-backed likely cause, checks the related code, screen, metadata, or backend state, recommends the minimum remedy, determines whether a new binary is needed, and drafts precise review steps and a professional reply.

## Recommended reasoning level

The skill works with any reasoning level available in Codex. The selected level affects audit depth, execution time, and how many edge cases Codex can investigate; it does not change Apple's requirements.

- **Medium:** quick audits, small applications, targeted checks, and verification after fixes.
- **High:** the primary recommendation for a complete pre-submission audit and for most production applications.
- **Extra High:** complex applications involving subscriptions, multiple authentication methods, third-party SDKs, artificial intelligence, user-generated content, sensitive data, or complicated App Store requirements.
- **Pro:** the deepest review of a large commercial application, particularly before its first submission or after repeated App Store rejections.

For a final release audit, use High or Extra High when available. Model names and available reasoning levels may change, so choose primarily by the required reasoning depth rather than a specific model or model version. No reasoning level guarantees that every issue will be found or that Apple will approve the application.

## Direct scanner usage

The scripts are read-only:

```bash
python3 "$HOME/.agents/skills/app_store_review/scripts/run_audit.py" \
  "/absolute/path/to/project" \
  --profile full
```

With App Store Connect evidence:

```bash
python3 "$HOME/.agents/skills/app_store_review/scripts/run_audit.py" \
  "/absolute/path/to/project" \
  --profile full \
  --asc-metadata "/absolute/path/to/app_store_connect.json"
```

Recheck:

```bash
python3 "$HOME/.agents/skills/app_store_review/scripts/run_audit.py" \
  "/absolute/path/to/project" \
  --baseline "/absolute/path/to/previous-report.json"
```

Reports default to a temporary directory so the audited project is not modified. Explicit report paths must also be outside the audited project; the runner rejects in-project destinations to preserve Audit mode's read-only guarantee.

## Example report summary

Illustrative output from the repository's intentionally risky fixture:

```text
Readiness: Not ready
Risk index: 72 / 100
Coverage: 51 / 100
Evidence completeness: 100 / 100
Source freshness: 100 / 100

Findings:
- High: 8
- Medium: 9
- Informational: 2
```

These numbers describe that fixture and test environment only. They are not effectiveness claims and must not be generalized to real submissions.

## Risk index

The 0–100 risk index is an internal weighted prioritization heuristic based on finding severity, confidence, and verification. It is not a statistical probability that Apple will reject an app. A high score means the detected evidence deserves attention; it does not predict a reviewer decision.

## Audit coverage

Coverage represents the proportion of applicable checks that produced verified static or supplied evidence. Runtime-only, device-only, Sandbox, backend, legal, and App Store Connect checks remain `Not verified` until evidence is supplied. High coverage does not guarantee correctness or approval.

## Official-source policy

Mandatory Apple requirements are mapped only to official Apple pages. The registry records the source title, section, canonical URL, last verification date, summary, applicability, and source status. Living pages must be checked again when internet access is available.

Unofficial articles, package names, anecdotes, and static patterns are hypothesis inputs only. The Mehran/AetherMaker article is not copied into this repository and is never treated as an authoritative requirement.

See `app_store_review/references/source_policy.md` and `app_store_review/references/apple_source_registry.json`.

## Limitations and disclaimer

- Static analysis does not replace testing on a physical device.
- Simulator testing does not replace a physical device.
- App Store Connect metadata cannot be completed without current App Store Connect evidence.
- Purchases cannot be confirmed without StoreKit Sandbox or an equivalent authorized environment.
- Static source cannot prove every SDK behavior, backend flow, entitlement, or built-bundle property.
- Some Apple rules require contextual or expert interpretation.
- Passing this audit does not guarantee App Store approval.
- This project is not legal advice. High-risk legal, privacy, consumer-protection, or contractual questions require qualified professional review.

## Report a false positive

Use the [false-positive issue template](.github/ISSUE_TEMPLATE/false_positive.yml). Include the finding ID, redacted evidence, project stack, expected behavior, and the smallest reproducible example. Never include credentials, customer data, unpublished source, or signing material.

## Report an Apple guideline update

Use the [Apple guideline update template](.github/ISSUE_TEMPLATE/apple_guideline_update.yml). Link the canonical Apple page, identify the changed section and effective date, and explain which checks may be affected. Nonofficial reports can be submitted as hypotheses but cannot replace an Apple source.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). Changes to scanners should include a focused regression fixture or self-test. Changes to mandatory requirements must update the source registry and cite a current official Apple page.

Run the complete local suite with:

```bash
python3 app_store_review/scripts/run_self_tests.py
```

## Security

See [SECURITY.md](SECURITY.md). Do not report secrets or private project data in public issues.

## License

Licensed under the [Apache License 2.0](LICENSE). Copyright 2026 Max Danilov.

## Roadmap

Near-term work focuses on stronger Xcode target mapping, more built-bundle verification, expanded StoreKit test evidence, additional cross-platform fixtures, and safer source-registry maintenance. See [ROADMAP.md](ROADMAP.md). Roadmap items are plans, not commitments.
