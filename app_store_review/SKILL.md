---
name: app-store-review
description: Comprehensive, evidence-backed Apple App Store pre-submission audit and rejection-response workflow for iOS-capable projects. Use for English or Russian requests to check an app before release or App Store submission, assess Apple rejection risk, audit a paywall or subscriptions, review App Store Connect materials, privacy/SDK/AI/user-content compliance, analyze an Apple rejection, prepare App Review Notes or a reviewer reply, fix user-selected release issues, or recheck fixes. Russian triggers include «Проверь приложение перед релизом», «проверь риск реджекта», «разбери отказ Apple», «подготовь ответ ревьюеру», and «исправь проблемы перед релизом». Supports SwiftUI, UIKit, Xcode/SPM/CocoaPods, React Native, Flutter, Capacitor, Expo native iOS, and other projects with an iOS target. Do not use for ordinary code review, general QA, or Google Play-only publication unless App Store readiness is also explicitly requested.
---

# App Store Review

Conduct an App Store readiness audit without pretending static analysis guarantees approval. Default to analysis-only Audit mode. Use only current, verified Apple sources for mandatory claims.

## Choose the mode

- **Audit** — default. Inspect and report; change nothing. Use `--profile full` for release readiness or `--profile blockers` for a fast blocking-risk pass. A blockers pass can never produce `Ready`.
- **Fix** — only after the user explicitly asks to fix and selects finding IDs or a precise scope. Show the proposed changes first, change only that scope, test it, then run Recheck. Never silently rewrite legal text or invent privacy disclosures.
- **Recheck** — compare the current project with a prior JSON report, verify selected fixes, and look for regressions.
- **Rejection response** — read Apple's complete message, separate the cited rule from the likely underlying issue, inspect related code/screens/metadata, decide whether a new build is required, propose the minimum remedy, and draft a factual reviewer reply.

If intent is ambiguous, remain in Audit. Never edit code merely because an audit found an issue.

## Start every task

1. Confirm the project root and requested mode. Record which evidence the user supplied: source, built app, device results, App Store Connect export/screenshots, StoreKit Sandbox results, rejection message, and credentials route.
2. Read `references/source_policy.md`, `references/risk_model.md`, and `references/evidence_policy.md`.
3. Resolve `SKILL_DIR` to the absolute directory containing this loaded `SKILL.md`; never assume the audited project's current directory contains the skill scripts. Run the read-only orchestrator, which detects the stack and isolates scanner failures:

   ```bash
   python3 "$SKILL_DIR/scripts/run_audit.py" "/absolute/path/to/project" --profile full
   ```

   For a quick pass, use `--profile blockers`. Add `--asc-metadata <json>` when evidence is available. Add `--network` only with permission and when live URL checks are useful. Outputs default to a temporary directory so the target project is not modified.
4. Read `references/audit_matrix.md`, then load only the domain references that match detected features:
   - privacy, permissions, SDKs: `references/privacy_audit.md`
   - purchases, subscriptions, paywalls: `references/subscription_audit.md`
   - AI or user content: `references/ai_and_user_content_audit.md`
   - metadata and reviewer access: `references/app_store_connect_checklist.md`
   - stack-specific limits: `references/platform_support_matrix.md`
5. Treat scanner output as leads, not verdicts. Validate high-impact findings against actual control flow, configuration, runtime evidence, and applicable exceptions.
6. Before stating a mandatory Apple requirement, resolve it through `references/apple_source_registry.json` and live-check the canonical Apple page when internet access is available. If it cannot be checked, say so; never reconstruct a citation from memory.
7. Present the result with `references/report_template.md`. Preserve finding IDs for Fix and Recheck.

## Mode workflows

### Audit

- Keep the project read-only.
- Combine static findings with manual device, Sandbox, backend, legal, and App Store Connect checks.
- Mark absent evidence `Not verified`; do not convert missing inputs into a pass.
- Distinguish verified violations from likely or possible risks, and distinguish enforceable rules from HIG guidance or subjective review judgment.
- Do not call the risk index a rejection probability.

### Fix

1. Read `references/fix_playbook.md`.
2. List the exact files, behavior, tests, and finding IDs proposed for change. Obtain explicit selection if not already supplied.
3. Preserve architecture and unrelated user changes. Add focused tests for changed behavior.
4. Build and run applicable tests. Never alter signing, profiles, developer data, distribution, or App Store Connect submission.
5. Run Recheck automatically and report resolved, persisting, new, and manual items.

### Recheck

Use the prior report as the baseline:

```bash
python3 "$SKILL_DIR/scripts/run_audit.py" "/absolute/path/to/project" --profile full --baseline "/absolute/path/to/previous-report.json"
```

Revalidate the original reproduction method, run applicable builds/tests, compare `resolved`, `persisting`, and `new`, and keep evidence for unresolved findings. A missing pattern is not proof that runtime behavior is fixed.

### Rejection response

1. Preserve the complete Apple message, guideline number, submission/build, device, OS, attachments, and reported steps.
2. Read `references/rejection_response_templates.md` and the relevant domain references.
3. Map the cited rule to a live official source, then inspect the exact screen, route, code, metadata, product, or backend state.
4. State separately: Apple's formal reason, evidence-backed likely cause, unknowns, minimum fix, whether a new binary is needed, and verification.
5. Draft a concise professional response and exact numbered review steps. Do not argue without evidence. If unclear, ask Apple for device, OS, reproduction steps, and screenshot/video.

## Non-negotiable guardrails

- Mandatory requirements come only from official Apple pages. Nonofficial material, including the Mehran/AetherMaker article, is hypothesis input only and must be independently verified.
- Never assert data transfer, tracking, required-reason API use, missing Sign in with Apple eligibility, or UGC noncompliance solely from a package name or missing keyword.
- Privacy manifests are conditional, not universally required. ATT is conditional on Apple's definition of tracking. Social-login exceptions and purchase-restoration scope require contextual review.
- UI aesthetics and minimum functionality are partly subjective; do not label them automatic rejection causes.
- Do not invent App Store Connect values, demo credentials, legal claims, privacy-policy content, consent language, product metadata, or review steps.
- Never publish, upload, submit, sign, change profiles, install dependencies unnecessarily, or mutate the audited project during Audit/Recheck.
- Static analysis does not replace a physical-device review; Simulator does not replace a device; StoreKit behavior requires Sandbox; metadata requires App Store Connect evidence; current rules require live source access; passing does not guarantee approval.

## Templates

- App Review Notes: `references/reviewer_notes_template.md`
- Rejection replies: `references/rejection_response_templates.md`
- Full report: `references/report_template.md`
- Manual fix and verification procedures: `references/fix_playbook.md`

Run `python3 "$SKILL_DIR/scripts/run_self_tests.py"` after changing this skill.
