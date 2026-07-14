# Contributing

Thank you for improving the App Store Review Audit Skill for Codex.

## Before opening a change

- Search existing issues and pull requests.
- Use the false-positive template for scanner calibration problems.
- Use the Apple guideline update template for changed official requirements.
- Do not include private source code, credentials, signing files, customer data, or App Store Connect exports from real apps.
- Keep mandatory claims tied to current official Apple pages.

## Local setup

Requirements are Python 3.9+ and, for Xcode fixture checks, macOS with Xcode command-line tools.

```bash
git clone https://github.com/maxeriomov-ship-it/app_store-review.git
cd app_store-review
python3 app_store_review/scripts/run_self_tests.py
```

No Python package installation is required for the skill or its self-tests.

## Change guidelines

### Scanner changes

- Preserve read-only behavior.
- Treat heuristic matches as leads, not final violations.
- Include evidence, confidence, verification, limitations, remediation, and a confirmation method.
- Add a focused regression test for each bug fix or new heuristic.
- Confirm one scanner failure cannot terminate the complete audit.
- Avoid broad keywords that turn ordinary UI text or comments into feature detection.

### Apple requirement changes

- Use an official Apple URL for every mandatory claim.
- Record the exact section or topic, applicability, status, and verification date.
- Update both `apple_source_registry.json` and the readable registry when needed.
- Mark future effective dates and conditional requirements explicitly.
- Do not convert Human Interface Guidelines or community anecdotes into universal rejection rules.

### Documentation changes

- Keep English and Russian README content materially equivalent.
- Avoid guarantees, invented effectiveness metrics, or claims of affiliation with Apple or OpenAI.
- Prefer short paraphrases and links over copied documentation.

## Required checks

```bash
python3 -m py_compile app_store_review/scripts/*.py
python3 app_store_review/scripts/run_self_tests.py
sh -n install.sh update.sh uninstall.sh
```

On macOS, also confirm the compliant fixture is readable by Xcode. GitHub Actions runs the portable checks on Ubuntu and the complete self-tests, including paths with spaces, Unicode, and fixture immutability.

## Pull requests

- Keep changes focused.
- Explain the problem, evidence, risk of false positives, and validation performed.
- Identify official Apple sources when behavior depends on an Apple requirement.
- Do not update generated reports or include build products.

By contributing, you agree that your contribution is licensed under Apache License 2.0.
