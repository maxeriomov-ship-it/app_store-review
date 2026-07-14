# Release checklist — v1.0.0

This file records checks actually completed on the public repository candidate before its first publication. The date is 2026-07-13 in the maintainer's local timezone.

## Source and skill integrity

- [x] Reviewed every file copied from the installed skill.
- [x] Kept the installed source directory read-only and prepared the repository in a separate location.
- [x] Confirmed the skill contains no build products, caches, generated reports, or temporary files.
- [x] Confirmed `SKILL.md` uses valid frontmatter, compact progressive disclosure, English/Russian triggers, and negative trigger boundaries.
- [x] Confirmed `agents/openai.yaml` matches the skill and permits implicit invocation.
- [x] Ran the official skill validator successfully.
- [x] Confirmed all skill scripts retain executable permissions.

## Functional validation

- [x] Compiled every Python scanner and repository check with Python 3.
- [x] Passed all 29 mandatory self-tests across 15 scanners.
- [x] Confirmed Unicode paths, paths with spaces, missing-tool behavior, scanner isolation, JSON/Markdown output, and fixture immutability.
- [x] Opened the compliant fixture with `xcodebuild -list`.
- [x] Built the compliant fixture in Debug for a generic iOS Simulator with signing disabled.
- [x] Built the compliant fixture in Release for a generic iOS Simulator with signing disabled.
- [x] Confirmed the compliant fixture produces no static findings.
- [x] Confirmed the risky fixture detects every intentional risk category.

## Installation lifecycle

- [x] Installed into a clean temporary skills root without root access.
- [x] Ran all self-tests from the clean installed copy.
- [x] Updated the temporary installation with `update.sh --skip-pull` and confirmed a timestamped backup was created.
- [x] Ran all self-tests from the updated copy.
- [x] Uninstalled the temporary copy and confirmed it was preserved as a timestamped `.removed-*` backup.
- [x] Repeated the lifecycle in a path containing spaces and Unicode.

## Security and privacy

- [x] Scanned the complete local Git history with checksum-verified Gitleaks 8.30.1; no leaks were found.
- [x] Checked for private keys, credentials, tokens, cookies, signing files, provisioning profiles, and sensitive file extensions.
- [x] Checked for absolute user-specific paths and identifiers tied to the maintainer's computer.
- [x] Checked for personal data and references to real closed projects.
- [x] Replaced secret-like redaction test values with explicit low-entropy test values in the public copy.
- [x] Checked shell scripts for pipe-to-shell installation, `eval`, `sudo`, unsafe root deletion, world-writable permissions, and unconfirmed replacement/removal.
- [x] Confirmed every GitHub Action reference is pinned to a full commit SHA.
- [x] Confirmed workflows use read-only default permissions, no custom secrets, and no automatic publishing or code modification.

## Sources, documentation, and licensing

- [x] Validated the machine-readable registry of 43 official Apple sources and every source record's required fields.
- [x] Ran a live link check over public Markdown links; 85 links passed and repository-self links were excluded before repository creation.
- [x] Confirmed mandatory claims use official Apple sources and unofficial material is labeled as hypothesis input.
- [x] Confirmed no third-party article or large Apple documentation excerpt is copied into the repository.
- [x] Reviewed English and Russian README content for unsupported guarantees, invented effectiveness numbers, legal-advice claims, and false affiliation.
- [x] Confirmed the displayed example metrics come only from the intentionally risky fixture and are labeled accordingly.
- [x] Reviewed runtime and CI dependencies and documented their licenses in `THIRD_PARTY_NOTICES.md`.
- [x] Confirmed Apache License 2.0 is compatible with the repository contents.
- [x] Confirmed the copyright notice is `Copyright 2026 Max Danilov`.

## Local GitHub Actions parity

- [x] Parsed all workflow and issue-form YAML files.
- [x] Ran the Python compile, repository structure/security checks, shell syntax checks, self-tests, and fixture immutability checks locally.
- [x] Ran the same Lychee link-check arguments locally with a checksum-verified binary.
- [x] Ran the same Gitleaks history scan locally with a checksum-verified binary.

ShellCheck and hosted-runner behavior are intentionally verified by the initial GitHub Actions run because ShellCheck is not installed in the local environment.
