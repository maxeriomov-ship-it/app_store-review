# Third-party components and materials

## Distributed skill

The installed skill uses Python's standard library and macOS/Xcode command-line tools when available. No third-party Python package, binary, framework source, Apple documentation, or third-party article is vendored in the distributed skill.

Fixture files mention technologies such as Google Sign-In and use synthetic endpoints to exercise detection logic. They do not include those SDKs' source or binaries.

Apple requirements are represented by canonical links and short original summaries. The Mehran/AetherMaker article and other unofficial articles are not reproduced.

## Repository automation

GitHub Actions and the local release audit invoke, but do not redistribute as part of the installed skill, the following upstream tools:

| Component | Pinned version | Upstream license | Purpose |
|---|---:|---|---|
| [actions/checkout](https://github.com/actions/checkout) | v7.0.0 | MIT | Repository checkout |
| [actions/setup-python](https://github.com/actions/setup-python) | v6.3.0 | MIT | Python runtime setup |
| [actions/dependency-review-action](https://github.com/actions/dependency-review-action) | v5.0.0 | MIT | Pull-request dependency review |
| [step-security/harden-runner](https://github.com/step-security/harden-runner) | v2.20.0 | Apache-2.0 | Hosted-runner hardening and egress audit |
| [lycheeverse/lychee-action](https://github.com/lycheeverse/lychee-action) | v2.9.0 | Apache-2.0 | Public Markdown link checking |
| [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) | v8.30.1 | MIT | Secret scanning via a checksum-verified CLI release |

Each component remains governed by its upstream license and terms. Full commit SHAs or release checksums are pinned in the workflow files.

## Project license choice

Apache License 2.0 is appropriate for this repository because the original skill, scripts, fixtures, and documentation are owned project content; the license permits broad reuse and contribution while providing explicit patent terms and preserving notices. No identified vendored material requires a conflicting license.
