# Security Policy

## Supported versions

Security fixes are provided for the latest published release and the current `main` branch.

## Reporting a vulnerability

Do not place secrets, private repository contents, customer data, signing material, App Store Connect credentials, or exploit details in a public issue.

For a sensitive report, use **Security → Report a vulnerability** on this GitHub repository. Include:

- affected version or commit;
- impact and realistic threat model;
- minimal reproduction with synthetic data;
- suggested mitigation, if known.

For non-sensitive hardening suggestions, open a normal issue.

The maintainer will acknowledge a private report when practical, investigate it, and coordinate disclosure after a fix is available. No response-time guarantee is offered.

## Scope

Relevant reports include:

- leakage of project evidence, credentials, or personal data;
- unsafe installer, updater, or uninstaller behavior;
- command injection or unsafe shell handling;
- report redaction bypasses;
- workflows that expose GitHub tokens or modify external state unexpectedly;
- scanners that mutate an audited project despite read-only guarantees.

Incorrect Apple-rule interpretation or a normal false positive is not usually a security vulnerability; use the dedicated issue templates instead.
