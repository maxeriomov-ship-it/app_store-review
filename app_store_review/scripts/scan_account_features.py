#!/usr/bin/env python3
"""Detect account, social-login, deletion, recovery, and review-access signals."""

from __future__ import annotations

from audit_core import (
    ScanContext,
    check,
    code_corpus,
    find_matches,
    finish_result,
    make_finding,
    match_evidence,
    new_result,
    scanner_cli,
)


ACCOUNT_CODE_SUFFIXES = {
    ".swift", ".m", ".mm", ".h", ".js", ".jsx", ".ts", ".tsx", ".dart",
    ".kt", ".java", ".strings", ".xcstrings",
}

PATTERNS = {
    "login": r"(?<![A-Za-z0-9_])(?:sign[\s_-]?in|log[\s_-]?in|authenticateAccount|AuthView|LoginView|loginWith[A-Za-z0-9_]*|signInWith[A-Za-z0-9_]*)(?![A-Za-z0-9_])",
    "account_creation": r"(?<![A-Za-z0-9_])(?:sign[\s_-]?up|register(?:Account|User)|createAccount|createUser|new account|guest account)(?![A-Za-z0-9_])",
    "social_login": r"(?<![A-Za-z0-9_])(?:GoogleSignIn|GIDSignIn[A-Za-z0-9_]*|FBSDKLogin[A-Za-z0-9_]*|FacebookLogin|LoginManager|signInWithGoogle|loginWithGoogle|loginWithFacebook|OAuthProvider)(?![A-Za-z0-9_])",
    "apple_login": r"(?<![A-Za-z0-9_])(?:ASAuthorizationAppleIDRequest|SignInWithAppleButton|ASAuthorizationAppleIDProvider[^\n]{0,120}createRequest|signInWithApple|authorizationController.*didCompleteWithAuthorization)(?![A-Za-z0-9_])",
    "delete_account": r"(?<![A-Za-z0-9_])(?:deleteAccount|delete account|account deletion|removeAccount|close account|erase account|requestAccountDeletion|deleteProfile|eraseProfile|destroy(?:User)?Profile(?:Permanently)?)(?![A-Za-z0-9_])",
    "logout": r"(?<![A-Za-z0-9_])(?:log[\s_-]?out|sign[\s_-]?out|logout|revokeToken|disconnectAccount|disconnectProvider)(?![A-Za-z0-9_])",
    "recovery": r"forgot password|resetPassword|password reset|recover account|sendPasswordReset",
    "guest": r"continue as guest|guest mode|skip sign.?in|without an account",
}


def scan(context: ScanContext) -> dict:
    result = new_result("scan_account_features")
    root = context.root
    corpus = [
        (path, text)
        for path, text in code_corpus(root)
        if path.suffix.lower() in ACCOUNT_CODE_SUFFIXES
    ]
    hits = {name: find_matches(corpus, pattern, root) for name, pattern in PATTERNS.items()}
    capability_hits = find_matches(
        code_corpus(root), r"com\.apple\.developer\.applesignin", root
    )
    account_applicable = bool(
        hits["login"] or hits["account_creation"] or hits["social_login"] or hits["apple_login"]
    )
    if hits["social_login"] and not hits["apple_login"]:
        first = hits["social_login"][0]
        result["findings"].append(
            make_finding(
                base_id="SOCIAL-LOGIN-EQUIVALENT-NOT-DETECTED",
                severity="High",
                confidence="Low",
                verification="Possible",
                area="Authentication and accounts",
                title="Equivalent privacy-preserving login option was not detected",
                problem="Third-party/social login signals were found, but no Sign in with Apple or another recognizable equivalent option was found statically.",
                evidence_items=[match_evidence(item, "Social login signal") for item in hits["social_login"][:5]],
                file=first["file"],
                line=first["line"],
                source_id="ARG-4.8",
                risk_reason="If social login establishes the primary account and no listed exception applies, Apple requires an equivalent login with specific privacy properties.",
                remediation="Confirm Guideline 4.8 applicability and exceptions; if applicable, offer an equivalent compliant login, commonly Sign in with Apple, at comparable prominence and functionality.",
                verification_steps=["Test every primary-account login path in the release build.", "Document any Guideline 4.8 exception with evidence in App Review Notes when necessary."],
                limitations=["Static absence is not proof; login may be server-driven, generated, or implemented by a binary SDK.", "Company-only, enterprise/education, government ID, specific third-party service client, and other listed exceptions may apply.", "Current guideline wording describes required properties and does not explicitly mandate Sign in with Apple by name."],
                heuristic=True,
            )
        )
    if hits["account_creation"] and not hits["delete_account"]:
        first = hits["account_creation"][0]
        result["findings"].append(
            make_finding(
                base_id="ACCOUNT-DELETION-NOT-DETECTED",
                severity="High",
                confidence="Low",
                verification="Possible",
                area="Authentication and accounts",
                title="In-app account deletion initiation was not detected",
                problem="Account creation signals were found, but no recognizable account deletion route or action was detected.",
                evidence_items=[match_evidence(item, "Account creation signal") for item in hits["account_creation"][:5]],
                file=first["file"],
                line=first["line"],
                source_id="ACCOUNT-DELETION",
                risk_reason="Apps supporting account creation must let users initiate full account deletion within the app.",
                remediation="Add an easy-to-find deletion flow that covers the account and associated data, explains timing/retention and subscription effects, and revokes Sign in with Apple tokens when applicable.",
                verification_steps=["Create a fresh account, initiate deletion in-app, and verify server-side completion and confirmation.", "Check UGC removal, retained-data disclosure, subscription messaging, and token revocation."],
                limitations=["The action may be remote-configured, web-hosted behind a direct deep link, or named in a way the detector does not recognize.", "Regulated services may use additional verification/support steps within Apple's stated exception."],
                heuristic=True,
            )
        )
    if account_applicable and not hits["logout"]:
        first = (
            hits["login"]
            or hits["account_creation"]
            or hits["social_login"]
            or hits["apple_login"]
        )[0]
        result["findings"].append(
            make_finding(
                base_id="ACCOUNT-LOGOUT-NOT-DETECTED",
                severity="Medium",
                confidence="Low",
                verification="Possible",
                area="Authentication and accounts",
                title="Sign-out or credential-revocation path was not detected",
                problem="Account authentication was detected without a recognizable sign-out action.",
                evidence_items=[match_evidence(first, "Authentication signal")],
                file=first["file"],
                line=first["line"],
                source_id="ARG-5.1.1",
                risk_reason="Reviewers need reliable account-state control, and social-network access must be revocable when applicable.",
                remediation="Expose a reliable sign-out route and revoke/clear app and social-provider credentials as appropriate.",
                verification_steps=["Sign in, sign out, relaunch, and confirm protected data is unavailable.", "Test revoked social credentials."],
                limitations=["The control may be generated or implemented outside scanned source."],
                heuristic=True,
            )
        )
    result["facts"] = {
        **{name: len(value) for name, value in hits.items()},
        "sign_in_with_apple_capability_signal_count": len(capability_hits),
        "sign_in_with_apple_capability_without_route": bool(capability_hits and not hits["apple_login"]),
    }
    material_static_findings = [
        item
        for item in result["findings"]
        if item.get("severity") in {"Critical", "High", "Medium"}
    ]
    result["checks"].extend(
        [
            check(
                "account.static-flow",
                "Authentication and accounts",
                "Failed" if material_static_findings else ("Passed" if account_applicable else "Not applicable"),
                f"Inspected account/authentication signals and detected {len(material_static_findings)} material static finding(s)."
                if account_applicable
                else "No account or login flow was detected.",
                applicable=account_applicable,
                source_id="ARG-5.1.1",
            ),
            check(
                "account.clean-install-and-deletion",
                "Authentication and accounts",
                "Not verified" if account_applicable else "Not applicable",
                "Clean-install, access recovery, server deletion, data retention, and social-token revocation require runtime/backend verification."
                if account_applicable
                else "Account runtime checks are not applicable from current evidence.",
                applicable=account_applicable,
                source_id="ACCOUNT-DELETION",
            ),
            check(
                "account.review-access",
                "App Store Connect metadata",
                "Not verified" if account_applicable else "Not applicable",
                "Non-expiring demo credentials, 2FA handling, and full-feature access require App Store Connect review information."
                if account_applicable
                else "Demo account is not applicable from current evidence.",
                applicable=account_applicable,
                source_id="ASC-PLATFORM-METADATA",
            ),
        ]
    )
    return finish_result(result)


if __name__ == "__main__":
    raise SystemExit(scanner_cli(scan, "scan_account_features"))
