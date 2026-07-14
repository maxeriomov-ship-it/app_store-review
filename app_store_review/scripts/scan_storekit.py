#!/usr/bin/env python3
"""Audit StoreKit, purchase restoration, transactions, and paywall signals."""

from __future__ import annotations

import re

from audit_core import (
    ScanContext,
    check,
    code_corpus,
    evidence,
    find_matches,
    finish_result,
    make_finding,
    match_evidence,
    new_result,
    scanner_cli,
)


STOREKIT_PATTERN = r"\bStoreKit\b|Product\.products|SKProductsRequest|react-native-iap|in_app_purchase|RevenueCat|Purchases\.|SubscriptionStoreView|StoreView"
PURCHASE_PATTERN = r"\.purchase\s*\(|addPayment\s*\(|requestPurchase|buyProduct|purchasePackage|SKPayment"
SUBSCRIPTION_PATTERN = r"SubscriptionStoreView|auto.?renew|subscription|monthly|yearly|annual|weekly|Product\.SubscriptionInfo"
RESTORE_PATTERN = r"AppStore\.sync\s*\(|restoreCompletedTransactions\s*\(|restorePurchases\s*\(|restorePurchase\s*\(|syncPurchases\s*\("
RESTORE_UI_PATTERN = r"Restore Purchases|Restore Purchase|restore_button|restoreButton"
ENTITLEMENT_PATTERN = r"Transaction\.currentEntitlements|currentEntitlements|customerInfo|activeSubscriptions"
TRANSACTION_PATTERN = r"Transaction\.updates|transaction\.finish\s*\(|paymentQueue\s*\(|completePurchase|completeTransactions|finishTransaction"
LEGAL_PATTERN = r"privacy\s*(policy)?|terms\s*(of\s*(use|service))?|EULA"


def scan(context: ScanContext) -> dict:
    result = new_result("scan_storekit")
    root = context.root
    corpus = code_corpus(root)
    storekit = find_matches(corpus, STOREKIT_PATTERN, root)
    purchases = find_matches(corpus, PURCHASE_PATTERN, root)
    subscriptions = find_matches(corpus, SUBSCRIPTION_PATTERN, root)
    restore = find_matches(corpus, RESTORE_PATTERN, root)
    restore_ui = find_matches(corpus, RESTORE_UI_PATTERN, root)
    entitlements = find_matches(corpus, ENTITLEMENT_PATTERN, root)
    transaction = find_matches(corpus, TRANSACTION_PATTERN, root)
    legal = find_matches(corpus, LEGAL_PATTERN, root)
    hard_prices = find_matches(corpus, re.compile(r"['\"](?:US)?\$\s?\d+(?:\.\d{1,2})?['\"]|['\"]\d+(?:\.\d{1,2})?\s?(?:USD|EUR|GBP)['\"]", re.I), root)
    applicable = bool(storekit or purchases or subscriptions)
    if applicable and not restore:
        first = (purchases or storekit or subscriptions)[0]
        result["findings"].append(
            make_finding(
                base_id="RESTORE-PURCHASE-NOT-DETECTED",
                severity="Medium",
                confidence="Low",
                verification="Possible",
                area="Purchases and subscriptions",
                title="User-initiated purchase restoration was not detected",
                problem="StoreKit or purchase signals were found, but no AppStore.sync, legacy restore call, or recognizable wrapper restoration API was detected. UI copy alone is not treated as restoration behavior.",
                evidence_items=[match_evidence(item, "Purchase/StoreKit signal") for item in (purchases or storekit)[:5]],
                file=first["file"],
                line=first["line"],
                source_id="STOREKIT-RESTORE",
                risk_reason="Customers need a discoverable way to regain eligible purchases after reinstalling or changing devices.",
                remediation="Add or expose a user-initiated Restore Purchases action and reconcile entitlements for the chosen StoreKit architecture.",
                verification_steps=["Use a Sandbox account with an existing non-consumable or subscription.", "Reinstall or use another device, invoke Restore Purchases, and verify access without a second charge."],
                limitations=["Restoration may be implemented in server code, generated framework code, a binary SDK, or via an unrecognized wrapper.", "Apple's guideline uses 'should' for a restore mechanism; applicability depends on product type."],
                heuristic=True,
            )
        )
    if purchases and not transaction:
        first = purchases[0]
        result["findings"].append(
            make_finding(
                base_id="STOREKIT-TRANSACTION-HANDLING-NOT-DETECTED",
                severity="High",
                confidence="Low",
                verification="Possible",
                area="Purchases and subscriptions",
                title="Transaction update and completion handling was not detected",
                problem="Purchase initiation was found without recognizable transaction updates, finishing, or queue-observer handling.",
                evidence_items=[match_evidence(item, "Purchase initiation") for item in purchases[:5]],
                file=first["file"],
                line=first["line"],
                source_id="ARG-2.1",
                risk_reason="Unfinished or externally updated transactions can leave paid access inconsistent during review.",
                remediation="Handle verified purchase results, pending/cancelled/error states, transaction updates, revocation/refund, and transaction finishing exactly once.",
                verification_steps=["Run StoreKit Test and Sandbox scenarios for success, cancel, pending, failure, refund, reinstall, and another device.", "Inspect unfinished transactions on relaunch."],
                limitations=["A purchase wrapper or server may own transaction handling outside scanned source."],
                heuristic=True,
            )
        )
    if subscriptions:
        missing_paywall_signals: list[str] = []
        corpus_text = "\n".join(text for _, text in corpus)
        for label, pattern in (
            ("duration", r"week|month|year|annual|duration"),
            ("renewal or trial conversion", r"renew|cancel|after.*trial|trial.*then"),
            ("privacy/terms links", LEGAL_PATTERN),
        ):
            if not re.search(pattern, corpus_text, re.I):
                missing_paywall_signals.append(label)
        if missing_paywall_signals:
            first = subscriptions[0]
            result["findings"].append(
                make_finding(
                    base_id="PAYWALL-DISCLOSURE-NOT-DETECTED",
                    severity="Medium",
                    confidence="Low",
                    verification="Possible",
                    area="Purchases and subscriptions",
                    title="Subscription disclosure elements were not all detected",
                    problem="Static text did not establish: " + ", ".join(missing_paywall_signals) + ".",
                    evidence_items=[match_evidence(item, "Subscription signal") for item in subscriptions[:5]],
                    file=first["file"],
                    line=first["line"],
                    source_id="APPLE-SUBSCRIPTIONS",
                    risk_reason="The signup screen needs clear value, duration, billing amount, trial conversion, restoration/sign-in, and legal access as applicable.",
                    remediation="Compare the rendered paywall against live StoreKit product data and Apple subscription disclosure requirements; add only truthful, localized elements.",
                    verification_steps=["Render the paywall in each supported locale with live Sandbox products.", "Compare displayed plan, duration, price, trial, and legal links with App Store Connect."],
                    limitations=["StoreKit views and server-driven paywalls may supply text only at runtime.", "Text presence does not prove visual prominence or accuracy."],
                    heuristic=True,
                    id_detail=",".join(missing_paywall_signals),
                )
            )
    if hard_prices:
        first = hard_prices[0]
        result["findings"].append(
            make_finding(
                base_id="PAYWALL-HARDCODED-PRICE",
                severity="Medium",
                confidence="Medium",
                verification="Likely",
                area="Purchases and subscriptions",
                title="Hard-coded currency price detected",
                problem="A price-like literal was detected in source instead of clearly using localized StoreKit product display data.",
                evidence_items=[match_evidence(item, "Price literal") for item in hard_prices[:5]],
                file=first["file"],
                line=first["line"],
                source_id="HIG-IAP",
                risk_reason="Hard-coded prices can disagree with App Store Connect, storefront currency, or trial terms.",
                remediation="Render billing price and period from the StoreKit product for the current storefront; keep any comparison subordinate and accurate.",
                verification_steps=["Test at least two Sandbox storefronts.", "Compare the payment sheet with every visible paywall price."],
                limitations=["The literal may be fixture, preview, test, or non-purchase copy."],
                heuristic=True,
            )
        )
    result["facts"] = {
        "storekit_signal_count": len(storekit),
        "purchase_signal_count": len(purchases),
        "subscription_signal_count": len(subscriptions),
        "restore_signal_count": len(restore),
        "restore_ui_signal_count": len(restore_ui),
        "entitlement_reconciliation_signal_count": len(entitlements),
        "transaction_handling_signal_count": len(transaction),
        "legal_text_signal_count": len(legal),
    }
    static_purchase_findings = bool(result["findings"])
    result["checks"].append(
        check(
            "storekit.static-flow",
            "Purchases and subscriptions",
            "Failed" if static_purchase_findings else ("Passed" if applicable else "Not applicable"),
            (
                "StoreKit/purchase sources were inspected and produced static compliance findings."
                if static_purchase_findings
                else "StoreKit/purchase sources were inspected."
                if applicable
                else "No StoreKit or in-app purchase signal was detected."
            ),
            applicable=applicable,
            source_id="ARG-3.1.1",
        )
    )
    result["checks"].append(
        check(
            "storekit.sandbox",
            "Purchases and subscriptions",
            "Not verified" if applicable else "Not applicable",
            "Purchase, restore, reinstall, device change, cancellation, payment failure, and subscription state require Sandbox verification."
            if applicable
            else "Sandbox purchase testing is not applicable from current evidence.",
            applicable=applicable,
            source_id="STOREKIT-RESTORE",
        )
    )
    result["checks"].append(
        check(
            "storekit.app-store-connect-products",
            "Purchases and subscriptions",
            "Not verified" if applicable else "Not applicable",
            "Product status, localization, pricing, review screenshot, and review notes require App Store Connect evidence."
            if applicable
            else "No product configuration appears applicable.",
            applicable=applicable,
            source_id="ASC-IAP",
        )
    )
    return finish_result(result)


if __name__ == "__main__":
    raise SystemExit(scanner_cli(scan, "scan_storekit"))
