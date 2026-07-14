#!/usr/bin/env python3
"""Extract URLs, find non-production endpoints, and optionally verify links."""

from __future__ import annotations

import ipaddress
import re
import socket
import urllib.error
import urllib.parse
import urllib.request

from audit_core import (
    ScanContext,
    check,
    code_corpus,
    evidence,
    finish_result,
    make_finding,
    new_result,
    relative_path,
    scanner_cli,
)


URL_PATTERN = re.compile(r"https?://[^\s'\"<>)}\]]+", re.I)
LEGAL_CONTEXT = re.compile(r"privacy|terms|eula|legal|support|delete account", re.I)
RESERVED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "example.com", "example.org", "example.net"}
KNOWN_METADATA_IPS = {
    "169.254.169.254",
    "100.100.100.200",
    "100.96.0.96",
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Keep a public URL from redirecting the audit into a private network."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _safe_url(raw: str) -> str:
    cleaned = raw.rstrip(".,;:")
    try:
        parsed = urllib.parse.urlsplit(cleaned)
    except ValueError:
        return cleaned.split("?", 1)[0].split("#", 1)[0]
    host = parsed.hostname or ""
    try:
        port_value = parsed.port
    except ValueError:
        port_value = None
    rendered_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    port = f":{port_value}" if port_value else ""
    return urllib.parse.urlunsplit((parsed.scheme, rendered_host + port, parsed.path, "", ""))


def _strip_xcconfig_comments(text: str) -> str:
    lines = []
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped.startswith(("//", "#")):
            lines.append("\n" if line.endswith("\n") else "")
            continue
        line = re.sub(r"\s+(?://|#).*?(?=\r?\n|$)", "", line)
        lines.append(line)
    return "".join(lines)


def _classification(url: str) -> str | None:
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return "malformed-url"
    host = (parsed.hostname or "").lower()
    if host in RESERVED_HOSTS or host.endswith((".example", ".invalid", ".test", ".local")):
        return "reserved-or-local"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and (
        not address.is_global or str(address) in KNOWN_METADATA_IPS
    ):
        return "private-local-or-metadata-address"
    labels = set(host.split("."))
    if labels & {"staging", "stage", "dev", "development", "test", "testing", "sandbox", "qa"}:
        return "non-production-host-label"
    return None


def _public_target(url: str) -> tuple[bool, str]:
    """Conservatively reject network checks that could reach local infrastructure."""

    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        return False, "only HTTP(S) destinations are allowed"
    host = parsed.hostname
    if not host:
        return False, "destination has no hostname"
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        return False, f"invalid port: {exc}"
    if port not in {80, 443}:
        return False, "non-standard network ports are not probed"
    try:
        literal = ipaddress.ip_address(host)
        addresses = {literal}
    except ValueError:
        try:
            addresses = {
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            }
        except (OSError, ValueError) as exc:
            return False, f"public DNS resolution was not established: {type(exc).__name__}"
    if not addresses:
        return False, "public DNS resolution returned no addresses"
    unsafe = sorted(
        str(address)
        for address in addresses
        if not address.is_global or str(address) in KNOWN_METADATA_IPS
    )
    if unsafe:
        return False, "destination resolves to a non-public or metadata address"
    return True, f"resolved to {len(addresses)} public address(es)"


def _verify(url: str) -> tuple[bool, str]:
    headers = {"User-Agent": "app-store-review-audit/1.0"}
    opener = urllib.request.build_opener(_NoRedirect)
    for method in ("HEAD", "GET"):
        try:
            request = urllib.request.Request(url, headers=headers, method=method)
            with opener.open(request, timeout=6) as response:
                status = getattr(response, "status", 200)
                return 200 <= status < 400, f"HTTP {status}"
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                return True, f"HTTP {exc.code}; redirect was not followed for network safety"
            if exc.code == 405 and method == "HEAD":
                continue
            return False, f"HTTP {exc.code}"
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            return False, f"{type(exc).__name__}: {exc}"
    return False, "No successful response"


def scan(context: ScanContext) -> dict:
    result = new_result("scan_urls")
    root = context.root
    records: list[dict] = []
    for path, text in code_corpus(root):
        suffix = path.suffix.lower()
        if suffix not in {".swift", ".m", ".mm", ".js", ".jsx", ".ts", ".tsx", ".dart", ".json", ".plist", ".strings", ".yaml", ".yml", ".xcconfig"}:
            continue
        if suffix == ".xcconfig":
            text = _strip_xcconfig_comments(text)
        for match in URL_PATTERN.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            line_text = text.splitlines()[line_no - 1].strip() if text.splitlines() else ""
            url = _safe_url(match.group(0))
            records.append(
                {
                    "url": url,
                    "file": relative_path(path, root),
                    "line": line_no,
                    "excerpt": re.sub(r"([?&](?:token|key|secret|password)=)[^&\s]+", r"\1<redacted>", line_text, flags=re.I)[:300],
                    "legal": bool(LEGAL_CONTEXT.search(line_text)),
                }
            )
    for record in records:
        classification = _classification(record["url"])
        if not classification:
            continue
        legal = record["legal"]
        result["findings"].append(
            make_finding(
                base_id="LEGAL-URL-INVALID" if legal else "URL-TEST-ENDPOINT",
                severity="High" if legal else "Medium",
                confidence="High" if classification == "reserved-or-local" else "Medium",
                verification="Likely",
                area="Legal materials" if legal else "Reliability",
                title="Non-production legal/support URL literal" if legal else "Non-production or test URL literal detected",
                problem=f"The source-visible URL literal {record['url']} is classified as {classification}; Release-target reachability is not established statically.",
                evidence_items=[
                    evidence(
                        kind="url",
                        value=record["url"],
                        file=record["file"],
                        line=record["line"],
                        excerpt=record["excerpt"],
                    )
                ],
                file=record["file"],
                line=record["line"],
                source_id="ARG-2.1" if not legal else "ARG-5.1.1",
                risk_reason="Reviewer access can fail or expose unfinished configuration when a release route uses a local, reserved, or test endpoint.",
                remediation="Replace the endpoint with the live production URL and verify its content, TLS, redirects, and availability without authentication where appropriate.",
                verification_steps=["Open the URL from a clean device/network.", "Test every in-app legal and support link in the Release build."],
                limitations=["The URL may exist only in test, preview, sample, or inactive configuration; confirm target and build-config reachability."],
                heuristic=classification != "reserved-or-local",
                id_detail=record["url"],
            )
        )
    live_results: list[dict] = []
    if context.network:
        # Only probe URLs that source context identifies as legal/support links.
        # API endpoints commonly and correctly return 401/403 without credentials;
        # probing them would be both noisy and a poor backend-health test.
        unique = sorted(
            {
                record["url"]
                for record in records
                if record["legal"] and _classification(record["url"]) is None
            }
        )
        for url in unique[:40]:
            safe, safety_detail = _public_target(url)
            if not safe:
                live_results.append(
                    {
                        "url": url,
                        "status": "skipped",
                        "reachable": None,
                        "detail": safety_detail,
                    }
                )
                continue
            ok, detail = _verify(url)
            live_results.append(
                {
                    "url": url,
                    "status": "checked",
                    "reachable": ok,
                    "detail": detail,
                    "safety": safety_detail,
                }
            )
            if not ok:
                record = next(item for item in records if item["url"] == url)
                result["findings"].append(
                    make_finding(
                        base_id="URL-LIVE-CHECK-FAILED",
                        severity="High" if record["legal"] else "Medium",
                        confidence="Medium",
                        verification="Likely",
                        area="Legal materials" if record["legal"] else "Reliability",
                        title="Live URL check failed",
                        problem=f"{url} did not return a successful response: {detail}",
                        evidence_items=[evidence(kind="network-check", value=url, file=record["file"], line=record["line"], excerpt=detail)],
                        file=record["file"],
                        line=record["line"],
                        command="HTTP HEAD, then GET fallback",
                        source_id="ARG-2.1",
                        risk_reason="Apple expects all submitted URLs and required support/privacy links to be functional.",
                        remediation="Restore the endpoint or update the app and metadata to a stable, publicly reachable URL.",
                        verification_steps=["Open the link from another network without developer credentials.", "Confirm redirects and final page content."],
                        limitations=["Temporary network, bot protection, geo-restriction, or HEAD/GET behavior can produce false failures.", "Redirects are intentionally not followed, and DNS can change between preflight resolution and the request."],
                        heuristic=True,
                        id_detail=url,
                    )
                )
    result["facts"] = {"urls": records, "live_checks": live_results}
    static_failures = [
        item
        for item in result["findings"]
        if item.get("rule_id") in {"LEGAL-URL-INVALID", "URL-TEST-ENDPOINT"}
    ]
    result["checks"].append(
        check(
            "urls.static",
            "Reliability",
            "Failed" if static_failures else "Passed",
            f"Inspected {len(records)} source-visible URL occurrence(s); detected {len(static_failures)} non-production/static URL finding(s).",
            source_id="ARG-2.1",
        )
    )
    checked_live = [item for item in live_results if item.get("status") == "checked"]
    skipped_live = [item for item in live_results if item.get("status") == "skipped"]
    if not context.network:
        live_status = "Not verified"
        live_summary = "Live URL access was not authorized/enabled; availability remains unverified."
    elif not checked_live:
        live_status = "Not verified"
        live_summary = (
            f"No safe public URL checks were completed; {len(skipped_live)} destination(s) were skipped."
        )
    elif any(item.get("reachable") is False for item in checked_live):
        live_status = "Failed"
        live_summary = (
            f"Completed {len(checked_live)} safe public URL check(s); at least one failed and "
            f"{len(skipped_live)} destination(s) were skipped."
        )
    elif skipped_live:
        live_status = "Not verified"
        live_summary = (
            f"Completed {len(checked_live)} safe public URL check(s), but skipped "
            f"{len(skipped_live)} destination(s)."
        )
    else:
        live_status = "Passed"
        live_summary = f"Completed {len(checked_live)} safe public URL check(s)."
    result["checks"].append(
        check(
            "urls.live",
            "Legal materials",
            live_status,
            live_summary,
            source_id="ARG-2.1",
        )
    )
    return finish_result(result)


if __name__ == "__main__":
    raise SystemExit(scanner_cli(scan, "scan_urls"))
