#!/usr/bin/env python3
"""Portable repository structure and security checks for CI and releases."""

from __future__ import annotations

import argparse
import json
import re
import stat
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "app_store_review"
TEXT_SUFFIXES = {
    "",
    ".entitlements",
    ".gitignore",
    ".json",
    ".md",
    ".plist",
    ".pbxproj",
    ".py",
    ".sh",
    ".strings",
    ".swift",
    ".xcprivacy",
    ".yaml",
    ".yml",
}
FORBIDDEN_FILE_SUFFIXES = {
    ".cer",
    ".der",
    ".env",
    ".key",
    ".mobileprovision",
    ".p12",
    ".pem",
    ".provisionprofile",
}
REQUIRED_REPOSITORY_FILES = {
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/workflows/link_check.yml",
    ".github/workflows/security.yml",
    ".github/workflows/tests.yml",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "README.md",
    "README.ru.md",
    "ROADMAP.md",
    "SECURITY.md",
    "install.sh",
    "uninstall.sh",
    "update.sh",
}
REQUIRED_SKILL_FILES = {
    "SKILL.md",
    "agents/openai.yaml",
    "references/apple_source_registry.json",
    "scripts/run_audit.py",
    "scripts/run_self_tests.py",
}


class CheckFailure(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


def iter_repository_files():
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or ".git" in path.parts:
            continue
        yield path


def read_text(path: Path) -> str | None:
    if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {
        "LICENSE",
        "NOTICE",
        "Podfile.lock",
    }:
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def check_structure() -> None:
    missing_repo = sorted(path for path in REQUIRED_REPOSITORY_FILES if not (ROOT / path).is_file())
    require(not missing_repo, f"missing repository files: {missing_repo}")

    missing_skill = sorted(path for path in REQUIRED_SKILL_FILES if not (SKILL / path).is_file())
    require(not missing_skill, f"missing skill files: {missing_skill}")

    skill_text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    require(skill_text.startswith("---\n"), "SKILL.md frontmatter is missing")
    end = skill_text.find("\n---\n", 4)
    require(end > 4, "SKILL.md frontmatter is not terminated")
    frontmatter = skill_text[4:end]
    keys = [line.split(":", 1)[0].strip() for line in frontmatter.splitlines() if ":" in line]
    require(keys == ["name", "description"], f"unexpected SKILL.md frontmatter keys: {keys}")
    require(re.search(r"^name:\s*app-store-review\s*$", frontmatter, re.MULTILINE) is not None, "skill name is invalid")
    require("Do not use for ordinary code review" in frontmatter, "negative trigger boundary is missing")

    agent_yaml = (SKILL / "agents" / "openai.yaml").read_text(encoding="utf-8")
    for expected in ("display_name:", "short_description:", "default_prompt:", "allow_implicit_invocation: true"):
        require(expected in agent_yaml, f"agents/openai.yaml is missing {expected}")

    registry = json.loads((SKILL / "references" / "apple_source_registry.json").read_text(encoding="utf-8"))
    sources = registry.get("sources")
    require(isinstance(sources, list) and len(sources) >= 40, "Apple source registry is unexpectedly small")
    for source in sources:
        require(set(source) >= {"id", "title", "section", "url", "last_checked", "summary", "applicability", "status"}, f"incomplete source entry: {source.get('id')}")
        require(source["url"].startswith("https://developer.apple.com/"), f"non-Apple mandatory source: {source['url']}")

    for script in (ROOT / "install.sh", ROOT / "update.sh", ROOT / "uninstall.sh"):
        require(script.stat().st_mode & stat.S_IXUSR, f"script is not executable: {script.name}")

    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    notice_text = (ROOT / "NOTICE").read_text(encoding="utf-8")
    require("Apache License" in license_text and "Version 2.0" in license_text, "Apache-2.0 license text is missing")
    require("Copyright 2026 Max Danilov" in notice_text, "copyright notice is missing or incorrect")


def check_security() -> None:
    failures: list[str] = []
    absolute_path_patterns = (
        re.compile(r"/Users/[A-Za-z0-9._-]+/"),
        re.compile(r"/home/[A-Za-z0-9._-]+/"),
        re.compile(r"[A-Za-z]:\\Users\\[^\\]+\\"),
    )
    private_key = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")
    unsafe_shell = (
        re.compile(r"(?:curl|wget)[^\n|]*\|\s*(?:sh|bash)\b"),
        re.compile(r"\beval\s+[\"'$A-Za-z]"),
        re.compile(r"\bsudo\b"),
        re.compile(r"\brm\s+-[A-Za-z]*r[A-Za-z]*f[A-Za-z]*\s+/(?:\s|$)"),
        re.compile(r"\bchmod\s+(?:-R\s+)?777\b"),
    )
    action_pin = re.compile(r"^\s*-\s*uses:\s*(\S+)(?:\s+#.*)?$", re.MULTILINE)

    for path in iter_repository_files():
        rel = path.relative_to(ROOT).as_posix()
        suffix = path.suffix.lower()
        if suffix in FORBIDDEN_FILE_SUFFIXES or path.name.startswith(".env."):
            failures.append(f"sensitive file type: {rel}")
        if path.stat().st_size > 1_000_000:
            failures.append(f"unexpected large file: {rel}")
        text = read_text(path)
        if text is None:
            continue
        if private_key.search(text):
            failures.append(f"private key marker: {rel}")
        for pattern in absolute_path_patterns:
            if pattern.search(text):
                failures.append(f"absolute user path: {rel}")
                break
        if suffix == ".sh":
            for pattern in unsafe_shell:
                if pattern.search(text):
                    failures.append(f"unsafe shell construct {pattern.pattern!r}: {rel}")
        if rel.startswith(".github/workflows/"):
            require("pull_request_target:" not in text, f"unsafe pull_request_target event: {rel}")
            require("write-all" not in text, f"overbroad workflow permissions: {rel}")
            for match in action_pin.finditer(text):
                reference = match.group(1)
                if reference.startswith("./"):
                    continue
                if not re.search(r"@[0-9a-f]{40}$", reference):
                    failures.append(f"GitHub Action is not pinned to a full SHA: {rel}: {reference}")

    forbidden_names = {".DS_Store", "app-store-review-report.json", "app-store-review-report.md"}
    for path in iter_repository_files():
        rel = path.relative_to(ROOT).as_posix()
        if path.name in forbidden_names or "__pycache__" in path.parts or "xcuserdata" in path.parts:
            failures.append(f"generated or local artifact: {rel}")

    require(not failures, "repository security checks failed:\n- " + "\n- ".join(sorted(set(failures))))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("all", "structure", "security"), default="all")
    args = parser.parse_args()
    try:
        if args.mode in {"all", "structure"}:
            check_structure()
            print("PASS repository structure")
        if args.mode in {"all", "security"}:
            check_security()
            print("PASS repository security")
    except (CheckFailure, json.JSONDecodeError, OSError) as error:
        print(f"FAIL {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
