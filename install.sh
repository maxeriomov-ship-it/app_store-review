#!/bin/sh

set -eu

PROGRAM=${0##*/}
ASSUME_YES=0

usage() {
    printf '%s\n' "Usage: $PROGRAM [--yes]"
    printf '%s\n' "Install app_store_review into \$HOME/.agents/skills."
    printf '%s\n' "Set CODEX_SKILLS_DIR to test or use a different skills root."
}

fail() {
    printf 'Error: %s\n' "$1" >&2
    exit 1
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --yes|-y) ASSUME_YES=1 ;;
        --help|-h) usage; exit 0 ;;
        *) fail "unknown option: $1" ;;
    esac
    shift
done

[ -n "${HOME:-}" ] || fail "HOME is not set"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE_DIR="$SCRIPT_DIR/app_store_review"
SKILLS_ROOT=${CODEX_SKILLS_DIR:-"$HOME/.agents/skills"}

case "$SKILLS_ROOT" in
    /*) ;;
    *) fail "CODEX_SKILLS_DIR must be an absolute path" ;;
esac

DESTINATION="$SKILLS_ROOT/app_store_review"
TIMESTAMP=$(date -u '+%Y%m%dT%H%M%SZ')
STAGING="$SKILLS_ROOT/.app_store_review.install.$$"
BACKUP=""

for required in \
    "$SOURCE_DIR/SKILL.md" \
    "$SOURCE_DIR/agents/openai.yaml" \
    "$SOURCE_DIR/scripts/run_audit.py" \
    "$SOURCE_DIR/scripts/run_self_tests.py"
do
    [ -f "$required" ] || fail "required skill file is missing: $required"
done

if [ -n "$(find "$SOURCE_DIR" -type l -print -quit)" ]; then
    fail "refusing to install a skill tree containing symbolic links"
fi

if [ -e "$DESTINATION" ]; then
    if [ "$ASSUME_YES" -ne 1 ]; then
        if [ ! -t 0 ]; then
            fail "an installation already exists; rerun interactively or pass --yes to create a backup and replace it"
        fi
        printf 'Existing installation: %s\n' "$DESTINATION"
        printf 'Create a timestamped backup and install this version? [y/N] '
        IFS= read -r answer
        case "$answer" in
            y|Y|yes|YES) ;;
            *) printf '%s\n' "Installation cancelled."; exit 0 ;;
        esac
    fi
    BACKUP="$DESTINATION.backup-$TIMESTAMP-$$"
fi

mkdir -p "$SKILLS_ROOT"
umask 022

cleanup() {
    status=$?
    trap - 0 1 2 15
    case "$STAGING" in
        "$SKILLS_ROOT"/.app_store_review.install.*)
            if [ -e "$STAGING" ]; then
                rm -rf -- "$STAGING"
            fi
            ;;
    esac
    if [ "$status" -ne 0 ] && [ -n "$BACKUP" ] && [ ! -e "$DESTINATION" ] && [ -e "$BACKUP" ]; then
        mv -- "$BACKUP" "$DESTINATION"
        printf '%s\n' "Previous installation restored after failure." >&2
    fi
    exit "$status"
}

trap cleanup 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

cp -R -- "$SOURCE_DIR" "$STAGING"
[ -f "$STAGING/SKILL.md" ] || fail "staged copy is incomplete"

if [ -n "$BACKUP" ]; then
    mv -- "$DESTINATION" "$BACKUP"
fi

mv -- "$STAGING" "$DESTINATION"

printf 'Installed app_store_review at %s\n' "$DESTINATION"
if [ -n "$BACKUP" ]; then
    printf 'Previous installation backed up at %s\n' "$BACKUP"
fi
printf '%s\n' 'Invoke it in Codex with: $app-store-review'
