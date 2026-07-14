#!/bin/sh

set -eu

PROGRAM=${0##*/}
ASSUME_YES=0

usage() {
    printf '%s\n' "Usage: $PROGRAM [--yes]"
    printf '%s\n' "Remove app_store_review from the active skills directory."
    printf '%s\n' "The installation is moved to a timestamped backup, not deleted."
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
SKILLS_ROOT=${CODEX_SKILLS_DIR:-"$HOME/.agents/skills"}

case "$SKILLS_ROOT" in
    /*) ;;
    *) fail "CODEX_SKILLS_DIR must be an absolute path" ;;
esac

DESTINATION="$SKILLS_ROOT/app_store_review"

if [ ! -e "$DESTINATION" ]; then
    printf 'No active installation found at %s\n' "$DESTINATION"
    exit 0
fi

if [ "$ASSUME_YES" -ne 1 ]; then
    if [ ! -t 0 ]; then
        fail "confirmation is required; rerun interactively or pass --yes"
    fi
    printf 'Deactivate the installation at %s? [y/N] ' "$DESTINATION"
    IFS= read -r answer
    case "$answer" in
        y|Y|yes|YES) ;;
        *) printf '%s\n' "Uninstall cancelled."; exit 0 ;;
    esac
fi

TIMESTAMP=$(date -u '+%Y%m%dT%H%M%SZ')
REMOVED="$DESTINATION.removed-$TIMESTAMP-$$"
mv -- "$DESTINATION" "$REMOVED"

printf 'Uninstalled app_store_review. Preserved copy: %s\n' "$REMOVED"
