#!/bin/sh

set -eu

PROGRAM=${0##*/}
ASSUME_YES=0
SKIP_PULL=0

usage() {
    printf '%s\n' "Usage: $PROGRAM [--yes] [--skip-pull]"
    printf '%s\n' "Fast-forward the local clone and reinstall app_store_review."
    printf '%s\n' "Use --skip-pull for an already-updated release tree or local test."
}

fail() {
    printf 'Error: %s\n' "$1" >&2
    exit 1
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --yes|-y) ASSUME_YES=1 ;;
        --skip-pull) SKIP_PULL=1 ;;
        --help|-h) usage; exit 0 ;;
        *) fail "unknown option: $1" ;;
    esac
    shift
done

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ "$SKIP_PULL" -ne 1 ]; then
    command -v git >/dev/null 2>&1 || fail "git is required to update the clone"
    [ -d "$SCRIPT_DIR/.git" ] || fail "this directory is not a git clone; download a newer release or clone the repository again"
    if [ -n "$(git -C "$SCRIPT_DIR" status --porcelain)" ]; then
        fail "the repository has local changes; commit, stash, or discard them before updating"
    fi
    git -C "$SCRIPT_DIR" pull --ff-only
fi

if [ "$ASSUME_YES" -eq 1 ]; then
    exec "$SCRIPT_DIR/install.sh" --yes
fi

exec "$SCRIPT_DIR/install.sh"
