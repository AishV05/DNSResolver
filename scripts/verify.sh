#!/usr/bin/env bash

# Deterministic repository validation. The Maven suite uses mocks or loopback
# sockets only; it does not issue a recursive query to the public Internet.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

for command in git; do
    if ! command -v "${command}" >/dev/null 2>&1; then
        printf 'Required command is unavailable: %s\n' "${command}" >&2
        exit 1
    fi
done

if [[ ! -x "${REPO_ROOT}/mvnw" ]]; then
    printf '%s\n' 'The Maven Wrapper is missing or is not executable: ./mvnw' >&2
    exit 1
fi

git diff --check HEAD

tracked_ignored_files="$(git ls-files -ci --exclude-standard)"
if [[ -n "${tracked_ignored_files}" ]]; then
    printf '%s\n' \
        'Tracked files match ignore rules; remove them from version control:' >&2
    printf '%s\n' "${tracked_ignored_files}" >&2
    exit 1
fi

./mvnw -B -ntp verify
