#!/usr/bin/env bash
# Checks for gray-acme. Run from anywhere; it always checks this directory.
#
# 1. gofmt -l must print nothing.
# 2. go vet must pass.
# 3. go test -race -count=1 must pass: the fake CA (main_test.go) and the real lego client against an
#    in-process ACME server on loopback (details_test.go). No network beyond loopback, no wall-clock wait.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

if [ -z "${GOCACHE:-}" ]; then
	GOCACHE="$(mktemp -d "${TMPDIR:-/tmp}/gray-acme-gocache.XXXXXX")"
	export GOCACHE
	trap 'rm -rf "$GOCACHE"' EXIT
fi

unformatted="$(gofmt -l .)"
if [ -n "$unformatted" ]; then
	echo "check.sh: gofmt found unformatted files:" >&2
	printf '%s\n' "$unformatted" >&2
	exit 1
fi

go vet ./...
go test -race -count=1 ./...

echo "check.sh: gofmt, vet and go test -race passed"
