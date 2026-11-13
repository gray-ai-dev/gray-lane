#!/usr/bin/env bash
# Maintains the in-repo fork of the Go standard library's HTTP/2 client, net/http/internal/http2 (README.md here).
#
#   sync.sh            rebuild http2/ and internal/ from $(go env GOROOT)/src/net/http/internal of the Go toolchain on
#                      PATH, write its version to BASE, then apply gray.patch. Run after moving egress to a new Go release
#                      (deploy/tee/build.sh GO_IMAGE and ci.yml GO_RELEASE); fix gray.patch if it no longer applies.
#   sync.sh --check    fail unless `go env GOVERSION` is the version in BASE and the files here equal "that release's
#                      files, copied as below, + gray.patch". check.sh runs this.
#   sync.sh --diff     rewrite gray.patch from the current files (after editing the fork by hand).
#
# Copying: the client files listed below, unchanged but for the import paths of net/http's internal packages
# ("net/http/internal", ".../httpcommon", ".../httpsfv"), rewritten to this directory, then gofmt. The x/net packages
# std imports through its vendor directory (golang.org/x/net/http2/hpack, .../http/httpguts, .../idna) are already
# written with their module paths, so they resolve to golang.org/x/net at ../../go.mod's version (README.md).
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
MODPATH=github.com/megaeth-labs/gray/deploy/tee/egress/third_party/stdhttp2

HTTP2_FILES=(
	api.go
	ascii.go
	client_conn_pool.go
	config.go
	databuffer.go
	errors.go
	flow.go
	frame.go
	gotrack.go
	http2.go
	pipe.go
	transport.go
)
INTERNAL_FILES=(common.go)
HTTPCOMMON_FILES=(httpcommon.go)
HTTPSFV_FILES=(httpsfv.go)

goversion=$(go env GOVERSION)
src=$(go env GOROOT)/src/net/http/internal
[ -d "$src/http2" ] || { echo "sync.sh: $src/http2 not found (go env GOROOT of $goversion)" >&2; exit 1; }

# copy_baseline <dest>: writes the unpatched copy of the toolchain's files into dest.
copy_baseline() {
	local dest=$1 f
	mkdir -p "$dest/http2" "$dest/internal/httpcommon" "$dest/internal/httpsfv"
	for f in "${HTTP2_FILES[@]}"; do cp "$src/http2/$f" "$dest/http2/$f"; done
	for f in "${INTERNAL_FILES[@]}"; do cp "$src/$f" "$dest/internal/$f"; done
	for f in "${HTTPCOMMON_FILES[@]}"; do cp "$src/httpcommon/$f" "$dest/internal/httpcommon/$f"; done
	for f in "${HTTPSFV_FILES[@]}"; do cp "$src/httpsfv/$f" "$dest/internal/httpsfv/$f"; done
	chmod -R u+w "$dest"
	local go
	for go in "$dest"/http2/*.go "$dest"/internal/*.go "$dest"/internal/*/*.go; do
		sed -i.orig \
			-e 's#"net/http/internal"#"'"$MODPATH"'/internal"#' \
			-e 's#"net/http/internal/httpcommon"#"'"$MODPATH"'/internal/httpcommon"#' \
			-e 's#"net/http/internal/httpsfv"#"'"$MODPATH"'/internal/httpsfv"#' \
			"$go"
		rm -f "$go.orig"
	done
	gofmt -w "$dest/http2" "$dest/internal"
	echo "$goversion" >"$dest/BASE"
}

apply_patch() {
	local dest=$1
	if [ -s "$HERE/gray.patch" ]; then
		patch -s -p1 -d "$dest" --no-backup-if-mismatch <"$HERE/gray.patch"
	fi
}

# tree_paths <dir>: the fork's generated content (not README.md, LICENSE, PATENTS, sync.sh or gray.patch).
tree_paths() {
	(cd "$1" && find BASE http2 internal -type f | LC_ALL=C sort)
}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/stdhttp2.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

case "${1:-}" in
"")
	copy_baseline "$tmp/new"
	apply_patch "$tmp/new"
	rm -rf "$HERE/http2" "$HERE/internal"
	cp -R "$tmp/new/http2" "$tmp/new/internal" "$HERE/"
	cp "$tmp/new/BASE" "$HERE/"
	echo "sync.sh: copied net/http/internal of $goversion and applied gray.patch"
	;;
--baseline)
	# The unpatched copy only (the first step of a re-base onto a new Go release; then re-apply the patch).
	copy_baseline "$tmp/new"
	rm -rf "$HERE/http2" "$HERE/internal"
	cp -R "$tmp/new/http2" "$tmp/new/internal" "$HERE/"
	cp "$tmp/new/BASE" "$HERE/"
	echo "sync.sh: copied net/http/internal of $goversion (no patch)"
	;;
--check)
	base=$(cat "$HERE/BASE" 2>/dev/null || true)
	if [ "$base" != "$goversion" ]; then
		echo "sync.sh: the fork is based on \"$base\" (BASE) but the Go toolchain here is $goversion; check with the Go" \
			"release egress is built with (deploy/tee/build.sh GO_IMAGE, ci.yml GO_RELEASE), or move the fork to" \
			"$goversion with third_party/stdhttp2/sync.sh (README.md, Syncing)" >&2
		exit 1
	fi
	copy_baseline "$tmp/want"
	apply_patch "$tmp/want"
	if ! diff <(tree_paths "$tmp/want") <(tree_paths "$HERE") >/dev/null; then
		echo "sync.sh: the fork's file list differs from $goversion's net/http/internal + gray.patch:" >&2
		diff <(tree_paths "$tmp/want") <(tree_paths "$HERE") >&2 || true
		exit 1
	fi
	while IFS= read -r p; do
		if ! cmp -s "$tmp/want/$p" "$HERE/$p"; then
			echo "sync.sh: $p differs from $goversion's net/http/internal + gray.patch (edit, then run sync.sh --diff):" >&2
			diff -u "$tmp/want/$p" "$HERE/$p" >&2 || true
			exit 1
		fi
	done < <(tree_paths "$tmp/want")
	echo "sync.sh: the fork is $goversion's net/http/internal + gray.patch"
	;;
--diff)
	copy_baseline "$tmp/a"
	mkdir -p "$tmp/b"
	cp -R "$HERE/http2" "$HERE/internal" "$tmp/b/"
	(cd "$tmp" && { diff -ruN a/http2 b/http2 || true; diff -ruN a/internal b/internal || true; }) |
		sed -E $'s#^(---|\\+\\+\\+) ([^\t]*)\t.*#\\1 \\2#' >"$HERE/gray.patch"
	echo "sync.sh: wrote gray.patch ($(wc -l <"$HERE/gray.patch") lines)"
	;;
*)
	echo "usage: sync.sh [--check|--diff|--baseline]" >&2
	exit 2
	;;
esac
