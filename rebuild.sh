#!/usr/bin/env bash
# Rebuilds the gray-lane image of 2026.11.10-1890a95ee1b1 from this tree with the release build script, deploy/tee/build.sh, unchanged,
# and prints the OCI manifest digest: the digest the release list names (`stack.gray_image`) and the measured compose
# runs. A different digest means the tree is not what the image was built from, or your build environment differs
# (README.md, "Rebuild").
#
#   ./rebuild.sh
#
# Needs: Linux on amd64 (or a builder that emulates it), docker with buildx and a builder that can export an OCI
# layout (the docker-container driver, or the containerd image store), node 24 with npm, curl, tar and git. Network:
# npm's registry (npm ci, and the workerd package build.sh downloads and checks against the lockfile), Docker Hub
# (the two base images, by digest) and the Go module proxy (the go.sum pins of gray-acme and gray-peerlink).
#
# build.sh asks git three things about the private checkout it ran in: the commit (written into the image's
# /etc/lane/build.env, so it is part of the digest), the commit's time (SOURCE_DATE_EPOCH, every timestamp in the
# image) and whether the tree is clean. This tree is not that checkout, so a `git` placed first on PATH for build.sh
# alone answers the first two with the values in SOURCE.json and passes every other git command, the clean check
# included, to your git.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
commit=1890a95ee1b1273398bd2f493726a4dad5a148d7
epoch=1794291410
for tool in node npm docker curl tar git; do
  command -v "$tool" >/dev/null 2>&1 || { echo "rebuild.sh: $tool is required" >&2; exit 2; }
done
real_git=$(command -v git)
shim=$(mktemp -d "${TMPDIR:-/tmp}/gray-rebuild-git.XXXXXX")
trap 'rm -rf "$shim"' EXIT
cat > "$shim/git" <<EOF
#!/bin/sh
case "\$*" in
  *" rev-parse HEAD") echo $commit ;;
  *" log -1 --format=%ct") echo $epoch ;;
  *" status --porcelain") if [ -d "$here/.git" ]; then exec "$real_git" -C "$here" status --porcelain; fi ;;
  *) exec "$real_git" "\$@" ;;
esac
EOF
chmod 0755 "$shim/git"

echo "rebuild.sh: npm ci in workers/ (workers/package-lock.json)"
(cd "$here/workers" && npm ci --no-audit --no-fund >/dev/null)
echo "rebuild.sh: deploy/tee/build.sh (two clean builds; it fails unless both have one digest)"
PATH="$shim:$PATH" SOURCE_DATE_EPOCH=$epoch TEE_TAG=${GRAY_REBUILD_TAG:-gray-lane:rebuild} "$here/deploy/tee/build.sh" | tee "$shim/build.log"
digest=$(grep -oE 'manifest +sha256:[0-9a-f]{64}' "$shim/build.log" | grep -oE 'sha256:[0-9a-f]{64}')
echo "rebuild.sh: commit $commit"
echo "rebuild.sh: oci $here/deploy/tee/build/second.tar"
echo "rebuild.sh: manifest $digest"
