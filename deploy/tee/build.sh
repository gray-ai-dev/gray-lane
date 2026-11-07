#!/usr/bin/env bash
# Builds the gray-lane image reproducibly: stages every input from the repository, builds twice from
# clean, and fails if the two OCI manifest digests differ. Prints the final digest — the value a
# customer's app-compose allowlist ends up naming (deploy/tee/app-compose.mjs).
#
#   deploy/tee/build.sh                         # release: linux/amd64, both bases by digest, clean tree
#   TEE_BUILD_LOCAL=1 deploy/tee/build.sh       # local: a breaking override is allowed and stamped
#
# D65: a release build is the default and the only build that may be signed. It refuses another
# platform, a base image without `@sha256:<64 hex>` or a dirty tree. The overrides that break one of
# those (TEE_PLATFORM, TEE_BASE_IMAGE/TEE_GO_IMAGE without a digest, TEE_BUILD_ALLOW_DIRTY=1) require
# TEE_BUILD_LOCAL=1. A local build writes `local=1` into /etc/lane/build.env and the
# `com.gray.build.local=1` image label; only a build from this default path is a release.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
workers="$repo/workers"
build="$here/build"
context="$build/context"

platform="${TEE_PLATFORM:-linux/amd64}"
# The multi-arch index digest of node:24-bookworm-slim (Docker Hub official image, resolved 2026-10-20).
base_image="${TEE_BASE_IMAGE:-node:24-bookworm-slim@sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5}"
# The multi-arch index digest of golang:1.27.2-bookworm (Docker Hub official image, resolved 2026-10-21).
go_image="${TEE_GO_IMAGE:-golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61}"
tag="${TEE_TAG:-gray-lane:local}"
source_date_epoch="${SOURCE_DATE_EPOCH:-$(git -C "$repo" log -1 --format=%ct)}"
local_build="${TEE_BUILD_LOCAL:-0}"

pinned_image() {
  case "$1" in
    *@sha256:*) ;;
    *) return 1 ;;
  esac
  local digest="${1##*@sha256:}"
  [ "${#digest}" -eq 64 ] || return 1
  case "$digest" in *[!0-9a-f]*) return 1 ;; esac
  return 0
}

case "$local_build" in
  0|1) ;;
  *) echo "build.sh: TEE_BUILD_LOCAL must be 1 or unset" >&2; exit 2 ;;
esac

# D65: release-only by default. A breaking override is not silently downgraded; it needs
# TEE_BUILD_LOCAL=1, and the resulting image says `local=1`.
if [ "$local_build" != "1" ]; then
  [ "$platform" = "linux/amd64" ] || {
    echo "build.sh: a release build is linux/amd64, not '$platform'; set TEE_BUILD_LOCAL=1 for a local build" >&2
    exit 2
  }
  pinned_image "$base_image" || {
    echo "build.sh: a release build needs TEE_BASE_IMAGE as name@sha256:<64 hex>, not '$base_image'" >&2
    echo "  (set TEE_BUILD_LOCAL=1 for a local, non-release build)" >&2
    exit 2
  }
  pinned_image "$go_image" || {
    echo "build.sh: a release build needs TEE_GO_IMAGE as name@sha256:<64 hex>, not '$go_image'" >&2
    echo "  (set TEE_BUILD_LOCAL=1 for a local, non-release build)" >&2
    exit 2
  }
  [ "${TEE_BUILD_ALLOW_DIRTY:-0}" != "1" ] || {
    echo "build.sh: TEE_BUILD_ALLOW_DIRTY=1 is a local build; set TEE_BUILD_LOCAL=1 as well" >&2
    exit 2
  }
fi

case "$platform" in
  linux/amd64) workerd_package="@cloudflare/workerd-linux-64" ;;
  linux/arm64) workerd_package="@cloudflare/workerd-linux-arm64" ;;
  *) echo "build.sh: unsupported TEE_PLATFORM '$platform' (linux/amd64 or linux/arm64)" >&2; exit 2 ;;
esac

for tool in node docker curl tar git; do
  command -v "$tool" >/dev/null 2>&1 || { echo "build.sh: $tool is required" >&2; exit 2; }
done
[ -d "$workers/node_modules" ] || { echo "build.sh: run npm ci in workers/ first (cf-check does it)" >&2; exit 2; }

# The dependency tree the bundle is built from must be the lockfile's, not a stale or locally
# modified node_modules (VG-16): every *installed* package must match the version and integrity
# package-lock.json pins. Platform-constrained optional deps the lockfile lists but this OS/arch
# never installed are absent from .package-lock.json by design and are skipped.
node -e '
  const { readFileSync, existsSync } = require("node:fs");
  const [root] = process.argv.slice(1);
  const installed = `${root}/node_modules/.package-lock.json`;
  const declared = `${root}/package-lock.json`;
  if (!existsSync(installed)) { console.error("build.sh: node_modules/.package-lock.json is missing; run npm ci"); process.exit(1); }
  const a = JSON.parse(readFileSync(installed, "utf8")).packages;
  const b = JSON.parse(readFileSync(declared, "utf8")).packages;
  for (const [path, entry] of Object.entries(a)) {
    if (path === "") continue;
    const pinned = b[path];
    if (pinned === undefined) { console.error(`build.sh: ${path} is installed but not in package-lock.json; run npm ci`); process.exit(1); }
    if (pinned.version !== entry.version || (entry.integrity !== undefined && pinned.integrity !== entry.integrity)) {
      console.error(`build.sh: ${path} is ${entry.version}, not the ${pinned === undefined ? "absent" : pinned.version} package-lock.json pins; run npm ci`);
      process.exit(1);
    }
  }
' "$workers"

# A reproducible build must come from a clean tree: build.env names the commit the image claims to
# be built from (source_provenance.repo_commit), and a dirty worktree would let the bundle differ
# from anything that commit contains. Set TEE_BUILD_ALLOW_DIRTY=1 to iterate locally; the image then
# still carries the commit's hash but is explicitly not a provenance-true release build.
if [ "${TEE_BUILD_ALLOW_DIRTY:-0}" != "1" ] && [ -n "$(git -C "$repo" status --porcelain)" ]; then
  echo "build.sh: the worktree is dirty; commit or stash before a reproducible build" >&2
  echo "  (TEE_BUILD_ALLOW_DIRTY=1 overrides for a local, non-release build)" >&2
  git -C "$repo" status --porcelain | head -n 20 >&2
  exit 2
fi

echo "build.sh: platform=$platform base=$base_image go=$go_image epoch=$source_date_epoch"

# 1. The workerd version and the tarball's integrity, from the workspace lockfile — the same bytes the
#    workspace's tests run.
read -r workerd_version workerd_integrity < <(node -e '
  const lock = require(process.argv[1]);
  const entry = lock.packages[`node_modules/${process.argv[2]}`];
  if (!entry) throw new Error(`the lockfile has no ${process.argv[2]}`);
  process.stdout.write(`${entry.version} ${entry.integrity}\n`);
' "$workers/package-lock.json" "$workerd_package")
echo "build.sh: workerd $workerd_version ($workerd_package)"

# 2. Stage the build context: every byte the image carries, and nothing else.
rm -rf "$build"
mkdir -p "$context" "$build/wrangler" "$context/egress" "$context/acme" "$context/isolation-check" "$context/peerlink" "$context/worker"

workerd_basename="${workerd_package##*/}"
curl -fsSL --retry 3 -o "$build/workerd.tgz" \
  "https://registry.npmjs.org/$workerd_package/-/${workerd_basename}-${workerd_version}.tgz"
node -e '
  const { createHash } = require("node:crypto");
  const { readFileSync } = require("node:fs");
  const [file, integrity] = process.argv.slice(1);
  const digest = createHash("sha512").update(readFileSync(file)).digest("base64");
  const expected = integrity.replace(/^sha512-/, "");
  if (digest !== expected) {
    console.error(`build.sh: ${file} does not match the lockfile integrity`);
    console.error(`  expected sha512-${expected}`);
    console.error(`  got      sha512-${digest}`);
    process.exit(1);
  }
' "$build/workerd.tgz" "$workerd_integrity"
tar -xzf "$build/workerd.tgz" -C "$build" package/bin/workerd
cp "$build/package/bin/workerd" "$context/workerd"
workerd_sha256="$(node -e 'const {createHash}=require("node:crypto");const {readFileSync}=require("node:fs");process.stdout.write(createHash("sha256").update(readFileSync(process.argv[1])).digest("hex"))' "$context/workerd")"
echo "build.sh: workerd sha256 $workerd_sha256"

# 3. The Worker bundle, wrangler's output from the lane's own bundling config (not a wrapper): the
#    config names src/lane/entry.ts, the CompiledWasm rule for the relay-policy interpreter and the
#    compatibility flags the image must run with.
(
  cd "$workers"
  npx --no-install wrangler deploy --dry-run --outdir "$build/wrangler" --config "$workers/gateway/wrangler.lane.jsonc" >"$build/wrangler.log" 2>&1 || {
    tail -n 20 "$build/wrangler.log" >&2
    echo "build.sh: wrangler did not produce the bundle" >&2
    exit 1
  }
)
[ -f "$build/wrangler/entry.js" ] || { echo "build.sh: wrangler wrote no entry.js" >&2; exit 1; }
cp "$build/wrangler/entry.js" "$context/worker/entry.js"
cp "$build/wrangler"/*.wasm "$context/worker/"
# workerd treats every named export of the entry module as an entrypoint, and the lane bundle also
# exports its route constants for the tests. A small wrapper makes the workerd entrypoints exactly the
# default one and `relayConfig` (S28: the relay-stack layout's config listener binds it; the default
# layout binds no socket to it); the bundle keeps its named exports for Node tests.
printf 'import entry, { relayConfig } from "./entry.js";\nexport default entry;\nexport { relayConfig };\n' > "$context/worker/worker.mjs"

# 4. What the image carries besides the bundle: the config template, the entrypoint and the three Go
#    programs' sources. Tests and notes are not part of the measured image; go.mod/go.sum are, so
#    the Go stage resolves exactly the pinned modules.
tar -C "$here/egress" --exclude='*_test.go' --exclude='test' --exclude='check.sh' --exclude='README.md' --exclude='IMPLEMENTATION_NOTES.md' -cf - . | tar -C "$context/egress" -xf -
tar -C "$here/acme" --exclude='*_test.go' --exclude='README.md' -cf - . | tar -C "$context/acme" -xf -
tar -C "$here/isolation-check" --exclude='*_test.go' --exclude='dockertest' --exclude='check.sh' -cf - . | tar -C "$context/isolation-check" -xf -
# gray-peerlink's sources, for the Dockerfile's peerlink stage (both layouts run it, relay-outbound-only §3.8).
tar -C "$here/peerlink" --exclude='*_test.go' --exclude='README.md' --exclude='check.sh' --exclude='testdata' -cf - . | tar -C "$context/peerlink" -xf -
cp "$here/workerd/config.capnp" "$context/config.capnp"
cp "$here/bin/entrypoint.mjs" "$context/entrypoint.mjs"

# 5. Provenance, from the worktree the bundle was made of (§4.1 `source_provenance`). The image digest is
#    not known until after the build, so it stays empty here and is a deployment-time value (README).
{
  echo "SOURCE_REPO_URL=https://github.com/megaeth-labs/gray"
  echo "SOURCE_REPO_COMMIT=$(git -C "$repo" rev-parse HEAD)"
  echo "SOURCE_IMAGE_DIGEST="
  echo "local=$local_build"
} >"$context/build.env"

# 6. One timestamp for every input: build.sh's half of reproducibility (the Dockerfile has no network
#    step; buildx's half is --rewrite-timestamp, below).
stamp=""
stamp="$(node -e 'const d=new Date(Number(process.argv[1])*1000);const p=(n)=>String(n).padStart(2,"0");process.stdout.write(`${d.getUTCFullYear()}${p(d.getUTCMonth()+1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}.${p(d.getUTCSeconds())}`)' "$source_date_epoch")"
find "$context" -type f -print0 | while IFS= read -r -d '' file; do TZ=UTC0 touch -t "$stamp" "$file"; done
find "$context" -type d -print0 | while IFS= read -r -d '' dir; do TZ=UTC0 touch -t "$stamp" "$dir"; done

# 7. Two clean builds, written to OCI layout tars. --no-cache twice; --provenance=false so no
#    attestation manifest carries a clock; rewrite-timestamp=true so every layer header and the image
#    config's created time are SOURCE_DATE_EPOCH (the docker exporter cannot do this: it unpacks the
#    layers into the daemon and rejects the option, so the reproducibility check compares OCI manifest
#    digests and the second build is then loaded for the e2e).
build_once() {
local dest="$1" log="$2"
BUILDX_CONFIG="$buildx_config" docker buildx build \
  --platform "$platform" \
  --no-cache \
  --provenance=false \
  --build-arg "BASE_IMAGE=$base_image" \
  --build-arg "GO_IMAGE=$go_image" \
  --build-arg "WORKERD_SHA256=$workerd_sha256" \
  --build-arg "SOURCE_DATE_EPOCH=$source_date_epoch" \
  --build-arg "LOCAL_BUILD=$local_build" \
  --output "type=oci,dest=$dest,rewrite-timestamp=true" \
  -f "$here/Dockerfile" \
  "$context" >"$log" 2>&1 || {
    tail -n 40 "$log" >&2
    echo "build.sh: the build failed (log $log)" >&2
    exit 1
  }
}

manifest_digest() {
node -e '
  const { execFileSync } = require("node:child_process");
  const index = JSON.parse(execFileSync("tar", ["-xOf", process.argv[1], "index.json"], { encoding: "utf8" }));
  if (!Array.isArray(index.manifests) || index.manifests.length !== 1) {
    console.error("build.sh: the OCI layout does not hold one manifest");
    process.exit(1);
  }
  process.stdout.write(index.manifests[0].digest);
' "$1"
}

# buildx keeps its state (activity, refs) in BUILDX_CONFIG. Each run starts from an empty one, as it
# always has (the two builds of one run share it; nothing of an earlier run's context transfer carries
# over), and it lives outside the checkout: docker may run as another user (the build box's wrapper runs
# the CLI through sudo and keeps BUILDX_CONFIG), and buildx then creates its directories as that user, mode
# 0700. Inside $build they made the next run's `rm -rf "$build"` and git clean fail. The run removes its own
# directory at exit, through the same docker when its own rm cannot (the pinned base image, no network); a
# caller's BUILDX_CONFIG is used as it is and left alone.
if [ -n "${BUILDX_CONFIG:-}" ]; then
  buildx_config="$BUILDX_CONFIG"
else
  buildx_config="$(mktemp -d "${TMPDIR:-/tmp}/gray-lane-buildx.XXXXXX")"
  remove_buildx_config() {
    rm -rf "$buildx_config" 2>/dev/null && return 0
    docker run --rm --network none --entrypoint sh -v "$buildx_config:/buildx" "$base_image" -c 'rm -rf /buildx/* /buildx/.[!.]*' >/dev/null 2>&1 || true
    rmdir "$buildx_config" 2>/dev/null || echo "build.sh: left buildx state in $buildx_config (outside the checkout)" >&2
  }
  trap remove_buildx_config EXIT
fi
build_once "$build/first.tar" "$build/first.log"
first="$(manifest_digest "$build/first.tar")"
build_once "$build/second.tar" "$build/second.log"
second="$(manifest_digest "$build/second.tar")"

if [ "$first" != "$second" ]; then
echo "build.sh: the two builds differ, so the image is not reproducible" >&2
echo "  first  $first" >&2
echo "  second $second" >&2
exit 1
fi

# The second build, loaded and tagged, is the image the e2e runs.
loaded="$(docker load -i "$build/second.tar" 2>&1 | sed -n 's/^Loaded image ID: //p' | tail -n 1)"
if [ -z "$loaded" ]; then
echo "build.sh: docker could not load the built image" >&2
exit 1
fi
docker tag "$loaded" "$tag"

# D55/D97: the runtime stage has no CA store of its own; the bundle is copied from the Go stage. Check
# it in the built image (not only in the Dockerfile) so a base change cannot ship a lane that fails
# every vendor TLS handshake at boot. The Go path serves gray-egress; /etc/ssl/cert.pem is BoringSSL's
# default file path, which is what workerd's trustBrowserCas reads (D97 notes cite the source lines).
if ! docker run --rm --entrypoint sh "$tag" -c 'test -s /etc/ssl/certs/ca-certificates.crt && test -s /etc/ssl/cert.pem'; then
  echo "build.sh: the CA bundle is missing or empty in $tag (need both /etc/ssl/certs/ca-certificates.crt and /etc/ssl/cert.pem)" >&2
  exit 1
fi

echo
echo "gray-lane is reproducible: two clean builds, one digest"
echo "  manifest $first"
echo "  tag      $tag"
echo "  platform $platform"
echo "  local    $local_build (1 = local build, not a release, never signed)"
echo "  ca       /etc/ssl/certs/ca-certificates.crt and /etc/ssl/cert.pem present"
echo "  workerd  $workerd_version sha256:$workerd_sha256"
echo "  source   $(git -C "$repo" rev-parse HEAD)"
echo "  bundle   $(node -e 'const {createHash}=require("node:crypto");const {readFileSync}=require("node:fs");process.stdout.write("sha256:"+createHash("sha256").update(readFileSync(process.argv[1])).digest("hex"))' "$context/worker/entry.js")"
echo "  config   $(node -e 'const {createHash}=require("node:crypto");const {readFileSync}=require("node:fs");process.stdout.write("sha256:"+createHash("sha256").update(readFileSync(process.argv[1])).digest("hex"))' "$context/config.capnp")"
echo "  egress   $(node -e 'const {createHash}=require("node:crypto");const {readdirSync,readFileSync}=require("node:fs");const {join}=require("node:path");const d=process.argv[1];const h=createHash("sha256");for(const f of readdirSync(d).sort()){if(f.endsWith(".go")||f==="go.mod")h.update(f).update(readFileSync(join(d,f)));}process.stdout.write("sha256:"+h.digest("hex"))' "$context/egress")"
echo "  acme     $(node -e 'const {createHash}=require("node:crypto");const {readdirSync,readFileSync}=require("node:fs");const {join}=require("node:path");const d=process.argv[1];const h=createHash("sha256");for(const f of readdirSync(d).sort()){if(f.endsWith(".go")||f==="go.mod"||f==="go.sum")h.update(f).update(readFileSync(join(d,f)));}process.stdout.write("sha256:"+h.digest("hex"))' "$context/acme")"
echo "  isolation $(node -e 'const {createHash}=require("node:crypto");const {readdirSync,readFileSync}=require("node:fs");const {join}=require("node:path");const d=process.argv[1];const h=createHash("sha256");for(const f of readdirSync(d).sort()){if(f.endsWith(".go")||f==="go.mod")h.update(f).update(readFileSync(join(d,f)));}process.stdout.write("sha256:"+h.digest("hex"))' "$context/isolation-check")"
