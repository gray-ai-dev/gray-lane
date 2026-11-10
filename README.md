# gray-lane 2026.11.10-2373d8cc36e3

The source of Gray's `gray-lane` image built from Gray's commit `2373d8cc36e3dd47f377025fb098a0c19c9525ea`, published so that a relay, or the
coding agent a relay uses, can review each release before it accepts it. The image runs in every lane CVM: in the
entry's default layout and in each relay's stack VM. This tree holds exactly the 620 files its build reads, at
the paths they have in Gray's repository, so the build scripts run unchanged. It also holds the measured compose
templates and pre-launch scripts that decide what the CVM starts. Tests, documentation and Gray's other services
are not included. Each release is one commit in this repository. Its parent is the release published before it, so
`git diff <previous tag> 2026.11.10-2373d8cc36e3` shows the code that changed between the two.

| What runs in the CVM | Where its source is |
|-|-|
| the lane Worker on workerd (the inbound program): requests in, policy, receipts | `workers/gateway/src/lane/` and the `workers/packages/` it imports, bundled by `workers/gateway/wrangler.lane.jsonc` |
| the entrypoint that starts workerd and gray-acme | `deploy/tee/bin/entrypoint.mjs`, `deploy/tee/workerd/config.capnp` |
| gray-egress (the outbound program): every vendor request leaves through it | `deploy/tee/egress/` |
| gray-peerlink: the stack VM's link to the entry | `deploy/tee/peerlink/` |
| gray-acme (the lane's TLS certificate) and gray-isolation-check | `deploy/tee/acme/`, `deploy/tee/isolation-check/` |
| the compose a CVM runs, and the script dstack runs before it | `deploy/tee/compose.stack.yaml`, `deploy/tee/pre-launch.stack.sh` (stack VM); `deploy/tee/compose.yaml`, `deploy/tee/pre-launch.sh` (entry); rendered by `deploy/tee/app-compose.mjs` |
| how the image is built | `deploy/tee/build.sh`, `deploy/tee/Dockerfile` |

## From the release list to this tag

Each entry of Gray's signed release list names a `compose_hash` and the `git_commit` it was built from. A
stack entry also names `stack.gray_image` (this image, by digest) and `stack.pre_launch_sha256`. For an entry:

1. Its source is the tag ending in the first 12 hex digits of `git_commit`: `git ls-remote --tags https://github.com/gray-ai-dev/gray-lane | grep <12 hex>`. `SOURCE.json` holds the full commit.
2. `stack.pre_launch_sha256` is the sha256 of `deploy/tee/pre-launch.stack.sh` in this tree. The script is embedded
   verbatim in the measured compose: `sha256sum deploy/tee/pre-launch.stack.sh`.
3. The digest in `stack.gray_image` is what `./rebuild.sh` prints (next section).

The image is public at `ghcr.io/gray-ai-dev/gray-lane`, and every lane CVM pulls it without a login, so anyone can fetch the
published manifest and compare: `docker manifest inspect <stack.gray_image>` needs no credential. Releases listed
before the image moved there name an earlier, private repository in `stack.gray_image`; their digests are checked
the same way, by rebuilding.

`gray-assistant releases` lists the releases your agent has seen, with their compose hashes and commits.

## What to review

The question to answer for each release is whether any code path can keep a relay's account credentials beyond
the boot that uses them, or send them, or anything derived from them, anywhere except the vendor they belong to.
Suggested instructions for a coding agent:

> Review this tree (and `git diff <the tag you accepted last> 2026.11.10-2373d8cc36e3`) for any way it could retain or transmit a
> relay's account keys. Trace: (1) where credentials enter: the sealed account records the lane opens with its
> per-boot keyset (`workers/gateway/src/lane/state.ts`, `workers/gateway/src/lane/stack-service.ts`,
> `workers/packages/relay-connector/`, `workers/packages/attest/`) and hands to gray-egress over its unix socket
> (`deploy/tee/egress/stack_control.go`), and the registry credential `deploy/tee/pre-launch.stack.sh` receives;
> (2) every network path out of the CVM: gray-egress's fixed vendor routes and proxies (`deploy/tee/egress/routes.go`
> and the files it uses), the lane's calls to Gray's bridge (`workers/gateway/src/lane/remote/`), gray-peerlink
> (`deploy/tee/peerlink/`), gray-acme, the pre-launch script's requests, and which networks and sockets the compose
> gives each container (`deploy/tee/compose.stack.yaml`, `deploy/tee/workerd/config.capnp`); (3) storage: every
> volume and file the compose and the programs write, and whether it is a tmpfs or the data disk. Report each place a
> credential, or a value derived from it, is logged, stored, put into a response or receipt, or sent to a host other
> than its vendor.

The request bodies a relay serves are not credentials, but the same paths carry them; a review of where they go is
the same review.

## Rebuild

`./rebuild.sh` runs Gray's release build, `deploy/tee/build.sh`, on this tree. It builds the image twice from
clean, fails unless both builds have the same digest, and prints `rebuild.sh: manifest sha256:…`. That digest must
equal the release list's `stack.gray_image` digest. The build is linux/amd64 and pins its inputs: the base images
by digest (`deploy/tee/build.sh`), npm packages by `workers/package-lock.json`, the workerd binary by the lockfile's
integrity, and Go modules by each program's `go.sum`.

`build.sh` reads the commit and its time from git, and they are part of the digest (`/etc/lane/build.env`). This
tree is not Gray's checkout, so `rebuild.sh` puts a small `git` first on `PATH` for the build. It answers those two
questions with the values in `SOURCE.json` and passes every other git command to your git. Read it before you run
it.

## What is not reproducible yet

- The image's digest is reproducible only for linux/amd64, which is the platform the CVM runs.
- The rendered compose, and so the compose hash, also depends on values outside this tree: the environment's
  domain, the KMS, and the names of the encrypted environment variables. This tree shows how `deploy/tee/app-compose.mjs`
  renders them, but it cannot recompute a compose hash alone. The parts that carry code (the image digest and the
  pre-launch script) can be checked as above.

## License

No license is granted. The source is published so that it can be reviewed and rebuilt. All rights are reserved by
Gray. Third-party code that the build pulls in (npm packages, Go modules, base images) keeps its own license.
