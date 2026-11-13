# The gray-lane image: workerd, the gateway's confidential-lane bundle, gray-egress, gray-acme,
# gray-isolation-check, gray-peerlink, gray-idle, the rendered workerd config, the entrypoint and pre-launch's boot box helper. The same image runs every Gray
# compose service (lane, egress and the one-shot acme; in the relay-stack layout also the one-shot
# isolation-check); egress, acme and isolation-check override the entrypoint.
#
# Reproducibility (deploy/tee/IMPLEMENTATION_NOTES.md §2 and §8):
# - both base images are pinned by digest (build.sh always passes BASE_IMAGE and GO_IMAGE; neither has
#   a default in this file, so the two places cannot drift apart);
# - workerd comes from the npm package the workspace lockfile pins, its sha256 checked again here;
# - the Worker bundle is wrangler's output from the same lockfile and the lane's bundling config;
# - gray-egress is built from this repository's deploy/tee/egress with -trimpath, CGO disabled and
#   an empty build id, in the pinned Go image; go.mod has no requirements, so that stage makes no
#   network request;
# - gray-isolation-check is built from deploy/tee/isolation-check like gray-egress (standard library
#   only, no network); so is gray-idle from deploy/tee/idle;
# - boot-box.mjs is esbuild's bundle of deploy/tee/boot-box/main.mjs from the same lockfile (build.sh);
# - gray-acme is built from deploy/tee/acme the same way. Its go.mod pins lego v5.6.0 and its
#   go.sum pins every module content hash, so the Go stage downloads exactly those bytes from the
#   module proxy (the only network step in the Go stages); `-mod=readonly` makes a missing go.sum entry
#   fail the build instead of silently resolving something else;
# - the runtime stage has no `apt-get`: every layer is a COPY of a byte-identical input;
# - D55/D97: the runtime stage has no CA store of its own (node:*-bookworm-slim purges ca-certificates).
#   The Go stage is Debian bookworm with Mozilla's ca-certificates, so its
#   /etc/ssl/certs/ca-certificates.crt is copied in at the same path for gray-egress, and the same
#   bundle is copied to /etc/ssl/cert.pem, where workerd's trustBrowserCas reads roots: in workerd
#   v1.20261006.1, src/workerd/server/server.c++:1832 maps the config flag to kj's
#   useSystemTrustStore; capnproto 1be2d2a c++/src/kj/compat/tls.c++:790-793 calls
#   SSL_CTX_set_default_verify_paths; BoringSSL 0.20260929.0 ssl/ssl_x509.cc:565 calls
#   X509_STORE_set_default_paths, crypto/x509/x509_d2.cc:19-35 loads the default file and hashed dir,
#   and crypto/x509/x509_def.cc:25-27 names them /etc/ssl/cert.pem and /etc/ssl/certs (with
#   $SSL_CERT_FILE / $SSL_CERT_DIR overrides in by_file.cc:42 and by_dir.cc:117). The file lookup is
#   enough; no hashed links are needed. gray-egress's production build fails closed when Go's system
#   pool is empty, so a missing bundle is a boot failure, not a silent TLS failure at every vendor
#   request. Both COPYs are deterministic (same base digest, same bytes).
# - build.sh normalises every input's mtime to SOURCE_DATE_EPOCH, builds twice with --no-cache and fails
#   when the two OCI manifest digests differ. Only a non-local build (D65) is a release build.
ARG BASE_IMAGE
ARG GO_IMAGE
ARG LOCAL_BUILD=0

# ---------------------------------------------------------------------------------------------------
# gray-egress (deploy/tee/egress): static; uTLS and x/net at the go.mod/go.sum pin, plus the in-repo fork of the standard
# library's HTTP/2 client (egress/third_party/stdhttp2: net/http/internal/http2 of this GO_IMAGE's Go release, recorded in
# its BASE, + gray.patch) for the mirrored transport.
# ---------------------------------------------------------------------------------------------------
FROM ${GO_IMAGE} AS egress
ARG TARGETARCH=amd64
WORKDIR /src
COPY egress/ /src/
RUN GOTOOLCHAIN=local go mod download \
 && CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -mod=readonly -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /out/gray-egress .

# ---------------------------------------------------------------------------------------------------
# gray-isolation-check (deploy/tee/isolation-check): standard library only, static, flags as egress.
# ---------------------------------------------------------------------------------------------------
FROM ${GO_IMAGE} AS isolation-check
ARG TARGETARCH=amd64
WORKDIR /src
COPY isolation-check/ /src/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /out/gray-isolation-check .

# ---------------------------------------------------------------------------------------------------
# gray-idle (deploy/tee/idle): the empty slot's program (docs/design/relay-no-always-on-host.md 13.11 P2d), standard
# library only, static, flags as egress. Pre-launch imports this one file as the relay's slot of a phase-2 boot that has
# no boot box to open, so it must run alone in an otherwise empty image.
# ---------------------------------------------------------------------------------------------------
FROM ${GO_IMAGE} AS idle
ARG TARGETARCH=amd64
WORKDIR /src
COPY idle/ /src/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /out/gray-idle .

# ---------------------------------------------------------------------------------------------------
# gray-acme (deploy/tee/acme): lego as a library at the go.mod/go.sum pin, same flags as egress.
# ---------------------------------------------------------------------------------------------------
FROM ${GO_IMAGE} AS acme
ARG TARGETARCH=amd64
WORKDIR /src
COPY acme/ /src/
RUN GOTOOLCHAIN=local go mod download \
 && CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -mod=readonly -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /out/gray-acme .

# ---------------------------------------------------------------------------------------------------
# gray-peerlink (deploy/tee/peerlink): coder/websocket and hashicorp/yamux at the go.mod/go.sum pin, built
# as gray-acme. The runtime image carries it for both layouts' peerlink service (docs/design/relay-outbound-only.md
# §3.2, §3.8: the entry's and the stack VM's own container).
# ---------------------------------------------------------------------------------------------------
FROM ${GO_IMAGE} AS peerlink
ARG TARGETARCH=amd64
WORKDIR /src
COPY peerlink/ /src/
RUN GOTOOLCHAIN=local go mod download \
 && CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -mod=readonly -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /out/gray-peerlink .

# ---------------------------------------------------------------------------------------------------
# The runtime image all services use.
# ---------------------------------------------------------------------------------------------------
FROM ${BASE_IMAGE}

# Checked against the binary, not only at download time in build.sh.
ARG WORKERD_SHA256
ARG LOCAL_BUILD=0

LABEL org.opencontainers.image.title="gray-lane" \
      com.gray.build.local="$LOCAL_BUILD" \
      org.opencontainers.image.description="Gray's confidential lane: the gateway Worker, its egress sidecar and its in-CVM ACME client inside a dstack CVM" \
      org.opencontainers.image.source="https://github.com/megaeth-labs/gray" \
      org.opencontainers.image.licenses="UNLICENSED"

# workerd, the Engine the Worker runs on, from the same npm version the workspace tests use.
COPY workerd /usr/local/bin/workerd
COPY --from=egress /out/gray-egress /usr/local/bin/gray-egress
COPY --from=acme /out/gray-acme /usr/local/bin/gray-acme
COPY --from=isolation-check /out/gray-isolation-check /usr/local/bin/gray-isolation-check
COPY --from=peerlink /out/gray-peerlink /usr/local/bin/gray-peerlink
COPY --from=idle /out/gray-idle /usr/local/bin/gray-idle
# D55: gray-egress verifies vendor TLS with Go's system roots at the Go path.
COPY --from=egress /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
# D97: workerd's trustBrowserCas reads BoringSSL's default file path. The file lookup loads this
# bundle; the hashed /etc/ssl/certs lookup finds no hashed names and is not what roots come from.
COPY --from=egress /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem

# /srv/lane: what workerd parses at start. `embed` in config.capnp resolves relative to the config file,
# so the Worker bundle sits in worker/ beside it.
COPY config.capnp /srv/lane/config.capnp
COPY worker/ /srv/lane/worker/
COPY entrypoint.mjs /srv/lane/entrypoint.mjs
COPY kms-lease.mjs /srv/lane/kms-lease.mjs
COPY vault-disk.mjs /srv/lane/vault-disk.mjs
# P2d: pre-launch's boot box helper, one esbuild bundle (deploy/tee/boot-box), run by a phase-2 pre-launch only.
COPY boot-box.mjs /srv/lane/boot-box.mjs

# The build provenance the report serves as `source_provenance`: the commit the bundle came from.
COPY build.env /etc/lane/build.env

# S2b: /run/gray is egress's (10002) with the socket group 10100 and setgid, so egress.sock is created
# in group 10100 and the lane (group 10100) reaches it, nothing else. The relay-stack layout's
# egress-socket volume is a plain named volume, which docker fills from this directory on first use,
# ownership and mode included (on a tmpfs docker root it is fresh every boot). compose.yaml's tmpfs
# volume is mounted empty (root, 1777) over it, so the default layout, which runs as root without
# capabilities, never sees this ownership. /run/peerlink is the same for peerlink's socket (relay-outbound-only
# §3.8): peerlink's (10005) with the group 10101 and setgid, so in the stack layout the lane (group 10101) reaches
# peerlink.sock and nothing else of peerlink's, and the relay, which mounts neither volume, reaches neither socket.
# The sign-in CA's volumes (docs/design/relay-sign-in-in-vm.md D1) fill the same way: /run/gray-sign-in-key is
# egress's alone (0700, the CA key), /run/gray-sign-in-ca egress's and readable (0755), mounted read-only in the relay.
RUN echo "${WORKERD_SHA256}  /usr/local/bin/workerd" | sha256sum -c - \
 && chmod 0755 /usr/local/bin/workerd /usr/local/bin/gray-egress /usr/local/bin/gray-acme \
      /usr/local/bin/gray-isolation-check /usr/local/bin/gray-peerlink /usr/local/bin/gray-idle /srv/lane/entrypoint.mjs \
 && chmod 0644 /srv/lane/config.capnp /srv/lane/worker/* /srv/lane/kms-lease.mjs /srv/lane/vault-disk.mjs /srv/lane/boot-box.mjs /etc/lane/build.env \
 && mkdir -p /run/lane /run/gray /run/peerlink /certs \
 && chmod 0700 /run/lane \
 && chown 10002:10100 /run/gray \
 && chmod 2750 /run/gray \
 && chown 10005:10101 /run/peerlink \
 && chmod 2750 /run/peerlink \
 && mkdir -p /run/gray-sign-in-key /run/gray-sign-in-ca \
 && chown 10002:10002 /run/gray-sign-in-key /run/gray-sign-in-ca \
 && chmod 0700 /run/gray-sign-in-key \
 && chmod 0755 /run/gray-sign-in-ca \
 && test -s /etc/ssl/certs/ca-certificates.crt \
 && test -s /etc/ssl/cert.pem

# D133: /certs holds gray-acme's ACME accounts only (compose.yaml mounts lane-certs there). Each boot's
# certificate key and certificate are generated by the lane's entrypoint (gray-acme) into the lane's
# /run/lane tmpfs: the image ships none, and the entrypoint refuses to start without one.
VOLUME ["/certs"]

# The lane publishes 443 (gray-acme's tls-alpn-01 listener, then workerd). The egress service has no port.
EXPOSE 443

# compose.yaml runs as root: root is what reads the host's /var/run/dstack.sock there; the compose
# drops every capability and makes the root filesystem read-only, and nothing else runs in this
# container. compose.stack.yaml sets a non-root `user:` on every service (S2b) and keeps this default.
USER root
ENTRYPOINT ["node", "/srv/lane/entrypoint.mjs"]
