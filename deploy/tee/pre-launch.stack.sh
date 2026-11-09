#!/bin/bash
# deploy/tee/pre-launch.stack.sh — the measured pre_launch_script of the relay-stack layout (S9).
#
# dstack sources this file under `set -euo pipefail` from app-compose.sh before `docker compose up`
# (dstack-src os/common/rootfs/app-compose.sh: `source <(jq -r '.pre_launch_script' …)`), as root, in
# /dstack, with APP_COMPOSE_FILE (app-compose.json) and COMPOSE_FILE (docker-compose.yaml, written by
# dstack-prepare.sh) set and the allowed_envs-filtered environment from `dstack-util exec-with-env`.
#
# What it does, in the order of S9 (docs/confidential-lane-supply-implementation.md §4, amended by S51 and S54):
#   1. stop dockerd, containerd and the stargz snapshotter, put every container-runtime state directory on a tmpfs, check each
#      with `stat -f` (findmnt --target reads the lower mount, measurements §3.7), bind one data-disk
#      directory for Gray's persistent state (relay-outbound-only §3.9: no certificate directory in it any more;
#      lane's gray-acme is self-signed and keeps no ACME account), start containerd and dockerd, check docker's root
#      and driver;
#   2. drop host INPUT from the two relay bridges, IPv4 and IPv6 (§9 B; iptables matches interface names lazily);
#   3. read the relay's identity from the encrypted env (S54: GRAY_STACK_RELAY_ID, GRAY_STACK_TOKEN_URL,
#      GRAY_STACK_RELAY_KEY; no TLS name since the VM has no public one, docs/design/relay-outbound-only.md §3.9),
#      check each form and extend RTMR3 with it as
#      `gray-stack-identity` (so the quote below carries it, and the token service sees whom the boot claims to
#      serve); then (S8a) pull Gray's own images with Gray's registry credential in a docker config of their
#      own, delete that config, and ask the relay's token service for a nonce, waiting for it with backoff
#      (S51a) while it is unreachable or answers 5xx/429;
#   4. make a one-time RSA-3072 key and bind it and each attempt's nonce into report_data;
#   5. take a quote from the guest agent;
#   6. send the quote, the event log and app-compose.json to the token service;
#   7. decrypt its RSA-OAEP-SHA256 envelope (the registry credential), and check the image the relay chose
#      (S51): its form, its registry (the envelope's), and the relay's Ed25519 signature over
#      `gray-relay-image/v1\n<nonce>\n<image>` with the measured relay key;
#   8. docker login with the password on stdin into a DOCKER_CONFIG on tmpfs, pull that image by its digest,
#      refuse it when its config declares a VOLUME, tag it into the relay's slot `gray-relay-slot:boot` (S50)
#      and check the slot is that image, and delete that DOCKER_CONFIG (the credential): `docker compose up`
#      then finds every image locally and no registry credential is left;
#   9. extend RTMR3 with `gray-relay-image` (the relay id, the image, the nonce and the signature, S52), then
#      with the seal event (every later quote of this boot carries it, and the token service refuses such
#      quotes, S11), and delete the key and the rest of the work directory.
#
# Phase 2 (docs/design/relay-no-always-on-host.md §3.5, 13.11 P2d). An app on an on-chain KMS names it in its measured
# compose (the lane's LANE_KMS_URL literal, app-compose.mjs --kms-url); only such an app takes this path, and every other
# app runs steps 4-9 above exactly as before. After steps 1-3 (the identity is measured as before; Gray's images are
# pulled), there is no token service: the registry login and the relay-signed image designation are in the sealed boot
# box on the data disk, with a copy at Gray. Steps 4-9 become `gray_prelaunch_stack_phase2`:
#   P1. the relay's data-disk directory /var/lib/gray-persist/relay, the lane's (10001:10001, 0700);
#   P2. the boot box helper, Gray's measured code from the lane image the compose pins by digest (/srv/lane/boot-box.mjs,
#       deploy/tee/boot-box), run once per attempt with the guest agent's socket, that directory and a fresh 0700 tmpfs
#       output directory: it reads the disk's record and Gray's copy, obtains Gray's share for a quote of this boot,
#       derives K_boot from the measured relay id and key, opens the newest record never below the highest this disk
#       has seen, checks the designation, and answers the login and the designation, or the empty slot with its reason.
#       It needs the bridge, so it runs on Docker's default bridge network (not --network none, which #349 assumed
#       before the copy and the share were bridge calls): the code is Gray's measured code, and nothing of the relay's
#       is in it but ciphertext until the share arrives sealed (HPKE) to a key of this run. Its input (the bridge URL,
#       the bridge key's seed, the identity) goes in on stdin, never in argv or env. While Gray's copy (with no disk
#       record) or its share is unavailable it exits 75 and runs again with the token wait's backoff, as S51a waits;
#   P3. the designation checked again here with the guest's OpenSSL (S49's command) against the measured relay key,
#       then the image pulled by digest with the boot box's login, a VOLUME refused, the slot tagged, the login deleted;
#       or, for the empty slot, the lane image's static gray-idle imported alone as the slot (no relay code runs);
#   P4. `gray-relay-image` v2: {image, image_sig, issued_ms, previous, relay_id, seq} (the designation and its
#       signature; no nonce), or {image: null, relay_id, seq: 0} for the empty slot; then the seal, as in step 9.
#
# Fail-closed: the work is one function, gray_prelaunch_stack, called as the last command of this file.
# Every command in it is checked explicitly (`|| { gray_prelaunch_stack_fail …; return 1; }`), so it does
# not depend on errexit, which bash ignores inside a function called from a condition. Any failure removes
# the work directory (key, envelope, credential, docker config) and returns 1; the call is the file's last
# command, so `source` returns 1, and app-compose.sh, under `set -e`, stops before `docker compose up`:
# the app does not start. The file never calls `exit`, never uses `|| true`, never turns errexit off.
#
# Output: fixed status lines only (it reaches the serial console, which is readable without a token).
# No line contains a value read at run time but one: the relay token service's refusal code (S58), a closed
# form of lower-case letters, digits and `_` read from `{"error": "<code>"}` alone. Every command's own output
# goes to /dev/null, so no token, nonce, other response text, curl error or key material can reach the console.
#
# Only openssl (crypto: OpenSSL 3.5.6 in dstack 0.6.1, whose `pkeyutl -verify -rawin` checks Ed25519, S49), jq
# (JSON) and curl (HTTP, with timeouts) are used; all are present at pre-launch (measurements §3.6). Hex becomes
# bytes with the printf builtin only, after a pattern check. The password reaches `docker login` on stdin and
# nothing else.
#
# GRAY_PRELAUNCH_ROOT is a test seam only: a prefix for the host paths this script touches, empty by
# default. It is not in allowed_envs (S8/S8a: LANE_BRIDGE_KEY_SEED and the three DSTACK_DOCKER_* names,
# checked by the token service), so a measured CVM never sets it, and a non-tmpfs path under it still
# fails the `stat -f` checks.
#
# The identity values are read from the environment dstack-util exec-with-env gives app-compose.sh (the
# allowed_envs-filtered encrypted env), which is the environment `docker compose up` interpolates
# LANE_STACK_RELAY_ID from; the lane's entrypoint refuses to start when it differs from the event, and when the lane
# has a TLS_DOMAIN at all (relay-outbound-only §3.9: the VM serves a per-boot key bound to no domain).
#
# `A && B || fail` is meant: fail runs when A or B fails.
# shellcheck disable=SC2015
set -euo pipefail

gray_prelaunch_stack_status() {
  printf 'gray-prelaunch: %s\n' "$1"
}

# $1: a fixed label. Reports and removes the work directory, which holds everything secret this script
# made; the caller then returns 1.
gray_prelaunch_stack_fail() {
  printf 'gray-prelaunch: FAILED: %s\n' "$1" >&2
  if [[ -n "${gray_prelaunch_stack_work:-}" ]]; then
    rm -rf -- "$gray_prelaunch_stack_work" >/dev/null 2>&1 \
      || printf 'gray-prelaunch: FAILED: removing the work directory\n' >&2
  fi
}

# $1: lower-case hex, already checked by the caller; writes its bytes to stdout with the printf builtin.
gray_prelaunch_stack_hex_bytes() {
  local hex="$1" index
  [[ "$hex" =~ ^([0-9a-f]{2})+$ ]] || return 1
  for ((index = 0; index < ${#hex}; index += 2)); do
    printf "\\x${hex:index:2}" || return 1
  done
}

# $1: a token service URL, $2: the body (JSON text, or @file), $3: the answer's file. Returns 0 on a 200, 1 when
# no answer came (no connection, a timeout), 3 when the service answered 5xx or 429 (it may answer later), 2 when it
# refused (any other status). Without --fail, so the status can be read; the body of every status goes to the answer's
# file in the work directory and nowhere else. The file is removed first, so it never holds an earlier call's body
# (curl writes no file for an empty body).
gray_prelaunch_stack_token_call() {
  local code
  rm -f -- "$3" >/dev/null 2>&1 || return 1
  code="$(curl --silent --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 --max-filesize 1048576 \
      -H 'Content-Type: application/json' -w '%{http_code}' --data-binary "$2" -o "$3" "$1" 2>/dev/null)" || return 1
  [[ "$code" == 200 ]] && return 0
  [[ "$code" =~ ^(5[0-9][0-9]|429)$ ]] && return 3
  return 2
}

# $1: a token service answer's file. Prints the refusal code of an answer {"error": "<code>"} whose code is
# ^[a-z0-9_]{1,64}$ (relay-kit's PULL_TOKEN_REFUSALS, S58), else prints nothing and returns 1. The code is the one
# value of an answer this script ever prints: a closed form (lower-case letters, digits, `_`), checked by jq and again
# by bash, so no token, nonce or other text of a body can reach the console through it.
gray_prelaunch_stack_refusal_code() {
  local code
  code="$(jq -er 'select(type == "object") | .error | select(type == "string" and test("^[a-z0-9_]{1,64}$"))' "$1" 2>/dev/null)" \
    && [[ "$code" =~ ^[a-z0-9_]{1,64}$ ]] \
    && printf '%s' "$code"
}

# $1: an event name, $2: its payload file; extends RTMR3 with the payload's bytes (dstack's runtime event).
gray_prelaunch_stack_extend() {
  local payload
  payload="$(od -An -v -tx1 < "$2" | tr -d ' \n')" && [[ -n "$payload" ]] \
    && dstack-util extend --event "$1" --payload "$payload" >/dev/null 2>&1
}

# Phase 2, the empty slot (P3): the lane image's static gray-idle, alone in an image of its own, as the relay's slot.
# `docker create` makes a container of the lane image that never starts, `docker cp` streams that one file as a tar,
# `docker import` makes it an image whose entrypoint is that file (the relay service sets no command, S50), and the
# result is checked: one layer, that entrypoint, no command, no VOLUME. Every byte comes from the lane image the
# compose pins by digest. Reads lane_image and slot from the caller.
gray_prelaunch_stack_empty_slot() {
  local container
  container="$(docker create --pull never --network none -- "$lane_image" 2>/dev/null)" \
    && [[ "$container" =~ ^[0-9a-f]{64}$ ]] \
    || { gray_prelaunch_stack_fail "preparing the empty slot"; return 1; }
  docker cp "$container:/usr/local/bin/gray-idle" - 2>/dev/null \
      | docker import --change 'ENTRYPOINT ["/gray-idle"]' - "$slot" >/dev/null 2>&1 \
    || { gray_prelaunch_stack_fail "importing the empty slot"; return 1; }
  # -v: the lane image declares VOLUME /certs, so the container has an anonymous volume, removed with it.
  docker rm -v -- "$container" >/dev/null 2>&1 \
    || { gray_prelaunch_stack_fail "removing the empty slot's source container"; return 1; }
  docker image inspect -- "$slot" 2>/dev/null \
      | jq -e 'length == 1 and .[0].Config.Entrypoint == ["/gray-idle"] and .[0].Config.Cmd == null
          and ((.[0].Config.Volumes // {}) | type == "object" and length == 0) and (.[0].RootFS.Layers | length == 1)' >/dev/null 2>&1 \
    || { gray_prelaunch_stack_fail "the empty slot is not gray-idle alone"; return 1; }
  gray_prelaunch_stack_status "empty slot in the relay's slot"
}

# Phase 2 (P1-P4 in the header). Reads root, work, persist, dstack_sock, slot, seal_payload, image_pattern,
# ed25519_spki_prefix, relay_id, relay_key, lane_image and bridge_url from gray_prelaunch_stack.
gray_prelaunch_stack_phase2() {
  local relay_dir="$persist/relay" box="$work/box"
  # P1. The lane's directory on the data disk (P2e binds it into the lane): the boot box and the vault records.
  mkdir -p -- "$relay_dir" >/dev/null 2>&1 \
    && chown 10001:10001 "$relay_dir" >/dev/null 2>&1 \
    && chmod 0700 "$relay_dir" >/dev/null 2>&1 \
    && [[ "$(stat -c '%u:%g:%a' "$relay_dir" 2>/dev/null)" == "10001:10001:700" ]] \
    || { gray_prelaunch_stack_fail "the relay's data-disk directory"; return 1; }
  [[ "$lane_image" =~ ^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$ ]] \
    && [[ "$bridge_url" =~ ^https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$ ]] \
    && [[ "${LANE_BRIDGE_KEY_SEED:-}" =~ ^[0-9a-f]{64}$ ]] \
    || { gray_prelaunch_stack_fail "the boot box helper's inputs"; return 1; }

  # P2. The helper, run again while Gray's copy or share is unavailable (exit 75), waiting 1 s, then doubling up to
  # 32 s, at most the token wait (840 s, S51a's budget) in all; any other failure stops the boot.
  local token_wait="${GRAY_PRELAUNCH_TOKEN_WAIT_SECONDS:-840}"
  [[ "$token_wait" =~ ^[0-9]{1,5}$ ]] || { gray_prelaunch_stack_fail "the token wait is not whole seconds"; return 1; }
  local started=$SECONDS delay=1 call
  while :; do
    rm -rf -- "$box" >/dev/null 2>&1 \
      && mkdir -m 0700 -- "$box" >/dev/null 2>&1 \
      && chown 10001:10001 "$box" >/dev/null 2>&1 \
      || { gray_prelaunch_stack_fail "the boot box helper's directory"; return 1; }
    call=0
    # The values are checked above to forms that need no JSON escaping; printf is a builtin, so the seed reaches the
    # helper's stdin and no process's arguments.
    printf '{"bridge_url":"%s","key_seed":"%s","relay_id":"%s","relay_key":"%s"}' \
        "$bridge_url" "$LANE_BRIDGE_KEY_SEED" "$relay_id" "$relay_key" \
      | docker run --rm -i --pull never --network bridge --user 10001:10001 --read-only --cap-drop ALL \
          --security-opt no-new-privileges --tmpfs /tmp --entrypoint node \
          -v "$dstack_sock:/var/run/dstack.sock" -v "$relay_dir:/persist" -v "$box:/out" \
          "$lane_image" /srv/lane/boot-box.mjs --socket /var/run/dstack.sock --persist /persist --out /out \
          >/dev/null 2>&1 \
      || call=$?
    [[ "$call" -eq 0 ]] && break
    [[ "$call" -eq 75 ]] || { gray_prelaunch_stack_fail "the boot box helper"; return 1; }
    if (( SECONDS - started + delay > token_wait )); then
      gray_prelaunch_stack_fail "Gray's boot box copy or share did not answer in time"
      return 1
    fi
    gray_prelaunch_stack_status "boot box copy or share unavailable, retrying"
    sleep "$delay" >/dev/null 2>&1 || { gray_prelaunch_stack_fail "waiting for Gray's boot box copy or share"; return 1; }
    delay=$(( delay >= 16 ? 32 : delay * 2 ))
  done

  local entries reason
  entries="$(ls -A -- "$box" 2>/dev/null | tr '\n' ' ')" \
    || { gray_prelaunch_stack_fail "the boot box helper's answer"; return 1; }
  if [[ "$entries" == "empty " ]]; then
    # The reason is one of the helper's closed codes (EMPTY_SLOT_REASONS), the one value of its answer printed.
    reason="$(cat -- "$box/empty" 2>/dev/null)" \
      || { gray_prelaunch_stack_fail "the boot box helper's answer"; return 1; }
    case "$reason" in
      no_boot_box|boot_box_missing|boot_box_rolled_back|boot_box_unopened|boot_box_invalid|designation_refused|share_refused) ;;
      *)
        gray_prelaunch_stack_fail "the boot box helper's answer"
        return 1
        ;;
    esac
    gray_prelaunch_stack_status "no boot box to run ($reason): the empty slot"
    gray_prelaunch_stack_empty_slot || return 1
    jq -ncSj --arg relay_id "$relay_id" '{image: null, relay_id: $relay_id, seq: 0}' > "$work/image.payload" 2>/dev/null \
      || { gray_prelaunch_stack_fail "measuring the relay image"; return 1; }
  elif [[ "$entries" == "designation.json designation.sig login.json " ]]; then
    gray_prelaunch_stack_status "boot box opened"
    # P3. The designation: the JCS the relay signed (jq -cS writes the same bytes for this closed shape of checked
    # forms), naming this relay, an image of S51's form, a seq of at least 1; its registry is the login's.
    local designation="$box/designation.json" image image_sig registry
    image="$(jq -er --arg relay_id "$relay_id" --arg pattern "$image_pattern" '
        select(type == "object" and (keys == ["image", "issued_ms", "previous", "relay_id", "seq"]) and .relay_id == $relay_id
          and (.seq | type == "number" and . >= 1 and . == floor and . <= 9007199254740991)
          and (.issued_ms | type == "number" and . >= 0 and . == floor and . <= 9007199254740991)
          and (.previous == null or (.previous | type == "string" and length <= 512 and test($pattern))))
        | .image | select(type == "string" and length <= 512 and test($pattern))' "$designation" 2>/dev/null)" \
      && [[ "$(jq -cSj . "$designation" 2>/dev/null)" == "$(cat -- "$designation" 2>/dev/null)" ]] \
      && image_sig="$(cat -- "$box/designation.sig" 2>/dev/null)" \
      && [[ "$image_sig" =~ ^[0-9a-f]{128}$ ]] \
      && registry="${image%%/*}" \
      && [[ -n "$registry" && "$registry" != "$image" ]] \
      || { gray_prelaunch_stack_fail "the designation in the boot box"; return 1; }
    # S49's check: the relay's Ed25519 signature over `gray-relay-designation/v1\n` ‖ the designation, with the key
    # the identity event measured. Gray, which holds the copy, cannot name another image.
    { gray_prelaunch_stack_hex_bytes "$ed25519_spki_prefix" && gray_prelaunch_stack_hex_bytes "$relay_key"; } > "$work/relay-key.der" 2>/dev/null \
      && gray_prelaunch_stack_hex_bytes "$image_sig" > "$work/designation.sig.bin" 2>/dev/null \
      && [[ "$(wc -c < "$work/relay-key.der")" -eq 44 && "$(wc -c < "$work/designation.sig.bin")" -eq 64 ]] \
      && { printf 'gray-relay-designation/v1\n' && cat -- "$designation"; } > "$work/designation.message" 2>/dev/null \
      && openssl pkeyutl -verify -pubin -keyform DER -inkey "$work/relay-key.der" -rawin -in "$work/designation.message" \
        -sigfile "$work/designation.sig.bin" >/dev/null 2>&1 \
      || { gray_prelaunch_stack_fail "the designation signature"; return 1; }
    gray_prelaunch_stack_status "designation signature verified"
    # The login, for the designated image's registry only; the password reaches `docker login` on stdin only.
    local login="$box/login.json" username relay_config="$work/docker"
    jq -e --arg registry "$registry" \
        '(keys == ["password", "registry", "username"]) and .registry == $registry
          and (.username | type == "string" and length > 0) and (.password | type == "string" and length > 0)' \
        "$login" >/dev/null 2>&1 \
      && username="$(jq -r .username "$login" 2>/dev/null)" \
      && mkdir -m 0700 -- "$relay_config" >/dev/null 2>&1 \
      || { gray_prelaunch_stack_fail "the registry login"; return 1; }
    jq -j .password "$login" 2>/dev/null \
        | DOCKER_CONFIG="$relay_config" docker login --username "$username" --password-stdin "$registry" >/dev/null 2>&1 \
      || { gray_prelaunch_stack_fail "the registry login"; return 1; }
    gray_prelaunch_stack_status "registry login done"
    DOCKER_CONFIG="$relay_config" docker pull --quiet "$image" >/dev/null 2>&1 \
      || { gray_prelaunch_stack_fail "pulling the relay image"; return 1; }
    gray_prelaunch_stack_status "relay image pulled"
    docker image inspect -- "$image" 2>/dev/null \
        | jq -e 'length == 1 and ((.[0].Config.Volumes // {}) | type == "object" and length == 0)' >/dev/null 2>&1 \
      || { gray_prelaunch_stack_fail "the relay image declares a volume"; return 1; }
    gray_prelaunch_stack_status "relay image declares no volume"
    local pulled_id slot_id
    docker tag "$image" "$slot" >/dev/null 2>&1 \
      && pulled_id="$(docker image inspect --format '{{.Id}}' -- "$image" 2>/dev/null)" \
      && slot_id="$(docker image inspect --format '{{.Id}}' -- "$slot" 2>/dev/null)" \
      && [[ "$pulled_id" =~ ^sha256:[0-9a-f]{64}$ && "$slot_id" == "$pulled_id" ]] \
      || { gray_prelaunch_stack_fail "tagging the relay image into its slot"; return 1; }
    gray_prelaunch_stack_status "relay image in its slot"
    rm -rf -- "$relay_config" "$login" >/dev/null 2>&1 && [[ ! -e "$relay_config" && ! -e "$login" ]] \
      || { gray_prelaunch_stack_fail "deleting the registry credential"; return 1; }
    gray_prelaunch_stack_status "registry credential deleted"
    # P4. v2: the designation's members and its signature, as the relay signed them (jq keeps its integers).
    jq -cSj --arg image_sig "$image_sig" '. + {image_sig: $image_sig}' "$designation" > "$work/image.payload" 2>/dev/null \
      || { gray_prelaunch_stack_fail "measuring the relay image"; return 1; }
  else
    gray_prelaunch_stack_fail "the boot box helper's answer"
    return 1
  fi

  gray_prelaunch_stack_extend gray-relay-image "$work/image.payload" \
    || { gray_prelaunch_stack_fail "measuring the relay image"; return 1; }
  gray_prelaunch_stack_status "relay image measured"
  dstack-util extend --event gray-prelaunch-sealed --payload "$seal_payload" >/dev/null 2>&1 \
    || { gray_prelaunch_stack_fail "sealing pre-launch"; return 1; }
  rm -rf -- "$work" >/dev/null 2>&1 && [[ ! -e "$work" ]] \
    || { gray_prelaunch_stack_fail "deleting the work directory"; return 1; }
  gray_prelaunch_stack_status "sealed"
}

gray_prelaunch_stack() {
  local root="${GRAY_PRELAUNCH_ROOT:-}"
  # The container runtimes' state directories (measured in deploy/tee/probe/isolation/): docker's image
  # store and containerd's metadata (which held a container's environment on disk, measurements §3.7).
  local stores=(/var/lib/docker /var/lib/containerd /var/lib/sysbox /var/lib/nerdctl /var/lib/containerd-stargz-grpc)
  # The size the isolation probe mounted each of them with (deploy/tee/probe/isolation/pre-launch.sh);
  # a tmpfs takes memory only as it fills.
  local store_size=1536m
  local persist_disk="$root/var/volatile/dstack/persistent/gray-persist"
  local persist="$root/var/lib/gray-persist"
  local dstack_sock="$root/var/run/dstack.sock"
  # hex("gray-prelaunch-sealed-v1")
  local seal_payload=677261792d7072656c61756e63682d7365616c65642d7631
  # S50: the relay's slot, which the compose runs with pull_policy: never.
  local slot="gray-relay-slot:boot"
  # S51: <registry host[:port]>/<repository>@sha256:<64 hex>, lower case, no tag (@gray/lane-verify's pattern); the
  # registry has a dot, a port or is localhost, as docker reads a first component as a registry only then.
  local image_pattern='^((?:[a-z0-9][a-z0-9-]*\.)+[a-z0-9-]*[a-z0-9](?::[0-9]{1,5})?|[a-z0-9][a-z0-9.-]*:[0-9]{1,5}|localhost)/([a-z0-9][a-z0-9._/-]*)@sha256:([0-9a-f]{64})$'
  # SPKI DER prefix of a raw Ed25519 public key (RFC 8410): SEQUENCE { SEQUENCE { id-Ed25519 }, BIT STRING }.
  local ed25519_spki_prefix=302a300506032b6570032100
  local d fstype

  gray_prelaunch_stack_work=""
  [[ -n "${APP_COMPOSE_FILE:-}" && -f "$APP_COMPOSE_FILE" && -n "${COMPOSE_FILE:-}" && -f "$COMPOSE_FILE" ]] \
    || { gray_prelaunch_stack_fail "app-compose.json or the compose file is missing"; return 1; }
  for d in curl jq openssl od docker systemctl mount stat iptables ip6tables dstack-util; do
    command -v "$d" >/dev/null 2>&1 || { gray_prelaunch_stack_fail "a required tool is missing"; return 1; }
  done

  # 1. The image store and the other runtime state on tmpfs; Gray's persistent directory on the data disk.
  # containerd-stargz-grpc holds /var/lib/containerd-stargz-grpc; the docker runner does not use it, so it
  # stays stopped.
  systemctl stop docker.socket docker.service containerd.service containerd-stargz-grpc.service >/dev/null 2>&1 \
    || { gray_prelaunch_stack_fail "stopping docker and containerd"; return 1; }
  for d in "${stores[@]}"; do
    mkdir -p -- "$root$d" >/dev/null 2>&1 \
      && mount -t tmpfs -o "mode=0711,size=$store_size" tmpfs "$root$d" >/dev/null 2>&1 \
      || { gray_prelaunch_stack_fail "mounting a tmpfs over a runtime directory"; return 1; }
  done
  for d in "${stores[@]}"; do
    fstype="$(stat -f -c %T "$root$d" 2>/dev/null)" && [[ "$fstype" == tmpfs ]] \
      || { gray_prelaunch_stack_fail "a runtime directory is not on tmpfs"; return 1; }
  done
  mkdir -p -- "$persist_disk" "$persist" >/dev/null 2>&1 \
    && mount --bind "$persist_disk" "$persist" >/dev/null 2>&1 \
    || { gray_prelaunch_stack_fail "binding the persistent directory"; return 1; }
  # relay-outbound-only §3.9: no certificate directory. The S2a bind is gone from the compose (lane's gray-acme is
  # self-signed and keeps no ACME account), so nothing here makes one; a lane-certs an earlier release left on the
  # data disk is mounted by no service.
  systemctl start containerd.service docker.service >/dev/null 2>&1 \
    || { gray_prelaunch_stack_fail "starting containerd and docker"; return 1; }
  # Docker's own root, not a seam path: dockerd keeps /var/lib/docker whatever this script was told.
  # overlay2 is the measured driver (docker 26.1.5, measurements §3.6); a different one is a change to
  # measure again, so it stops the boot.
  [[ "$(docker info --format '{{.DockerRootDir}} {{.Driver}}' 2>/dev/null)" == "/var/lib/docker overlay2" ]] \
    || { gray_prelaunch_stack_fail "docker is not on the expected root and driver"; return 1; }
  gray_prelaunch_stack_status "runtime state on tmpfs"

  # 2. The relay bridges cannot reach the host (§9 B). -w: dockerd may hold the xtables lock just now.
  # IPv6 too: dstack 0.6.1's rootfs ships ip6tables (Debian's nft frontend), and docker gives each bridge
  # an IPv6 link-local address. The containers' own interfaces have IPv6 off (docker 26.1 disables it on
  # IPv4-only networks; measured), so these two rules keep the host closed should that ever change.
  iptables -w -I INPUT -i gr-relay-in -j DROP >/dev/null 2>&1 \
    && iptables -w -I INPUT -i gr-relay-out -j DROP >/dev/null 2>&1 \
    && ip6tables -w -I INPUT -i gr-relay-in -j DROP >/dev/null 2>&1 \
    && ip6tables -w -I INPUT -i gr-relay-out -j DROP >/dev/null 2>&1 \
    || { gray_prelaunch_stack_fail "closing the relay bridges to the host"; return 1; }
  gray_prelaunch_stack_status "relay bridges closed to the host"

  # The work directory: a fresh 0700 directory on tmpfs for the key, the envelope and the credential.
  fstype="$(stat -f -c %T "$root/run" 2>/dev/null)" && [[ "$fstype" == tmpfs ]] \
    || { gray_prelaunch_stack_fail "/run is not on tmpfs"; return 1; }
  rm -rf -- "$root/run/gray-pull" >/dev/null 2>&1 \
    && mkdir -m 0700 -- "$root/run/gray-pull" >/dev/null 2>&1 \
    || { gray_prelaunch_stack_fail "making the work directory"; return 1; }
  gray_prelaunch_stack_work="$root/run/gray-pull"
  local work="$gray_prelaunch_stack_work"

  # 3. The relay's identity (S54), from the encrypted env, each in its form (@gray/lane-verify's
  # parseStackIdentityPayload), checked first because `docker compose config` below interpolates the relay id: the
  # relay id, its token service as an https origin written as its origin (no path, no default port), its Ed25519
  # public key. No TLS name (relay-outbound-only §3.9): the VM has no public name, and the identity is held to the
  # relay a verifier expected; GRAY_STACK_TLS_DOMAIN is not in this layout's allowed_envs and is never read. jq writes
  # the payload with sorted keys and no whitespace (`-cS`), which every reader parses, and it is measured before
  # anything uses it.
  jq -ncS --arg relay_id "${GRAY_STACK_RELAY_ID:-}" --arg token_url "${GRAY_STACK_TOKEN_URL:-}" \
      --arg public_key "${GRAY_STACK_RELAY_KEY:-}" \
      '{relay_id: $relay_id, token_url: $token_url, public_key: $public_key}
        | select(.relay_id | test("^[A-Za-z0-9_.:-]{1,128}$"))
        | select(.token_url | test("^https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$") and (endswith(":443") | not))
        | select(.public_key | test("^[0-9a-f]{64}$"))' \
      > "$work/identity.json" 2>/dev/null \
    && [[ -s "$work/identity.json" ]] \
    || { gray_prelaunch_stack_fail "the relay identity in the encrypted env"; return 1; }
  # jq ends its output with a newline; the measured payload is the object's bytes alone.
  local token_url relay_id relay_key
  token_url="$(jq -r .token_url "$work/identity.json" 2>/dev/null)" \
    && relay_id="$(jq -r .relay_id "$work/identity.json" 2>/dev/null)" \
    && relay_key="$(jq -r .public_key "$work/identity.json" 2>/dev/null)" \
    && jq -cSj . "$work/identity.json" > "$work/identity.payload" 2>/dev/null \
    && gray_prelaunch_stack_extend gray-stack-identity "$work/identity.payload" \
    || { gray_prelaunch_stack_fail "measuring the relay identity"; return 1; }
  gray_prelaunch_stack_status "relay identity measured"

  # S8a: Gray's own images, every service's but relay's, pulled now with Gray's registry credential
  # (DSTACK_DOCKER_*, the encrypted env) in a docker config of their own, deleted before the relay's login,
  # so the two logins never share a config, even on one registry host. Without the three values the pull is
  # anonymous (a public image); a partial set is refused. Each image must be pinned by digest. The compose's
  # JSON carries interpolated environment values, so it goes straight into jq and only the names are kept.
  # The password reaches `docker login` on stdin only (printf is a builtin).
  # Phase 2 reads three more values of the same JSON: the lane's image, its bridge URL and its LANE_KMS_URL literal
  # (none secret); the seed it carries never leaves jq.
  local gray_config="$work/gray-docker" gray_images image compose_facts lane_image bridge_url kms_url
  compose_facts="$(docker compose -f "$COMPOSE_FILE" config --format json 2>/dev/null \
      | jq -ec '{images: ([.services | to_entries[] | select(.key != "relay") | .value.image] | unique),
            lane_image: (.services.lane.image // ""), bridge_url: (.services.lane.environment.LANE_BRIDGE_URL // ""),
            kms_url: (.services.lane.environment.LANE_KMS_URL // "")}
          | select((.images | length > 0 and all(type == "string" and test("^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$")))
            and (.lane_image | type == "string") and (.bridge_url | type == "string") and (.kms_url | type == "string"))' 2>/dev/null)" \
    && gray_images="$(jq -er '.images[]' <<<"$compose_facts" 2>/dev/null)" \
    && lane_image="$(jq -r .lane_image <<<"$compose_facts" 2>/dev/null)" \
    && bridge_url="$(jq -r .bridge_url <<<"$compose_facts" 2>/dev/null)" \
    && kms_url="$(jq -r .kms_url <<<"$compose_facts" 2>/dev/null)" \
    && mkdir -m 0700 -- "$gray_config" >/dev/null 2>&1 \
    || { gray_prelaunch_stack_fail "reading Gray's images from the compose"; return 1; }
  if [[ -n "${DSTACK_DOCKER_REGISTRY:-}" && -n "${DSTACK_DOCKER_USERNAME:-}" && -n "${DSTACK_DOCKER_PASSWORD:-}" ]]; then
    printf '%s' "$DSTACK_DOCKER_PASSWORD" \
      | DOCKER_CONFIG="$gray_config" docker login --username "$DSTACK_DOCKER_USERNAME" --password-stdin "$DSTACK_DOCKER_REGISTRY" \
        >/dev/null 2>&1 \
      || { gray_prelaunch_stack_fail "the Gray registry login"; return 1; }
  elif [[ -n "${DSTACK_DOCKER_REGISTRY:-}${DSTACK_DOCKER_USERNAME:-}${DSTACK_DOCKER_PASSWORD:-}" ]]; then
    gray_prelaunch_stack_fail "the Gray registry credential is incomplete"
    return 1
  fi
  while IFS= read -r image; do
    DOCKER_CONFIG="$gray_config" docker pull --quiet "$image" >/dev/null 2>&1 \
      || { gray_prelaunch_stack_fail "pulling Gray's images"; return 1; }
  done <<<"$gray_images"
  rm -rf -- "$gray_config" >/dev/null 2>&1 && [[ ! -e "$gray_config" ]] \
    || { gray_prelaunch_stack_fail "deleting the Gray registry login"; return 1; }
  gray_prelaunch_stack_status "Gray images pulled"

  # Phase 2 (the header's P1-P4): an app whose measured compose names its on-chain KMS has no token service.
  if [[ -n "$kms_url" ]]; then
    gray_prelaunch_stack_phase2 || return 1
    return 0
  fi

  # 4. The one-time key (its SPKI goes into every attempt's report_data below).
  (umask 077 && openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$work/pull.key") >/dev/null 2>&1 \
    && openssl pkey -in "$work/pull.key" -pubout -outform DER -out "$work/pull.spki.der" >/dev/null 2>&1 \
    || { gray_prelaunch_stack_fail "making the pull key"; return 1; }
  local spki_b64
  spki_b64="$(openssl base64 -A -in "$work/pull.spki.der" 2>/dev/null)" && [[ -n "$spki_b64" ]] \
    || { gray_prelaunch_stack_fail "making the pull key"; return 1; }

  # 3b-6, retried (S51a): the relay's token service may not answer yet (a gray-relay started after its VM, a
  # restart of it). While it is unreachable or answers 5xx/429 the exchange starts again from a new challenge (a
  # new nonce, so a new quote), waiting 1 s, then doubling up to 32 s, at most `token_wait` seconds in all; a
  # refusal (any other status) stops the boot at once. Each wait prints one fixed line, the one the provisioner's
  # boot timeline matches in full (branch life/provision): `gray-prelaunch: pull-token service not answering, retrying`.
  # token_wait is 840 s: Gray's watch on a booting CVM is release.mjs's WAITS.running (900 s), and the measured
  # boot spends under 60 s around the exchange (40 s from kernel start to the challenge, 8 s from the token to
  # the seal: deploy/tee/README.md, the real-TDX stack run), so a boot that gets its token at the end of the
  # wait still comes up inside the watch. GRAY_PRELAUNCH_TOKEN_WAIT_SECONDS is a test seam like
  # GRAY_PRELAUNCH_ROOT (not in allowed_envs, so a measured CVM never sets it).
  # S58: an answer that names the token service's refusal code (`{"error": "<code>"}`, the one value read from it)
  # puts the code in the line instead: `pull-token service held the boot (<code>), retrying` for a 5xx or 429 (the
  # relay's to fix, after which the boot goes on), `FAILED: <label> (<code>)` for a refusal. A body without one keeps
  # the lines above.
  local token_wait="${GRAY_PRELAUNCH_TOKEN_WAIT_SECONDS:-840}"
  [[ "$token_wait" =~ ^[0-9]{1,5}$ ]] || { gray_prelaunch_stack_fail "the token wait is not whole seconds"; return 1; }
  local started=$SECONDS delay=1 call answer refusal nonce report_data
  while :; do
    call=0
    answer="$work/challenge.json"
    gray_prelaunch_stack_token_call "$token_url/v1/pull-token/challenge" '{}' "$answer" || call=$?
    if [[ "$call" -eq 0 ]]; then
      nonce="$(jq -er '.nonce | select(type == "string" and test("^([0-9a-f]{2}){16,64}$"))' "$work/challenge.json" 2>/dev/null)" \
        || { gray_prelaunch_stack_fail "the pull-token challenge response"; return 1; }
      gray_prelaunch_stack_status "pull-token challenge received"
      # report_data = SHA-512("gray-relay-pull-token/v1\n" || nonce_hex || "\n" || spki_der).
      report_data="$({ printf 'gray-relay-pull-token/v1\n%s\n' "$nonce" && cat -- "$work/pull.spki.der"; } \
          | openssl dgst -sha512 -binary | od -An -v -tx1 | tr -d ' \n')" \
        && [[ "$report_data" =~ ^[0-9a-f]{128}$ ]] \
        || { gray_prelaunch_stack_fail "computing report_data"; return 1; }
      # 5. The quote of this boot, before the seal; it carries the identity measured above.
      curl --silent --fail --connect-timeout 10 --max-time 30 --max-filesize 16777216 --unix-socket "$dstack_sock" \
          -o "$work/quote.json" "http://dstack/GetQuote?report_data=$report_data" >/dev/null 2>&1 \
        && jq -e '(.quote | type == "string" and length > 0) and (.event_log | type == "string" and length > 0)' \
          "$work/quote.json" >/dev/null 2>&1 \
        || { gray_prelaunch_stack_fail "taking the quote"; return 1; }
      gray_prelaunch_stack_status "quote taken"
      # 6. The token request. app_compose is the exact text of app-compose.json (its SHA-256 is the
      # compose-hash event the token service checks).
      jq -c --arg nonce "$nonce" --arg spki "$spki_b64" --rawfile app_compose "$APP_COMPOSE_FILE" \
          '{nonce: $nonce, spki_der_b64: $spki, quote: .quote, event_log: .event_log, app_compose: $app_compose}' \
          "$work/quote.json" > "$work/request.json" 2>/dev/null \
        || { gray_prelaunch_stack_fail "the pull-token request"; return 1; }
      answer="$work/response.json"
      gray_prelaunch_stack_token_call "$token_url/v1/pull-token" "@$work/request.json" "$answer" || call=$?
      [[ "$call" -eq 0 ]] && break
      if [[ "$call" -eq 2 ]]; then
        if refusal="$(gray_prelaunch_stack_refusal_code "$answer")"; then
          gray_prelaunch_stack_fail "the pull-token request ($refusal)"
        else
          gray_prelaunch_stack_fail "the pull-token request"
        fi
        return 1
      fi
    elif [[ "$call" -eq 2 ]]; then
      if refusal="$(gray_prelaunch_stack_refusal_code "$answer")"; then
        gray_prelaunch_stack_fail "the pull-token challenge request ($refusal)"
      else
        gray_prelaunch_stack_fail "the pull-token challenge request"
      fi
      return 1
    fi
    if (( SECONDS - started + delay > token_wait )); then
      gray_prelaunch_stack_fail "the relay token service did not answer in time"
      return 1
    fi
    if [[ "$call" -eq 3 ]] && refusal="$(gray_prelaunch_stack_refusal_code "$answer")"; then
      gray_prelaunch_stack_status "pull-token service held the boot ($refusal), retrying"
    else
      gray_prelaunch_stack_status "pull-token service not answering, retrying"
    fi
    sleep "$delay" >/dev/null 2>&1 || { gray_prelaunch_stack_fail "waiting for the relay token service"; return 1; }
    delay=$(( delay >= 16 ? 32 : delay * 2 ))
  done

  # 7. The answer is exactly {ciphertext_b64, image, image_sig} (S51). The image is the relay's choice for this
  # boot, in its form; its registry (the text before the first `/`) is the one the envelope logs in to.
  local image image_sig registry
  image="$(jq -er --arg pattern "$image_pattern" \
      'select(type == "object" and (keys == ["ciphertext_b64", "image", "image_sig"]))
        | .image | select(type == "string" and length <= 512 and test($pattern))' "$work/response.json" 2>/dev/null)" \
    && image_sig="$(jq -er '.image_sig | select(type == "string" and test("^[0-9a-f]{128}$"))' "$work/response.json" 2>/dev/null)" \
    && registry="${image%%/*}" \
    && [[ -n "$registry" && "$registry" != "$image" ]] \
    || { gray_prelaunch_stack_fail "the relay image in the pull-token answer"; return 1; }
  # The envelope: RSA-OAEP-SHA256 (MGF1-SHA256, openssl's default for that digest, set explicitly)
  # of {"registry","username","password","expires_at"}, at most 300 bytes, for the image's registry only.
  jq -ej '.ciphertext_b64 | select(type == "string" and length > 0)' "$work/response.json" 2>/dev/null \
      | openssl base64 -d -A -out "$work/envelope.bin" >/dev/null 2>&1 \
    && (umask 077 && openssl pkeyutl -decrypt -inkey "$work/pull.key" -in "$work/envelope.bin" -out "$work/credential.json" \
      -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256) >/dev/null 2>&1 \
    && [[ "$(wc -c < "$work/credential.json")" -le 300 ]] \
    && jq -e --arg registry "$registry" \
      '(keys == ["expires_at", "password", "registry", "username"]) and .registry == $registry
        and (.username | type == "string" and length > 0) and (.password | type == "string" and length > 0)' \
      "$work/credential.json" >/dev/null 2>&1 \
    || { gray_prelaunch_stack_fail "opening the pull-token envelope"; return 1; }
  gray_prelaunch_stack_status "pull token received"
  # S51: the relay's signature on its choice, with the key the identity event measured. Gray, which carries
  # the answer, cannot name another image (or replay an old answer to this boot: the nonce is this boot's).
  { gray_prelaunch_stack_hex_bytes "$ed25519_spki_prefix" && gray_prelaunch_stack_hex_bytes "$relay_key"; } > "$work/relay-key.der" 2>/dev/null \
    && gray_prelaunch_stack_hex_bytes "$image_sig" > "$work/image.sig" 2>/dev/null \
    && [[ "$(wc -c < "$work/relay-key.der")" -eq 44 && "$(wc -c < "$work/image.sig")" -eq 64 ]] \
    && printf 'gray-relay-image/v1\n%s\n%s' "$nonce" "$image" > "$work/image.message" \
    && openssl pkeyutl -verify -pubin -keyform DER -inkey "$work/relay-key.der" -rawin -in "$work/image.message" \
      -sigfile "$work/image.sig" >/dev/null 2>&1 \
    || { gray_prelaunch_stack_fail "the relay image signature"; return 1; }
  gray_prelaunch_stack_status "relay image signature verified"

  # 8. docker login into a DOCKER_CONFIG of its own on tmpfs (never exported), then the relay's image by its
  # digest. An image whose config declares a VOLUME is refused: docker would mount it as a writable
  # anonymous volume despite read_only, outside the tmpfs size limits, and the compose gate cannot see
  # image config. Then the credential goes: `docker compose up` finds every image locally (compose pulls
  # only what is missing) and needs no login.
  local username relay_config="$work/docker"
  username="$(jq -r .username "$work/credential.json" 2>/dev/null)" \
    && mkdir -m 0700 -- "$relay_config" >/dev/null 2>&1 \
    || { gray_prelaunch_stack_fail "the registry login"; return 1; }
  jq -j .password "$work/credential.json" 2>/dev/null \
      | DOCKER_CONFIG="$relay_config" docker login --username "$username" --password-stdin "$registry" >/dev/null 2>&1 \
    || { gray_prelaunch_stack_fail "the registry login"; return 1; }
  gray_prelaunch_stack_status "registry login done"
  DOCKER_CONFIG="$relay_config" docker pull --quiet "$image" >/dev/null 2>&1 \
    || { gray_prelaunch_stack_fail "pulling the relay image"; return 1; }
  gray_prelaunch_stack_status "relay image pulled"
  docker image inspect -- "$image" 2>/dev/null \
      | jq -e 'length == 1 and ((.[0].Config.Volumes // {}) | type == "object" and length == 0)' >/dev/null 2>&1 \
    || { gray_prelaunch_stack_fail "the relay image declares a volume"; return 1; }
  gray_prelaunch_stack_status "relay image declares no volume"
  # S50: into the slot the compose runs; the slot must then be exactly the image pulled by its digest.
  local pulled_id slot_id
  docker tag "$image" "$slot" >/dev/null 2>&1 \
    && pulled_id="$(docker image inspect --format '{{.Id}}' -- "$image" 2>/dev/null)" \
    && slot_id="$(docker image inspect --format '{{.Id}}' -- "$slot" 2>/dev/null)" \
    && [[ "$pulled_id" =~ ^sha256:[0-9a-f]{64}$ && "$slot_id" == "$pulled_id" ]] \
    || { gray_prelaunch_stack_fail "tagging the relay image into its slot"; return 1; }
  gray_prelaunch_stack_status "relay image in its slot"
  rm -rf -- "$relay_config" "$work/credential.json" >/dev/null 2>&1 && [[ ! -e "$relay_config" && ! -e "$work/credential.json" ]] \
    || { gray_prelaunch_stack_fail "deleting the registry credential"; return 1; }
  gray_prelaunch_stack_status "registry credential deleted"

  # 9. The image this boot runs (S52): the relay, the image, this boot's nonce and the relay's signature, which a
  # customer checks with the identity's key; then the seal, then nothing of this boot's pull is left.
  jq -ncSj --arg image "$image" --arg image_sig "$image_sig" --arg nonce "$nonce" --arg relay_id "$relay_id" \
      '{image: $image, image_sig: $image_sig, nonce: $nonce, relay_id: $relay_id}' > "$work/image.payload" 2>/dev/null \
    && gray_prelaunch_stack_extend gray-relay-image "$work/image.payload" \
    || { gray_prelaunch_stack_fail "measuring the relay image"; return 1; }
  gray_prelaunch_stack_status "relay image measured"
  dstack-util extend --event gray-prelaunch-sealed --payload "$seal_payload" >/dev/null 2>&1 \
    || { gray_prelaunch_stack_fail "sealing pre-launch"; return 1; }
  rm -rf -- "$work" >/dev/null 2>&1 && [[ ! -e "$work" ]] \
    || { gray_prelaunch_stack_fail "deleting the pull key"; return 1; }
  gray_prelaunch_stack_status "sealed"
}

gray_prelaunch_stack
