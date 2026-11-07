#!/bin/bash
# deploy/tee/pre-launch.sh — the measured pre_launch_script of the gray-lane app-compose (D44).
#
# dstack sources this file under `set -euo pipefail` from app-compose.sh before `docker compose up`
# (dstack-src os/common/rootfs/app-compose.service:12-14, app-compose.sh:157-163), with the
# decrypted, allowed_envs-filtered environment passed by `dstack-util exec-with-env`.
#
# Its only job is to authenticate dockerd to the private registry that holds the gray-lane image.
# The three DSTACK_DOCKER_* names are in app-compose's allowed_envs (D44); no compose service may
# reference them (app-compose.mjs asserts that). The password goes to `docker login` on stdin and
# is never echoed. When any of the three is unset the login is skipped: a public image needs none.
#
# D104: /root is read-only on dstack 0.6.1, so docker cannot create /root/.docker. Put its
# credentials in a fresh 0700 directory on tmpfs instead, and export DOCKER_CONFIG before the login
# (dstack sources this file, so the export reaches the `docker compose` pull that follows).
# GRAY_PRELAUNCH_RUN_ROOT is a test seam only: it defaults to /run, is not in allowed_envs, and the
# measured CVM never sets it.
set -euo pipefail

if [[ -n "${DSTACK_DOCKER_REGISTRY:-}" && -n "${DSTACK_DOCKER_USERNAME:-}" && -n "${DSTACK_DOCKER_PASSWORD:-}" ]]; then
  gray_prelaunch_run_root="${GRAY_PRELAUNCH_RUN_ROOT:-/run}"
  DOCKER_CONFIG="$(mktemp -d "${gray_prelaunch_run_root}/gray-docker.XXXXXX")"
  export DOCKER_CONFIG
  printf '%s' "$DSTACK_DOCKER_PASSWORD" | docker login --username "$DSTACK_DOCKER_USERNAME" --password-stdin "$DSTACK_DOCKER_REGISTRY"
fi
