#!/bin/sh
# Build the e2e image and run the two-layer cases in a throwaway container.
# Usage: e2e/run.sh [agent_e2e.py options, e.g. --agents claude --cases mcp_use]
# Model endpoints and keys come from e2e/.env (git-ignored, never copied into the image); see e2e/env.example.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
env_file=${SG_E2E_ENV:-$here/.env}
out=${SG_E2E_OUT:-$here/out}
image=${SG_E2E_IMAGE:-secret-guard-e2e:local}
[ -f "$env_file" ] || { echo "Missing $env_file; copy e2e/env.example and fill it in." >&2; exit 2; }

docker build -q -f "$here/Dockerfile" -t "$image" "$here/.." >/dev/null
name=secret-guard-e2e-$$
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
status=0
# host.docker.internal lets a model endpoint on the host (e.g. a local gateway) be reached on Linux too.
# seccomp=unconfined: Codex's Linux sandbox (bubblewrap) needs user namespaces, which Docker's default profile refuses.
docker run --name "$name" --env-file "$env_file" --add-host host.docker.internal:host-gateway \
  --security-opt seccomp=unconfined \
  "$image" --out /home/agent/out "$@" >/dev/null || status=$?
rm -rf "$out"
docker cp -q "$name:/home/agent/out" "$out" 2>/dev/null || echo "No report produced." >&2
[ -f "$out/report.json" ] && cat "$out/report.json"
exit "$status"
