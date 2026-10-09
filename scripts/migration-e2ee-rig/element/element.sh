#!/usr/bin/env bash
# Fresh Element Web login + recovery key against a rig homeserver.
#
#   element.sh <dark-spindle|dark-synapse> <a|b|c>
#
# Runs on the workstation. It port-forwards the service to 127.0.0.1:8008
# and serves a pinned Element Web on 127.0.0.1:18009. Chromium maps
# *.spindle-rehearsal.svc.cluster.local to 127.0.0.1, because both servers
# advertise their in-cluster public base URL and Element switches to it
# after login, and every other origin is blocked. Secrets come from
# secret/spindle-mig-rig through the environment and are never printed.
#
# Environment: NODE_PATH (where require('playwright') resolves; its chromium
# must be installed), OUT_DIR (default ${TMPDIR:-/tmp}/mig-rig-element).
set -uo pipefail
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config-aws-migration}"
NS="${NS:-spindle-rehearsal}"
here="$(cd "$(dirname "$0")" && pwd)"
svc="${1:?service}"; u="${2:?user}"
ELEMENT_TAG=v1.12.28
ELEMENT_SHA256=45319cf2e89d685f4a5bcab1c9afca3f8315dedc962801ecc12490fd23cb2546
cache="${TMPDIR:-/tmp}/mig-rig-element-web"
out="${OUT_DIR:-${TMPDIR:-/tmp}/mig-rig-element}/$svc-$u-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$cache" "$out"

tarball="$cache/element-$ELEMENT_TAG.tar.gz"
web="$cache/element-$ELEMENT_TAG"
[[ -f $tarball ]] || curl -sSfL --retry 3 -o "$tarball" \
  "https://github.com/element-hq/element-web/releases/download/$ELEMENT_TAG/element-$ELEMENT_TAG.tar.gz"
echo "$ELEMENT_SHA256  $tarball" | sha256sum -c --quiet || exit 1
[[ -f $web/config.sample.json ]] || tar -xzf "$tarball" -C "$cache"
python3 "$here/mkconfig.py" "$web" http://127.0.0.1:8008 >/dev/null

kubectl -n "$NS" get configmap spindle-mig-rig-manifest -o jsonpath='{.data.manifest\.json}' >"$out/manifest.json"
kubectl -n "$NS" port-forward --address 127.0.0.1 "svc/$svc" 8008:8008 >"$out/port-forward.log" 2>&1 &
pf=$!
(cd "$web" && exec python3 -m http.server --bind 127.0.0.1 18009) >"$out/web.log" 2>&1 &
static=$!
trap 'kill $pf $static 2>/dev/null' EXIT
for _ in $(seq 1 50); do
  curl -sf -o /dev/null http://127.0.0.1:8008/_matrix/client/versions &&
    curl -sf -o /dev/null http://127.0.0.1:18009/config.json && break
  sleep 0.3
done

RIG_PASSWORD="$(kubectl -n "$NS" get secret spindle-mig-rig -o jsonpath="{.data.password-$u}" | base64 -d)"
RIG_RECOVERY_KEY="$(kubectl -n "$NS" get secret spindle-mig-rig -o jsonpath="{.data.recovery-key-$u}" | base64 -d)"
export RIG_PASSWORD RIG_RECOVERY_KEY
WEB_URL=http://127.0.0.1:18009 RIG_USER="$u" MANIFEST="$out/manifest.json" OUT_DIR="$out" \
  node "$here/recover.cjs"
rc=$?
echo "report: $out/element-$u.json"
exit $rc
