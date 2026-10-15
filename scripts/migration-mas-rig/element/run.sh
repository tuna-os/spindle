#!/usr/bin/env bash
# Element Web login through the dark MAS against the dark Spindle, then
# recovery-key restore and decryption of the rig manifest.  run.sh <a|b|c>
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
u="${1:-a}"
export KUBECONFIG=$HOME/.kube/config-aws-migration
NS=spindle-rehearsal
out="$here/out/$u-$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$out"
kubectl -n $NS get configmap spindle-mig-rig-manifest -o json | jq -r '.data["manifest.json"]' > "$out/manifest.json"
RIG_PASSWORD="$(kubectl -n $NS get secret spindle-mig-rig -o json | jq -r ".data[\"password-$u\"]" | base64 -d)"
RIG_RECOVERY_KEY="$(kubectl -n $NS get secret spindle-mig-rig -o json | jq -r ".data[\"recovery-key-$u\"]" | base64 -d)"
export RIG_PASSWORD RIG_RECOVERY_KEY
# Give the rig user the same password in the dark MAS (admin API).
RIG_USER_LOCALPART="spindle-mig-$u" python3 "$here/set_pw.py" || exit 1
ELEMENT_TAG=v1.12.28
ELEMENT_SHA256=45319cf2e89d685f4a5bcab1c9afca3f8315dedc962801ecc12490fd23cb2546
web="$here/element-$ELEMENT_TAG"
if [[ ! -f $web/config.json ]]; then
  curl -sSfL --retry 3 -o "$here/element.tar.gz" "https://github.com/element-hq/element-web/releases/download/$ELEMENT_TAG/element-$ELEMENT_TAG.tar.gz"
  echo "$ELEMENT_SHA256  $here/element.tar.gz" | sha256sum -c --quiet || exit 1
  tar -xzf "$here/element.tar.gz" -C "$here"
  python3 "$here/mkconfig.py" "$web" http://127.0.0.1:18008 >/dev/null
fi
(cd "$web" && exec python3 -m http.server --bind 127.0.0.1 18009) > "$out/web.log" 2>&1 &
static=$!
trap 'kill $static 2>/dev/null' EXIT
sleep 1
NODE_PATH="${NODE_PATH:?where require(playwright) resolves}" WEB_URL=http://127.0.0.1:18009 RIG_USER="$u" \
  MANIFEST="$out/manifest.json" OUT_DIR="$out" node "$here/recover-mas.cjs"
rc=$?
echo "out: $out rc=$rc"
exit $rc
