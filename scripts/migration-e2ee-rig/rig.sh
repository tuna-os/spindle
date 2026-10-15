#!/usr/bin/env bash
# Driver for the Synapse -> Spindle E2EE migration rig. See README.md.
#
#   rig.sh secrets              create dark-synapse-secrets + spindle-mig-rig (idempotent)
#   rig.sh dark-db              create synapse_dark from the pristine `synapse` restore
#   rig.sh deploy               render + apply the dark Synapse, wait until ready
#   rig.sh isolation [MINUTES]  effective-config dump, log scan, netwatch summary
#   rig.sh toolbox              apply the build/run pod and its PVC
#   rig.sh build                copy rig/ into the toolbox and cargo build --release
#   rig.sh seed                 create users, rooms, history; store keys + manifest
#   rig.sh store-manifest       (re)publish the manifest ConfigMap from the PVC
#   rig.sh verify [HS_URL] [USER]   fresh-device recovery + per-event decrypt report
#   rig.sh spindle-build [REF]  build spindle (synapse-import) from a git ref in the toolbox
#   rig.sh spindle-import       import all manifest rooms + users a,b,c into the dark Spindle
#   rig.sh spindle-isolation    dark Spindle switches, resolver, exposure, netwatch summary
#   rig.sh element SVC USER     fresh Element Web login + recovery key (workstation)
#   rig.sh reset                delete dark Synapse, drop synapse_dark, clear rig state
#
# Environment: KUBECONFIG (default ~/.kube/config-aws-migration), NS
# (default spindle-rehearsal). Secrets are moved with kubectl pipes and
# never printed.
set -euo pipefail

export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config-aws-migration}"
NS="${NS:-spindle-rehearsal}"
here="$(cd "$(dirname "$0")" && pwd)"
k() { kubectl -n "$NS" "$@"; }
tb() { k exec -i mig-rig-toolbox -c toolbox -- "$@"; }
tbo() { k exec mig-rig-toolbox -c toolbox -- "$@" </dev/null; }
psql_pg() { k exec -i deploy/rehearsal-pg -- psql -U postgres -v ON_ERROR_STOP=1 -At "$@"; }
# Large exec streams through this API server are sometimes reset mid-copy;
# fetch a JSON file from the PVC with retries and validate it.
tb_json() {
  local out i
  for i in 1 2 3 4 5; do
    if out="$(tbo cat "$1")" && python3 -c 'import json,sys; json.loads(sys.stdin.read())' <<<"$out" 2>/dev/null; then
      printf '%s\n' "$out"; return 0
    fi
    sleep 2
  done
  echo "could not fetch $1" >&2; return 1
}
rand() { head -c 48 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

cmd_secrets() {
  if ! k get secret dark-synapse-secrets >/dev/null 2>&1; then
    local d; d="$(mktemp -d)"; chmod 700 "$d"
    # Production signing key, read-only from ess/ess-synapse. Same server
    # name + key is the point of the rig, and the reason it is isolated.
    kubectl -n ess get secret ess-synapse -o jsonpath='{.data.SIGNING_KEY}' | base64 -d >"$d/signing.key"
    [[ -s $d/signing.key ]] || { echo "could not read the signing key" >&2; rm -rf "$d"; exit 1; }
    rand >"$d/registration_shared_secret"
    {
      echo "registration_shared_secret: \"$(cat "$d/registration_shared_secret")\""
      echo "macaroon_secret_key: \"$(rand)\""
      echo "form_secret: \"$(rand)\""
    } >"$d/secrets.yaml"
    k create secret generic dark-synapse-secrets \
      --from-file=signing.key="$d/signing.key" \
      --from-file=registration_shared_secret="$d/registration_shared_secret" \
      --from-file=secrets.yaml="$d/secrets.yaml" >/dev/null
    k label secret dark-synapse-secrets part-of=spindle-mig-rig >/dev/null
    rm -rf "$d"
    echo "created secret dark-synapse-secrets"
  fi
  if ! k get secret spindle-mig-rig >/dev/null 2>&1; then
    k create secret generic spindle-mig-rig \
      --from-literal=password-a="$(rand)" \
      --from-literal=password-b="$(rand)" \
      --from-literal=password-c="$(rand)" >/dev/null
    k label secret spindle-mig-rig part-of=spindle-mig-rig >/dev/null
    echo "created secret spindle-mig-rig (passwords; recovery keys are added by seed)"
  fi
}

cmd_dark_db() {
  if [[ -n $(pgrep_restore) ]]; then echo "pg_restore still running" >&2; exit 1; fi
  if [[ $(psql_pg -c "select 1 from pg_database where datname='synapse_dark'") == 1 ]]; then
    echo "synapse_dark already exists"; return
  fi
  psql_pg -c "CREATE DATABASE synapse_dark TEMPLATE synapse STRATEGY FILE_COPY"
  echo "created synapse_dark"
}
pgrep_restore() { k exec deploy/rehearsal-pg -- sh -c 'ps -eo comm | grep -x pg_restore || true'; }

cmd_deploy() {
  local ip; ip="$(k get svc rehearsal-pg -o jsonpath='{.spec.clusterIP}')"
  sed "s/__PG_IP__/$ip/g" "$here/k8s/dark-synapse.yaml" | k apply -f -
  k rollout status deploy/dark-synapse --timeout=15m
}

cmd_isolation() {
  local minutes="${1:-0}"
  local pod; pod="$(k get pod -l app=dark-synapse -o jsonpath='{.items[0].metadata.name}')"
  echo "== effective configuration as Synapse parses it"
  k exec -i "$pod" -c synapse -- python3 - <<'PY'
from synapse.config.homeserver import HomeServerConfig
c = HomeServerConfig.load_config("", ["-c", "/conf/homeserver.yaml", "-c", "/secrets/secrets.yaml"])
w = c.worker
print("server_name                 ", c.server.server_name)
print("send_federation (this proc) ", w.send_federation)
print("federation_sender_instances ", w.federation_shard_config.instances)
print("start_pushers (this proc)   ", getattr(w, "start_pushers", None))
print("pusher_instances            ", w.pusher_shard_config.instances)
print("federation_domain_whitelist ", c.federation.federation_domain_whitelist)
print("trusted_key_servers         ", [s.server_name for s in c.key.key_servers])
print("ip_range_blocklist          ", sorted(str(n) for n in c.server.ip_range_blocklist.iter_cidrs()))
print("url_preview_enabled         ", c.media.url_preview_enabled)
print("push.enabled                ", c.push.enable_push)
print("email notifs / identity     ", c.email.email_enable_notifs, getattr(c.registration, "default_identity_server", None))
print("app_service_config_files    ", c.appservice.app_service_config_files)
print("msc3861 / MAS               ", c.experimental.msc3861.enabled, getattr(getattr(c, "mas", None), "enabled", None))
print("redis                       ", c.redis.redis_enabled)
print("listeners                   ", [(l.port, [r.names for r in l.http_options.resources]) for l in c.server.listeners])
PY
  echo "== resolver in the pod"
  k exec "$pod" -c synapse -- cat /etc/resolv.conf
  echo "== services / ingresses exposing it"
  k get svc,ingress -l part-of=spindle-mig-rig -o wide 2>/dev/null || true
  if (( minutes > 0 )); then echo "== observing for $minutes min"; sleep $((minutes * 60)); fi
  echo "== synapse log lines mentioning outbound activity (since pod start)"
  k logs "$pod" -c synapse | grep -Ei 'matrixfederationclient|federation denied|sending request|outbound|keyring|fetching keys|pusher|push gateway|http_client|connection refused|dns|lookup' | grep -v 'Sending request.*GET /health' | tail -n 50 || echo "(none)"
  echo "== netwatch (sockets other than loopback/database/inbound client)"
  k logs "$pod" -c netwatch | grep -E '"OUTBOUND"|heartbeat' | tail -n 5
  local n; n="$(k logs "$pod" -c netwatch | grep -c '"new": "OUTBOUND"' || true)"
  echo "outbound endpoints seen: ${n:-0}"
}

cmd_toolbox() {
  k apply -f "$here/k8s/toolbox.yaml"
  k wait --for=condition=Ready pod/mig-rig-toolbox --timeout=10m
}

cmd_build() {
  tb mkdir -p /work/src /work/bin
  tar -C "$here/rig" -cf - Cargo.toml src $( [[ -f $here/rig/Cargo.lock ]] && echo Cargo.lock ) | tb tar -C /work/src -xf -
  tb bash -c 'cd /work/src && cargo build --release 2>&1 | tail -n 40 && cp /work/target/release/mig-rig /work/bin/mig-rig'
}

cmd_seed() {
  if k get secret spindle-mig-rig -o jsonpath='{.data.recovery-key-a}' | grep -q .; then
    echo "spindle-mig-rig already holds recovery keys: run 'rig.sh reset' first" >&2; exit 1
  fi
  # Secret volumes lag API updates by up to a minute, so the inputs are
  # piped from the API into a private dir on the PVC and removed afterwards.
  tb bash -c 'rm -rf /work/out && mkdir -p /work/out/in && chmod 700 /work/out/in'
  for u in a b c; do
    k get secret spindle-mig-rig -o jsonpath="{.data.password-$u}" | base64 -d | tb bash -c "umask 077; cat >/work/out/in/password-$u"
  done
  k get secret dark-synapse-secrets -o jsonpath='{.data.registration_shared_secret}' | base64 -d | tb bash -c 'umask 077; cat >/work/out/in/registration_shared_secret'
  local rc=0
  tb bash -c '/work/bin/mig-rig seed \
      --homeserver "$RIG_HOMESERVER" --server-name reilly.asia \
      --registration-secret-file /work/out/in/registration_shared_secret \
      --secrets-dir /work/out/in --out /work/out' || rc=$?
  tb rm -rf /work/out/in
  (( rc == 0 )) || { tb rm -f /work/out/credentials.json; echo "seed failed (rc=$rc); run 'rig.sh reset' before retrying" >&2; exit "$rc"; }
  # Recovery keys: PVC -> Secret, through a pipe, then off the PVC.
  local args=()
  for u in a b c; do
    args+=(--from-literal="recovery-key-$u=$(tb_json /work/out/credentials.json | python3 -c "import json,sys;print(json.load(sys.stdin)['recovery-key-$u'])")")
    args+=(--from-literal="password-$u=$(k get secret spindle-mig-rig -o jsonpath="{.data.password-$u}" | base64 -d)")
  done
  k create secret generic spindle-mig-rig "${args[@]}" --dry-run=client -o yaml | k apply -f - >/dev/null
  k label --overwrite secret spindle-mig-rig part-of=spindle-mig-rig >/dev/null
  tb rm -f /work/out/credentials.json
  cmd_store_manifest
}

# Re-runnable on its own if the API connection drops after the keys are stored.
cmd_store_manifest() {
  tb_json /work/out/manifest.json >"${TMPDIR:-/tmp}/mig-rig-manifest.json"
  k create configmap spindle-mig-rig-manifest \
    --from-file=manifest.json="${TMPDIR:-/tmp}/mig-rig-manifest.json" \
    --from-literal=seed-summary.json="$(tb_json /work/out/seed-summary.json)" \
    --dry-run=client -o yaml | k apply -f - >/dev/null
  k label --overwrite configmap spindle-mig-rig-manifest part-of=spindle-mig-rig >/dev/null
  rm -f "${TMPDIR:-/tmp}/mig-rig-manifest.json"
  echo "stored recovery keys in secret/spindle-mig-rig and manifest in configmap/spindle-mig-rig-manifest"
}

cmd_verify() {
  local hs="${1:-http://dark-synapse.spindle-rehearsal.svc.cluster.local:8008}" user="${2:-a}"
  k get configmap spindle-mig-rig-manifest -o jsonpath='{.data.manifest\.json}' | tb bash -c 'mkdir -p /work/verify && cat >/work/verify/manifest.json'
  local report="/work/verify/report-$user-$(date -u +%Y%m%dT%H%M%SZ).json"
  # Secret volume updates take up to a minute; read keys from the API instead.
  local pw rk
  pw="$(k get secret spindle-mig-rig -o jsonpath="{.data.password-$user}" | base64 -d)"
  rk="$(k get secret spindle-mig-rig -o jsonpath="{.data.recovery-key-$user}" | base64 -d)"
  local rc=0
  printf '%s\n%s\n' "$pw" "$rk" | tb bash -c "read -r RIG_PASSWORD; read -r RIG_RECOVERY_KEY; export RIG_PASSWORD RIG_RECOVERY_KEY; \
    /work/bin/mig-rig verify --homeserver '$hs' --user '$user' --manifest /work/verify/manifest.json --report '$report' >/dev/null" || rc=$?
  tb_json "$report"
  return $rc
}

# --- the dark Spindle --------------------------------------------------------

# Build `spindle` (with the synapse-import feature) in the toolbox from a git
# ref of this repository, into /work/bin/spindle on the PVC.
cmd_spindle_build() {
  local ref="${1:-HEAD}"
  tb bash -c 'mkdir -p /work/spindle-src /work/bin && find /work/spindle-src -mindepth 1 -maxdepth 1 -exec rm -rf {} +'
  git -C "$(git -C "$here" rev-parse --show-toplevel)" archive --format=tar "$ref" | tb tar -C /work/spindle-src -xf -
  tb bash -c 'cd /work/spindle-src && CARGO_TARGET_DIR=/work/spindle-target \
    cargo build --release -p spindle-server --features synapse-import --bin spindle 2>&1 | tail -n 5 &&
    cp /work/spindle-target/release/spindle /work/bin/spindle.new && mv /work/bin/spindle.new /work/bin/spindle'
}

# Import every manifest room and users a, b, c from synapse_dark into an
# empty store, then (re)start the dark Spindle on it.
cmd_spindle_import() {
  local ip rooms
  ip="$(k get svc rehearsal-pg -o jsonpath='{.spec.clusterIP}')"
  rooms="$(k get configmap spindle-mig-rig-manifest -o jsonpath='{.data.manifest\.json}' |
    python3 -c 'import json,sys; print(",".join(r["room_id"] for r in json.load(sys.stdin)["rooms"]))')"
  k scale deploy/dark-spindle --replicas=0 >/dev/null 2>&1 || true
  k delete job dark-spindle-import --ignore-not-found --wait >/dev/null
  tb bash -c 'rm -rf /work/dark-spindle/store && mkdir -p /work/dark-spindle && chown 10092:10092 /work/dark-spindle'
  sed -e "s/__PG_IP__/$ip/g" -e "s/__ROOMS__/$rooms/g" "$here/k8s/dark-spindle.yaml" | k apply -f - >/dev/null
  k scale deploy/dark-spindle --replicas=0 >/dev/null
  if ! k wait --for=condition=complete job/dark-spindle-import --timeout=10m; then
    k logs job/dark-spindle-import; exit 1
  fi
  k logs job/dark-spindle-import
  k scale deploy/dark-spindle --replicas=1 >/dev/null
  k rollout status deploy/dark-spindle --timeout=5m
}

cmd_spindle_isolation() {
  local pod; pod="$(k get pod -l app=dark-spindle -o jsonpath='{.items[0].metadata.name}')"
  echo "== [federation] and outbound switches as configured"
  k get configmap dark-spindle-config -o jsonpath='{.data.spindle\.toml}' | grep -A1 -E '^\[(federation|push|previews)\]'
  echo "== resolver in the pod"
  k exec "$pod" -c spindle -- cat /etc/resolv.conf
  echo "== services / ingresses exposing it"
  k get svc,ingress -l app=dark-spindle -o wide 2>/dev/null || true
  echo "== server-server API from inside the namespace (expect 404 M_UNRECOGNIZED)"
  for p in /_matrix/key/v2/server /_matrix/federation/v1/version; do
    tbo curl -s -o /dev/null -w "$p %{http_code}\n" "http://dark-spindle.$NS.svc.cluster.local:8008$p"
  done
  echo "== netwatch (sockets other than loopback/database/inbound client)"
  k logs "$pod" -c netwatch | grep -E '"OUTBOUND"|heartbeat' | tail -n 3
  local n; n="$(k logs "$pod" -c netwatch | grep -c '"new": "OUTBOUND"' || true)"
  echo "outbound endpoints seen: ${n:-0}"
}

cmd_reset() {
  k delete deploy/dark-synapse --ignore-not-found --wait
  psql_pg -c "DROP DATABASE IF EXISTS synapse_dark"
  k delete configmap spindle-mig-rig-manifest --ignore-not-found
  k delete secret spindle-mig-rig --ignore-not-found
  k get pod mig-rig-toolbox >/dev/null 2>&1 && tb rm -rf /work/out /work/verify || true
  echo "reset done: run secrets, dark-db, deploy, seed again"
}

case "${1:-}" in
  secrets) cmd_secrets ;;
  dark-db) cmd_dark_db ;;
  deploy) cmd_deploy ;;
  isolation) shift; cmd_isolation "$@" ;;
  toolbox) cmd_toolbox ;;
  build) cmd_build ;;
  seed) cmd_seed ;;
  store-manifest) cmd_store_manifest ;;
  verify) shift; cmd_verify "$@" ;;
  spindle-build) shift; cmd_spindle_build "$@" ;;
  spindle-import) cmd_spindle_import ;;
  spindle-isolation) cmd_spindle_isolation ;;
  element) shift; "$here/element/element.sh" "$@" ;;
  reset) cmd_reset ;;
  *) sed -n '2,19p' "$0"; exit 2 ;;
esac
