#!/usr/bin/env bash
# Driver for the federation drill (docs/synapse-migration-drill.md) in the
# spindle-rehearsal namespace. See scripts/federation-drill/README.md.
#
#   drill.sh tls DIR            make the private CA and certs in DIR (local)
#   drill.sh secrets DIR        load TLS from DIR, make the A key/secrets,
#                               copy the production key for B
#   drill.sh db                 create drill_a and drill_b (empty)
#   drill.sh resolver           deploy the private resolver
#   drill.sh client             deploy (or refresh drill.py in) the client pod
#   drill.sh up-a               deploy Synapse A (the witness)
#   drill.sh up-b-synapse       deploy Synapse B
#   drill.sh partition on|off   503 federation at both fronts (contested fork)
#   drill.sh seal               stop Synapse B after its queue drains, back up
#   drill.sh import ROOMS USERS run the importer into Spindle B's store
#   drill.sh verify-import     verify the full import against expected fixture IDs
#   drill.sh up-b-spindle       deploy Spindle B in drill-b's place
#   drill.sh rollback           stop Spindle B, restore the seal, start Synapse B
#                               (SPINDLE_IMAGE / SPINDLE_BIN pick the build)
#   drill.sh extremities [DB]   forward extremities and event counts per room
#   drill.sh netwatch           print the OUTBOUND count from every netwatch
#   drill.sh teardown           delete every drill object and database
set -euo pipefail
NS=spindle-rehearsal
export KUBECONFIG=${KUBECONFIG:-$HOME/.kube/config-aws-migration}
HERE=$(cd "$(dirname "$0")" && pwd)
K="kubectl -n $NS"
A_IP=10.111.63.11
B_IP=10.111.63.12

pg_ip() { $K get svc rehearsal-pg -o jsonpath='{.spec.clusterIP}'; }
psql_() { $K exec -i deploy/rehearsal-pg -- psql -U postgres -v ON_ERROR_STOP=1 -At "$@"; }

render_synapse_conf() { # app server fed_host db peer_name peer_ip
  sed -e "s/__SERVER_NAME__/$2/g" -e "s/__FED_HOST__/$3/g" -e "s/__DB__/$4/g" \
      -e "s/__PEER_NAME__/$5/g" -e "s/__PEER_IP__/$6/g" "$HERE/synapse.yaml.template" > "$tmp/homeserver.yaml"
  $K create configmap "$1-config" --from-file=homeserver.yaml="$tmp/homeserver.yaml" \
     --from-file=log_config.yaml="$HERE/log_config.yaml" --dry-run=client -o yaml | $K apply -f -
}

render_deploy() { # template app server fed_host peer_ip data
  sed -e "s/__APP__/$2/g" -e "s/__SERVER_NAME__/$3/g" -e "s/__FED_HOST__/$4/g" \
      -e "s/__PEER_IP__/$5/g" -e "s/__PG_IP__/$(pg_ip)/g" -e "s|__DATA__|$6|g" \
      -e "s|__SPINDLE_IMAGE__|$SPINDLE_IMAGE|g" -e "s|__SPINDLE_BIN__|$SPINDLE_BIN|g" \
      -e "s|__ROOMS__|${ROOMS:-}|g" -e "s|__USERS__|${USERS:-}|g" "$HERE/k8s/$1"
}

# Spindle B: the rehearsal image from #557, or a binary built in the
# toolbox (SPINDLE_BIN=/work/drill/bin/spindle) run inside that image.
SPINDLE_IMAGE=${SPINDLE_IMAGE:-ghcr.io/tuna-os/spindle:rehearsal-35848ed}
SPINDLE_BIN=${SPINDLE_BIN:-/usr/local/bin/spindle}

# A throwaway pod on drill-b's node with the drill-b-data PVC at /d.
on_data() {
  $K delete pod drill-b-data-op --ignore-not-found --wait >/dev/null
  $K run drill-b-data-op --rm -i --restart=Never --image=busybox:1.36 \
    --overrides='{"spec":{"nodeSelector":{"kubernetes.io/hostname":"ip-10-20-1-11"},"automountServiceAccountToken":false,"securityContext":{"runAsUser":10093,"runAsGroup":10093,"fsGroup":10093},"volumes":[{"name":"d","persistentVolumeClaim":{"claimName":"drill-b-data"}},{"name":"s","secret":{"secretName":"drill-b-secrets"}}],"containers":[{"name":"op","image":"busybox:1.36","command":["sh","-c","'"$1"'"],"volumeMounts":[{"name":"d","mountPath":"/d"},{"name":"s","mountPath":"/s"}]}]}}'
}

front_cm() {
  $K create configmap drill-front --from-file=front.conf.template="$HERE/front.conf.template" \
     --from-file=netwatch.py="$HERE/netwatch.py" --dry-run=client -o yaml | $K apply -f -
}

# Read only the completed import report, in a disposable pod on the PVC's node.
# The proof image is independent of the server's runtime image.
verify_import() {
  ROOMS=$($K get cm drill-b-spindle-config -o jsonpath='{.data.expected-rooms}')
  USERS=$($K get cm drill-b-spindle-config -o jsonpath='{.data.expected-users}')
  [ -n "$ROOMS" ] && [ -n "$USERS" ] || { echo 'missing expected fixture IDs' >&2; return 1; }
  $K create configmap drill-import-proof --from-file=verify-import.py="$HERE/verify-import.py" \
    --dry-run=client -o yaml | $K apply -f -
  $K delete pod drill-import-proof --ignore-not-found --wait >/dev/null
  proof_pod=$(python3 - "$ROOMS" "$USERS" <<'PY'
import json,sys
print(json.dumps({'metadata':{'labels':{'part-of':'federation-drill'}},'spec':{
 'nodeSelector':{'kubernetes.io/hostname':'ip-10-20-1-11'},
 'automountServiceAccountToken':False,'enableServiceLinks':False,
 'dnsPolicy':'None','dnsConfig':{'nameservers':['127.0.0.1'],'searches':[]},
 'securityContext':{'runAsUser':10093,'runAsGroup':10093,'runAsNonRoot':True,
                    'seccompProfile':{'type':'RuntimeDefault'}},
 'containers':[{'name':'drill-import-proof','image':'python:3.12-slim',
   'command':['python3','/verify/verify-import.py','/data/spindle/report.json',*sys.argv[1:]],
   'resources':{'requests':{'cpu':'10m','memory':'32Mi'},'limits':{'cpu':'1','memory':'128Mi'}},
   'securityContext':{'allowPrivilegeEscalation':False,'capabilities':{'drop':['ALL']}},
   'volumeMounts':[{'name':'data','mountPath':'/data','readOnly':True},
                  {'name':'verify','mountPath':'/verify','readOnly':True}]}],
 'volumes':[{'name':'data','persistentVolumeClaim':{'claimName':'drill-b-data','readOnly':True}},
            {'name':'verify','configMap':{'name':'drill-import-proof'}}]}}))
PY
  )
  $K run drill-import-proof --rm -i --restart=Never --image=python:3.12-slim \
    --overrides="$proof_pod"
}

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

case "${1:-}" in
tls)
  out=$2; mkdir -p "$out"; cd "$out"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
    -subj "/CN=spindle federation drill private CA" -keyout ca.key -out ca.crt \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  for pair in "witness witness.lab matrix.witness.lab" "reilly reilly.asia matrix.reilly.asia"; do
    read -r -a cert_args <<< "$pair"
    set -- "${cert_args[@]}"
    openssl req -newkey rsa:2048 -nodes -subj "/CN=$2" -keyout "$1.key" -out "$1.csr" 2>/dev/null
    printf 'subjectAltName=DNS:%s,DNS:%s\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' "$2" "$3" > "$1.ext"
    openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 30 -extfile "$1.ext" -out "$1.crt" 2>/dev/null
    cat "$1.crt" ca.crt > "$1.chain.crt"; rm -f "$1.csr" "$1.ext"
  done
  rm -f ca.key ;;  # nothing else is ever signed by this CA
secrets)
  dir=$2
  for pair in "drill-a witness" "drill-b reilly"; do
    read -r -a cert_args <<< "$pair"
    set -- "${cert_args[@]}"
    $K create secret generic "$1-tls" --from-file=tls.chain.crt="$dir/$2.chain.crt" \
       --from-file=tls.key="$dir/$2.key" --from-file=ca.crt="$dir/ca.crt" --dry-run=client -o yaml | $K apply -f -
  done
  rnd() { openssl rand -hex 32; }
  # Synapse A: a fresh key under a fresh ID.
  seed=$(openssl genpkey -algorithm ed25519 -outform DER | tail -c 32 | base64 | tr -d '=')
  printf 'ed25519 a_wtns %s\n' "$seed" > "$tmp/a.key"
  for app in drill-a drill-b; do
    printf 'registration_shared_secret: "%s"\nmacaroon_secret_key: "%s"\nform_secret: "%s"\n' \
      "$(rnd)" "$(rnd)" "$(rnd)" > "$tmp/$app.yaml"
  done
  # Synapse B: the production key, taken from the E2EE rig's secret without
  # touching local disk.
  $K get secret dark-synapse-secrets -o jsonpath='{.data.signing\.key}' | base64 -d > "$tmp/b.key"
  $K create secret generic drill-a-secrets --from-file=secrets.yaml="$tmp/drill-a.yaml" \
     --from-file=signing.key="$tmp/a.key" --dry-run=client -o yaml | $K apply -f -
  $K create secret generic drill-b-secrets --from-file=secrets.yaml="$tmp/drill-b.yaml" \
     --from-file=signing.key="$tmp/b.key" --dry-run=client -o yaml | $K apply -f -
  cut -d' ' -f1-2 "$tmp/b.key" | sed 's/^/drill-b key id: /' ;;
db)
  for db in drill_a drill_b; do
    psql_ -c "CREATE DATABASE $db ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C' TEMPLATE template0"
  done ;;
client)
  $K create configmap drill-client --from-file=drill.py="$HERE/drill.py" --from-file=e2ee.sh="$HERE/e2ee.sh" --dry-run=client -o yaml | $K apply -f -
  $K get pod drill-client >/dev/null 2>&1 || $K apply -f "$HERE/k8s/client.yaml"
  $K wait --for=condition=Ready pod/drill-client --timeout=300s ;;
resolver)
  $K apply -f "$HERE/k8s/resolver.yaml"
  $K rollout status deploy/drill-resolver --timeout=120s ;;
up-a)
  front_cm
  $K apply -f "$HERE/k8s/services.yaml"
  render_synapse_conf drill-a witness.lab matrix.witness.lab drill_a reilly.asia "$B_IP"
  render_deploy synapse.yaml drill-a witness.lab matrix.witness.lab "$B_IP" "emptyDir: {sizeLimit: 1Gi}" | $K apply -f -
  $K rollout status deploy/drill-a --timeout=600s ;;
up-b-synapse)
  front_cm
  $K apply -f "$HERE/k8s/services.yaml"
  $K delete deploy/drill-b --ignore-not-found --wait
  render_synapse_conf drill-b reilly.asia matrix.reilly.asia drill_b witness.lab "$A_IP"
  render_deploy synapse.yaml drill-b reilly.asia matrix.reilly.asia "$A_IP" \
    "persistentVolumeClaim: {claimName: drill-b-data}" | $K apply -f -
  $K rollout status deploy/drill-b --timeout=600s ;;
partition)
  for app in drill-a drill-b; do
    if [ "$2" = on ]; then $K exec deploy/$app -c front -- touch /tmp/partition
    else $K exec deploy/$app -c front -- rm -f /tmp/partition; fi
  done ;;
seal)
  # 4.3: no new client traffic is the caller's job (the drill client
  # stops). Wait for the federation queue on B to drain, then stop B.
  drained=false
  for i in $(seq 1 60); do
    pending=$(psql_ -d drill_b -c "SELECT count(*) FROM destinations WHERE retry_last_ts > 0 OR failure_ts IS NOT NULL" || echo "?")
    # PDUs not yet acknowledged by a destination: destination_rooms rows
    # past the destination's last successful stream position.
    lag=$(psql_ -d drill_b -c "SELECT count(*) FROM destination_rooms r JOIN destinations d USING (destination) WHERE r.stream_ordering > coalesce(d.last_successful_stream_ordering, 0)" || echo "?")
    echo "seal: attempt=$i destinations in backoff=$pending, rooms with unsent PDUs=$lag"
    if [ "$pending" = 0 ] && [ "$lag" -le 0 ] 2>/dev/null; then drained=true; break; fi
    sleep 5
  done
  [ "$drained" = true ] || { echo 'seal refused: federation did not drain' >&2; exit 1; }
  $K scale deploy/drill-b --replicas=0
  $K wait --for=delete pod -l app=drill-b --timeout=180s || true
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  psql_ -c "DROP DATABASE IF EXISTS drill_b_seal"
  psql_ -c "CREATE DATABASE drill_b_seal TEMPLATE drill_b"
  echo "seal: database drill_b -> drill_b_seal at $stamp"
  # Media store and the signing key go into the same PVC beside it.
  on_data 'rm -rf /d/seal && mkdir -p /d/seal && (cp -a /d/media_store /d/seal/ 2>/dev/null || true) && cp /s/signing.key /d/seal/signing.key && chmod 600 /d/seal/signing.key && du -sh /d/seal && sha256sum /d/seal/signing.key | cut -c1-16'
  ;;
import)
  # 4.4: the importer against Synapse B's stopped database, into an empty
  # store. The test accounts keep their passwords (one file each).
  ROOMS=$2 USERS=$3
  source_users=$(psql_ -d drill_b -c "SELECT coalesce(json_agg(name ORDER BY name)::text, '[]') FROM users WHERE right(name, length('reilly.asia') + 1) = ':reilly.asia'")
  python3 - "$USERS" "$source_users" <<'PY'
import json,sys
expected=sys.argv[1].split(',')
if not all(expected) or len(set(expected)) != len(expected) or set(expected) != set(json.loads(sys.argv[2])):
 raise SystemExit('import refused: source accounts differ from expected fixture users')
PY
  $K exec drill-client -- cat /state/passwords.json > "$tmp/pw.json"
  args=()
  for u in $(echo "$USERS" | tr ',' ' '); do
    lp=${u#@}; lp=${lp%%:*}
    python3 -c "import json,sys; sys.stdout.write(json.load(open(sys.argv[1]))[sys.argv[2]])" "$tmp/pw.json" "$lp" > "$tmp/pw-$lp"
    args+=(--from-file="$lp=$tmp/pw-$lp")
  done
  $K create secret generic drill-passwords "${args[@]}" --dry-run=client -o yaml | $K apply -f -
  $K delete job drill-b-import --ignore-not-found --wait
  # shellcheck disable=SC2016 # The timestamp expands inside the data pod.
  on_data 'if [ -e /d/spindle ]; then mv /d/spindle /d/spindle.before-import-$(date -u +%Y%m%dT%H%M%SZ); fi; mkdir -p /d/spindle && echo fresh target prepared'
  export ROOMS USERS
  render_deploy spindle.yaml drill-b reilly.asia matrix.reilly.asia "$A_IP" "" \
    | $K apply -l 'app in (drill-b-spindle-config,drill-b-import)' -f -
  if ! $K wait --for=condition=complete job/drill-b-import --timeout=900s; then
    $K logs job/drill-b-import --tail=25 >&2
    exit 1
  fi
  $K logs job/drill-b-import --tail=25
  verify_import ;;
verify-import)
  verify_import ;;
up-b-spindle)
  verify_import
  export ROOMS USERS
  front_cm
  $K delete deploy/drill-b --ignore-not-found --wait
  $K wait --for=delete pod -l app=drill-b --timeout=180s || true
  render_deploy spindle.yaml drill-b reilly.asia matrix.reilly.asia "$A_IP" "" \
    | $K apply -l 'app in (drill-b-spindle-config,drill-b)' -f -
  $K rollout status deploy/drill-b --timeout=300s ;;
rollback)
  # 4.7: stop Spindle B, restore the seal, start Synapse B.
  $K delete deploy/drill-b --ignore-not-found --wait
  $K wait --for=delete pod -l app=drill-b --timeout=180s || true
  psql_ -c "DROP DATABASE IF EXISTS drill_b WITH (FORCE)"
  psql_ -c "CREATE DATABASE drill_b TEMPLATE drill_b_seal"
  on_data 'rm -rf /d/media_store && (cp -a /d/seal/media_store /d/ 2>/dev/null || mkdir -p /d/media_store) && cmp /d/seal/signing.key /s/signing.key && echo restored: database, media store, key unchanged'
  "$0" up-b-synapse ;;
extremities)
  # Forward extremities and event counts per room, from each Synapse
  # database (drill_b only while Synapse B owns it).
  for db in ${2:-drill_a drill_b}; do
    echo "== $db"
    psql_ -d "$db" -F ' ' -c "SELECT r.room_id, r.room_version, (SELECT count(*) FROM events e WHERE e.room_id = r.room_id) AS events, (SELECT string_agg(event_id, ',' ORDER BY event_id) FROM event_forward_extremities x WHERE x.room_id = r.room_id) AS extremities FROM rooms r ORDER BY r.room_id"
  done ;;
netwatch)
  for app in drill-a drill-b; do
    echo "== $app"; $K logs deploy/$app -c netwatch --tail=-1 | grep -E 'OUTBOUND|heartbeat' | tail -3
  done ;;
teardown)
  $K delete deploy,svc,cm,secret,job,pvc -l part-of=federation-drill --ignore-not-found
  $K delete secret drill-a-secrets drill-b-secrets drill-a-tls drill-b-tls --ignore-not-found
  for db in drill_a drill_b drill_b_seal; do psql_ -c "DROP DATABASE IF EXISTS $db"; done ;;
*)
  sed -n '2,20p' "$0"; exit 2 ;;
esac
