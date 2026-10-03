#!/usr/bin/env bash
# Full-corpus dark rehearsal of the Synapse importer (#563).
#
#   run.sh base                 PVC fi-dark-spindle, config, shell pod
#   run.sh media                copy Synapse's local media store, read-only (#563)
#   run.sh import [extra args]  Job: spindle import-synapse from db `synapse`
#   run.sh rig-import           Job: the E2EE rig's rooms and users from `synapse_dark`
#   run.sh serve                the dark Spindle (Deployment + ClusterIP Service)
#   run.sh report [file]        print the import report from the volume
#
# IMAGE (default below) is a rehearsal image with the synapse-import feature.
# FRESH=1 (default) empties the store before `import`; FRESH=0 resumes.
# Isolation: [federation] enabled = false, no resolver (nameserver
# 127.0.0.1), the database through hostAliases only, ClusterIP only, and a
# netwatch sidecar on the server, as for dark-spindle in #558.
set -euo pipefail

export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config-aws-migration}"
NS="${NS:-spindle-rehearsal}"
IMAGE="${IMAGE:-ghcr.io/tuna-os/spindle:rehearsal-latest}"
NODE="${NODE:-ip-10-20-1-11}"
here="$(cd "$(dirname "$0")" && pwd)"
k() { kubectl -n "$NS" "$@"; }

render() {
  sed -e "s|__IMAGE__|$IMAGE|g" -e "s|__NODE__|$NODE|g" "$@"
}

wait_job() {
  local job=$1
  until k get job "$job" -o jsonpath='{.status.conditions[*].type}' | grep -qE 'Complete|Failed'; do sleep 10; done
  k logs "job/$job" --tail=200 | grep -vE '^progress: room [0-9]+/' || true
  k get job "$job" -o jsonpath='{.status.conditions[*].type}{"\n"}'
}

# One import Job. $1 name, $2 database, rest: extra import-synapse args.
import_job() {
  local name=$1 db=$2; shift 2
  local ip args="" passwords=""
  ip="$(k get svc rehearsal-pg -o jsonpath='{.spec.clusterIP}')"
  for a in "$@"; do args+="        - \"$a\""$'\n'; done
  k delete job "$name" --ignore-not-found --wait >/dev/null
  render "$here/import-job.yaml" | sed -e "s|__NAME__|$name|g" -e "s|__DB__|$db|g" -e "s|__PG_IP__|$ip|g" \
    | awk -v args="$args" '{ if ($0 ~ /__ARGS__/) printf "%s", args; else print }' | k apply -f - >/dev/null
  wait_job "$name"
}

case "${1:-}" in
  base)
    render "$here/base.yaml" | k apply -f -
    k wait --for=condition=Ready pod/fi-shell --timeout=300s ;;
  media)
    kubectl apply -f "$here/media-reader.yaml"
    kubectl -n ess wait --for=condition=Ready pod/spindle-media-reader --timeout=120s
    kubectl -n ess exec spindle-media-reader -- tar cf - -C /media/media_store local_content local_thumbnails \
      | k exec -i fi-shell -- bash -c 'mkdir -p /data/synapse-media && tar xf - -C /data/synapse-media && du -sh /data/synapse-media/*'
    kubectl -n ess delete pod spindle-media-reader --wait=false ;;
  import)
    shift
    k scale deploy/fi-dark-spindle --replicas=0 >/dev/null 2>&1 || true
    if [ "${FRESH:-1}" = 1 ]; then
      k exec fi-shell -- rm -rf /data/store /data/import.json /data/rig-import.json
    fi
    import_job fi-import synapse --media /data/synapse-media --checkpoint /data/import.json "$@" ;;
  rig-import)
    rooms="$(k get configmap spindle-mig-rig-manifest -o jsonpath='{.data.manifest\.json}' |
      python3 -c 'import json,sys; print(",".join(r["room_id"] for r in json.load(sys.stdin)["rooms"]))')"
    k scale deploy/fi-dark-spindle --replicas=0 >/dev/null 2>&1 || true
    import_job fi-rig-import synapse_dark --media /data/synapse-media --checkpoint /data/rig-import.json \
      --allow-nonempty --rooms "$rooms" \
      --users @spindle-mig-a:reilly.asia,@spindle-mig-b:reilly.asia,@spindle-mig-c:reilly.asia ;;
  serve)
    render "$here/server.yaml" | k apply -f -
    k scale deploy/fi-dark-spindle --replicas=1
    k rollout status deploy/fi-dark-spindle --timeout=600s ;;
  report)
    k exec fi-shell -- cat "${2:-/data/import.json}" ;;
  *) sed -n '2,15p' "$0"; exit 2 ;;
esac
