#!/usr/bin/env bash
# Quiesce or resume an Element Server Suite Synapse without allowing two
# homeservers to accept writes for the same server name.
#
# This is the outage boundary of a Synapse -> Spindle cutover, not the data
# importer. It deliberately has no "start Spindle anyway" escape hatch: the
# importer, validation, signing-key continuity, MAS switch and ingress switch
# must all succeed before a future `cutover` command can safely compose them.
set -euo pipefail

usage() {
  cat <<'EOF'
usage: synapse-k8s-cutover.sh COMMAND --kubeconfig FILE --context NAME [OPTIONS]

Commands:
  plan               Inspect the ESS profile and PostgreSQL writers (read-only)
  quiesce            Show the ordered scale-to-zero operation
  quiesce --execute  Save replica state, close the front doors, then stop Synapse
  verify-quiesced    Require every selected workload and Synapse DB session gone
  resume --execute   Restore saved replicas, workers first and front doors last

Options:
  --namespace NAME       ESS namespace (default: ess)
  --state-dir DIR        Required for executing quiesce/resume
  --timeout SECONDS      Workload convergence timeout (default: 180)
  --execute              Perform mutations; otherwise quiesce is a dry run

Profile overrides (space-separated Kubernetes resource names):
  SPINDLE_CUTOVER_FRONTENDS
  SPINDLE_CUTOVER_WRITERS

PostgreSQL inspection overrides:
  SPINDLE_PG_NAMESPACE  (default: postgres)
  SPINDLE_PG_WORKLOAD   (default: deployment/postgres)
  SPINDLE_PG_USER       (default: postgres)
  SPINDLE_PG_DATABASE   (default: postgres)
EOF
}

die() {
  echo "synapse-k8s-cutover: $*" >&2
  exit 1
}

command_name=${1:-}
[[ -n $command_name ]] || { usage >&2; exit 2; }
shift

kubeconfig=
expected_context=
namespace=ess
state_dir=
timeout=180
execute=false
while (($#)); do
  case $1 in
    --kubeconfig) kubeconfig=${2:-}; shift 2 ;;
    --context) expected_context=${2:-}; shift 2 ;;
    --namespace) namespace=${2:-}; shift 2 ;;
    --state-dir) state_dir=${2:-}; shift 2 ;;
    --timeout) timeout=${2:-}; shift 2 ;;
    --execute) execute=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ -n $kubeconfig && -f $kubeconfig ]] || die "--kubeconfig must name a readable file"
[[ -n $expected_context ]] || die "--context is required"
[[ $timeout =~ ^[1-9][0-9]*$ ]] || die "--timeout must be a positive integer"
command -v kubectl >/dev/null || die "kubectl is not installed"

k() {
  kubectl --kubeconfig "$kubeconfig" --context "$expected_context" "$@"
}

actual_context=$(k config current-context)
[[ $actual_context == "$expected_context" ]] ||
  die "kubeconfig resolves to context $actual_context, not $expected_context"

# ESS sends all ordinary Matrix traffic through HAProxy, but routes login and
# refresh directly to MAS. Both front doors close before any Synapse worker is
# touched, so no new write can race the worker shutdown.
read -r -a frontends <<<"${SPINDLE_CUTOVER_FRONTENDS:-deployment/ess-haproxy deployment/ess-matrix-authentication-service}"
read -r -a writers <<<"${SPINDLE_CUTOVER_WRITERS:-statefulset/ess-synapse-main statefulset/ess-synapse-fed-sender statefulset/ess-synapse-sliding-sync}"
resources=("${frontends[@]}" "${writers[@]}")

for resource in "${resources[@]}"; do
  k -n "$namespace" get "$resource" >/dev/null
done

pg_namespace=${SPINDLE_PG_NAMESPACE:-postgres}
pg_workload=${SPINDLE_PG_WORKLOAD:-deployment/postgres}
pg_user=${SPINDLE_PG_USER:-postgres}
pg_database=${SPINDLE_PG_DATABASE:-postgres}

database_sessions() {
  k -n "$pg_namespace" exec "$pg_workload" -- \
    psql -X -U "$pg_user" -d "$pg_database" -Atc \
      "SELECT datname || '|' || application_name || '|' || \
              coalesce(client_addr::text, 'local') || '|' || state || '|' || count(*) \
       FROM pg_stat_activity \
       WHERE pid <> pg_backend_pid() AND datname IN ('synapse', 'mas') \
       GROUP BY datname, application_name, client_addr, state \
       ORDER BY datname, application_name, client_addr, state"
}

synapse_session_count() {
  k -n "$pg_namespace" exec "$pg_workload" -- \
    psql -X -U "$pg_user" -d "$pg_database" -Atc \
      "SELECT count(*) FROM pg_stat_activity \
       WHERE pid <> pg_backend_pid() AND datname = 'synapse'"
}

replicas_of() {
  k -n "$namespace" get "$1" -o jsonpath='{.spec.replicas}'
}

uid_of() {
  k -n "$namespace" get "$1" -o jsonpath='{.metadata.uid}'
}

status() {
  echo "context=$actual_context namespace=$namespace"
  for resource in "${resources[@]}"; do
    desired=$(replicas_of "$resource")
    ready=$(k -n "$namespace" get "$resource" -o jsonpath='{.status.readyReplicas}')
    echo "$resource desired=${desired:-0} ready=${ready:-0}"
  done
  echo "database sessions (database|application|address|state|count):"
  sessions=$(database_sessions)
  if [[ -n $sessions ]]; then
    echo "$sessions"
  else
    echo "none"
  fi
}

wait_for_replicas() {
  local resource=$1 expected=$2 deadline=$((SECONDS + timeout))
  while ((SECONDS < deadline)); do
    desired=$(replicas_of "$resource")
    ready=$(k -n "$namespace" get "$resource" -o jsonpath='{.status.readyReplicas}')
    current=$(k -n "$namespace" get "$resource" -o jsonpath='{.status.replicas}')
    if [[ ${desired:-0} == "$expected" && ${ready:-0} == "$expected" && ${current:-0} == "$expected" ]]; then
      return 0
    fi
    sleep 2
  done
  die "$resource did not converge to $expected replicas within ${timeout}s"
}

require_state_dir() {
  [[ -n $state_dir ]] || die "--state-dir is required with --execute"
  [[ $state_dir == /* ]] || die "--state-dir must be an absolute path"
  [[ $state_dir != / && $state_dir != "${HOME:-/nonexistent}" ]] ||
    die "refusing broad --state-dir $state_dir"
}

capture_state() {
  require_state_dir
  mkdir -p "$state_dir"
  state_file=$state_dir/replicas.tsv
  [[ ! -e $state_file ]] || die "$state_file already exists; resume or choose a fresh directory"
  temporary=$state_dir/replicas.tsv.tmp
  : >"$temporary"
  for resource in "${resources[@]}"; do
    group=writer
    for frontend in "${frontends[@]}"; do
      [[ $resource == "$frontend" ]] && group=frontend
    done
    printf '%s\t%s\t%s\t%s\n' "$group" "$resource" "$(replicas_of "$resource")" "$(uid_of "$resource")" >>"$temporary"
  done
  mv "$temporary" "$state_file"
  chmod 600 "$state_file"
}

restore_state() {
  require_state_dir
  state_file=$state_dir/replicas.tsv
  [[ -f $state_file ]] || die "no saved replica state at $state_file"

  for group in writer frontend; do
    while IFS=$'\t' read -r saved_group resource replicas uid; do
      [[ $saved_group == "$group" ]] || continue
      current_uid=$(uid_of "$resource")
      [[ $current_uid == "$uid" ]] ||
        die "$resource was replaced since quiesce; refusing to restore replicas"
      echo "restoring $resource to $replicas"
      k -n "$namespace" scale "$resource" --replicas="$replicas"
      wait_for_replicas "$resource" "$replicas"
    done <"$state_file"
  done
}

verify_quiesced() {
  for resource in "${resources[@]}"; do
    [[ $(replicas_of "$resource") == 0 ]] || die "$resource is not scaled to zero"
    ready=$(k -n "$namespace" get "$resource" -o jsonpath='{.status.readyReplicas}')
    current=$(k -n "$namespace" get "$resource" -o jsonpath='{.status.replicas}')
    [[ ${ready:-0} == 0 && ${current:-0} == 0 ]] || die "$resource still has running pods"
  done
  sessions=$(synapse_session_count)
  [[ $sessions == 0 ]] || die "Synapse still has $sessions PostgreSQL sessions"
  echo "quiesced: all selected workloads are zero and Synapse has no PostgreSQL sessions"
}

case $command_name in
  plan)
    status
    ;;
  quiesce)
    if [[ $execute != true ]]; then
      status
      echo "dry run: scale frontends to zero, wait; scale writers to zero, wait; verify PostgreSQL has zero Synapse sessions"
      exit 0
    fi
    capture_state
    rollback=true
    on_exit() {
      rc=$?
      trap - EXIT
      if [[ $rc != 0 && $rollback == true ]]; then
        echo "quiesce failed; restoring saved replicas" >&2
        restore_state || true
      fi
      exit "$rc"
    }
    # EXIT also covers an explicit `die`, SIGINT and SIGTERM. An ERR trap does
    # not run for `exit 1`, which is exactly how a convergence timeout ends.
    trap on_exit EXIT
    echo "closing Matrix and MAS front doors"
    k -n "$namespace" scale "${frontends[@]}" --replicas=0
    for resource in "${frontends[@]}"; do wait_for_replicas "$resource" 0; done
    echo "stopping every Synapse writer"
    k -n "$namespace" scale "${writers[@]}" --replicas=0
    for resource in "${writers[@]}"; do wait_for_replicas "$resource" 0; done
    verify_quiesced
    rollback=false
    trap - EXIT
    echo "source is quiesced; replica state is $state_dir/replicas.tsv"
    ;;
  verify-quiesced)
    verify_quiesced
    ;;
  resume)
    [[ $execute == true ]] || die "resume requires --execute"
    restore_state
    echo "Synapse resumed; retained replica state is $state_dir/replicas.tsv"
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
