#!/usr/bin/env bash
# Decide what a run of .github/workflows/compliance.yml starts, and write
# the answer to $GITHUB_OUTPUT (stdout when unset):
#
#   code=true|false   false only when every changed path is prose, so a
#                     docs-only change does not build the server five times
#   rotation=[...]    which of the heavy rigs run in this run
#
# The heavy rigs (ROTATING below) each build a tree of their own and take
# a quarter of an hour; they are coverage of the same server, not of
# different code, so a push to main runs a rotating slice of them and the
# nightly and dispatched runs run all of them. Pull requests run none:
# they never did.
#
# Environment (the workflow passes these; set them by hand to try it):
#   EVENT        github.event_name
#   REPO         owner/name, for the API calls
#   PR           the pull request number (pull_request)
#   BEFORE, SHA  the pushed range (push)
#   RUN_NUMBER   github.run_number: what the rotation turns on
#   SIZE         rigs per push (repo variable COMPLIANCE_ROUND_ROBIN_SIZE)
#   CHANGED      newline-separated paths; skips the API (for testing)
set -euo pipefail

ROTATING=(rust-sdk-suite element-call-e2e mesh-seam)

# True when there is at least one path and every one is prose. An empty
# or unreadable list is not "docs only": when in doubt, run everything.
docs_only() {
  local any=false path
  while IFS= read -r path; do
    [[ -z $path ]] && continue
    any=true
    case $path in
      *.md | *.mdx | docs/* | .ste-budget) ;;
      *) return 1 ;;
    esac
  done
  $any
}

changed() {
  if [[ -n ${CHANGED+x} ]]; then
    printf '%s\n' "$CHANGED"
    return
  fi
  case $EVENT in
    pull_request)
      # The files endpoint stops at 3000; a list that long is not prose.
      gh api --paginate "repos/$REPO/pulls/$PR/files" --jq '.[].filename' |
        awk 'NR > 2999 { print "(truncated)"; exit } { print }'
      ;;
    push)
      # A new ref has no before; compare stops listing at 300 files.
      [[ $BEFORE =~ ^0+$ ]] && return
      gh api "repos/$REPO/compare/$BEFORE...$SHA" --jq '.files[].filename' |
        awk 'NR > 299 { print "(truncated)"; exit } { print }'
      ;;
  esac
}

json() {
  local out='' item
  for item in "$@"; do out+="${out:+,}\"$item\""; done
  printf '[%s]' "$out"
}

code=true
rotation='[]'
case $EVENT in
  pull_request | push)
    if files=$(changed) && docs_only <<<"$files"; then
      code=false
    fi
    if [[ $EVENT == push && $code == true ]]; then
      n=${#ROTATING[@]}
      size=${SIZE:-1}
      [[ $size =~ ^[0-9]+$ ]] || size=1
      ((size > n)) && size=$n
      picked=()
      for ((i = 0; i < size; i++)); do
        picked+=("${ROTATING[(RUN_NUMBER * size + i) % n]}")
      done
      rotation=$(json "${picked[@]}")
    fi
    ;;
  *)
    rotation=$(json "${ROTATING[@]}")
    ;;
esac

{
  echo "code=$code"
  echo "rotation=$rotation"
} >>"${GITHUB_OUTPUT:-/dev/stdout}"
