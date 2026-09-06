#!/usr/bin/env bash
# Decide which tag, if any, the Release workflow cuts from this checkout.
#
# Writes `tag`, `sha` and `previous` to $GITHUB_OUTPUT (or stdout when run
# by hand). An empty `tag` means "nothing to release", which is an answer
# rather than an error: main has not moved since the last tag, or CI on the
# commit it moved to is not green yet.
#
#   scripts/release-cut.sh            # from a checkout of main, with tags
#   BUMP=minor scripts/release-cut.sh
#
# On a `push` of a tag the decision is already made: the tag is the ref.
set -euo pipefail

out="${GITHUB_OUTPUT:-/dev/stdout}"
bump="${BUMP:-patch}"

if [ "${GITHUB_EVENT_NAME:-}" = "push" ]; then
  {
    echo "tag=${GITHUB_REF_NAME}"
    echo "sha=${GITHUB_SHA}"
    echo "previous=$(git tag -l 'v*' --sort=-v:refname | grep -vx "${GITHUB_REF_NAME}" | head -1)"
  } >> "$out"
  exit 0
fi

sha=$(git rev-parse HEAD)
last=$(git tag -l 'v*' --sort=-v:refname | head -1)

if [ -n "$last" ] && [ "$(git rev-parse "${last}^{commit}")" = "$sha" ]; then
  echo "main is still at ${last}; nothing to release."
  echo "tag=" >> "$out"
  exit 0
fi

# CI's verdict on this exact commit. Every check that ran must have
# finished without failing (a skipped nightly-only job is fine), and the
# quality gate must be among the ones that passed: a commit with no checks
# at all is one CI has not looked at, not one it approved.
#
# This workflow's own jobs are check runs on the same commit, and the one
# running this script is "in progress" by definition (run 34053330372
# declined its own release that way), so runs belonging to this workflow
# run are left out of the verdict.
if [ -n "${GH_TOKEN:-}" ] && [ -n "${GITHUB_REPOSITORY:-}" ]; then
  own="/runs/${GITHUB_RUN_ID:-none}/"
  gh api "repos/${GITHUB_REPOSITORY}/commits/${sha}/check-runs?per_page=100" --paginate \
    --jq --arg own "$own" '.check_runs[] | select((.html_url // "") | contains($own) | not)
      | [.name, .status, (.conclusion // "")] | @tsv' > checks.tsv
  if ! grep -Pq '^Rust quality gate\tcompleted\tsuccess$' checks.tsv; then
    echo "The Rust quality gate has not passed on ${sha}; not releasing it."
    cat checks.tsv
    echo "tag=" >> "$out"
    exit 0
  fi
  if grep -Pv '\t(success|skipped|neutral)$' checks.tsv | grep -Pq '\tcompleted\t'; then
    echo "A check failed on ${sha}; not releasing it:"
    grep -Pv '\t(success|skipped|neutral)$' checks.tsv
    echo "tag=" >> "$out"
    exit 0
  fi
  if grep -Pq '\t(queued|in_progress)\t' checks.tsv; then
    echo "CI is still running on ${sha}; not releasing it yet."
    echo "tag=" >> "$out"
    exit 0
  fi
fi

base="${last:-v0.0.0}"
IFS=. read -r major minor patch <<< "${base#v}"
case "$bump" in
  patch) patch=$((patch + 1)) ;;
  minor) minor=$((minor + 1)); patch=0 ;;
  *) echo "unknown bump: ${bump}" >&2; exit 2 ;;
esac
tag="v${major}.${minor}.${patch}"

echo "Cutting ${tag} from ${sha} (previous: ${last:-none})."
{
  echo "tag=${tag}"
  echo "sha=${sha}"
  echo "previous=${last}"
} >> "$out"
