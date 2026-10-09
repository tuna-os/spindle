#!/usr/bin/env bash
#
# #21's disk-full drill: fill a real filesystem under the store and under a
# running server, and check what an operator and an orchestrator see.
#
# The two tests are `#[ignore]`d, because they need a filesystem small
# enough to fill and a test cannot make one without root. This script
# makes one: a 64 MiB tmpfs, mounted with sudo, unmounted on exit. Give it
# SPINDLE_DISK_FULL_DIR instead to use a directory on a small filesystem
# you already have (/dev/shm in a container is often 64 MiB), and nothing
# is mounted. The tests refuse a directory with more than 256 MiB free.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here/.."

dir="${SPINDLE_DISK_FULL_DIR:-}"
if [ -z "$dir" ]; then
    dir="$(mktemp -d)"
    sudo mount -t tmpfs -o "size=64m,uid=$(id -u),gid=$(id -g)" tmpfs "$dir"
    trap 'sudo umount "$dir" && rmdir "$dir"' EXIT
fi

# `--all-features` matches the CI test step, so the build is reused.
# One crate at a time and one test at a time: two drills filling the same
# filesystem would each see the other's refusal.
for crate in spindle-store spindle-server; do
    # The server half cannot clean up after itself (its delivery loops keep
    # the store open until the process ends), and its full directory would
    # leave the next drill no room to open a store at all.
    rm -rf "$dir/store" "$dir/server" "$dir/ballast"
    SPINDLE_DISK_FULL_DIR="$dir" cargo test -p "$crate" --all-features --test disk_full \
        -- --ignored --test-threads=1
done
