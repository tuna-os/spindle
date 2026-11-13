#!/usr/bin/env bash
# Builds the .deb and the .rpm from one binary.
#
# The release workflow and the pull-request packaging job both run this
# script, so the tool versions and the commands cannot drift apart (#825).
#
# usage: scripts/build-packages.sh <version> <deb-arch> <rpm-arch> <out-dir> [binary]
#   version   the package version without a leading "v" (for example 0.1.0)
#   deb-arch  the name Debian uses for the architecture (amd64, arm64)
#   rpm-arch  the name RPM uses for the architecture (x86_64, aarch64)
#   out-dir   where the two packages go
#   binary    the spindle executable to package (default target/release/spindle)
#
# Set SKIP_TOOL_INSTALL=1 when the pinned tools are already installed.
set -euo pipefail

CARGO_DEB_VERSION=3.8.0
CARGO_GENERATE_RPM_VERSION=0.21.1

[ "$#" -ge 4 ] || { sed -n '4,13p' "$0" >&2; exit 2; }
version=$1
deb_arch=$2
rpm_arch=$3
out=$4
root=$(cd "$(dirname "$0")/.." && pwd)
binary=${5:-$root/target/release/spindle}

mkdir -p "$out"
out=$(cd "$out" && pwd)
case "$binary" in /*) ;; *) binary=$PWD/$binary ;; esac
[ -x "$binary" ] || { echo "build-packages: no executable at $binary" >&2; exit 1; }

if [ -z "${SKIP_TOOL_INSTALL:-}" ]; then
  cargo install --locked "cargo-deb@$CARGO_DEB_VERSION" \
    "cargo-generate-rpm@$CARGO_GENERATE_RPM_VERSION"
fi

# Every asset in crates/spindle-server/Cargo.toml is named relative to the
# crate directory under package-staging/. Both tools run from that directory,
# so "relative to the crate" and "relative to the working directory" mean the
# same place and no path climbs out with "../../".
crate=$root/crates/spindle-server
stage=$crate/package-staging
rm -rf "$stage"
mkdir -p "$stage"
install -m 0755 "$binary" "$stage/spindle"
# The tarball unit starts /usr/local/bin/spindle; a package installs /usr/bin.
sed 's|^ExecStart=/usr/local/bin/spindle |ExecStart=/usr/bin/spindle |' \
  "$root/deploy/systemd/spindle.service" > "$stage/spindle.service"
grep -q '^ExecStart=/usr/bin/spindle ' "$stage/spindle.service"
cp "$root/spindle.example.toml" "$root/LICENSE-MIT" "$root/LICENSE-APACHE" "$stage/"

cd "$crate"
cargo deb --no-build --deb-version "$version" \
  --output "$out/spindle-v${version}-${deb_arch}.deb"
cargo generate-rpm \
  --set-metadata "version = \"$version\"" \
  --output "$out/spindle-v${version}-${rpm_arch}.rpm"
