#!/usr/bin/env bash
# Checks a built .deb and .rpm hold what an operator needs, then unpacks the
# .deb into a throwaway directory and starts the binary from there (#825).
# The release workflow and the pull-request packaging job both run it.
#
# usage: scripts/check-packages.sh <version> <deb> <rpm> <deb-arch> <rpm-arch>
# Needs dpkg-deb and rpm.
set -euo pipefail

[ "$#" -eq 5 ] || { sed -n '2,7p' "$0" >&2; exit 2; }
version=$1 deb=$2 rpm=$3 deb_arch=$4 rpm_arch=$5
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

dpkg-deb --contents "$deb" | tee "$work/deb.list"
dpkg-deb --info "$deb"
[ "$(dpkg-deb -f "$deb" Package)" = spindle ]
[ "$(dpkg-deb -f "$deb" Version)" = "$version" ]
[ "$(dpkg-deb -f "$deb" Architecture)" = "$deb_arch" ]
for f in ./usr/bin/spindle ./usr/lib/systemd/system/spindle.service \
         ./etc/spindle/spindle.toml ./usr/share/doc/spindle/LICENSE-MIT \
         ./usr/share/doc/spindle/LICENSE-APACHE; do
  grep -q " $f\$" "$work/deb.list" || { echo "deb lacks $f" >&2; exit 1; }
done
# A conffile survives an upgrade that the operator edited.
dpkg-deb --ctrl-tarfile "$deb" | tar -xO ./conffiles | grep -qx /etc/spindle/spindle.toml

rpm -qlp "$rpm" | tee "$work/rpm.list"
rpm -qip "$rpm"
[ "$(rpm -qp --qf '%{NAME}' "$rpm")" = spindle ]
[ "$(rpm -qp --qf '%{VERSION}' "$rpm")" = "$version" ]
[ "$(rpm -qp --qf '%{ARCH}' "$rpm")" = "$rpm_arch" ]
for f in /usr/bin/spindle /usr/lib/systemd/system/spindle.service \
         /etc/spindle/spindle.toml /usr/share/doc/spindle/LICENSE-MIT \
         /usr/share/doc/spindle/LICENSE-APACHE; do
  grep -qx "$f" "$work/rpm.list" || { echo "rpm lacks $f" >&2; exit 1; }
done
# %config(noreplace) keeps an edited config on upgrade.
rpm -qcp "$rpm" | grep -qx /etc/spindle/spindle.toml

# Install into a throwaway root: unpack, then run what the package ships.
root=$work/root
mkdir "$root"
dpkg-deb -x "$deb" "$root"
grep -q '^ExecStart=/usr/bin/spindle ' "$root/usr/lib/systemd/system/spindle.service"
# `spindle --help` is not a flag: a bare argument is a config path, so the
# usage check goes through a subcommand that prints usage and exits 0.
"$root/usr/bin/spindle" gc --help
# The shipped config must load and its store must open. `verify` does both
# and exits non-zero on a bad config. Its store goes in the throwaway root.
sed "s|^path = \"./data\"|path = \"$work/data\"|" \
  "$root/etc/spindle/spindle.toml" > "$work/check.toml"
grep -q "^path = \"$work/data\"" "$work/check.toml"
"$root/usr/bin/spindle" verify "$work/check.toml"
echo "packages ok"
