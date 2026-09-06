#!/usr/bin/env bash
# Start-up for Spindle inside Element Call's Playwright stack (#269).
#
# The Complement image's own entrypoint wants Complement's CA and signs a
# federation certificate with it; here nginx terminates TLS with upstream's
# dev certificate, so all this has to do is trust the CA that signed it --
# the two Spindles federate through nginx over https -- and start the server
# on the mounted config, unprivileged.
set -euo pipefail
say() { echo "entrypoint: $*"; }

if [[ ! -f /cfg/spindle.toml ]]; then
    echo "entrypoint: /cfg/spindle.toml is not mounted" >&2
    exit 1
fi
if [[ -f /cfg/dev-ca.crt ]]; then
    say "trusting Element Call's dev CA"
    cp /cfg/dev-ca.crt /usr/local/share/ca-certificates/element-call-dev-ca.crt
    update-ca-certificates >/dev/null
else
    say "no dev CA mounted; federation to the other site will not verify"
fi
mkdir -p /data/store
chown -R spindle:spindle /data
say "starting spindle on /cfg/spindle.toml, dropping to uid 10001"
exec setpriv --reuid=10001 --regid=10001 --clear-groups \
    /usr/local/bin/spindle /cfg/spindle.toml
