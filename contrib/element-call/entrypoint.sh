#!/usr/bin/env bash
# Start-up for Spindle inside Element Call's Playwright stack (#269).
#
# The Complement image's own entrypoint wants Complement's CA and signs a
# federation certificate with it; here nginx terminates TLS with upstream's
# dev certificate, so all this has to do is trust the CA that signed it --
# the homeservers federate through nginx over https -- and start the server
# on the mounted config, unprivileged.
#
# The dead peers (docker-compose-dead-peers.yml, #795) share one config
# template and set SPINDLE_SERVER_NAME: their config is the template with
# that name in it, and they serve TLS themselves with upstream's dev key,
# copied where the unprivileged server can read it.
set -euo pipefail
say() { echo "entrypoint: $*"; }

mkdir -p /data/store
config=/cfg/spindle.toml
if [[ -n "${SPINDLE_SERVER_NAME:-}" ]]; then
    mkdir -p /data/cfg
    sed "s/@SERVER_NAME@/${SPINDLE_SERVER_NAME}/" /cfg/spindle.toml.in > /data/cfg/spindle.toml
    install -m 0600 /cfg/tls.key /data/cfg/tls.key
    config=/data/cfg/spindle.toml
fi
if [[ ! -f "$config" ]]; then
    echo "entrypoint: $config is not mounted" >&2
    exit 1
fi
if [[ -f /cfg/dev-ca.crt ]]; then
    say "trusting Element Call's dev CA"
    cp /cfg/dev-ca.crt /usr/local/share/ca-certificates/element-call-dev-ca.crt
    update-ca-certificates >/dev/null
else
    say "no dev CA mounted; federation to the other site will not verify"
fi
chown -R spindle:spindle /data
say "starting spindle on $config, dropping to uid 10001"
exec setpriv --reuid=10001 --regid=10001 --clear-groups \
    /usr/local/bin/spindle "$config"
