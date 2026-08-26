#!/usr/bin/env bash
#
# Complement start-up for Spindle. Fails loudly on anything missing: a
# homeserver that starts without the identity or trust material it was supposed
# to get will fail later, in a test whose name has nothing to do with the cause.
set -euo pipefail

# Every step announces itself. When this fails it fails inside a container
# Complement started and will discard, and `docker logs` is the only evidence
# anyone gets -- so silence is the one thing the script must not do. An earlier
# version sent openssl's stderr to /dev/null and left a dead container whose
# entire log was the CA install succeeding.
say() { echo "entrypoint: $*"; }

if [[ -z "${SERVER_NAME:-}" ]]; then
    echo "entrypoint: SERVER_NAME is not set" >&2
    exit 1
fi

if [[ ! -f /complement/ca/ca.crt || ! -f /complement/ca/ca.key ]]; then
    echo "entrypoint: /complement/ca/ca.{crt,key} missing" >&2
    exit 1
fi

# Trust the CA Complement signs peer certificates with.
say "installing the Complement CA"
cp /complement/ca/ca.crt /usr/local/share/ca-certificates/complement-ca.crt
update-ca-certificates || {
    echo "entrypoint: could not refresh the trust store" >&2
    exit 1
}

# Sign our own federation certificate. Nothing serves TLS yet -- 8448 arrives
# with federation in M3 (#14) -- but the material is generated here so that
# turning the listener on is a config change rather than a rework of this
# script, and so a mis-mounted CA fails now rather than a milestone later.
say "generating a key and CSR for ${SERVER_NAME}"
openssl req -new -newkey rsa:2048 -nodes \
    -keyout "/certs/${SERVER_NAME}.key" \
    -out "/certs/${SERVER_NAME}.csr" \
    -subj "/CN=${SERVER_NAME}" \
    -addext "subjectAltName=DNS:${SERVER_NAME}"

cat > /certs/cert.ext <<EXT
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names
[alt_names]
DNS.1 = ${SERVER_NAME}
DNS.2 = hs1
DNS.3 = hs2
DNS.4 = hs3
DNS.5 = hs4
IP.1 = 127.0.0.1
EXT

# `-CAserial` matters: the CA is mounted read-only, and the default serial path
# is beside the CA certificate. Letting openssl pick it means trying to write
# into that mount, which fails and takes the whole container with it.
say "signing it with the Complement CA"
openssl x509 -req -sha256 -days 1 \
    -in "/certs/${SERVER_NAME}.csr" \
    -CA /complement/ca/ca.crt \
    -CAkey /complement/ca/ca.key \
    -CAserial /certs/ca.srl \
    -CAcreateserial \
    -extfile /certs/cert.ext \
    -out "/certs/${SERVER_NAME}.crt"

cat > /data/spindle.toml <<TOML
[server]
name = "${SERVER_NAME}"
# Every interface: Complement reaches the container from outside it. This is a
# test image and binds accordingly; the shipped default is loopback.
bind = "0.0.0.0:8008"
public_base_url = "https://${SERVER_NAME}"

[storage]
path = "/data/store"

[logging]
filter = "${SPINDLE_LOG:-info}"
TOML

# Everything above needed root: the trust store, and Complement's 0600 CA key.
# Nothing below does. `exec` means PID 1 is the server itself, running as
# uid 10001 -- so the process that stays up and takes traffic is unprivileged
# even though the setup that produced its certificate was not.
say "starting spindle as ${SERVER_NAME}, dropping to uid 10001"
exec setpriv --reuid=10001 --regid=10001 --clear-groups \
    /usr/local/bin/spindle /data/spindle.toml
