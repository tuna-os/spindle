"""Log every socket in this pod's network namespace by where it goes.

Runs as a sidecar, so /proc/net/* is the pod's own socket table. Each
remote endpoint is classified as loopback, inbound (a peer connected to one
of LISTEN_PORTS), one of the ALLOWED endpoints, or OUTBOUND. OUTBOUND is a
connection the drill does not expect: the isolation claim is that the count
stays at zero.

  ALLOWED       comma-separated label=ip:port, e.g.
                "database=10.104.171.212:5432,resolver=10.111.63.10:53,peer=10.111.63.11:443"
  LISTEN_PORTS  comma-separated ports this pod serves, e.g. "8008,8443"

Prints one JSON line per newly seen (kind, remote) pair and a heartbeat with
running totals every 60 s. The socket table is sampled every 200 ms, so a
connection shorter than that can be missed; the resolver's query log covers
the names, and Synapse/Spindle logs cover each federation request.
"""
import json
import os
import socket
import struct
import time

ALLOWED = {}
for item in filter(None, os.environ.get("ALLOWED", "").split(",")):
    label, _, endpoint = item.partition("=")
    ALLOWED[endpoint.strip()] = label.strip()
LISTEN_PORTS = {int(p) for p in os.environ.get("LISTEN_PORTS", "8008").split(",") if p}
TCP_STATES = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
              "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
              "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
              "0A": "LISTEN", "0B": "CLOSING"}


def addr4(h):
    ip, port = h.split(":")
    return socket.inet_ntoa(struct.pack("<I", int(ip, 16))), int(port, 16)


def addr6(h):
    ip, port = h.split(":")
    raw = b"".join(struct.pack("<I", int(ip[i:i + 8], 16)) for i in range(0, 32, 8))
    a = socket.inet_ntop(socket.AF_INET6, raw)
    if a.startswith("::ffff:"):
        a = a[7:]
    return a, int(port, 16)


def sockets():
    for proto, conv in (("tcp", addr4), ("tcp6", addr6), ("udp", addr4), ("udp6", addr6)):
        try:
            lines = open(f"/proc/net/{proto}").read().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            f = line.split()
            (lip, lport), (rip, rport) = conv(f[1]), conv(f[2])
            yield proto, lip, lport, rip, rport, TCP_STATES.get(f[3], f[3])


def classify(proto, lip, lport, rip, rport, state):
    if rport == 0 or rip in ("0.0.0.0", "::"):
        return None
    if rip.startswith("127.") or rip == "::1":
        return "loopback"
    if proto.startswith("tcp") and lport in LISTEN_PORTS:
        return "inbound"
    label = ALLOWED.get(f"{rip}:{rport}")
    if label:
        return label
    return "OUTBOUND"


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


seen, totals, last_beat = set(), {}, 0.0
print(json.dumps({"netwatch": "start", "allowed": ALLOWED,
                  "listen_ports": sorted(LISTEN_PORTS)}), flush=True)
while True:
    for s in sockets():
        kind = classify(*s)
        if kind is None or kind == "loopback":
            continue
        key = (kind, s[3]) if kind == "inbound" else (kind, s[0], s[3], s[4])
        if key not in seen:
            seen.add(key)
            totals[kind] = totals.get(kind, 0) + 1
            print(json.dumps({"ts": now(), "new": kind, "proto": s[0],
                              "local": f"{s[1]}:{s[2]}", "remote": f"{s[3]}:{s[4]}",
                              "state": s[5]}), flush=True)
    t = time.time()
    if t - last_beat >= 60:
        last_beat = t
        print(json.dumps({"ts": now(), "heartbeat": True, "distinct": totals,
                          "outbound": totals.get("OUTBOUND", 0)}), flush=True)
    time.sleep(0.2)
