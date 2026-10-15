"""Log every socket in this pod's network namespace whose remote end is
not loopback, an allowed lab peer, or an inbound connection to one of
this pod's listeners. Variant of the #558 netwatch with a peer list.

ALLOWED="ip:port,ip:port"   lab peers (database, the paired dark server)
LISTEN="8008,8080"          ports this pod serves
"""
import json, os, socket, struct, time

ALLOWED = {p for p in os.environ.get("ALLOWED", "").split(",") if p}
LISTEN_PORTS = {int(p) for p in os.environ.get("LISTEN", "8008").split(",") if p}
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
    if f"{rip}:{rport}" in ALLOWED:
        return "lab-peer"
    if proto.startswith("tcp") and lport in LISTEN_PORTS:
        return "inbound"
    return "OUTBOUND"

seen, totals, last_beat = set(), {}, 0.0
print(json.dumps({"netwatch": "start", "allowed": sorted(ALLOWED), "listen": sorted(LISTEN_PORTS)}), flush=True)
while True:
    for s in sockets():
        kind = classify(*s)
        if kind is None:
            continue
        key = (kind, s[0], s[3], s[4]) if kind != "inbound" else (kind, s[3])
        if key not in seen:
            seen.add(key)
            totals[kind] = totals.get(kind, 0) + 1
            print(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                              "new": kind, "proto": s[0], "local": f"{s[1]}:{s[2]}",
                              "remote": f"{s[3]}:{s[4]}", "state": s[5]}), flush=True)
    now = time.time()
    if now - last_beat >= 60:
        last_beat = now
        print(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                          "heartbeat": True, "distinct": totals,
                          "outbound": totals.get("OUTBOUND", 0)}), flush=True)
    time.sleep(1)
