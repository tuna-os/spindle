#!/usr/bin/env python3
"""Keep the files under deploy/ from rotting (#825).

Checks, each with the tool an operator would use:
  - the Compose files render (`docker compose config`) and the Caddyfile
    validates (`caddy validate` in the pinned image);
  - the Helm chart lints and renders with default and with every optional
    value, and the rendered YAML parses;
  - the systemd unit passes `systemd-analyze verify`;
  - the TOML examples parse, and the LiveKit key and secret in the Compose
    pair agree.

A tool that is missing is skipped with a note, unless --require-all is
given (CI does). Run from anywhere:  python3 scripts/check-deploy.py
"""
import argparse
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy"
failures: list[str] = []
skipped: list[str] = []


def fail(message: str) -> None:
    failures.append(message)
    print(f"FAIL {message}")


def run(args, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, **kwargs)


def need(tool: str, what: str) -> bool:
    if shutil.which(tool):
        return True
    skipped.append(f"{what} (no {tool})")
    return False


def check_toml() -> None:
    for name in ("compose/spindle.toml", "compose/spindle-rtc.toml"):
        try:
            tomllib.loads((DEPLOY / name).read_text())
        except tomllib.TOMLDecodeError as error:
            fail(f"deploy/{name} is not TOML: {error}")
    rtc = tomllib.loads((DEPLOY / "compose/spindle-rtc.toml").read_text())["rtc"]["livekit"]
    keys = yaml.safe_load((DEPLOY / "compose/livekit.yaml").read_text())["keys"]
    if keys.get(rtc["key"]) != rtc["secret"]:
        fail("compose/livekit.yaml keys do not match [rtc.livekit] in spindle-rtc.toml")
    # The two server configs must differ only by the [rtc.livekit] section.
    base = tomllib.loads((DEPLOY / "compose/spindle.toml").read_text())
    full = tomllib.loads((DEPLOY / "compose/spindle-rtc.toml").read_text())
    full.pop("rtc")
    if base != full:
        fail("compose/spindle.toml and spindle-rtc.toml differ outside [rtc.livekit]")


def check_compose() -> None:
    directory = DEPLOY / "compose"
    for path in directory.glob("*.yaml"):
        yaml.safe_load(path.read_text())
    if not need("docker", "docker compose config and caddy validate"):
        return
    environment = ["--env-file", str(directory / ".env.example")]
    for files in (["compose.yaml"], ["compose.yaml", "compose.livekit.yaml"]):
        command = ["docker", "compose", *environment]
        for name in files:
            command += ["-f", name]
        result = run([*command, "config", "-q"], cwd=directory)
        if result.returncode:
            fail(f"docker compose config {' '.join(files)}: {result.stderr.strip()}")
    # A missing SPINDLE_IMAGE must stop the stack, not start something unpinned.
    result = run(["docker", "compose", "-f", "compose.yaml", "config", "-q"], cwd=directory,
                 env={"PATH": "/usr/bin:/bin:/usr/local/bin", "SPINDLE_DOMAIN": "x"})
    if result.returncode == 0:
        fail("compose.yaml renders without SPINDLE_IMAGE")
    # Caddy, in the image the Compose file pins, reads both Caddyfile and the LiveKit block.
    compose = yaml.safe_load((directory / "compose.yaml").read_text())
    image = compose["services"]["caddy"]["image"]
    for extra in (None, "livekit.caddy"):
        mounts = ["-v", f"{directory / 'Caddyfile'}:/etc/caddy/Caddyfile:ro"]
        if extra:
            mounts += ["-v", f"{directory / extra}:/etc/caddy/conf.d/{extra}:ro"]
        result = run(["docker", "run", "--rm", "-e", "SPINDLE_DOMAIN=matrix.example.org", *mounts,
                      image, "caddy", "validate", "--config", "/etc/caddy/Caddyfile"])
        if result.returncode:
            fail(f"caddy validate ({extra or 'base'}): {result.stderr.strip()[-400:]}")
    # The standalone example, in the same image.
    result = run(["docker", "run", "--rm", "-v", f"{DEPLOY / 'proxy/Caddyfile'}:/etc/caddy/Caddyfile:ro",
                  image, "caddy", "validate", "--config", "/etc/caddy/Caddyfile"])
    if result.returncode:
        fail(f"caddy validate proxy/Caddyfile: {result.stderr.strip()[-400:]}")


def check_helm() -> None:
    chart = DEPLOY / "helm/spindle"
    if not need("helm", "helm lint and template"):
        return
    result = run(["helm", "lint", str(chart), "--strict", "--set", "image.tag=v0.0.0"])
    if result.returncode:
        fail(f"helm lint: {result.stdout.strip()[-400:]}")
    # No tag must be an error, not a default.
    if run(["helm", "template", "r", str(chart)]).returncode == 0:
        fail("helm template renders without image.tag")
    variants = [
        [],
        ["--set", "metrics.enabled=true", "--set", "metrics.serviceMonitor.enabled=true",
         "--set", "ingress.enabled=true", "--set", "ingress.tlsSecretName=tls",
         "--set", "image.digest=sha256:" + "0" * 64, "--set", "config.existingSecret=cfg"],
    ]
    for extra in variants:
        result = run(["helm", "template", "r", str(chart), "--set", "image.tag=v0.0.0", *extra])
        if result.returncode:
            fail(f"helm template {extra}: {result.stderr.strip()[-400:]}")
            continue
        docs = [d for d in yaml.safe_load_all(result.stdout) if d]
        sets = [d for d in docs if d["kind"] == "StatefulSet"]
        if len(sets) != 1 or sets[0]["spec"]["replicas"] != 1:
            fail("the chart must render exactly one StatefulSet with one replica")
        container = sets[0]["spec"]["template"]["spec"]["containers"][0]
        paths = {container["readinessProbe"]["httpGet"]["path"], container["livenessProbe"]["httpGet"]["path"]}
        if paths != {"/ready", "/health"}:
            fail(f"probe paths are {paths}")
    plain = run(["helm", "template", "r", str(chart), "--set", "image.tag=v0.0.0"]).stdout
    for doc in yaml.safe_load_all(plain):
        if doc and doc["kind"] == "ConfigMap":
            try:
                tomllib.loads(doc["data"]["spindle.toml"])
            except tomllib.TOMLDecodeError as error:
                fail(f"the chart's spindle.toml is not TOML: {error}")


def check_systemd() -> None:
    unit = (DEPLOY / "systemd/spindle.service").read_text()
    if not need("systemd-analyze", "systemd-analyze verify"):
        return
    with tempfile.TemporaryDirectory() as tmp:
        # verify wants the binary to exist; a stub stands in for it.
        stub = pathlib.Path(tmp) / "spindle"
        stub.write_text("#!/bin/sh\n")
        stub.chmod(0o755)
        path = pathlib.Path(tmp) / "spindle.service"
        path.write_text(unit.replace("/usr/local/bin/spindle", str(stub)))
        result = run(["systemd-analyze", "verify", "--man=no", str(path)])
        # ConditionPathExists is a runtime condition, not a verify error.
        problems = [l for l in (result.stdout + result.stderr).splitlines() if l.strip()]
        if problems:
            fail("systemd-analyze verify: " + "; ".join(problems))
    for needle in ("DynamicUser=yes", "StateDirectory=spindle", "ProtectSystem=strict"):
        if needle not in unit:
            fail(f"spindle.service lost {needle}")
    if not re.search(r"^ExecStart=/usr/local/bin/spindle ", unit, re.M):
        fail("spindle.service ExecStart changed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-all", action="store_true", help="fail when a tool is missing")
    arguments = parser.parse_args()
    check_toml()
    check_compose()
    check_helm()
    check_systemd()
    for note in skipped:
        print(f"skipped {note}")
    if arguments.require_all and skipped:
        failures.append("tools missing: " + ", ".join(skipped))
    if failures:
        print(f"{len(failures)} problem(s)")
        return 1
    print("deploy: files render and validate")
    return 0


if __name__ == "__main__":
    sys.exit(main())
