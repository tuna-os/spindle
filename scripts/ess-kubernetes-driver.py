#!/usr/bin/env python3
"""Restart-safe ESS/Kubernetes fencing and traffic-switch driver.

The driver deliberately accepts only an explicit topology document.  Guessing from
resource names is unsafe at the one-writer boundary: discovery proves that every
workload in the deployment selector is accounted for before planning a mutation.

It uses kubectl rather than a Python Kubernetes dependency so the exact kubeconfig
and context remain visible operator inputs.  Plans, checkpoints, and output contain
metadata and health only; Secret objects are never requested.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

ROLES = {
    "synapse",
    "federation-sender",
    "sliding-sync",
    "mas",
    "postgres",
    "media",
    "element-call",
    "livekit",
}
REQUIRED_ROLES = ROLES
FENCE_ORDER = ("mas", "sliding-sync", "federation-sender", "synapse")
WORKLOAD_KINDS = ("Deployment", "StatefulSet")


class Blocked(RuntimeError):
    """An actionable safety refusal rather than an unexpected failure."""


class Conflict(Blocked):
    """A Kubernetes resource changed since it was observed."""


def canonical_kind(kind: str) -> str:
    values = {"deployment": "Deployment", "statefulset": "StatefulSet", "ingress": "Ingress"}
    try:
        return values[kind.lower()]
    except KeyError as error:
        raise Blocked(f"unsupported Kubernetes kind {kind!r}") from error


def ref(kind: str, name: str) -> str:
    return f"{canonical_kind(kind).lower()}/{name}"


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as source:
            value = json.load(source)
    except (OSError, json.JSONDecodeError) as error:
        raise Blocked(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise Blocked(f"{path} must contain a JSON object")
    return value


class Kubectl:
    def __init__(self, kubeconfig: Path, context: str):
        self.prefix = ["kubectl", "--kubeconfig", str(kubeconfig), "--context", context]
        self.context = context

    def run(self, arguments: list[str], *, stdin: dict[str, Any] | None = None) -> str:
        result = subprocess.run(
            self.prefix + arguments,
            input=None if stdin is None else json.dumps(stdin),
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode:
            message = result.stderr.strip() or result.stdout.strip()
            if "Conflict" in message or "test failed" in message:
                raise Conflict(f"Kubernetes resource version changed: {message}")
            raise Blocked(f"kubectl {' '.join(arguments)} failed: {message}")
        return result.stdout

    def get(self, kind: str, name: str, namespace: str) -> dict[str, Any]:
        return json.loads(self.run(["-n", namespace, "get", kind, name, "-o", "json"]))

    def list(self, kind: str, namespace: str, selector: str) -> list[dict[str, Any]]:
        value = json.loads(
            self.run(["-n", namespace, "get", kind, "-l", selector, "-o", "json"])
        )
        return value.get("items", [])

    def patch(self, kind: str, name: str, namespace: str, patch: list[dict[str, Any]]) -> dict[str, Any]:
        output = self.run(
            [
                "-n",
                namespace,
                "patch",
                kind,
                name,
                "--type=json",
                "-p",
                json.dumps(patch, separators=(",", ":")),
                "-o",
                "json",
            ]
        )
        return json.loads(output)

    def postgres_sessions(self, config: dict[str, Any]) -> int:
        namespace = config["namespace"]
        selector = config["pod_selector"]
        pods = self.list("pods", namespace, selector)
        running = [pod for pod in pods if pod.get("status", {}).get("phase") == "Running"]
        if len(running) != 1:
            raise Blocked(
                f"PostgreSQL selector {selector!r} in {namespace} matched "
                f"{len(running)} running pods; expected exactly one"
            )
        databases = config.get("databases", ["synapse", "mas"])
        if not databases or not all(isinstance(item, str) and item for item in databases):
            raise Blocked("postgres.databases must be a non-empty string list")
        quoted = ",".join("'" + item.replace("'", "''") + "'" for item in databases)
        query = (
            "SELECT count(*) FROM pg_stat_activity WHERE pid <> pg_backend_pid() "
            f"AND datname IN ({quoted})"
        )
        output = self.run(
            [
                "-n",
                namespace,
                "exec",
                f"pod/{running[0]['metadata']['name']}",
                "--",
                "psql",
                "-XAt",
                "-d",
                config.get("maintenance_database", "postgres"),
                "-c",
                query,
            ]
        ).strip()
        try:
            return int(output)
        except ValueError as error:
            raise Blocked(f"PostgreSQL session probe returned {output!r}, not a count") from error


@dataclass
class Driver:
    kube: Any
    topology: dict[str, Any]
    state_path: Path
    timeout: int = 180
    interval: float = 2.0
    clock: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep

    def __post_init__(self) -> None:
        self.profile, self.namespace, self.selector = self._validate_topology()

    def _validate_topology(self) -> tuple[str, str, str]:
        profile = self.topology.get("profile")
        if profile != "ess-v1":
            raise Blocked(f"unrecognized topology profile {profile!r}; supported profile: ess-v1")
        scope = self.topology.get("scope", {})
        namespace, selector = scope.get("namespace"), scope.get("selector")
        if not namespace or not selector:
            raise Blocked("scope.namespace and scope.selector are required")
        workloads = self.topology.get("workloads")
        if not isinstance(workloads, list):
            raise Blocked("workloads must be a list")
        seen_refs: set[str] = set()
        roles: dict[str, int] = {}
        for workload in workloads:
            kind = canonical_kind(workload.get("kind", ""))
            if kind not in WORKLOAD_KINDS:
                raise Blocked(f"{kind} cannot be used as a workload")
            name, role = workload.get("name"), workload.get("role")
            if not name or role not in ROLES:
                raise Blocked(f"workload must have a name and one of these roles: {sorted(ROLES)}")
            resource_ref = ref(kind, name)
            if resource_ref in seen_refs:
                raise Blocked(f"duplicate workload {resource_ref}")
            seen_refs.add(resource_ref)
            roles[role] = roles.get(role, 0) + 1
        missing = sorted(REQUIRED_ROLES - roles.keys())
        if missing:
            raise Blocked(f"topology is incomplete; missing roles: {', '.join(missing)}")
        singular = sorted(role for role, count in roles.items() if role != "media" and count != 1)
        if singular:
            raise Blocked(f"ambiguous singular roles: {', '.join(singular)}")
        routes = self.topology.get("routes")
        if not isinstance(routes, list) or not routes:
            raise Blocked("at least one ingress route is required")
        route_refs: set[str] = set()
        for route in routes:
            if canonical_kind(route.get("kind", "")) != "Ingress":
                raise Blocked("ess-v1 routes must be Ingress resources")
            required = ("name", "host", "path", "source_service", "target_service")
            if any(not route.get(key) for key in required):
                raise Blocked(f"route requires {', '.join(required)}")
            route_key = f"{route['name']}|{route['host']}|{route['path']}"
            if route_key in route_refs:
                raise Blocked(f"duplicate route {route_key}")
            route_refs.add(route_key)
        postgres = self.topology.get("postgres", {})
        if not postgres.get("namespace") or not postgres.get("pod_selector"):
            raise Blocked("postgres.namespace and postgres.pod_selector are required")
        return profile, namespace, selector

    def discover(self) -> dict[str, Any]:
        selected: dict[str, dict[str, Any]] = {}
        for kind in WORKLOAD_KINDS:
            for item in self.kube.list(kind.lower(), self.namespace, self.selector):
                resource_ref = ref(kind, item["metadata"]["name"])
                selected[resource_ref] = item
        configured = {
            ref(item["kind"], item["name"]): item for item in self.topology["workloads"]
        }
        omitted = sorted(selected.keys() - configured.keys())
        absent = sorted(configured.keys() - selected.keys())
        if omitted or absent:
            details = []
            if omitted:
                details.append("unrecognized selected workloads: " + ", ".join(omitted))
            if absent:
                details.append("configured workloads outside scope or absent: " + ", ".join(absent))
            raise Blocked("; ".join(details))

        workloads = []
        for resource_ref in sorted(configured):
            item, declared = selected[resource_ref], configured[resource_ref]
            metadata, spec, status = item["metadata"], item.get("spec", {}), item.get("status", {})
            workloads.append(
                {
                    "ref": resource_ref,
                    "kind": canonical_kind(declared["kind"]),
                    "name": declared["name"],
                    "role": declared["role"],
                    "writer": declared["role"] in FENCE_ORDER,
                    "uid": metadata["uid"],
                    "resource_version": metadata["resourceVersion"],
                    "replicas": spec.get("replicas", 1),
                    "selector": copy.deepcopy(spec.get("selector", {})),
                    "health": {
                        "observed_generation": status.get("observedGeneration", 0),
                        "current": status.get("replicas", 0),
                        "ready": status.get("readyReplicas", 0),
                        "available": status.get("availableReplicas", 0),
                    },
                }
            )

        selected_ingresses = {
            item["metadata"]["name"]
            for item in self.kube.list("ingress", self.namespace, self.selector)
        }
        configured_ingresses = {route["name"] for route in self.topology["routes"]}
        omitted_ingresses = sorted(selected_ingresses - configured_ingresses)
        absent_ingresses = sorted(configured_ingresses - selected_ingresses)
        if omitted_ingresses or absent_ingresses:
            details = []
            if omitted_ingresses:
                details.append("unrecognized selected ingresses: " + ", ".join(omitted_ingresses))
            if absent_ingresses:
                details.append("configured ingresses outside scope or absent: " + ", ".join(absent_ingresses))
            raise Blocked("; ".join(details))

        routes = [self._route_snapshot(route) for route in self.topology["routes"]]
        sessions = self.kube.postgres_sessions(self.topology["postgres"])
        return {
            "api_version": 1,
            "profile": self.profile,
            "scope": {"namespace": self.namespace, "selector": self.selector},
            "observed_at": now(),
            "workloads": workloads,
            "routes": routes,
            "postgres_sessions": sessions,
        }

    def _route_snapshot(self, route: dict[str, Any]) -> dict[str, Any]:
        item = self.kube.get("ingress", route["name"], self.namespace)
        matches = self._route_matches(item, route["host"], route["path"])
        if len(matches) != 1:
            raise Blocked(
                f"ingress/{route['name']} host {route['host']!r} path {route['path']!r} "
                f"matched {len(matches)} backends; expected exactly one"
            )
        rule_index, path_index, service = matches[0]
        if service not in (route["source_service"], route["target_service"]):
            raise Blocked(
                f"ingress/{route['name']} routes to unrecognized service {service!r}, "
                f"expected {route['source_service']!r} or {route['target_service']!r}"
            )
        metadata = item["metadata"]
        return {
            "ref": ref("Ingress", route["name"]),
            "name": route["name"],
            "uid": metadata["uid"],
            "resource_version": metadata["resourceVersion"],
            "host": route["host"],
            "path": route["path"],
            "rule_index": rule_index,
            "path_index": path_index,
            "service": service,
            "source_service": route["source_service"],
            "target_service": route["target_service"],
            "health": {"load_balancer": copy.deepcopy(item.get("status", {}).get("loadBalancer", {}))},
        }

    @staticmethod
    def _route_matches(item: dict[str, Any], host: str, path: str) -> list[tuple[int, int, str]]:
        matches = []
        for rule_index, rule in enumerate(item.get("spec", {}).get("rules", [])):
            if rule.get("host") != host:
                continue
            for path_index, entry in enumerate(rule.get("http", {}).get("paths", [])):
                if entry.get("path") == path:
                    service = entry.get("backend", {}).get("service", {}).get("name")
                    matches.append((rule_index, path_index, service))
        return matches

    def plan(self, discovery: dict[str, Any]) -> dict[str, Any]:
        mutations = []
        for role in FENCE_ORDER:
            workload = next(item for item in discovery["workloads"] if item["role"] == role)
            if workload["replicas"]:
                mutations.append({"action": "scale", "resource": workload["ref"], "replicas": 0})
        for route in discovery["routes"]:
            mutations.append(
                {
                    "action": "route",
                    "resource": route["ref"],
                    "host": route["host"],
                    "path": route["path"],
                    "from": route["service"],
                    "to": route["target_service"],
                    "requires": "unexpired migration validation and quiesced source",
                }
            )
        return {"api_version": 1, "read_only": True, "discovery": discovery, "mutations": mutations}

    def _new_state(self, discovery: dict[str, Any]) -> dict[str, Any]:
        return {
            "api_version": 1,
            "profile": self.profile,
            "scope": discovery["scope"],
            "created_at": now(),
            "phase": "discovered",
            "target_writes_observed": False,
            "snapshot": discovery,
            "completed": [],
            "mutations": [],
        }

    def state(self, discovery: dict[str, Any] | None = None) -> dict[str, Any]:
        if self.state_path.exists():
            state = load_json(self.state_path)
            expected = {"namespace": self.namespace, "selector": self.selector}
            if state.get("profile") != self.profile or state.get("scope") != expected:
                raise Blocked("checkpoint belongs to a different profile or deployment scope")
            return state
        if discovery is None:
            raise Blocked(f"no checkpoint at {self.state_path}")
        state = self._new_state(discovery)
        atomic_json(self.state_path, state)
        return state

    def _save(self, state: dict[str, Any]) -> None:
        state["updated_at"] = now()
        atomic_json(self.state_path, state)

    def _record(self, state: dict[str, Any], step: str, before: str, after: str) -> None:
        state["mutations"].append(
            {"step": step, "at": now(), "before_resource_version": before, "resource_version": after}
        )
        if step not in state["completed"]:
            state["completed"].append(step)
        self._save(state)

    def _assert_identity(self, current: dict[str, Any], saved: dict[str, Any]) -> None:
        if current["metadata"]["uid"] != saved["uid"]:
            raise Conflict(f"{saved['ref']} was replaced since discovery")

    def _scale(self, state: dict[str, Any], saved: dict[str, Any], replicas: int, step: str) -> None:
        current = self.kube.get(saved["kind"].lower(), saved["name"], self.namespace)
        self._assert_identity(current, saved)
        current_replicas = current.get("spec", {}).get("replicas", 1)
        if current_replicas != replicas:
            before = current["metadata"]["resourceVersion"]
            result = self.kube.patch(
                saved["kind"].lower(),
                saved["name"],
                self.namespace,
                [
                    {"op": "test", "path": "/metadata/resourceVersion", "value": before},
                    {"op": "replace", "path": "/spec/replicas", "value": replicas},
                ],
            )
            after = result["metadata"]["resourceVersion"]
            self._record(state, step, before, after)
        elif step not in state["completed"]:
            # A crash can happen after API success and before checkpointing. Observed
            # state is authoritative, so resumption records rather than repeats it.
            self._record(state, step, current["metadata"]["resourceVersion"], current["metadata"]["resourceVersion"])
        self._wait_workload(saved, replicas)

    def _wait_workload(self, saved: dict[str, Any], replicas: int) -> None:
        deadline = self.clock() + self.timeout
        while self.clock() < deadline:
            current = self.kube.get(saved["kind"].lower(), saved["name"], self.namespace)
            self._assert_identity(current, saved)
            spec, status = current.get("spec", {}), current.get("status", {})
            if (
                spec.get("replicas", 1) == replicas
                and status.get("replicas", 0) == replicas
                and status.get("readyReplicas", 0) == replicas
            ):
                return
            self.sleep(self.interval)
        raise Blocked(f"{saved['ref']} did not converge to {replicas} replicas")

    def quiesce(self) -> dict[str, Any]:
        discovery = self.discover()
        state = self.state(discovery)
        if state["phase"] in ("switching", "target-written"):
            raise Blocked(f"cannot quiesce checkpoint in phase {state['phase']}")
        for role in FENCE_ORDER:
            saved = next(item for item in state["snapshot"]["workloads"] if item["role"] == role)
            self._scale(state, saved, 0, f"fence:{saved['ref']}")
        self._wait_sessions(0)
        state["phase"] = "source-sealed"
        self._save(state)
        return state

    def _wait_sessions(self, expected: int) -> None:
        deadline = self.clock() + self.timeout
        while self.clock() < deadline:
            if self.kube.postgres_sessions(self.topology["postgres"]) == expected:
                return
            self.sleep(self.interval)
        raise Blocked("PostgreSQL sessions did not drain")

    def verify_quiesced(self, state: dict[str, Any] | None = None) -> None:
        state = state or self.state()
        for saved in state["snapshot"]["workloads"]:
            if not saved["writer"]:
                continue
            current = self.kube.get(saved["kind"].lower(), saved["name"], self.namespace)
            self._assert_identity(current, saved)
            if current.get("spec", {}).get("replicas", 1) != 0:
                raise Blocked(f"{saved['ref']} is writable: desired replicas are not zero")
            status = current.get("status", {})
            if status.get("replicas", 0) or status.get("readyReplicas", 0):
                raise Blocked(f"{saved['ref']} still has running pods")
        sessions = self.kube.postgres_sessions(self.topology["postgres"])
        if sessions:
            raise Blocked(f"PostgreSQL still has {sessions} relevant sessions")

    @staticmethod
    def verify_validation(path: Path) -> dict[str, Any]:
        evidence = load_json(path)
        if evidence.get("passed") is not True:
            raise Blocked("migration validation has not passed")
        expires = evidence.get("expires_at")
        try:
            expiry = dt.datetime.fromisoformat(expires.replace("Z", "+00:00"))
        except (AttributeError, ValueError) as error:
            raise Blocked("validation expires_at must be an ISO-8601 timestamp") from error
        if expiry <= dt.datetime.now(dt.timezone.utc):
            raise Blocked("migration validation has expired")
        if not evidence.get("assessment_id") or not evidence.get("target"):
            raise Blocked("validation must name assessment_id and target")
        return {key: evidence[key] for key in ("assessment_id", "target", "expires_at", "passed")}

    def switch(self, validation_path: Path) -> dict[str, Any]:
        state = self.state()
        evidence = self.verify_validation(validation_path)
        self.verify_quiesced(state)
        # Once an ingress mutation begins, a request may reach Spindle before
        # any observer can prove whether it wrote. Close ordinary rollback
        # *before* that first mutation; guessing "probably no writes" is how a
        # split-brain recovery loses events.
        state["validation"] = evidence
        state["target_writes_observed"] = True
        state["phase"] = "switching"
        self._save(state)
        for saved in state["snapshot"]["routes"]:
            self._set_route(state, saved, saved["target_service"], f"switch:{saved['ref']}:{saved['path']}")
        state["phase"] = "target-written"
        self._save(state)
        return state

    def _set_route(self, state: dict[str, Any], saved: dict[str, Any], service: str, step: str) -> None:
        current = self.kube.get("ingress", saved["name"], self.namespace)
        self._assert_identity(current, saved)
        matches = self._route_matches(current, saved["host"], saved["path"])
        if len(matches) != 1:
            raise Blocked(f"{saved['ref']} route became ambiguous while converging")
        rule_index, path_index, current_service = matches[0]
        allowed = {saved["source_service"], saved["target_service"]}
        if current_service not in allowed:
            raise Blocked(f"{saved['ref']} routes to unrecognized service {current_service!r}")
        if current_service != service:
            before = current["metadata"]["resourceVersion"]
            path = f"/spec/rules/{rule_index}/http/paths/{path_index}/backend/service/name"
            result = self.kube.patch(
                "ingress",
                saved["name"],
                self.namespace,
                [
                    {"op": "test", "path": "/metadata/resourceVersion", "value": before},
                    {"op": "test", "path": path, "value": current_service},
                    {"op": "replace", "path": path, "value": service},
                ],
            )
            self._record(state, step, before, result["metadata"]["resourceVersion"])
        elif step not in state["completed"]:
            self._record(state, step, current["metadata"]["resourceVersion"], current["metadata"]["resourceVersion"])
        self._wait_route(saved, service)

    def _wait_route(self, saved: dict[str, Any], service: str) -> None:
        deadline = self.clock() + self.timeout
        while self.clock() < deadline:
            current = self.kube.get("ingress", saved["name"], self.namespace)
            self._assert_identity(current, saved)
            matches = self._route_matches(current, saved["host"], saved["path"])
            if len(matches) == 1 and matches[0][2] == service:
                return
            self.sleep(self.interval)
        raise Blocked(f"{saved['ref']} did not converge to service {service}")

    def rollback(self) -> dict[str, Any]:
        state = self.state()
        if state.get("target_writes_observed"):
            raise Blocked("ordinary rollback is forbidden after Spindle accepted writes")
        for saved in reversed(state["snapshot"]["routes"]):
            self._set_route(state, saved, saved["service"], f"rollback-route:{saved['ref']}:{saved['path']}")
        # Restore the exact recorded writer state in reverse fencing order. Non-
        # writers were evidence only and were never mutated by this operation.
        for role in reversed(FENCE_ORDER):
            saved = next(item for item in state["snapshot"]["workloads"] if item["role"] == role)
            self._scale(state, saved, saved["replicas"], f"restore:{saved['ref']}")
        state["phase"] = "rolled-back"
        self._save(state)
        return state


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("command", choices=("discover", "plan", "quiesce", "verify-quiesced", "switch", "rollback"))
    value.add_argument("--topology", required=True, type=Path)
    value.add_argument("--kubeconfig", required=True, type=Path)
    value.add_argument("--context", required=True)
    value.add_argument("--state", type=Path, help="absolute checkpoint path; required for mutating commands")
    value.add_argument("--validation", type=Path, help="redacted validation evidence for switch")
    value.add_argument("--timeout", type=int, default=180)
    return value


def main(arguments: list[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    mutating = options.command in ("quiesce", "switch", "rollback")
    if options.timeout <= 0:
        raise Blocked("--timeout must be positive")
    if not options.kubeconfig.is_file():
        raise Blocked("--kubeconfig must name a readable file")
    if mutating and (options.state is None or not options.state.is_absolute()):
        raise Blocked("mutating commands require an absolute --state path")
    if options.command == "verify-quiesced" and options.state is None:
        raise Blocked("verify-quiesced requires --state")
    if options.state is not None and not options.state.is_absolute():
        raise Blocked("--state must be an absolute path")
    topology = load_json(options.topology)
    driver = Driver(Kubectl(options.kubeconfig, options.context), topology, options.state or Path("/dev/null"), options.timeout)
    if options.command == "discover":
        result = driver.discover()
    elif options.command == "plan":
        result = driver.plan(driver.discover())
    elif options.command == "quiesce":
        result = driver.quiesce()
    elif options.command == "verify-quiesced":
        driver.verify_quiesced()
        result = {"quiesced": True}
    elif options.command == "switch":
        if options.validation is None:
            raise Blocked("switch requires --validation")
        result = driver.switch(options.validation)
    else:
        result = driver.rollback()
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Blocked as error:
        print(f"ess-kubernetes-driver: blocked: {error}", file=sys.stderr)
        raise SystemExit(1) from error
