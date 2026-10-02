#!/usr/bin/env python3
"""Durable safety gate for a Synapse-to-Spindle migration.

This is deliberately infrastructure-neutral.  Probes and deployment drivers write
small evidence documents; this workspace decides whether the next authority
transition is allowed.  It never accepts credentials, recovery material, decrypted
content, or arbitrary commands.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

PHASES = (
    "REHEARSE",
    "PREFLIGHT",
    "SEAL_SOURCE",
    "IMPORT",
    "VALIDATE",
    "SWITCH",
    "OBSERVE",
)
AUTHORITIES = {
    "SYNAPSE_LIVE",
    "SEALING_SOURCE",
    "SOURCE_SEALED",
    "IMPORTING",
    "VALIDATING_DARK_TARGET",
    "SPINDLE_LIVE",
    "RECOVERY_REQUIRED",
}
GATES = {
    "retained_rooms",
    "room_versions",
    "signing_identity",
    "element_e2ee",
    "users",
    "devices",
    "keys",
    "state",
    "account_data",
    "receipts",
    "push_data",
    "media",
    "source_workloads_zero",
    "postgres_sessions_drained",
    "target_empty",
    "import_checkpoint",
    "dark_target_client",
    "federation_bidirectional",
    "mas",
    "ingress_single_writer",
}
MUTATING_REQUIREMENTS = {
    "SEAL_SOURCE": {
        "retained_rooms",
        "room_versions",
        "signing_identity",
        "target_empty",
    },
    "IMPORT": {
        "retained_rooms",
        "room_versions",
        "signing_identity",
        "target_empty",
        "source_workloads_zero",
        "postgres_sessions_drained",
    },
    "SWITCH": GATES,
}
AUTHORITY_FOR_PHASE = {
    "REHEARSE": "SYNAPSE_LIVE",
    "PREFLIGHT": "SYNAPSE_LIVE",
    "SEAL_SOURCE": "SEALING_SOURCE",
    "IMPORT": "IMPORTING",
    "VALIDATE": "VALIDATING_DARK_TARGET",
    "SWITCH": "SPINDLE_LIVE",
    "OBSERVE": "SPINDLE_LIVE",
}
FORBIDDEN_FIELDS = {
    "access_token",
    "admin_token",
    "credential",
    "decrypted_content",
    "password",
    "private_key",
    "recovery_key",
    "secret",
    "signing_key",
}
SENSITIVE_VALUE = re.compile(r"-----BEGIN .*PRIVATE KEY-----|syt_[A-Za-z0-9_-]{16,}")


class Blocked(RuntimeError):
    """An expected safety refusal with an actionable explanation."""


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def timestamp(value: str, field: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as error:
        raise Blocked(f"evidence {field} must be an RFC 3339 timestamp") from error
    if parsed.tzinfo is None:
        raise Blocked(f"evidence {field} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


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


def assert_redacted(value: Any, path: str = "evidence") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in FORBIDDEN_FIELDS:
                raise Blocked(
                    f"{path}.{key} is secret or content material and cannot be stored"
                )
            assert_redacted(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            assert_redacted(child, f"{path}[{index}]")
    elif isinstance(value, str) and SENSITIVE_VALUE.search(value):
        raise Blocked(f"{path} resembles secret material and cannot be stored")


def append_event(state: dict[str, Any], kind: str, actor: str, **details: Any) -> None:
    state["events"].append(
        {
            "sequence": len(state["events"]) + 1,
            "timestamp": now().isoformat().replace("+00:00", "Z"),
            "kind": kind,
            "actor": actor,
            "details": details,
        }
    )


def initial_state(operation_id: str, actor: str, mode: str) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", operation_id):
        raise Blocked("operation ID must be 1-128 safe filename characters")
    if mode not in {"live", "rehearsal"}:
        raise Blocked("mode must be live or rehearsal")
    state = {
        "schema_version": 1,
        "operation_id": operation_id,
        "mode": mode,
        "created_by": actor,
        "phase": "REHEARSE",
        "authority": "SYNAPSE_LIVE",
        "target_has_accepted_writes": False,
        "source_sealed": False,
        "revision": 1,
        "inventory": None,
        "evidence": {},
        "approvals": [],
        "import": {
            "rooms": 0,
            "events": 0,
            "bytes": 0,
            "exclusions": 0,
            "checkpoint": None,
            "complete": False,
        },
        "events": [],
    }
    append_event(state, "workspace-created", actor, mode=mode)
    return state


def inventory_from(document: dict[str, Any]) -> dict[str, Any]:
    rooms = document.get("rooms")
    if not isinstance(rooms, list) or not rooms:
        raise Blocked("inventory rooms must be a non-empty list")
    retained: dict[str, int] = {}
    excluded: dict[str, int] = {}
    approvals: set[str] = set()
    for index, room in enumerate(rooms):
        if not isinstance(room, dict):
            raise Blocked(f"inventory room {index} must be an object")
        extra = set(room) - {"version", "disposition", "approval"}
        if extra:
            raise Blocked(
                f"inventory room {index} has unsupported fields: {', '.join(sorted(extra))}"
            )
        version = room.get("version")
        disposition = room.get("disposition")
        if not isinstance(version, str) or not version:
            raise Blocked(f"inventory room {index} has no version")
        if disposition == "retain":
            retained[version] = retained.get(version, 0) + 1
        elif disposition == "exclude":
            approval = room.get("approval")
            if not isinstance(approval, str) or not approval:
                raise Blocked(
                    f"excluded inventory room {index} has no approval reference"
                )
            excluded[version] = excluded.get(version, 0) + 1
            approvals.add(approval)
        else:
            raise Blocked(
                f"inventory room {index} disposition must be retain or exclude"
            )
    if not retained:
        raise Blocked("inventory retains no rooms")
    return {
        "retained": dict(sorted(retained.items())),
        "excluded": dict(sorted(excluded.items())),
        "approved_exclusions": sorted(approvals),
        "total": len(rooms),
    }


def validate_evidence(
    gate: str, document: dict[str, Any], inventory: dict[str, Any] | None
) -> dict[str, Any]:
    if gate not in GATES:
        raise Blocked(f"unknown gate {gate!r}")
    required = {
        "status",
        "probe_version",
        "timestamp",
        "target",
        "observations",
        "artifacts",
        "expires_at",
        "attested_by",
    }
    missing = sorted(required - document.keys())
    extra = sorted(set(document) - required)
    if missing or extra:
        parts = []
        if missing:
            parts.append(f"missing {', '.join(missing)}")
        if extra:
            parts.append(f"unknown {', '.join(extra)}")
        raise Blocked("invalid evidence contract: " + "; ".join(parts))
    if document["status"] not in {"passed", "failed"}:
        raise Blocked("evidence status must be passed or failed")
    for field in ("probe_version", "target", "attested_by"):
        if not isinstance(document[field], str) or not document[field]:
            raise Blocked(f"evidence {field} must be a non-empty string")
    if not isinstance(document["observations"], dict):
        raise Blocked("evidence observations must be an object")
    if not isinstance(document["artifacts"], list) or not all(
        isinstance(item, str) and item for item in document["artifacts"]
    ):
        raise Blocked("evidence artifacts must be a list of references")
    observed = timestamp(document["timestamp"], "timestamp")
    expires = timestamp(document["expires_at"], "expires_at")
    current = now()
    if observed > current + dt.timedelta(minutes=5):
        raise Blocked("evidence timestamp is in the future")
    if expires <= observed:
        raise Blocked("evidence expires_at must be after its timestamp")
    assert_redacted(document)

    observations = document["observations"]
    passed = document["status"] == "passed"
    if passed and gate in {"source_workloads_zero", "postgres_sessions_drained"}:
        field = "workloads" if gate == "source_workloads_zero" else "sessions"
        if observations.get(field) != 0:
            raise Blocked(f"{gate} evidence must report {field}=0")
    if (
        passed
        and gate == "target_empty"
        and observations.get("empty_validated") is not True
    ):
        raise Blocked("target_empty evidence must report empty_validated=true")
    if (
        passed
        and gate == "ingress_single_writer"
        and observations.get("writers") != ["spindle"]
    ):
        raise Blocked('ingress evidence must report exactly writers=["spindle"]')
    if (
        passed
        and gate == "federation_bidirectional"
        and (
            observations.get("bidirectional") is not True
            or observations.get("independent_server") is not True
        )
    ):
        raise Blocked(
            "federation evidence must prove both directions with an independent server"
        )
    if passed and gate == "element_e2ee":
        checks = (
            "fresh_login",
            "verification",
            "key_recovery",
            "historical_decryption",
        )
        if any(observations.get(check) is not True for check in checks):
            raise Blocked(
                "Element evidence must attest fresh login, verification, key recovery, and historical decryption"
            )
    if gate == "room_versions":
        if inventory is None:
            raise Blocked(
                "record the retained-room inventory before room-version evidence"
            )
        retained = set(inventory["retained"])
        reported = observations.get("retained_distribution")
        client = set(observations.get("client_supported", []))
        federation = set(observations.get("federation_supported", []))
        if reported != inventory["retained"]:
            raise Blocked(
                "room-version evidence distribution differs from preflight inventory"
            )
        missing_client = sorted(retained - client)
        missing_federation = sorted(retained - federation)
        if passed and (missing_client or missing_federation):
            raise Blocked(
                "retained room versions lack proof: "
                f"client={missing_client or 'none'}, federation={missing_federation or 'none'}"
            )
    return copy.deepcopy(document)


def evidence_failures(state: dict[str, Any], required: set[str]) -> list[str]:
    current = now()
    failures = []
    for gate in sorted(required):
        evidence = state["evidence"].get(gate)
        if evidence is None:
            failures.append(f"{gate}: missing")
        elif evidence["status"] != "passed":
            failures.append(f"{gate}: {evidence['status']}")
        elif timestamp(evidence["expires_at"], "expires_at") <= current:
            failures.append(f"{gate}: stale")
    return failures


def semantic_cutover_failures(state: dict[str, Any]) -> list[str]:
    failures = []
    inventory = state.get("inventory")
    if inventory is None:
        return ["retained-room inventory is missing"]
    versions = set(inventory["retained"])
    federation = (
        state["evidence"].get("federation_bidirectional", {}).get("observations", {})
    )
    proven = set(federation.get("versions", []))
    missing = sorted(versions - proven)
    if missing:
        failures.append(
            f"bidirectional federation not proven for retained versions: {', '.join(missing)}"
        )
    if "10" in versions:
        element = state["evidence"].get("element_e2ee", {}).get("observations", {})
        if element.get("room_version") != "10":
            failures.append(
                "v10 requires fresh-Element encrypted-history evidence from a v10 room"
            )
    progress = state["import"]
    if not progress["complete"] or not progress["checkpoint"]:
        failures.append("import has no durable completed checkpoint")
    expected = inventory["total"]
    if progress["rooms"] + progress["exclusions"] != expected:
        failures.append(
            "imported rooms plus exclusions do not equal the assessed inventory"
        )
    approvers = {
        item["actor"] for item in state["approvals"] if item["scope"] == "switch"
    }
    if not approvers:
        failures.append("switch has no independent approval")
    if state["created_by"] in approvers:
        failures.append(
            "switch approval must come from someone other than the requester"
        )
    return failures


def advance(
    state: dict[str, Any], target: str, actor: str, confirmation: str | None
) -> None:
    if target not in PHASES:
        raise Blocked(f"unknown phase {target!r}")
    current_index = PHASES.index(state["phase"])
    if current_index + 1 >= len(PHASES) or PHASES[current_index + 1] != target:
        raise Blocked(
            f"can only advance from {state['phase']} to {PHASES[current_index + 1] if current_index + 1 < len(PHASES) else 'nothing'}"
        )
    requirements = MUTATING_REQUIREMENTS.get(target, set())
    failures = evidence_failures(state, requirements)
    if target == "IMPORT" and not state["source_sealed"]:
        failures.append("source sealing has not completed")
    if target == "VALIDATE":
        failures.extend(evidence_failures(state, {"import_checkpoint"}))
        if not state["import"]["complete"]:
            failures.append("import progress is not complete")
    if target == "SWITCH":
        failures.extend(semantic_cutover_failures(state))
        if confirmation != state["operation_id"]:
            failures.append("typed confirmation must equal the operation ID")
    if failures:
        raise Blocked("advancement blocked: " + "; ".join(failures))

    state["phase"] = target
    if state["mode"] == "live":
        state["authority"] = AUTHORITY_FOR_PHASE[target]
        if target == "SWITCH":
            state["target_has_accepted_writes"] = True
    else:
        state["authority"] = "SYNAPSE_LIVE"
    append_event(
        state,
        "phase-advanced",
        actor,
        phase=target,
        authority=state["authority"],
        rehearsal=state["mode"] == "rehearsal",
    )


def mark_source_sealed(state: dict[str, Any], actor: str) -> None:
    if state["phase"] != "SEAL_SOURCE":
        raise Blocked("source sealing can only complete during SEAL_SOURCE")
    failures = evidence_failures(
        state,
        MUTATING_REQUIREMENTS["SEAL_SOURCE"]
        | {"source_workloads_zero", "postgres_sessions_drained"},
    )
    if failures:
        raise Blocked("source sealing blocked: " + "; ".join(failures))
    state["source_sealed"] = True
    if state["mode"] == "live":
        state["authority"] = "SOURCE_SEALED"
    append_event(
        state,
        "source-sealed",
        actor,
        authority=state["authority"],
        rehearsal=state["mode"] == "rehearsal",
    )


def update_import(state: dict[str, Any], document: dict[str, Any], actor: str) -> None:
    if state["phase"] != "IMPORT":
        raise Blocked("import progress can only be recorded during IMPORT")
    required = {"rooms", "events", "bytes", "exclusions", "checkpoint", "complete"}
    if set(document) != required:
        raise Blocked(
            "import progress requires rooms, events, bytes, exclusions, checkpoint, and complete"
        )
    for field in ("rooms", "events", "bytes", "exclusions"):
        if (
            not isinstance(document[field], int)
            or document[field] < state["import"][field]
        ):
            raise Blocked(f"import {field} must be a monotonic non-negative integer")
    if not isinstance(document["checkpoint"], str) or not document["checkpoint"]:
        raise Blocked("import checkpoint must be a durable reference")
    if not isinstance(document["complete"], bool):
        raise Blocked("import complete must be a boolean")
    if state["import"]["complete"] and not document["complete"]:
        raise Blocked("a completed import cannot become incomplete")
    state["import"] = copy.deepcopy(document)
    append_event(state, "import-progress", actor, **document)


def rollback(state: dict[str, Any], actor: str, confirmation: str) -> None:
    if confirmation != state["operation_id"]:
        raise Blocked("typed confirmation must equal the operation ID")
    if state["mode"] != "live":
        raise Blocked("a rehearsal never changed authority and needs no rollback")
    if state["target_has_accepted_writes"] or PHASES.index(
        state["phase"]
    ) >= PHASES.index("SWITCH"):
        raise Blocked(
            "Spindle may have accepted writes; ordinary rollback is closed, use recovery-required"
        )
    if state["phase"] not in {"SEAL_SOURCE", "IMPORT", "VALIDATE"}:
        raise Blocked(
            "ordinary rollback is only available after source sealing and before switch"
        )
    state["phase"] = "PREFLIGHT"
    state["authority"] = "SYNAPSE_LIVE"
    state["source_sealed"] = False
    append_event(
        state,
        "pre-write-rollback",
        actor,
        compensation="restore recorded source authority",
    )


def view(state: dict[str, Any]) -> dict[str, Any]:
    failures = evidence_failures(state, GATES)
    next_phase = (
        PHASES[PHASES.index(state["phase"]) + 1]
        if state["phase"] != "OBSERVE"
        else None
    )
    return {
        "Runbook": {
            "operation_id": state["operation_id"],
            "mode": state["mode"],
            "active_step": state["phase"],
            "authority": state["authority"],
            "target_has_accepted_writes": state["target_has_accepted_writes"],
            "source_sealed": state["source_sealed"],
            "next_step": next_phase,
        },
        "Gates": {
            "blocking": failures,
            "passed": sorted(
                set(state["evidence"]) - {item.split(":", 1)[0] for item in failures}
            ),
        },
        "Evidence": {
            gate: {
                "status": item["status"],
                "probe_version": item["probe_version"],
                "timestamp": item["timestamp"],
                "expires_at": item["expires_at"],
                "attested_by": item["attested_by"],
                "artifacts": item["artifacts"],
            }
            for gate, item in sorted(state["evidence"].items())
        },
        "Resources": {"room_versions": state["inventory"], "import": state["import"]},
        "Recovery": {
            "ordinary_rollback_available": state["mode"] == "live"
            and state["phase"] in {"SEAL_SOURCE", "IMPORT", "VALIDATE"}
            and not state["target_has_accepted_writes"],
            "boundary": "post-write recovery"
            if state["target_has_accepted_writes"]
            else "pre-write compensation",
            "recommended_action": "execute recovery plan"
            if state["authority"] == "RECOVERY_REQUIRED"
            else (
                f"resolve {failures[0]}"
                if failures
                else (
                    f"advance to {next_phase}" if next_phase else "continue observation"
                )
            ),
        },
    }


def save(path: Path, state: dict[str, Any]) -> None:
    state["revision"] += 1
    atomic_json(path, state)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--state", type=Path, required=True, help="durable workspace JSON"
    )
    commands = result.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    init.add_argument("--operation-id", required=True)
    init.add_argument("--actor", required=True)
    init.add_argument("--mode", choices=("live", "rehearsal"), default="live")
    inventory = commands.add_parser("inventory")
    inventory.add_argument("--input", type=Path, required=True)
    inventory.add_argument("--actor", required=True)
    attest = commands.add_parser("attest")
    attest.add_argument("--gate", required=True)
    attest.add_argument("--input", type=Path, required=True)
    attest.add_argument("--actor", required=True)
    approve = commands.add_parser("approve")
    approve.add_argument("--scope", choices=("switch",), required=True)
    approve.add_argument("--actor", required=True)
    sealed = commands.add_parser("source-sealed")
    sealed.add_argument("--actor", required=True)
    progress = commands.add_parser("import-progress")
    progress.add_argument("--input", type=Path, required=True)
    progress.add_argument("--actor", required=True)
    move = commands.add_parser("advance")
    move.add_argument("--to", required=True)
    move.add_argument("--actor", required=True)
    move.add_argument("--confirm")
    undo = commands.add_parser("rollback")
    undo.add_argument("--actor", required=True)
    undo.add_argument("--confirm", required=True)
    recover = commands.add_parser("recovery-required")
    recover.add_argument("--actor", required=True)
    recover.add_argument("--reason", required=True)
    commands.add_parser("view")
    report = commands.add_parser("report")
    report.add_argument("--output", type=Path, required=True)
    return result


def main(arguments: list[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    try:
        if options.command == "init":
            if options.state.exists():
                raise Blocked(f"workspace {options.state} already exists")
            state = initial_state(options.operation_id, options.actor, options.mode)
            atomic_json(options.state, state)
            return 0
        state = load_json(options.state)
        if (
            state.get("authority") not in AUTHORITIES
            or state.get("phase") not in PHASES
        ):
            raise Blocked("workspace has an unknown authority or phase")
        if options.command == "view":
            print(json.dumps(view(state), indent=2, sort_keys=True))
            return 0
        if options.command == "report":
            report = {
                "schema_version": 1,
                "exported_at": now().isoformat().replace("+00:00", "Z"),
                "view": view(state),
                "audit": state["events"],
            }
            assert_redacted(report, "report")
            atomic_json(options.output, report)
            return 0
        if options.command == "inventory":
            if state["phase"] not in {"REHEARSE", "PREFLIGHT"}:
                raise Blocked("inventory can only change during rehearsal or preflight")
            state["inventory"] = inventory_from(load_json(options.input))
            append_event(
                state,
                "inventory-derived",
                options.actor,
                distribution=state["inventory"],
            )
        elif options.command == "attest":
            state["evidence"][options.gate] = validate_evidence(
                options.gate, load_json(options.input), state["inventory"]
            )
            append_event(
                state,
                "gate-attested",
                options.actor,
                gate=options.gate,
                status=state["evidence"][options.gate]["status"],
            )
        elif options.command == "approve":
            if options.actor == state["created_by"]:
                raise Blocked("approval must be independent from the requester")
            if not any(
                item["scope"] == options.scope and item["actor"] == options.actor
                for item in state["approvals"]
            ):
                state["approvals"].append(
                    {
                        "scope": options.scope,
                        "actor": options.actor,
                        "timestamp": now().isoformat().replace("+00:00", "Z"),
                    }
                )
                append_event(state, "approved", options.actor, scope=options.scope)
        elif options.command == "source-sealed":
            mark_source_sealed(state, options.actor)
        elif options.command == "import-progress":
            update_import(state, load_json(options.input), options.actor)
        elif options.command == "advance":
            advance(state, options.to, options.actor, options.confirm)
        elif options.command == "rollback":
            rollback(state, options.actor, options.confirm)
        elif options.command == "recovery-required":
            if not state["target_has_accepted_writes"]:
                raise Blocked(
                    "post-write recovery cannot start before Spindle may have accepted writes"
                )
            state["authority"] = "RECOVERY_REQUIRED"
            append_event(
                state, "recovery-required", options.actor, reason=options.reason
            )
        save(options.state, state)
        return 0
    except Blocked as error:
        print(f"migration-workspace: blocked: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
