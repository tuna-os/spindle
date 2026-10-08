#!/usr/bin/env python3
"""Safety and restart tests for the migration workspace."""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("migration-workspace.py")
SPEC = importlib.util.spec_from_file_location("migration_workspace", MODULE_PATH)
workspace = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = workspace
assert SPEC.loader is not None
SPEC.loader.exec_module(workspace)


def iso(moment: dt.datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def evidence(gate: str, *, status: str = "passed", stale: bool = False) -> dict:
    current = dt.datetime.now(dt.timezone.utc)
    observed = current - dt.timedelta(hours=2 if stale else 0)
    expires = (
        current - dt.timedelta(hours=1) if stale else current + dt.timedelta(hours=1)
    )
    observations: dict = {"checked": True}
    if gate == "room_versions":
        observations = {
            "retained_distribution": {"10": 2},
            "client_supported": ["10"],
            "federation_supported": ["10"],
        }
    elif gate == "element_e2ee":
        observations = {
            "room_version": "10",
            "fresh_login": True,
            "verification": True,
            "key_recovery": True,
            "historical_decryption": True,
        }
    elif gate == "federation_bidirectional":
        observations = {
            "bidirectional": True,
            "independent_server": True,
            "versions": ["10"],
        }
    elif gate == "source_workloads_zero":
        observations = {"workloads": 0}
    elif gate == "postgres_sessions_drained":
        observations = {"sessions": 0}
    elif gate == "target_empty":
        observations = {"empty_validated": True}
    elif gate == "ingress_single_writer":
        observations = {"writers": ["spindle"]}
    return {
        "status": status,
        "probe_version": "probe/1.2.3",
        "timestamp": iso(observed),
        "target": "migration-target",
        "observations": observations,
        "artifacts": [f"sha256:{gate}"],
        "expires_at": iso(expires),
        "attested_by": "probe@example.org",
    }


def inventory() -> dict:
    return {
        "rooms": [
            {"version": "10", "disposition": "retain"},
            {"version": "10", "disposition": "retain"},
            {"version": "9", "disposition": "exclude", "approval": "approval-9"},
        ]
    }


class MigrationWorkspaceTests(unittest.TestCase):
    def state(self, mode: str = "live") -> dict:
        state = workspace.initial_state("migration-42", "requester", mode)
        state["inventory"] = workspace.inventory_from(inventory())
        return state

    def attest(self, state: dict, *gates: str) -> None:
        for gate in gates:
            state["evidence"][gate] = workspace.validate_evidence(
                gate, evidence(gate), state["inventory"]
            )

    def reach_import(self, state: dict) -> None:
        workspace.advance(state, "PREFLIGHT", "operator", None)
        self.attest(
            state, "retained_rooms", "room_versions", "signing_identity", "target_empty"
        )
        workspace.advance(state, "SEAL_SOURCE", "operator", None)
        self.attest(state, "source_workloads_zero", "postgres_sessions_drained")
        workspace.mark_source_sealed(state, "operator")
        self.assertEqual(
            state["authority"],
            "SOURCE_SEALED" if state["mode"] == "live" else "SYNAPSE_LIVE",
        )
        workspace.advance(state, "IMPORT", "operator", None)

    def reach_validate(self, state: dict) -> None:
        self.reach_import(state)
        workspace.update_import(
            state,
            {
                "rooms": 2,
                "events": 240,
                "bytes": 8192,
                "exclusions": 1,
                "checkpoint": "s3://evidence/checkpoints/import-42",
                "complete": True,
            },
            "importer",
        )
        self.attest(state, "import_checkpoint")
        workspace.advance(state, "VALIDATE", "operator", None)

    def prepare_switch(self, state: dict) -> None:
        self.reach_validate(state)
        self.attest(state, *(workspace.GATES - set(state["evidence"])))
        state["approvals"].append(
            {
                "scope": "switch",
                "actor": "approver",
                "timestamp": iso(dt.datetime.now(dt.timezone.utc)),
            }
        )

    def test_inventory_derives_versions_and_requires_approved_exclusions(self):
        derived = workspace.inventory_from(inventory())
        self.assertEqual(derived["retained"], {"10": 2})
        self.assertEqual(derived["excluded"], {"9": 1})
        bad = {"rooms": [{"version": "9", "disposition": "exclude"}]}
        with self.assertRaisesRegex(workspace.Blocked, "approval"):
            workspace.inventory_from(bad)

    def test_room_version_gate_fails_closed_for_any_retained_version(self):
        state = self.state()
        document = evidence("room_versions")
        document["observations"]["federation_supported"] = []
        with self.assertRaisesRegex(workspace.Blocked, r"federation=\['10'\]"):
            workspace.validate_evidence("room_versions", document, state["inventory"])

    def test_stale_or_failed_gate_prevents_mutation(self):
        state = self.state()
        workspace.advance(state, "PREFLIGHT", "operator", None)
        self.attest(state, "retained_rooms", "room_versions", "signing_identity")
        state["evidence"]["target_empty"] = workspace.validate_evidence(
            "target_empty", evidence("target_empty", stale=True), state["inventory"]
        )
        with self.assertRaisesRegex(workspace.Blocked, "target_empty: stale"):
            workspace.advance(state, "SEAL_SOURCE", "operator", None)
        self.assertEqual(state["authority"], "SYNAPSE_LIVE")

    def test_failed_probe_is_recorded_but_cannot_open_a_gate(self):
        state = self.state()
        workspace.advance(state, "PREFLIGHT", "operator", None)
        self.attest(state, "retained_rooms", "room_versions", "signing_identity")
        failed = evidence("target_empty", status="failed")
        failed["observations"] = {"empty_validated": False}
        state["evidence"]["target_empty"] = workspace.validate_evidence(
            "target_empty", failed, state["inventory"]
        )
        with self.assertRaisesRegex(workspace.Blocked, "target_empty: failed"):
            workspace.advance(state, "SEAL_SOURCE", "operator", None)

    def test_import_progress_is_monotonic_and_restart_safe(self):
        state = self.state()
        self.reach_import(state)
        first = {
            "rooms": 1,
            "events": 100,
            "bytes": 1024,
            "exclusions": 0,
            "checkpoint": "file:///durable/checkpoint-1",
            "complete": False,
        }
        workspace.update_import(state, first, "importer")
        with self.assertRaisesRegex(workspace.Blocked, "events must be a monotonic"):
            workspace.update_import(state, {**first, "events": 99}, "importer")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "workspace.json"
            workspace.atomic_json(path, state)
            restarted = workspace.load_json(path)
        self.assertEqual(restarted["import"], first)

    def test_v10_switch_requires_real_element_and_federation_claims(self):
        state = self.state()
        self.reach_validate(state)
        self.attest(state, *(workspace.GATES - set(state["evidence"])))
        state["evidence"]["element_e2ee"]["observations"]["room_version"] = "11"
        state["approvals"].append({"scope": "switch", "actor": "approver"})
        with self.assertRaisesRegex(workspace.Blocked, "v10 requires fresh-Element"):
            workspace.advance(state, "SWITCH", "operator", "migration-42")

    def test_switch_closes_rollback_and_recovery_is_separate(self):
        state = self.state()
        self.prepare_switch(state)
        workspace.advance(state, "SWITCH", "operator", "migration-42")
        self.assertEqual(state["authority"], "SPINDLE_LIVE")
        self.assertTrue(state["target_has_accepted_writes"])
        with self.assertRaisesRegex(workspace.Blocked, "ordinary rollback is closed"):
            workspace.rollback(state, "operator", "migration-42")
        state["authority"] = "RECOVERY_REQUIRED"
        pane = workspace.view(state)["Recovery"]
        self.assertEqual(pane["boundary"], "post-write recovery")
        self.assertFalse(pane["ordinary_rollback_available"])

    def test_prewrite_compensation_restores_synapse_authority(self):
        state = self.state()
        self.reach_import(state)
        workspace.rollback(state, "operator", "migration-42")
        self.assertEqual(state["phase"], "PREFLIGHT")
        self.assertEqual(state["authority"], "SYNAPSE_LIVE")

    def test_rehearsal_never_changes_source_authority(self):
        state = self.state("rehearsal")
        self.prepare_switch(state)
        workspace.advance(state, "SWITCH", "operator", "migration-42")
        self.assertEqual(state["authority"], "SYNAPSE_LIVE")
        self.assertFalse(state["target_has_accepted_writes"])

    def test_evidence_refuses_recovery_keys_and_decrypted_content(self):
        state = self.state()
        for field in ("recovery_key", "decrypted_content"):
            document = evidence("element_e2ee")
            document["observations"][field] = "must-not-persist"
            with self.assertRaisesRegex(workspace.Blocked, "cannot be stored"):
                workspace.validate_evidence(
                    "element_e2ee", document, state["inventory"]
                )

    def test_five_pane_view_contains_only_evidence_metadata(self):
        state = self.state()
        self.attest(state, "element_e2ee")
        result = workspace.view(state)
        self.assertEqual(
            set(result), {"Runbook", "Gates", "Evidence", "Resources", "Recovery"}
        )
        rendered = json.dumps(result)
        self.assertNotIn("historical_decryption", rendered)
        self.assertIn("probe/1.2.3", rendered)


if __name__ == "__main__":
    unittest.main()
