#!/usr/bin/env python3
"""Integration-shaped tests for the ESS driver with an in-memory Kubernetes API."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("ess-kubernetes-driver.py")
SPEC = importlib.util.spec_from_file_location("ess_driver", MODULE_PATH)
ess = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ess
assert SPEC.loader is not None
SPEC.loader.exec_module(ess)


ROLES = [
    ("synapse", "StatefulSet"),
    ("federation-sender", "StatefulSet"),
    ("sliding-sync", "StatefulSet"),
    ("mas", "Deployment"),
    ("postgres", "StatefulSet"),
    ("media", "Deployment"),
    ("element-call", "Deployment"),
    ("livekit", "Deployment"),
]


def workload(name, kind, replicas=1):
    return {
        "apiVersion": "apps/v1",
        "kind": kind,
        "metadata": {
            "name": name,
            "uid": f"uid-{name}",
            "resourceVersion": "1",
            "labels": {"spindle.tunaos.org/deployment": "matrix"},
        },
        "spec": {
            "replicas": replicas,
            "selector": {"matchLabels": {"app": name}},
        },
        "status": {
            "observedGeneration": 1,
            "replicas": replicas,
            "readyReplicas": replicas,
            "availableReplicas": replicas,
        },
    }


def ingress(service="synapse-client"):
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {"name": "matrix", "uid": "uid-ingress", "resourceVersion": "1"},
        "spec": {
            "rules": [
                {
                    "host": "matrix.example.org",
                    "http": {
                        "paths": [
                            {
                                "path": "/",
                                "pathType": "Prefix",
                                "backend": {"service": {"name": service, "port": {"name": "http"}}},
                            }
                        ]
                    },
                }
            ]
        },
        "status": {"loadBalancer": {"ingress": [{"ip": "192.0.2.1"}]}},
    }


def topology():
    return {
        "profile": "ess-v1",
        "scope": {"namespace": "ess", "selector": "spindle.tunaos.org/deployment=matrix"},
        "workloads": [
            {"name": role.replace("-", "_"), "kind": kind, "role": role} for role, kind in ROLES
        ],
        "routes": [
            {
                "kind": "Ingress",
                "name": "matrix",
                "host": "matrix.example.org",
                "path": "/",
                "source_service": "synapse-client",
                "target_service": "spindle-client",
            }
        ],
        "postgres": {
            "namespace": "ess",
            "pod_selector": "app=postgres",
            "databases": ["synapse", "mas"],
        },
    }


class FakeKube:
    def __init__(self):
        self.objects = {}
        for role, kind in ROLES:
            item = workload(role.replace("-", "_"), kind)
            self.objects[(kind.lower(), item["metadata"]["name"])] = item
        self.objects[("ingress", "matrix")] = ingress()
        self.sessions = 0
        self.patches = []
        self.conflict_once = False
        self.freeze_workload = None
        self.freeze_route = False

    def list(self, kind, namespace, selector):
        if kind == "pods":
            return [{"metadata": {"name": "postgres-0"}, "status": {"phase": "Running"}}]
        return [copy.deepcopy(value) for (item_kind, _), value in self.objects.items() if item_kind == kind]

    def get(self, kind, name, namespace):
        return copy.deepcopy(self.objects[(kind, name)])

    def postgres_sessions(self, config):
        return self.sessions

    def patch(self, kind, name, namespace, patch):
        if self.conflict_once:
            self.conflict_once = False
            raise ess.Conflict("resource version changed")
        value = self.objects[(kind, name)]
        before = value["metadata"]["resourceVersion"]
        if patch[0]["value"] != before:
            raise ess.Conflict("resource version changed")
        operation = patch[-1]
        if operation["path"] == "/spec/replicas":
            value["spec"]["replicas"] = operation["value"]
            if self.freeze_workload != name:
                value["status"]["replicas"] = operation["value"]
                value["status"]["readyReplicas"] = operation["value"]
                value["status"]["availableReplicas"] = operation["value"]
        elif not self.freeze_route:
            value["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"]["name"] = operation["value"]
        value["metadata"]["resourceVersion"] = str(int(before) + 1)
        self.patches.append((kind, name, copy.deepcopy(patch)))
        return copy.deepcopy(value)


class FastClock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        self.value += 1.0
        return self.value


class DriverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.state = Path(self.temporary.name) / "operation.json"
        self.kube = FakeKube()
        self.driver = ess.Driver(
            self.kube,
            topology(),
            self.state,
            timeout=3,
            interval=0,
            clock=FastClock(),
            sleep=lambda _: None,
        )

    def tearDown(self):
        self.temporary.cleanup()

    def validation(self):
        path = Path(self.temporary.name) / "validation.json"
        path.write_text(
            json.dumps(
                {
                    "passed": True,
                    "assessment_id": "assessment-42",
                    "target": "spindle/matrix",
                    "expires_at": "2999-01-01T00:00:00Z",
                    "observations": {"secret": "this field must not be checkpointed"},
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_discovery_is_complete_redacted_and_plan_is_read_only(self):
        before = copy.deepcopy(self.kube.objects)
        discovered = self.driver.discover()
        plan = self.driver.plan(discovered)
        self.assertEqual({item["role"] for item in discovered["workloads"]}, set(ess.ROLES))
        self.assertEqual(discovered["postgres_sessions"], 0)
        self.assertTrue(plan["read_only"])
        self.assertEqual(self.kube.objects, before)
        self.assertEqual(self.kube.patches, [])

    def test_ambiguous_selector_is_an_actionable_block(self):
        extra = workload("mystery-writer", "Deployment")
        self.kube.objects[("deployment", "mystery-writer")] = extra
        with self.assertRaisesRegex(ess.Blocked, "unrecognized selected workloads"):
            self.driver.discover()

    def test_partial_scale_down_is_preserved_and_restart_does_not_repeat_mutations(self):
        synapse = self.kube.objects[("statefulset", "synapse")]
        synapse["spec"]["replicas"] = 0
        synapse["status"].update({"replicas": 0, "readyReplicas": 0, "availableReplicas": 0})
        first = self.driver.quiesce()
        patch_count = len(self.kube.patches)
        second = self.driver.quiesce()
        self.assertEqual(len(self.kube.patches), patch_count)
        original = next(item for item in first["snapshot"]["workloads"] if item["role"] == "synapse")
        self.assertEqual(original["replicas"], 0)
        self.assertEqual(second["phase"], "source-sealed")

    def test_stale_resource_version_stops_without_skipping_the_step(self):
        self.kube.conflict_once = True
        with self.assertRaises(ess.Conflict):
            self.driver.quiesce()
        checkpoint = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(checkpoint["completed"], [])
        resumed = self.driver.quiesce()
        self.assertEqual(resumed["phase"], "source-sealed")

    def test_unavailable_pod_blocks_convergence(self):
        self.kube.freeze_workload = "mas"
        with self.assertRaisesRegex(ess.Blocked, "did not converge"):
            self.driver.quiesce()
        checkpoint = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertIn("fence:deployment/mas", checkpoint["completed"])
        self.assertNotEqual(checkpoint["phase"], "source-sealed")

    def test_switch_requires_validation_and_zero_database_sessions(self):
        self.driver.quiesce()
        bad = Path(self.temporary.name) / "bad.json"
        bad.write_text('{"passed": false}', encoding="utf-8")
        with self.assertRaisesRegex(ess.Blocked, "has not passed"):
            self.driver.switch(bad)
        self.kube.sessions = 1
        with self.assertRaisesRegex(ess.Blocked, "still has 1"):
            self.driver.switch(self.validation())
        self.kube.sessions = 0
        switched = self.driver.switch(self.validation())
        self.assertEqual(switched["phase"], "target-written")
        self.assertNotIn("observations", switched["validation"])
        route = self.kube.objects[("ingress", "matrix")]
        service = route["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"]["name"]
        self.assertEqual(service, "spindle-client")

    def test_failed_ingress_convergence_is_checkpointed_and_retryable(self):
        self.driver.quiesce()
        self.kube.freeze_route = True
        with self.assertRaisesRegex(ess.Blocked, "did not converge"):
            self.driver.switch(self.validation())
        checkpoint = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertIn("switch:ingress/matrix:/", checkpoint["completed"])
        self.assertEqual(checkpoint["phase"], "switching")
        with self.assertRaisesRegex(ess.Blocked, "forbidden"):
            self.driver.rollback()
        self.kube.freeze_route = False
        switched = self.driver.switch(self.validation())
        self.assertEqual(switched["phase"], "target-written")

    def test_pre_write_rollback_restores_exact_replicas_and_route(self):
        self.kube.objects[("statefulset", "federation_sender")]["spec"]["replicas"] = 3
        self.kube.objects[("statefulset", "federation_sender")]["status"].update(
            {"replicas": 3, "readyReplicas": 3, "availableReplicas": 3}
        )
        self.driver.quiesce()
        rolled_back = self.driver.rollback()
        self.assertEqual(rolled_back["phase"], "rolled-back")
        self.assertEqual(self.kube.objects[("statefulset", "federation_sender")]["spec"]["replicas"], 3)
        service = self.kube.objects[("ingress", "matrix")]["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"]["name"]
        self.assertEqual(service, "synapse-client")

    def test_post_write_rollback_is_forbidden(self):
        self.driver.quiesce()
        self.driver.switch(self.validation())
        with self.assertRaisesRegex(ess.Blocked, "forbidden"):
            self.driver.rollback()


if __name__ == "__main__":
    unittest.main()
