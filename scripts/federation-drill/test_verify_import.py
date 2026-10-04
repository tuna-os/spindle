"""Import report refusal regressions; no cluster or credential access."""

import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("verify_import", Path(__file__).with_name("verify-import.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture():
    return {
        "server_name": "reilly.asia", "dry_run": False,
        "phases_done": ["signing_key", "users", "devices", "cross_signing", "backups",
                        "account_data", "pushers", "receipts", "directory", "media"],
        "excluded_rooms": {},
        "domains": {"users": {"source": 2, "imported": 2}, "signing_key": {"imported": 1}},
        "rooms": {"!room:reilly.asia": {
            "rejection_policy_version": 3, "imported_events": 10, "pagination_positions": 10,
            "divergence": [], "resolver_disagreed": [], "signatures": {"verified": 10}}},
        "validation": {
            "rooms_checked": 1, "events_sampled": 10, "rooms_divergent": {}, "rooms_short": {},
            "sample_mismatches": [], "domains": {
                name: [2 if name == "users" else 1, []] for name in ["users", "devices", "device_keys", "cross_signing_keys",
                                          "account_data", "key_backup_sessions", "auth_context",
                                          "historical_rejections", "profiles", "cross_signing_signatures",
                                          "push_rules", "pushers", "receipts", "directory", "media"]}},
    }


class ImportProofTests(unittest.TestCase):
    def verify(self, report):
        return module.verify(report, {"!room:reilly.asia"}, {"@a:reilly.asia", "@b:reilly.asia"})

    def test_complete_fixture_passes(self):
        proof = self.verify(fixture())
        self.assertEqual(proof, {"passed": True, "rooms": 1, "users": 2, "events": 10,
                                 "sampled": 10, "rejection_policy_version": 3})

    def test_incomplete_or_mismatching_evidence_is_refused(self):
        cases = [
            (["server_name"], "other.test"), (["dry_run"], True), (["rooms"], {}),
            (["excluded_rooms"], {"!missing:reilly.asia": {}}), (["phases_done"], ["users"]),
            (["domains", "users", "source"], 3), (["domains", "users", "imported"], 1),
            (["domains", "signing_key", "imported"], 0),
            (["rooms", "!room:reilly.asia", "rejection_policy_version"], 0),
            (["rooms", "!room:reilly.asia", "pagination_positions"], 9),
            (["rooms", "!room:reilly.asia", "imported_events"], 0),
            (["rooms", "!room:reilly.asia", "divergence"], ["different"]),
            (["rooms", "!room:reilly.asia", "resolver_disagreed"], ["different"]),
            (["rooms", "!room:reilly.asia", "signatures"], {"verified": 9}),
            (["rooms", "!room:reilly.asia", "signatures"], {"unverifiable": 10}),
            (["rooms", "!room:reilly.asia", "signatures"], {"unknown": 10}),
            (["validation"], None), (["validation", "rooms_checked"], 0),
            (["validation", "events_sampled"], 0),
            (["validation", "rooms_divergent"], {"room": "different"}),
            (["validation", "rooms_short"], {"room": "short"}),
            (["validation", "sample_mismatches"], ["different"]),
            (["validation", "domains", "users"], [2, ["different"]]),
            (["validation", "domains", "users"], [1, []]),
            (["validation", "domains", "key_backup_sessions"], [0, []]),
        ]
        for path, value in cases:
            with self.subTest(path=path, value=value):
                report = copy.deepcopy(fixture())
                parent = report
                for key in path[:-1]:
                    parent = parent[key]
                parent[path[-1]] = value
                with self.assertRaises(module.ProofError):
                    self.verify(report)

    def test_required_domain_cannot_be_omitted(self):
        for domain in fixture()["validation"]["domains"]:
            with self.subTest(domain=domain):
                report = fixture()
                del report["validation"]["domains"][domain]
                with self.assertRaises(module.ProofError):
                    self.verify(report)

    def test_fixture_ids_must_be_nonempty_and_unique(self):
        for csv in ["", "a,", "a,a"]:
            with self.subTest(csv=csv), self.assertRaises(module.ProofError):
                module.identifiers(csv)


if __name__ == "__main__":
    unittest.main()
