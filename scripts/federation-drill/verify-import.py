#!/usr/bin/env python3
"""Refuse a drill cutover without complete full-import read-back evidence."""

import argparse
import hashlib
import json
from pathlib import Path


class ProofError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise ProofError(reason)


def identifiers(csv):
    values = csv.split(",")
    require(all(values) and len(values) == len(set(values)), "empty or duplicate expected ID")
    return set(values)


def verify(report, expected_rooms, expected_users):
    require(report["server_name"] == "reilly.asia", "wrong server name")
    require(report["dry_run"] is False, "dry run cannot prove a written store")
    require(set(report["rooms"]) == expected_rooms, "imported rooms differ from expected rooms")
    require(not report["excluded_rooms"], "a drill room was excluded")
    phases = {"signing_key", "users", "devices", "cross_signing", "backups",
              "account_data", "pushers", "receipts", "directory", "media"}
    require(phases <= set(report["phases_done"]), "an import phase is incomplete")
    require(all(user.startswith("@") and user.endswith(":reilly.asia")
                for user in expected_users), "expected users must belong to the drill server")
    accounts = report["domains"]["users"]
    require(accounts["source"] == accounts["imported"] == len(expected_users),
            "not every expected account was imported")
    require(report["domains"]["signing_key"]["imported"] == 1, "server key was not imported")
    for room in report["rooms"].values():
        require(room["rejection_policy_version"] == 3, "historical rejection policy is absent")
        require(room["imported_events"] > 0, "an imported room has no timeline")
        require(room["pagination_positions"] == room["imported_events"],
                "cached pagination positions are incomplete")
        require(not room["divergence"] and not room["resolver_disagreed"],
                "room replay disagrees with Synapse")
        require(room["signatures"].get("unverifiable", 0) == 0,
                "a drill event's signatures could not be verified")
        accepted = {"verified", "verified with an older key under a reused key ID",
                    "signatures verify, received redacted"}
        require(set(room["signatures"]) <= accepted | {"unverifiable"},
                "unknown signature outcome")
        require(sum(room["signatures"].values()) == room["imported_events"],
                "not every timeline event's signatures were checked")
    validation = report.get("validation")
    require(isinstance(validation, dict), "read-back validation is absent")
    require(validation["rooms_checked"] == len(expected_rooms), "not every room was checked")
    require(validation["events_sampled"] > 0, "no persisted event bodies were sampled")
    for field in ["rooms_divergent", "rooms_short", "sample_mismatches"]:
        require(not validation[field], "read-back validation failed: " + field)
    for domain, (rows, mismatches) in validation["domains"].items():
        require(rows >= 0 and not mismatches, "read-back domain mismatch: " + domain)
    required_domains = {"users", "profiles", "devices", "device_keys", "cross_signing_keys",
                        "cross_signing_signatures", "account_data", "key_backup_sessions",
                        "push_rules", "pushers", "receipts", "directory", "media",
                        "auth_context", "historical_rejections"}
    require(required_domains <= set(validation["domains"]), "read-back domains are incomplete")
    require(validation["domains"]["users"][0] == len(expected_users),
            "not every imported account was checked")
    # These nonempty domains establish that the encrypted drill fixture was
    # imported. Counts cannot substitute for the later client decryption check.
    for domain in ["users", "devices", "device_keys", "cross_signing_keys",
                   "account_data", "key_backup_sessions", "auth_context"]:
        require(validation["domains"].get(domain, [0])[0] > 0,
                "required fixture domain was not checked: " + domain)
    require("historical_rejections" in validation["domains"],
            "historical rejection continuity was not checked")
    return {"passed": True, "rooms": len(expected_rooms), "users": len(expected_users),
            "events": sum(room["imported_events"] for room in report["rooms"].values()),
            "sampled": validation["events_sampled"], "rejection_policy_version": 3}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("rooms", help="expected room IDs, comma separated")
    parser.add_argument("users", help="expected local user IDs, comma separated")
    args = parser.parse_args()
    try:
        body = args.report.read_bytes()
        proof = verify(json.loads(body), identifiers(args.rooms), identifiers(args.users))
        proof["report_sha256"] = hashlib.sha256(body).hexdigest()
    except (OSError, KeyError, TypeError, ValueError) as error:
        parser.exit(1, "full-import proof refused: " + str(error) + "\n")
    print(json.dumps(proof, sort_keys=True))


if __name__ == "__main__":
    main()
