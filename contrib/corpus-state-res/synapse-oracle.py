#!/usr/bin/env python3
"""Resolve an opt-in corpus fixture with an installed Synapse (no DB writes)."""
import asyncio
import json
import sys

# Match Synapse's initialization order to avoid a state/event_auth import cycle.
import synapse.event_auth  # noqa: F401
from synapse.api.room_versions import KNOWN_ROOM_VERSIONS
from synapse.events import make_event_from_dict
from synapse.state.v2 import resolve_events_with_store
from synapse.storage.databases.main.event_federation import StateDifference


async def replay(path):
    with open(path) as source:
        fixture = json.load(source)
    bodies = fixture["bodies"]
    create = next(body for body in bodies.values() if body["type"] == "m.room.create")
    version = KNOWN_ROOM_VERSIONS[create["content"].get("room_version", "1")]
    rejected = set(fixture["rejected"])
    events = {}
    missing_auth = set()
    for event_id, body in bodies.items():
        body = dict(body, room_id=fixture["room_id"])
        if version.event_format == 1:
            body["event_id"] = event_id
        else:
            body.pop("event_id", None)
        events[event_id] = make_event_from_dict(
            body, version, rejected_reason="auth_error" if event_id in rejected else None
        )
        if events[event_id].event_id != event_id:
            raise ValueError("Fixture event ID does not match its original signed PDU")

    class Clock:
        async def sleep(self, duration):
            await asyncio.sleep(0)

    class Store:
        async def get_events(self, ids, allow_rejected=False):
            return {
                event_id: events[event_id]
                for event_id in ids
                if event_id in events
                and (allow_rejected or not events[event_id].rejected_reason)
            }

        async def get_auth_chain_difference(self, room, states, conflicted, extra):
            if version.state_res != 2:
                raise ValueError("This diagnostic supports state resolution v2 only")
            chains = []
            for state in states:
                seen, pending = set(), list(state)
                while pending:
                    event_id = pending.pop()
                    if event_id in seen:
                        continue
                    seen.add(event_id)
                    event = events.get(event_id)
                    if event is None:
                        # Synapse can retain references to historical PDUs it
                        # does not have. Keep the referenced ID in the chain,
                        # and report this limitation instead of fabricating it.
                        missing_auth.add(event_id)
                        continue
                    pending.extend(event.auth_event_ids())
                chains.append(seen)
            difference = set.union(*chains) - set.intersection(*chains)
            return StateDifference(difference, None)

    to_state = lambda rows: {(kind, key): event_id for kind, key, event_id in rows}
    resolved = await resolve_events_with_store(
        Clock(), fixture["room_id"], version,
        [to_state(rows) for rows in fixture["parents"]], None, Store()
    )
    ignore = tuple(fixture["ignore"]) if fixture["ignore"] else None

    def differences(rows):
        other = to_state(rows)
        return sum(
            resolved.get(key) != other.get(key)
            for key in resolved.keys() | other.keys() if key != ignore
        )

    # Only counts and identifiers are printed; PDU bodies remain in the private fixture.
    print(json.dumps({
        "room_id": fixture["room_id"], "event_id": fixture["event_id"],
        "room_version": version.identifier,
        "synapse_differs_from_source": differences(fixture["expected"]),
        "synapse_differs_from_live": differences(fixture["live"]),
        "masked_own_slot": ignore is not None,
        "unavailable_auth_pdus": len(missing_auth),
    }))


if __name__ == "__main__":
    asyncio.run(replay(sys.argv[1]))
