//! MSC3995 linearized hub mode between Spindles: the first slice (#22).
//!
//! Built only with `--features hub-mode`; `hub_mode_disabled.rs` is its
//! counterpart for the default build. Every test here runs real servers on
//! loopback, each behind a proxy that can cut it off (`support/hub_rig.rs`).
//!
//! What is under test, from SPEC section 12.6:
//!
//! - the capability probe and the routes exist only with the switch on;
//! - a participant's events are placed by the room's hub, so two servers
//!   sending at once still produce one chain, in the same order on both,
//!   with the hub's signed attestation for every entry;
//! - a server that does not speak hub mode, in the same room, receives only
//!   ordinary events and nothing namespaced, and the room converges;
//! - a participant cut off from its hub keeps sending, ordinarily, and the
//!   room heals once the partition does;
//! - a hub that signs two different things for one position is caught,
//!   with a proof anyone holding its key can check.

#![cfg(feature = "hub-mode")]

#[path = "support/hub_rig.rs"]
mod hub_rig;

use hub_rig::{Node, eventually};
use serde_json::{Value, json};

/// A room hubbed by `hub`, with `alice` (on `hub`) and one user per other
/// node joined: `(room, alice's token, the joiners' tokens)`.
async fn hub_room(hub: &Node, others: &[&Node]) -> (String, String, Vec<String>) {
    let (alice, _) = hub.register("alice").await;
    let room = hub.create_room(&alice).await;
    hub.designate_hub(&alice, &room).await;
    let mut tokens = Vec::new();
    for (index, node) in others.iter().enumerate() {
        let (token, user) = node.register(&format!("user{index}")).await;
        node.join(&token, &room, hub).await;
        // The join reaches every server already in the room before anyone
        // relies on it there.
        for server in std::iter::once(hub).chain(others[..=index].iter().copied()) {
            assert!(
                eventually(10, async || {
                    server
                        .state
                        .rooms
                        .joined_member_ids(&room)
                        .is_ok_and(|members| members.contains(&user))
                })
                .await,
                "{user}'s join reaches {}",
                server.name
            );
        }
        tokens.push(token);
    }
    // Every server reads the same hub off the room's state.
    for server in std::iter::once(hub).chain(others.iter().copied()) {
        assert_eq!(
            server
                .state
                .rooms
                .hub_designation(&room)
                .unwrap()
                .map(|hub| hub.server),
            Some(hub.name.clone()),
            "{} sees the hub",
            server.name
        );
    }
    (room, alice, tokens)
}

/// Every event in `ids` has exactly one parent at `node`: a chain.
fn single_parent(node: &Node, room: &str, ids: &[String]) -> bool {
    ids.iter().all(|id| {
        node.pdu(room, id)["prev_events"]
            .as_array()
            .is_some_and(|parents| parents.len() == 1)
    })
}

/// The event IDs `node` holds attestations for in `room`.
fn attested(node: &Node, room: &str) -> Vec<String> {
    spindle_server::hub::attestations(&node.store, room)
        .unwrap()
        .iter()
        .filter_map(|attestation| attestation["event_id"].as_str().map(str::to_owned))
        .collect()
}

#[tokio::test]
async fn the_hub_surface_exists_only_with_the_switch_on() {
    let on = Node::start(true).await;
    let off = Node::start(false).await;
    let path = "/_matrix/federation/unstable/org.spindle.msc3995/capabilities";

    let (status, body) = on.request(reqwest::Method::GET, path, None, None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["org.spindle.msc3995"]["hub"], json!(true), "{body}");

    // Same binary, switch off: the path is one the server does not speak.
    let (status, body) = off.request(reqwest::Method::GET, path, None, None).await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["errcode"], "M_UNRECOGNIZED", "{body}");
    let (status, body) = off
        .request(
            reqwest::Method::POST,
            "/_matrix/federation/unstable/org.spindle.msc3995/submit/!r:x",
            None,
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, 404, "{body}");
}

#[tokio::test]
async fn two_spindles_sending_at_once_get_one_chain_in_the_hubs_order() {
    let hub = Node::start(true).await;
    let participant = Node::start(true).await;
    let (room, alice, tokens) = hub_room(&hub, &[&participant]).await;
    let bob = &tokens[0];

    // Both servers send at once, interleaved, messages and state alike.
    // Without a hub, concurrent sends from two servers fork the DAG
    // whenever one lands before the other's arrives.
    let from_hub = async {
        let mut ids = Vec::new();
        for n in 0..6 {
            ids.push(hub.say(&alice, &room, &format!("hub {n}")).await);
        }
        ids
    };
    let from_participant = async {
        let mut ids = Vec::new();
        for n in 0..6 {
            if n == 3 {
                ids.push(participant.set_topic(bob, &room, "set via the hub").await);
            } else {
                ids.push(
                    participant
                        .say(bob, &room, &format!("participant {n}"))
                        .await,
                );
            }
        }
        ids
    };
    let (hub_ids, participant_ids) = tokio::join!(from_hub, from_participant);
    let all: Vec<String> = hub_ids.iter().chain(&participant_ids).cloned().collect();

    assert!(
        eventually(15, async || all
            .iter()
            .all(|id| hub.holds(&room, id) && participant.holds(&room, id)))
        .await,
        "every event reaches both servers"
    );

    // The hub placed every one of the participant's events; none needed the
    // ordinary fallback.
    let counts = participant.state.hub.counts();
    assert_eq!(counts.submitted, 6, "{counts:?}");
    assert_eq!(counts.fallbacks, 0, "{counts:?}");
    assert!(hub.state.hub.counts().sequenced >= 6);

    // One chain: every event names exactly one parent, on both servers,
    // and neither server is left with a fork.
    assert!(single_parent(&hub, &room, &all), "the hub's log is a chain");
    assert!(single_parent(&participant, &room, &all));
    for node in [&hub, &participant] {
        assert_eq!(
            node.state.rooms.forward_extremity_count(&room).unwrap(),
            1,
            "{} has one head",
            node.name
        );
    }

    // In the same order on both.
    let at_hub = hub.messages(&alice, &room).await;
    let at_participant = participant.messages(bob, &room).await;
    assert_eq!(at_hub, at_participant, "both servers show one order");
    assert_eq!(
        hub.state_ids(&alice, &room).await,
        participant.state_ids(bob, &room).await
    );

    // The hub attested every entry it ordered -- its own users' events and
    // the participant's alike -- and the attestations chain.
    assert!(
        eventually(10, async || {
            let held = attested(&participant, &room);
            all.iter().all(|id| held.contains(id))
        })
        .await,
        "the participant holds an attestation for every event: {:?}",
        attested(&participant, &room)
    );
    let counts = participant.state.hub.counts();
    assert_eq!(counts.equivocations, 0, "{counts:?}");
    assert_eq!(counts.attestations_rejected, 0, "{counts:?}");
    assert!(
        spindle_server::hub::equivocation_proofs(&participant.store, &room)
            .unwrap()
            .is_empty()
    );
    let attestations = spindle_server::hub::attestations(&participant.store, &room).unwrap();
    for pair in attestations.windows(2) {
        if pair[1]["li"].as_i64() == pair[0]["li"].as_i64().map(|li| li + 1) {
            assert_eq!(pair[0]["hub"], json!(hub.name));
        }
    }
}

#[tokio::test]
async fn a_server_that_does_not_speak_hub_mode_sees_an_ordinary_room_that_converges() {
    let hub = Node::start(true).await;
    let participant = Node::start(true).await;
    // The stand-in for Synapse: a server with hub mode off. Its own events
    // name its own head, so with three servers sending at once the DAG
    // forks; that is the class-D room SPEC section 12.3 describes.
    let ordinary = Node::start(false).await;
    let (room, alice, tokens) = hub_room(&hub, &[&participant, &ordinary]).await;
    let (bob, carol) = (&tokens[0], &tokens[1]);

    let sends = async {
        let mut ids = Vec::new();
        for n in 0..4 {
            ids.push(hub.say(&alice, &room, &format!("hub {n}")).await);
        }
        ids
    };
    let submits = async {
        let mut ids = Vec::new();
        for n in 0..4 {
            ids.push(
                participant
                    .say(bob, &room, &format!("participant {n}"))
                    .await,
            );
        }
        ids
    };
    let ordinary_sends = async {
        let mut ids = Vec::new();
        for n in 0..4 {
            ids.push(ordinary.say(carol, &room, &format!("ordinary {n}")).await);
        }
        ids
    };
    let (a, b, c) = tokio::join!(sends, submits, ordinary_sends);
    let mut all: Vec<String> = a.into_iter().chain(b).chain(c).collect();
    // One more event from each hub-mode server merges whatever forked.
    all.push(hub.say(&alice, &room, "merge").await);

    let nodes = [&hub, &participant, &ordinary];
    assert!(
        eventually(20, async || {
            all.iter()
                .all(|id| nodes.iter().all(|node| node.holds(&room, id)))
        })
        .await,
        "every event reaches every server"
    );
    // Converged: the same current state everywhere, and the same events.
    assert!(
        eventually(20, async || {
            let hub_state = hub.state_ids(&alice, &room).await;
            hub_state == participant.state_ids(bob, &room).await
                && hub_state == ordinary.state_ids(carol, &room).await
        })
        .await,
        "the three servers agree on the room's state"
    );
    let mut seen: Vec<Vec<String>> = Vec::new();
    for (node, token) in [(&hub, &alice), (&participant, bob), (&ordinary, carol)] {
        let mut ids = node.messages(token, &room).await;
        ids.sort();
        seen.push(ids);
    }
    assert_eq!(seen[0], seen[1]);
    assert_eq!(seen[0], seen[2]);

    // The participant still went through the hub; forks from the ordinary
    // server only made it catch up first.
    let counts = participant.state.hub.counts();
    assert_eq!(counts.submitted, 4, "{counts:?}");
    assert_eq!(counts.fallbacks, 0, "{counts:?}");

    // Nothing hub-shaped reached the ordinary server: every event it holds
    // is an ordinary PDU with no Spindle or MSC3995 field, and it was sent
    // no hub EDU at all (the hub's probe found it does not speak hub mode).
    for id in &all {
        let pdu = ordinary.pdu(&room, id).to_string();
        assert!(
            !pdu.contains("org.spindle") && !pdu.contains("hub_server"),
            "{pdu}"
        );
    }
    let other_edus: u64 = spindle_server::metrics::EduResult::ALL
        .iter()
        .map(|result| {
            ordinary
                .state
                .metrics
                .edu_received_count(spindle_server::metrics::EduType::Other, *result)
        })
        .sum();
    assert_eq!(other_edus, 0, "the ordinary server was sent no hub EDU");
}

#[tokio::test]
async fn a_participant_cut_off_from_its_hub_keeps_sending_and_the_room_heals() {
    let hub = Node::start(true).await;
    let participant = Node::start(true).await;
    let (room, alice, tokens) = hub_room(&hub, &[&participant]).await;
    let bob = &tokens[0];

    let before = participant.say(bob, &room, "before").await;
    assert_eq!(participant.state.hub.counts().submitted, 1);

    // Partition. The participant's send is not refused and does not hang:
    // the hub cannot place it, so it goes out the ordinary way and waits in
    // the outbox. The hub keeps serving its own users meanwhile.
    hub.partition(true);
    participant.partition(true);
    let during = participant.say(bob, &room, "during").await;
    let concurrent = hub.say(&alice, &room, "concurrent").await;
    let counts = participant.state.hub.counts();
    assert_eq!(counts.fallbacks, 1, "{counts:?}");
    assert!(!hub.holds(&room, &during), "the partition holds");
    assert!(!participant.holds(&room, &concurrent));

    // Heal: both sides' outboxes deliver, and the fork the partition made
    // is merged by the hub's next event.
    hub.partition(false);
    participant.partition(false);
    assert!(
        eventually(20, async || hub.holds(&room, &during)
            && participant.holds(&room, &concurrent))
        .await,
        "the partition's events cross once it heals"
    );
    let merge = hub.say(&alice, &room, "merge").await;
    let parents: Vec<String> = hub.pdu(&room, &merge)["prev_events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap().to_owned())
        .collect();
    assert!(
        parents.contains(&during) && parents.contains(&concurrent),
        "the hub's next event merges both sides: {parents:?}"
    );

    // And the hub orders the participant's events again.
    assert!(
        eventually(10, async || participant.holds(&room, &merge)).await,
        "the merge reaches the participant"
    );
    let after = participant.say(bob, &room, "after").await;
    let counts = participant.state.hub.counts();
    assert_eq!(counts.submitted, 2, "{counts:?}");
    assert_eq!(counts.fallbacks, 1, "{counts:?}");
    assert_eq!(
        participant.pdu(&room, &after)["prev_events"],
        json!([merge]),
        "the participant's next event extends the hub's head"
    );
    assert!(
        eventually(10, async || hub.holds(&room, &after)).await,
        "it is at the hub"
    );
    for id in [&before, &during, &concurrent, &merge, &after] {
        assert!(hub.holds(&room, id) && participant.holds(&room, id));
    }
    // The partition's two events are in arrival order on each side -- that
    // is what a fork is -- but everything from the merge on is one order.
    let (at_hub, at_participant) = (
        hub.messages(&alice, &room).await,
        participant.messages(bob, &room).await,
    );
    let mut sorted = (at_hub.clone(), at_participant.clone());
    sorted.0.sort();
    sorted.1.sort();
    assert_eq!(sorted.0, sorted.1, "the same messages on both");
    assert_eq!(
        at_hub[at_hub.len() - 2..],
        at_participant[at_participant.len() - 2..],
        "one order from the merge on"
    );
    assert_eq!(
        hub.state_ids(&alice, &room).await,
        participant.state_ids(bob, &room).await
    );
}

#[tokio::test]
async fn a_hub_that_signs_two_entries_for_one_position_is_caught_with_a_portable_proof() {
    let hub = Node::start(true).await;
    let participant = Node::start(true).await;
    let (room, _alice, tokens) = hub_room(&hub, &[&participant]).await;
    let bob = &tokens[0];
    let event = participant.say(bob, &room, "attested").await;

    let held = spindle_server::hub::attestations(&participant.store, &room).unwrap();
    let honest = held
        .iter()
        .find(|attestation| attestation["event_id"] == json!(event))
        .cloned()
        .expect("the hub's answer carried an attestation");

    // The hub now claims a different event at the same position, signed
    // with its real key.
    let mut lie = honest.clone();
    lie.as_object_mut().unwrap().remove("signatures");
    lie["event_id"] = json!("$not-what-the-hub-said-before");
    let ruma::CanonicalJsonValue::Object(mut lie) =
        ruma::CanonicalJsonValue::try_from(lie).unwrap()
    else {
        unreachable!()
    };
    ruma::signatures::sign_json(&hub.name, hub.state.key.pair(), &mut lie).unwrap();
    let lie = serde_json::to_value(&lie).unwrap();
    let uri = "/_matrix/federation/v1/send/equivocate";
    let body = json!({
        "origin": hub.name,
        "origin_server_ts": 0,
        "pdus": [],
        "edus": [{
            "edu_type": "org.spindle.msc3995.attestations",
            "content": { "room_id": room, "attestations": [lie] },
        }],
    });
    let (status, answer) = hub.federation_put(&participant, uri, &body).await;
    assert_eq!(status, 200, "{answer}");

    let proofs = spindle_server::hub::equivocation_proofs(&participant.store, &room).unwrap();
    assert_eq!(proofs.len(), 1, "{proofs:?}");
    let proof = &proofs[0];
    assert_eq!(proof["kind"], "org.spindle.msc3995.equivocation");
    assert_eq!(proof["reason"], "conflicting_entries");
    assert_eq!(participant.state.hub.counts().equivocations, 1);
    // The first answer is what the participant keeps.
    let kept = spindle_server::hub::attestations(&participant.store, &room).unwrap();
    assert!(kept.iter().any(|attestation| attestation == &honest));

    // Portable: both halves verify against nothing but the hub's public
    // key, and they name different events at one position.
    let mut keys = ruma::signatures::PublicKeyMap::new();
    keys.entry(hub.name.clone()).or_default().insert(
        hub.state.key.key_id(),
        ruma::serde::Base64::new(hub.state.key.pair().public_key().to_vec()),
    );
    let pair: Vec<Value> = proof["attestations"].as_array().unwrap().clone();
    assert_eq!(pair.len(), 2);
    for half in &pair {
        let ruma::CanonicalJsonValue::Object(object) =
            ruma::CanonicalJsonValue::try_from(half.clone()).unwrap()
        else {
            unreachable!()
        };
        ruma::signatures::verify_json(&keys, &object).expect("signed by the hub");
    }
    assert_eq!(pair[0]["li"], pair[1]["li"]);
    assert_ne!(pair[0]["event_id"], pair[1]["event_id"]);
}
