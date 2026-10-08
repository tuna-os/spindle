//! The default build carries no MSC3995 hub mode at all (#22's first exit
//! criterion: "feature-disabled builds contain no unstable wire behavior").
//!
//! Built only *without* `--features hub-mode`; `hub_mode.rs` is its
//! counterpart. What a build without the feature must not do:
//!
//! - serve any hub endpoint, or name one in its route table;
//! - accept `[federation.hub] enabled = true` and then quietly ignore it;
//! - put anything namespaced for hub mode into what it sends a peer, or act
//!   on an `m.room.hub` event: in a room that has one, two such servers
//!   exchange ordinary events and nothing else, and an attestation EDU sent
//!   to one is dropped as the unknown EDU it is.

#![cfg(not(feature = "hub-mode"))]

#[path = "support/hub_rig.rs"]
mod hub_rig;

use hub_rig::{Node, eventually};
use serde_json::json;
use spindle_server::metrics::{EduResult, EduType};

#[test]
fn the_route_table_names_no_hub_endpoint() {
    for path in spindle_server::routes::MOUNTED {
        assert!(
            !path.contains("msc3995") && !path.contains("org.spindle"),
            "{path} is hub mode's"
        );
    }
}

#[test]
fn a_config_that_turns_hub_mode_on_is_refused_rather_than_ignored() {
    let refused = spindle_server::Config::parse(
        "[server]\nname = \"example.org\"\n[federation.hub]\nenabled = true\n",
    )
    .expect_err("this build cannot honour the switch");
    assert!(refused.to_string().contains("hub-mode"), "{refused}");
    // Off, or absent, is the same as every config before the section
    // existed.
    spindle_server::Config::parse(
        "[server]\nname = \"example.org\"\n[federation.hub]\nenabled = false\n",
    )
    .expect("off is fine");
}

#[tokio::test]
async fn no_hub_endpoint_answers_and_nothing_hub_shaped_crosses_the_wire() {
    let first = Node::start(false).await;
    let second = Node::start(false).await;

    for (method, path) in [
        (
            reqwest::Method::GET,
            "/_matrix/federation/unstable/org.spindle.msc3995/capabilities",
        ),
        (
            reqwest::Method::POST,
            "/_matrix/federation/unstable/org.spindle.msc3995/submit/!r:example.org",
        ),
    ] {
        let (status, body) = first.request(method, path, None, Some(&json!({}))).await;
        assert_eq!(status, 404, "{path}: {body}");
        assert_eq!(body["errcode"], "M_UNRECOGNIZED", "{path}: {body}");
    }
    let (status, keys) = first
        .request(reqwest::Method::GET, "/_matrix/key/v2/server", None, None)
        .await;
    assert_eq!(status, 200);
    assert!(!keys.to_string().contains("msc3995"), "{keys}");
    assert!(!keys.to_string().contains("linearized"), "{keys}");

    // A room with an `m.room.hub` in it is an ordinary room here: the
    // event is just state, and both servers author their own events.
    let (alice, _) = first.register("alice").await;
    let room = first.create_room(&alice).await;
    first.designate_hub(&alice, &room).await;
    let (bob, bob_id) = second.register("bob").await;
    second.join(&bob, &room, &first).await;
    assert!(
        eventually(10, async || first
            .state
            .rooms
            .joined_member_ids(&room)
            .is_ok_and(|members| members.contains(&bob_id)))
        .await
    );
    let mut sent = Vec::new();
    for n in 0..3 {
        sent.push(second.say(&bob, &room, &format!("bob {n}")).await);
        sent.push(first.say(&alice, &room, &format!("alice {n}")).await);
    }
    assert!(
        eventually(10, async || sent
            .iter()
            .all(|id| first.holds(&room, id) && second.holds(&room, id)))
        .await,
        "ordinary federation delivers everything"
    );
    for id in &sent {
        for node in [&first, &second] {
            let pdu = node.pdu(&room, id).to_string();
            assert!(
                !pdu.contains("org.spindle") && !pdu.contains("hub_server"),
                "{pdu}"
            );
        }
    }
    for node in [&first, &second] {
        let unknown: u64 = EduResult::ALL
            .iter()
            .map(|result| {
                node.state
                    .metrics
                    .edu_received_count(EduType::Other, *result)
            })
            .sum();
        assert_eq!(unknown, 0, "{} was sent no unknown EDU", node.name);
    }

    // An attestation EDU from a peer that does speak hub mode is just an
    // EDU type this server does not know: counted, and dropped.
    let body = json!({
        "origin": first.name,
        "origin_server_ts": 0,
        "pdus": [],
        "edus": [{
            "edu_type": "org.spindle.msc3995.attestations",
            "content": { "room_id": room, "attestations": [] },
        }],
    });
    let (status, answer) = first
        .federation_put(&second, "/_matrix/federation/v1/send/attest", &body)
        .await;
    assert_eq!(status, 200, "{answer}");
    assert_eq!(
        second
            .state
            .metrics
            .edu_received_count(EduType::Other, EduResult::Unsupported),
        1
    );
}
