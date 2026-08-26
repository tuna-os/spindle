//! The rules deciding what a client is notified about.
//!
//! Push rules are both account data and an endpoint, which is the thing most
//! worth testing: `/sync` and `/pushrules/` read one stored value, so a client
//! that edits through one and reads through the other must never see two
//! different rulesets.
//!
//! Nothing here evaluates a rule against an event — that belongs with the
//! notification count. What is pinned down is the ruleset's shape: the
//! defaults, the five kinds and their order, and which edits a client may
//! make.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

struct Harness {
    _dir: TempDir,
    app: axum::Router,
}

impl Harness {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse("[server]\nname = \"example.org\"\n").unwrap();
        let app = spindle_server::app(config, store).expect("a signing key is established");
        Self { _dir: dir, app }
    }

    async fn call(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn register(&self, username: &str) -> String {
        let (status, body) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri("/_matrix/client/v3/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": username,
                            "password": "hunter2",
                            "auth": { "type": "m.login.dummy" },
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["access_token"].as_str().unwrap().to_owned()
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        token: &str,
        body: &Value,
    ) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    async fn get(&self, path: &str, token: &str) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    async fn rules(&self, token: &str) -> Value {
        let (status, body) = self.get("/_matrix/client/v3/pushrules/", token).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["global"].clone()
    }

    /// The ruleset as `/sync` delivers it, which must be the same value.
    async fn rules_via_sync(&self, token: &str) -> Value {
        let (status, body) = self.get("/_matrix/client/v3/sync", token).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["account_data"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event["type"] == "m.push_rules")
            .unwrap_or_else(|| panic!("no m.push_rules in {body}"))["content"]
            .clone()
    }
}

fn rule_ids(ruleset: &Value, kind: &str) -> Vec<String> {
    ruleset[kind]
        .as_array()
        .unwrap()
        .iter()
        .map(|rule| rule["rule_id"].as_str().unwrap().to_owned())
        .collect()
}

fn find<'a>(ruleset: &'a Value, kind: &str, rule_id: &str) -> Option<&'a Value> {
    ruleset[kind]
        .as_array()?
        .iter()
        .find(|rule| rule["rule_id"] == rule_id)
}

#[tokio::test]
async fn a_new_user_has_the_default_ruleset_with_all_five_kinds() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let ruleset = harness.rules(&alice).await;

    for kind in ["override", "content", "room", "sender", "underride"] {
        assert!(
            ruleset[kind].is_array(),
            "every kind must be present even when empty: {kind} in {ruleset}"
        );
    }

    // `.m.rule.master` ships disabled -- it is the switch that silences
    // everything, so an enabled default would mean no user is ever notified.
    let master = find(&ruleset, "override", ".m.rule.master").expect("a master rule");
    assert_eq!(master["enabled"], false, "{master}");
    assert_eq!(master["actions"], json!([]));

    assert!(find(&ruleset, "underride", ".m.rule.message").is_some());
    assert!(find(&ruleset, "override", ".m.rule.is_user_mention").is_some());
}

#[tokio::test]
async fn the_defaults_name_the_user_they_belong_to() {
    // Three defaults carry the user's own identity, so a shared constant would
    // notify everyone for everyone else's name.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;

    let alices = harness.rules(&alice).await;
    let bobs = harness.rules(&bob).await;

    assert_eq!(
        find(&alices, "content", ".m.rule.contains_user_name").unwrap()["pattern"],
        "alice"
    );
    assert_eq!(
        find(&bobs, "content", ".m.rule.contains_user_name").unwrap()["pattern"],
        "bob"
    );

    let alice_mention = find(&alices, "override", ".m.rule.is_user_mention").unwrap();
    assert_eq!(
        alice_mention["conditions"][0]["value"], "@alice:example.org",
        "{alice_mention}"
    );

    let alice_invite = find(&alices, "override", ".m.rule.invite_for_me").unwrap();
    let state_key = alice_invite["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|condition| condition["key"] == "state_key")
        .unwrap();
    assert_eq!(state_key["pattern"], "@alice:example.org");
}

#[tokio::test]
async fn pushrules_and_sync_deliver_the_same_ruleset_before_and_after_an_edit() {
    // The one property that makes two surfaces over one value safe.
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    assert_eq!(
        harness.rules(&alice).await,
        harness.rules_via_sync(&alice).await,
        "an untouched ruleset must read the same both ways"
    );

    let (status, body) = harness
        .request(
            "PUT",
            "/_matrix/client/v3/pushrules/global/override/.m.rule.master/enabled",
            &alice,
            &json!({ "enabled": true }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let via_endpoint = harness.rules(&alice).await;
    assert_eq!(
        via_endpoint,
        harness.rules_via_sync(&alice).await,
        "an edited ruleset must read the same both ways"
    );
    assert_eq!(
        find(&via_endpoint, "override", ".m.rule.master").unwrap()["enabled"],
        true,
        "and must carry the edit"
    );
}

#[tokio::test]
async fn a_client_rule_can_be_created_read_edited_and_deleted() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let path = "/_matrix/client/v3/pushrules/global/content/coffee";

    let (status, body) = harness
        .request(
            "PUT",
            path,
            &alice,
            &json!({ "pattern": "coffee", "actions": ["notify"] }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, rule) = harness.get(path, &alice).await;
    assert_eq!(status, StatusCode::OK, "{rule}");
    assert_eq!(rule["pattern"], "coffee");
    assert_eq!(rule["actions"], json!(["notify"]));
    assert_eq!(rule["enabled"], true, "a new rule is enabled by default");
    assert_eq!(
        rule["default"], false,
        "`default` is the server's word for its own rules, and a client cannot claim it"
    );

    let (status, body) = harness
        .request(
            "PUT",
            &format!("{path}/actions"),
            &alice,
            &json!({ "actions": ["notify", { "set_tweak": "sound", "value": "default" }] }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, actions) = harness.get(&format!("{path}/actions"), &alice).await;
    assert_eq!(
        actions["actions"],
        json!(["notify", { "set_tweak": "sound", "value": "default" }])
    );

    let (status, body) = harness
        .request(
            "PUT",
            &format!("{path}/enabled"),
            &alice,
            &json!({ "enabled": false }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, enabled) = harness.get(&format!("{path}/enabled"), &alice).await;
    assert_eq!(enabled["enabled"], false);

    let (status, body) = harness.request("DELETE", path, &alice, &json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = harness.get(path, &alice).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn a_client_cannot_mint_a_rule_in_the_servers_namespace() {
    // A dotted ID means a rule the server defined. If a client could create
    // one, a later spec version defining that ID would collide with it.
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    let (status, body) = harness
        .request(
            "PUT",
            "/_matrix/client/v3/pushrules/global/override/.m.rule.invented",
            &alice,
            &json!({ "actions": ["notify"], "conditions": [] }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_INVALID_PARAM");
    assert!(
        find(&harness.rules(&alice).await, "override", ".m.rule.invented").is_none(),
        "a refused create must not have half-happened"
    );
}

#[tokio::test]
async fn a_server_default_can_still_be_silenced_and_re_actioned() {
    // The other half of the namespace rule: a client may not *create* a dotted
    // rule, but disabling `.m.rule.message` is exactly what these two
    // endpoints are for.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let path = "/_matrix/client/v3/pushrules/global/underride/.m.rule.message";

    let (status, body) = harness
        .request(
            "PUT",
            &format!("{path}/enabled"),
            &alice,
            &json!({ "enabled": false }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = harness
        .request(
            "PUT",
            &format!("{path}/actions"),
            &alice,
            &json!({ "actions": [] }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let rule = find(&harness.rules(&alice).await, "underride", ".m.rule.message")
        .unwrap()
        .clone();
    assert_eq!(rule["enabled"], false);
    assert_eq!(rule["actions"], json!([]));
    assert_eq!(
        rule["default"], true,
        "editing a default rule does not stop it being one"
    );
}

#[tokio::test]
async fn editing_a_rule_leaves_it_where_it_was_and_a_new_rule_goes_first() {
    // Order within a kind is priority. An edit is not a re-prioritisation, and
    // for a default rule, moving it would break the order the spec fixes.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let before = rule_ids(&harness.rules(&alice).await, "underride");

    harness
        .request(
            "PUT",
            "/_matrix/client/v3/pushrules/global/underride/.m.rule.message/enabled",
            &alice,
            &json!({ "enabled": false }),
        )
        .await;
    assert_eq!(
        rule_ids(&harness.rules(&alice).await, "underride"),
        before,
        "an edit must not reorder the kind"
    );

    harness
        .request(
            "PUT",
            "/_matrix/client/v3/pushrules/global/content/first",
            &alice,
            &json!({ "pattern": "a", "actions": ["notify"] }),
        )
        .await;
    harness
        .request(
            "PUT",
            "/_matrix/client/v3/pushrules/global/content/second",
            &alice,
            &json!({ "pattern": "b", "actions": ["notify"] }),
        )
        .await;
    let content = rule_ids(&harness.rules(&alice).await, "content");
    assert_eq!(
        content.first().map(String::as_str),
        Some("second"),
        "the newest rule wins: {content:?}"
    );
    assert_eq!(content.get(1).map(String::as_str), Some("first"));

    // Replacing one leaves it in place rather than promoting it.
    harness
        .request(
            "PUT",
            "/_matrix/client/v3/pushrules/global/content/first",
            &alice,
            &json!({ "pattern": "changed", "actions": ["notify"] }),
        )
        .await;
    assert_eq!(
        rule_ids(&harness.rules(&alice).await, "content"),
        content,
        "a replace is an edit, not a re-prioritisation"
    );
}

#[tokio::test]
async fn an_unknown_scope_or_kind_is_refused_rather_than_treated_as_global() {
    // `device` scope was in older drafts and clients still ask for it.
    // Treating it as `global` would let a client believe it stored a
    // per-device rule that silently applied everywhere.
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    let (status, body) = harness
        .get(
            "/_matrix/client/v3/pushrules/device/underride/.m.rule.message",
            &alice,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    let (status, body) = harness
        .get(
            "/_matrix/client/v3/pushrules/global/nonsense/.m.rule.message",
            &alice,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_INVALID_PARAM");
}

#[tokio::test]
async fn a_rule_that_does_not_exist_is_a_404_on_every_arity() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let base = "/_matrix/client/v3/pushrules/global/content/absent";

    for path in [base, &format!("{base}/enabled"), &format!("{base}/actions")] {
        let (status, body) = harness.get(path, &alice).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {body}");
    }
    let (status, body) = harness.request("DELETE", base, &alice, &json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, body) = harness
        .request(
            "PUT",
            &format!("{base}/enabled"),
            &alice,
            &json!({ "enabled": true }),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn push_rules_cannot_be_written_through_the_account_data_endpoint() {
    // Two writers on one value drift. `m.push_rules` is edited a rule at a
    // time through `/pushrules/`, and `m.fully_read` moves through
    // `/read_markers`.
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    for event_type in ["m.push_rules", "m.fully_read"] {
        let (status, body) = harness
            .request(
                "PUT",
                &format!("/_matrix/client/v3/user/@alice:example.org/account_data/{event_type}"),
                &alice,
                &json!({ "clobbered": true }),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::METHOD_NOT_ALLOWED,
            "{event_type}: {body}"
        );
    }

    // And the ruleset is untouched, not merely un-replaced.
    assert!(
        find(&harness.rules(&alice).await, "underride", ".m.rule.message").is_some(),
        "the defaults survived the refused write"
    );
}

#[tokio::test]
async fn a_rule_needs_actions() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (status, body) = harness
        .request(
            "PUT",
            "/_matrix/client/v3/pushrules/global/content/coffee",
            &alice,
            &json!({ "pattern": "coffee" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_BAD_JSON");
}

#[tokio::test]
async fn one_users_rules_are_not_anothers() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;

    harness
        .request(
            "PUT",
            "/_matrix/client/v3/pushrules/global/content/coffee",
            &alice,
            &json!({ "pattern": "coffee", "actions": ["notify"] }),
        )
        .await;

    assert!(find(&harness.rules(&alice).await, "content", "coffee").is_some());
    assert!(
        find(&harness.rules(&bob).await, "content", "coffee").is_none(),
        "alice's rule must not appear in bob's ruleset"
    );
}
