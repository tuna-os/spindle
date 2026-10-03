#![recursion_limit = "256"]
//! Element X's sync stack against a homeserver: matrix-sdk-ui's
//! `SyncService` (room list + encryption sync over MSC4186 simplified
//! sliding sync), a session restored from a provider-issued (MAS) token,
//! recovery from the recovery key, and the timeline Element X renders.
//!
//! Env: HS, TOKEN, USER_ID, DEVICE_ID, RECOVERY_KEY, EXPECT_ROOMS (comma
//! separated room IDs), STORE (empty dir), OUT (report path).
use std::{collections::BTreeMap, time::Duration};

use anyhow::{Context, Result, anyhow};
use futures_util::{StreamExt, pin_mut};
use matrix_sdk::{
    Client, SessionMeta, SessionTokens,
    authentication::matrix::MatrixSession,
    ruma::{OwnedRoomId, events::room::message::RoomMessageEventContent},
    sliding_sync::VersionBuilder,
};
use matrix_sdk_ui::{
    room_list_service::filters::new_filter_all,
    sync_service::{State, SyncService},
    timeline::RoomExt,
};
use serde_json::{Value, json};

const SYNAPSE_SINCE: &str = "s1600473_59519903_23_1472883_8005_125_9029_4969314_0_165_2_1_1";
const SYNAPSE_POS: &str = "20489%2Fs1600473_59519903_23_1472883_8005_125_9029_4969314_0_165_2_1_1";

fn env(k: &str) -> Result<String> {
    std::env::var(k).with_context(|| format!("env {k}"))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".into()))
        .with_writer(std::io::stderr)
        .init();
    let hs = env("HS")?;
    let token = env("TOKEN")?;
    let user_id = env("USER_ID")?;
    let device_id = env("DEVICE_ID")?;
    let expect: Vec<OwnedRoomId> = env("EXPECT_ROOMS")?
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.try_into().map_err(|e| anyhow!("{s}: {e}")))
        .collect::<Result<_>>()?;
    let mut report = serde_json::Map::new();
    let mut ok = true;
    let mut check = |report: &mut serde_json::Map<String, Value>, name: &str, pass: bool, detail: Value| {
        eprintln!("{} {name} {detail}", if pass { "PASS" } else { "FAIL" });
        ok &= pass;
        report.insert(name.to_owned(), json!({ "pass": pass, "detail": detail }));
    };

    // --- raw protocol checks, the way a migrated Element X meets the server --
    let http = reqwest::Client::new();
    let versions: Value = http.get(format!("{hs}/_matrix/client/versions")).send().await?.json().await?;
    let advertised = versions["unstable_features"]["org.matrix.simplified_msc3575"] == json!(true);
    check(&mut report, "versions_advertise_simplified_msc3575", advertised, json!(advertised));
    let r = http
        .post(format!("{hs}/_matrix/client/unstable/org.matrix.simplified_msc3575/sync?pos={SYNAPSE_POS}&timeout=0"))
        .bearer_auth(&token)
        .json(&json!({"lists": {}}))
        .send()
        .await?;
    let status = r.status().as_u16();
    let body: Value = r.json().await.unwrap_or(Value::Null);
    check(&mut report, "synapse_pos_is_M_UNKNOWN_POS", status == 400 && body["errcode"] == "M_UNKNOWN_POS", json!({"status": status, "body": body}));
    let r = http
        .get(format!("{hs}/_matrix/client/v3/sync?since={SYNAPSE_SINCE}&timeout=0&filter=%7B%22room%22%3A%7B%22timeline%22%3A%7B%22limit%22%3A1%7D%7D%7D"))
        .bearer_auth(&token)
        .send()
        .await?;
    let status = r.status().as_u16();
    let body: Value = r.json().await.unwrap_or(Value::Null);
    check(&mut report, "synapse_since_is_an_initial_sync", status == 200 && body["next_batch"].is_string(), json!({"status": status, "joined": body["rooms"]["join"].as_object().map(|o| o.len()), "device_lists_changed": body["device_lists"]["changed"].as_array().map(Vec::len)}));

    // --- the client, as Element X builds it ---------------------------------
    let store = env("STORE")?;
    let discovered = Client::builder()
        .homeserver_url(&hs)
        .sqlite_store(&store, None)
        .with_encryption_settings(matrix_sdk::encryption::EncryptionSettings {
            auto_enable_cross_signing: false,
            backup_download_strategy: matrix_sdk::encryption::BackupDownloadStrategy::AfterDecryptionFailure,
            auto_enable_backups: true,
        })
                .sliding_sync_version_builder(VersionBuilder::DiscoverNative)
        .build()
        .await;
    check(&mut report, "client_discovers_native_sliding_sync", discovered.is_ok(), json!(discovered.as_ref().err().map(ToString::to_string)));
    let client = match discovered {
        Ok(c) => c,
        Err(_) => Client::builder()
            .homeserver_url(&hs)
            .sqlite_store(format!("{store}-native"), None)
            .with_encryption_settings(matrix_sdk::encryption::EncryptionSettings {
            auto_enable_cross_signing: false,
            backup_download_strategy: matrix_sdk::encryption::BackupDownloadStrategy::AfterDecryptionFailure,
            auto_enable_backups: true,
        })
                    .sliding_sync_version_builder(VersionBuilder::Native)
            .build()
            .await?,
    };
    client
        .restore_session(MatrixSession {
            meta: SessionMeta { user_id: user_id.as_str().try_into()?, device_id: device_id.as_str().into() },
            tokens: SessionTokens { access_token: token.clone(), refresh_token: None },
        })
        .await?;

    // As Element X's FFI client does: the event cache backs every timeline.
    client.event_cache().subscribe()?;
    let sync_service = SyncService::builder(client.clone()).build().await?;
    let mut states = sync_service.state();
    sync_service.start().await;

    // Room list: Element X's home screen.
    let room_list_service = sync_service.room_list_service();
    let all_rooms = room_list_service.all_rooms().await?;
    let (entries, controller) = all_rooms.entries_with_dynamic_adapters(200);
    controller.set_filter(Box::new(new_filter_all(vec![])));
    pin_mut!(entries);
    let mut listed: Vec<OwnedRoomId> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    while !expect.iter().all(|r| listed.contains(r)) && tokio::time::Instant::now() < deadline {
        let Ok(Some(diffs)) = tokio::time::timeout(Duration::from_secs(10), entries.next()).await else { continue };
        for diff in diffs {
            use eyeball_im::VectorDiff;
            match diff {
                VectorDiff::Reset { values } | VectorDiff::Append { values } => listed.extend(values.iter().map(|r| r.room_id().to_owned())),
                VectorDiff::PushBack { value } | VectorDiff::PushFront { value } | VectorDiff::Insert { value, .. } | VectorDiff::Set { value, .. } => listed.push(value.room_id().to_owned()),
                _ => {}
            }
        }
        listed.sort();
        listed.dedup();
    }
    let missing: Vec<String> = expect.iter().filter(|r| !listed.contains(r)).map(ToString::to_string).collect();
    check(&mut report, "room_list_shows_expected_rooms", missing.is_empty(), json!({"listed": listed.len(), "missing": missing}));
    check(&mut report, "sync_service_running", matches!(states.get(), State::Running), json!(format!("{:?}", states.get())));

    // Recovery: secrets and the key backup, from the recovery key.
    let recovery_key = env("RECOVERY_KEY")?;
    let recovered = client.encryption().recovery().recover(&recovery_key).await;
    check(&mut report, "recovery_with_recovery_key", recovered.is_ok(), json!(recovered.as_ref().err().map(ToString::to_string)));

    // Each expected room: what the room list row and the timeline show.
    let mut rooms = BTreeMap::new();
    for room_id in &expect {
        let Some(room) = client.get_room(room_id) else {
            check(&mut report, &format!("room_{room_id}"), false, json!("not known to the client"));
            continue;
        };
        let name = room.display_name().await.map(|n| n.to_string()).unwrap_or_default();
        let encrypted = room.latest_encryption_state().await.map(|s| s.is_encrypted()).unwrap_or(false);
        let latest = format!("{:?}", room.latest_event().await);
        let timeline = room.timeline().await?;
        let mut at_start = false;
        for _ in 0..10 {
            if at_start {
                break;
            }
            at_start = timeline.paginate_backwards(50).await.unwrap_or(true);
        }
        // Give backup downloads a moment to land and redecrypt.
        let mut events = 0;
        let mut utd = 0;
        let mut last = usize::MAX;
        let mut stable = 0;
        // Settle: pagination results and backup redecryption land on the
        // timeline asynchronously, so read until the count stops moving.
        for _ in 0..60 {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let items = timeline.items().await;
            events = items.iter().filter(|i| i.as_event().is_some_and(|e| e.content().as_message().is_some() || e.content().is_unable_to_decrypt())).count();
            utd = items.iter().filter(|i| i.as_event().is_some_and(|e| e.content().is_unable_to_decrypt())).count();
            if events == last && utd == 0 {
                stable += 1;
                if stable >= 3 {
                    break;
                }
            } else {
                stable = 0;
            }
            last = events;
        }
        let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
        for item in timeline.items().await.iter() {
            let kind = match item.as_event() {
                Some(e) => format!("{:?}", e.content()).chars().take(48).collect::<String>(),
                None => "virtual".to_owned(),
            };
            *kinds.entry(kind).or_default() += 1;
        }
        rooms.insert(room_id.to_string(), json!({
            "item_kinds": kinds,
            "name": name, "encrypted": encrypted, "at_start": at_start,
            "messages": events, "utd": utd,
            "unread_notifications": room.num_unread_notifications(),
            "latest_event_kind": latest.split(['(', ' ', '{']).next().unwrap_or_default(),
        }));
        let pass = at_start && events > 0 && utd == 0;
        check(&mut report, &format!("room_{room_id}"), pass, rooms[&room_id.to_string()].clone());
    }

    // Send through the timeline and see the remote echo arrive by sync.
    if let Some(room_id) = expect.first()
        && let Some(room) = client.get_room(room_id)
    {
        let timeline = room.timeline().await?;
        let text = format!("ssprobe {}", std::process::id());
        timeline.send(RoomMessageEventContent::text_plain(&text).into()).await?;
        let mut echoed = false;
        for _ in 0..30 {
            let items = timeline.items().await;
            echoed = items.iter().any(|i| {
                i.as_event().is_some_and(|e| !e.is_local_echo() && e.content().as_message().is_some_and(|m| m.body() == text))
            });
            if echoed {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        check(&mut report, "send_and_remote_echo", echoed, json!(room_id.to_string()));
    }
    check(&mut report, "sync_service_still_running", matches!(states.get(), State::Running), json!(format!("{:?}", states.get())));
    let _ = states.next_now();

    sync_service.stop().await;
    report.insert("pass".into(), json!(ok));
    let out = serde_json::to_string_pretty(&Value::Object(report))?;
    if let Ok(path) = std::env::var("OUT") {
        std::fs::write(path, &out)?;
    }
    println!("{out}");
    std::process::exit(if ok { 0 } else { 1 });
}
