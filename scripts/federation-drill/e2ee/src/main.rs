#![recursion_limit = "256"]
//! drill-e2ee: the encrypted room of the federation drill (plan step 4.5.6).
//!
//! One state directory per test account holds its device store, its
//! session and, for `prepare --recovery`, its recovery key. Commands:
//!
//!   drill-e2ee prepare --state DIR --hs URL --user LOCALPART [--recovery]
//!   drill-e2ee create  --state DIR --name NAME --version 10 --invite MXID
//!   drill-e2ee join    --state DIR --room ID
//!   drill-e2ee send    --state DIR --room ID --count N --label L --manifest F
//!   drill-e2ee check   --state DIR --room ID --manifest F [--hs URL] [--relogin]
//!
//! The password is read from the environment variable DRILL_PASSWORD.
//! `send` appends one JSON line per message to the manifest: event ID,
//! sender, label and the SHA-256 of the plaintext. Plaintext is written
//! nowhere but the homeserver. `check` reads every manifest event back and
//! reports whether it decrypts to the recorded hash. With `--relogin` it
//! signs in a new device (for a server that no longer accepts the old
//! access token, such as Spindle B after the cut-over) and takes the room
//! keys from the server-side backup with the stored recovery key.

use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use matrix_sdk::{
    Client, Room,
    authentication::matrix::MatrixSession,
    config::SyncSettings,
    deserialized_responses::TimelineEventKind,
    encryption::{BackupDownloadStrategy, EncryptionSettings},
    ruma::{
        EventId, OwnedRoomId, RoomId, RoomVersionId, UserId,
        api::client::room::create_room::v3::{Request as CreateRoomRequest, RoomPreset},
        api::client::{filter::FilterDefinition, sync::sync_events},
        events::{InitialStateEvent, room::encryption::RoomEncryptionEventContent},
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .expect("read /dev/urandom");
    hex::encode(buf)
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn write_private(path: &Path, contents: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    std::io::Write::write_all(&mut f, contents.as_bytes())?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct Meta {
    homeserver: String,
    user: String,
    session: MatrixSession,
}

#[derive(Serialize, Deserialize, Clone)]
struct Line {
    event_id: String,
    room_id: String,
    sender: String,
    label: String,
    sha256: String,
    ts: u64,
}

fn password() -> Result<String> {
    std::env::var("DRILL_PASSWORD").context("DRILL_PASSWORD is not set")
}

async fn build(homeserver: &str, store: &Path) -> Result<Client> {
    std::fs::create_dir_all(store)?;
    Ok(Client::builder()
        .homeserver_url(homeserver)
        // Synapse's login response names its public_baseurl
        // (https://matrix.reilly.asia/), which outside the lab is the
        // production server. The client must stay on the URL it was given.
        .respect_login_well_known(false)
        .sqlite_store(store, None)
        .with_encryption_settings(EncryptionSettings {
            auto_enable_cross_signing: true,
            backup_download_strategy: BackupDownloadStrategy::AfterDecryptionFailure,
            auto_enable_backups: true,
        })
        .build()
        .await?)
}

async fn login(state: &Path, homeserver: &str, user: &str) -> Result<Client> {
    // A new device gets a new store: the old store belongs to the old device.
    let store = state.join(format!("store-{}", random_hex(4)));
    let client = build(homeserver, &store).await?;
    client
        .matrix_auth()
        .login_username(user, &password()?)
        .initial_device_display_name(&format!("drill-e2ee {}", now_secs()))
        .await
        .context("password login")?;
    let session = client.matrix_auth().session().ok_or_else(|| anyhow!("no session after login"))?;
    let meta = Meta { homeserver: homeserver.to_owned(), user: user.to_owned(), session };
    write_private(&state.join("meta.json"), &serde_json::to_string_pretty(&meta)?)?;
    std::fs::write(state.join("store-current"), store.to_string_lossy().as_bytes())?;
    eprintln!("{} logged in on device {:?} at {homeserver}", meta.session.meta.user_id, client.device_id());
    Ok(client)
}

async fn restore(state: &Path, homeserver: Option<&str>) -> Result<(Client, Meta)> {
    let meta: Meta = serde_json::from_str(&std::fs::read_to_string(state.join("meta.json"))?)?;
    let store = PathBuf::from(std::fs::read_to_string(state.join("store-current"))?.trim());
    let hs = homeserver.unwrap_or(&meta.homeserver);
    let client = build(hs, &store).await?;
    client.restore_session(meta.session.clone()).await?;
    Ok((client, meta))
}

/// Sync settings, with the rooms named in DRILL_SYNC_EXCLUDE (comma
/// separated) filtered out. The drill uses it to step around an imported
/// room that the server cannot render (recorded in the evidence).
fn sync_settings(timeout_secs: u64) -> SyncSettings {
    let settings = SyncSettings::default().timeout(Duration::from_secs(timeout_secs));
    let exclude: Vec<OwnedRoomId> = std::env::var("DRILL_SYNC_EXCLUDE")
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
        .filter_map(|s| OwnedRoomId::try_from(s).ok())
        .collect();
    if exclude.is_empty() {
        return settings;
    }
    let mut definition = FilterDefinition::default();
    definition.room.not_rooms = exclude;
    settings.filter(sync_events::v3::Filter::FilterDefinition(definition))
}

fn spawn_sync(client: &Client) {
    let c = client.clone();
    tokio::spawn(async move {
        if let Err(e) = c.sync(sync_settings(3)).await {
            eprintln!("sync loop ended: {e}");
        }
    });
}

async fn wait_room(client: &Client, room_id: &RoomId) -> Result<Room> {
    for _ in 0..240 {
        if let Some(r) = client.get_room(room_id) {
            return Ok(r);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    bail!("room {room_id} never appeared")
}

/// Every joined member must have a device this client knows, or the Megolm
/// session is shared with nobody on that side.
async fn wait_member_devices(client: &Client, room: &Room) -> Result<()> {
    for _ in 0..240 {
        let members = room.members(matrix_sdk::RoomMemberships::JOIN).await?;
        let mut all = !members.is_empty();
        for m in &members {
            let devs = client.encryption().get_user_devices(m.user_id()).await?;
            if devs.devices().count() == 0 {
                all = false;
            }
        }
        if all && members.len() >= 2 {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    bail!("the devices of every member never became known in {}", room.room_id())
}

fn body_hash(kind: &TimelineEventKind) -> (Option<String>, &'static str) {
    let v: Option<Value> = match kind {
        TimelineEventKind::Decrypted(d) => d.event.deserialize_as_unchecked().ok(),
        TimelineEventKind::PlainText { event } => event.deserialize_as_unchecked().ok(),
        TimelineEventKind::UnableToDecrypt { .. } => return (None, "utd"),
    };
    let what = if matches!(kind, TimelineEventKind::Decrypted(_)) { "decrypted" } else { "plaintext" };
    (v.and_then(|v| v["content"]["body"].as_str().map(sha256_hex)), what)
}

async fn cmd_prepare(a: &Args) -> Result<()> {
    let state = PathBuf::from(a.req("state")?);
    std::fs::create_dir_all(&state)?;
    let client = login(&state, a.req("hs")?, a.req("user")?).await?;
    spawn_sync(&client);
    client.encryption().wait_for_e2ee_initialization_tasks().await;
    if a.flag("recovery") {
        let key = client.encryption().recovery().enable().wait_for_backups_to_upload().await?;
        write_private(&state.join("recovery.key"), &key)?;
        eprintln!("recovery enabled; key stored in {}", state.join("recovery.key").display());
    }
    let cs = client.encryption().cross_signing_status().await;
    println!("{}", json!({"device": client.device_id().map(|d| d.to_string()),
        "cross_signing": cs.map(|s| s.has_master && s.has_self_signing && s.has_user_signing)}));
    Ok(())
}

async fn cmd_create(a: &Args) -> Result<()> {
    let (client, _) = restore(Path::new(a.req("state")?), None).await?;
    spawn_sync(&client);
    let mut req = CreateRoomRequest::new();
    req.name = Some(a.req("name")?.to_owned());
    req.preset = Some(RoomPreset::PrivateChat);
    req.invite = vec![UserId::parse(a.req("invite")?)?];
    req.room_version = Some(RoomVersionId::try_from(a.req("version")?)?);
    req.initial_state = vec![
        InitialStateEvent::with_empty_state_key(RoomEncryptionEventContent::with_recommended_defaults()).to_raw_any(),
    ];
    let room = client.create_room(req).await?;
    println!("{}", room.room_id());
    Ok(())
}

async fn cmd_join(a: &Args) -> Result<()> {
    let (client, _) = restore(Path::new(a.req("state")?), None).await?;
    spawn_sync(&client);
    let rid = OwnedRoomId::try_from(a.req("room")?)?;
    for attempt in 0..30 {
        match client.join_room_by_id(&rid).await {
            Ok(_) => break,
            Err(e) if attempt < 29 => {
                eprintln!("join: {e}; retrying");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }
    let room = wait_room(&client, &rid).await?;
    wait_member_devices(&client, &room).await?;
    println!("joined {rid}");
    Ok(())
}

async fn cmd_send(a: &Args) -> Result<()> {
    let state = PathBuf::from(a.req("state")?);
    let (client, meta) = restore(&state, a.get("hs")).await?;
    spawn_sync(&client);
    let rid = OwnedRoomId::try_from(a.req("room")?)?;
    let room = wait_room(&client, &rid).await?;
    wait_member_devices(&client, &room).await?;
    let count: usize = a.req("count")?.parse()?;
    let label = a.req("label")?.to_owned();
    let manifest = PathBuf::from(a.req("manifest")?);
    let mut out = std::fs::OpenOptions::new().create(true).append(true).open(&manifest)?;
    let salt = random_hex(4);
    for i in 0..count {
        let body = format!("drill e2ee {label} {} #{i} {salt} {}", meta.session.meta.user_id, random_hex(6));
        let r = room.send_raw("m.room.message", json!({"msgtype": "m.text", "body": body})).await?;
        if r.encryption_info.is_none() {
            bail!("{} went out unencrypted", r.response.event_id);
        }
        let line = Line {
            event_id: r.response.event_id.to_string(),
            room_id: rid.to_string(),
            sender: meta.session.meta.user_id.to_string(),
            label: label.clone(),
            sha256: sha256_hex(&body),
            ts: now_secs(),
        };
        std::io::Write::write_all(&mut out, format!("{}\n", serde_json::to_string(&line)?).as_bytes())?;
    }
    client.encryption().backups().wait_for_steady_state().await.ok();
    println!("sent {count} encrypted messages as {} ({label})", meta.session.meta.user_id);
    Ok(())
}

async fn cmd_check(a: &Args) -> Result<bool> {
    let state = PathBuf::from(a.req("state")?);
    let rid = OwnedRoomId::try_from(a.req("room")?)?;
    let (client, how) = if a.flag("relogin") {
        let meta: Meta = serde_json::from_str(&std::fs::read_to_string(state.join("meta.json"))?)?;
        let hs = a.get("hs").unwrap_or(&meta.homeserver).to_owned();
        let client = login(&state, &hs, &meta.user).await?;
        client.sync_once(sync_settings(1)).await?;
        client.encryption().wait_for_e2ee_initialization_tasks().await;
        let key = std::fs::read_to_string(state.join("recovery.key")).context("no recovery.key in state")?;
        client.encryption().recovery().recover(key.trim()).await.context("recovery")?;
        client.encryption().backups().download_room_keys_for_room(&rid).await.context("backup download")?;
        (client, "new device, keys from backup")
    } else {
        let (client, _) = restore(&state, a.get("hs")).await?;
        (client, "same device")
    };
    spawn_sync(&client);
    let room = wait_room(&client, &rid).await?;
    let lines: Vec<Line> = std::fs::read_to_string(a.req("manifest")?)?
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    let mut by: BTreeMap<String, usize> = BTreeMap::new();
    let mut failures = vec![];
    for l in lines.iter().filter(|l| l.room_id == rid.as_str()) {
        let eid = EventId::parse(l.event_id.as_str())?;
        let mut outcome = String::from("missing");
        // Room keys for the newest messages may still be in flight.
        for _ in 0..30 {
            match room.event(&eid, None).await {
                Ok(ev) => {
                    let (h, what) = body_hash(&ev.kind);
                    outcome = match h {
                        Some(h) if h == l.sha256 => what.to_owned(),
                        Some(_) => "hash-mismatch".into(),
                        None => what.to_owned(),
                    };
                    if outcome == "decrypted" {
                        break;
                    }
                }
                Err(e) => outcome = format!("fetch-failed: {e}"),
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let key = format!("{}:{}", l.label, outcome.split(':').next().unwrap_or(""));
        *by.entry(key).or_default() += 1;
        if outcome != "decrypted" {
            failures.push(json!({"event_id": l.event_id, "label": l.label, "sender": l.sender, "outcome": outcome}));
        }
    }
    let total = lines.iter().filter(|l| l.room_id == rid.as_str()).count();
    let pass = failures.is_empty() && total > 0;
    println!("{}", serde_json::to_string_pretty(&json!({
        "pass": pass, "user": client.user_id().map(|u| u.to_string()),
        "device": client.device_id().map(|d| d.to_string()), "how": how,
        "homeserver": client.homeserver().to_string(), "room": rid.to_string(),
        "events": total, "by_label_outcome": by, "failures": failures,
    }))?);
    Ok(pass)
}

struct Args {
    cmd: String,
    opts: BTreeMap<String, String>,
    flags: Vec<String>,
}

impl Args {
    fn parse() -> Result<Self> {
        let mut it = std::env::args().skip(1);
        let cmd = it.next().ok_or_else(|| anyhow!("usage: drill-e2ee prepare|create|join|send|check"))?;
        let rest: Vec<String> = it.collect();
        let (mut opts, mut flags, mut i) = (BTreeMap::new(), vec![], 0);
        while i < rest.len() {
            let k = rest[i].strip_prefix("--").ok_or_else(|| anyhow!("unexpected {}", rest[i]))?;
            if i + 1 < rest.len() && !rest[i + 1].starts_with("--") {
                opts.insert(k.to_owned(), rest[i + 1].clone());
                i += 2;
            } else {
                flags.push(k.to_owned());
                i += 1;
            }
        }
        Ok(Self { cmd, opts, flags })
    }
    fn get(&self, k: &str) -> Option<&str> {
        self.opts.get(k).map(String::as_str)
    }
    fn req(&self, k: &str) -> Result<&str> {
        self.get(k).ok_or_else(|| anyhow!("--{k} is required"))
    }
    fn flag(&self, k: &str) -> bool {
        self.flags.iter().any(|f| f == k)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .with_writer(std::io::stderr)
        .init();
    let a = Args::parse()?;
    match a.cmd.as_str() {
        "prepare" => cmd_prepare(&a).await,
        "create" => cmd_create(&a).await,
        "join" => cmd_join(&a).await,
        "send" => cmd_send(&a).await,
        "check" => {
            if cmd_check(&a).await? {
                Ok(())
            } else {
                std::process::exit(1)
            }
        }
        other => bail!("unknown command {other}"),
    }
}
