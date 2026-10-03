#![recursion_limit = "256"]
//! mig-rig: E2EE history fixture for the Synapse -> Spindle migration rig.
//!
//!   mig-rig seed   --homeserver URL --server-name NAME --registration-secret-file F
//!                  --secrets-dir DIR --out DIR
//!   mig-rig verify --homeserver URL --user LOCALPART|MXID --manifest F
//!                  (--password-file F | env RIG_PASSWORD)
//!                  (--recovery-key-file F | env RIG_RECOVERY_KEY)
//!                  [--report F] [--keep-device]
//!
//! `seed` registers three users through Synapse's shared-secret admin API,
//! bootstraps cross-signing + secret storage + key backup for each (keeping
//! the recovery keys), builds four rooms of history and writes a manifest of
//! event IDs with the SHA-256 of each plaintext body. Plaintext bodies are
//! never written anywhere except the homeserver.
//!
//! `verify` logs in as a brand-new device, recovers secrets with the
//! recovery key, downloads room keys from the server-side backup only
//! (no key gossip: the SDK is built without automatic room-key forwarding)
//! and reports, per manifest event, whether it decrypts to the recorded hash.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use hmac::{Hmac, Mac};
use matrix_sdk::{
    Client, Room,
    config::SyncSettings,
    deserialized_responses::TimelineEventKind,
    encryption::{BackupDownloadStrategy, EncryptionSettings},
    ruma::{
        EventId, Int, OwnedRoomId, OwnedUserId, RoomId, RoomVersionId, UserId,
        api::client::room::create_room::v3::{Request as CreateRoomRequest, RoomPreset},
        events::{
            InitialStateEvent, room::encryption::RoomEncryptionEventContent,
            room::member::MembershipState,
        },
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const USERS: [&str; 3] = ["a", "b", "c"];

fn localpart(key: &str) -> String {
    format!("spindle-mig-{key}")
}

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

fn read_trimmed(path: &Path) -> Result<String> {
    Ok(std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?
        .trim()
        .to_owned())
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

// ---------------------------------------------------------------- manifest

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Manifest {
    format: u32,
    server_name: String,
    seeded_at: u64,
    seeded_against: String,
    users: BTreeMap<String, String>,
    rooms: Vec<RoomRecord>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct RoomRecord {
    key: String,
    room_id: String,
    room_version: String,
    encrypted: bool,
    events: Vec<EventRecord>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct EventRecord {
    event_id: String,
    /// user key (a/b/c)
    sender: String,
    /// message | edit | reply | redacted | redaction | state
    kind: String,
    /// event type as the server stores it
    event_type: String,
    encrypted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
    /// SHA-256 of the plaintext `body` (messages) or of the serialized
    /// content (state events). Absent for redacted events.
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relates_to: Option<String>,
    /// user keys that were joined when the event was sent, i.e. who must be
    /// able to read it.
    readable_by: Vec<String>,
}

// ------------------------------------------------------------------ client

async fn new_client(homeserver: &str, store: &Path, settings: EncryptionSettings) -> Result<Client> {
    std::fs::create_dir_all(store)?;
    Ok(Client::builder()
        .homeserver_url(homeserver)
        .sqlite_store(store, None)
        .with_encryption_settings(settings)
        .build()
        .await?)
}

fn spawn_sync(client: &Client) {
    let c = client.clone();
    tokio::spawn(async move {
        if let Err(e) = c.sync(SyncSettings::default().timeout(Duration::from_secs(3))).await {
            eprintln!("sync loop ended: {e}");
        }
    });
}

async fn wait_member(room: &Room, user: &UserId, want: MembershipState) -> Result<()> {
    for _ in 0..240 {
        if let Ok(Some(m)) = room.get_member_no_sync(user).await
            && *m.membership() == want
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    bail!("{user} never reached {want} in {}", room.room_id())
}

/// Wait until `viewer` knows at least one device of `user`. Sending before
/// that shares the Megolm session with nobody, and the first messages of
/// the session then become undecryptable for the other members.
async fn wait_devices(viewer: &Client, user: &UserId) -> Result<()> {
    for _ in 0..240 {
        if let Ok(devs) = viewer.encryption().get_user_devices(user).await
            && devs.devices().count() > 0
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    bail!("{:?} never learned the devices of {user}", viewer.user_id())
}

async fn wait_room(client: &Client, room_id: &RoomId) -> Result<Room> {
    for _ in 0..240 {
        if let Some(r) = client.get_room(room_id) {
            return Ok(r);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    bail!("room {room_id} never appeared for {:?}", client.user_id())
}

// -------------------------------------------------------------------- seed

async fn register_shared_secret(
    http: &reqwest::Client,
    homeserver: &str,
    secret: &str,
    user: &str,
    password: &str,
) -> Result<()> {
    let url = format!("{}/_synapse/admin/v1/register", homeserver.trim_end_matches('/'));
    let nonce: Value = http.get(&url).send().await?.error_for_status()?.json().await?;
    let nonce = nonce["nonce"].as_str().ok_or_else(|| anyhow!("no nonce"))?.to_owned();
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(secret.as_bytes())?;
    mac.update(nonce.as_bytes());
    mac.update(b"\x00");
    mac.update(user.as_bytes());
    mac.update(b"\x00");
    mac.update(password.as_bytes());
    mac.update(b"\x00notadmin");
    let mac = hex::encode(mac.finalize().into_bytes());
    let resp = http
        .post(&url)
        .json(&json!({"nonce": nonce, "username": user, "password": password, "admin": false, "mac": mac}))
        .send()
        .await?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        bail!("register {user}: {status} {}", body["errcode"].as_str().unwrap_or("?"));
    }
    Ok(())
}

struct Seeder {
    clients: BTreeMap<String, Client>,
    mxids: BTreeMap<String, OwnedUserId>,
    salt: String,
    counter: usize,
}

struct RoomBuilder {
    record: RoomRecord,
    joined: BTreeSet<String>,
}

impl Seeder {
    fn room(&self, user: &str, room_id: &RoomId) -> Result<Room> {
        self.clients[user].get_room(room_id).ok_or_else(|| anyhow!("{user} has no room {room_id}"))
    }

    fn body(&mut self, rb: &RoomBuilder, what: &str) -> String {
        self.counter += 1;
        format!("mig-rig {} {what} #{} {} {}", rb.record.key, self.counter, self.salt, random_hex(6))
    }

    async fn send_content(&mut self, rb: &mut RoomBuilder, user: &str, kind: &str, content: Value, body: &str, relates_to: Option<String>) -> Result<String> {
        let room = self.room(user, &OwnedRoomId::try_from(rb.record.room_id.as_str())?)?;
        let result = room.send_raw("m.room.message", content).await?;
        let session_id = result.encryption_info.as_ref().and_then(|i| i.session_id().map(str::to_owned));
        if rb.record.encrypted && session_id.is_none() {
            bail!("{} sent in an encrypted room without encryption info", result.response.event_id);
        }
        let event_id = result.response.event_id.to_string();
        rb.record.events.push(EventRecord {
            event_id: event_id.clone(),
            sender: user.to_owned(),
            kind: kind.to_owned(),
            event_type: if rb.record.encrypted { "m.room.encrypted".into() } else { "m.room.message".into() },
            encrypted: rb.record.encrypted,
            session_id,
            sha256: Some(sha256_hex(body)),
            relates_to,
            readable_by: rb.joined.iter().cloned().collect(),
        });
        Ok(event_id)
    }

    async fn text(&mut self, rb: &mut RoomBuilder, user: &str) -> Result<String> {
        let body = self.body(rb, "text");
        self.send_content(rb, user, "message", json!({"msgtype": "m.text", "body": body}), &body, None).await
    }

    async fn reply(&mut self, rb: &mut RoomBuilder, user: &str, to: &str) -> Result<String> {
        let body = self.body(rb, "reply");
        let content = json!({"msgtype": "m.text", "body": body, "m.relates_to": {"m.in_reply_to": {"event_id": to}}});
        self.send_content(rb, user, "reply", content, &body, Some(to.to_owned())).await
    }

    async fn edit(&mut self, rb: &mut RoomBuilder, user: &str, of: &str) -> Result<String> {
        let new = self.body(rb, "edited");
        let body = format!("* {new}");
        let content = json!({
            "msgtype": "m.text", "body": body,
            "m.new_content": {"msgtype": "m.text", "body": new},
            "m.relates_to": {"rel_type": "m.replace", "event_id": of},
        });
        self.send_content(rb, user, "edit", content, &body, Some(of.to_owned())).await
    }

    async fn redact(&mut self, rb: &mut RoomBuilder, user: &str, target: &str) -> Result<()> {
        let rid = OwnedRoomId::try_from(rb.record.room_id.as_str())?;
        let room = self.room(user, &rid)?;
        let resp = room.redact(&EventId::parse(target)?, Some("mig-rig redaction"), None).await?;
        for e in rb.record.events.iter_mut().filter(|e| e.event_id == target) {
            e.kind = "redacted".into();
            e.sha256 = None;
        }
        rb.record.events.push(EventRecord {
            event_id: resp.event_id.to_string(),
            sender: user.to_owned(),
            kind: "redaction".into(),
            event_type: "m.room.redaction".into(),
            encrypted: false,
            session_id: None,
            sha256: None,
            relates_to: Some(target.to_owned()),
            readable_by: rb.joined.iter().cloned().collect(),
        });
        Ok(())
    }

    async fn record_state(&mut self, rb: &mut RoomBuilder, user: &str, event_id: String) -> Result<()> {
        let rid = OwnedRoomId::try_from(rb.record.room_id.as_str())?;
        let room = self.room(user, &rid)?;
        let ev = room.event(<&EventId>::try_from(event_id.as_str())?, None).await?;
        let v: Value = ev.kind.raw().deserialize_as_unchecked()?;
        rb.record.events.push(EventRecord {
            event_id,
            sender: user.to_owned(),
            kind: "state".into(),
            event_type: v["type"].as_str().unwrap_or("?").to_owned(),
            encrypted: false,
            session_id: None,
            sha256: Some(sha256_hex(&serde_json::to_string(&v["content"])?)),
            relates_to: None,
            readable_by: rb.joined.iter().cloned().collect(),
        });
        Ok(())
    }

    async fn create_room(&mut self, key: &str, creator: &str, invite: &[&str], encrypted: bool, version: Option<RoomVersionId>, direct: bool) -> Result<RoomBuilder> {
        let mut req = CreateRoomRequest::new();
        req.name = Some(format!("mig-rig {key}"));
        req.preset = Some(if direct { RoomPreset::TrustedPrivateChat } else { RoomPreset::PrivateChat });
        req.is_direct = direct;
        req.invite = invite.iter().map(|u| self.mxids[*u].clone()).collect();
        req.room_version = version;
        if encrypted {
            req.initial_state = vec![
                InitialStateEvent::with_empty_state_key(RoomEncryptionEventContent::with_recommended_defaults()).to_raw_any(),
            ];
        }
        let room = self.clients[creator].create_room(req).await?;
        let room_id = room.room_id().to_owned();
        let mut joined = BTreeSet::from([creator.to_owned()]);
        for u in invite {
            self.clients[*u].join_room_by_id(&room_id).await?;
            joined.insert((*u).to_owned());
        }
        // Every member must see every other member joined before anyone
        // sends, so each Megolm session is shared with all of them.
        for viewer in &joined {
            let r = wait_room(&self.clients[viewer], &room_id).await?;
            for m in &joined {
                wait_member(&r, &self.mxids[m], MembershipState::Join).await?;
                if encrypted {
                    wait_devices(&self.clients[viewer], &self.mxids[m]).await?;
                }
            }
        }
        let version = room.version().map(|v| v.to_string()).unwrap_or_else(|| "?".into());
        eprintln!("room {key}: {room_id} v{version} encrypted={encrypted}");
        Ok(RoomBuilder {
            record: RoomRecord { key: key.into(), room_id: room_id.to_string(), room_version: version, encrypted, events: vec![] },
            joined,
        })
    }

    async fn leave(&mut self, rb: &mut RoomBuilder, user: &str) -> Result<()> {
        let rid = OwnedRoomId::try_from(rb.record.room_id.as_str())?;
        self.room(user, &rid)?.leave().await?;
        rb.joined.remove(user);
        for viewer in rb.joined.clone() {
            wait_member(&self.room(&viewer, &rid)?, &self.mxids[user], MembershipState::Leave).await?;
        }
        Ok(())
    }

    async fn rejoin(&mut self, rb: &mut RoomBuilder, inviter: &str, user: &str) -> Result<()> {
        let rid = OwnedRoomId::try_from(rb.record.room_id.as_str())?;
        self.room(inviter, &rid)?.invite_user_by_id(&self.mxids[user]).await?;
        self.clients[user].join_room_by_id(&rid).await?;
        rb.joined.insert(user.to_owned());
        for viewer in rb.joined.clone() {
            let r = wait_room(&self.clients[&viewer], &rid).await?;
            for m in rb.joined.clone() {
                wait_member(&r, &self.mxids[&m], MembershipState::Join).await?;
                wait_devices(&self.clients[&viewer], &self.mxids[&m]).await?;
            }
        }
        Ok(())
    }
}

/// Each reader must decrypt every event it is expected to, from its own
/// seeding device. Retries while to-device room keys are still arriving.
async fn seed_self_check(seeder: &Seeder, rooms: &[RoomRecord]) -> Result<BTreeMap<String, (usize, usize)>> {
    let mut out = BTreeMap::new();
    for user in USERS {
        let (mut ok, mut want) = (0, 0);
        for rr in rooms {
            let rid = OwnedRoomId::try_from(rr.room_id.as_str())?;
            let Some(room) = seeder.clients[user].get_room(&rid) else { continue };
            for e in rr.events.iter().filter(|e| e.readable_by.iter().any(|u| u == user)) {
                if !matches!(e.kind.as_str(), "message" | "edit" | "reply") {
                    continue;
                }
                want += 1;
                let mut good = false;
                for _ in 0..40 {
                    let ev = room.event(<&EventId>::try_from(e.event_id.as_str())?, None).await?;
                    if let Some(h) = body_hash(&ev.kind)
                        && Some(&h) == e.sha256.as_ref()
                    {
                        good = true;
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                if good {
                    ok += 1;
                } else {
                    eprintln!("seed self-check: {user} cannot read {} in {}", e.event_id, rr.key);
                }
            }
        }
        eprintln!("seed self-check {user}: {ok}/{want}");
        out.insert(user.to_owned(), (ok, want));
    }
    Ok(out)
}

fn body_hash(kind: &TimelineEventKind) -> Option<String> {
    let v: Value = match kind {
        TimelineEventKind::Decrypted(d) => d.event.deserialize_as_unchecked().ok()?,
        TimelineEventKind::PlainText { event } => event.deserialize_as_unchecked().ok()?,
        TimelineEventKind::UnableToDecrypt { .. } => return None,
    };
    v["content"]["body"].as_str().map(sha256_hex)
}

async fn backup_info(http: &reqwest::Client, homeserver: &str, token: &str) -> Value {
    let url = format!("{}/_matrix/client/v3/room_keys/version", homeserver.trim_end_matches('/'));
    match http.get(url).bearer_auth(token).send().await {
        Ok(r) => {
            let mut v: Value = r.json().await.unwrap_or(Value::Null);
            if let Some(o) = v.as_object_mut() {
                o.remove("auth_data");
            }
            v
        }
        Err(e) => json!({"error": e.to_string()}),
    }
}

async fn seed(args: &Args) -> Result<()> {
    let homeserver = args.req("homeserver")?;
    let server_name = args.get("server-name").unwrap_or("reilly.asia").to_owned();
    let secret = read_trimmed(Path::new(args.req("registration-secret-file")?))?;
    let secrets_dir = PathBuf::from(args.req("secrets-dir")?);
    let out = PathBuf::from(args.req("out")?);
    std::fs::create_dir_all(&out)?;
    let http = reqwest::Client::new();

    let mut clients = BTreeMap::new();
    let mut mxids = BTreeMap::new();
    let mut credentials = BTreeMap::new();
    let mut backups = BTreeMap::new();
    for user in USERS {
        let lp = localpart(user);
        let password = read_trimmed(&secrets_dir.join(format!("password-{user}")))?;
        register_shared_secret(&http, homeserver, &secret, &lp, &password).await?;
        let client = new_client(
            homeserver,
            &out.join("stores").join(user),
            EncryptionSettings {
                auto_enable_cross_signing: true,
                backup_download_strategy: BackupDownloadStrategy::AfterDecryptionFailure,
                auto_enable_backups: false,
            },
        )
        .await?;
        client.matrix_auth().login_username(&lp, &password).initial_device_display_name("mig-rig seed").await?;
        spawn_sync(&client);
        client.encryption().wait_for_e2ee_initialization_tasks().await;
        let recovery_key = client.encryption().recovery().enable().wait_for_backups_to_upload().await?;
        let cs = client.encryption().cross_signing_status().await;
        let cs_ok = cs.as_ref().map(|s| s.has_master && s.has_self_signing && s.has_user_signing).unwrap_or(false);
        if !cs_ok {
            bail!("{lp}: cross-signing not bootstrapped: {cs:?}");
        }
        eprintln!("{lp}: device {:?}, cross-signing ok, recovery {:?}", client.device_id(), client.encryption().recovery().state());
        credentials.insert(format!("recovery-key-{user}"), recovery_key);
        mxids.insert(user.to_owned(), UserId::parse(format!("@{lp}:{server_name}"))?);
        clients.insert(user.to_owned(), client);
    }

    let mut s = Seeder { clients, mxids, salt: random_hex(8), counter: 0 };
    let mut rooms = vec![];

    // (1) encrypted DM a <-> b
    let mut dm = s.create_room("dm", "a", &["b"], true, Some(RoomVersionId::V12), true).await?;
    let first = s.text(&mut dm, "a").await?;
    s.text(&mut dm, "b").await?;
    s.reply(&mut dm, "b", &first).await?;
    let to_edit = s.text(&mut dm, "a").await?;
    s.edit(&mut dm, "a", &to_edit).await?;
    let to_redact = s.text(&mut dm, "b").await?;
    s.redact(&mut dm, "b", &to_redact).await?;
    for i in 0..6 {
        s.text(&mut dm, if i % 2 == 0 { "a" } else { "b" }).await?;
    }
    rooms.push(dm.record);

    // (2) encrypted private group a, b, c: 60+ messages, c leaves and is
    // re-invited part way (rotates the Megolm session), plus topic and
    // power-level changes.
    let mut grp = s.create_room("group", "a", &["b", "c"], true, None, false).await?;
    let topic = s.room("a", &OwnedRoomId::try_from(grp.record.room_id.as_str())?)?.set_room_topic("mig-rig group topic").await?;
    s.record_state(&mut grp, "a", topic.event_id.to_string()).await?;
    let mut sent = vec![];
    for i in 0..25 {
        sent.push(s.text(&mut grp, USERS[i % 3]).await?);
    }
    s.reply(&mut grp, "c", &sent[3]).await?;
    s.edit(&mut grp, "b", &sent[4]).await?;
    s.leave(&mut grp, "c").await?;
    for i in 0..15 {
        sent.push(s.text(&mut grp, if i % 2 == 0 { "a" } else { "b" }).await?);
    }
    let pl = s
        .room("a", &OwnedRoomId::try_from(grp.record.room_id.as_str())?)?
        .update_power_levels(vec![(&s.mxids["b"].clone(), Int::new(50).unwrap())])
        .await?;
    s.record_state(&mut grp, "a", pl.event_id.to_string()).await?;
    s.rejoin(&mut grp, "a", "c").await?;
    for i in 0..20 {
        sent.push(s.text(&mut grp, USERS[i % 3]).await?);
    }
    s.reply(&mut grp, "a", &sent[30]).await?;
    s.edit(&mut grp, "a", &sent[43]).await?;
    s.redact(&mut grp, "a", &sent[0]).await?;
    let topic2 = s.room("b", &OwnedRoomId::try_from(grp.record.room_id.as_str())?)?.set_room_topic("mig-rig group topic, changed by b").await?;
    s.record_state(&mut grp, "b", topic2.event_id.to_string()).await?;
    rooms.push(grp.record);

    // (3) unencrypted room
    let mut plain = s.create_room("plain", "a", &["b"], false, Some(RoomVersionId::V11), false).await?;
    let p1 = s.text(&mut plain, "a").await?;
    s.text(&mut plain, "b").await?;
    s.reply(&mut plain, "b", &p1).await?;
    s.edit(&mut plain, "a", &p1).await?;
    let p_red = s.text(&mut plain, "a").await?;
    s.redact(&mut plain, "a", &p_red).await?;
    let t = s.room("a", &OwnedRoomId::try_from(plain.record.room_id.as_str())?)?.set_room_topic("mig-rig plain topic").await?;
    s.record_state(&mut plain, "a", t.event_id.to_string()).await?;
    rooms.push(plain.record);

    // (4) encrypted room at room version 10 (#456)
    let mut v10 = s.create_room("v10", "a", &["b", "c"], true, Some(RoomVersionId::V10), false).await?;
    let mut v10sent = vec![];
    for i in 0..10 {
        v10sent.push(s.text(&mut v10, USERS[i % 3]).await?);
    }
    s.reply(&mut v10, "b", &v10sent[1]).await?;
    s.edit(&mut v10, "a", &v10sent[0]).await?;
    s.redact(&mut v10, "c", &v10sent[2]).await?;
    let t = s.room("a", &OwnedRoomId::try_from(v10.record.room_id.as_str())?)?.set_room_topic("mig-rig v10 topic").await?;
    s.record_state(&mut v10, "a", t.event_id.to_string()).await?;
    rooms.push(v10.record);

    // Let every client receive every room key, prove it can read what it
    // should, then let each backup reach a steady state.
    let check = seed_self_check(&s, &rooms).await?;
    for user in USERS {
        s.clients[user].encryption().backups().wait_for_steady_state().await?;
        let token = s.clients[user].access_token().unwrap_or_default();
        backups.insert(user.to_owned(), backup_info(&http, homeserver, &token).await);
    }
    let (a_ok, a_want) = check["a"];
    let manifest = Manifest {
        format: 1,
        server_name: server_name.clone(),
        seeded_at: now_secs(),
        seeded_against: homeserver.to_owned(),
        users: s.mxids.iter().map(|(k, v)| (k.clone(), v.to_string())).collect(),
        rooms,
    };
    std::fs::write(out.join("manifest.json"), serde_json::to_string_pretty(&manifest)?)?;
    write_private(&out.join("credentials.json"), &serde_json::to_string_pretty(&credentials)?)?;
    let summary = json!({
        "self_check": check.iter().map(|(k, (ok, want))| (k.clone(), json!({"ok": ok, "expected": want}))).collect::<BTreeMap<_, _>>(),
        "backups": backups,
        "rooms": manifest.rooms.iter().map(|r| json!({
            "key": r.key, "room_id": r.room_id, "room_version": r.room_version, "encrypted": r.encrypted,
            "events": r.events.len(),
            "sessions": r.events.iter().filter_map(|e| e.session_id.clone()).collect::<BTreeSet<_>>().len(),
        })).collect::<Vec<_>>(),
    });
    std::fs::write(out.join("seed-summary.json"), serde_json::to_string_pretty(&summary)?)?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    if a_ok != a_want {
        bail!("user a cannot read {}/{} of its own history on the seeding device", a_want - a_ok, a_want);
    }
    Ok(())
}

// ------------------------------------------------------------------ verify

#[derive(Serialize)]
struct EventResult {
    room: String,
    event_id: String,
    kind: String,
    expected: String,
    outcome: String,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

async fn verify(args: &Args) -> Result<bool> {
    let homeserver = args.req("homeserver")?;
    let manifest: Manifest = serde_json::from_str(&std::fs::read_to_string(args.req("manifest")?)?)?;
    let user_arg = args.req("user")?;
    // Accept a manifest key (a), a localpart or a full MXID.
    let (user_key, mxid) = if let Some(m) = manifest.users.get(user_arg) {
        (user_arg.to_owned(), m.clone())
    } else if let Some((k, m)) = manifest.users.iter().find(|(_, m)| m.as_str() == user_arg || m.trim_start_matches('@').split(':').next() == Some(user_arg)) {
        (k.clone(), m.clone())
    } else {
        bail!("{user_arg} is not a manifest user ({:?})", manifest.users.values().collect::<Vec<_>>());
    };
    let password = match args.get("password-file") {
        Some(p) => read_trimmed(Path::new(p))?,
        None => std::env::var("RIG_PASSWORD").context("--password-file or RIG_PASSWORD")?,
    };
    let recovery_key = match args.get("recovery-key-file") {
        Some(p) => read_trimmed(Path::new(p))?,
        None => std::env::var("RIG_RECOVERY_KEY").context("--recovery-key-file or RIG_RECOVERY_KEY")?,
    };
    let store = std::env::temp_dir().join(format!("mig-rig-verify-{}", random_hex(6)));
    let client = new_client(homeserver, &store, EncryptionSettings::default()).await?;
    let localpart = mxid.trim_start_matches('@').split(':').next().unwrap_or_default().to_owned();
    client
        .matrix_auth()
        .login_username(&localpart, &password)
        .initial_device_display_name(&format!("mig-rig verify {}", now_secs()))
        .await
        .context("password login")?;
    let device = client.device_id().map(|d| d.to_string()).unwrap_or_default();
    eprintln!("logged in as {mxid} on new device {device} at {homeserver}");
    client.sync_once(SyncSettings::default().timeout(Duration::from_secs(1))).await?;
    client.encryption().wait_for_e2ee_initialization_tasks().await;

    let recover = client.encryption().recovery().recover(&recovery_key).await;
    let recovery_ok = recover.is_ok();
    if let Err(e) = &recover {
        eprintln!("recovery failed: {e}");
    }
    client.sync_once(SyncSettings::default().timeout(Duration::from_secs(1))).await?;
    let cs = client.encryption().cross_signing_status().await;
    let own_cross_signed = match client.encryption().get_own_device().await {
        Ok(Some(d)) => d.is_cross_signed_by_owner(),
        _ => false,
    };
    let http = reqwest::Client::new();
    let backup = backup_info(&http, homeserver, &client.access_token().unwrap_or_default()).await;

    let mut results = vec![];
    let mut rooms_out = vec![];
    for rr in &manifest.rooms {
        let rid = OwnedRoomId::try_from(rr.room_id.as_str())?;
        let Some(room) = client.get_room(&rid) else {
            let required = rr.events.iter().any(|e| e.readable_by.iter().any(|u| *u == user_key));
            rooms_out.push(json!({"key": rr.key, "room_id": rr.room_id, "present": false, "required": required}));
            for e in &rr.events {
                let expected = expected_for(e, &user_key);
                results.push(EventResult { room: rr.key.clone(), event_id: e.event_id.clone(), kind: e.kind.clone(), ok: expected == "not-required", expected, outcome: "room-not-joined".into(), detail: None });
            }
            continue;
        };
        let version = room.version().map(|v| v.to_string()).unwrap_or_else(|| "?".into());
        let download = if rr.encrypted && recovery_ok {
            match client.encryption().backups().download_room_keys_for_room(&rid).await {
                Ok(()) => "ok".to_owned(),
                Err(e) => format!("error: {e}"),
            }
        } else {
            "skipped".into()
        };
        rooms_out.push(json!({"key": rr.key, "room_id": rr.room_id, "present": true,
            "room_version": version, "room_version_expected": rr.room_version,
            "room_version_ok": version == rr.room_version, "backup_download": download}));
        for e in &rr.events {
            results.push(check_event(&room, rr, e, &user_key).await);
        }
    }

    let expected_readable = results.iter().filter(|r| r.expected == "decrypt" || r.expected == "plaintext").count();
    let decrypted_ok = results.iter().filter(|r| r.ok && (r.expected == "decrypt" || r.expected == "plaintext")).count();
    let failures: Vec<&EventResult> = results.iter().filter(|r| !r.ok).collect();
    let rooms_ok = rooms_out.iter().all(|r| (r["present"] == json!(true) && r["room_version_ok"] == json!(true)) || r["required"] == json!(false));
    let pass = recovery_ok && own_cross_signed && failures.is_empty() && rooms_ok;
    let report = json!({
        "pass": pass,
        "homeserver": homeserver,
        "user": mxid,
        "device": device,
        "checked_at": now_secs(),
        "recovery_ok": recovery_ok,
        "recovery_error": recover.err().map(|e| e.to_string()),
        "recovery_state": format!("{:?}", client.encryption().recovery().state()),
        "cross_signing": cs.map(|s| json!({"master": s.has_master, "self_signing": s.has_self_signing, "user_signing": s.has_user_signing})),
        "own_device_cross_signed": own_cross_signed,
        "backup": backup,
        "rooms": rooms_out,
        "summary": {
            "events": results.len(),
            "expected_readable": expected_readable,
            "readable_ok": decrypted_ok,
            "failures": failures.len(),
            "by_outcome": results.iter().fold(BTreeMap::<String, usize>::new(), |mut m, r| { *m.entry(r.outcome.clone()).or_default() += 1; m }),
        },
        "events": results,
    });
    let text = serde_json::to_string_pretty(&report)?;
    if let Some(path) = args.get("report") {
        std::fs::write(path, &text)?;
    }
    println!("{text}");
    eprintln!(
        "verify {}: recovery={recovery_ok} cross-signed={own_cross_signed} readable {decrypted_ok}/{expected_readable}, failures {}",
        if pass { "PASS" } else { "FAIL" },
        failures.len()
    );
    if !args.flag("keep-device") {
        let _ = client.matrix_auth().logout().await;
    }
    let _ = std::fs::remove_dir_all(&store);
    Ok(pass)
}

fn expected_for(e: &EventRecord, user: &str) -> String {
    let member = e.readable_by.iter().any(|u| u == user);
    match e.kind.as_str() {
        // Sent while the user was not joined: nothing is required (history
        // visibility may or may not show it); recorded, never a failure.
        _ if !member => "not-required".into(),
        "redacted" => "redacted".into(),
        "redaction" | "state" => "present".into(),
        _ if !e.encrypted => "plaintext".into(),
        _ => "decrypt".into(),
    }
}

async fn check_event(room: &Room, rr: &RoomRecord, e: &EventRecord, user: &str) -> EventResult {
    let expected = expected_for(e, user);
    let mut r = EventResult { room: rr.key.clone(), event_id: e.event_id.clone(), kind: e.kind.clone(), expected: expected.clone(), outcome: String::new(), ok: false, detail: None };
    let not_required = expected == "not-required";
    let Ok(eid) = EventId::parse(e.event_id.as_str()) else {
        r.outcome = "bad-event-id".into();
        return r;
    };
    let ev = match room.event(&eid, None).await {
        Ok(ev) => ev,
        Err(err) => {
            r.outcome = "fetch-failed".into();
            r.detail = Some(err.to_string());
            r.ok = expected == "not-required";
            return r;
        }
    };
    let raw: Value = ev.kind.raw().deserialize_as_unchecked().unwrap_or(Value::Null);
    match (&ev.kind, e.kind.as_str()) {
        (_, "redacted") => {
            let redacted = raw["unsigned"]["redacted_because"].is_object() || raw["content"].as_object().map(|c| c.is_empty()).unwrap_or(false);
            r.outcome = if redacted { "redacted".into() } else { "not-redacted".into() };
            r.ok = redacted;
        }
        (_, "redaction" | "state") => {
            let type_ok = raw["type"].as_str() == Some(e.event_type.as_str());
            let content_ok = match &e.sha256 {
                Some(h) => serde_json::to_string(&raw["content"]).map(|s| &sha256_hex(&s) == h).unwrap_or(false),
                None => true,
            };
            r.outcome = if type_ok && content_ok { "present".into() } else { "content-mismatch".into() };
            r.ok = type_ok && content_ok;
        }
        (TimelineEventKind::UnableToDecrypt { utd_info, .. }, _) => {
            r.outcome = "utd".into();
            r.detail = Some(format!("{:?} session={:?}", utd_info.reason, utd_info.session_id));
            r.ok = false;
        }
        (kind, _) => {
            let h = body_hash(kind);
            let matches = h.is_some() && h.as_ref() == e.sha256.as_ref();
            let decrypted = matches!(kind, TimelineEventKind::Decrypted(_));
            r.outcome = match (decrypted, matches) {
                (true, true) => "decrypted".into(),
                (false, true) => "plaintext".into(),
                (_, false) => "hash-mismatch".into(),
            };
            r.ok = match expected.as_str() {
                "decrypt" => decrypted && matches,
                "plaintext" => !decrypted && matches,
                // readable although the user was not joined at send time
                // (e.g. shared history); not a failure.
                _ => true,
            };
        }
    }
    if not_required {
        r.ok = true;
    }
    r
}

// -------------------------------------------------------------------- args

struct Args {
    cmd: String,
    opts: BTreeMap<String, String>,
    flags: BTreeSet<String>,
}

impl Args {
    fn parse() -> Result<Self> {
        let mut it = std::env::args().skip(1);
        let cmd = it.next().ok_or_else(|| anyhow!("usage: mig-rig seed|verify --help"))?;
        let mut opts = BTreeMap::new();
        let mut flags = BTreeSet::new();
        let rest: Vec<String> = it.collect();
        let mut i = 0;
        while i < rest.len() {
            let a = rest[i].strip_prefix("--").ok_or_else(|| anyhow!("unexpected argument {}", rest[i]))?;
            if let Some((k, v)) = a.split_once('=') {
                opts.insert(k.to_owned(), v.to_owned());
            } else if i + 1 < rest.len() && !rest[i + 1].starts_with("--") {
                opts.insert(a.to_owned(), rest[i + 1].clone());
                i += 1;
            } else {
                flags.insert(a.to_owned());
            }
            i += 1;
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
        self.flags.contains(k)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse()?;
    match args.cmd.as_str() {
        "seed" => seed(&args).await,
        "verify" => {
            if verify(&args).await? {
                Ok(())
            } else {
                std::process::exit(1)
            }
        }
        _ => {
            eprintln!("{}", include_str!("main.rs").lines().take(12).collect::<Vec<_>>().join("\n"));
            bail!("unknown command {}", args.cmd)
        }
    }
}
