//! #20: the backup and restore an operator actually runs.
//!
//! `spindle-store`'s `backup_restore` tests cover the format. These cover the
//! two refusals that only exist at the command line, and both are refusals
//! rather than features — the ways a lifecycle tool destroys the thing it was
//! run to protect:
//!
//! - a backup that overwrites is one keystroke from replacing the good copy
//!   with a bad one, discovered at restore time;
//! - a restore into a populated store is a *merge*: rows the target holds and
//!   the backup does not survive it, so the result matches neither.

use std::process::Command;

use tempfile::TempDir;

/// Write a config naming a store directory under `work`.
fn config_for(work: &TempDir, data: &str) -> std::path::PathBuf {
    let config_path = work.path().join(format!("{data}.toml"));
    std::fs::write(
        &config_path,
        format!(
            "[server]\nname = \"example.org\"\n[storage]\npath = \"{}\"\n",
            work.path().join(data).display()
        ),
    )
    .unwrap();
    config_path
}

fn run(args: &[&std::ffi::OsStr]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_spindle"))
        .args(args)
        .output()
        .expect("the spindle binary runs")
}

fn os(value: &str) -> &std::ffi::OsStr {
    std::ffi::OsStr::new(value)
}

/// Put real rows in the store the config names.
///
/// Without this the store holds only its schema marker, and every assertion
/// below passes vacuously: an empty backup restores into an empty store and
/// leaves it empty, so "restore refuses a populated store" never gets a
/// populated store to refuse. The first version of these tests did exactly
/// that and looked green.
fn seed(config_path: &std::path::Path) {
    let config = spindle_server::Config::load(config_path.to_str().unwrap()).unwrap();
    let store = spindle_store::FjallStore::open(&config.storage.path).unwrap();
    let room_store = spindle_store::RoomStore::new(&store, "!seeded:example.org");
    let mut log = spindle_core::RoomLog::new();
    for number in 0..6 {
        let entry = log.append_local(format!("$seed-{number}"), None).unwrap();
        let entry = entry.clone();
        room_store
            .commit_entry(&entry, &log, spindle_store::Durability::Strict)
            .unwrap();
    }
}

/// A store backed up and restored into an empty store comes back.
#[test]
fn backup_then_restore_reproduces_the_store() {
    let work = TempDir::new().unwrap();
    let source = config_for(&work, "source");
    let target = config_for(&work, "target");
    let file = work.path().join("spindle.backup");

    seed(&source);

    let backed_up = run(&[os("backup"), source.as_os_str(), file.as_os_str()]);
    assert!(
        backed_up.status.success(),
        "backup failed: {}",
        String::from_utf8_lossy(&backed_up.stderr)
    );
    assert!(file.exists(), "the backup file was written");

    let restored = run(&[os("restore"), target.as_os_str(), file.as_os_str()]);
    assert!(
        restored.status.success(),
        "restore failed: {}",
        String::from_utf8_lossy(&restored.stderr)
    );
    let said = String::from_utf8_lossy(&restored.stdout);
    assert!(said.contains("restored"), "{said:?}");
    // The count is the point: a vacuous backup would restore nothing and
    // still say "restored".
    assert!(
        !said.contains("restored 0 rows"),
        "the backup carried no rows, so this proves nothing: {said:?}"
    );
}

/// A backup refuses to overwrite a file that is already there.
#[test]
fn backup_refuses_to_overwrite_an_existing_file() {
    let work = TempDir::new().unwrap();
    let config = config_for(&work, "data");
    let file = work.path().join("spindle.backup");
    std::fs::write(&file, b"an earlier backup nobody wants replaced").unwrap();

    let output = run(&[os("backup"), config.as_os_str(), file.as_os_str()]);
    assert!(!output.status.success(), "overwriting must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("refusing to overwrite"),
        "the refusal says why: {stderr}"
    );
    assert_eq!(
        std::fs::read(&file).unwrap(),
        b"an earlier backup nobody wants replaced",
        "the existing backup is untouched"
    );
}

/// A restore refuses a store that already holds rows.
///
/// Not a safety rail around a rare mistake: restoring over a populated store
/// silently produces a third thing that is neither the backup nor the
/// original, and looks like a success.
#[test]
fn restore_refuses_a_store_that_is_not_empty() {
    let work = TempDir::new().unwrap();
    let source = config_for(&work, "source");
    let target = config_for(&work, "target");
    let file = work.path().join("spindle.backup");
    seed(&source);

    let backed_up = run(&[os("backup"), source.as_os_str(), file.as_os_str()]);
    assert!(backed_up.status.success());

    // First restore into the empty target: fine.
    let first = run(&[os("restore"), target.as_os_str(), file.as_os_str()]);
    assert!(
        first.status.success(),
        "the first restore should succeed: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    // Second restore into the now-populated target: refused.
    let second = run(&[os("restore"), target.as_os_str(), file.as_os_str()]);
    assert!(
        !second.status.success(),
        "restoring into a populated store must fail"
    );
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        stderr.contains("already holds") && stderr.contains("merge"),
        "the refusal explains the hazard: {stderr}"
    );
}

/// A file that is not a backup is refused by name.
#[test]
fn restore_refuses_something_that_is_not_a_backup() {
    let work = TempDir::new().unwrap();
    let config = config_for(&work, "data");
    let not_a_backup = work.path().join("spindle.toml.bak");
    std::fs::write(&not_a_backup, b"[server]\nname = \"example.org\"\n").unwrap();

    let output = run(&[os("restore"), config.as_os_str(), not_a_backup.as_os_str()]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not a Spindle backup"),
        "the refusal names the problem: {stderr}"
    );
}

/// Put one media record in the store, and optionally its blob on disk.
///
/// The two are written separately on purpose: that separation is the whole
/// subject. A record without its blob is exactly the state a row-only
/// restore leaves behind, and it is indistinguishable from a healthy server
/// until someone asks for the file.
fn seed_media(config_path: &std::path::Path, bytes: &[u8], with_blob: bool) -> String {
    let config = spindle_server::Config::load(config_path.to_str().unwrap()).unwrap();
    let store = spindle_store::FjallStore::open(&config.storage.path).unwrap();
    let hash = blake3::hash(bytes).to_hex().to_string();
    let media_id = format!("media{}", &hash[..8]);
    let record = serde_json::json!({
        "hash": hash,
        "content_type": "text/plain",
        "filename": "note.txt",
        "size": bytes.len(),
        "uploaded_by": "@alice:example.org",
    });
    spindle_store::Store::put(
        &store,
        &spindle_core::keys::media(&media_id),
        &serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    if with_blob {
        let root = config.storage.path.join("media");
        let path = root.join(&hash[0..2]).join(&hash[2..4]).join(&hash);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
    media_id
}

#[test]
fn verify_media_is_silent_about_a_store_whose_blobs_are_all_there() {
    let work = TempDir::new().unwrap();
    let config = config_for(&work, "data");
    seed(&config);
    seed_media(&config, b"present", true);

    let output = run(&[os("verify-media"), os(config.to_str().unwrap())]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{text}{:?}", output.stderr);
    assert!(text.contains("1 blobs, all present"), "{text}");
}

#[test]
fn verify_media_names_the_files_a_missing_blob_takes_down() {
    let work = TempDir::new().unwrap();
    let config = config_for(&work, "data");
    seed(&config);
    let present = seed_media(&config, b"present", true);
    let absent = seed_media(&config, b"absent", false);

    let output = run(&[os("verify-media"), os(config.to_str().unwrap())]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        !output.status.success(),
        "a store missing a blob reported healthy: {text}"
    );
    assert!(text.contains("2 blobs, 1 present, 1 MISSING"), "{text}");
    // The media ID, not just the hash: the hash is what the backend calls
    // it, and the ID is what an operator has to look for in their other copy.
    assert!(text.contains(&absent), "{text}");
    assert!(
        !text.contains(&present),
        "the present blob was reported: {text}"
    );
}

#[test]
fn a_restore_says_which_media_the_rows_it_wrote_still_need() {
    let work = TempDir::new().unwrap();
    let source = config_for(&work, "source");
    seed(&source);
    let orphan = seed_media(&source, b"only a row survives this", true);

    let archive = work.path().join("backup.spindle");
    let output = run(&[
        os("backup"),
        os(source.to_str().unwrap()),
        os(archive.to_str().unwrap()),
    ]);
    assert!(output.status.success());

    // The target is a fresh directory, so the rows arrive and the blobs do
    // not -- which is what happens to anyone who copies the backup file and
    // forgets the media directory.
    let target = config_for(&work, "target");
    let output = run(&[
        os("restore"),
        os(target.to_str().unwrap()),
        os(archive.to_str().unwrap()),
    ]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{text}");
    assert!(text.contains("restored"), "{text}");
    assert!(
        text.contains("1 MISSING") && text.contains(&orphan),
        "the restore claimed success without naming the media it is missing: {text}"
    );
}
