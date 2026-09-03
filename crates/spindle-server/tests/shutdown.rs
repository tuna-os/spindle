//! #292's production shape: a SIGTERM to a server with a federation
//! listener closes the store on the thread that opened it, after every
//! listener is gone, and the process exits.
//!
//! The federation listener is a spawned task holding its own copy of the
//! router, and through it the store. Abandoned, it would be the store's
//! last owner at exit, dropped by the runtime tearing its tasks down --
//! and fjall's close joins its worker threads, which is where #292 caught
//! it waiting forever. So `serve` drains and joins the listener before it
//! closes the store, and logs the close; the log is what this reads, since
//! the ordering is not otherwise visible from outside the process.

#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tempfile::TempDir;

/// Poll the captured output until `marker` appears, killing the server
/// and failing if it does not within the deadline.
fn wait_for(output: &Mutex<Vec<String>>, marker: &str, child: &mut std::process::Child) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if output
            .lock()
            .unwrap()
            .iter()
            .any(|line| line.contains(marker))
        {
            return;
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!(
                "the server exited ({status}) before logging {marker:?}:\n{}",
                output.lock().unwrap().join("\n")
            );
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!(
                "the server did not log {marker:?} within 30 s:\n{}",
                output.lock().unwrap().join("\n")
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn sigterm_with_a_federation_listener_closes_the_store_and_exits() {
    let work = TempDir::new().unwrap();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert = work.path().join("cert.pem");
    std::fs::write(&cert, certified.cert.pem()).unwrap();
    let key = work.path().join("key.pem");
    std::fs::write(&key, certified.signing_key.serialize_pem()).unwrap();
    let config = work.path().join("spindle.toml");
    std::fs::write(
        &config,
        format!(
            "[server]\nname = \"example.org\"\nbind = \"127.0.0.1:0\"\n\
             [storage]\npath = \"{}\"\n\
             [federation]\nbind = \"127.0.0.1:0\"\ntls_cert = \"{}\"\ntls_key = \"{}\"\n",
            work.path().join("data").display(),
            cert.display(),
            key.display()
        ),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_spindle"))
        .arg(&config)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("the spindle binary runs");
    let stdout = child.stdout.take().unwrap();
    let output: Arc<Mutex<Vec<String>>> = Arc::default();
    let reader = std::thread::spawn({
        let output = Arc::clone(&output);
        move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                output.lock().unwrap().push(line);
            }
        }
    });

    // Both listeners are up. The signal is listened for before either is
    // bound, so this is not racing the handler's installation.
    wait_for(&output, "federation listening on", &mut child);
    wait_for(&output, "spindle listening on", &mut child);
    let signalled = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(signalled.success());

    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!(
                "the server did not exit within 30 s of SIGTERM:\n{}",
                output.lock().unwrap().join("\n")
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    reader.join().unwrap();
    let lines = output.lock().unwrap().join("\n");
    assert!(status.success(), "exit {status}:\n{lines}");
    assert!(
        lines.contains("storage closed"),
        "the store did not close on the serving thread:\n{lines}"
    );
    assert!(lines.contains("shut down cleanly"), "{lines}");
    // The close came after the listener was gone, not before: the order
    // the lines were logged in is the order the shutdown ran in.
    let position = |marker: &str| lines.find(marker).unwrap_or(usize::MAX);
    assert!(
        position("terminating, draining") < position("storage closed"),
        "{lines}"
    );
}
