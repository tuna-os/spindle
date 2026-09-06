//! #413: the metrics listener and the OTLP trace exporter, end to end
//! through the built binary.
//!
//! `tests/metrics.rs` reads the registry in-process, which proves the
//! numbers. What it cannot prove is the operator's side: that `[metrics]
//! bind` opens a second listener serving `GET /metrics` in the Prometheus
//! text format, and that `[logging] traces = "otlp"` sends a request's
//! span to whatever `OTEL_EXPORTER_OTLP_ENDPOINT` names and flushes it on
//! shutdown. Both run here against a real process, with a stand-in
//! collector that accepts `POST /v1/traces` and counts what arrives.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tempfile::TempDir;

/// A port nothing holds right now, for a listener the config must name
/// before the process exists to pick one.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Poll the captured output until `marker` appears, killing the server
/// and failing if it does not within the deadline.
async fn wait_for(output: &Mutex<Vec<String>>, marker: &str, child: &mut std::process::Child) {
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
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The stand-in collector: any OTLP/HTTP trace export is a 200 and a
/// count. It knows nothing of protobuf, and need not: the assertion is
/// that the exporter was wired to the endpoint named and flushed.
async fn collector() -> (u16, Arc<AtomicUsize>) {
    let received = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = axum::Router::new().route(
        "/v1/traces",
        axum::routing::post({
            let received = Arc::clone(&received);
            move || {
                received.fetch_add(1, Ordering::SeqCst);
                async { axum::http::StatusCode::OK }
            }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (port, received)
}

/// SIGTERM the server and wait for it to exit cleanly.
async fn stop(child: &mut std::process::Child) {
    let signalled = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(signalled.success());
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "the server exited {status}");
            return;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("the server did not exit within 30 s of SIGTERM");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_metrics_listener_serves_prometheus_text_and_traces_reach_the_collector() {
    let (collector_port, received) = collector().await;

    let work = TempDir::new().unwrap();
    let server_port = free_port();
    let metrics_port = free_port();
    let config = work.path().join("spindle.toml");
    std::fs::write(
        &config,
        format!(
            "[server]\nname = \"example.org\"\nbind = \"127.0.0.1:{server_port}\"\n\
             [storage]\npath = \"{}\"\n\
             [metrics]\nbind = \"127.0.0.1:{metrics_port}\"\n\
             [logging]\ntraces = \"otlp\"\n",
            work.path().join("data").display(),
        ),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_spindle"))
        .arg(&config)
        .env(
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            format!("http://127.0.0.1:{collector_port}"),
        )
        // The exporter must not be sent through a proxy the sandbox may
        // have configured; the collector is on loopback.
        .env("NO_PROXY", "*")
        .env("no_proxy", "*")
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
    wait_for(&output, "metrics listening on", &mut child).await;
    wait_for(&output, "spindle listening on", &mut child).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();

    // A request the server instruments, so there is a span to export.
    let health = client
        .get(format!(
            "http://127.0.0.1:{server_port}/_matrix/client/versions"
        ))
        .send()
        .await
        .expect("the server answers");
    assert_eq!(health.status(), 200);

    // The second listener, in the format Prometheus scrapes.
    let scraped = client
        .get(format!("http://127.0.0.1:{metrics_port}/metrics"))
        .send()
        .await
        .expect("the metrics listener answers");
    assert_eq!(scraped.status(), 200);
    let content_type = scraped
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert!(
        content_type.starts_with("text/plain; version=0.0.4"),
        "content-type: {content_type}"
    );
    let body = scraped.text().await.unwrap();
    assert!(body.contains("spindle_build_info{"), "{body}");
    assert!(
        body.contains("spindle_http_requests_total") || body.contains("spindle_request"),
        "the request just made is counted:\n{body}"
    );

    // A stop flushes the batch exporter, so the span reaches the collector
    // before the process is gone.
    stop(&mut child).await;
    reader.join().unwrap();
    assert!(
        received.load(Ordering::SeqCst) >= 1,
        "no trace export reached the collector; server output:\n{}",
        output.lock().unwrap().join("\n")
    );
}
