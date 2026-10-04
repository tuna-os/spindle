use std::collections::HashMap;
use std::sync::Mutex;

use hickory_resolver::config::{LookupIpStrategy, NameServerConfig, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::op::{Message, MessageType, OpCode};
use hickory_resolver::proto::rr::{
    Name, RData, Record, RecordType,
    rdata::{A, SRV},
};
use hickory_resolver::proto::xfer::Protocol;
use rand::SeedableRng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use super::*;

struct Dns {
    resolver: TokioResolver,
    asked: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Dns {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn dns(records: Vec<(&str, RData)>) -> Dns {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let mut answers: HashMap<(String, RecordType), Vec<RData>> = HashMap::new();
    for (name, data) in records {
        answers
            .entry((name.to_owned(), data.record_type()))
            .or_default()
            .push(data);
    }
    let asked: Arc<Mutex<Vec<String>>> = Arc::default();
    let queries = Arc::clone(&asked);
    let task = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        loop {
            let (length, peer) = socket.recv_from(&mut bytes).await.unwrap();
            let query = Message::from_vec(&bytes[..length]).unwrap();
            let mut response = Message::new();
            response
                .set_id(query.id())
                .set_message_type(MessageType::Response)
                .set_op_code(OpCode::Query)
                .set_authoritative(true)
                .set_recursion_desired(true)
                .set_recursion_available(true);
            for question in query.queries() {
                response.add_query(question.clone());
                let name = question.name().to_utf8();
                queries.lock().unwrap().push(name.clone());
                for data in answers
                    .get(&(name, question.query_type()))
                    .into_iter()
                    .flatten()
                {
                    response.add_answer(Record::from_rdata(
                        question.name().clone(),
                        30,
                        data.clone(),
                    ));
                }
            }
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let config = ResolverConfig::from_parts(
        None,
        vec![],
        vec![NameServerConfig::new(address, Protocol::Udp)],
    );
    let mut builder =
        hickory_resolver::Resolver::builder_with_config(config, TokioConnectionProvider::default());
    builder.options_mut().attempts = 1;
    builder.options_mut().timeout = Duration::from_millis(500);
    builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    Dns {
        resolver: builder.build(),
        asked,
        task,
    }
}

fn srv(priority: u16, weight: u16, port: u16, target: &str) -> RData {
    RData::SRV(SRV::new(
        priority,
        weight,
        port,
        Name::from_ascii(target).unwrap(),
    ))
}

fn ipv4() -> RData {
    RData::A(A::new(127, 0, 0, 1))
}

async fn headers(stream: &mut (impl AsyncRead + Unpin)) -> String {
    let mut bytes = Vec::new();
    while !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
        let mut chunk = [0; 4096];
        let length = stream.read(&mut chunk).await.unwrap();
        assert_ne!(length, 0);
        bytes.extend_from_slice(&chunk[..length]);
        assert!(bytes.len() < 65536);
    }
    let boundary = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let length = String::from_utf8_lossy(&bytes[..boundary])
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    while bytes.len() < boundary + length {
        let mut chunk = [0; 4096];
        let received = stream.read(&mut chunk).await.unwrap();
        assert_ne!(received, 0);
        bytes.extend_from_slice(&chunk[..received]);
        assert!(bytes.len() < 65536);
    }
    String::from_utf8(bytes).unwrap()
}

async fn http() -> (u16, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = headers(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
            .await
            .unwrap();
        request
    });
    (port, task)
}

#[test]
fn weighted_draws_keep_priorities_and_use_all_candidates_once() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(7842);
    let ranks = [(20, 0), (10, 1), (10, 100), (30, 20)];
    let mut high_weight_first = 0;
    for _ in 0..4096 {
        let order = weighted_order_with(&ranks, &mut rng);
        assert_eq!(order[2..], [0, 3]);
        assert!(order[..2].contains(&1) && order[..2].contains(&2));
        high_weight_first += usize::from(order[0] == 2);
    }
    assert!(high_weight_first > 3800);
    let zero = weighted_order_with(&[(0, 0); 8], &mut rng);
    let mut sorted = zero;
    sorted.sort_unstable();
    assert_eq!(sorted, (0..8).collect::<Vec<_>>());
}

#[tokio::test]
async fn modern_srv_fails_over_a_closed_port_and_keeps_the_logical_host() {
    let (port, server) = http().await;
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable = closed.local_addr().unwrap().port();
    drop(closed);
    let dns = dns(vec![
        (
            "_matrix-fed._tcp.logical.test.",
            srv(0, 0, unavailable, "closed.test."),
        ),
        (
            "_matrix-fed._tcp.logical.test.",
            srv(10, 0, port, "backend.test."),
        ),
        ("closed.test.", ipv4()),
        ("backend.test.", ipv4()),
    ])
    .await;
    let (destination, _) = resolve(
        &dns.resolver,
        "logical.test",
        &[Cidr::parse("127.0.0.0/8").unwrap()],
        true,
    )
    .await
    .unwrap();
    let response = destination
        .unwrap()
        .request(reqwest::Method::GET, "/path?x=1")
        .timeout(Duration::from_secs(3))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let request = server.await.unwrap().to_lowercase();
    assert!(request.starts_with("get /path?x=1 http/1.1"));
    assert!(request.contains("\r\nhost: logical.test\r\n"));
    assert!(
        !dns.asked
            .lock()
            .unwrap()
            .iter()
            .any(|n| n.starts_with("_matrix._tcp"))
    );
}

#[tokio::test]
async fn legacy_srv_is_used_only_after_modern_records_are_absent() {
    let (port, server) = http().await;
    let dns = dns(vec![
        (
            "_matrix._tcp.logical.test.",
            srv(0, 0, port, "backend.test."),
        ),
        ("backend.test.", ipv4()),
    ])
    .await;
    let (destination, _) = resolve(
        &dns.resolver,
        "logical.test",
        &[Cidr::parse("127.0.0.0/8").unwrap()],
        true,
    )
    .await
    .unwrap();
    destination
        .unwrap()
        .request(reqwest::Method::GET, "/legacy")
        .send()
        .await
        .unwrap();
    assert!(server.await.unwrap().contains("/legacy"));
    let asked = dns.asked.lock().unwrap();
    assert!(
        asked
            .iter()
            .position(|n| n == "_matrix-fed._tcp.logical.test.")
            .unwrap()
            < asked
                .iter()
                .position(|n| n == "_matrix._tcp.logical.test.")
                .unwrap()
    );
}

#[tokio::test]
async fn absent_srv_allows_fallback_but_unavailable_service_does_not() {
    let empty = dns(vec![]).await;
    assert!(
        resolve(&empty.resolver, "logical.test", &[], true)
            .await
            .unwrap()
            .0
            .is_none()
    );
    let unavailable = dns(vec![("_matrix-fed._tcp.logical.test.", srv(0, 0, 0, "."))]).await;
    assert!(
        resolve(&unavailable.resolver, "logical.test", &[], true)
            .await
            .is_err()
    );
    assert!(
        !unavailable
            .asked
            .lock()
            .unwrap()
            .iter()
            .any(|n| n.starts_with("_matrix._tcp"))
    );
}

#[tokio::test]
async fn private_srv_targets_are_refused_without_a_fallback_lookup() {
    let dns = dns(vec![
        (
            "_matrix-fed._tcp.logical.test.",
            srv(0, 0, 8448, "private.test."),
        ),
        ("private.test.", RData::A(A::new(169, 254, 169, 254))),
    ])
    .await;
    assert!(
        resolve(&dns.resolver, "logical.test", &[], false)
            .await
            .is_err()
    );
    assert!(
        !dns.asked
            .lock()
            .unwrap()
            .iter()
            .any(|n| n == "logical.test.")
    );
}

async fn tls_server(
    name: &str,
) -> (
    u16,
    reqwest::Certificate,
    tokio::task::JoinHandle<Option<(String, String)>>,
) {
    let certified = rcgen::generate_simple_self_signed(vec![name.to_owned()]).unwrap();
    let certificate = reqwest::Certificate::from_der(certified.cert.der()).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![certified.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()).into(),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let Ok(mut stream) = acceptor.accept(stream).await else {
            return None;
        };
        let sni = stream
            .get_ref()
            .1
            .server_name()
            .unwrap_or_default()
            .to_owned();
        let request = headers(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
            .await
            .unwrap();
        Some((sni, request))
    });
    (port, certificate, task)
}

#[tokio::test]
async fn tls_uses_the_logical_name_and_fails_over_a_wrong_hostname_certificate() {
    let (wrong_port, wrong_certificate, wrong_server) = tls_server("physical.test").await;
    let (right_port, right_certificate, right_server) = tls_server("logical.test").await;
    let mut candidates = Vec::new();
    for (priority, port) in [(0, wrong_port), (10, right_port)] {
        let client = super::super::client_builder(&[Cidr::parse("127.0.0.0/8").unwrap()])
            .add_root_certificate(wrong_certificate.clone())
            .add_root_certificate(right_certificate.clone())
            .resolve("logical.test", SocketAddr::from(([127, 0, 0, 1], port)))
            .build()
            .unwrap();
        candidates.push(Candidate {
            priority,
            weight: 0,
            client,
        });
    }
    let destination = Destination {
        url: "https://logical.test".to_owned(),
        host: Some("logical.test".to_owned()),
        candidates: Arc::new(candidates),
    };
    let authorization =
        "X-Matrix origin=sender.test,destination=original.test,key=ed25519:0,sig=synthetic";
    let response = destination
        .request(
            reqwest::Method::PUT,
            "/_matrix/federation/v1/send/stable-txn",
        )
        .header("authorization", authorization)
        .header("content-type", "application/json")
        .body("{\"pdus\":[]}")
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(
        wrong_server.await.unwrap().is_none(),
        "the physical hostname's certificate must not be accepted"
    );
    let (sni, request) = right_server.await.unwrap().unwrap();
    assert_eq!(sni, "logical.test");
    assert!(
        request
            .to_lowercase()
            .contains("\r\nhost: logical.test\r\n")
    );
    assert!(request.contains(authorization));
    assert!(request.ends_with("{\"pdus\":[]}"));
    assert!(request.starts_with("PUT /_matrix/federation/v1/send/stable-txn HTTP/1.1"));
}

#[tokio::test]
async fn well_known_delegation_uses_the_delegated_srv_name() {
    let (port, server) = http().await;
    let dns = dns(vec![
        (
            "_matrix-fed._tcp.delegated.test.",
            srv(0, 0, port, "backend.test."),
        ),
        ("backend.test.", ipv4()),
    ])
    .await;
    let allowed = vec![Cidr::parse("127.0.0.0/8").unwrap()];
    let resolver = std::sync::OnceLock::new();
    resolver.set(Ok(dns.resolver.clone())).unwrap();
    let discovery = super::super::Discovery {
        client: super::super::client_builder(&allowed).build().unwrap(),
        insecure_http: true,
        allowed,
        delegations: Arc::new(Mutex::new(HashMap::from([(
            "original.test".to_owned(),
            (
                Some("delegated.test".to_owned()),
                Instant::now() + Duration::from_secs(60),
            ),
        )]))),
        destinations: Arc::default(),
        srv_dns: Arc::new(resolver),
        well_known_port: 443,
    };
    let destination = discovery
        .destination("original.test", "http://original.test:8448")
        .await
        .unwrap();
    destination
        .request(reqwest::Method::GET, "/delegated")
        .send()
        .await
        .unwrap();
    assert!(
        server
            .await
            .unwrap()
            .to_lowercase()
            .contains("\r\nhost: delegated.test\r\n")
    );
    assert!(
        dns.asked
            .lock()
            .unwrap()
            .iter()
            .any(|name| name == "_matrix-fed._tcp.delegated.test.")
    );
    assert!(
        !dns.asked
            .lock()
            .unwrap()
            .iter()
            .any(|name| name.contains("original.test"))
    );
}

#[tokio::test]
async fn http_refusal_does_not_replay_a_transaction_on_another_target() {
    let primary = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backup = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let primary_port = primary.local_addr().unwrap().port();
    let backup_port = backup.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = primary.accept().await.unwrap();
        let request = headers(&mut stream).await;
        stream
            .write_all(
                b"HTTP/1.1 503 Unavailable\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
            )
            .await
            .unwrap();
        request
    });
    let dns = dns(vec![
        (
            "_matrix-fed._tcp.logical.test.",
            srv(0, 0, primary_port, "primary.test."),
        ),
        (
            "_matrix-fed._tcp.logical.test.",
            srv(10, 0, backup_port, "backup.test."),
        ),
        ("primary.test.", ipv4()),
        ("backup.test.", ipv4()),
    ])
    .await;
    let destination = resolve(
        &dns.resolver,
        "logical.test",
        &[Cidr::parse("127.0.0.0/8").unwrap()],
        true,
    )
    .await
    .unwrap()
    .0
    .unwrap();
    let response = destination
        .request(reqwest::Method::PUT, "/transaction")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    assert!(server.await.unwrap().ends_with("{}"));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), backup.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn non_root_srv_with_zero_port_is_refused() {
    let dns = dns(vec![(
        "_matrix-fed._tcp.logical.test.",
        srv(0, 0, 0, "backend.test."),
    )])
    .await;
    assert!(
        resolve(&dns.resolver, "logical.test", &[], false)
            .await
            .is_err()
    );
    assert_eq!(
        *dns.asked.lock().unwrap(),
        ["_matrix-fed._tcp.logical.test."]
    );
}

#[tokio::test]
async fn destination_cache_expires_with_its_delegation() {
    let dns = dns(vec![
        (
            "_matrix-fed._tcp.delegated.test.",
            srv(0, 0, 8448, "backend.test."),
        ),
        ("backend.test.", ipv4()),
    ])
    .await;
    let allowed = vec![Cidr::parse("127.0.0.0/8").unwrap()];
    let resolver = std::sync::OnceLock::new();
    resolver.set(Ok(dns.resolver.clone())).unwrap();
    let until = Instant::now() + Duration::from_secs(2);
    let discovery = super::super::Discovery {
        client: super::super::client_builder(&allowed).build().unwrap(),
        insecure_http: true,
        allowed,
        delegations: Arc::new(Mutex::new(HashMap::from([(
            "original.test".to_owned(),
            (Some("delegated.test".to_owned()), until),
        )]))),
        destinations: Arc::default(),
        srv_dns: Arc::new(resolver),
        well_known_port: 443,
    };
    discovery
        .destination("original.test", "http://original.test:8448")
        .await
        .unwrap();
    assert_eq!(
        discovery.destinations.lock().unwrap()["original.test"].1,
        until
    );
    let count = dns.asked.lock().unwrap().len();
    discovery
        .destination("original.test", "http://original.test:8448")
        .await
        .unwrap();
    assert_eq!(
        dns.asked.lock().unwrap().len(),
        count,
        "a live destination is reused"
    );
}

#[tokio::test]
async fn explicit_delegations_skip_srv_and_destination_pools_are_bounded() {
    let allowed = vec![Cidr::parse("127.0.0.0/8").unwrap()];
    let discovery = super::super::Discovery {
        client: super::super::client_builder(&allowed).build().unwrap(),
        insecure_http: true,
        allowed,
        delegations: Arc::default(),
        destinations: Arc::default(),
        srv_dns: Arc::default(),
        well_known_port: 443,
    };
    for index in 0..130 {
        let name = format!("original-{index}.test");
        discovery.delegations.lock().unwrap().insert(
            name.clone(),
            (
                Some("127.0.0.1:8448".to_owned()),
                Instant::now() + Duration::from_secs(60),
            ),
        );
        let destination = discovery.destination(&name, "unused").await.unwrap();
        assert_eq!(destination.url, "http://127.0.0.1:8448");
        assert_eq!(destination.host.as_deref(), Some("127.0.0.1:8448"));
    }
    assert!(
        discovery.srv_dns.get().is_none(),
        "explicit ports do not initialise SRV discovery"
    );
    let cache = discovery.destinations.lock().unwrap();
    assert_eq!(cache.len(), 128);
    assert_eq!(
        cache.values().map(|(d, _)| d.pool_size()).sum::<usize>(),
        128
    );
}
