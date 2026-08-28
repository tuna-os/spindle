//! Configuration is validated at load, not at first use.
//!
//! A homeserver that starts and then fails on its first request has already
//! told its operator it was healthy, and taken traffic on that promise.

use spindle_server::{Config, ConfigError};

fn parse(text: &str) -> Result<Config, ConfigError> {
    Config::parse(text)
}

#[test]
fn the_minimal_configuration_is_a_server_name() {
    let config = parse(
        r#"
        [server]
        name = "example.org"
        "#,
    )
    .expect("a server name is enough");
    assert_eq!(config.server.name, "example.org");
    assert_eq!(config.server.bind, "127.0.0.1:8008");
    assert_eq!(config.storage.path.to_str(), Some("./data"));
    // Loopback by default: a server that binds every interface the moment it
    // is installed has made an exposure decision on the operator's behalf.
    assert!(config.server.bind.starts_with("127.0.0.1"));
}

#[test]
fn an_unknown_field_is_refused_rather_than_ignored() {
    // A silently ignored key is how an operator ends up believing they
    // configured something they did not.
    let error = parse(
        r#"
        [server]
        name = "example.org"
        listen = "0.0.0.0:8008"
        "#,
    )
    .expect_err("a misspelled key must not be ignored");
    assert!(matches!(error, ConfigError::Syntax { .. }), "{error}");
    assert!(format!("{error}").contains("listen"), "{error}");
}

#[test]
fn a_server_name_that_would_poison_every_identifier_is_refused() {
    // The server name ends up inside every user and room ID this server mints,
    // and those federate. Catching it here is cheaper than in a peer's
    // signature check.
    for name in ["", "example.org/matrix", "example org"] {
        let error = parse(&format!(
            r#"
            [server]
            name = "{name}"
            "#
        ))
        .expect_err("{name:?} must be refused");
        assert!(
            matches!(
                error,
                ConfigError::Invalid {
                    field: "server.name",
                    ..
                }
            ),
            "{error}"
        );
    }
}

/// The mistake worth naming specifically, because the fix is not obvious.
#[test]
fn a_url_as_a_server_name_says_what_to_do_instead() {
    let error = parse(
        r#"
        [server]
        name = "https://example.org"
        "#,
    )
    .expect_err("a URL is not a server name");
    let text = format!("{error}");
    assert!(
        text.contains("public_base_url"),
        "the error should name the field that does what the operator meant: {text}"
    );
}

#[test]
fn a_bind_address_that_cannot_be_bound_is_refused_at_load() {
    let error = parse(
        r#"
        [server]
        name = "example.org"
        bind = "not-an-address"
        "#,
    )
    .expect_err("an unparseable bind must not reach the listener");
    assert!(
        matches!(
            error,
            ConfigError::Invalid {
                field: "server.bind",
                ..
            }
        ),
        "{error}"
    );
}

#[test]
fn delegation_is_what_public_base_url_is_for() {
    let config = parse(
        r#"
        [server]
        name = "example.org"
        public_base_url = "https://matrix.example.org"
        "#,
    )
    .expect("delegation is ordinary");
    assert_eq!(config.client_base_url(), "https://matrix.example.org");

    // Without it, the server name is the base URL, which is the non-delegated
    // deployment rather than an error.
    let plain = parse(
        r#"
        [server]
        name = "example.org"
        "#,
    )
    .unwrap();
    assert_eq!(plain.client_base_url(), "https://example.org");
}

#[test]
fn a_missing_file_names_the_path_it_could_not_read() {
    let error = Config::load("/nonexistent/spindle.toml").expect_err("no such file");
    let text = format!("{error}");
    assert!(text.contains("/nonexistent/spindle.toml"), "{text}");
}

/// Rate limiting is on unless a config says otherwise, and saying otherwise is
/// a single explicit key. Defaulting it off would make a server exposed to the
/// internet a brute-force target through inattention rather than intent.
#[test]
fn rate_limiting_defaults_on_and_is_switched_off_explicitly() {
    let default = Config::parse("[server]\nname = \"example.org\"\n").unwrap();
    assert!(default.ratelimit.enabled);

    let off = Config::parse("[server]\nname = \"example.org\"\n\n[ratelimit]\nenabled = false\n")
        .unwrap();
    assert!(!off.ratelimit.enabled);

    // The section rejects anything it does not know, so a misspelled key is an
    // error rather than a limit that silently stays on.
    let typo = Config::parse("[server]\nname = \"example.org\"\n\n[ratelimit]\nenable = false\n");
    assert!(typo.is_err(), "a misspelled key was accepted: {typo:?}");
}

/// The federation listener is opt-in and all-or-nothing: a bind with no TLS
/// material is a misconfiguration `main()` refuses at startup, so the parse
/// itself only carries the fields faithfully.
#[test]
fn federation_tls_fields_parse_and_default_off() {
    let default = Config::parse("[server]\nname = \"example.org\"\n").unwrap();
    assert!(default.federation.bind.is_none());
    assert!(default.federation.tls_cert.is_none());

    let configured = Config::parse(
        "[server]\nname = \"example.org\"\n\n[federation]\n\
         bind = \"0.0.0.0:8448\"\n\
         tls_cert = \"/certs/hs1.crt\"\ntls_key = \"/certs/hs1.key\"\n",
    )
    .unwrap();
    assert_eq!(configured.federation.bind.as_deref(), Some("0.0.0.0:8448"));
    assert_eq!(
        configured.federation.tls_cert.as_deref(),
        Some(std::path::Path::new("/certs/hs1.crt"))
    );
    assert_eq!(
        configured.federation.tls_key.as_deref(),
        Some(std::path::Path::new("/certs/hs1.key"))
    );
}

#[test]
fn the_shipped_example_parses() {
    // The example config is the only place an operator learns a setting
    // exists, and nothing held it to the code. This is the half that
    // `deny_unknown_fields` can enforce: an example naming a field the code
    // has since removed or renamed fails here, at `cargo test`, rather than
    // at someone's first boot.
    //
    // The other half -- a field added to the code and never written down --
    // is `scripts/config-drift.py`, because Rust cannot enumerate its own
    // struct fields at runtime without machinery this does not need.
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../spindle.example.toml"
    ))
    .expect("spindle.example.toml sits at the repository root");

    let config = parse(&text).expect("the shipped example must parse");
    assert_eq!(
        config.server.name, "example.org",
        "the example should keep an obviously-placeholder server name, so a \
         copied config cannot accidentally federate as something real"
    );
}
