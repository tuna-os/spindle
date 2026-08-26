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
