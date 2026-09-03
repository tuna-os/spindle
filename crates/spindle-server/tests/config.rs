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

/// #36 asks for both delayed-event caps to be "rejected loudly". A zero is
/// the case worth naming: it reads like "no limit" and means the opposite,
/// so a server that accepted it would start with the dead-man's switch
/// silently refusing every schedule -- the failure MSC4140 exists to prevent,
/// arrived at through the config file.
/// The same rule for the per-account caps (#268): a zero would refuse every
/// filter upload, every account-data write or every key upload, which is
/// not a limit but an outage, and it must not start the server.
#[test]
fn a_zero_account_cap_is_refused_at_startup() {
    for (field, line) in [
        ("limits.filters_per_user", "filters_per_user = 0"),
        ("limits.account_data_per_user", "account_data_per_user = 0"),
        (
            "limits.one_time_keys_per_device",
            "one_time_keys_per_device = 0",
        ),
    ] {
        let error = parse(&format!(
            "[server]\nname = \"example.org\"\n[limits]\n{line}\n"
        ))
        .expect_err("a zero cap must not start the server");
        let rendered = error.to_string();
        assert!(rendered.contains(field), "{rendered}");
        assert!(rendered.contains("refuses every write"), "{rendered}");
    }
    // And the defaults are what the module says they are.
    let config = parse("[server]\nname = \"example.org\"\n").expect("defaults parse");
    assert_eq!(
        config.limits.filters_per_user,
        spindle_server::config::DEFAULT_FILTERS_PER_USER
    );
    assert_eq!(
        config.limits.account_data_per_user,
        spindle_server::config::DEFAULT_ACCOUNT_DATA_PER_USER
    );
    assert_eq!(
        config.limits.one_time_keys_per_device,
        spindle_server::config::DEFAULT_ONE_TIME_KEYS_PER_DEVICE
    );
}

#[test]
fn a_zero_delayed_event_cap_is_refused_at_startup() {
    for (field, line) in [
        ("delayed_events.max_delay_ms", "max_delay_ms = 0"),
        ("delayed_events.max_per_room", "max_per_room = 0"),
    ] {
        let error = parse(&format!(
            "[server]\nname = \"example.org\"\n[delayed_events]\n{line}\n"
        ))
        .expect_err("a zero cap must not start the server");
        let rendered = error.to_string();
        assert!(
            rendered.contains(field),
            "the refusal names the field the operator has to fix: {rendered}"
        );
        assert!(
            rendered.contains("refuses every delayed event"),
            "and says what the zero would actually do: {rendered}"
        );
    }
}

/// The defaults still apply when the section is absent, so an existing
/// config keeps working and does not have to learn about this.
/// A ring budget of zero would refuse every ring (#39): refused at startup
/// like the other zero caps, and ten a minute without the field.
#[test]
fn a_zero_ring_budget_is_refused_and_the_default_is_ten() {
    let error = parse("[server]\nname = \"example.org\"\n[ratelimit]\nrings_per_minute = 0\n")
        .expect_err("a zero budget must not start the server");
    let rendered = error.to_string();
    assert!(
        rendered.contains("ratelimit.rings_per_minute"),
        "{rendered}"
    );
    assert!(rendered.contains("refuses every ring"), "{rendered}");
    let config = parse("[server]\nname = \"example.org\"\n").expect("no section is fine");
    assert_eq!(config.ratelimit.rings_per_minute, 10);
}

#[test]
fn the_delayed_event_caps_default_without_the_section() {
    let config = parse("[server]\nname = \"example.org\"\n").expect("no section is fine");
    assert_eq!(config.delayed_events.max_delay_ms, 24 * 60 * 60 * 1000);
    assert_eq!(config.delayed_events.max_per_room, 100);
}

/// A transport this server cannot render is refused at startup (#37).
///
/// The reason is the missing feedback path: a focus is advertised to
/// clients and never used here, so a wrong entry fails in somebody's
/// browser, mid-call, as "no transport", with nothing in this server's log
/// to connect it to the config file. Everything checkable is therefore
/// checked at load, where the operator is still watching.
#[test]
fn an_unusable_rtc_transport_is_refused_at_startup() {
    for (foci, expected) in [
        (
            r#"{ type = "janus", livekit_service_url = "https://livekit.example.org/jwt" }"#,
            "only \"livekit\"",
        ),
        (r#"{ type = "livekit" }"#, "needs livekit_service_url"),
        (
            r#"{ type = "livekit", livekit_service_url = "livekit.example.org" }"#,
            "is not an http(s) URL",
        ),
    ] {
        let error = parse(&format!(
            "[server]\nname = \"example.org\"\n[rtc]\nfoci = [{foci}]\n"
        ))
        .expect_err("an unusable transport must not start the server");
        let rendered = error.to_string();
        assert!(
            rendered.contains("rtc.foci"),
            "the refusal names the field to fix: {rendered}"
        );
        assert!(
            rendered.contains(expected),
            "and says what is wrong with it: {rendered}"
        );
    }
}

/// The section is optional and its absence is a working configuration: no
/// backend is what most deployments have, and it must not be a parse error.
#[test]
fn no_rtc_section_means_no_transports() {
    let config = parse("[server]\nname = \"example.org\"\n").expect("no section is fine");
    assert!(config.rtc.foci.is_empty());
}
