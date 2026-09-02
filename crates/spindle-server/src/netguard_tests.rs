//! Unit tests for the SSRF allow-list guard ([`crate::netguard`]).
//!
//! A separate file rather than an inline `#[cfg(test)] mod tests` at the
//! bottom of `netguard.rs`, so these tests are visible as their own file in
//! review and diff tooling for the security-sensitive module they cover.

mod is_global_tests {
    use crate::netguard::is_global;

    #[test]
    fn private_and_special_v4_ranges_are_not_global() {
        assert!(!is_global("127.0.0.1".parse().unwrap())); // loopback
        assert!(!is_global("192.168.1.1".parse().unwrap())); // private
        assert!(!is_global("10.0.0.1".parse().unwrap())); // private
        assert!(!is_global("169.254.1.1".parse().unwrap())); // link-local
        assert!(!is_global("255.255.255.255".parse().unwrap())); // broadcast
        assert!(!is_global("192.0.2.1".parse().unwrap())); // documentation
        assert!(!is_global("0.0.0.0".parse().unwrap())); // unspecified
        assert!(!is_global("224.0.0.1".parse().unwrap())); // multicast
        assert!(!is_global("240.0.0.1".parse().unwrap())); // reserved
        assert!(!is_global("192.0.0.1".parse().unwrap())); // IETF protocol assignment
    }

    #[test]
    fn cgnat_range_is_bounded_to_a_slash_10() {
        assert!(!is_global("100.64.0.1".parse().unwrap())); // inside 100.64.0.0/10
        assert!(!is_global("100.127.255.255".parse().unwrap())); // top of the range
        assert!(is_global("100.63.255.255".parse().unwrap())); // just below the range
        assert!(is_global("100.128.0.0".parse().unwrap())); // just above the range
    }

    #[test]
    fn routable_v4_addresses_are_global() {
        assert!(is_global("8.8.8.8".parse().unwrap()));
        assert!(is_global("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn private_and_special_v6_ranges_are_not_global() {
        assert!(!is_global("::1".parse().unwrap())); // loopback
        assert!(!is_global("::".parse().unwrap())); // unspecified
        assert!(!is_global("ff00::1".parse().unwrap())); // multicast
        assert!(!is_global("fc00::1".parse().unwrap())); // ULA
        assert!(!is_global("fe80::1".parse().unwrap())); // link-local
        assert!(!is_global("2001:db8::1".parse().unwrap())); // documentation
    }

    #[test]
    fn routable_v6_addresses_are_global() {
        assert!(is_global("2001:4860:4860::8888".parse().unwrap()));
    }

    #[test]
    fn v4_mapped_v6_defers_to_the_v4_judgement() {
        // A private v4 address smuggled in through the v6 mapped form must
        // still be refused, not waved through because it parsed as v6.
        assert!(!is_global("::ffff:192.168.1.1".parse().unwrap()));
        assert!(is_global("::ffff:8.8.8.8".parse().unwrap()));
    }
}

mod cidr_tests {
    use crate::netguard::Cidr;

    #[test]
    fn a_bare_address_matches_only_itself() {
        let cidr = Cidr::parse("10.0.0.5").unwrap();
        assert!(cidr.contains("10.0.0.5".parse().unwrap()));
        assert!(!cidr.contains("10.0.0.6".parse().unwrap()));
    }

    #[test]
    fn a_prefix_matches_the_whole_range_and_nothing_else() {
        let cidr = Cidr::parse("127.0.0.0/8").unwrap();
        assert!(cidr.contains("127.5.5.5".parse().unwrap()));
        assert!(!cidr.contains("128.0.0.1".parse().unwrap()));
    }

    #[test]
    fn v4_and_v6_ranges_never_match_the_other_family() {
        let v4_default_route = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(v4_default_route.contains("203.0.113.1".parse().unwrap()));
        assert!(!v4_default_route.contains("::1".parse().unwrap()));
    }

    #[test]
    fn a_prefix_longer_than_the_address_is_refused() {
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("::1/129").is_err());
    }

    #[test]
    fn a_non_numeric_prefix_is_refused() {
        assert!(Cidr::parse("10.0.0.0/abc").is_err());
    }

    #[test]
    fn an_unparsable_address_is_refused() {
        assert!(Cidr::parse("not-an-address/24").is_err());
    }
}

mod allow_list_tests {
    use crate::netguard::{parse_allow_list, permits};

    #[test]
    fn every_entry_parses_or_the_whole_list_is_refused() {
        let good = vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()];
        assert_eq!(parse_allow_list(&good).unwrap().len(), 2);

        // A config error must fail closed, not silently drop the bad entry.
        let one_bad = vec!["10.0.0.0/8".to_string(), "not-an-address".to_string()];
        assert!(parse_allow_list(&one_bad).is_err());
    }

    #[test]
    fn permits_allows_global_addresses_with_an_empty_list() {
        assert!(permits(&[], "8.8.8.8".parse().unwrap()));
        assert!(!permits(&[], "192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn permits_allows_a_private_address_the_operator_opened_up() {
        let allowed = parse_allow_list(&["192.168.0.0/16".to_string()]).unwrap();
        assert!(permits(&allowed, "192.168.5.5".parse().unwrap()));
        assert!(!permits(&allowed, "10.0.0.1".parse().unwrap()));
    }
}
