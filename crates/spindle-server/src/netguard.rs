//! Which addresses an outbound fetch may reach.
//!
//! Two features make this server connect to a host somebody else chose: a
//! URL preview (the URL is the caller's) and a federation fetch (the server
//! name is whatever an `X-Matrix` header or a room's membership says). Both
//! are the textbook request-forgery vector, and both use the same judgement
//! from here: every resolved address is vetted, non-global ranges are
//! refused, and an operator opens named CIDR ranges back up explicitly.
//! A literal IP never touches DNS, so callers vet those themselves with
//! [`permits`] before connecting.

use std::net::{IpAddr, SocketAddr};

/// Parse an allow-list, refusing the whole list on the first bad entry.
///
/// A typo'd range that silently matched nothing would fail closed in a
/// way nobody notices until the internal wiki stops previewing, and fail
/// *open* is not a direction this list can fail in -- so a config error
/// surfaces at startup, not at first use.
pub(crate) fn parse_allow_list(entries: &[String]) -> Result<Vec<Cidr>, String> {
    entries.iter().map(|entry| Cidr::parse(entry)).collect()
}

/// Is `address` reachable under this allow-list: routable, or opened up.
pub(crate) fn permits(allowed: &[Cidr], address: IpAddr) -> bool {
    is_global(address) || allowed.iter().any(|cidr| cidr.contains(address))
}

/// The vetting DNS resolver: resolve, then judge every address.
///
/// Addresses that fail the judgement are dropped; if none survive, the
/// lookup errors and no connection is attempted. reqwest connects to the
/// addresses this returns and nothing else, redirects included — each hop
/// re-enters this resolver.
pub(crate) struct VettingResolver {
    pub(crate) allowed: Vec<Cidr>,
}

impl reqwest::dns::Resolve for VettingResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let allowed = self.allowed.clone();
        Box::pin(async move {
            let host = name.as_str().to_owned();
            let addresses = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
            let vetted: Vec<SocketAddr> = addresses
                .filter(|address| {
                    is_global(address.ip())
                        || allowed.iter().any(|cidr| cidr.contains(address.ip()))
                })
                .collect();
            if vetted.is_empty() {
                return Err(format!(
                    "{host} resolves only to addresses this server does not reach"
                )
                .into());
            }
            Ok(Box::new(vetted.into_iter()) as Box<dyn Iterator<Item = SocketAddr> + Send>)
        })
    }
}

/// Is this an address the open internet routes?
///
/// The refusal list is explicit rather than `!is_global()` from std (still
/// unstable) — and explicitness has a virtue here: each line names an
/// attack surface (loopback: local admin ports; private + ULA: the LAN;
/// link-local v4 169.254/16 *and* v6 `fe80::/10`: cloud metadata services;
/// et cetera).
pub(crate) fn is_global(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.octets()[0] >= 224 // multicast + reserved
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64) // CGNAT 100.64/10
                || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0))
            // 192.0.0.0/24: IETF protocol assignments
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_global(IpAddr::V4(mapped));
            }
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (v6.segments()[0] == 0x2001 && v6.segments()[1] == 0xdb8))
            // documentation 2001:db8::/32
        }
    }
}

/// One allow-listed range, e.g. `127.0.0.0/8`.
#[derive(Clone, Debug)]
pub(crate) struct Cidr {
    base: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub(crate) fn parse(entry: &str) -> Result<Self, String> {
        let (base, prefix) = match entry.split_once('/') {
            Some((base, prefix)) => (base, prefix),
            // A bare address is that address exactly.
            None => (entry, ""),
        };
        let base: IpAddr = base
            .parse()
            .map_err(|_| format!("allow-list entry {entry} is not an address"))?;
        let full = match base {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix: u8 = if prefix.is_empty() {
            full
        } else {
            prefix
                .parse()
                .map_err(|_| format!("allow-list entry {entry} has a bad prefix"))?
        };
        if prefix > full {
            return Err(format!(
                "allow-list entry {entry} has a prefix longer than the address"
            ));
        }
        Ok(Self { base, prefix })
    }

    pub(crate) fn contains(&self, address: IpAddr) -> bool {
        fn bits(address: IpAddr) -> u128 {
            match address {
                IpAddr::V4(v4) => u128::from(u32::from(v4)) << 96,
                IpAddr::V6(v6) => u128::from(v6),
            }
        }
        // v4 and v6 never match each other.
        if matches!(self.base, IpAddr::V4(_)) != matches!(address, IpAddr::V4(_)) {
            return false;
        }
        if self.prefix == 0 {
            return true;
        }
        let mask = u128::MAX << (128 - u32::from(self.prefix));
        (bits(self.base) & mask) == (bits(address) & mask)
    }
}

#[cfg(test)]
mod is_global_tests {
    use super::is_global;

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

#[cfg(test)]
mod cidr_tests {
    use super::Cidr;

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

#[cfg(test)]
mod allow_list_tests {
    use super::{parse_allow_list, permits};

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
