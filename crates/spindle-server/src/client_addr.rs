//! Who a request is from, for the limits that are keyed by source (#831).
//!
//! Behind a reverse proxy the TCP peer is always the proxy, so keying on it
//! puts every client into one bucket: one caller's bad logins then lock out
//! everyone. Reading `X-Forwarded-For` fixes that, but any client can send
//! that header. So it is read only when the peer is a proxy the operator
//! listed in `[server] trusted_proxies`, and then from the right: each
//! trusted proxy appends the address it saw, so the first hop from the right
//! that is not trusted is the last address a trusted party vouches for.
//! Anything to its left was written by the client.

use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

use serde::Deserialize;

/// An address or a network, from `trusted_proxies`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(try_from = "String")]
pub struct TrustedProxy {
    network: IpAddr,
    prefix: u8,
}

impl TrustedProxy {
    /// Whether `address` is in this network.
    #[must_use]
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.network, canonical(address)) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                masked(u128::from(u32::from(network)), self.prefix, 32)
                    == masked(u128::from(u32::from(address)), self.prefix, 32)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                masked(u128::from(network), self.prefix, 128)
                    == masked(u128::from(address), self.prefix, 128)
            }
            _ => false,
        }
    }
}

/// `value` with all but the first `prefix` of `bits` bits cleared.
fn masked(value: u128, prefix: u8, bits: u8) -> u128 {
    let host_bits = u32::from(bits.saturating_sub(prefix));
    if host_bits >= 128 {
        0
    } else {
        (value >> host_bits) << host_bits
    }
}

/// An IPv4 address that arrived in its IPv6-mapped form, as plain IPv4.
///
/// A dual-stack listener reports every IPv4 peer as `::ffff:a.b.c.d`; an
/// operator who wrote `127.0.0.1` means that peer too.
fn canonical(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    }
}

impl FromStr for TrustedProxy {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };
        let network: IpAddr = address
            .trim()
            .parse()
            .map_err(|_| format!("{text:?} is not an IP address or CIDR network"))?;
        let longest = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) => prefix
                .trim()
                .parse::<u8>()
                .ok()
                .filter(|prefix| *prefix <= longest)
                .ok_or_else(|| format!("{text:?} has a prefix length outside 0..={longest}"))?,
            None => longest,
        };
        Ok(Self { network, prefix })
    }
}

impl TryFrom<String> for TrustedProxy {
    type Error = String;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        text.parse()
    }
}

/// The address to key a source limit on, as text.
///
/// `forwarded` is every `X-Forwarded-For` header value on the request. It is
/// ignored unless `peer` is trusted.
#[must_use]
pub fn source_key(peer: IpAddr, forwarded: &[&str], trusted: &[TrustedProxy]) -> String {
    let is_trusted = |address: IpAddr| trusted.iter().any(|proxy| proxy.contains(address));
    let mut client = canonical(peer);
    if is_trusted(client) {
        // Walk from the right while the hop is one of ours. An entry that
        // is not an address ends the walk: nothing left of garbage can be
        // believed, so the last good hop stands.
        for hop in forwarded.iter().flat_map(|value| value.split(',')).rev() {
            let Ok(hop) = hop.trim().parse::<IpAddr>() else {
                break;
            };
            client = canonical(hop);
            if !is_trusted(client) {
                break;
            }
        }
    }
    match client {
        IpAddr::V4(v4) => v4.to_string(),
        // One subscriber is normally given a whole /64, so a per-address
        // key would let them take a fresh bucket for each of 2^64 addresses.
        IpAddr::V6(v6) => {
            let high = u128::from(v6) >> 64 << 64;
            format!("{}/64", Ipv6Addr::from(high))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nets(list: &[&str]) -> Vec<TrustedProxy> {
        list.iter().map(|net| net.parse().unwrap()).collect()
    }

    fn key(peer: &str, forwarded: &[&str], trusted: &[&str]) -> String {
        source_key(peer.parse().unwrap(), forwarded, &nets(trusted))
    }

    #[test]
    fn an_untrusted_peer_cannot_choose_its_address() {
        assert_eq!(key("203.0.113.9", &["198.51.100.1"], &[]), "203.0.113.9");
        assert_eq!(
            key("203.0.113.9", &["198.51.100.1"], &["127.0.0.1"]),
            "203.0.113.9"
        );
    }

    #[test]
    fn a_trusted_peer_vouches_for_the_rightmost_untrusted_hop() {
        let trusted = ["127.0.0.1/32", "10.0.0.0/8"];
        assert_eq!(
            key("127.0.0.1", &["198.51.100.1"], &trusted),
            "198.51.100.1"
        );
        // The client wrote the left entry; only the right two were appended
        // by proxies, so the middle one is the client's real address.
        assert_eq!(
            key(
                "127.0.0.1",
                &["6.6.6.6, 198.51.100.1", "10.1.2.3"],
                &trusted
            ),
            "198.51.100.1"
        );
        assert_eq!(key("127.0.0.1", &[], &trusted), "127.0.0.1");
        assert_eq!(key("127.0.0.1", &["garbage"], &trusted), "127.0.0.1");
    }

    #[test]
    fn v4_mapped_peers_match_v4_networks() {
        assert_eq!(
            key("::ffff:127.0.0.1", &["198.51.100.1"], &["127.0.0.1"]),
            "198.51.100.1"
        );
    }

    #[test]
    fn v6_sources_share_a_bucket_per_64() {
        let a = key("2001:db8:1:2::1", &[], &[]);
        let b = key("2001:db8:1:2:ffff::9", &[], &[]);
        let c = key("2001:db8:1:3::1", &[], &[]);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a, "2001:db8:1:2::/64");
    }

    #[test]
    fn bad_networks_are_refused() {
        assert!("10.0.0.0/33".parse::<TrustedProxy>().is_err());
        assert!("nonsense".parse::<TrustedProxy>().is_err());
        assert!("::1/128".parse::<TrustedProxy>().is_ok());
        assert!("0.0.0.0/0".parse::<TrustedProxy>().is_ok());
    }
}
