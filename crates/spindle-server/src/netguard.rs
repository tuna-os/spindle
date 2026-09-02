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
///
/// An IPv4 address written inside an IPv6 one is judged as the address it
/// names, so a listed range covers it however it is spelled (#313).
pub(crate) fn permits(allowed: &[Cidr], address: IpAddr) -> bool {
    let address = canonical(address);
    is_global(address) || allowed.iter().any(|cidr| cidr.contains(address))
}

/// `address`, with an IPv4 address carried inside an IPv6 one unwrapped.
fn canonical(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => embedded_ipv4(v6).map_or(address, IpAddr::V4),
        IpAddr::V4(_) => address,
    }
}

/// The redirect policy every outbound client installs beside its
/// [`VettingResolver`].
///
/// A hop to a hostname goes back through the resolver, which vets what it
/// resolves to; a hop to a *literal IP* never touches DNS, and without
/// this policy any public host could `302` to `http://169.254.169.254/`
/// and walk straight past the resolver. Previews had this and federation
/// did not (#312): the drift was the bug, so there is one policy here and
/// two callers of it. `reach` names the caller in the refusal
/// ("previewable", "federatable"), which is the only thing they differ in.
pub(crate) fn redirect_policy(
    allowed: Vec<Cidr>,
    reach: &'static str,
) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() > 5 {
            return attempt.error("too many redirects");
        }
        if let Some(host) = attempt.url().host_str()
            && let Ok(literal) = host.trim_matches(['[', ']']).parse::<IpAddr>()
            && !permits(&allowed, literal)
        {
            return attempt.error(format!("redirect into a non-{reach} address"));
        }
        attempt.follow()
    })
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
                .filter(|address| permits(&allowed, address.ip()))
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
                || v4.octets()[0] == 0 // 0.0.0.0/8 "this network", not only 0.0.0.0
                || v4.octets()[0] >= 224 // multicast + reserved
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64) // CGNAT 100.64/10
                || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0) // 192.0.0.0/24: IETF protocol assignments
                || (v4.octets()[0] == 198 && (v4.octets()[1] & 0xfe) == 18) // benchmarking 198.18/15
                || (v4.octets()[0] == 192 && v4.octets()[1] == 88 && v4.octets()[2] == 99))
            // 192.88.99.0/24: 6to4 relay anycast
        }
        IpAddr::V6(v6) => {
            // An IPv4 address written inside an IPv6 one is judged as the
            // IPv4 address it names, whichever encoding carries it (#313):
            // a NAT64 gateway turns `64:ff9b::a9fe:a9fe` into a packet to
            // 169.254.169.254, so the v4 judgement is the true one -- and
            // recursing rather than refusing keeps an operator's
            // `allow_internal` entry meaning the same thing however the
            // address is spelled.
            if let Some(embedded) = embedded_ipv4(v6) {
                return is_global(IpAddr::V4(embedded));
            }
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfec0 // site-local fec0::/10 (deprecated, still routed by some)
                || (v6.segments()[0] == 0x2001 && v6.segments()[1] == 0xdb8))
            // documentation 2001:db8::/32
        }
    }
}

/// The IPv4 address an IPv6 one carries, for the encodings that carry one:
/// v4-mapped `::ffff:a.b.c.d`, IPv4-compatible `::a.b.c.d` (RFC 4291,
/// deprecated), NAT64 `64:ff9b::a.b.c.d` and `64:ff9b:1::/48` (RFC 6052,
/// RFC 8215; the address sits in the low 32 bits), and 6to4
/// `2002:a.b.c.d::/48` (RFC 3056; the address sits in the second and third
/// segments). `::` and `::1` are not addresses in disguise and stay with
/// the v6 rules.
fn embedded_ipv4(v6: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    if let Some(mapped) = v6.to_ipv4_mapped() {
        return Some(mapped);
    }
    let s = v6.segments();
    let low = |a: u16, b: u16| std::net::Ipv4Addr::from(u32::from(a) << 16 | u32::from(b));
    let compatible = s[..6].iter().all(|segment| *segment == 0) && !(s[6] == 0 && s[7] <= 1);
    let nat64 = s[0] == 0x64 && s[1] == 0xff9b && (s[2] == 0 || s[2] == 1);
    if compatible || nat64 {
        return Some(low(s[6], s[7]));
    }
    if s[0] == 0x2002 {
        return Some(low(s[1], s[2]));
    }
    None
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
mod tests {
    use super::*;

    fn judged(spelling: &str) -> bool {
        is_global(spelling.parse().expect("a valid address"))
    }

    #[test]
    fn every_encoding_of_an_internal_ipv4_address_is_judged_as_that_address() {
        // The cloud metadata service, in every spelling an IPv6 stack
        // accepts (#313). A NAT64 gateway turns the first into a packet to
        // 169.254.169.254; the others are the same address in older forms.
        for spelling in [
            "64:ff9b::a9fe:a9fe",
            "64:ff9b::169.254.169.254",
            "64:ff9b:1::a9fe:a9fe",
            "::169.254.169.254",
            "::a9fe:a9fe",
            "2002:a9fe:a9fe::",
            "::ffff:169.254.169.254",
        ] {
            assert!(!judged(spelling), "{spelling} must be refused");
        }
        // And a public address in the same encodings stays reachable, so
        // an allow-list entry means the same thing however it is spelled.
        for spelling in [
            "64:ff9b::808:808",
            "::8.8.8.8",
            "2002:808:808::",
            "::ffff:8.8.8.8",
        ] {
            assert!(judged(spelling), "{spelling} carries a public address");
        }
    }

    #[test]
    fn the_ranges_the_first_pass_missed_are_refused() {
        for spelling in [
            "0.1.2.3",        // 0.0.0.0/8, not only 0.0.0.0
            "198.18.0.1",     // benchmarking 198.18/15
            "198.19.255.255", // its upper half
            "192.88.99.1",    // 6to4 relay anycast
            "fec0::1",        // site-local
            "feff::1",        // top of fec0::/10
        ] {
            assert!(!judged(spelling), "{spelling} must be refused");
        }
        for spelling in ["198.17.255.255", "198.20.0.0", "192.88.100.1", "ff00::1"] {
            assert_eq!(
                judged(spelling),
                spelling != "ff00::1",
                "{spelling} sits just outside a refused range, or inside multicast"
            );
        }
    }

    #[test]
    fn the_unspecified_and_loopback_v6_addresses_are_not_disguised_v4_ones() {
        assert!(!judged("::"));
        assert!(!judged("::1"));
        assert_eq!(embedded_ipv4("::1".parse().unwrap()), None);
        assert_eq!(embedded_ipv4("::".parse().unwrap()), None);
        assert_eq!(
            embedded_ipv4("::2".parse().unwrap()),
            Some(std::net::Ipv4Addr::new(0, 0, 0, 2))
        );
    }

    #[test]
    fn an_allow_list_entry_covers_the_address_in_every_spelling() {
        let allowed = parse_allow_list(&["169.254.169.254/32".to_owned()]).unwrap();
        for spelling in [
            "169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "::ffff:169.254.169.254",
        ] {
            assert!(
                permits(&allowed, spelling.parse().unwrap()),
                "{spelling} is the listed address"
            );
        }
        assert!(!permits(&allowed, "64:ff9b::a9fe:a9ff".parse().unwrap()));
    }
}
