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

    fn address(spelling: &str) -> IpAddr {
        spelling.parse().expect("a valid address")
    }

    fn allow_list(entries: &[&str]) -> Vec<Cidr> {
        parse_allow_list(
            &entries
                .iter()
                .map(|entry| (*entry).to_owned())
                .collect::<Vec<_>>(),
        )
        .expect("a valid allow-list")
    }

    /// A refused range: its name, first and last address, and the address
    /// just below and just above it -- `None` where there is no address on
    /// that side, or the neighbour is itself refused.
    type Edges = (
        &'static str,
        &'static str,
        &'static str,
        Option<&'static str>,
        Option<&'static str>,
    );

    /// Every IPv4 range the guard refuses.
    const REFUSED_IPV4: &[Edges] = &[
        (
            "0.0.0.0/8 this network",
            "0.0.0.0",
            "0.255.255.255",
            None,
            Some("1.0.0.0"),
        ),
        (
            "10/8 private",
            "10.0.0.0",
            "10.255.255.255",
            Some("9.255.255.255"),
            Some("11.0.0.0"),
        ),
        (
            "100.64/10 CGNAT",
            "100.64.0.0",
            "100.127.255.255",
            Some("100.63.255.255"),
            Some("100.128.0.0"),
        ),
        (
            "127/8 loopback",
            "127.0.0.0",
            "127.255.255.255",
            Some("126.255.255.255"),
            Some("128.0.0.0"),
        ),
        (
            "169.254/16 link-local",
            "169.254.0.0",
            "169.254.255.255",
            Some("169.253.255.255"),
            Some("169.255.0.0"),
        ),
        (
            "172.16/12 private",
            "172.16.0.0",
            "172.31.255.255",
            Some("172.15.255.255"),
            Some("172.32.0.0"),
        ),
        (
            "192.0.0/24 IETF protocol assignments",
            "192.0.0.0",
            "192.0.0.255",
            Some("191.255.255.255"),
            Some("192.0.1.0"),
        ),
        (
            "192.0.2/24 documentation",
            "192.0.2.0",
            "192.0.2.255",
            Some("192.0.1.255"),
            Some("192.0.3.0"),
        ),
        (
            "192.88.99/24 6to4 relay anycast",
            "192.88.99.0",
            "192.88.99.255",
            Some("192.88.98.255"),
            Some("192.88.100.0"),
        ),
        (
            "192.168/16 private",
            "192.168.0.0",
            "192.168.255.255",
            Some("192.167.255.255"),
            Some("192.169.0.0"),
        ),
        (
            "198.18/15 benchmarking",
            "198.18.0.0",
            "198.19.255.255",
            Some("198.17.255.255"),
            Some("198.20.0.0"),
        ),
        (
            "198.51.100/24 documentation",
            "198.51.100.0",
            "198.51.100.255",
            Some("198.51.99.255"),
            Some("198.51.101.0"),
        ),
        (
            "203.0.113/24 documentation",
            "203.0.113.0",
            "203.0.113.255",
            Some("203.0.112.255"),
            Some("203.0.114.0"),
        ),
        // Multicast runs straight into reserved, and reserved ends in
        // the broadcast address: one refused block from 224.0.0.0 up.
        (
            "224/4 multicast",
            "224.0.0.0",
            "239.255.255.255",
            Some("223.255.255.255"),
            None,
        ),
        (
            "240/4 reserved, up to broadcast",
            "240.0.0.0",
            "255.255.255.255",
            None,
            None,
        ),
    ];

    /// Every IPv6 range the guard refuses on its own terms; the ranges
    /// that carry an IPv4 address are judged as it and tested apart.
    const REFUSED_IPV6: &[Edges] = &[
        // `::` and `::1` are the only two addresses under `::/96` that
        // are not read as an IPv4-compatible one; `::2` is 0.0.0.2.
        ("unspecified", "::", "::", None, None),
        ("loopback", "::1", "::1", None, None),
        (
            "fc00::/7 unique local",
            "fc00::",
            "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some("fbff::ffff"),
            Some("fe00::"),
        ),
        (
            "fe80::/10 link-local",
            "fe80::",
            "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some("fe7f::ffff"),
            None,
        ),
        (
            "fec0::/10 site-local",
            "fec0::",
            "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            None,
            None,
        ),
        (
            "ff00::/8 multicast",
            "ff00::",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            None,
            None,
        ),
        (
            "2001:db8::/32 documentation",
            "2001:db8::",
            "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
            Some("2001:db7:ffff::ffff"),
            Some("2001:db9::"),
        ),
    ];

    /// A range whose edge is off by one is a range with a hole in it, and
    /// the hole is where the request goes: so every refused range is
    /// checked at its first and last address, and at the address on either
    /// side of it.
    fn assert_refused_edge_to_edge(ranges: &[Edges]) {
        for (range, first, last, below, above) in ranges {
            assert!(!judged(first), "{range}: {first} is its first address");
            assert!(!judged(last), "{range}: {last} is its last address");
            if let Some(below) = below {
                assert!(judged(below), "{range}: {below} sits just below it");
            }
            if let Some(above) = above {
                assert!(judged(above), "{range}: {above} sits just above it");
            }
        }
    }

    #[test]
    fn every_refused_ipv4_range_is_refused_edge_to_edge() {
        assert_refused_edge_to_edge(REFUSED_IPV4);
    }

    #[test]
    fn ordinary_public_ipv4_addresses_are_global() {
        for spelling in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "100.63.0.1",
            "100.128.0.1",
        ] {
            assert!(
                judged(spelling),
                "{spelling} is routed by the open internet"
            );
        }
    }

    #[test]
    fn every_refused_ipv6_range_is_refused_edge_to_edge() {
        assert_refused_edge_to_edge(REFUSED_IPV6);
    }

    #[test]
    fn ordinary_public_ipv6_addresses_are_global() {
        for spelling in [
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
            "2a00:1450:4001:80b::200e",
        ] {
            assert!(
                judged(spelling),
                "{spelling} is routed by the open internet"
            );
        }
    }

    /// An IPv6 address that carries an IPv4 one is judged as that address,
    /// in each encoding the stack accepts, for a refused and a public one.
    #[test]
    fn an_ipv6_address_carrying_an_ipv4_one_is_judged_as_that_address() {
        let carried: &[(&str, &str, &str)] = &[
            // (encoding, refused inside, public inside)
            (
                "v4-mapped ::ffff:a.b.c.d",
                "::ffff:127.0.0.1",
                "::ffff:8.8.8.8",
            ),
            ("v4-mapped, hex spelled", "::ffff:7f00:1", "::ffff:808:808"),
            ("v4-compatible ::a.b.c.d", "::10.0.0.1", "::8.8.8.8"),
            (
                "NAT64 64:ff9b::/96",
                "64:ff9b::192.168.0.1",
                "64:ff9b::8.8.8.8",
            ),
            (
                "NAT64 local-use 64:ff9b:1::/48",
                "64:ff9b:1::a9fe:a9fe",
                "64:ff9b:1::808:808",
            ),
            ("6to4 2002:a.b.c.d::/48", "2002:a00:1::", "2002:808:808::"),
        ];
        for (encoding, refused, public) in carried {
            assert!(
                !judged(refused),
                "{encoding}: {refused} carries a refused address"
            );
            assert!(
                judged(public),
                "{encoding}: {public} carries a public address"
            );
            let refused_inside = embedded_ipv4(refused.parse().unwrap()).expect(encoding);
            assert!(
                !is_global(IpAddr::V4(refused_inside)),
                "{encoding}: {refused_inside}"
            );
        }
        // Outside those encodings nothing is unwrapped: `64:ff9b:2::` is
        // not a NAT64 prefix this guard knows, and is judged as plain v6.
        assert_eq!(embedded_ipv4("64:ff9b:2::a9fe:a9fe".parse().unwrap()), None);
        assert_eq!(embedded_ipv4("2001:db8::a9fe:a9fe".parse().unwrap()), None);
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

    /// What `Cidr::parse` accepts and refuses. An entry it refuses refuses
    /// the whole list, so each refusal here is a config error caught at
    /// startup rather than a range that silently matches nothing.
    #[test]
    fn an_allow_list_entry_parses_or_is_refused() {
        let accepted: &[(&str, &str, u8)] = &[
            // (entry, base it parses to, prefix)
            ("10.0.0.0/8", "10.0.0.0", 8),
            ("10.0.0.5", "10.0.0.5", 32), // a bare address is that host
            ("10.0.0.5/32", "10.0.0.5", 32),
            ("0.0.0.0/0", "0.0.0.0", 0),
            ("10.1.2.3/8", "10.1.2.3", 8), // host bits set: masked at match time
            ("fd00::/8", "fd00::", 8),
            ("::1", "::1", 128), // a bare v6 address is that host too
            ("::1/128", "::1", 128),
            ("::/0", "::", 0),
            ("::ffff:10.0.0.0/104", "::ffff:10.0.0.0", 104),
            ("64:ff9b::/96", "64:ff9b::", 96),
        ];
        for (entry, base, prefix) in accepted {
            let cidr = Cidr::parse(entry).unwrap_or_else(|why| panic!("{entry}: {why}"));
            assert_eq!(cidr.base, address(base), "{entry}");
            assert_eq!(cidr.prefix, *prefix, "{entry}");
        }
        let refused: &[(&str, &str)] = &[
            // (entry, what is wrong with it)
            ("", "empty"),
            (" ", "blank"),
            ("/8", "a prefix with no address"),
            ("10.0.0.0/33", "a prefix longer than an IPv4 address"),
            ("10.0.0.0/128", "an IPv6-sized prefix on an IPv4 address"),
            ("::1/129", "a prefix longer than an IPv6 address"),
            ("10.0.0.0/-1", "a negative prefix"),
            ("10.0.0.0/256", "a prefix that does not fit a byte"),
            ("10.0.0.0/eight", "a prefix that is not a number"),
            ("10.0.0.0/8/8", "two prefixes"),
            ("10.0.0.0/ 8", "a space in the prefix"),
            ("10.0.0/8", "three octets"),
            ("10.0.0.256/8", "an octet that does not fit"),
            ("10.0.0.0/255.0.0.0", "a netmask instead of a prefix length"),
            ("[::1]/128", "brackets around the address"),
            ("localhost", "a hostname, which the list never resolves"),
            ("internal.example.org/24", "a hostname with a prefix"),
            ("10.0.0.0-10.0.0.255", "a range, not a CIDR"),
        ];
        for (entry, wrong) in refused {
            let why = Cidr::parse(entry)
                .err()
                .unwrap_or_else(|| panic!("{entry:?} ({wrong}) parsed"));
            assert!(why.contains("allow-list entry"), "{entry:?}: {why}");
        }
    }

    /// Which addresses a parsed entry covers: the range edge to edge, the
    /// neighbours on either side, and never the other address family.
    #[test]
    fn an_allow_list_entry_covers_its_range_and_nothing_else() {
        let cases: &[(&str, &[&str], &[&str])] = &[
            // (entry, inside, outside)
            (
                "10.0.0.5",
                &["10.0.0.5"],
                &["10.0.0.4", "10.0.0.6", "::ffff:10.0.0.5"],
            ),
            (
                "127.0.0.0/8",
                &["127.0.0.0", "127.0.0.1", "127.255.255.255"],
                &["126.255.255.255", "128.0.0.0", "::1"],
            ),
            ("10.1.2.3/8", &["10.0.0.0", "10.255.255.255"], &["11.1.2.3"]),
            (
                "192.168.1.0/31",
                &["192.168.1.0", "192.168.1.1"],
                &["192.168.0.255", "192.168.1.2"],
            ),
            (
                "0.0.0.0/0",
                &["0.0.0.0", "10.0.0.1", "203.0.113.9", "255.255.255.255"],
                &["::", "::1", "::ffff:10.0.0.1", "2001:db8::1"],
            ),
            ("::1", &["::1"], &["::", "::2", "127.0.0.1"]),
            ("::1/127", &["::", "::1"], &["::2"]),
            (
                "fd00::/8",
                &[
                    "fd00::",
                    "fd12:3456::1",
                    "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                ],
                &["fcff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fe00::"],
            ),
            (
                "::/0",
                &["::", "::1", "fe80::1", "2001:db8::1"],
                &["0.0.0.0", "127.0.0.1", "255.255.255.255"],
            ),
        ];
        for (entry, inside, outside) in cases {
            let cidr = Cidr::parse(entry).unwrap();
            for spelling in *inside {
                assert!(
                    cidr.contains(address(spelling)),
                    "{entry} covers {spelling}"
                );
            }
            for spelling in *outside {
                assert!(
                    !cidr.contains(address(spelling)),
                    "{entry} does not cover {spelling}"
                );
            }
        }
    }

    /// One bad entry refuses the whole list, wherever it sits, and the
    /// refusal names the entry so the operator can find it.
    #[test]
    fn an_allow_list_fails_closed_on_any_bad_entry() {
        assert!(parse_allow_list(&[]).unwrap().is_empty());
        let good = ["10.0.0.0/8", "127.0.0.1", "fd00::/8"];
        assert_eq!(allow_list(&good).len(), good.len());

        let bad = ["10.0.0.0/33", "not-an-address", "", "localhost"];
        for entry in bad {
            for position in 0..=good.len() {
                let mut entries: Vec<String> =
                    good.iter().map(|entry| (*entry).to_owned()).collect();
                entries.insert(position, entry.to_owned());
                let why = parse_allow_list(&entries)
                    .err()
                    .unwrap_or_else(|| panic!("{entry:?} at {position} was accepted"));
                assert!(why.contains(entry), "{why} does not name {entry:?}");
            }
        }
    }

    /// `permits` is `is_global` or an allow-list hit, and the two halves
    /// only ever open addresses up: no entry closes a public one.
    #[test]
    fn permits_is_the_guard_or_an_entry_the_operator_listed() {
        let cases: &[(&[&str], &[&str], &[&str])] = &[
            // (allow-list, permitted, refused)
            (
                &[],
                &["8.8.8.8", "2001:4860:4860::8888", "::ffff:8.8.8.8"],
                &[
                    "127.0.0.1",
                    "10.0.0.1",
                    "169.254.169.254",
                    "::1",
                    "fe80::1",
                    "::ffff:127.0.0.1",
                ],
            ),
            // A v4 loopback entry opens v4 loopback, in every spelling of
            // it, and not the v6 loopback address.
            (
                &["127.0.0.0/8"],
                &[
                    "127.0.0.1",
                    "127.255.255.255",
                    "::ffff:127.0.0.1",
                    "::127.0.0.1",
                    "64:ff9b::7f00:1",
                    "8.8.8.8",
                ],
                &["::1", "10.0.0.1", "169.254.169.254"],
            ),
            // And the v6 loopback entry opens only itself.
            (
                &["::1/128"],
                &["::1"],
                &["::2", "127.0.0.1", "::ffff:127.0.0.1"],
            ),
            // A host route opens one address.
            (
                &["169.254.169.254"],
                &["169.254.169.254", "::ffff:169.254.169.254"],
                &["169.254.169.253", "169.254.169.255"],
            ),
            // Several entries are a union; a public address needs none.
            (
                &["10.0.0.0/8", "fd00::/8"],
                &["10.1.2.3", "fd12::1", "1.1.1.1"],
                &["192.168.0.1", "fc00::1", "::1"],
            ),
            // `/0` opens the whole family, which is what it says.
            (
                &["0.0.0.0/0"],
                &["127.0.0.1", "0.0.0.0", "255.255.255.255"],
                &["::1", "fe80::1"],
            ),
        ];
        for (entries, permitted, refused) in cases {
            let allowed = allow_list(entries);
            for spelling in *permitted {
                assert!(
                    permits(&allowed, address(spelling)),
                    "{entries:?} permits {spelling}"
                );
            }
            for spelling in *refused {
                assert!(
                    !permits(&allowed, address(spelling)),
                    "{entries:?} refuses {spelling}"
                );
            }
        }
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

    /// The resolver hands reqwest only the addresses the guard permits,
    /// and a name with none is an error rather than an empty answer. Only
    /// `localhost` resolves without a network, so it stands in for a public
    /// name that resolves inward.
    #[tokio::test]
    async fn the_resolver_drops_what_the_guard_refuses_and_errors_on_nothing_left() {
        use reqwest::dns::Resolve;
        let name = |host: &str| host.parse::<reqwest::dns::Name>().unwrap();

        let refused = VettingResolver { allowed: vec![] }
            .resolve(name("localhost"))
            .await
            .err()
            .expect("localhost resolves only to loopback, which the default refuses");
        assert!(
            refused
                .to_string()
                .contains("localhost resolves only to addresses"),
            "{refused}"
        );

        let allowed = allow_list(&["127.0.0.0/8", "::1/128"]);
        let vetted: Vec<SocketAddr> = VettingResolver {
            allowed: allowed.clone(),
        }
        .resolve(name("localhost"))
        .await
        .expect("loopback is listed")
        .collect();
        assert!(!vetted.is_empty());
        for socket in &vetted {
            assert!(socket.ip().is_loopback(), "{socket}");
            assert!(permits(&allowed, socket.ip()), "{socket}");
        }

        // With only the v4 half listed, the v6 loopback answer (if the
        // host gives one) is dropped and the v4 one survives.
        let v4_only = VettingResolver {
            allowed: allow_list(&["127.0.0.0/8"]),
        }
        .resolve(name("localhost"))
        .await
        .expect("127.0.0.1 is listed")
        .collect::<Vec<_>>();
        assert!(
            v4_only.iter().all(|socket| socket.ip().is_ipv4()),
            "{v4_only:?}"
        );
    }
}
