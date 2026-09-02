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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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
/// The single entry point. Every caller goes through here rather than
/// pairing [`is_global`] with its own allow-list scan, so that an address
/// is canonicalised once and the operator's ranges are matched against the
/// same thing the routability judgement saw.
pub(crate) fn permits(allowed: &[Cidr], address: IpAddr) -> bool {
    let address = canonical(address);
    is_global(address) || allowed.iter().any(|cidr| cidr.contains(address))
}

/// The address a packet to `address` actually reaches.
///
/// IPv6 has several ways to carry an IPv4 address, and on a network that
/// translates them the destination is that IPv4 address rather than the
/// IPv6 spelling of it. A filter that judges the spelling therefore has
/// one bypass per spelling: `::ffff:169.254.169.254` was already handled,
/// but `64:ff9b::169.254.169.254` — the same host, on any NAT64 network,
/// which is the ordinary shape of an IPv6-only cloud subnet — was not.
///
/// Normalising here rather than adding refusal lines means the operator's
/// `allow_internal` keeps meaning what it says: a range they opened stays
/// open however an address in it is written, and everything else stays
/// shut the same way.
fn canonical(address: IpAddr) -> IpAddr {
    let IpAddr::V6(v6) = address else {
        return address;
    };
    if let Some(mapped) = v6.to_ipv4_mapped() {
        return IpAddr::V4(mapped);
    }
    // A `match` would fold these together -- the arms return the same
    // thing -- and folding them would take the comments with it. Each
    // line below is a different transition mechanism with a different
    // reason for being here, so they stay separate.
    let [first, second, third, fourth, fifth, sixth, high, low] = v6.segments();
    let leading = [first, second, third, fourth, fifth, sixth];
    // 64:ff9b::/96, NAT64's well-known prefix (RFC 6052 §2.1). The longer
    // 64:ff9b:1::/48 form carries the address at a prefix-dependent
    // offset and is not decoded here.
    if leading == [0x0064, 0xff9b, 0, 0, 0, 0] {
        return embedded_v4(high, low);
    }
    // 2002::/16, 6to4 (RFC 3056): the embedded address is the relay's.
    if first == 0x2002 {
        return embedded_v4(second, third);
    }
    // ::a.b.c.d, IPv4-compatible (RFC 4291 §2.5.5.1, deprecated). `::`
    // and `::1` are IPv6 addresses in their own right, judged as such
    // below — not as 0.0.0.0 and 0.0.0.1.
    if leading == [0, 0, 0, 0, 0, 0] && (high != 0 || low > 1) {
        return embedded_v4(high, low);
    }
    address
}

/// The IPv4 address two IPv6 segments spell.
fn embedded_v4(high: u16, low: u16) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from((u32::from(high) << 16) | u32::from(low)))
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
///
/// [`canonical`] runs first, so the v6 arm only ever judges addresses that
/// are genuinely v6 destinations: every form that carries an IPv4 address
/// has already become one, and is refused or allowed as that address.
pub(crate) fn is_global(address: IpAddr) -> bool {
    match canonical(address) {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.octets()[0] == 0 // 0.0.0.0/8: `is_unspecified` is only 0.0.0.0
                || v4.octets()[0] >= 224 // multicast + reserved
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64) // CGNAT 100.64/10
                || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0) // 192.0.0.0/24: IETF protocol assignments
                || (v4.octets()[0] == 198 && (v4.octets()[1] & 0xfe) == 18) // benchmarking 198.18.0.0/15
                || (v4.octets()[0] == 192 && v4.octets()[1] == 88 && v4.octets()[2] == 99))
            // 192.88.99.0/24: the 6to4 relay anycast address
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfec0 // site-local fec0::/10, deprecated but routed
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
