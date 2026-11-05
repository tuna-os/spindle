//! `m.room.server_acl`: which servers a room admits over federation.
//!
//! The spec's rules, in the spec's order: strip the port from the server
//! name; an IP literal is refused unless `allow_ip_literals` says
//! otherwise; a name matching any `deny` glob is refused; a name matching
//! some `allow` glob is admitted; anything else is refused. A missing
//! `allow` admits nobody, which is the spec's reading and the one that
//! fails closed. Globs are `*` (any run) and `?` (one character); nothing
//! else is special.
//!
//! The content is read from the room's current state and applied in two
//! places: inbound, before a peer's PDU or room read is judged, and
//! outbound, when the fan-out for a local event is planned. The spec asks
//! for both — a denied server must neither feed the room nor hear it.

use serde_json::Value;

/// One room's ACL, parsed from the state event's content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAcl {
    allow: Vec<String>,
    deny: Vec<String>,
    allow_ip_literals: bool,
}

impl ServerAcl {
    /// Parse an `m.room.server_acl` content. Non-string entries in a list
    /// are skipped rather than failing the whole event, as Synapse does:
    /// a malformed entry must not turn a lockdown into an open door.
    #[must_use]
    pub fn from_content(content: &Value) -> Self {
        let list = |key: &str| -> Vec<String> {
            content[key]
                .as_array()
                .map(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default()
        };
        Self {
            allow: list("allow"),
            deny: list("deny"),
            allow_ip_literals: content["allow_ip_literals"].as_bool().unwrap_or(true),
        }
    }

    /// Whether `server_name` may take part in the room.
    #[must_use]
    pub fn permits(&self, server_name: &str) -> bool {
        let host = strip_port(server_name);
        if !self.allow_ip_literals && is_ip_literal(host) {
            return false;
        }
        if self.deny.iter().any(|pattern| glob_matches(pattern, host)) {
            return false;
        }
        self.allow.iter().any(|pattern| glob_matches(pattern, host))
    }
}

/// The host part of a server name: a trailing `:port` removed, a bracketed
/// IPv6 literal left whole.
fn strip_port(name: &str) -> &str {
    if name.starts_with('[') {
        return name.find(']').map_or(name, |end| &name[..=end]);
    }
    match name.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => name,
    }
}

fn is_ip_literal(host: &str) -> bool {
    if let Some(inner) = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        return inner.parse::<std::net::Ipv6Addr>().is_ok();
    }
    host.parse::<std::net::Ipv4Addr>().is_ok()
}

/// `*` matches any run of characters, `?` exactly one; everything else is
/// literal. Iterative with backtracking to the last `*`, so a pattern of
/// many stars costs linear time rather than exponential.
fn glob_matches(pattern: &str, text: &str) -> bool {
    let pattern = pattern.as_bytes();
    let text = text.as_bytes();
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some(b'*') => {
                star = Some((p, t));
                p += 1;
            }
            Some(b'?') => {
                p += 1;
                t += 1;
            }
            Some(&c) if c.eq_ignore_ascii_case(&text[t]) => {
                p += 1;
                t += 1;
            }
            _ => match star {
                Some((sp, st)) => {
                    p = sp + 1;
                    t = st + 1;
                    star = Some((sp, st + 1));
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&c| c == b'*')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn acl(content: &Value) -> ServerAcl {
        ServerAcl::from_content(content)
    }

    #[test]
    fn allow_list_admits_matches_and_nothing_else() {
        let acl = acl(&json!({ "allow": ["*.example.org", "friend.net"] }));
        assert!(acl.permits("a.example.org"));
        assert!(acl.permits("friend.net"));
        assert!(!acl.permits("example.org"));
        assert!(!acl.permits("stranger.org"));
    }

    #[test]
    fn deny_beats_allow() {
        let acl = acl(&json!({ "allow": ["*"], "deny": ["evil.*", "bad?.net"] }));
        assert!(acl.permits("good.org"));
        assert!(!acl.permits("evil.org"));
        assert!(!acl.permits("bad1.net"));
        assert!(acl.permits("bad12.net"));
    }

    #[test]
    fn missing_allow_admits_nobody() {
        assert!(!acl(&json!({})).permits("anyone.org"));
        assert!(!acl(&json!({ "deny": [] })).permits("anyone.org"));
    }

    #[test]
    fn ip_literals_follow_the_flag_and_ports_are_ignored() {
        let open = acl(&json!({ "allow": ["*"] }));
        assert!(open.permits("1.2.3.4:8448"));
        assert!(open.permits("[::1]:8448"));
        assert!(open.permits("host.org:443"));
        let closed = acl(&json!({ "allow": ["*"], "allow_ip_literals": false }));
        assert!(!closed.permits("1.2.3.4"));
        assert!(!closed.permits("1.2.3.4:8448"));
        assert!(!closed.permits("[::1]"));
        assert!(closed.permits("host.org:443"));
    }

    #[test]
    fn malformed_entries_are_skipped_not_fatal() {
        let acl = acl(&json!({ "allow": ["ok.org", 5, null], "deny": [{}] }));
        assert!(acl.permits("ok.org"));
        assert!(!acl.permits("other.org"));
    }

    #[test]
    fn glob_backtracks_across_many_stars() {
        assert!(glob_matches("*a*b*c*", "xxaxxbxxcxx"));
        assert!(!glob_matches("*a*b*c", "xxaxxbxx"));
        assert!(glob_matches("*", ""));
        assert!(!glob_matches("?", ""));
        assert!(glob_matches("Example.ORG", "example.org"));
    }
}
