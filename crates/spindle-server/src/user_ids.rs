//! What a Matrix user ID says about where it lives.
//!
//! The server part of a user ID decides whose account a request names.
//! Each module used to parse it for itself, and a caller that got the rule
//! wrong acted on the wrong account: #951 locked the local `@alice` when
//! an admin named `@alice:elsewhere.example`. One module holds the rule,
//! so that a caller asks it rather than parses the ID again.
//!
//! These functions only split the ID. They do not check the grammar of
//! a user ID, and they do not fold case.

/// The server part of `user_id`: all of the text after the first `:`.
///
/// A server name can have a port (`example.org:8448`), and a localpart
/// cannot contain `:`, so the first `:` is where the server part starts.
/// `None` when there is no `:`, which is not a user ID.
#[must_use]
pub fn server_of(user_id: &str) -> Option<&str> {
    user_id.split_once(':').map(|(_, server)| server)
}

/// Whether `server_name` is the server of `user_id`.
///
/// The names must be equal. A server name that ends with `server_name`
/// is a different server.
#[must_use]
pub fn is_on(user_id: &str, server_name: &str) -> bool {
    server_of(user_id) == Some(server_name)
}

/// The localpart of `user_id` if `user_id` is a user of `server_name`.
///
/// `user_id` must be a full ID (`@localpart:server`). An ID of another
/// server is `None`: it never names the local account of the same name.
#[must_use]
pub fn local_localpart<'a>(user_id: &'a str, server_name: &str) -> Option<&'a str> {
    user_id
        .strip_prefix('@')
        .and_then(|rest| rest.split_once(':'))
        .filter(|(_, server)| *server == server_name)
        .map(|(localpart, _)| localpart)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_server_part_starts_at_the_first_colon() {
        assert_eq!(server_of("@alice:example.org"), Some("example.org"));
        assert_eq!(
            server_of("@alice:example.org:8448"),
            Some("example.org:8448")
        );
        assert_eq!(server_of("alice"), None);
    }

    #[test]
    fn a_server_must_match_the_whole_name() {
        assert!(is_on("@alice:example.org", "example.org"));
        assert!(!is_on("@alice:evil.example.org", "example.org"));
        assert!(!is_on("@alice:example.org:8448", "example.org"));
        assert!(!is_on("alice", "example.org"));
    }

    #[test]
    fn an_id_of_another_server_names_no_local_account() {
        assert_eq!(
            local_localpart("@alice:example.org", "example.org"),
            Some("alice")
        );
        assert_eq!(
            local_localpart("@alice:elsewhere.example", "example.org"),
            None
        );
        // A full ID only: a bare localpart and an ID without `@` are refused.
        assert_eq!(local_localpart("alice", "example.org"), None);
        assert_eq!(local_localpart("alice:example.org", "example.org"), None);
        // No case fold. The account rows decide what a case difference means.
        assert_eq!(
            local_localpart("@Alice:example.org", "example.org"),
            Some("Alice")
        );
    }
}
