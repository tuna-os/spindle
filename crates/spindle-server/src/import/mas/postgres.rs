//! Reading a [`Snapshot`] from MAS's `PostgreSQL` database, as MAS 1.23
//! lays it out.
//!
//! One read-only, repeatable-read transaction for every query, so a MAS
//! that is still running cannot show a user here and that user's link
//! from a moment later. Identifiers are read as text: the importer needs
//! them only to join rows and to name providers, and the text form keeps
//! the `uuid` type out of the client's features.

use std::collections::HashMap;

use ::postgres::{Client, Config, IsolationLevel, NoTls, Transaction};

use super::{Link, Password, Provider, Snapshot, User};

/// Connect without transport TLS, as the Synapse reader does: for a
/// loopback port-forward or a private network.
///
/// # Errors
///
/// The configuration does not parse or the server cannot be reached.
pub fn connect_no_tls(config: &str, password: Option<&str>) -> Result<Client, String> {
    let mut config: Config = config
        .parse()
        .map_err(|error| format!("MAS database: {error}"))?;
    if let Some(password) = password {
        config.password(password);
    }
    config
        .connect(NoTls)
        .map_err(|error| format!("MAS database: {error}"))
}

/// Read the users, their current passwords and addresses, the upstream
/// providers and the links.
///
/// # Errors
///
/// A query fails: most likely a schema older than MAS 1.23's, which lacks
/// a column read here.
pub fn read(client: &mut Client) -> Result<Snapshot, String> {
    let failed = |error: ::postgres::Error| format!("MAS database: {error}");
    let mut transaction = client
        .build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .map_err(failed)?;
    let mut users: Vec<User> = transaction
        .query(
            "SELECT user_id::text, username, locked_at IS NOT NULL, \
                    deactivated_at IS NOT NULL, can_request_admin \
             FROM users ORDER BY username",
            &[],
        )
        .map_err(failed)?
        .iter()
        .map(|row| User {
            id: row.get(0),
            username: row.get(1),
            locked: row.get(2),
            deactivated: row.get(3),
            can_request_admin: row.get(4),
            password: None,
            emails: Vec::new(),
        })
        .collect();
    let index: HashMap<String, usize> = users
        .iter()
        .enumerate()
        .map(|(at, user)| (user.id.clone(), at))
        .collect();
    // The newest row is the one MAS verifies against: an upgrade or a
    // change adds a row and leaves the old ones.
    for row in transaction
        .query(
            "SELECT DISTINCT ON (user_id) user_id::text, hashed_password, version \
             FROM user_passwords ORDER BY user_id, created_at DESC",
            &[],
        )
        .map_err(failed)?
    {
        let user_id: String = row.get(0);
        let version: i32 = row.get(2);
        if let Some(&at) = index.get(&user_id) {
            users[at].password = Some(Password {
                hash: row.get(1),
                version: u16::try_from(version)
                    .map_err(|_| format!("user_passwords.version {version} is out of range"))?,
            });
        }
    }
    read_emails(&mut transaction, &mut users, &index)?;
    let providers = transaction
        .query(
            "SELECT upstream_oauth_provider_id::text, issuer FROM upstream_oauth_providers",
            &[],
        )
        .map_err(failed)?
        .iter()
        .map(|row| Provider {
            id: row.get(0),
            issuer: row.get(1),
        })
        .collect();
    let links = transaction
        .query(
            "SELECT upstream_oauth_provider_id::text, subject, user_id::text \
             FROM upstream_oauth_links",
            &[],
        )
        .map_err(failed)?
        .iter()
        .map(|row| Link {
            provider_id: row.get(0),
            subject: row.get(1),
            user_id: row.get(2),
        })
        .collect();
    transaction.commit().map_err(failed)?;
    Ok(Snapshot {
        users,
        providers,
        links,
    })
}

/// Add each user's confirmed addresses.
fn read_emails(
    transaction: &mut Transaction<'_>,
    users: &mut [User],
    index: &HashMap<String, usize>,
) -> Result<(), String> {
    let failed = |error: ::postgres::Error| format!("MAS database: {error}");
    // MAS before 1.23 kept unconfirmed addresses beside confirmed ones,
    // told apart by `confirmed_at`; 1.23 dropped the column with the
    // unconfirmed rows. Read either.
    let has_confirmed_at = !transaction
        .query(
            "SELECT 1 FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = 'user_emails' \
               AND column_name = 'confirmed_at'",
            &[],
        )
        .map_err(failed)?
        .is_empty();
    let emails = if has_confirmed_at {
        "SELECT user_id::text, email FROM user_emails WHERE confirmed_at IS NOT NULL \
         ORDER BY created_at"
    } else {
        "SELECT user_id::text, email FROM user_emails ORDER BY created_at"
    };
    for row in transaction.query(emails, &[]).map_err(failed)? {
        let user_id: String = row.get(0);
        if let Some(&at) = index.get(&user_id) {
            users[at].emails.push(row.get(1));
        }
    }
    Ok(())
}
