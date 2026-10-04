//! Native, snapshot-consistent reads from a live Synapse `PostgreSQL` database.
//!
//! This is the production path. The sibling `SQLite` reader remains useful for
//! small, shareable fixtures, but exporting a multi-gigabyte deployment just
//! to decide whether it can migrate duplicates work and can mix database
//! snapshots. A [`Snapshot`] holds one repeatable-read transaction and reads
//! rooms one at a time, bounding memory by the largest room rather than the
//! whole homeserver.

use ::postgres::{Client, Config, IsolationLevel, NoTls, Transaction};
use serde_json::Value;

use super::{ReadError, is_create_rooted};
use crate::import::{PlanError, SourceEvent, SourceRoom, StateMap, plan_resolving};

/// A connection to Synapse's `PostgreSQL` database.
pub struct Reader {
    client: Client,
}

impl Reader {
    /// Connect without transport TLS.
    ///
    /// This is appropriate for a loopback port-forward or a private service
    /// mesh. Call [`Self::from_client`] with a TLS-configured client when the
    /// `PostgreSQL` connection itself crosses an untrusted network.
    ///
    /// # Errors
    ///
    /// Returns [`ReadError`] if the configuration is invalid or `PostgreSQL`
    /// cannot be reached.
    pub fn connect_no_tls(config: &str, password: Option<&str>) -> Result<Self, ReadError> {
        let mut config: Config = config.parse().map_err(ReadError::Postgres)?;
        if let Some(password) = password {
            config.password(password);
        }
        Ok(Self {
            client: config.connect(NoTls)?,
        })
    }

    /// Wrap a `PostgreSQL` client configured by the operator, including TLS.
    #[must_use]
    pub fn from_client(client: Client) -> Self {
        Self { client }
    }

    /// Hold one source snapshot for room discovery and every subsequent read.
    ///
    /// # Errors
    ///
    /// Returns [`ReadError`] if `PostgreSQL` cannot begin the transaction.
    pub fn snapshot(&mut self) -> Result<Snapshot<'_>, ReadError> {
        let transaction = self
            .client
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()?;
        Ok(Snapshot { transaction })
    }

    /// Join a snapshot exported by another live [`Snapshot`].
    ///
    /// The exporting transaction must remain open until this transaction is
    /// started. This is the primitive a bounded room-worker pool uses to read
    /// in parallel without observing different points in live Synapse.
    ///
    /// # Errors
    ///
    /// Returns [`ReadError`] if the identifier is invalid or `PostgreSQL` cannot
    /// join the exported snapshot.
    pub fn snapshot_from(&mut self, snapshot_id: &str) -> Result<Snapshot<'_>, ReadError> {
        if snapshot_id.is_empty()
            || !snapshot_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ReadError::InvalidSnapshotId(snapshot_id.to_owned()));
        }
        let mut snapshot = self.snapshot()?;
        snapshot
            .transaction
            .batch_execute(&format!("SET TRANSACTION SNAPSHOT '{snapshot_id}'"))?;
        Ok(snapshot)
    }
}

/// A consistent view of the live Synapse database.
pub struct Snapshot<'client> {
    transaction: Transaction<'client>,
}

/// Event state groups and their storage compression predecessors.
pub type StateGroupGraph = (
    std::collections::HashMap<String, i64>,
    std::collections::HashMap<i64, i64>,
);

/// One global or room-scoped account-data record.
pub struct AccountDataRow {
    pub room_id: String,
    pub event_type: String,
    pub content: Value,
}

/// A device's signed identity keys.
pub struct DeviceKeyRow {
    pub device_id: String,
    pub keys: Value,
}

/// One of the user's master, self-signing, or user-signing keys.
pub struct CrossSigningKeyRow {
    pub key_type: String,
    pub keys: Value,
}

/// A normalized Synapse signature to merge into its target key.
pub struct SignatureRow {
    pub signer_user_id: String,
    pub signer_key_id: String,
    pub target_user_id: String,
    pub target_device_id: String,
    pub signature: String,
}

/// Metadata for one server-side encrypted room-key backup version.
pub struct BackupVersionRow {
    pub version: u64,
    pub algorithm: String,
    pub auth_data: Value,
    pub deleted: bool,
    pub etag: u64,
}

/// One opaque, recovery-key-encrypted Megolm session.
pub struct BackupSessionRow {
    pub room_id: String,
    pub session_id: String,
    pub version: u64,
    pub data: Value,
}

/// The server-held data a fresh client needs for secret-storage recovery.
pub struct RecoveryData {
    pub user_id: String,
    pub account_data: Vec<AccountDataRow>,
    pub device_keys: Vec<DeviceKeyRow>,
    pub cross_signing_keys: Vec<CrossSigningKeyRow>,
    pub signatures: Vec<SignatureRow>,
    pub backup_versions: Vec<BackupVersionRow>,
    pub backup_sessions: Vec<BackupSessionRow>,
}

impl Snapshot<'_> {
    /// Export this snapshot so independent room workers can join it.
    ///
    /// # Errors
    ///
    /// Returns [`ReadError`] if `PostgreSQL` cannot export the transaction.
    pub fn export_id(&mut self) -> Result<String, ReadError> {
        Ok(self
            .transaction
            .query_one("SELECT pg_export_snapshot()", &[])?
            .get(0))
    }

    /// Rooms in which a local user is currently joined, in stable order.
    ///
    /// # Errors
    ///
    /// Returns [`ReadError`] if the source query fails.
    pub fn joined_rooms(&mut self, server_name: &str) -> Result<Vec<String>, ReadError> {
        let rows = self.transaction.query(
            "SELECT DISTINCT state.room_id \
             FROM current_state_events AS state \
             INNER JOIN event_json AS body ON body.event_id = state.event_id \
             WHERE state.type = 'm.room.member' \
               AND right(state.state_key, length($1) + 1) = ':' || $1 \
               AND body.json::jsonb -> 'content' ->> 'membership' = 'join' \
             ORDER BY state.room_id",
            &[&server_name],
        )?;
        Ok(rows.into_iter().map(|row| row.get(0)).collect())
    }

    /// Read the opaque custody data used by fresh-client key recovery.
    ///
    /// # Errors
    ///
    /// Returns [`ReadError`] if a source query fails or stored JSON is invalid.
    #[allow(clippy::too_many_lines)]
    pub fn recovery_data(&mut self, user_id: &str) -> Result<RecoveryData, ReadError> {
        let rows = self.transaction.query(
            "SELECT room_id, account_data_type, content FROM ( \
                 SELECT ''::text AS room_id, account_data_type, content \
                 FROM account_data WHERE user_id = $1 \
                 UNION ALL \
                 SELECT room_id, account_data_type, content \
                 FROM room_account_data WHERE user_id = $1 \
             ) AS data ORDER BY room_id, account_data_type",
            &[&user_id],
        )?;
        let mut account_data = Vec::with_capacity(rows.len());
        for row in rows {
            account_data.push(AccountDataRow {
                room_id: row.get(0),
                event_type: row.get(1),
                content: serde_json::from_str(&row.get::<_, String>(2))?,
            });
        }

        let rows = self.transaction.query(
            "SELECT device_id, key_json FROM e2e_device_keys_json \
             WHERE user_id = $1 ORDER BY device_id",
            &[&user_id],
        )?;
        let mut device_keys = Vec::with_capacity(rows.len());
        for row in rows {
            device_keys.push(DeviceKeyRow {
                device_id: row.get(0),
                keys: serde_json::from_str(&row.get::<_, String>(1))?,
            });
        }

        let rows = self.transaction.query(
            // A key that was replaced keeps its old row under a lower
            // `stream_id`; only the newest row per type is the user's key.
            "SELECT DISTINCT ON (keytype) keytype, keydata FROM e2e_cross_signing_keys \
             WHERE user_id = $1 ORDER BY keytype, stream_id DESC",
            &[&user_id],
        )?;
        let mut cross_signing_keys = Vec::with_capacity(rows.len());
        for row in rows {
            cross_signing_keys.push(CrossSigningKeyRow {
                key_type: row.get(0),
                keys: serde_json::from_str(&row.get::<_, String>(1))?,
            });
        }

        let signatures = self
            .transaction
            .query(
                "SELECT user_id, key_id, target_user_id, target_device_id, signature \
                 FROM e2e_cross_signing_signatures \
                 WHERE user_id = $1 OR target_user_id = $1 \
                 ORDER BY target_user_id, target_device_id, user_id, key_id",
                &[&user_id],
            )?
            .into_iter()
            .map(|row| SignatureRow {
                signer_user_id: row.get(0),
                signer_key_id: row.get(1),
                target_user_id: row.get(2),
                target_device_id: row.get(3),
                signature: row.get(4),
            })
            .collect();

        let rows = self.transaction.query(
            "SELECT version, algorithm, auth_data, deleted, etag \
             FROM e2e_room_keys_versions WHERE user_id = $1 ORDER BY version",
            &[&user_id],
        )?;
        let mut backup_versions = Vec::with_capacity(rows.len());
        for row in rows {
            backup_versions.push(BackupVersionRow {
                version: row.get::<_, i64>(0).try_into().unwrap_or(0),
                algorithm: row.get(1),
                auth_data: serde_json::from_str(&row.get::<_, String>(2))?,
                deleted: row.get::<_, i16>(3) != 0,
                etag: row.get::<_, i64>(4).try_into().unwrap_or(0),
            });
        }

        let rows = self.transaction.query(
            "SELECT room_id, session_id, version, first_message_index, \
                    forwarded_count, is_verified, session_data \
             FROM e2e_room_keys WHERE user_id = $1 \
             ORDER BY version, room_id, session_id",
            &[&user_id],
        )?;
        let mut backup_sessions = Vec::with_capacity(rows.len());
        for row in rows {
            backup_sessions.push(BackupSessionRow {
                room_id: row.get(0),
                session_id: row.get(1),
                version: row.get::<_, i64>(2).try_into().unwrap_or(0),
                data: serde_json::json!({
                    "first_message_index": row.get::<_, i32>(3),
                    "forwarded_count": row.get::<_, i32>(4),
                    "is_verified": row.get::<_, bool>(5),
                    "session_data": serde_json::from_str::<Value>(&row.get::<_, String>(6))?,
                }),
            });
        }

        Ok(RecoveryData {
            user_id: user_id.to_owned(),
            account_data,
            device_keys,
            cross_signing_keys,
            signatures,
            backup_versions,
            backup_sessions,
        })
    }

    /// Run one read-only query inside this snapshot.
    ///
    /// The full importer reads many small tables; each read is one query
    /// here rather than one method per table.
    ///
    /// # Errors
    ///
    /// Returns [`ReadError`] if the query fails.
    pub fn query(
        &mut self,
        sql: &str,
        params: &[&(dyn ::postgres::types::ToSql + Sync)],
    ) -> Result<Vec<::postgres::Row>, ReadError> {
        Ok(self.transaction.query(sql, params)?)
    }

    /// Original signed JSON bodies for the named events.
    ///
    /// The full importer asks for one chunk of a room's plan at a time, so a
    /// room with a million events never holds every body at once.
    ///
    /// # Errors
    ///
    /// Returns [`ReadError`] if the query fails or a body is not valid JSON.
    pub fn event_bodies_for(
        &mut self,
        event_ids: &[String],
    ) -> Result<std::collections::HashMap<String, Value>, ReadError> {
        let rows = self.transaction.query(
            "SELECT event_id, json FROM event_json WHERE event_id = ANY($1)",
            &[&event_ids],
        )?;
        let mut bodies = std::collections::HashMap::with_capacity(rows.len());
        for row in rows {
            bodies.insert(row.get(0), serde_json::from_str(&row.get::<_, String>(1))?);
        }
        Ok(bodies)
    }

    /// Original signed JSON bodies for every event row retained in a room.
    ///
    /// # Errors
    ///
    /// Returns [`ReadError`] if the source query fails or an event body is not
    /// valid JSON.
    pub fn event_bodies(
        &mut self,
        room_id: &str,
    ) -> Result<std::collections::BTreeMap<String, Value>, ReadError> {
        let rows = self.transaction.query(
            "SELECT event.event_id, body.json \
             FROM events AS event \
             INNER JOIN event_json AS body ON body.event_id = event.event_id \
             WHERE event.room_id = $1 ORDER BY event.stream_ordering",
            &[&room_id],
        )?;
        let mut bodies = std::collections::BTreeMap::new();
        for row in rows {
            bodies.insert(row.get(0), serde_json::from_str(&row.get::<_, String>(1))?);
        }
        Ok(bodies)
    }

    /// Read one room directly from Synapse's normalized tables.
    ///
    /// # Errors
    ///
    /// Returns [`ReadError`] if the room is absent, a query fails, or a
    /// retained-history horizon cannot be reconstructed safely.
    pub fn read_room(&mut self, room_id: &str) -> Result<SourceRoom, ReadError> {
        let known = self
            .transaction
            .query_opt("SELECT room_id FROM rooms WHERE room_id = $1", &[&room_id])?;
        if known.is_none() {
            return Err(ReadError::UnknownRoom(room_id.to_owned()));
        }

        let rows = self.transaction.query(
            "SELECT event_id, type, state_key, depth, stream_ordering, outlier, \
                    rejection_reason IS NOT NULL \
             FROM events WHERE room_id = $1 ORDER BY stream_ordering",
            &[&room_id],
        )?;
        let mut events: Vec<SourceEvent> = rows
            .into_iter()
            .map(|row| SourceEvent {
                event_id: row.get(0),
                event_type: row.get(1),
                state_key: row.get(2),
                depth: row.get::<_, i64>(3).try_into().unwrap_or(0),
                stream_ordering: row.get(4),
                outlier: row.get(5),
                rejected: row.get(6),
                prev_events: Vec::new(),
            })
            .collect();

        let rows = self.transaction.query(
            "SELECT edge.event_id, edge.prev_event_id \
             FROM event_edges AS edge \
             INNER JOIN events ON events.event_id = edge.event_id \
             WHERE events.room_id = $1 AND edge.is_state = FALSE",
            &[&room_id],
        )?;
        let mut parents = std::collections::BTreeMap::<String, Vec<String>>::new();
        for row in rows {
            parents.entry(row.get(0)).or_default().push(row.get(1));
        }
        for event in &mut events {
            if let Some(found) = parents.remove(&event.event_id) {
                event.prev_events = found;
            }
        }

        let rows = self.transaction.query(
            "SELECT type, state_key, event_id \
             FROM current_state_events WHERE room_id = $1",
            &[&room_id],
        )?;
        let mut current_state = StateMap::new();
        for row in rows {
            current_state.insert((row.get(0), row.get(1)), row.get(2));
        }

        let mut forward_extremities: Vec<String> = self
            .transaction
            .query(
                "SELECT event_id FROM event_forward_extremities WHERE room_id = $1",
                &[&room_id],
            )?
            .into_iter()
            .map(|row| row.get(0))
            .collect();
        forward_extremities.sort_unstable();

        let mut room = SourceRoom {
            room_id: room_id.to_owned(),
            events,
            current_state,
            state_after_root: None,
            forward_extremities,
        };

        // `plan_resolving` names the same root as `plan` for a room with one
        // starting point, and still names one when there are several.
        if !is_create_rooted(&room)
            && let Err(PlanError::NoRootState { root, .. }) = plan_resolving(&room)
        {
            room.state_after_root = Some(self.state_after_root(room_id, &root)?);
        }
        Ok(room)
    }

    /// The state after one event, as Synapse resolved it.
    ///
    /// # Errors
    ///
    /// Returns [`ReadError`] if the event has no state group or the chain
    /// cannot be walked.
    pub fn state_after_event(
        &mut self,
        room_id: &str,
        event_id: &str,
    ) -> Result<StateMap, ReadError> {
        self.state_after_root(room_id, event_id)
    }

    /// Every `(event, auth event)` edge Synapse holds for a room, outliers
    /// included: the auth DAG the room version's resolver walks.
    ///
    /// # Errors
    ///
    /// Returns [`ReadError`] if the query fails.
    pub fn auth_edges(&mut self, room_id: &str) -> Result<Vec<(String, String)>, ReadError> {
        Ok(self
            .transaction
            .query(
                "SELECT event_id, auth_id FROM event_auth WHERE room_id = $1",
                &[&room_id],
            )?
            .into_iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect())
    }

    /// Each of a room's events' state group, and each such group's
    /// `prev_state_group`: enough to tell, per event, whether Synapse
    /// derived its state from its parents or took it from elsewhere.
    ///
    /// # Errors
    ///
    /// Returns [`ReadError`] if a query fails.
    pub fn state_group_graph(&mut self, room_id: &str) -> Result<StateGroupGraph, ReadError> {
        let rows = self.transaction.query(
            "SELECT groups.event_id, groups.state_group \
             FROM event_to_state_groups AS groups \
             INNER JOIN events ON events.event_id = groups.event_id \
             WHERE events.room_id = $1",
            &[&room_id],
        )?;
        let mut groups = std::collections::HashMap::with_capacity(rows.len());
        for row in rows {
            groups.insert(row.get::<_, String>(0), row.get::<_, i64>(1));
        }
        let ids: Vec<i64> = {
            let mut ids: Vec<i64> = groups.values().copied().collect();
            ids.sort_unstable();
            ids.dedup();
            ids
        };
        let rows = self.transaction.query(
            "SELECT state_group, prev_state_group FROM state_group_edges \
             WHERE state_group = ANY($1)",
            &[&ids],
        )?;
        let mut edges = std::collections::HashMap::with_capacity(rows.len());
        for row in rows {
            edges.insert(row.get::<_, i64>(0), row.get::<_, i64>(1));
        }
        Ok((groups, edges))
    }

    /// The state after one event as Synapse resolved it, for the named slots
    /// only. A slot Synapse's state does not hold is absent from the map.
    ///
    /// The importer compares the room version's resolver with Synapse at
    /// each fork on the slots the fork contested; reading the whole state of
    /// a room with tens of thousands of members for each would dominate.
    ///
    /// # Errors
    ///
    /// Returns [`ReadError`] if the event has no state group or a query fails.
    pub fn state_after_event_keys(
        &mut self,
        room_id: &str,
        event_id: &str,
        keys: &[(String, String)],
    ) -> Result<StateMap, ReadError> {
        let groups = self.state_group_chain(room_id, event_id)?;
        let types: Vec<&str> = keys.iter().map(|(kind, _)| kind.as_str()).collect();
        let state_keys: Vec<&str> = keys.iter().map(|(_, key)| key.as_str()).collect();
        let rows = self.transaction.query(
            "SELECT state_group, type, state_key, event_id \
             FROM state_groups_state \
             WHERE room_id = $1 AND state_group = ANY($2) \
               AND type = ANY($3) AND state_key = ANY($4)",
            &[&room_id, &groups, &types, &state_keys],
        )?;
        let wanted: std::collections::HashSet<(&str, &str)> = keys
            .iter()
            .map(|(kind, key)| (kind.as_str(), key.as_str()))
            .collect();
        let depth: std::collections::HashMap<i64, usize> = groups
            .iter()
            .enumerate()
            .map(|(depth, state_group)| (*state_group, depth))
            .collect();
        let mut rows: Vec<_> = rows.into_iter().collect();
        rows.sort_unstable_by_key(|row| depth.get(&row.get::<_, i64>(0)).copied());
        let mut state = StateMap::new();
        for row in rows {
            let (kind, key): (String, String) = (row.get(1), row.get(2));
            if wanted.contains(&(kind.as_str(), key.as_str())) {
                state.entry((kind, key)).or_insert(row.get(3));
            }
        }
        Ok(state)
    }

    /// The state groups behind `event_id`'s, newest first.
    fn state_group_chain(&mut self, room_id: &str, event_id: &str) -> Result<Vec<i64>, ReadError> {
        let Some(row) = self.transaction.query_opt(
            "SELECT state_group FROM event_to_state_groups WHERE event_id = $1",
            &[&event_id],
        )?
        else {
            return Err(ReadError::MissingStateGroup {
                room_id: room_id.to_owned(),
                root: event_id.to_owned(),
            });
        };
        let root_group: i64 = row.get(0);
        let chain = self.transaction.query(
            "WITH RECURSIVE chain(state_group, depth, path, cycle) AS ( \
                 SELECT $1::bigint, 0::bigint, ARRAY[$1::bigint], FALSE \
                 UNION ALL \
                 SELECT edge.prev_state_group, chain.depth + 1, \
                        chain.path || edge.prev_state_group, \
                        edge.prev_state_group = ANY(chain.path) \
                 FROM chain \
                 INNER JOIN state_group_edges AS edge \
                         ON edge.state_group = chain.state_group \
                 WHERE NOT chain.cycle \
             ) \
             SELECT state_group, cycle FROM chain ORDER BY depth",
            &[&root_group],
        )?;
        let mut groups = Vec::with_capacity(chain.len());
        for row in chain {
            let state_group: i64 = row.get(0);
            if row.get::<_, bool>(1) {
                return Err(ReadError::StateGroupCycle {
                    room_id: room_id.to_owned(),
                    state_group,
                });
            }
            groups.push(state_group);
        }
        Ok(groups)
    }

    /// Resolve Synapse's delta-compressed state group for a horizon root.
    ///
    /// Groups are walked newest to oldest. The first value for a state slot
    /// therefore wins, while older deltas fill only slots not mentioned by a
    /// newer group.
    fn state_after_root(
        &mut self,
        room_id: &str,
        root_event_id: &str,
    ) -> Result<StateMap, ReadError> {
        let Some(row) = self.transaction.query_opt(
            "SELECT state_group FROM event_to_state_groups WHERE event_id = $1",
            &[&root_event_id],
        )?
        else {
            return Err(ReadError::MissingStateGroup {
                room_id: room_id.to_owned(),
                root: root_event_id.to_owned(),
            });
        };
        let root_group: i64 = row.get(0);
        let chain = self.transaction.query(
            "WITH RECURSIVE chain(state_group, depth, path, cycle) AS ( \
                 SELECT $1::bigint, 0::bigint, ARRAY[$1::bigint], FALSE \
                 UNION ALL \
                 SELECT edge.prev_state_group, chain.depth + 1, \
                        chain.path || edge.prev_state_group, \
                        edge.prev_state_group = ANY(chain.path) \
                 FROM chain \
                 INNER JOIN state_group_edges AS edge \
                         ON edge.state_group = chain.state_group \
                 WHERE NOT chain.cycle \
             ) \
             SELECT state_group, cycle FROM chain ORDER BY depth",
            &[&root_group],
        )?;

        let mut groups = Vec::with_capacity(chain.len());
        for row in chain {
            let state_group: i64 = row.get(0);
            if row.get::<_, bool>(1) {
                return Err(ReadError::StateGroupCycle {
                    room_id: room_id.to_owned(),
                    state_group,
                });
            }
            groups.push(state_group);
        }

        let rows = self.transaction.query(
            "SELECT state_group, type, state_key, event_id \
             FROM state_groups_state \
             WHERE room_id = $1 AND state_group = ANY($2)",
            &[&room_id, &groups],
        )?;
        let depth: std::collections::HashMap<i64, usize> = groups
            .iter()
            .enumerate()
            .map(|(depth, state_group)| (*state_group, depth))
            .collect();
        let mut rows: Vec<_> = rows.into_iter().collect();
        rows.sort_unstable_by_key(|row| depth.get(&row.get::<_, i64>(0)).copied());

        let mut state = StateMap::new();
        for row in rows {
            state.entry((row.get(1), row.get(2))).or_insert(row.get(3));
        }
        Ok(state)
    }
}
