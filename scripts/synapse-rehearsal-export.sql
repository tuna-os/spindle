\set ON_ERROR_STOP on

\if :{?server_name}
\else
\echo 'usage: psql -v server_name=example.org -f synapse-rehearsal-export.sql'
\quit
\endif

-- Take every table from one MVCC snapshot. A live homeserver can receive an
-- event between two otherwise-correct COPY commands, leaving current state
-- pointing at an event absent from the exported event set.
-- PostgreSQL does not permit CREATE TEMPORARY TABLE AS in an explicitly
-- read-only transaction. This transaction writes only the session-local room
-- set below; no persistent Synapse table is changed.
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ;

CREATE TEMPORARY TABLE spindle_joined_rooms ON COMMIT DROP AS
SELECT DISTINCT state.room_id
FROM current_state_events AS state
INNER JOIN event_json AS body ON body.event_id = state.event_id
WHERE state.type = 'm.room.member'
  AND right(state.state_key, length(:'server_name') + 1) = ':' || :'server_name'
  AND body.json::jsonb -> 'content' ->> 'membership' = 'join';

-- \copy makes PROGRAM run beside psql, not inside the database pod. Mount a
-- private output directory at /out when running the PostgreSQL client.
\copy (SELECT room.room_id, room.room_version FROM rooms AS room INNER JOIN spindle_joined_rooms AS joined USING (room_id) ORDER BY room.room_id) TO PROGRAM 'zstd -1 -q -c > /out/rooms.tsv.zst'

\copy (SELECT event.event_id, event.type, event.room_id, event.state_key, event.depth, event.stream_ordering, event.outlier::integer, event.rejection_reason FROM events AS event INNER JOIN spindle_joined_rooms AS joined USING (room_id) ORDER BY event.room_id, event.stream_ordering) TO PROGRAM 'zstd -1 -q -c > /out/events.tsv.zst'

\copy (SELECT edge.event_id, edge.prev_event_id, edge.room_id, edge.is_state::integer FROM event_edges AS edge INNER JOIN events AS event ON event.event_id = edge.event_id INNER JOIN spindle_joined_rooms AS joined ON joined.room_id = event.room_id ORDER BY event.room_id, edge.event_id, edge.prev_event_id) TO PROGRAM 'zstd -1 -q -c > /out/edges.tsv.zst'

\copy (SELECT state.event_id, state.room_id, state.type, state.state_key FROM current_state_events AS state INNER JOIN spindle_joined_rooms AS joined USING (room_id) ORDER BY state.room_id, state.type, state.state_key) TO PROGRAM 'zstd -1 -q -c > /out/current-state.tsv.zst'

COMMIT;
