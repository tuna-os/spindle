// Contested forks resolved alike by Spindle and its peer (#563, ADR 0005).
//
// Three servers: hs1 (Spindle), hs2 (Spindle in the homogeneous run,
// Synapse in the state-resolution-interop job), and Complement's own
// federation server, which signs whatever DAG the test asks for. The fake
// server builds a fork no live server would author on purpose -- five
// events, all naming the same parent, contesting the power levels, a
// member's ban against that member's write, and a join against a
// join-rule change -- and sends the branches to hs1 and hs2 in opposite
// orders. Each server resolves the fork its own way; the test passes only
// if both end on the same room state, slot for slot.
//
// scripts/complement.sh copies this directory into the pinned Complement
// checkout as tests/spindle, so it builds against upstream's harness
// unmodified.

package spindle

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/b"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/federation"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/must"
	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/tidwall/gjson"
)

// The room versions of each state-resolution family: the original
// algorithm, v2 under the pre-v11 rules, v2 under v11's, and v2.1.
var stateResVersions = []string{"1", "6", "10", "11", "12"}

func TestContestedForkResolvesLikeThePeer(t *testing.T) {
	deployment := complement.Deploy(t, 2)
	defer deployment.Destroy(t)

	srv := federation.NewServer(t, deployment,
		federation.HandleKeyRequests(),
		federation.HandleMakeSendJoinRequests(),
		federation.HandleTransactionRequests(nil, nil),
		federation.HandleEventRequests(),
		federation.HandleEventAuthRequests(),
	)
	cancel := srv.Listen()
	defer cancel()

	hs1 := deployment.GetFullyQualifiedHomeserverName(t, "hs1")
	hs2 := deployment.GetFullyQualifiedHomeserverName(t, "hs2")

	for _, version := range stateResVersions {
		version := version
		t.Run("v"+version, func(t *testing.T) {
			alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{LocalpartSuffix: "alice" + version})
			bob := deployment.Register(t, "hs2", helpers.RegistrationOpts{LocalpartSuffix: "bob" + version})
			roomID := alice.MustCreateRoom(t, map[string]interface{}{
				"preset":       "public_chat",
				"room_version": version,
			})
			bob.MustJoinRoom(t, roomID, []spec.ServerName{hs1})
			alice.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(bob.UserID, roomID))

			charlie := srv.UserID("charlie" + version)
			frank := srv.UserID("frank" + version)
			eve := srv.UserID("eve" + version)
			hank := srv.UserID("hank" + version)
			room := srv.MustJoinRoom(t, deployment, hs1, roomID, charlie)
			bob.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(charlie, roomID))

			// The other fake users join by plain membership events, sent
			// to both servers: the fake server is in the room now.
			var joins []json.RawMessage
			for _, user := range []string{frank, eve} {
				join := srv.MustCreateEvent(t, room, federation.Event{
					Type:     "m.room.member",
					StateKey: b.Ptr(user),
					Sender:   user,
					Content:  map[string]interface{}{"membership": "join"},
				})
				room.AddEvent(join)
				joins = append(joins, join.JSON())
			}
			sendIgnoringVerdicts(t, srv, deployment, hs1, joins)
			sendIgnoringVerdicts(t, srv, deployment, hs2, joins)
			alice.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(eve, roomID))
			bob.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(eve, roomID))

			// Two admins on the fake server and one moderator.
			users := map[string]interface{}{charlie: 100, frank: 100, eve: 50}
			if version != "12" {
				users[alice.UserID] = 100
			}
			plID := alice.SendEventSynced(t, roomID, b.Event{
				Type:     "m.room.power_levels",
				StateKey: b.Ptr(""),
				Content: map[string]interface{}{
					"users":          users,
					"users_default":  0,
					"events_default": 0,
					"state_default":  50,
					"ban":            50,
					"kick":           50,
					"invite":         0,
					"redact":         50,
				},
			})
			room.WaiterForEvent(plID).Waitf(t, 10*time.Second, "the fake server never received the power levels")
			bob.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(roomID, plID))

			// The fork: every event names the same parent.
			parent, ok := room.GetEventInTimeline(room.ForwardExtremities[0])
			if !ok {
				t.Fatalf("the fake server lost its own extremity")
			}
			prev := room.EventIDsOrReferences([]gomatrixserverlib.PDU{parent})
			fork := func(sender, kind, stateKey string, content map[string]interface{}) gomatrixserverlib.PDU {
				return srv.MustCreateEvent(t, room, federation.Event{
					Type:       kind,
					StateKey:   b.Ptr(stateKey),
					Sender:     sender,
					Content:    content,
					PrevEvents: prev,
				})
			}
			branchA := []gomatrixserverlib.PDU{
				fork(charlie, "m.room.member", eve, map[string]interface{}{"membership": "ban"}),
				fork(charlie, "m.room.join_rules", "", map[string]interface{}{"join_rule": "invite"}),
				fork(charlie, "m.room.power_levels", "", powerLevels(users, eve, 0)),
			}
			branchB := []gomatrixserverlib.PDU{
				fork(eve, "m.room.topic", "", map[string]interface{}{"topic": "eve's, before the ban"}),
				fork(hank, "m.room.member", hank, map[string]interface{}{"membership": "join"}),
				fork(frank, "m.room.power_levels", "", powerLevels(users, hank, 50)),
			}
			for _, event := range append(append([]gomatrixserverlib.PDU{}, branchA...), branchB...) {
				room.Timeline = append(room.Timeline, event)
			}
			sendIgnoringVerdicts(t, srv, deployment, hs1, raw(append(append([]gomatrixserverlib.PDU{}, branchB...), branchA...)))
			sendIgnoringVerdicts(t, srv, deployment, hs2, raw(append(append([]gomatrixserverlib.PDU{}, branchA...), branchB...)))

			// A message from each side names the tips it holds and merges them.
			fromAlice := alice.SendEventSynced(t, roomID, b.Event{
				Type:    "m.room.message",
				Content: map[string]interface{}{"msgtype": "m.text", "body": "merge from hs1"},
			})
			fromBob := bob.SendEventSynced(t, roomID, b.Event{
				Type:    "m.room.message",
				Content: map[string]interface{}{"msgtype": "m.text", "body": "merge from hs2"},
			})
			alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(roomID, fromBob))
			bob.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(roomID, fromAlice))

			// Both servers on one state.
			var ours, theirs map[string]string
			deadline := time.Now().Add(20 * time.Second)
			for {
				ours = roomState(t, alice, roomID)
				theirs = roomState(t, bob, roomID)
				if equal(ours, theirs) || time.Now().After(deadline) {
					break
				}
				time.Sleep(250 * time.Millisecond)
			}
			if !equal(ours, theirs) {
				t.Fatalf("hs1 and hs2 resolved the fork differently:\n%s", diff(ours, theirs))
			}

			// And it is what state resolution decides, whatever the order.
			must.Equal(t, gjsonField(ours, "m.room.member|"+eve), branchA[0].EventID(), "the ban stands")
			if ours["m.room.topic|"] == branchB[0].EventID() {
				t.Fatalf("a write by a user the other branch banned survived resolution")
			}
			if _, joined := ours["m.room.member|"+hank]; joined && ours["m.room.member|"+hank] == branchB[1].EventID() {
				if ours["m.room.join_rules|"] == branchA[1].EventID() {
					t.Fatalf("a join survived a concurrent change to invite-only")
				}
			}
		})
	}
}

func powerLevels(base map[string]interface{}, user string, level int) map[string]interface{} {
	users := map[string]interface{}{}
	for k, v := range base {
		users[k] = v
	}
	users[user] = level
	return map[string]interface{}{
		"users":          users,
		"users_default":  0,
		"events_default": 0,
		"state_default":  50,
		"ban":            50,
		"kick":           50,
		"invite":         0,
		"redact":         50,
	}
}

func raw(events []gomatrixserverlib.PDU) []json.RawMessage {
	out := make([]json.RawMessage, 0, len(events))
	for _, event := range events {
		out = append(out, event.JSON())
	}
	return out
}

// Send PDUs in one transaction and log, not fail on, per-event verdicts: a
// soft-failed or rejected branch event is exactly what this test is about.
func sendIgnoringVerdicts(t *testing.T, srv *federation.Server, deployment federation.FederationDeployment, destination spec.ServerName, pdus []json.RawMessage) {
	t.Helper()
	fedClient := srv.FederationClient(deployment)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := fedClient.SendTransaction(ctx, gomatrixserverlib.Transaction{
		TransactionID:  gomatrixserverlib.TransactionID(fmt.Sprintf("state-res-%d", time.Now().UnixNano())),
		Origin:         srv.ServerName(),
		Destination:    destination,
		OriginServerTS: spec.AsTimestamp(time.Now()),
		PDUs:           pdus,
	})
	must.NotError(t, "SendTransaction", err)
	for eventID, result := range resp.PDUs {
		if result.Error != "" {
			t.Logf("%s: %s refused %s: %s", destination, destination, eventID, result.Error)
		}
	}
}

// The room's state as "type|state_key" -> event ID.
func roomState(t *testing.T, user *client.CSAPI, roomID string) map[string]string {
	t.Helper()
	res := user.MustDo(t, http.MethodGet, []string{"_matrix", "client", "v3", "rooms", roomID, "state"})
	body := client.ParseJSON(t, res)
	out := map[string]string{}
	for _, event := range gjson.ParseBytes(body).Array() {
		out[event.Get("type").Str+"|"+event.Get("state_key").Str] = event.Get("event_id").Str
	}
	return out
}

func equal(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func diff(left, right map[string]string) string {
	keys := map[string]bool{}
	for key := range left {
		keys[key] = true
	}
	for key := range right {
		keys[key] = true
	}
	var sorted []string
	for key := range keys {
		sorted = append(sorted, key)
	}
	sort.Strings(sorted)
	var out strings.Builder
	for _, key := range sorted {
		marker := " "
		if left[key] != right[key] {
			marker = "!"
		}
		fmt.Fprintf(&out, "%s %s: hs1=%s hs2=%s\n", marker, key, left[key], right[key])
	}
	return out.String()
}

func gjsonField(state map[string]string, key string) string {
	return state[key]
}
