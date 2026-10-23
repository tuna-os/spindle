// MSC3995 hub mode in a room shared with a server that does not speak it
// (#22, SPEC section 12.6).
//
// hs1 is Spindle built with the `hub-mode` feature and `[federation.hub]
// enabled` (the image's SPINDLE_HUB_MODE build argument). hs2 is the same
// image in the homogeneous run -- so its user's events are submitted to
// hs1, the hub -- and Element's Synapse image in the interop run, which
// knows nothing of hub mode. Either way the room must stay an ordinary
// Matrix room: hs2 accepts the hub's `m.room.hub` as ordinary state, both
// servers hold every event from both users, and they agree on the room's
// state, slot for slot.
//
// Skipped when hs1 does not speak hub mode, so the default image's runs of
// this package are unaffected.

package spindle

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/b"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/tidwall/gjson"
)

func TestHubModeRoomStaysOrdinary(t *testing.T) {
	deployment := complement.Deploy(t, 2)
	defer deployment.Destroy(t)

	hs1 := deployment.GetFullyQualifiedHomeserverName(t, "hs1")
	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{LocalpartSuffix: "hubalice"})
	bob := deployment.Register(t, "hs2", helpers.RegistrationOpts{LocalpartSuffix: "hubbob"})

	probe := alice.Do(t, http.MethodGet, []string{
		"_matrix", "federation", "unstable", "org.spindle.msc3995", "capabilities",
	})
	if probe.StatusCode != http.StatusOK ||
		!gjson.ParseBytes(client.ParseJSON(t, probe)).Get(`org\.spindle\.msc3995.hub`).Bool() {
		t.Skip("hs1 does not speak hub mode; build the image with SPINDLE_HUB_MODE=1")
	}

	roomID := alice.MustCreateRoom(t, map[string]interface{}{
		"preset": "public_chat",
		"power_level_content_override": map[string]interface{}{
			"events": map[string]interface{}{"m.room.topic": 0},
		},
	})
	hubEvent := alice.SendEventSynced(t, roomID, b.Event{
		Type:     "m.room.hub",
		StateKey: b.Ptr(""),
		Content:  map[string]interface{}{},
	})
	bob.MustJoinRoom(t, roomID, []spec.ServerName{hs1})
	alice.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(bob.UserID, roomID))

	// Both users send, interleaved, messages and a state event each.
	var sent []string
	for i := 0; i < 4; i++ {
		sent = append(sent, alice.SendEventSynced(t, roomID, b.Event{
			Type:    "m.room.message",
			Content: map[string]interface{}{"msgtype": "m.text", "body": fmt.Sprintf("alice %d", i)},
		}))
		sent = append(sent, bob.SendEventSynced(t, roomID, b.Event{
			Type:    "m.room.message",
			Content: map[string]interface{}{"msgtype": "m.text", "body": fmt.Sprintf("bob %d", i)},
		}))
	}
	sent = append(sent, bob.SendEventSynced(t, roomID, b.Event{
		Type:     "m.room.topic",
		StateKey: b.Ptr(""),
		Content:  map[string]interface{}{"topic": "set from hs2"},
	}))
	final := alice.SendEventSynced(t, roomID, b.Event{
		Type:    "m.room.message",
		Content: map[string]interface{}{"msgtype": "m.text", "body": "last"},
	})
	sent = append(sent, final)

	// The checks are subtests, so scripts/complement-require.py can see
	// each of them pass rather than only the test around them.
	//
	// Every event reaches both servers: neither refused the other's.
	t.Run("EveryEventReachesBothServers", func(t *testing.T) {
		for _, eventID := range sent {
			alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(roomID, eventID))
			bob.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(roomID, eventID))
		}
	})

	// The same state on both, the hub's own event included.
	t.Run("BothServersHoldTheSameState", func(t *testing.T) {
		left, right := roomState(t, alice, roomID), roomState(t, bob, roomID)
		if !equal(left, right) {
			t.Fatalf("hs1 and hs2 disagree on the hub room's state:\n%s", diff(left, right))
		}
		if left["m.room.hub|"] != hubEvent {
			t.Fatalf("m.room.hub is %q on both, not %q", left["m.room.hub|"], hubEvent)
		}
		if left["m.room.topic|"] == "" {
			t.Fatalf("hs2's state event is not in the room's state:\n%s", diff(left, right))
		}
	})
}

// The first listed backup takes over while a legacy server remains in the
// room. In CI hs1 and hs2 are hub-mode Spindles and hs3 is Synapse, so the
// claim and all traffic around it must remain ordinary Matrix state and PDUs.
func TestHubModeFailoverWithSynapse(t *testing.T) {
	deployment := complement.Deploy(t, 3)
	defer deployment.Destroy(t)

	hs1 := deployment.GetFullyQualifiedHomeserverName(t, "hs1")
	hs2 := deployment.GetFullyQualifiedHomeserverName(t, "hs2")
	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{LocalpartSuffix: "failalice"})
	bob := deployment.Register(t, "hs2", helpers.RegistrationOpts{LocalpartSuffix: "failbob"})
	carol := deployment.Register(t, "hs3", helpers.RegistrationOpts{LocalpartSuffix: "failcarol"})

	probe := alice.Do(t, http.MethodGet, []string{
		"_matrix", "federation", "unstable", "org.spindle.msc3995", "capabilities",
	})
	if probe.StatusCode != http.StatusOK ||
		!gjson.ParseBytes(client.ParseJSON(t, probe)).Get(`org\.spindle\.msc3995.hub`).Bool() {
		t.Skip("hs1 does not speak hub mode; build the image with SPINDLE_HUB_MODE=1")
	}

	roomID := alice.MustCreateRoom(t, map[string]interface{}{
		"preset": "public_chat",
		"power_level_content_override": map[string]interface{}{
			"events": map[string]interface{}{"m.room.hub": 0},
		},
	})
	firstHub := alice.SendEventSynced(t, roomID, b.Event{
		Type:     "m.room.hub",
		StateKey: b.Ptr(""),
		Content: map[string]interface{}{
			"org.spindle.backups": []string{string(hs2)},
		},
	})
	bob.MustJoinRoom(t, roomID, []spec.ServerName{hs1})
	alice.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(bob.UserID, roomID))
	carol.MustJoinRoom(t, roomID, []spec.ServerName{hs1})
	alice.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(carol.UserID, roomID))
	bob.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(carol.UserID, roomID))

	// This submission gives the backup a directly returned attestation before
	// the hub disappears, so its failover claim has an attested prefix.
	before := bob.SendEventSynced(t, roomID, b.Event{
		Type:    "m.room.message",
		Content: map[string]interface{}{"msgtype": "m.text", "body": "before failover"},
	})
	alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(roomID, before))

	deployment.PauseServer(t, "hs1")
	during := bob.SendEventSynced(t, roomID, b.Event{
		Type:    "m.room.message",
		Content: map[string]interface{}{"msgtype": "m.text", "body": "hub unavailable"},
	})
	// The first failed submission starts the failover clock. The Complement
	// image uses a 250 ms threshold; the second failure performs the claim.
	time.Sleep(300 * time.Millisecond)
	trigger := bob.SendEventSynced(t, roomID, b.Event{
		Type:    "m.room.message",
		Content: map[string]interface{}{"msgtype": "m.text", "body": "claim failover"},
	})
	claim := roomState(t, bob, roomID)["m.room.hub|"]
	if claim == "" || claim == firstHub {
		t.Fatalf("hs2 did not replace the paused hub: first=%q current=%q", firstHub, claim)
	}
	carol.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(roomID, claim))

	t.Run("SynapseAcceptsTheBackupClaim", func(t *testing.T) {
		for name, user := range map[string]*client.CSAPI{"backup": bob, "synapse": carol} {
			content := user.MustGetStateEventContent(t, roomID, "m.room.hub", "")
			if !content.Get(`org\.spindle\.failover`).Bool() ||
				content.Get(`org\.spindle\.epoch`).Uint() != 1 {
				t.Fatalf("%s sees an invalid failover: %s", name, content.Raw)
			}
		}
		event := bob.MustGetEvent(t, roomID, claim)
		if event.Get("sender").Str != bob.UserID {
			t.Fatalf("backup claim sender is %q, want %q", event.Get("sender").Str, bob.UserID)
		}
	})

	var fromBackup, fromSynapse, merged string
	t.Run("TrafficContinuesWhileTheOldHubIsDown", func(t *testing.T) {
		fromBackup = bob.SendEventSynced(t, roomID, b.Event{
			Type:    "m.room.message",
			Content: map[string]interface{}{"msgtype": "m.text", "body": "from the new hub"},
		})
		fromSynapse = carol.SendEventSynced(t, roomID, b.Event{
			Type:    "m.room.message",
			Content: map[string]interface{}{"msgtype": "m.text", "body": "from Synapse"},
		})
		bob.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(roomID, fromSynapse))
		carol.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(roomID, fromBackup))
		// Authoring after both branches arrive merges any fork made while
		// Synapse and the new hub sent concurrently.
		merged = bob.SendEventSynced(t, roomID, b.Event{
			Type:    "m.room.message",
			Content: map[string]interface{}{"msgtype": "m.text", "body": "merge after failover"},
		})
		carol.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(roomID, merged))
	})

	deployment.UnpauseServer(t, "hs1")
	t.Run("TheOldHubRejoinsWithoutDivergence", func(t *testing.T) {
		for _, eventID := range []string{
			during, trigger, claim, fromBackup, fromSynapse, merged,
		} {
			alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(roomID, eventID))
		}
		left := roomState(t, alice, roomID)
		for name, state := range map[string]map[string]string{
			"backup":  roomState(t, bob, roomID),
			"synapse": roomState(t, carol, roomID),
		} {
			if !equal(left, state) {
				t.Fatalf("old hub and %s disagree after recovery:\n%s", name, diff(left, state))
			}
		}
	})
}
