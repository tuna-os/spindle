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

	// Every event reaches both servers: neither refused the other's.
	for _, eventID := range sent {
		alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(roomID, eventID))
		bob.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(roomID, eventID))
	}

	// The same state on both, the hub's own event included.
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
}
