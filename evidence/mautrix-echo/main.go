// The M4 appservice evidence harness: mautrix-go's own appservice
// package — the exact library every mautrix bridge is built on —
// speaking to a live Spindle.
//
// What one run proves, end to end and over real TCP:
//   - the bridge's registration works: the bot intent ensures its own
//     account through m.login.application_service registration;
//   - ghosts provision through the intent API (register + profile);
//   - a room created by the bot, with a human invited, carries messages
//     BOTH ways: the human's message reaches the bridge as a pushed
//     transaction (mautrix validates the hs_token on our push), and the
//     ghost's reply reaches the human through the ordinary client API;
//   - typing sent by the human arrives as MSC2409 ephemeral.
//
// The process exits 0 only if every assertion held; the printed
// transcript is the evidence.
package main

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

const (
	asToken  = "as_evidence_token"
	hsToken  = "hs_evidence_token"
	asPort   = 29333
	ghostRaw = "_bridge_echo"
)

func main() {
	hsURL := os.Getenv("SPINDLE_URL")
	serverName := os.Getenv("SPINDLE_NAME")
	if hsURL == "" || serverName == "" {
		fmt.Println("FAIL: SPINDLE_URL and SPINDLE_NAME must be set")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	as := appservice.Create()
	as.Registration = &appservice.Registration{
		ID:              "evidence",
		URL:             fmt.Sprintf("http://127.0.0.1:%d", asPort),
		AppToken:        asToken,
		ServerToken:     hsToken,
		SenderLocalpart: "_bridge_bot",
		// The stable MSC2409 flag: without it mautrix's transaction
		// handler drops the ephemeral array before dispatch.
		EphemeralEvents: true,
	}
	as.Registration.Namespaces.UserIDs.Register(
		regexp.MustCompile(fmt.Sprintf("@_bridge_.*:%s", regexp.QuoteMeta(serverName))), true)
	as.HomeserverDomain = serverName
	if err := as.SetHomeserverURL(hsURL); err != nil {
		fail("homeserver url", err)
	}
	as.Host = appservice.HostConfig{Hostname: "127.0.0.1", Port: asPort}

	received := make(chan *event.Event, 16)
	typing := make(chan *event.Event, 16)
	processor := appservice.NewEventProcessor(as)
	processor.On(event.EventMessage, func(_ context.Context, evt *event.Event) {
		received <- evt
	})
	processor.On(event.EphemeralEventTyping, func(_ context.Context, evt *event.Event) {
		typing <- evt
	})
	go as.Start()
	go processor.Start(ctx)
	defer as.Stop()
	defer processor.Stop()

	// 1. The bridge bot exists because the library asked for it.
	bot := as.BotIntent()
	if err := bot.EnsureRegistered(ctx); err != nil {
		fail("bot registration", err)
	}
	step("bot registered as %s through m.login.application_service", bot.UserID)

	// 2. A ghost, provisioned through the intent API like every mautrix
	// puppet, with a profile to prove it is a real account.
	ghost := as.Intent(id.NewUserID(ghostRaw, serverName))
	if err := ghost.EnsureRegistered(ctx); err != nil {
		fail("ghost registration", err)
	}
	if err := ghost.SetDisplayName(ctx, "Echo Ghost"); err != nil {
		fail("ghost display name", err)
	}
	step("ghost %s provisioned, display name set", ghost.UserID)

	// 3. A human, through the ordinary client API.
	alice, err := mautrix.NewClient(hsURL, "", "")
	if err != nil {
		fail("client", err)
	}
	registered, err := alice.RegisterDummy(ctx, &mautrix.ReqRegister[any]{
		Username: "alice", Password: "evidence-password",
	})
	if err != nil {
		fail("alice registration", err)
	}
	alice.UserID = registered.UserID
	alice.AccessToken = registered.AccessToken
	alice.DeviceID = registered.DeviceID
	step("human %s registered through the ordinary client API", alice.UserID)

	// 4. The bot builds the bridge room and brings everyone in.
	created, err := bot.CreateRoom(ctx, &mautrix.ReqCreateRoom{
		Name:   "bridge room",
		Invite: []id.UserID{alice.UserID, ghost.UserID},
	})
	if err != nil {
		fail("create room", err)
	}
	room := created.RoomID
	if err = ghost.EnsureJoined(ctx, room); err != nil {
		fail("ghost join", err)
	}
	if _, err = alice.JoinRoomByID(ctx, room); err != nil {
		fail("alice join", err)
	}
	step("room %s created by the bot; ghost and human joined", room)

	// 5. Human → bridge: the message must arrive as a pushed
	// transaction, which mautrix only accepts with the right hs_token.
	if _, err = alice.SendText(ctx, room, "ping from the human"); err != nil {
		fail("alice send", err)
	}
	evt := waitFor(received, func(evt *event.Event) bool {
		return evt.RoomID == room && evt.Sender == alice.UserID &&
			evt.Content.AsMessage().Body == "ping from the human"
	})
	if evt == nil {
		fail("transaction push", fmt.Errorf("the human's message never arrived at the bridge"))
	}
	step("bridge received %q from %s via transaction push (hs_token verified by mautrix)",
		evt.Content.AsMessage().Body, evt.Sender)

	// 6. Typing crosses as MSC2409 ephemeral.
	if _, err = alice.UserTyping(ctx, room, true, 30*time.Second); err != nil {
		fail("alice typing", err)
	}
	tevt := waitFor(typing, func(evt *event.Event) bool {
		return evt.RoomID == room
	})
	if tevt == nil {
		fail("ephemeral push", fmt.Errorf("typing never arrived at the bridge"))
	}
	step("bridge received m.typing for %s via MSC2409 ephemeral", tevt.RoomID)

	// 7. Bridge → human: the ghost answers, and the human reads it back
	// through the ordinary client API.
	if _, err = ghost.SendText(ctx, room, "pong from the bridge"); err != nil {
		fail("ghost send", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		messages, err := alice.Messages(ctx, room, "", "", mautrix.DirectionBackward, nil, 20)
		if err != nil {
			fail("alice messages", err)
		}
		found := false
		for _, evt := range messages.Chunk {
			_ = evt.Content.ParseRaw(evt.Type)
			if evt.Sender == ghost.UserID && evt.Content.AsMessage().Body == "pong from the bridge" {
				found = true
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			fail("round trip", fmt.Errorf("the ghost's reply never reached the human"))
		}
		time.Sleep(200 * time.Millisecond)
	}
	step("human read %q from the ghost — the round trip is closed", "pong from the bridge")

	fmt.Println("EVIDENCE: PASS — mautrix-go appservice stack round-trips against Spindle")
}

func step(format string, args ...any) {
	fmt.Printf("  ok: "+format+"\n", args...)
}

func fail(what string, err error) {
	fmt.Printf("FAIL at %s: %v\n", what, err)
	os.Exit(1)
}

func waitFor(events <-chan *event.Event, want func(*event.Event) bool) *event.Event {
	timeout := time.After(15 * time.Second)
	for {
		select {
		case evt := <-events:
			if want(evt) {
				return evt
			}
		case <-timeout:
			return nil
		}
	}
}
