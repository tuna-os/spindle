/*
A DM call that rings across federation (#795, MSC4075), in the rig's
Spindle-to-Synapse variant (SPINDLE_PEER=synapse). Upstream's
voice-call-dm spec rings a user on the same server; here the caller and
the callee are on different servers, and the ring must reach the callee
within RING_BOUND_MS of the caller's "Calling…" tile.

The last test is the one reilly.asia failed on 2026-11-06. The DM also
holds a user from each of three servers that have stopped answering, so
the caller's server owes transactions to dead destinations while it
rings. Before #794 the outbox sent one destination at a time and waited
out each dead server's 30-second timeout before the next one, and the
ring did not reach matrix.org at all.
*/

import { expect, test } from "@playwright/test";

import { widgetTest } from "../fixtures/widget-user.ts";
import { HOST1, HOST2, TestHelpers } from "../widget/test-helpers.ts";
import {
  DEAD_PEERS,
  expectCalling,
  joinDeadPeers,
  joinedCount,
  RING_BOUND_MS,
  silenceDeadPeers,
  startDm,
  startVideoCall,
  wakeDeadPeers,
} from "./synapse-peer-helpers.ts";

// HOST1 is synapse.m.localhost, which is Spindle in this variant, and
// HOST2 is synapse.othersite.m.localhost, which is Synapse.
const directions = [
  { title: "Spindle rings Synapse", caller: HOST1, callee: HOST2 },
  { title: "Synapse rings Spindle", caller: HOST2, callee: HOST1 },
];

for (const { title, caller: callerHost, callee: calleeHost } of directions) {
  widgetTest(
    `DM call across federation, ${title} in time and connects`,
    async ({ addUser, browserName }) => {
      test.skip(
        browserName === "firefox",
        "No fake media devices on the firefox CI runner, as upstream's specs note",
      );
      test.setTimeout(240_000);

      const [caller, callee] = await Promise.all([
        addUser("brooks", callerHost),
        addUser("whistler", calleeHost),
      ]);
      await startDm(caller, callee);

      await TestHelpers.startCallInCurrentRoom(caller.page, false);
      await expectCalling(caller.page);
      await expect(callee.page.getByText("Incoming video call")).toBeVisible({
        timeout: RING_BOUND_MS,
      });

      // The callee answers from the toast. The caller's ringing tile goes
      // once the callee's membership comes back over federation, and both
      // sides then see both participants.
      await callee.page
        .getByRole("alert")
        .getByRole("button", { name: "Join" })
        .click();
      const callerFrame = caller.page
        .locator('iframe[title="Element Call"]')
        .contentFrame();
      await expect(callerFrame.getByText("Calling…")).not.toBeVisible({
        timeout: 30_000,
      });
      for (const user of [caller, callee]) {
        const frame = user.page
          .locator('iframe[title="Element Call"]')
          .contentFrame();
        await expect(frame.getByTestId("videoTile")).toHaveCount(2, {
          timeout: 30_000,
        });
      }

      // Hanging up on one side ends the call on the other.
      await callerFrame.getByRole("button", { name: "End call" }).click();
      await expect(
        callee.page.locator('iframe[title="Element Call"]'),
      ).not.toBeVisible({ timeout: 30_000 });
    },
  );
}

widgetTest(
  "DM call across federation, Spindle rings Synapse in time with three dead servers in the room",
  async ({ addUser, browserName }) => {
    test.skip(
      browserName === "firefox",
      "No fake media devices on the firefox CI runner, as upstream's specs note",
    );
    test.setTimeout(300_000);
    // A retry, or the test after this one, must find the peers awake.
    wakeDeadPeers();

    try {
      const [caller, callee] = await Promise.all([
        addUser("brooks", HOST1),
        addUser("whistler", HOST2),
      ]);
      const roomId = await startDm(caller, callee);

      // A user from each dead peer joins while the peer is alive. Both
      // homeservers see them joined before the peers go quiet, so
      // everything the room sends from here on is owed to them too.
      await joinDeadPeers(caller, roomId, "synapse.m.localhost");
      const members = 2 + DEAD_PEERS.length;
      await expect
        .poll(() => joinedCount(caller, roomId), { timeout: 30_000 })
        .toBe(members);
      await expect
        .poll(() => joinedCount(callee, roomId), { timeout: 30_000 })
        .toBe(members);
      silenceDeadPeers();

      await startVideoCall(caller.page);
      await expectCalling(caller.page);
      await expect(callee.page.getByText("Incoming video call")).toBeVisible({
        timeout: RING_BOUND_MS,
      });

      // The caller gives up; that also has to cross federation past the
      // dead peers before the callee stops ringing.
      const callerFrame = caller.page
        .locator('iframe[title="Element Call"]')
        .contentFrame();
      await callerFrame.getByRole("button", { name: "End call" }).click();
      await expect(callee.page.getByText("Incoming video call")).not.toBeVisible(
        { timeout: 30_000 },
      );
    } finally {
      wakeDeadPeers();
    }
  },
);
