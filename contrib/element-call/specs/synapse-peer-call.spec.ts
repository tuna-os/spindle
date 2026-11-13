/*
A call between a Spindle user and a Synapse user (#795): the rig's
Spindle-to-Synapse variant (SPINDLE_PEER=synapse), with upstream's own
Synapse in the second seat. Each user is in their own Element Web, the room
is created on the caller's server and joined over federation, and the call
goes through Element Call. The caller is on Spindle in one direction and
on Synapse in the other, in both membership modes. federated-call.spec.ts
is the same call between two Spindles; this one is the call a Spindle
user makes to someone on matrix.org.
*/

import { expect, test } from "@playwright/test";

import { widgetTest } from "../fixtures/widget-user.ts";
import {
  HOST1,
  HOST2,
  type RtcMode,
  TestHelpers,
} from "../widget/test-helpers.ts";

const modes: RtcMode[] = ["compat", "2_0"];
// HOST1 is synapse.m.localhost, which is Spindle in this variant, and
// HOST2 is synapse.othersite.m.localhost, which is Synapse.
const directions = [
  { title: "caller on Spindle, callee on Synapse", caller: HOST1, callee: HOST2 },
  { title: "caller on Synapse, callee on Spindle", caller: HOST2, callee: HOST1 },
];

for (const { title, caller: callerHost, callee: calleeHost } of directions) {
  for (const mode of modes) {
    widgetTest(
      `Federated call, ${title} (${mode})`,
      async ({ addUser, browserName }) => {
        test.skip(
          browserName === "firefox",
          "No fake media devices on the firefox CI runner, as upstream's specs note",
        );
        test.setTimeout(240_000);

        const [caller, callee] = await Promise.all([
          addUser("florian", callerHost),
          addUser("timo", calleeHost),
        ]);

        const roomName = `Federated Call ${mode}`;
        await TestHelpers.createRoom(roomName, caller.page, [callee.mxId]);
        await TestHelpers.acceptRoomInvite(roomName, callee.page);

        await TestHelpers.openWidgetSetEmbeddedElementCallRtcModeCloseWidget(
          caller.page,
          mode,
        );
        await TestHelpers.openWidgetSetEmbeddedElementCallRtcModeCloseWidget(
          callee.page,
          mode,
        );

        await TestHelpers.startCallInCurrentRoom(caller.page, false);
        await TestHelpers.joinCallFromLobby(caller.page);
        // The callee joins from the "Group call started" toast, which is the
        // caller's call notification arriving over federation.
        await TestHelpers.joinCallInCurrentRoom(callee.page);

        // Both sides see both participants, with media flowing.
        for (const user of [caller, callee]) {
          const frame = user.page
            .locator('iframe[title="Element Call"]')
            .contentFrame();
          await expect(frame.getByTestId("videoTile")).toHaveCount(2, {
            timeout: 30_000,
          });
          await expect(
            frame.getByText("Waiting for media..."),
          ).not.toBeVisible({ timeout: 30_000 });
          await TestHelpers.expectVisibleVideoCount(frame, 2);
        }

        // The callee leaves; the caller sees it over federation.
        const calleeFrame = callee.page
          .locator('iframe[title="Element Call"]')
          .contentFrame();
        await calleeFrame.getByRole("button", { name: "End call" }).click();
        const callerFrame = caller.page
          .locator('iframe[title="Element Call"]')
          .contentFrame();
        await expect(callerFrame.getByTestId("videoTile")).toHaveCount(1, {
          timeout: 30_000,
        });
      },
    );
  }
}
