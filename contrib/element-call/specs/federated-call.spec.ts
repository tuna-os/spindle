/*
A call across the rig's two Spindles (#41, #269's next subset): a user on
synapse.m.localhost and a user on synapse.othersite.m.localhost, each in their
own Element Web, in a room created on the first server and joined over
federation, calling through Element Call. Upstream's own federated-call test
has the same shape but stops at an interactive page.pause(), so it cannot run
unattended; this is that test without the pause, in both membership modes.
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

for (const mode of modes) {
  widgetTest(
    `Federated call between two Spindles (${mode})`,
    async ({ addUser, browserName }) => {
      test.skip(
        browserName === "firefox",
        "No fake media devices on the firefox CI runner, as upstream's specs note",
      );
      test.setTimeout(240_000);

      const [local, remote] = await Promise.all([
        addUser("florian", HOST1),
        addUser("timo", HOST2),
      ]);

      const roomName = `Federated Call ${mode}`;
      await TestHelpers.createRoom(roomName, local.page, [remote.mxId]);
      await TestHelpers.acceptRoomInvite(roomName, remote.page);

      await TestHelpers.openWidgetSetEmbeddedElementCallRtcModeCloseWidget(
        local.page,
        mode,
      );
      await TestHelpers.openWidgetSetEmbeddedElementCallRtcModeCloseWidget(
        remote.page,
        mode,
      );

      await TestHelpers.startCallInCurrentRoom(local.page, false);
      await TestHelpers.joinCallFromLobby(local.page);
      await TestHelpers.joinCallInCurrentRoom(remote.page);

      // Both sides see both participants, with media flowing.
      for (const user of [local, remote]) {
        const frame = user.page
          .locator('iframe[title="Element Call"]')
          .contentFrame();
        await expect(frame.getByTestId("videoTile")).toHaveCount(2, {
          timeout: 30_000,
        });
        await expect(frame.getByText("Waiting for media...")).not.toBeVisible({
          timeout: 30_000,
        });
        await TestHelpers.expectVisibleVideoCount(frame, 2);
      }

      // The remote participant leaves; the local one sees it over federation.
      const remoteFrame = remote.page
        .locator('iframe[title="Element Call"]')
        .contentFrame();
      await remoteFrame.getByRole("button", { name: "End call" }).click();
      const localFrame = local.page
        .locator('iframe[title="Element Call"]')
        .contentFrame();
      await expect(localFrame.getByTestId("videoTile")).toHaveCount(1, {
        timeout: 30_000,
      });
    },
  );
}
