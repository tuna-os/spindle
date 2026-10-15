/*
Ringing that ends because the caller gave up (#41, MSC4075). Upstream's
voice-call-dm spec covers a ring that is answered and one that is declined;
this is the third way a ring ends, and the one where the callee's device has
to work it out on its own: the caller's membership goes, and the ring with
it.
*/

import { expect, test } from "@playwright/test";

import { widgetTest } from "../fixtures/widget-user.ts";
import { TestHelpers } from "../widget/test-helpers.ts";

widgetTest.use({ callType: "dm" });

widgetTest(
  "Caller abandons a ringing DM call and the callee stops ringing",
  async ({ asWidget, browserName }) => {
    test.skip(
      browserName === "firefox",
      "No fake media devices on the firefox CI runner, as upstream's specs note",
    );
    test.slow();

    const { brooks, whistler } = asWidget;

    await TestHelpers.startCallInCurrentRoom(brooks.page, false);
    await expect(
      brooks.page.locator('iframe[title="Element Call"]'),
    ).toBeVisible();
    const brooksFrame = brooks.page
      .locator('iframe[title="Element Call"]')
      .contentFrame();
    await expect(
      brooksFrame
        .getByTestId("videoTile")
        .filter({ has: brooksFrame.getByText("Calling…") }),
    ).toBeVisible();

    // The callee is being rung...
    await expect(whistler.page.getByText("Incoming video call")).toBeVisible();

    // ...and the caller hangs up before anyone answers.
    await brooksFrame.getByRole("button", { name: "End call" }).click();
    await expect(
      brooks.page.locator('iframe[title="Element Call"]'),
    ).not.toBeVisible();

    // The ring stops on the callee's side without them doing anything.
    await expect(whistler.page.getByText("Incoming video call")).not.toBeVisible(
      { timeout: 30_000 },
    );
    await expect(
      whistler.page.locator('iframe[title="Element Call"]'),
    ).not.toBeVisible();
  },
);
