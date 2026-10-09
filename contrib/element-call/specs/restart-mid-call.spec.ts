/*
A homeserver restart in the middle of a call (#41). The failure mode
delayed events exist for: a server that forgot its pending leaves on restart
would leave every participant who then crashed in the call forever, and one
that fired them all on start would drop everyone at once. The call has to
survive the restart -- media never touches the homeserver, but membership
does -- and a participant who dies afterwards still has to be removed, by a
delayed leave the server held across the restart.

Run in both of Element Call's membership modes: compatibility (state
events) and Matrix 2.0 (sticky events, MSC4354).
*/

import { expect, test } from "@playwright/test";

import { SpaHelpers } from "../spa-helpers.ts";
import {
  expectTiles,
  kill,
  restartHomeserver,
  type Guest,
  useGrid,
} from "./spindle-helpers.ts";

const modes = [
  ["compat", "state events"],
  ["2_0", "sticky events"],
] as const;

for (const [mode, label] of modes) {
  test(`Call survives a homeserver restart and a later crash still expires (${label})`, async ({
    browser,
    browserName,
  }) => {
    test.skip(
      browserName === "firefox",
      "No fake media devices on the firefox CI runner, as upstream's specs note",
    );
    test.setTimeout(300_000);

    const creatorContext = await browser.newContext({ reducedMotion: "reduce" });
    const creatorPage = await creatorContext.newPage();
    await creatorPage.goto("/");
    await SpaHelpers.createCall(
      creatorPage,
      "Stayer",
      `RestartCall${mode}`,
      true,
      mode,
    );
    await useGrid(creatorPage);
    const inviteLink = await SpaHelpers.getCallInviteLink(creatorPage);
    await creatorPage.keyboard.press("Escape");

    const guestContext = await browser.newContext({ reducedMotion: "reduce" });
    const guestPage = await guestContext.newPage();
    await SpaHelpers.joinCallFromInviteLink(
      guestPage,
      inviteLink,
      "Crasher",
      mode,
    );
    await useGrid(guestPage);
    const guest: Guest = { context: guestContext, page: guestPage, name: "Crasher" };

    await expectTiles([creatorPage, guestPage], 2);

    await restartHomeserver();

    // Longer than Element Call's delayed leave (18 s), so a membership whose
    // delay the server lost or fired early would already have gone.
    await creatorPage.waitForTimeout(30_000);
    await expectTiles([creatorPage, guestPage], 2);
    await expect(
      creatorPage.getByRole("dialog", { name: "Reconnecting…" }),
    ).not.toBeVisible();

    // Now the guest dies. Only a delayed leave the server kept across its
    // restart can remove them.
    await kill(guest);
    await expectTiles([creatorPage], 1, 90_000);
  });
}
