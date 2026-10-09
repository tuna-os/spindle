/*
Five-party churn (#41, #40): participants joining, leaving, rejoining and
dying throughout one call, with every remaining participant's view checked
after each step. Upstream's suite stops at three participants and never
removes one uncleanly; this is the state-churn and to-device burst #40 names,
driven by the real client.
*/

import { test } from "@playwright/test";

import {
  createCallAsGuest,
  expectTiles,
  joinAsGuest,
  kill,
  leave,
  rejoin,
} from "./spindle-helpers.ts";

test("Five-party call with participants joining, leaving, rejoining and dying throughout", async ({
  browser,
  browserName,
}) => {
  test.skip(
    browserName === "firefox",
    "No fake media devices on the firefox CI runner, as upstream's specs note",
  );
  test.setTimeout(420_000);

  const { guest: creator, inviteLink } = await createCallAsGuest(
    browser,
    "Party0",
    "ChurnCall",
  );
  const guests = [creator];

  // Join one at a time, and everyone already there sees each arrival.
  for (let n = 1; n < 5; n++) {
    guests.push(await joinAsGuest(browser, inviteLink, `Party${n}`));
    await expectTiles(
      guests.map((guest) => guest.page),
      guests.length,
    );
  }

  // A clean leave: gone for everyone at once, no expiry involved.
  const [p0, p1, p2, p3, p4] = guests;
  await leave(p2);
  await expectTiles([p0.page, p1.page, p3.page, p4.page], 4);

  // The same tab comes back (a new membership for the same device).
  await rejoin(p2);
  await expectTiles([p0.page, p1.page, p2.page, p3.page, p4.page], 5);

  // Two arrivals and a departure at the same moment.
  const [p5, p6] = await Promise.all([
    joinAsGuest(browser, inviteLink, "Party5"),
    joinAsGuest(browser, inviteLink, "Party6"),
    leave(p1),
  ]);
  await expectTiles([p0.page, p2.page, p3.page, p4.page, p5.page, p6.page], 6);

  // A participant dies: no leave is sent, and the server's delayed leave
  // (MSC4140) is the only thing that can take them out of everyone's call.
  await kill(p4);
  await expectTiles([p0.page, p2.page, p3.page, p5.page, p6.page], 5, 90_000);

  // And the room settles: a late joiner sees exactly who is left, with no
  // ghost of the dead participant or of the ones who left.
  const late = await joinAsGuest(browser, inviteLink, "Party7");
  await expectTiles(
    [p0.page, p2.page, p3.page, p5.page, p6.page, late.page],
    6,
  );
});
