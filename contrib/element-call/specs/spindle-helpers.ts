/*
Spindle's own Element Call scenarios (#35, #41): the parts of the gate
upstream's suite has no spec for. run.sh copies this directory into the
checkout as playwright/spindle/, so these import upstream's helpers by the
same relative paths upstream's specs use and drive the same client the same
way; nothing here patches Element Call.
*/

import { execSync } from "node:child_process";

import {
  type Browser,
  type BrowserContext,
  expect,
  type Page,
} from "@playwright/test";

import { SpaHelpers } from "../spa-helpers.ts";

export type Guest = { context: BrowserContext; page: Page; name: string };

/** The SPA's call layout with every participant as a tile of its own. */
export async function useGrid(page: Page): Promise<void> {
  await page.getByRole("radio", { name: "Grid" }).check();
}

/**
 * A guest creates a call from the SPA home page and joins it.
 *
 * Returns the guest and the invite link others join with.
 */
export async function createCallAsGuest(
  browser: Browser,
  name: string,
  callName: string,
): Promise<{ guest: Guest; inviteLink: string }> {
  const context = await browser.newContext({ reducedMotion: "reduce" });
  const page = await context.newPage();
  await page.goto("/");
  await SpaHelpers.createCall(page, name, callName, true);
  await useGrid(page);
  const inviteLink = await SpaHelpers.getCallInviteLink(page);
  // The invite dialog stays open over the call; close it so later
  // assertions see the tiles rather than the modal.
  await page.keyboard.press("Escape");
  return { guest: { context, page, name }, inviteLink };
}

/** A new guest joins a call from its invite link, in the grid layout. */
export async function joinAsGuest(
  browser: Browser,
  inviteLink: string,
  name: string,
): Promise<Guest> {
  const context = await browser.newContext({ reducedMotion: "reduce" });
  const page = await context.newPage();
  await page.goto(inviteLink);
  await page.getByTestId("joincall_displayName").fill(name);
  await expect(page.getByTestId("joincall_joincall")).toBeVisible();
  await page.getByTestId("joincall_joincall").click();
  await page.getByTestId("lobby_joinCall").click();
  await useGrid(page);
  return { context, page, name };
}

/** Rejoin from the lobby after a reload, the way a returning tab does. */
export async function rejoin(guest: Guest): Promise<void> {
  await guest.page.reload();
  await expect(guest.page.getByTestId("lobby_joinCall")).toBeVisible({
    timeout: 20_000,
  });
  await guest.page.getByTestId("lobby_joinCall").click();
  await useGrid(guest.page);
}

/** Leave the call cleanly, with the hang-up button. */
export async function leave(guest: Guest): Promise<void> {
  await guest.page.getByTestId("incall_leave").click();
}

/**
 * Kill a participant rather than let it leave: the network goes first, so
 * the client can neither send its leave nor restart its delayed one, and
 * then the browser context is closed under it. What removes it from
 * everyone else's call is the server firing the delayed leave (MSC4140),
 * which is the point.
 */
export async function kill(guest: Guest): Promise<void> {
  await guest.context.setOffline(true);
  await guest.context.close();
}

/**
 * Every page in `pages` shows exactly `count` participant tiles.
 *
 * `timeout` is generous because a departure that is not a clean leave is
 * only seen once the client's delayed leave fires: Element Call schedules
 * it eighteen seconds out and restarts it every four.
 */
export async function expectTiles(
  pages: Page[],
  count: number,
  timeout = 30_000,
): Promise<void> {
  for (const page of pages) {
    await expect(page.getByTestId("videoTile")).toHaveCount(count, {
      timeout,
    });
  }
}

/**
 * Restart the first homeserver (synapse.m.localhost) the way an operator
 * would -- SIGTERM, then start the same container on the same store -- and
 * wait until it answers again. run.sh supplies the command, because only it
 * knows the compose project the stack is running under.
 */
export async function restartHomeserver(): Promise<void> {
  const command = process.env.SPINDLE_RESTART_HOMESERVER;
  if (!command) {
    throw new Error(
      "SPINDLE_RESTART_HOMESERVER is not set; run this spec through contrib/element-call/run.sh",
    );
  }
  execSync(command, { stdio: "inherit", timeout: 120_000 });
  const deadline = Date.now() + 60_000;
  for (;;) {
    try {
      const response = await fetch(
        "https://synapse.m.localhost/_matrix/client/versions",
      );
      if (response.ok) return;
    } catch {
      // not up yet
    }
    if (Date.now() > deadline) {
      throw new Error("the homeserver did not answer within a minute of its restart");
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
}
