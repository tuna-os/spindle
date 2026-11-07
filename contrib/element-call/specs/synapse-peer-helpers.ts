/*
Helpers for the Spindle-to-Synapse variant of the rig (#795,
SPINDLE_PEER=synapse): a DM between users on two homeservers, made the way
upstream's widget fixture makes its same-server DM, and the dead peers of
docker-compose-dead-peers.yml.
*/

import { execSync } from "node:child_process";

import { expect, type Page } from "@playwright/test";

import { type UserBaseFixture } from "../fixtures/widget-user.ts";
import { SynapseAdmin } from "../utils/synapse-admin.ts";
import { TestHelpers } from "../widget/test-helpers.ts";

/**
 * How long a ring may take from the caller's "Calling…" tile to the
 * callee's incoming-call toast. Element Call shows the tile once its
 * homeserver has accepted the call notification, so this bounds the trip
 * across federation and the callee's sync, not the caller's start-up.
 * Fifteen seconds is generous for two servers on one host, and a caller
 * who hears nothing back for longer than that tends to hang up.
 */
export const RING_BOUND_MS = 15_000;

/** A user's localpart, which the fixtures also register as the display name. */
export function localpart(mxId: string): string {
  return mxId.slice(1).split(":")[0];
}

/**
 * The caller starts a DM with the callee and sends the first message, and
 * the callee accepts it, as upstream's widget fixture does for its
 * same-server DM. Returns the room ID.
 */
export async function startDm(
  caller: UserBaseFixture,
  callee: UserBaseFixture,
): Promise<string> {
  const page = caller.page;
  await TestHelpers.closeReleaseAnnouncement(page, "Introducing Sections");
  await page
    .getByRole("navigation", { name: "Room list" })
    .getByRole("button", { name: "New conversation" })
    .click();
  await page.getByRole("menuitem", { name: "Start chat" }).click();
  await page.getByRole("textbox", { name: "Search" }).click();
  await page.getByRole("textbox", { name: "Search" }).fill(callee.mxId);
  await page.getByRole("button", { name: "Go" }).click();
  // Element Web asks before a DM with someone it has no profile or shared
  // room for. Whether it does for a user on another server depends on the
  // profile lookup, so accept the question if it comes.
  const newContact = page.getByRole("heading", {
    name: "Start a chat with this new contact?",
  });
  const firstMessage = page.getByText(/Send your first message to invite/);
  await expect(newContact.or(firstMessage)).toBeVisible({ timeout: 15_000 });
  if (await newContact.isVisible()) {
    await page.getByRole("button", { name: "Continue" }).click();
  }
  await expect(firstMessage).toBeVisible();
  await page.locator(".mx_BasicMessageComposer_input > div").click();
  await page.getByRole("textbox", { name: "Send a message…" }).fill("Hello!");
  await page.getByRole("button", { name: "Send message" }).click();
  await expect(page.getByText("This is the beginning of your")).toBeVisible({
    timeout: 15_000,
  });

  // The callee is a new user, so the invite is the only room they have;
  // the entry is named after the inviter, which the inviter's server
  // supplies, and that is not what this test is about.
  await TestHelpers.closeReleaseAnnouncement(
    callee.page,
    "Introducing Sections",
  );
  await TestHelpers.expandAllSections(callee.page);
  await callee.page
    .locator('[aria-label^="Open room "]')
    .first()
    .click({ timeout: 30_000 });
  await callee.page.getByRole("button", { name: "Start chatting" }).click();
  await expect(callee.page.locator(".mx_BasicMessageComposer")).toBeVisible({
    timeout: 15_000,
  });

  // The caller's client sees the callee's join once it has crossed
  // federation; that is the moment the DM is ready to call.
  let roomId: string | undefined;
  await expect
    .poll(
      async () => {
        roomId = await caller.clientHandle.evaluate(
          (client, calleeId) =>
            client
              .getRooms()
              .find((room) => room.getMember(calleeId)?.membership === "join")
              ?.roomId,
          callee.mxId,
        );
        return roomId;
      },
      { timeout: 30_000 },
    )
    .toBeTruthy();
  return roomId as string;
}

/**
 * Start an Element Call video call in the open room. In a two-person room
 * Element Web asks which call to place; in a larger one Element Call is the
 * only choice and the button starts it directly, so pick it only if asked.
 */
export async function startVideoCall(page: Page): Promise<void> {
  await page.getByRole("button", { name: "Video call" }).click();
  const choice = page.getByRole("menuitem", { name: "Element Call" });
  const widget = page.locator('iframe[title="Element Call"]');
  await expect(choice.or(widget)).toBeVisible({ timeout: 10_000 });
  if (await choice.isVisible()) await choice.click();
}

/** The caller's ringing tile: Element Call has sent the ring. */
export async function expectCalling(page: Page): Promise<void> {
  const frame = page.locator('iframe[title="Element Call"]').contentFrame();
  await expect(
    frame
      .getByTestId("videoTile")
      .filter({ has: frame.getByText("Calling…") }),
  ).toBeVisible({ timeout: 30_000 });
}

/** One of the servers in docker-compose-dead-peers.yml. */
export type DeadPeer = {
  /** Its compose service. */
  service: string;
  /** Its server name, port included. */
  name: string;
  /** Its client API, published on the host. */
  url: string;
};

export const DEAD_PEERS: DeadPeer[] = [1, 2, 3].map((n) => ({
  service: `dead-peer-${n}`,
  name: `dead${n}.m.localhost:8448`,
  url: `http://127.0.0.1:2810${n}`,
}));

function compose(args: string): void {
  const command = process.env.SPINDLE_COMPOSE;
  if (!command) {
    throw new Error(
      "SPINDLE_COMPOSE is not set; run this spec through contrib/element-call/run.sh with SPINDLE_PEER=synapse",
    );
  }
  execSync(`${command} ${args}`, { stdio: "inherit", timeout: 60_000 });
}

/** Freeze the dead peers: their names resolve and nothing answers. */
export function silenceDeadPeers(): void {
  compose(`pause ${DEAD_PEERS.map((peer) => peer.service).join(" ")}`);
}

/**
 * Wake the dead peers so the stack is whole again for the next test and
 * for a retry. Docker refuses to unpause a container that is not paused,
 * so each one is tried on its own and the refusal ignored.
 */
export function wakeDeadPeers(): void {
  for (const peer of DEAD_PEERS) {
    try {
      compose(`unpause ${peer.service}`);
    } catch {
      // not paused
    }
  }
}

/**
 * A user on each dead peer joins `roomId`, invited by `inviter`, while the
 * peers are still alive. Returns once the inviter's client sees them all
 * joined, so the inviter's server owes every peer what the room sends next.
 */
export async function joinDeadPeers(
  inviter: UserBaseFixture,
  roomId: string,
  via: string,
): Promise<void> {
  for (const peer of DEAD_PEERS) {
    const username = `ghost_${Date.now()}`;
    const user = await SynapseAdmin.forHomeserver(peer.url).registerUser(
      username,
      "foobarbaz1!",
    );
    await inviter.clientHandle.evaluate(
      (client, [room, userId]) => client.invite(room, userId),
      [roomId, user.user_id] as const,
    );
    const response = await fetch(
      `${peer.url}/_matrix/client/v3/join/${encodeURIComponent(roomId)}?server_name=${encodeURIComponent(via)}`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${user.access_token}`,
          "Content-Type": "application/json",
        },
        body: "{}",
      },
    );
    if (!response.ok) {
      throw new Error(
        `${user.user_id} could not join ${roomId}: ${response.status} ${await response.text()}`,
      );
    }
  }
}

/** How many members `user`'s client sees joined to `roomId`. */
export async function joinedCount(
  user: UserBaseFixture,
  roomId: string,
): Promise<number> {
  return user.clientHandle.evaluate(
    (client, room) => client.getRoom(room)?.getJoinedMemberCount() ?? 0,
    roomId,
  );
}
