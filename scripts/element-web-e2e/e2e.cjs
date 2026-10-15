// Two people meet in a room, through Element Web, on a Spindle that was
// empty a moment ago. Run it through run.sh, which starts both servers and
// sets the environment this script reads:
//
//   WEB_URL   where Element Web is served
//   OUT_DIR   where screenshots go (one per step on failure, final on success)
//
// Every step is named. When one fails, every open page is photographed into
// OUT_DIR under that step's name, and the error says which step it was, so a
// CI failure reads as "invite: timeout waiting for button" with a picture,
// not as a Playwright stack trace.
const { chromium } = require('playwright');
const path = require('node:path');

const WEB_URL = process.env.WEB_URL;
const OUT_DIR = process.env.OUT_DIR || '.';
const PASSWORD = 'correct horse battery staple';
const ROOM = 'Two-user lifecycle';
const SERVER = process.env.SERVER_NAME || 'e2e.local';
const SLOW = 30_000; // one sync round trip on a cold client can take a while

if (!WEB_URL) {
  console.error('WEB_URL is not set; run this through run.sh');
  process.exit(2);
}

const pages = new Map();
let current = 'start';

async function step(name, fn) {
  current = name;
  console.log(`--- ${name}`);
  try {
    await fn();
  } catch (err) {
    for (const [who, page] of pages) {
      const file = path.join(OUT_DIR, `${name}-${who}.png`);
      await page.screenshot({ path: file, fullPage: true }).catch(() => {});
      console.error(`screenshot: ${file}`);
    }
    err.message = `step "${name}" failed: ${err.message}`;
    throw err;
  }
}

async function open(browser, who) {
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => console.error(`[${who}] page error: ${e.message}`));
  pages.set(who, page);
  return page;
}

async function register(page, name) {
  await page.goto(`${WEB_URL}/#/register`, { waitUntil: 'load' });
  await page.locator('#mx_RegistrationForm_username').fill(name);
  await page.locator('#mx_RegistrationForm_password').fill(PASSWORD);
  await page.locator('#mx_RegistrationForm_passwordConfirm').fill(PASSWORD);
  await page.getByRole('button', { name: 'Register', exact: true }).click();
  await page.waitForURL(/#\/home/, { timeout: SLOW });
}

async function login(page, name) {
  await page.goto(`${WEB_URL}/#/login`, { waitUntil: 'load' });
  await page.getByRole('textbox', { name: /username/i }).fill(name);
  await page.getByRole('textbox', { name: /password/i }).fill(PASSWORD);
  await page.getByRole('button', { name: /sign in/i }).click();
  // A second device of an account with cross-signing keys is asked to
  // verify itself before it reaches the home page. There is no other
  // device here to verify against, so it skips, the way a user can.
  const verify = page.getByRole('heading', { name: /confirm your digital identity/i });
  await Promise.race([
    page.waitForURL(/#\/home/, { timeout: SLOW }),
    verify.waitFor({ timeout: SLOW }),
  ]);
  if (await verify.isVisible()) {
    await page.getByRole('button', { name: 'Skip verification for now' }).click();
    await page.getByRole('button', { name: "I'll verify later" }).click();
  }
  await page.waitForURL(/#\/home/, { timeout: SLOW });
}

// A fresh client stacks tooltips over the room list one after another:
// "verify this device" for a device that skipped verification, then
// "enable desktop notifications". Each is turned down until none is left.
async function dismissTooltips(page) {
  const later = page.getByRole('button', { name: /^(later|dismiss)$/i }).first();
  for (let i = 0; i < 5; i++) {
    try {
      await later.waitFor({ timeout: 3_000 });
    } catch {
      return;
    }
    await later.click();
  }
}

function composer(page) {
  return page.getByRole('textbox', { name: /send an? (unencrypted )?message/i });
}

async function send(page, text) {
  const box = composer(page);
  await box.click();
  await box.fill(text);
  await box.press('Enter');
}

(async () => {
  const browser = await chromium.launch();
  const alice = await open(browser, 'alice');
  let bob = await open(browser, 'bob');
  let roomUrl;

  await step('register', async () => {
    await register(alice, 'alice');
    await register(bob, 'bob');
  });

  // Bob logs in again from a fresh browser context: an empty client store,
  // the way a second device starts, so the flow covers a password login as
  // well as a registration. The first context is closed once the second
  // one is in.
  await step('login', async () => {
    const first = bob;
    bob = await open(browser, 'bob');
    await login(bob, 'bob');
    await first.context().close();
  });

  await step('create-room', async () => {
    // A new account is greeted by a "back up your chats" tooltip that sits
    // over the room list header.
    const dismiss = alice.getByRole('button', { name: 'Dismiss', exact: true });
    if (await dismiss.isVisible().catch(() => false)) await dismiss.click();
    await alice.getByRole('button', { name: 'New room', exact: true }).click();
    const dialog = alice.getByRole('dialog');
    await dialog.getByRole('textbox', { name: /^name$/i }).fill(ROOM);
    // A private room defaults to encrypted; the point here is the plain
    // event path, and E2EE has its own rig (complement-crypto, §4.2).
    const e2ee = dialog.getByRole('switch', { name: /end-to-end encryption/i });
    if (await e2ee.isChecked()) await e2ee.click();
    await dialog.getByRole('button', { name: 'Create room' }).click();
    await alice.waitForURL(/#\/room\//, { timeout: SLOW });
    roomUrl = alice.url();
    console.log(`room: ${roomUrl.slice(roomUrl.indexOf('#'))}`);
    // The room intro, not the "can't see earlier messages" tile: the client
    // reached the creation event, which needs the sync window to say where
    // it begins so the client can page back to it (#331).
    await alice.getByText(/created this room\./).waitFor({ timeout: SLOW });
    await send(alice, 'before bob');
  });

  await step('invite', async () => {
    await alice.getByRole('button', { name: 'Room info' }).first().click();
    // A first visit to the panel is greeted by a "what's new" tooltip that
    // sits over the Invite button.
    const ok = alice.getByRole('button', { name: 'Ok', exact: true });
    if (await ok.isVisible().catch(() => false)) await ok.click();
    await alice.getByText('Invite', { exact: true }).click();
    const dialog = alice.getByRole('dialog');
    const bobId = `@bob:${SERVER}`;
    await dialog.getByRole('textbox').first().fill(bobId);
    await dialog.getByText(bobId, { exact: true }).first().click();
    await dialog.getByRole('button', { name: 'Invite', exact: true }).click();
    // Inviting someone alice has no chat with yet asks her to confirm.
    const confirm = alice.locator('.mx_UnknownIdentityUsersWarningDialog');
    await confirm.getByRole('button', { name: 'Invite', exact: true }).click({ timeout: SLOW });
    await alice.getByRole('dialog').waitFor({ state: 'hidden', timeout: SLOW });
  });

  await step('accept-invite', async () => {
    await dismissTooltips(bob);
    // The invite waits in an "Invites" section of the room list, which
    // starts collapsed.
    const room = bob.getByText(ROOM, { exact: true }).first();
    if (!(await room.isVisible().catch(() => false))) {
      await bob.getByRole('button', { name: /^toggle invites section/i }).click({ timeout: SLOW });
    }
    await room.click({ timeout: SLOW });
    await bob.waitForURL(/#\/room\//, { timeout: SLOW });
    await bob.getByRole('button', { name: /^accept$/i }).click({ timeout: SLOW });
    await composer(bob).waitFor({ timeout: SLOW });
    await alice.getByText(`@bob:${SERVER} joined the room`).waitFor({ timeout: SLOW });
    // History visibility is `shared`, so what alice said before the invite
    // is bob's to read once he is in -- if the client can page back to it
    // (#331).
    await bob.getByText('before bob').waitFor({ timeout: SLOW });
  });

  await step('bob-to-alice', async () => {
    await send(bob, 'hello from bob');
    await alice.getByText('hello from bob').first().waitFor({ timeout: SLOW });
  });

  await step('alice-to-bob', async () => {
    await send(alice, 'hello from alice');
    await bob.getByText('hello from alice').first().waitFor({ timeout: SLOW });
  });

  await step('leave', async () => {
    await bob.getByRole('button', { name: 'Room info' }).first().click();
    await bob.getByText('Leave room', { exact: true }).click({ timeout: SLOW });
    await bob.getByRole('dialog').getByRole('button', { name: 'Leave', exact: true }).click();
    await bob.waitForURL(/#\/home/, { timeout: SLOW });
    await alice.getByText(`@bob:${SERVER} left the room`).waitFor({ timeout: SLOW });
  });

  await alice.screenshot({ path: path.join(OUT_DIR, 'done-alice.png'), fullPage: true });
  await browser.close();
  console.log('ok');
})().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
