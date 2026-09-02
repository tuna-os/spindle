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
  await page.locator('input[type=submit]').click();
  await page.waitForURL(/#\/home/, { timeout: SLOW });
}

async function login(page, name) {
  await page.goto(`${WEB_URL}/#/login`, { waitUntil: 'load' });
  await page.getByRole('textbox', { name: /username/i }).fill(name);
  await page.getByRole('textbox', { name: /password/i }).fill(PASSWORD);
  await page.getByRole('button', { name: /sign in/i }).click();
  await page.waitForURL(/#\/home/, { timeout: SLOW });
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
    await alice.getByRole('button', { name: 'Add room' }).click();
    await alice.getByRole('menuitem', { name: /new room/i }).click();
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
    await dialog.getByRole('button', { name: bobId }).first().click();
    await dialog.getByRole('button', { name: 'Invite', exact: true }).click();
    await alice.getByRole('dialog').waitFor({ state: 'hidden', timeout: SLOW });
  });

  await step('accept-invite', async () => {
    await bob.getByRole('treeitem', { name: ROOM }).first().click({ timeout: SLOW });
    await bob.waitForURL(/#\/room\//, { timeout: SLOW });
    await bob.getByRole('button', { name: /^accept$/i }).click({ timeout: SLOW });
    await composer(bob).waitFor({ timeout: SLOW });
    await alice.getByText(`@bob:${SERVER} joined the room`).waitFor({ timeout: SLOW });
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
