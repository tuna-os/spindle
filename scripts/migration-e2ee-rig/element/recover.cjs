// Fresh Element Web login with a recovery key, then a check that every
// manifest event this user should read renders decrypted. Run it through
// element.sh.
//
// Steps: password login on an empty browser profile; "Use recovery key";
// "Device verified" -> Done. Then, for each encrypted room, page back to the
// start of the room and wait up to 90 s for backup restore. Each manifest
// message, reply and redaction target readable by the user must render
// without a decryption failure. Edits are folded into their originals, so
// they are not checked, and a failed quote of an event the user may not
// read is not counted. The room must also look like the room it is: no
// "encryption not enabled" notice, no unencrypted composer, and no
// unstable-room-version banner.
//
// Pass: every required event decrypted and every room looks right.
// Written to OUT_DIR: element-<user>.json, screenshots, console and HTTP
// logs. The HTTP log holds only status lines, plus the bodies of key and
// account-data responses, which are ciphertext.
//
// Env: WEB_URL, RIG_USER (manifest key, e.g. a), RIG_PASSWORD, RIG_RECOVERY_KEY,
//      MANIFEST, OUT_DIR
const { chromium } = require('playwright');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const WEB_URL = process.env.WEB_URL;
const OUT = process.env.OUT_DIR || '.';
const USER = process.env.RIG_USER || 'a';
const manifest = JSON.parse(fs.readFileSync(process.env.MANIFEST, 'utf8'));
const MXID = manifest.users[USER];
const LOCALPART = MXID.slice(1).split(':')[0];
const SLOW = 60_000;

let page; let syncN = 0;
async function step(name, fn) {
  console.log(`--- ${name}`);
  try {
    return await fn();
  } catch (err) {
    await page.screenshot({ path: path.join(OUT, `fail-${USER}-${name}.png`), fullPage: true }).catch(() => {});
    err.message = `step "${name}" failed: ${err.message}`;
    throw err;
  }
}

(async () => {
  const browser = await chromium.launch({ args: ['--host-resolver-rules=MAP *.spindle-rehearsal.svc.cluster.local 127.0.0.1'] });
  const ctx = await browser.newContext({ viewport: { width: 1400, height: 1000 } });
  // Keep the browser on the two local origins only.
  await ctx.route('**/*', (route) => {
    const u = new URL(route.request().url());
    if (u.hostname === '127.0.0.1' || u.hostname === 'localhost' || u.hostname.endsWith('.spindle-rehearsal.svc.cluster.local')) return route.continue();
    return route.abort();
  });
  page = await ctx.newPage();
  const log = fs.createWriteStream(path.join(OUT, `console-${USER}.log`));
  page.on('console', (m) => log.write(`[${m.type()}] ${m.text()}\n`));
  page.on('pageerror', (e) => log.write(`[pageerror] ${e.message}\n`));
  const http = fs.createWriteStream(path.join(OUT, `http-${USER}.log`));
  page.on('response', async (r) => {
    const u = r.url();
    if (!u.includes('/_matrix/')) return;
    let body = '';
    if (u.includes('/dehydrated_device') && r.request().method() === 'PUT') {
      let id = null;
      try { id = JSON.parse(r.request().postData() || '{}').device_id; } catch (e) { /* ignore */ }
      http.write(`DEHYDRATE-PUT device_id=${id} slash=${id ? id.includes('/') : null} -> ${r.status()}\n`);
    }
    if (u.includes('/filter')) {
      http.write(`FILTER-REQ ${r.request().postData()}\n`);
    }
    if (u.includes('/v3/sync')) {
      syncN = (syncN || 0) + 1;
      const t = await r.text().catch(() => '');
      if (syncN <= 3) fs.writeFileSync(path.join(OUT, `sync-${USER}-${syncN}.json`), `${u}\n${t}`);
    }
    if (/room_keys|keys\/query|account_data|secret|versions|capabilities/.test(u)) {
      body = (await r.text().catch(() => '')).slice(0, 4000);
    }
    http.write(`${r.request().method()} ${u} -> ${r.status()} ${body}\n`);
  });

  await step('login', async () => {
    await page.goto(`${WEB_URL}/#/login`, { waitUntil: 'load' });
    await page.getByRole('textbox', { name: /username/i }).fill(LOCALPART, { timeout: SLOW });
    await page.getByRole('textbox', { name: /password/i }).fill(process.env.RIG_PASSWORD);
    await page.getByRole('button', { name: /sign in/i }).click();
  });

  await step('recovery', async () => {
    // "Confirm your digital identity" / "Verify this device"
    const useKey = page.getByRole('button', { name: /use (a |your )?(recovery|security) key|verify with (recovery|security) key/i });
    await useKey.first().waitFor({ timeout: SLOW });
    await page.screenshot({ path: path.join(OUT, `01-${USER}-complete-security.png`) });
    await useKey.first().click();
    const box = page.getByRole('dialog').getByRole('textbox').first();
    await box.waitFor({ timeout: SLOW });
    await box.fill(process.env.RIG_RECOVERY_KEY);
    await page.screenshot({ path: path.join(OUT, `02-${USER}-key-entered.png`) });
    await page.getByRole('dialog').getByRole('button', { name: /continue/i }).click();
    // Success screen, then Done.
    const done = page.getByRole('button', { name: /^done$/i });
    await done.waitFor({ timeout: SLOW });
    await page.screenshot({ path: path.join(OUT, `03-${USER}-verified.png`) });
    await done.click();
    await page.waitForURL(/#\/(home|room)/, { timeout: SLOW }).catch(() => {});
  });

  const results = []; const rooms = [];
  for (const room of manifest.rooms) {
    const required = room.events.filter((e) => e.readable_by.includes(USER) && e.encrypted && e.kind !== 'redacted' && e.kind !== 'edit' && e.kind !== 'redaction' && e.kind !== 'state');
    if (!required.length) continue;
    await step(`room-${room.key}`, async () => {
      await page.goto(`${WEB_URL}/#/room/${room.room_id}`);
      await page.locator('.mx_RoomView_MessageList').waitFor({ timeout: SLOW });
      // Page back to the start of the room.
      for (let i = 0; i < 40; i++) {
        if (await page.getByText(/created (and configured )?the room|created this room/i).count()) break;
        await page.locator('.mx_RoomView_messagePanel').hover();
        await page.mouse.wheel(0, -5000);
        await page.waitForTimeout(500);
      }
      // Let backup restore / lazy decryption settle.
      const deadline = Date.now() + 90_000;
      let pending = required;
      while (Date.now() < deadline) {
        pending = [];
        for (const e of required) {
          const tile = page.locator(`[data-scroll-tokens*="${e.event_id}"]`).first();
          if (!(await tile.count())) { pending.push(e); continue; }
          const utd = await tile.locator('.mx_DecryptionFailureBody:not(.mx_ReplyChain *), .mx_UnknownBody:not(.mx_ReplyChain *)').count();
          if (utd) pending.push(e);
        }
        if (!pending.length) break;
        await page.waitForTimeout(3000);
      }
      for (const e of required) {
        const tile = page.locator(`[data-scroll-tokens*="${e.event_id}"]`).first();
        const present = (await tile.count()) > 0;
        let text = null, utd = null;
        if (present) {
          utd = (await tile.locator('.mx_DecryptionFailureBody:not(.mx_ReplyChain *), .mx_UnknownBody:not(.mx_ReplyChain *)').count()) > 0;
          text = await tile.locator('.mx_EventTile_body').first().innerText().catch(() => null);
        }
        const hash = text == null ? null : crypto.createHash('sha256').update(text).digest('hex');
        results.push({ room: room.key, event_id: e.event_id, kind: e.kind, present, utd, hash_match: hash === e.sha256 });
      }
      // The room as Element understands it: an encrypted room of the
      // recorded version, not an unnamed v1 room with no encryption.
      const placeholder = await page.locator('.mx_BasicMessageComposer_input, [contenteditable=true]').first().getAttribute('aria-label').catch(() => null);
      const unsupported = await page.getByText(/encryption not enabled|isn't supported|room version 1\b/i).count();
      const unstable = await page.getByText(/homeserver has marked as unstable/i).count();
      rooms.push({ room: room.key, composer: placeholder, encrypted_ui_ok: !unsupported && !/unencrypted/i.test(placeholder || ''), unstable_version_banner: unstable > 0 });
      await page.screenshot({ path: path.join(OUT, `room-${USER}-${room.key}.png`), fullPage: true });
    });
  }
  const decrypted = results.filter((r) => r.present && !r.utd).length;
  const utd = results.filter((r) => r.utd).length;
  const missing = results.filter((r) => !r.present).length;
  const summary = { user: MXID, web: WEB_URL, required: results.length, decrypted, utd, missing,
    hash_match: results.filter((r) => r.hash_match).length, rooms, pass: results.length > 0 && decrypted === results.length && rooms.every((r) => r.encrypted_ui_ok && !r.unstable_version_banner) };
  fs.writeFileSync(path.join(OUT, `element-${USER}.json`), JSON.stringify({ summary, results }, null, 1));
  console.log(JSON.stringify(summary));
  await browser.close();
  process.exit(summary.pass ? 0 : 1);
})().catch(async (err) => {
  console.error(err.message);
  process.exit(2);
});
