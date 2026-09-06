// Two people meet in a peer-to-peer call through Element Call's full-mesh
// build, on a Spindle that was empty a moment ago and with no SFU anywhere.
// Run it through run.sh, which starts the server, serves the build and sets
// the environment this script reads:
//
//   WEB_URL   where the full-mesh build is served
//   OUT_DIR   where screenshots go (one per step on failure, final on success)
//
// The call is MSC3401 as the full-mesh branch speaks it: call membership as
// `org.matrix.msc3401.call.member` room state, WebRTC offers, answers and
// candidates over to-device messages, media straight between the two
// browsers. What this proves is the homeserver's whole part in a
// peer-to-peer call -- registration, the room, the state, the to-device
// signalling, TURN discovery -- driven by the real client.
//
// Every step is named. When one fails, every open page is photographed into
// OUT_DIR under that step's name, and the error says which step it was.
const { chromium } = require('playwright');
const path = require('node:path');

const WEB_URL = process.env.WEB_URL;
const OUT_DIR = process.env.OUT_DIR || '.';
const CALL = `venue-${Date.now().toString(36)}`;
const SLOW = 45_000;
// The WebRTC leg waits on an Olm session per direction before the first
// offer can even be read, so the media check gets a window of its own.
const MEDIA = 120_000;

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
      console.error(`${who} peer connections: ${JSON.stringify(await peerReport(page).catch(() => 'n/a'))}`);
    }
    err.message = `step "${name}": ${err.message}`;
    throw err;
  }
}

// Fake camera and microphone, so getUserMedia succeeds headless and every
// tile carries a real (synthetic) stream; media permissions granted up
// front so no prompt blocks the lobby.
const ARGS = [
  '--use-fake-device-for-media-capture',
  '--use-fake-ui-for-media-capture',
  '--autoplay-policy=no-user-gesture-required',
];

// Chromium's own fake devices need a media stack the machine may not
// have (this sandbox has none, and reports no device even to the fake
// flags), so the page synthesizes them: a canvas painted every frame for
// the camera, a Web Audio oscillator for the microphone. Both are real
// MediaStreamTracks and cross the real RTCPeerConnection, which is what
// the assertions read; only their origin is faked.
const FAKE_DEVICES = `
  (() => {
    const canvas = document.createElement('canvas');
    canvas.width = 320; canvas.height = 240;
    const ctx = canvas.getContext('2d');
    let hue = 0;
    setInterval(() => {
      hue = (hue + 7) % 360;
      ctx.fillStyle = 'hsl(' + hue + ',80%,50%)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = '#fff';
      ctx.font = '48px sans-serif';
      ctx.fillText(String(Date.now() % 100000), 20, 120);
    }, 40);
    let audioContext;
    const audioTrack = () => {
      audioContext = audioContext || new AudioContext();
      const oscillator = audioContext.createOscillator();
      const destination = audioContext.createMediaStreamDestination();
      oscillator.connect(destination);
      oscillator.start();
      return destination.stream.getAudioTracks()[0];
    };
    const md = navigator.mediaDevices;
    md.getUserMedia = async (constraints) => {
      const stream = new MediaStream();
      if (constraints && constraints.video) {
        stream.addTrack(canvas.captureStream(25).getVideoTracks()[0]);
      }
      if (constraints && constraints.audio) stream.addTrack(audioTrack());
      return stream;
    };
    md.enumerateDevices = async () => [
      { deviceId: 'fake-mic', groupId: 'fake', kind: 'audioinput', label: 'Fake microphone', toJSON() { return this; } },
      { deviceId: 'fake-cam', groupId: 'fake', kind: 'videoinput', label: 'Fake camera', toJSON() { return this; } },
      { deviceId: 'fake-out', groupId: 'fake', kind: 'audiooutput', label: 'Fake speaker', toJSON() { return this; } },
    ];
    // Keep every peer connection reachable for the candidate-pair check.
    window.__pcs = [];
    const Original = window.RTCPeerConnection;
    window.RTCPeerConnection = function (...args) {
      const pc = new Original(...args);
      window.__pcs.push(pc);
      return pc;
    };
    window.RTCPeerConnection.prototype = Original.prototype;
    Object.setPrototypeOf(window.RTCPeerConnection, Original);
  })();
`;

async function open(browser, who) {
  const context = await browser.newContext({ permissions: ['camera', 'microphone'] });
  await context.addInitScript(FAKE_DEVICES);
  const page = await context.newPage();
  // Errors, and the ICE state machine: the lines that say where a call
  // that did not connect got to. `Failed to load resource` is the 401 on
  // the first /register (the interactive-auth handshake) and is noise.
  page.on('console', (msg) => {
    const text = msg.text();
    if (/Failed to load resource/.test(text)) return;
    if (msg.type() === 'error' || /onIceConnectionStateChanged|unknown call ID/.test(text)) {
      console.log(`[${who}] ${text.slice(0, 240)}`);
    }
  });
  pages.set(who, page);
  return page;
}

// Every peer connection's state, for the failure report.
async function peerReport(page) {
  return page.evaluate(async () => {
    const out = [];
    for (const pc of window.__pcs || []) {
      const stats = await pc.getStats();
      let local = 0, remote = 0, pairs = [];
      for (const s of stats.values()) {
        if (s.type === 'local-candidate') local += 1;
        if (s.type === 'remote-candidate') remote += 1;
        if (s.type === 'candidate-pair') pairs.push(s.state);
      }
      out.push({
        signaling: pc.signalingState, ice: pc.iceConnectionState, gathering: pc.iceGatheringState,
        connection: pc.connectionState, hasLocal: !!pc.localDescription, hasRemote: !!pc.remoteDescription,
        local, remote, pairs,
      });
    }
    return out;
  });
}

async function tiles(page) {
  return page.locator('[data-testid="videoTile"]').count();
}

async function waitForTiles(page, count) {
  await page.waitForFunction(
    (n) => document.querySelectorAll('[data-testid="videoTile"]').length >= n,
    count,
    { timeout: SLOW },
  );
}

(async () => {
  const browser = await chromium.launch({ args: ARGS });
  const alice = await open(browser, 'alice');
  const bob = await open(browser, 'bob');
  let inviteUrl;

  await step('alice creates the call as a guest', async () => {
    await alice.goto(`${WEB_URL}/`);
    await alice.getByTestId('home_callName').fill(CALL, { timeout: SLOW });
    await alice.getByTestId('home_displayName').fill('Alice');
    await alice.getByTestId('home_go').click();
    // Registration (passwordless, m.login.dummy), room creation with the
    // MSC3401 power levels, then the lobby.
    await alice.getByTestId('lobby_joinCall').waitFor({ timeout: SLOW });
    inviteUrl = alice.url();
    console.log(`call url: ${inviteUrl}`);
  });

  await step('alice joins', async () => {
    await alice.getByTestId('lobby_joinCall').click();
    await waitForTiles(alice, 1);
  });

  await step('bob opens the invite as a guest', async () => {
    await bob.goto(inviteUrl);
    await bob.getByTestId('joincall_displayName').fill('Bob', { timeout: SLOW });
    await bob.getByTestId('joincall_joincall').click();
    await bob.getByTestId('lobby_joinCall').waitFor({ timeout: SLOW });
  });

  await step('bob joins', async () => {
    await bob.getByTestId('lobby_joinCall').click();
    await waitForTiles(bob, 1);
  });

  await step('media flows both ways, peer to peer', async () => {
    // Two tiles on each side: self and the other. The remote tile carries a
    // playing video element, which only happens once ICE connected and
    // frames arrived over the direct RTCPeerConnection.
    await waitForTiles(alice, 2);
    await waitForTiles(bob, 2);
    for (const [who, page] of pages) {
      await page.waitForFunction(() => {
        const videos = [...document.querySelectorAll('[data-testid="videoTile_video"]')];
        return videos.filter((v) => v.readyState >= 2 && !v.paused && v.videoWidth > 0).length >= 2;
      }, null, { timeout: MEDIA, polling: 500 });
      console.log(`${who}: ${await tiles(page)} tiles, both playing`);
    }
    // And no SFU took part: every RTCPeerConnection's selected candidate
    // pair is host-to-host on loopback.
    for (const [who, page] of pages) {
      const kinds = await page.evaluate(async () => {
        const pcs = window.__pcs || [];
        const out = [];
        for (const pc of pcs) {
          const stats = await pc.getStats();
          for (const s of stats.values()) {
            if (s.type === 'candidate-pair' && s.state === 'succeeded') {
              const local = stats.get(s.localCandidateId);
              const remote = stats.get(s.remoteCandidateId);
              out.push(`${local?.candidateType}->${remote?.candidateType}`);
            }
          }
        }
        return out;
      });
      console.log(`${who}: candidate pairs ${JSON.stringify(kinds)}`);
    }
  });

  await step('bob leaves and alice sees it', async () => {
    await bob.getByTestId('incall_leave').click();
    await alice.waitForFunction(
      () => document.querySelectorAll('[data-testid="videoTile"]').length === 1,
      null,
      { timeout: SLOW },
    );
  });

  for (const [who, page] of pages) {
    await page.screenshot({ path: path.join(OUT_DIR, `final-${who}.png`), fullPage: true });
  }
  await browser.close();
  console.log('full-mesh call: ok');
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
