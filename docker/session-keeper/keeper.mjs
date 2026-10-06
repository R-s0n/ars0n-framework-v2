// Durable headless session keeper - the browser side.
//
// A long-lived process that reconciles the Go control side over the shared temp_data volume:
//
//   /tmp/session-keeper/desired/<id>.json   the wanted state for one keeper (read)
//   /tmp/session-keeper/harvest/<id>-<ts>.json  a freshly harvested credential (written)
//   /tmp/session-keeper/status/<id>.json    this keeper's health (written)
//
// For each desired keeper it holds a PERSISTENT Chromium profile (userDataDir on the volume, so a
// rotated IdP refresh cookie survives a container restart), seeds the operator's captured cookies on
// first fill, loads the UNMODIFIED SPA, and on a cadence RELOADS it from the keeper process (never
// trusting the page's own setTimeout, which Chromium throttles to ~1/min on a hidden page). The
// reload re-bootstraps the app, which re-mints its bearer via its own refresh call; the keeper
// harvests that bearer from its OWN network (request Authorization header and/or the token-endpoint
// response body) - the network layer, which no page-JS redaction can touch.
//
// SCOPE SAFETY: request interception is a fail-closed egress gate. Only hosts on the desired
// allowlist ({in-scope} UNION {classified auth hosts}) are allowed; everything else is aborted. The
// attribution header is attached only to in-scope app hosts, never to an auth host. The keeper never
// crafts or fuzzes a request; it only lets the unmodified SPA's own calls through.

import { promises as fs } from 'fs';
import path from 'path';
import { pathToFileURL } from 'url';
import puppeteer from 'puppeteer';
import { hostMatches, hostOf, toPuppeteerCookie, accessTokenFromBody, stripBearer, hashInt } from './keeperLib.mjs';

const ROOT = '/tmp/session-keeper';
const DESIRED = path.join(ROOT, 'desired');
const HARVEST = path.join(ROOT, 'harvest');
const STATUS = path.join(ROOT, 'status');
const PROFILES = path.join(ROOT, 'profiles');

const RECONCILE_MS = 10_000;        // how often we read desired/ and reconcile
const MAX_BODY_BYTES = 64 * 1024;   // cap on token-endpoint response bodies we read
const MAX_KEEPERS = 6;              // concurrency ceiling: one Chromium profile each
const NAV_TIMEOUT_MS = 45_000;
const NO_HARVEST_DEADLINE = 2;      // consecutive reloads with no bearer observed -> needs_recapture
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Live keepers, keyed by keeper id.
const live = new Map();

function log(...a) { console.log('[keeper]', ...a); }

async function readJSON(p) {
  try { return JSON.parse(await fs.readFile(p, 'utf8')); } catch { return null; }
}

async function writeStatus(id, st) {
  try {
    const tmp = path.join(STATUS, id + '.json.tmp');
    await fs.writeFile(tmp, JSON.stringify(st, null, 2));
    await fs.rename(tmp, path.join(STATUS, id + '.json'));
  } catch (e) { log('status write failed', id, e.message); }
}

async function writeHarvest(id, h) {
  try {
    const name = `${id}-${Date.now()}.json`;
    const tmp = path.join(HARVEST, name + '.tmp');
    await fs.writeFile(tmp, JSON.stringify(h, null, 2));
    await fs.rename(tmp, path.join(HARVEST, name));
  } catch (e) { log('harvest write failed', id, e.message); }
}

// startKeeper launches a persistent-profile browser for one keeper and wires interception + harvest.
async function startKeeper(desired) {
  const id = desired.keeper_id;
  const state = {
    id,
    desired,
    browser: null,
    page: null,
    lastValue: '',          // last harvested access-token value (dedup)
    lastHarvestAt: '',
    lastReloadAt: '',
    consecutiveNoHarvest: 0,
    consecutiveFailures: 0,
    abortedSample: new Set(),
    status: 'seeding',
    detail: 'launching',
    timer: null,
    cadenceMs: 0,
    sawBearerThisCycle: false, // saw ANY live bearer this reload cycle (not just a changed one)
    closing: false,
  };
  const userDataDir = path.join(PROFILES, id);
  // Seed cookies only on a genuinely FRESH profile: a persisted profile already holds the rotated IdP
  // cookie, and overwriting it with the older captured seed on every restart would defeat the whole
  // point of the persistent profile. Detect emptiness before mkdir creates the dir.
  let freshProfile = true;
  try { freshProfile = (await fs.readdir(userDataDir)).length === 0; } catch { freshProfile = true; }
  await fs.mkdir(userDataDir, { recursive: true });

  try {
    state.browser = await puppeteer.launch({
      headless: 'new',
      userDataDir,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-blink-features=AutomationControlled'],
    });
    const pages = await state.browser.pages();
    state.page = pages[0] || (await state.browser.newPage());

    if (freshProfile && Array.isArray(desired.cookies) && desired.cookies.length) {
      try {
        const jar = desired.cookies.map((c) => toPuppeteerCookie(c, desired.target_url));
        await state.page.setCookie(...jar);
        log(id, 'seeded', jar.length, 'cookies into a fresh profile');
      } catch (e) { log(id, 'cookie seed failed', e.message); }
    }

    // The egress gate + harvest taps must cover EVERY page target, not just the first: a window.open()
    // / target=_blank / OAuth popup would otherwise get a page with interception off and bypass the
    // fail-closed allowlist.
    state.browser.on('targetcreated', async (t) => {
      try { if (t.type && t.type() === 'page') { const p = await t.page(); if (p) await wirePage(state, p); } }
      catch (e) { log(id, 'could not gate a new target', e.message); }
    });
    await wirePage(state, state.page);

    await reload(state);
    scheduleReload(state);
    live.set(id, state); // register only AFTER setup succeeds, so a failed launch frees the slot
    return state;
  } catch (e) {
    try { if (state.browser) await state.browser.close(); } catch { /* ignore */ }
    live.delete(id);
    throw e;
  }
}

// scheduleReload (re)arms the keeper-driven reload timer. The timer lives in the keeper PROCESS, not
// page JS, because a hidden page's setTimeout is throttled to ~1/min. state.cadenceMs lets reconcile
// notice a cadence change and reschedule without a full restart.
function scheduleReload(state) {
  if (state.timer) clearInterval(state.timer);
  const cad = Math.max(120, state.desired.cadence_seconds || 600) * 1000;
  const jitter = Math.floor((hashInt(state.id) % 1000) * (cad / 20000)) * 1000;
  state.cadenceMs = cad;
  state.timer = setInterval(() => { reload(state).catch((e) => log(state.id, 'reload error', e.message)); }, cad + jitter);
}

// wirePage applies the fail-closed egress gate and the harvest taps to ONE page, shared by the first
// page and every new target so no page is ever ungated. It reads state.desired LIVE, so an allowlist
// or header change reconcile applied without a restart takes effect on the next request.
async function wirePage(state, page) {
  await page.setDefaultNavigationTimeout(NAV_TIMEOUT_MS);
  await page.setRequestInterception(true);
  page.on('request', (req) => {
    const d = state.desired;
    const host = hostOf(req.url());
    if (!hostMatches(host, d.allowlist)) {
      state.abortedSample.add(host);
      req.abort('blockedbyclient').catch(() => {});
      return;
    }
    const headers = req.headers();
    const bearer = stripBearer(headers['authorization'] || headers['Authorization'] || '');
    const inScope = hostMatches(host, d.in_scope_hosts);
    if (bearer && inScope) {
      state.sawBearerThisCycle = true; // a live bearer was observed, independent of the write dedup
      maybeHarvest(state, 'bearer_header', bearer, '', host);
    }
    // Attribution header ONLY on in-scope app hosts and NEVER on an auth host. An auth host can be a
    // subdomain of an in-scope domain (login.example.com under example.com), so exclude the auth side
    // explicitly rather than relying on the suffix match alone.
    const extra = {};
    if (inScope && !hostMatches(host, d.auth_hosts || []) && d.program_headers) {
      for (const [k, v] of Object.entries(d.program_headers)) extra[k] = v;
    }
    req.continue(Object.keys(extra).length ? { headers: { ...headers, ...extra } } : {}).catch(() => {});
  });
  page.on('response', async (resp) => {
    try {
      const host = hostOf(resp.url());
      if (!hostMatches(host, state.desired.allowlist)) return;
      const ct = (resp.headers()['content-type'] || '').toLowerCase();
      if (!ct.includes('json')) return;
      const len = parseInt(resp.headers()['content-length'] || '0', 10);
      if (len && len > MAX_BODY_BYTES) return;
      const body = await resp.text().catch(() => '');
      if (!body || body.length > MAX_BODY_BYTES || body.indexOf('access_token') === -1) return;
      const val = accessTokenFromBody(body);
      if (val) {
        state.sawBearerThisCycle = true; // observed a token-endpoint response
        maybeHarvest(state, 'oauth_token_response', val, body, host);
      }
    } catch { /* ignore a response we could not read */ }
  });
}

// maybeHarvest writes a harvest file only when the access-token VALUE changed since the last one, so a
// token-endpoint response and the authenticated request that follows it do not double-store, and a
// reload that re-mints the SAME still-valid token does not churn. Liveness is judged separately from
// this dedup (state.sawBearerThisCycle, set by the handlers), so a healthy session that re-mints an
// unchanged token is NOT mistaken for a dead one.
function maybeHarvest(state, kind, value, body, host) {
  if (!value || value === state.lastValue) return;
  state.lastValue = value;
  state.lastHarvestAt = new Date().toISOString();
  writeHarvest(state.id, {
    keeper_id: state.id,
    name: state.desired.name,
    host,
    observed_at: new Date().toISOString(),
    kind,
    body: kind === 'oauth_token_response' ? body : '',
    value: kind === 'oauth_token_response' ? '' : value,
  });
  log(state.id, 'harvested', kind, 'from', host);
}

async function reload(state) {
  if (state.closing) return;
  state.sawBearerThisCycle = false;
  try {
    await state.page.goto(state.desired.target_url, { waitUntil: 'networkidle2', timeout: NAV_TIMEOUT_MS });
    state.lastReloadAt = new Date().toISOString();
    state.consecutiveFailures = 0;
    // Give the SPA a moment to fire its own refresh after bootstrap, then judge.
    await new Promise((r) => setTimeout(r, 4000));
    const finalHost = hostOf(state.page.url());
    const onAppHost = hostMatches(finalHost, state.desired.in_scope_hosts);
    // Judge liveness on whether a bearer was OBSERVED this cycle, not on whether a NEW one was stored:
    // a still-valid token the app re-presents unchanged is a live session, not a dead one.
    if (!state.sawBearerThisCycle) {
      state.consecutiveNoHarvest += 1;
    } else {
      state.consecutiveNoHarvest = 0;
    }
    if (!onAppHost || state.consecutiveNoHarvest >= NO_HARVEST_DEADLINE) {
      state.status = 'needs_recapture';
      state.detail = onAppHost
        ? `No fresh bearer after ${state.consecutiveNoHarvest} reload(s); the IdP session has likely expired. Re-capture it in the browser.`
        : `A reload landed on ${finalHost}, outside the app - the IdP session has expired. Re-capture it in the browser.`;
    } else {
      state.status = 'live';
      state.detail = 'Session held; bearer is being kept fresh.';
    }
  } catch (e) {
    state.consecutiveFailures += 1;
    state.status = state.consecutiveFailures >= 5 ? 'error' : 'seeding';
    state.detail = 'reload failed: ' + e.message;
  }
  await reportStatus(state);
}

async function reportStatus(state) {
  await writeStatus(state.id, {
    keeper_id: state.id,
    status: state.status,
    detail: state.detail,
    last_reload_at: state.lastReloadAt,
    last_harvest_at: state.lastHarvestAt,
    consecutive_failures: state.consecutiveFailures,
    aborted_sample: Array.from(state.abortedSample).slice(0, 20),
  });
}

async function stopKeeper(id) {
  const state = live.get(id);
  if (!state) return;
  state.closing = true;
  if (state.timer) clearInterval(state.timer);
  try { if (state.browser) await state.browser.close(); } catch { /* ignore */ }
  live.delete(id);
  // Reap the persistent profile AFTER the browser is closed (owner-cleans-up, no cross-container race),
  // so a stop/delete/re-seed does not leave the IdP refresh cookie sitting on the volume. A plain
  // container restart does NOT call stopKeeper, so the profile - and the rotated cookie - survive that.
  try { await fs.rm(path.join(PROFILES, id), { recursive: true, force: true }); } catch { /* ignore */ }
  log(id, 'stopped');
}

// reconcile reads desired/ and makes live match it: start new keepers, restart ones whose seed
// generation changed, and stop ones whose desired file is gone.
async function reconcile() {
  let names = [];
  try { names = (await fs.readdir(DESIRED)).filter((n) => n.endsWith('.json')); } catch { return; }

  const wanted = new Map();
  for (const n of names) {
    const d = await readJSON(path.join(DESIRED, n));
    if (!d || typeof d.keeper_id !== 'string') continue;
    // keeper_id becomes a filesystem path segment (profiles/<id>, status/<id>.json, harvest/<id>-...).
    // Require it to be a bare UUID AND to equal the filename Go wrote, so a crafted id can never be a
    // separator or traversal. Go only ever writes <uuid>.json, so a mismatch means a tampered file.
    if (!UUID_RE.test(d.keeper_id) || d.keeper_id !== path.basename(n, '.json')) {
      log('skipping desired file with an invalid/mismatched keeper_id:', n);
      continue;
    }
    wanted.set(d.keeper_id, d);
  }

  // Stop keepers no longer wanted.
  for (const id of [...live.keys()]) {
    if (!wanted.has(id)) await stopKeeper(id);
  }

  // Start / restart wanted keepers.
  for (const [id, d] of wanted) {
    const state = live.get(id);
    if (!state) {
      if (live.size >= MAX_KEEPERS) {
        await writeStatus(id, { keeper_id: id, status: 'error', detail: `keeper concurrency ceiling (${MAX_KEEPERS}) reached`, consecutive_failures: 0, aborted_sample: [] });
        continue;
      }
      try { await startKeeper(d); }
      catch (e) {
        log(id, 'start failed', e.message);
        await writeStatus(id, { keeper_id: id, status: 'error', detail: 'start failed: ' + e.message, consecutive_failures: 1, aborted_sample: [] });
      }
      continue;
    }
    // A changed seed generation (target or cookies) means re-seed: restart the profile cleanly.
    if (state.desired.generation !== d.generation) {
      log(id, 'generation changed, restarting');
      await stopKeeper(id);
      try { await startKeeper(d); } catch (e) { log(id, 'restart failed', e.message); }
      continue;
    }
    // Same generation: pick up allowlist / header changes live (the handlers read state.desired), and
    // reschedule the reload timer if the cadence changed, all without a restart.
    const newCad = Math.max(120, d.cadence_seconds || 600) * 1000;
    state.desired = d;
    if (newCad !== state.cadenceMs) {
      log(id, 'cadence changed, rescheduling reload');
      scheduleReload(state);
    }
  }
}

async function main() {
  for (const d of [DESIRED, HARVEST, STATUS, PROFILES]) await fs.mkdir(d, { recursive: true });
  log('started; reconciling', DESIRED, 'every', RECONCILE_MS, 'ms');
  // eslint-disable-next-line no-constant-condition
  while (true) {
    try { await reconcile(); } catch (e) { log('reconcile error', e.message); }
    await new Promise((r) => setTimeout(r, RECONCILE_MS));
  }
}

// Only run when invoked directly (lets the egress matcher be unit-tested by importing this file).
// Run main only when invoked directly. The process.argv[1] guard keeps a bare `import()` of this
// module (used by the Dockerfile build check to resolve the import graph) from running the loop or
// throwing on an undefined argv.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((e) => { console.error('[keeper] fatal', e); process.exit(1); });
}
