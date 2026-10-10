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
import { hostMatches, hostOf, toPuppeteerCookie, accessTokenFromBody, stripBearer, hashInt, validateLoginConfig, buildLoginPlan, loginUrlAllowed } from './keeperLib.mjs';

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

// Auto-login (opt-in): when the refresh token itself has expired, log in again with stored creds
// instead of parking. Attempt-capped and spaced by the reload cadence so a wrong password can never
// hammer the real account into a lockout.
const MAX_LOGIN_ATTEMPTS = 2;        // auto-login tries (one per reload cycle) before parking for good
const LOGIN_STEP_TIMEOUT_MS = 15_000;
const LOGIN_SUBMIT_TIMEOUT_MS = 30_000;
const LOGIN_SUCCESS_WAIT_MS = 15_000;
// Best-effort hints that a human is required (CAPTCHA / MFA / OTP). A match PARKS auto-login and never
// retries. Deliberately generic (no app-specific strings) and conservative: a plain wrong-password
// failure is caught by the success probe, not by this.
const CHALLENGE_TEXT_HINTS = ['captcha', 'verify you are human', 'are you a robot',
  'one-time code', 'one time code', 'verification code', 'enter the code we sent',
  'two-factor', 'two factor', 'authenticator app'];

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
    loginAttempts: 0,          // consecutive auto-login tries this container lifetime (lockout cap)
    autoLoginParked: false,    // true once auto-login gave up (challenge or exhausted); stops retrying
    loginPhase: '',            // '' | logging_in | login_ok | login_failed (reported to Go)
    lastLoginAttemptAt: '',    // RFC3339 of the most recent auto-login attempt (edge-triggers Go count)
  };
  const userDataDir = path.join(PROFILES, id);
  // Seed cookies only on a genuinely FRESH profile: a persisted profile already holds the rotated IdP
  // cookie, and overwriting it with the older captured seed on every restart would defeat the whole
  // point of the persistent profile. Detect emptiness before mkdir creates the dir.
  let freshProfile = true;
  try { freshProfile = (await fs.readdir(userDataDir)).length === 0; } catch { freshProfile = true; }
  await fs.mkdir(userDataDir, { recursive: true });

  // A persistent profile left by a KILLED container (any ungraceful stop, e.g. a rebuild) keeps a stale
  // SingletonLock/Cookie/Socket pointing at the dead PID/host, and Chromium then refuses to launch
  // ("profile appears to be in use by another process on another computer"). No Chromium is actually
  // running at keeper startup, so clearing these is safe and is the standard fix; without it the keeper
  // crash-loops every restart until the lock is cleared by hand (observed twice). freshProfile is read
  // above first, so this never changes the seed decision.
  for (const lock of ['SingletonLock', 'SingletonCookie', 'SingletonSocket']) {
    try { await fs.rm(path.join(userDataDir, lock), { force: true }); } catch { /* best effort */ }
  }

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
  state.loginPhase = ''; // cleared each cycle; handleDeadSession sets it only when it drives a login
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
      // The re-mint path has failed (no bearer this cycle, or we landed off the app): the refresh
      // token behind the session has expired. If the operator armed auto-login, log in again with the
      // stored credentials instead of parking; otherwise park needs_recapture exactly as before.
      await handleDeadSession(state, onAppHost, finalHost);
    } else {
      state.loginAttempts = 0;       // a healthy cycle clears the auto-login attempt cap...
      state.autoLoginParked = false; // ...and re-arms auto-login for a future expiry
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
    login_phase: state.loginPhase || '',
    last_login_attempt_at: state.lastLoginAttemptAt || '',
  });
}

// loginCreds reads the stored credentials the Go side conveys in the desired file when auto-login is
// armed. It tolerates either nesting (desired.credentials.* or desired.auto_login.username/password),
// so this side merges with whichever the Go/IPC spec writes. The password is only ever read here and
// in performLogin's page.type; it is never logged.
function loginCreds(d) {
  const cfg = (d && d.auto_login) || {};
  const src = (d && d.credentials) || {};
  return {
    username: String(src.username || cfg.username || ''),
    password: String(src.password || cfg.password || ''),
  };
}

// autoLoginEnabled is the opt-in gate. Off (or absent) means the keeper behaves exactly as before.
function autoLoginEnabled(d) {
  const cfg = (d && d.auto_login) || {};
  return !!(d && d.auto_login) || cfg.enabled === true;
}

// handleDeadSession decides what to do when a reload found no live session and the refresh re-mint
// failed. Three cases, matching the Go reconcile's intent:
//   - auto-login NOT armed            -> park needs_recapture, UNCHANGED from before.
//   - auto-login armed, under the cap -> log in again with the stored credentials (performLogin).
//   - auto-login armed, cap reached   -> park error and stop, so a bad password never locks the account.
async function handleDeadSession(state, onAppHost, finalHost) {
  const d = state.desired;
  const creds = loginCreds(d);
  const eligible = autoLoginEnabled(d) && !!creds.username && !!creds.password && !state.autoLoginParked;

  if (!eligible) {
    // UNCHANGED behaviour: with no armed auto-login, park needs_recapture exactly as the keeper always has.
    state.status = 'needs_recapture';
    state.detail = onAppHost
      ? `No fresh bearer after ${state.consecutiveNoHarvest} reload(s); the IdP session has likely expired. Re-capture it in the browser.`
      : `A reload landed on ${finalHost}, outside the app - the IdP session has expired. Re-capture it in the browser.`;
    return;
  }

  // ONE attempt per dead-session cycle. Cycles are the reload cadence apart (>= 120s), so even a
  // failing login is never hammered. After MAX_LOGIN_ATTEMPTS we park for good (lockout safety).
  state.loginAttempts = (state.loginAttempts || 0) + 1;
  state.loginPhase = 'logging_in';
  state.lastLoginAttemptAt = new Date().toISOString();
  state.status = 'logging_in';
  state.detail = 'The IdP session expired; logging in again with the stored credentials.';
  await reportStatus(state);

  let res;
  try {
    res = await performLogin(state, state.page);
  } catch (e) {
    res = { ok: false, reason: 'auto-login error: ' + e.message };
  }
  log(state.id, 'auto-login result:', res.ok ? 'ok' : res.reason); // reason is value-free by construction

  if (res.ok) {
    state.loginPhase = 'login_ok';
    state.loginAttempts = 0;
    state.autoLoginParked = false;
    await reseedFromBrowser(state);                 // refresh the Go-side seed to the account just logged into
    await new Promise((r) => setTimeout(r, 2000));  // let the SPA bootstrap and mint its bearer
    if (state.sawBearerThisCycle) {
      state.status = 'live';
      state.detail = 'Logged in again with the stored credentials; the session is restored.';
    } else {
      state.status = 'seeding';
      state.detail = 'Logged in; waiting for the app to mint its bearer on the next reload.';
    }
    return;
  }

  state.loginPhase = 'login_failed';

  if (res.challenge) {
    // A human is required (CAPTCHA / MFA / OTP). Park and STOP auto-login for this container lifetime:
    // a challenge is never retried blindly.
    state.autoLoginParked = true;
    state.status = 'needs_recapture';
    state.detail = 'Auto-login needs a human: a CAPTCHA or MFA/OTP prompt appeared. Re-capture the session in the browser.';
    return;
  }

  if (state.loginAttempts >= MAX_LOGIN_ATTEMPTS) {
    // Give up for good so a wrong password or a changed form can never lock the real account out.
    state.autoLoginParked = true;
    state.status = 'error';
    state.detail = 'Auto-login failed (bad credentials or a changed login form); stopped to avoid locking the account. Fix the credentials or the login steps, then re-enable the keeper.';
  } else {
    state.status = 'seeding';
    state.detail = `Auto-login attempt ${state.loginAttempts} did not succeed; will try once more on the next reload cycle.`;
  }
}

// performLogin drives the operator-configured login FORM in the headless browser when the keeper has
// no live session and cannot re-mint from the refresh token. It is sequence-driven and app-agnostic:
// the shape it reads is desired.auto_login = { login_url, steps:[{selector, action in
// type|click|waitFor|submit, value_ref in username|password|literal, literal?, timeout_ms?}],
// success:{kind in url|selector|cookie|bearer, value?, timeout_ms?} } with credentials from
// loginCreds(desired). It navigates to the allowlisted login_url, runs the fill steps (typing the
// stored username/password), submits, and waits for the success probe. The password is passed ONLY to
// page.type and is never logged, written to a status or harvest file, or put in an error message.
// Returns { ok, reason, challenge } - challenge true means a CAPTCHA/MFA was seen, a PARK-not-retry
// condition. The caller caps attempts; this function itself never loops.
async function performLogin(state, page) {
  const d = state.desired;
  const cfg = (d && d.auto_login) || {};
  const creds = loginCreds(d);

  // Fail-closed egress: the login page must be on the SAME allowlist as every other keeper request.
  if (!loginUrlAllowed(cfg, d.allowlist)) {
    return { ok: false, reason: 'the configured login_url host is not on the egress allowlist' };
  }
  const v = validateLoginConfig(cfg);
  if (!v.ok) return { ok: false, reason: 'login config is incomplete: ' + v.errors.join('; ') };
  if (!creds.username || !creds.password) return { ok: false, reason: 'no stored credentials to log in with' };

  const plan = buildLoginPlan(cfg, creds); // values resolved here, never logged
  log(state.id, 'auto-login: driving the configured login form,', plan.length, 'steps');

  await page.goto(cfg.login_url, { waitUntil: 'networkidle2', timeout: NAV_TIMEOUT_MS });
  if (await loginChallengePresent(page)) {
    return { ok: false, reason: 'a CAPTCHA or MFA/OTP prompt is on the login page', challenge: true };
  }

  for (const instr of plan) {
    try {
      if (instr.op === 'type') {
        await page.waitForSelector(instr.selector, { timeout: LOGIN_STEP_TIMEOUT_MS });
        await page.type(instr.selector, instr.value, { delay: 15 }); // instr.value never logged
      } else if (instr.op === 'click') {
        await page.waitForSelector(instr.selector, { timeout: LOGIN_STEP_TIMEOUT_MS });
        await page.click(instr.selector);
      } else if (instr.op === 'waitFor') {
        await page.waitForSelector(instr.selector, { timeout: instr.timeout_ms || LOGIN_STEP_TIMEOUT_MS });
      } else if (instr.op === 'submit') {
        // Submit plus the navigation it may trigger, raced so a SPA/XHR login that does NOT navigate
        // does not hang until the nav timeout.
        const nav = page
          .waitForNavigation({ waitUntil: 'networkidle2', timeout: LOGIN_SUBMIT_TIMEOUT_MS })
          .catch(() => {});
        if (instr.selector) await page.click(instr.selector);
        else await page.keyboard.press('Enter');
        await nav;
      }
    } catch (e) {
      // instr.label names the field (e.g. "type password into #pass"), never the typed value.
      return { ok: false, reason: `login ${instr.label} failed: ${e.message}` };
    }
  }

  if (await loginChallengePresent(page)) {
    return { ok: false, reason: 'a CAPTCHA or MFA/OTP challenge appeared after submit', challenge: true };
  }

  const ok = await loginSucceeded(state, page, cfg.success || {});
  return ok
    ? { ok: true }
    : { ok: false, reason: 'the login success check did not pass (wrong credentials or a changed form)' };
}

// loginChallengePresent is a best-effort detector for a human-required obstacle on the current page: a
// CAPTCHA widget or an MFA/OTP prompt. A match makes performLogin PARK, never retry, so a step-up
// challenge can never be hammered. Deliberately conservative - false negatives are fine, because a
// wrong-credentials failure is caught by the success probe instead.
async function loginChallengePresent(page) {
  try {
    return await page.evaluate((hints) => {
      try {
        if (document.querySelector(
          'iframe[src*="recaptcha"], iframe[src*="hcaptcha"], iframe[title*="captcha" i], .g-recaptcha, [data-sitekey], [class*="captcha" i]'
        )) return true;
        const text = ((document.body && document.body.innerText) || '').toLowerCase();
        return hints.some((h) => text.includes(h));
      } catch (e) { return false; }
    }, CHALLENGE_TEXT_HINTS);
  } catch { return false; }
}

// loginSucceeded evaluates the operator-configured success probe. A bearer probe is judged from the
// keeper's OWN network (state.sawBearerThisCycle, set by wirePage) - the same signal a normal reload
// trusts; url/cookie are polled, selector waits. It never crafts a request; it only observes.
async function loginSucceeded(state, page, probe) {
  const kind = probe && probe.kind;
  const val = String((probe && probe.value) || '');
  const timeout = (probe && Number.isFinite(probe.timeout_ms) && probe.timeout_ms > 0)
    ? probe.timeout_ms : LOGIN_SUCCESS_WAIT_MS;
  try {
    if (kind === 'selector') { await page.waitForSelector(val, { timeout }); return true; }
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      if (kind === 'bearer' && state.sawBearerThisCycle) return true;
      if (kind === 'url' && (page.url() || '').includes(val)) return true;
      if (kind === 'cookie') {
        const jar = await page.cookies().catch(() => []);
        if (jar.some((c) => c.name === val)) return true;
      }
      await new Promise((r) => setTimeout(r, 400));
    }
    if (kind === 'bearer') return !!state.sawBearerThisCycle;
    if (kind === 'url') return (page.url() || '').includes(val);
    return false;
  } catch { return false; }
}

// reseedFromBrowser writes the post-login cookie set back as a cookie harvest so the Go-side seed
// (session_tokens) reflects the account the keeper just logged into. The persistent profile already
// holds these cookies for the container's own restarts; this keeps the DURABLE seed current for the
// case where the profile is ever re-created. Only cookies on allowlisted hosts are emitted (fail
// closed), and a password is never a cookie, so nothing beyond already-stored session material leaves.
async function reseedFromBrowser(state) {
  try {
    const d = state.desired;
    const urls = [d.target_url, (d.auto_login && d.auto_login.login_url)].filter(Boolean);
    const cookies = await state.page.cookies(...urls).catch(() => []);
    const byHost = new Map();
    for (const c of cookies) {
      const host = String(c.domain || '').replace(/^\./, '').toLowerCase();
      if (!hostMatches(host, d.allowlist)) continue; // never harvest an off-scope cookie
      const arr = byHost.get(host) || [];
      arr.push(`${c.name}=${c.value}`);
      byHost.set(host, arr);
    }
    for (const [host, pairs] of byHost) {
      if (!pairs.length) continue;
      writeHarvest(state.id, {
        keeper_id: state.id,
        name: d.name,
        host,
        observed_at: new Date().toISOString(),
        kind: 'cookie',
        body: '',
        value: pairs.join('; '),
      });
    }
  } catch (e) { log(state.id, 'post-login cookie reseed skipped', e.message); }
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
