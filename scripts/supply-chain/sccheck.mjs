#!/usr/bin/env node
// Supply-chain version checker. Zero dependencies (Node >= 18 built-in fetch). It only READS registry
// metadata and OSV; it never installs or executes any package, so it is safe to run on unvetted sets.
// It fails closed: anything it cannot verify sets a non-zero exit code.
//
// Modes (pick one input):
//   --npm <package-lock.json>         every package@version in an npm v2/v3 lockfile
//   --gomod <dir>                     every module in `go list -m -json all` for that module dir (run on a
//                                     temp copy of go.mod/go.sum with GOTOOLCHAIN=local, so the dir is untouched)
//   --gobin <binary>                  every module compiled into a Go binary (`go version -m`)
//   --pip <requirements.txt>          every pinned name==version line (hashes/markers tolerated)
//   --cargo <Cargo.lock>              every package in a Cargo.lock
//   --gemlock <Gemfile.lock>          every gem in a Gemfile.lock
//   --list <file>                     lines "ecosystem name version" (ecosystem: npm|PyPI|Go|crates.io|RubyGems)
// Options:
//   --baseline <same-kind-input>      only report entries that are NEW or CHANGED vs this baseline
//                                     (a changed tarball URL, integrity, hash or checksum counts as changed)
//   --min-age-days N                  flag versions published less than N days ago (default 7)
//   --ioc <ioc.json>                  [{ecosystem,name,versions:[...]}] extra known-bad versions
//   --out <file.json>                 write full per-entry results as JSON
//   --cache <dir>                     cache registry responses (default: <script dir>/.sccache)
//
// Flags reported per entry: VULN (OSV advisory), MALICIOUS (OSV MAL-* or IOC match), YOUNG (< min age),
// INSTALL_SCRIPT (npm lifecycle scripts), PUBLISHER_CHANGED (npm: different publisher than the
// previous release), PROVENANCE_DROPPED (npm: previous release had provenance, this one does not),
// YANKED (PyPI/crates/gems), DEPRECATED (npm), UNPINNED (pip line without ==version),
// NO_METADATA (registry lookup failed), NO_OSV (OSV lookup failed), NO_DATE (no publish date),
// LATE_FILE (PyPI: a file the lock allows was added > 2 days after the release and inside the min-age window),
// OPTION (pip option line other than --hash/--require-hashes/--only-binary=:all:, e.g. -i, -r, -e, --pre),
// DIRECT_URL (pip "name @ url" that is not https on an allowlisted host with a --hash and a wheel filename),
// NON_REGISTRY (npm resolved not on registry.npmjs.org or no integrity; other Cargo registry; gem not from
// rubygems.org or a PATH gem), GIT_SOURCE (Cargo/Gemfile git dependency: not the registry artifact),
// ARTIFACT_MISMATCH (lock's tarball/integrity/hash/checksum differs from what the registry publishes).
// Exit code: 2 if any MALICIOUS, 1 if any other flag except INSTALL_SCRIPT/DEPRECATED, else 0;
// 64 on a usage error (no mode, an option without a value, a bad --min-age-days).

import { readFileSync, writeFileSync, mkdirSync, existsSync, mkdtempSync, copyFileSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2);
// A missing, empty or option-looking value is a usage error, never a silent default.
const opt = (k, d) => { const i = args.indexOf(k); if (i < 0) return d; const v = args[i + 1]; if (!v || v.startsWith('--')) { console.error(`${k} needs a value`); process.exit(64); } return v; };
const MIN_AGE = Number(opt('--min-age-days', '7'));
if (!Number.isFinite(MIN_AGE) || MIN_AGE < 0) { console.error('--min-age-days must be a number >= 0'); process.exit(64); }
const CACHE = resolve(opt('--cache', join(dirname(fileURLToPath(import.meta.url)), '.sccache')));
mkdirSync(CACHE, { recursive: true });
const NOW = Date.now();
const DAY = 86400000;
const sleep = ms => new Promise(s => setTimeout(s, ms));
const pyNorm = n => n.toLowerCase().replace(/[-_.]+/g, '-');
const UA = { 'user-agent': 'ars0n-sccheck (supply-chain audit)' };

// crates.io allows 1 request per second per client; serialize those calls.
let crateQ = Promise.resolve(), crateLast = 0;
const crateTurn = () => (crateQ = crateQ.then(async () => { const w = crateLast + 1000 - Date.now(); if (w > 0) await sleep(w); crateLast = Date.now(); }));

async function getJSON(url, { cache = true, method = 'GET', body, headers = {} } = {}) {
  const key = join(CACHE, createHash('sha256').update(method + url + (body || '')).digest('hex') + '.json');
  if (cache && existsSync(key)) return JSON.parse(readFileSync(key, 'utf8'));
  for (let attempt = 1; attempt <= 4; attempt++) {
    try {
      if (url.startsWith('https://crates.io/')) await crateTurn();
      const r = await fetch(url, { method, body, headers: { ...headers, ...(body ? { 'content-type': 'application/json' } : {}) } });
      if (r.status === 404) return null;
      if (r.status === 429) { await sleep(5000 * attempt); throw new Error('HTTP 429'); }
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      if (cache) writeFileSync(key, JSON.stringify(j));
      return j;
    } catch (e) {
      if (attempt === 4) { process.stderr.write(`fetch failed ${url}: ${e.message}\n`); return undefined; }
      await sleep(500 * attempt);
    }
  }
}

async function pool(items, n, fn) {
  const out = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); }
  }));
  return out;
}

// ---------- input parsers -> [{eco, name, version, extra}] ----------
// extra.src fingerprints where the artifact comes from (for --baseline); extra.flags are parser-level flags;
// extra.noLookup skips registry metadata (the artifact is not the registry's).
function parseNpmLock(file) {
  const lock = JSON.parse(readFileSync(file, 'utf8'));
  const seen = new Map();
  for (const [path, e] of Object.entries(lock.packages || {})) {
    if (!path || e.link || !e.version || !path.includes('node_modules/')) continue; // root, links, workspace dirs
    const name = e.name || path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
    const bundled = !!e.inBundle; // ships inside its parent's tarball; no resolved/integrity of its own
    const flags = !bundled && (!(e.resolved || '').startsWith('https://registry.npmjs.org/') || !e.integrity) ? ['NON_REGISTRY'] : [];
    const src = bundled ? 'bundled' : `${e.resolved || ''} ${e.integrity || ''}`;
    const k = `${name}@${e.version} ${src}`;
    const prev = seen.get(k);
    const extra = { hasInstallScript: !!e.hasInstallScript, dev: !!e.dev, optional: !!e.optional, bundled, resolved: e.resolved || '', integrity: e.integrity || '', src, flags };
    if (!prev) seen.set(k, { eco: 'npm', name, version: e.version, extra });
    else prev.extra.dev = prev.extra.dev && extra.dev; // prod if ANY copy is prod
  }
  return [...seen.values()];
}
function parseGoListJSON(text) {
  const out = []; let depth = 0, buf = '';
  for (const ch of text) { buf += ch; if (ch === '{') depth++; else if (ch === '}' && --depth === 0) { const m = JSON.parse(buf); buf = ''; if (!m.Main && m.Version) out.push({ eco: 'Go', name: (m.Replace && m.Replace.Path) || m.Path, version: (m.Replace && m.Replace.Version) || m.Version, extra: { indirect: !!m.Indirect } }); } }
  return out;
}
function parseGoMod(dir) {
  // `go list -mod=mod` may rewrite go.sum, so run it on a temp copy. GOTOOLCHAIN=local (unless set
  // explicitly) stops it from downloading another Go toolchain; GOFLAGS/GOWORK are cleared so a
  // vendor/workspace setting cannot change what is listed.
  const tmp = mkdtempSync(join(tmpdir(), 'sccheck-go-'));
  try {
    for (const f of ['go.mod', 'go.sum']) if (existsSync(join(dir, f))) copyFileSync(join(dir, f), join(tmp, f));
    const env = { ...process.env, GOTOOLCHAIN: process.env.GOTOOLCHAIN || 'local', GOFLAGS: '', GOWORK: 'off' };
    return parseGoListJSON(execFileSync('go', ['list', '-mod=mod', '-m', '-json', 'all'], { cwd: tmp, env, encoding: 'utf8', maxBuffer: 64 << 20 }));
  } finally { rmSync(tmp, { recursive: true, force: true }); }
}
function parseGoBin(bin) {
  const text = execFileSync('go', ['version', '-m', bin], { encoding: 'utf8' });
  const out = [];
  for (const line of text.split('\n')) {
    const f = line.trim().split(/\s+/);
    if ((f[0] === 'dep' || f[0] === 'mod') && f[2] && f[2] !== '(devel)') out.push({ eco: 'Go', name: f[1], version: f[2], extra: { kind: f[0] } });
    if (f[0] === '=>' && out.length) { out[out.length - 1].name = f[1]; out[out.length - 1].version = f[2]; }
  }
  return out;
}
// Hosts a pip "name @ url" line may point at: PyPI's file host and the official PyTorch wheel index.
const PIP_URL_HOSTS = new Set(['files.pythonhosted.org', 'download.pytorch.org']);
const PIP_OK_OPTION = /^(--require-hashes|--only-binary(=|\s+):all:)$/;
function parsePip(file) {
  const out = [];
  const text = readFileSync(file, 'utf8').replace(/\\\r?\n/g, ' ');
  for (let line of text.split(/\r?\n/)) {
    line = line.replace(/(^|\s)#.*$/, '').trim(); // pip comments need leading whitespace; keeps url#fragments
    if (!line) continue;
    if (line.startsWith('-')) {
      if (!PIP_OK_OPTION.test(line)) out.push({ eco: 'PyPI', name: line, version: '', extra: { src: line, flags: ['OPTION'], noLookup: true } });
      continue;
    }
    const hashes = [...line.matchAll(/--hash[=\s]+sha256:([0-9a-fA-F]{64})\b/g)].map(m => m[1].toLowerCase());
    const req = line.replace(/\s--hash[=\s]+\S+/g, '').trim();
    const flags = /\s-/.test(req) ? ['OPTION'] : []; // per-requirement options (--config-settings, ...)
    const extra = { hashes, src: [...hashes].sort().join(','), flags };
    const m = req.match(/^([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*===?\s*([^\s;]+)/);
    if (m) { out.push({ eco: 'PyPI', name: pyNorm(m[1]), version: m[3], extra }); continue; }
    const d = req.match(/^([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*@\s*(\S+)/);
    if (d) {
      let u = null; try { u = new URL(d[3]); } catch {}
      const fname = u ? decodeURIComponent(u.pathname.split('/').pop()) : '';
      const w = fname.match(/^([A-Za-z0-9_.]+)-([^-]+)(-\d[^-]*)?-[^-]+-[^-]+-[^-]+\.whl$/);
      const ok = u && u.protocol === 'https:' && PIP_URL_HOSTS.has(u.hostname) && hashes.length && w && pyNorm(w[1]) === pyNorm(d[1]);
      if (!ok) { out.push({ eco: 'PyPI', name: pyNorm(d[1]), version: '', extra: { ...extra, src: req, flags: [...flags, 'DIRECT_URL'], noLookup: true, url: d[3] } }); continue; }
      // The registry and OSV know the public version, so drop a PEP 440 +local label (2.14.1+cpu -> 2.14.1).
      out.push({ eco: 'PyPI', name: pyNorm(d[1]), version: w[2], lookupVersion: w[2].replace(/\+.*$/, ''), extra: { ...extra, src: `${d[3]} ${extra.src}`, url: d[3], urlHost: u.hostname } });
      continue;
    }
    process.stderr.write(`pip line not pinned (unverifiable): ${line}\n`);
    out.push({ eco: 'PyPI', name: line, version: '', extra: { unpinned: true, src: line, flags } });
  }
  return out;
}
function parseList(file) {
  return readFileSync(file, 'utf8').split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith('#')).map(l => { const [eco, name, version] = l.split(/\s+/); return { eco, name, version, extra: {} }; });
}
function parseCargo(file) {
  const out = [];
  for (const blk of readFileSync(file, 'utf8').split('[[package]]').slice(1)) {
    const g = k => (blk.match(new RegExp(`^${k} = "([^"]+)"`, 'm')) || [])[1];
    const source = g('source'), checksum = g('checksum');
    if (!source) continue; // a crate of this workspace (local path)
    const cratesIo = source === 'registry+https://github.com/rust-lang/crates.io-index' || source === 'sparse+https://index.crates.io/';
    const flags = cratesIo ? (checksum ? [] : ['NON_REGISTRY']) : [source.startsWith('git+') ? 'GIT_SOURCE' : 'NON_REGISTRY'];
    // A git or foreign-registry crate is not the crates.io artifact: OSV still runs on its version number.
    out.push({ eco: 'crates.io', name: g('name'), version: g('version'), extra: { source, checksum, src: `${source} ${checksum || ''}`, flags, noLookup: !cratesIo } });
  }
  return out;
}
function parseGemlock(file) {
  const out = []; const sums = new Map();
  let section = '', remote = '', inSpecs = false;
  for (const line of readFileSync(file, 'utf8').split(/\r?\n/)) {
    if (/^\S/.test(line)) { section = line.trim(); remote = ''; inSpecs = false; continue; }
    if (section === 'CHECKSUMS') {
      const c = line.match(/^ {2}(\S+) \(([^)]+)\)(.*)$/);
      if (c) sums.set(`${c[1]} ${c[2]}`, ((c[3] || '').match(/sha256=([0-9a-f]{64})/) || [])[1]);
      continue;
    }
    const r = line.match(/^ {2}remote: (\S+)/);
    if (r) { remote = r[1]; continue; }
    if (/^ {2}specs:/.test(line)) { inSpecs = true; continue; }
    if (/^ {2}\S/.test(line)) { inSpecs = false; continue; }
    const m = inSpecs && line.match(/^ {4}([A-Za-z0-9_.\-]+) \(([^)\s]+)\)/);
    if (!m) continue;
    const dash = m[2].indexOf('-'); // Bundler: the version has no '-'; anything after the first one is the platform
    const version = dash < 0 ? m[2] : m[2].slice(0, dash), platform = dash < 0 ? '' : m[2].slice(dash + 1);
    const flags = section === 'GEM' ? (remote === 'https://rubygems.org/' ? [] : ['NON_REGISTRY']) : [section === 'GIT' ? 'GIT_SOURCE' : 'NON_REGISTRY'];
    out.push({ eco: 'RubyGems', name: m[1], version, extra: { platform, section, remote, spec: `${m[1]} ${m[2]}`, flags, noLookup: section !== 'GEM' } });
  }
  for (const e of out) { e.extra.sha256 = sums.get(e.extra.spec); e.extra.src = `${e.extra.section} ${e.extra.remote} ${e.extra.platform} ${e.extra.sha256 || ''}`; }
  return out;
}
function load(kind, v) {
  if (kind === '--cargo') return parseCargo(v);
  if (kind === '--gemlock') return parseGemlock(v);
  if (kind === '--npm') return parseNpmLock(v);
  if (kind === '--gomod') return parseGoMod(v);
  if (kind === '--gobin') return parseGoBin(v);
  if (kind === '--pip') return parsePip(v);
  if (kind === '--list') return parseList(v);
  throw new Error('no input mode');
}

// ---------- registry metadata ----------
const npmDocs = new Map();
async function npmDoc(name) {
  if (!npmDocs.has(name)) npmDocs.set(name, getJSON(`https://registry.npmjs.org/${name.replace('/', '%2F')}`));
  return npmDocs.get(name);
}
async function metaNpm(e) {
  const doc = await npmDoc(e.name);
  if (!doc || !doc.versions || !doc.versions[e.version]) return { noMeta: true };
  const v = doc.versions[e.version];
  const t = doc.time && doc.time[e.version];
  const ordered = Object.keys(doc.versions).filter(x => doc.time && doc.time[x]).sort((a, b) => Date.parse(doc.time[a]) - Date.parse(doc.time[b]));
  const idx = ordered.indexOf(e.version);
  const prev = idx > 0 ? doc.versions[ordered[idx - 1]] : null;
  const pub = v._npmUser && v._npmUser.name;
  const scripts = v.scripts || {};
  // The lock must point at this exact package's tarball and hash (not, say, another package's tarball).
  let mismatch = false;
  if (e.extra && e.extra.resolved && !e.extra.bundled) {
    const dist = v.dist || {};
    const known = new Set([dist.integrity, dist.shasum && 'sha1-' + Buffer.from(dist.shasum, 'hex').toString('base64')].filter(Boolean));
    mismatch = e.extra.resolved !== dist.tarball || !e.extra.integrity.split(/\s+/).every(h => known.has(h));
  }
  return {
    published: t, publisher: pub, prevVersion: prev && prev.version, prevPublisher: prev && prev._npmUser && prev._npmUser.name,
    provenance: !!(v.dist && v.dist.attestations), prevProvenance: !!(prev && prev.dist && prev.dist.attestations),
    deprecated: v.deprecated || null, mismatch,
    installScripts: ['preinstall', 'install', 'postinstall', 'prepare'].filter(s => scripts[s]).map(s => `${s}: ${String(scripts[s]).slice(0, 120)}`),
    latest: doc['dist-tags'] && doc['dist-tags'].latest,
  };
}
const goEsc = p => p.replace(/[A-Z]/g, c => '!' + c.toLowerCase());
async function metaGo(e) {
  const info = await getJSON(`https://proxy.golang.org/${goEsc(e.name)}/@v/${goEsc(e.version)}.info`);
  if (!info) return { noMeta: true };
  const latest = await getJSON(`https://proxy.golang.org/${goEsc(e.name)}/@latest`, { cache: false });
  return { published: info.Time, latest: latest && latest.Version };
}
async function metaCrate(e) {
  const j = await getJSON(`https://crates.io/api/v1/crates/${e.name}/${e.version}`, { headers: UA });
  if (!j || !j.version) return { noMeta: true };
  const top = await getJSON(`https://crates.io/api/v1/crates/${e.name}`, { headers: UA });
  const v = j.version;
  return { published: v.created_at, yanked: !!v.yanked, publisher: v.published_by && v.published_by.login, latest: top && top.crate && top.crate.max_stable_version, mismatch: !!(e.extra && e.extra.checksum && e.extra.checksum !== v.checksum) };
}
async function metaGem(e) {
  // Without ?platform the API may answer for another platform's gem (e.g. racc's java build).
  const plat = (e.extra && e.extra.platform) || 'ruby';
  const j = await getJSON(`https://rubygems.org/api/v2/rubygems/${e.name}/versions/${e.version}.json?platform=${encodeURIComponent(plat)}`);
  if (!j) return { noMeta: true };
  const top = await getJSON(`https://rubygems.org/api/v1/gems/${e.name}.json`, { cache: false });
  return { published: j.version_created_at || j.created_at, yanked: !!j.yanked, latest: top && top.version, mismatch: j.platform !== plat || !!(e.extra && e.extra.sha256 && j.sha !== e.extra.sha256) };
}
async function metaPyPI(e) {
  const ver = e.lookupVersion || e.version;
  if (!ver) return { noMeta: true, unpinned: true };
  const j = await getJSON(`https://pypi.org/pypi/${e.name}/${ver}/json`);
  if (!j || !j.urls) return { noMeta: true };
  const times = j.urls.map(u => u.upload_time_iso_8601).filter(Boolean).sort();
  let provenance = false;
  const f = j.urls.find(u => u.packagetype === 'bdist_wheel') || j.urls[0];
  if (f) { const p = await getJSON(`https://pypi.org/integrity/${e.name}/${ver}/${f.filename}/provenance`); provenance = !!(p && p.attestation_bundles); }
  const top = await getJSON(`https://pypi.org/pypi/${e.name}/json`);
  const hashes = (e.extra && e.extra.hashes) || [];
  const allowed = u => !hashes.length || hashes.includes(u.digests && u.digests.sha256);
  // A file added to an old release long after it shipped (and recently) is how a hijacked account
  // would slip a payload into a pinned version; only files the lock would accept matter.
  const lateFiles = j.urls.filter(u => times.length && Date.parse(u.upload_time_iso_8601) - Date.parse(times[0]) > 2 * DAY && Date.parse(u.upload_time_iso_8601) > NOW - MIN_AGE * DAY && allowed(u)).map(u => u.filename);
  // Hashes are checked against PyPI's own digests unless the line is a direct URL to another host.
  const digests = new Set(j.urls.map(u => u.digests && u.digests.sha256));
  const checkHashes = !(e.extra && e.extra.urlHost && e.extra.urlHost !== 'files.pythonhosted.org');
  return {
    published: times[0], yanked: j.urls.length > 0 && j.urls.every(u => u.yanked), yankedReason: j.info && j.info.yanked_reason,
    provenance, pypiVulns: (j.vulnerabilities || []).map(v => v.id), latest: top && top.info && top.info.version,
    lateFiles, mismatch: checkHashes && hashes.some(h => !digests.has(h)),
  };
}

// ---------- OSV ----------
const osvVer = e => (e.lookupVersion || e.version).replace(/\+incompatible$/, '');
async function osvBatch(entries) {
  const res = new Map();
  const q = entries.filter(e => e.version).map(e => ({ package: { name: e.name, ecosystem: e.eco }, version: osvVer(e) }));
  for (let i = 0; i < q.length; i += 500) {
    const chunk = q.slice(i, i + 500);
    const r = await getJSON('https://api.osv.dev/v1/querybatch', { cache: false, method: 'POST', body: JSON.stringify({ queries: chunk }) });
    if (!r) { chunk.forEach(c => res.set(`${c.package.ecosystem}|${c.package.name}|${c.version}`, null)); continue; }
    r.results.forEach((x, k) => { const c = chunk[k]; res.set(`${c.package.ecosystem}|${c.package.name}|${c.version}`, (x.vulns || []).map(v => v.id)); });
  }
  return res;
}
const vulnDetail = new Map();
async function osvDetail(id) {
  if (!vulnDetail.has(id)) vulnDetail.set(id, getJSON(`https://api.osv.dev/v1/vulns/${id}`));
  const v = await vulnDetail.get(id);
  if (!v) return { id };
  const sev = (v.database_specific && v.database_specific.severity) || (v.severity && v.severity.map(s => s.score).join(' ')) || '';
  return { id, aliases: v.aliases || [], summary: (v.summary || v.details || '').slice(0, 140), severity: sev, withdrawn: !!v.withdrawn };
}

// ---------- main ----------
const mode = ['--npm', '--gomod', '--gobin', '--pip', '--cargo', '--gemlock', '--list'].find(m => args.includes(m));
if (!mode) { console.error('usage: see header'); process.exit(64); }
let entries = load(mode, opt(mode));
const entryKey = e => `${e.eco}|${e.name}|${e.version}|${(e.extra && e.extra.src) || ''}`;
const base = opt('--baseline');
if (base) {
  const b = new Set(load(mode, base).map(entryKey));
  const before = entries.length;
  entries = entries.filter(e => !b.has(entryKey(e)));
  console.log(`baseline: ${before} entries, ${entries.length} new/changed`);
}
const ioc = opt('--ioc') ? JSON.parse(readFileSync(opt('--ioc'), 'utf8')) : [];
const iocName = (eco, n) => (eco.toLowerCase() === 'pypi' ? pyNorm(n) : n);
const iocHit = e => ioc.some(x => x.ecosystem.toLowerCase() === e.eco.toLowerCase() && iocName(x.ecosystem, x.name) === iocName(e.eco, e.name) && (x.versions.includes(e.version) || x.versions.includes(osvVer(e)) || x.versions.includes('*')));

const osv = await osvBatch(entries);
const metas = await pool(entries, 8, e => (e.extra && e.extra.noLookup ? Promise.resolve({ skipped: true }) : e.eco === 'npm' ? metaNpm(e) : e.eco === 'Go' ? metaGo(e) : e.eco === 'crates.io' ? metaCrate(e) : e.eco === 'RubyGems' ? metaGem(e) : metaPyPI(e)).catch(err => ({ noMeta: true, err: err.message })));

const results = await pool(entries, 16, async (e, k) => {
  const m = metas[k] || { noMeta: true };
  const ids = osv.get(`${e.eco}|${e.name}|${osvVer(e)}`);
  const vulns = ids ? (await Promise.all(ids.map(osvDetail))).filter(v => !v.withdrawn) : [];
  const ageDays = m.published ? (NOW - Date.parse(m.published)) / DAY : null;
  const flags = [...((e.extra && e.extra.flags) || [])];
  if (vulns.some(v => v.id.startsWith('MAL-')) || iocHit(e)) flags.unshift('MALICIOUS');
  if (vulns.some(v => !v.id.startsWith('MAL-'))) flags.push('VULN');
  if (ids === null) flags.push('NO_OSV');
  if (m.noMeta) flags.push('NO_METADATA');
  else if (!m.skipped && !m.published) flags.push('NO_DATE');
  if (ageDays !== null && ageDays < MIN_AGE) flags.push('YOUNG');
  if (e.eco === 'npm') {
    if (e.extra.hasInstallScript || (m.installScripts && m.installScripts.length)) flags.push('INSTALL_SCRIPT');
    if (m.prevPublisher && m.publisher && m.prevPublisher !== m.publisher) flags.push('PUBLISHER_CHANGED');
    if (m.prevProvenance && !m.provenance) flags.push('PROVENANCE_DROPPED');
    if (m.deprecated) flags.push('DEPRECATED');
  }
  if (m.mismatch) flags.push('ARTIFACT_MISMATCH');
  if (m.lateFiles && m.lateFiles.length) flags.push('LATE_FILE');
  if (m.yanked) flags.push('YANKED');
  if (m.unpinned) flags.push('UNPINNED');
  return { ...e, ...m, ageDays: ageDays === null ? null : Math.round(ageDays * 10) / 10, vulns, flags };
});

const out = opt('--out');
if (out) writeFileSync(out, JSON.stringify({ input: opt(mode), mode, minAgeDays: MIN_AGE, checkedAt: new Date(NOW).toISOString(), results }, null, 1));
const count = f => results.filter(r => r.flags.includes(f)).length;
const FL = ['MALICIOUS', 'VULN', 'YOUNG', 'PUBLISHER_CHANGED', 'PROVENANCE_DROPPED', 'YANKED', 'UNPINNED', 'NO_METADATA', 'NO_OSV', 'NO_DATE', 'LATE_FILE', 'OPTION', 'DIRECT_URL', 'NON_REGISTRY', 'GIT_SOURCE', 'ARTIFACT_MISMATCH', 'INSTALL_SCRIPT', 'DEPRECATED'];
const INFO = new Set(['INSTALL_SCRIPT', 'DEPRECATED']); // reported, but they do not fail the run
console.log(`checked ${results.length} entries (${mode} ${opt(mode)}), min-age ${MIN_AGE}d`);
console.log(FL.map(f => `${f}=${count(f)}`).join('  '));
for (const r of results.filter(r => r.flags.some(f => !INFO.has(f))).sort((a, b) => a.name.localeCompare(b.name))) {
  const v = r.vulns.map(x => `${x.id}${x.severity ? '(' + x.severity + ')' : ''}`).join(',');
  console.log(`  ${r.flags.join('|').padEnd(28)} ${r.eco} ${r.name}@${r.version}  pub=${(r.published || '?').slice(0, 10)} age=${r.ageDays ?? '?'}d latest=${r.latest || '?'}${r.publisher ? ' by=' + r.publisher + (r.prevPublisher && r.prevPublisher !== r.publisher ? ' (prev ' + r.prevPublisher + ')' : '') : ''}${v ? '  ' + v : ''}`);
}
const isc = results.filter(r => r.flags.includes('INSTALL_SCRIPT'));
if (isc.length) console.log(`install scripts (${isc.length}): ` + isc.map(r => `${r.name}@${r.version}`).join(', '));
// exitCode (not process.exit) lets open sockets close first; process.exit here aborts on Windows (libuv).
process.exitCode = count('MALICIOUS') ? 2 : results.some(r => r.flags.some(f => !INFO.has(f))) ? 1 : 0;
