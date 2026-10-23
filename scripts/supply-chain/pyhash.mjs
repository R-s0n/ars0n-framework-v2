#!/usr/bin/env node
// Turn a resolved Python dependency set into a hash-locked requirements file for
// `pip install --no-deps --require-hashes --only-binary=:all: -r <lock>`. Zero dependencies; reads PyPI JSON only.
//
//   node pyhash.mjs --uploaded-prior-to <YYYY-MM-DDTHH:MM:SSZ> --report <pip-report.json> [--out requirements.txt] [--header "text"] [--allow-local <name>]
//   node pyhash.mjs --uploaded-prior-to <YYYY-MM-DDTHH:MM:SSZ> --pins <file with name==version lines> [--out ...]
//
// The pip report comes from resolving INSIDE a disposable container, e.g.
//   pip install --dry-run --ignore-installed --only-binary=:all: --uploaded-prior-to <same cutoff> --report /out/report.json -r requirements.in
// Every distribution file PyPI has for each pinned version gets a --hash (all wheels + sdist), so the
// same lock installs on linux/amd64 and linux/arm64 (Apple Silicon Docker) alike. Yanked files and files
// uploaded after the cutoff (or without an upload time) are left out, so a file added to an old release
// later cannot be installed. It fails (exit 1) on anything it cannot lock: a pin with no files left, a
// VCS or local requirement, an unparseable --pins line, or a report hash that PyPI does not list.

import { readFileSync, writeFileSync } from 'node:fs';

const args = process.argv.slice(2);
// A missing, empty or option-looking value is a usage error, never a silent default.
const opt = (k, d) => { const i = args.indexOf(k); if (i < 0) return d; const v = args[i + 1]; if (!v || v.startsWith('--')) { console.error(`${k} needs a value`); process.exit(64); } return v; };
const norm = n => n.toLowerCase().replace(/[-_.]+/g, '-');
const fail = msg => { console.error(msg); process.exitCode = 1; };

const cutoffArg = opt('--uploaded-prior-to', '');
if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(cutoffArg)) { console.error('need --uploaded-prior-to <YYYY-MM-DDTHH:MM:SSZ> (UTC; the same cutoff the resolver used)'); process.exit(64); }
const CUTOFF = Date.parse(cutoffArg);

let pins = [];
if (opt('--report')) {
  const rep = JSON.parse(readFileSync(opt('--report'), 'utf8'));
  for (const it of rep.install || []) {
    const di = it.download_info || {};
    if (di.dir_info) { if (opt('--allow-local') && norm(opt('--allow-local')) === norm(it.metadata.name)) console.error(`skip local project: ${it.metadata.name}`); else fail(`local/dir requirement cannot be hash-locked: ${it.metadata.name} ${di.url}`); continue; }
    if (di.vcs_info) { fail(`VCS requirement cannot be hash-locked from PyPI: ${it.metadata.name} ${di.url}`); continue; }
    const ai = di.archive_info || {};
    const sha = (ai.hashes && ai.hashes.sha256) || ((ai.hash || '').startsWith('sha256=') ? ai.hash.slice(7) : '');
    pins.push({ name: norm(it.metadata.name), version: it.metadata.version, sha, url: di.url });
  }
} else if (opt('--pins')) {
  for (const l of readFileSync(opt('--pins'), 'utf8').split(/\r?\n/)) {
    const line = l.replace(/#.*/, '').trim();
    if (!line) continue;
    const m = line.match(/^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?==([^\s;]+)$/);
    if (m) pins.push({ name: norm(m[1]), version: m[2] }); else fail(`not a name==version pin: ${line}`);
  }
} else { console.error('need --report or --pins'); process.exit(64); }

pins.sort((a, b) => a.name.localeCompare(b.name));
const lines = [];
for (const p of pins) {
  const r = await fetch(`https://pypi.org/pypi/${p.name}/${p.version}/json`);
  if (!r.ok) { fail(`PyPI lookup failed ${p.name}==${p.version}: HTTP ${r.status}`); continue; }
  const j = await r.json();
  const files = [];
  for (const u of j.urls || []) {
    if (u.yanked || !u.digests || !u.digests.sha256) continue;
    const t = Date.parse(u.upload_time_iso_8601 || '');
    if (!(t <= CUTOFF)) { console.error(`left out (uploaded ${u.upload_time_iso_8601 || 'at an unknown time'}, after the cutoff): ${u.filename}`); continue; }
    files.push(u);
  }
  if (!files.length) { fail(`no unyanked files uploaded before the cutoff for ${p.name}==${p.version}`); continue; }
  // pip's own resolution must have picked one of the files we lock.
  if (p.sha && !files.some(f => f.digests.sha256 === p.sha)) { fail(`resolved file for ${p.name}==${p.version} (${p.url}) is not among the PyPI files locked`); continue; }
  lines.push(`${p.name}==${p.version} \\\n` + files.map(f => `    --hash=sha256:${f.digests.sha256}`).join(' \\\n'));
}
const header = (opt('--header') || 'Hash-locked; install with: pip install --no-deps --require-hashes --only-binary=:all: -r <this file>').split('\n').map(l => `# ${l}`).join('\n');
const text = `${header}\n${lines.join('\n')}\n`;
// On any error, leave an existing --out file alone so a partial lock never replaces a good one.
const out = opt('--out');
if (!out) process.stdout.write(text); else if (!process.exitCode) writeFileSync(out, text);
console.error(out && process.exitCode ? `${out} NOT written (errors above)` : `${lines.length} pins written${process.exitCode ? ' (with errors above; do not use this lock)' : ''}`);
