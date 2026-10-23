const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

// The image runs as the unprivileged node user, which cannot write /app (the working directory), so a
// relative file_path has to land in the one directory it owns, /app/exports (MCP_EXPORT_DIR here).
// These cases pin that: both exports write there, the bundle reads resolve the same way so an export
// round-trips into import_file / inspect, an absolute path is still honoured, and a failed write comes
// back as {error} rather than a throw.
//
// db.js opens a Postgres pool and api.js an HTTP client at require time. Populating require.cache
// with a stub means neither file is ever executed.
function stubModule(relPath, exports) {
  const filename = require.resolve(relPath);
  require.cache[filename] = { id: filename, filename, loaded: true, exports, children: [], paths: [] };
}

const POSTED = [];
stubModule('../src/db', { query: async () => ({ rows: [] }) });
stubModule('../src/api', {
  apiGet: async () => [],
  apiPost: async (p, body) => { POSTED.push({ path: p, body }); return { ok: true }; },
});

// Both exports fetch binary bodies directly rather than through apiPost.
const BYTES = Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x00, 0xff, 0x10, 0x80]);
globalThis.fetch = async () => ({ ok: true, status: 200, arrayBuffer: async () => BYTES, text: async () => '' });

// The module imports zod; skip rather than fail where node_modules is absent, like the other suites.
let wc = null;
try {
  wc = require('../src/tools/wildcard');
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error;
}
const maybe = wc ? test : test.skip;

const ID = '00000000-0000-4000-8000-000000000001';
const tmp = (name) => fs.mkdtempSync(path.join(os.tmpdir(), `mcp-${name}-`));

maybe('export_scan_data writes a relative file_path into the export dir', async () => {
  const dir = tmp('exports');
  process.env.MCP_EXPORT_DIR = dir;
  const out = await wc.exportScanData({ target_id: ID, file_path: 'scan.zip' });
  assert.strictEqual(out.error, undefined);
  assert.strictEqual(out.saved_path, path.join(dir, 'scan.zip'));
  assert.ok(path.isAbsolute(out.saved_path));
  assert.deepStrictEqual(fs.readFileSync(out.saved_path), BYTES);
});

maybe('an absolute file_path is used as given', async () => {
  process.env.MCP_EXPORT_DIR = tmp('exports');
  const elsewhere = path.join(tmp('abs'), 'scan.zip');
  const out = await wc.exportScanData({ target_id: ID, file_path: elsewhere });
  assert.strictEqual(out.saved_path, elsewhere);
  assert.deepStrictEqual(fs.readFileSync(elsewhere), BYTES);
});

maybe('a bundle exported to a relative path round-trips into import_file and inspect', async () => {
  const dir = tmp('exports');
  process.env.MCP_EXPORT_DIR = dir;
  const out = await wc.manageDatabaseBundle({ action: 'export', scope_target_ids: [ID], file_path: 't.rs0n' });
  assert.strictEqual(out.saved_path, path.join(dir, 't.rs0n'));
  assert.deepStrictEqual(fs.readFileSync(out.saved_path), BYTES);

  POSTED.length = 0;
  assert.deepStrictEqual(await wc.manageDatabaseBundle({ action: 'import_file', file_path: 't.rs0n' }), { ok: true });
  assert.deepStrictEqual(await wc.manageDatabaseBundle({ action: 'inspect', file_path: 't.rs0n' }), { ok: true });
  assert.deepStrictEqual(POSTED.map((p) => p.path), ['/api/database-import-base64', '/api/debug-export-file']);
  for (const p of POSTED) assert.strictEqual(p.body.data, BYTES.toString('base64'));
});

maybe('a write that fails comes back as an error, not a throw', async () => {
  process.env.MCP_EXPORT_DIR = tmp('exports');
  const out = await wc.exportScanData({ target_id: ID, file_path: path.join('missing-dir', 'scan.zip') });
  assert.match(out.error, /could not write file_path/);
  const bundle = await wc.manageDatabaseBundle({ action: 'export', scope_target_ids: [ID], file_path: 'missing-dir/t.rs0n' });
  assert.match(bundle.error, /could not write file_path/);
  const read = await wc.manageDatabaseBundle({ action: 'import_file', file_path: 'missing-dir/t.rs0n' });
  assert.match(read.error, /cannot read file_path/);
});

maybe('without MCP_EXPORT_DIR a relative path resolves to <package>/exports (/app/exports in the image)', () => {
  delete process.env.MCP_EXPORT_DIR;
  assert.strictEqual(wc.resolveFilePath('x.zip'), path.join(__dirname, '..', 'exports', 'x.zip'));
  assert.strictEqual(wc.resolveFilePath('/tmp/x.zip'), path.resolve('/tmp/x.zip'));
});
