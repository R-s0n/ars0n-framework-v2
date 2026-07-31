const API_BASE = process.env.API_URL || 'http://api:8443';

// Parse a response body tolerantly: some Go handlers return an empty body or a plain-text message
// (e.g. after a successful POST/PUT/DELETE). Blindly calling res.json() on those throws
// "Unexpected end of JSON input", so we read the text and only JSON.parse when there's content.
async function parseBody(res) {
  const text = await res.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return { message: text };
  }
}

async function apiGet(path) {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API GET ${path} failed (${res.status}): ${text}`);
  }
  return parseBody(res);
}

async function apiPost(path, body = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API POST ${path} failed (${res.status}): ${text}`);
  }
  return parseBody(res);
}

async function apiPut(path, body = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API PUT ${path} failed (${res.status}): ${text}`);
  }
  return parseBody(res);
}

async function apiDelete(path) {
  const res = await fetch(`${API_BASE}${path}`, { method: 'DELETE' });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API DELETE ${path} failed (${res.status}): ${text}`);
  }
  return parseBody(res);
}

module.exports = { apiGet, apiPost, apiPut, apiDelete };
