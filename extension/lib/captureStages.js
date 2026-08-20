// The webRequest lifecycle stages, as pure functions over a pending record.
//
// These live here rather than inline in the listeners because the bug they exist to prevent is a
// WIRING bug, not a logic bug, and wiring bugs are invisible without a test that replays the real
// event order. chrome fires, for a request that redirects once:
//
//   onBeforeRequest -> onSendHeaders -> onHeadersReceived -> onBeforeRedirect
//     -> onBeforeRequest -> onSendHeaders -> onHeadersReceived -> onCompleted
//
// and every one of those carries the SAME requestId, so all eight land on the same record. The
// second onBeforeRequest describes the redirect destination, which is a different request: usually
// a GET, with no body and no Content-Type. Letting it write to the record replaced the body and
// headers of the request that actually mattered.
//
// Measured on ginandjuice.shop 2026-08-19: the successful login POST stored has_body false, no
// post_params at all, and headers with no content-type and no origin, while still claiming
// method POST and carrying its redirect chain. The login is precisely the request a crawl exists
// to capture, and it was the one guaranteed to be destroyed, because a successful login almost
// always redirects.

// applyRequestBodyStage records the parsed body, unless the record is already sealed.
//
// Guarded rather than assigned even when unsealed: an empty parse must never overwrite a body an
// earlier stage recorded. The auth path always did this; the main path did not, and that
// difference was the whole defect.
export function applyRequestBodyStage(record, parsed) {
  if (!record || record.requestSealed) return record;
  if (parsed && parsed.text) record.postData = parsed.text;
  if (parsed && parsed.formData) record.formData = parsed.formData;
  return record;
}

// applyRequestHeadersStage records the request headers, unless the record is already sealed.
export function applyRequestHeadersStage(record, headers) {
  if (!record || record.requestSealed) return record;
  record.headers = headers || {};
  return record;
}

// applyRedirectStage appends the hop and freezes the request side of the record.
//
// The response side is deliberately left open, so the record still ends up with the status the
// chain finally settled on. Only the request is frozen, because only the request is being
// described by a different HTTP message from here on.
export function applyRedirectStage(record, hop) {
  if (!record) return record;
  record.redirectChain = record.redirectChain || [];
  if (hop) record.redirectChain.push(hop);
  record.requestSealed = true;
  return record;
}
