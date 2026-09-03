const DEFAULT_MAX_RESULTS = 50;
const MAX_LIMIT = 1000;

// limitResults is for a set the caller ALREADY HOLDS IN FULL. Only then is rows.length the total,
// and only then does reporting it as "total" tell the truth.
function limitResults(rows, maxResults) {
  const limit = maxResults || DEFAULT_MAX_RESULTS;
  const total = rows.length;
  const truncated = total > limit;
  return {
    data: rows.slice(0, limit),
    total,
    truncated,
  };
}

// limitFetched is for a set POSTGRES ALREADY LIMITED, which is the `LIMIT ${lim + 1}` idiom used in
// thirteen places here. Those callers were passing the clipped page to limitResults, so rows.length
// was at most limit+1 and the response said `total`.
//
// MEASURED: query_endpoints with source=linkfinder and max_results=5 answered `total: 6` on a target
// whose own sources_present, in the same response, said linkfinder found 13. A field named total that
// reports the page size is worse than no field, because a caller reads 6 and stops looking. That is
// the same fail-open shape as a green scan that never ran: a number that reads as a measurement and
// is an artefact of the query.
//
// So this reports what it actually knows. `returned` is the row count in this response. `truncated`
// says more exist. `total` is emitted ONLY when the caller supplies a real COUNT(*) over the same
// filters, and is otherwise absent rather than guessed.
function limitFetched(rows, limit, total = null) {
  const truncated = rows.length > limit;
  const data = rows.slice(0, limit);
  const out = { data, returned: data.length, truncated };
  if (Number.isFinite(total)) out.total = total;
  else if (!truncated) out.total = data.length; // No more rows exist, so the page IS the total.
  return out;
}

// Clamp a user-supplied max_results into [1, MAX_LIMIT], defaulting to DEFAULT_MAX_RESULTS.
// Used to build a safe SQL `LIMIT <n>` so tools fetch a bounded set from Postgres instead of
// pulling every row into the MCP process and slicing in memory. The return value is a validated
// integer, so it is safe to interpolate directly into the SQL LIMIT clause.
function clampLimit(maxResults, def = DEFAULT_MAX_RESULTS) {
  const n = parseInt(maxResults, 10);
  if (!Number.isFinite(n) || n <= 0) return def;
  return Math.min(n, MAX_LIMIT);
}

function truncateText(text, maxLength = 2000) {
  if (text.length <= maxLength) return text;
  return text.slice(0, maxLength) + `\n... [truncated, ${text.length - maxLength} chars remaining]`;
}

// The API's scan endpoints return full scan records with raw tool output inline (result / stdout /
// stderr can each be hundreds of KB). Returned verbatim to an LLM they blow the context window, so
// the status/overview tools trim those heavy fields. Use get_scan_results (already row-truncated)
// when the actual output is needed.
const HEAVY_SCAN_FIELDS = ['result', 'stdout', 'stderr', 'raw_output', 'output', 'raw_results'];

function trimScanRecord(rec, maxLen) {
  if (!rec || typeof rec !== 'object') return rec;
  const copy = Array.isArray(rec) ? [...rec] : { ...rec };
  for (const f of HEAVY_SCAN_FIELDS) {
    if (typeof copy[f] === 'string' && copy[f].length > maxLen) {
      copy[f] = copy[f].slice(0, maxLen) + `\n... [truncated, ${copy[f].length - maxLen} chars, use get_scan_results for full output]`;
    }
  }
  return copy;
}

// Accepts an array of scan records, a single record, or a { scans: [...] } wrapper and trims the
// heavy output fields on each. maxLen defaults small because these tools are for status/overview.
function trimScanRecords(data, maxLen = 800) {
  if (Array.isArray(data)) return data.map((r) => trimScanRecord(r, maxLen));
  if (data && Array.isArray(data.scans)) return { ...data, scans: data.scans.map((r) => trimScanRecord(r, maxLen)) };
  return trimScanRecord(data, maxLen);
}

module.exports = { limitResults, limitFetched, truncateText, clampLimit, trimScanRecords };
