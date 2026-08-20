// One place that decides how much of a response body an MCP client gets to see.
//
// Every tool used to hard-code its own ceiling as a module constant with no way for a caller to
// raise it, and every one of them chose 2000. That number is sized for the worst case, a fifty-row
// listing at detail:"full", and it is applied identically to the best case, a deliberate read of one
// record. The cost of a body in an MCP response is rows x fields x chars, so the same constant is
// far too generous in one situation and far too mean in the other.
//
// The failure this caused was real. Reading a CSRF token out of a captured login page was impossible
// because the token sat around character 3500 of a 7492 character form, so the token could not be
// read at any price even though the whole body was sitting in the database. A cap that cannot be
// lifted is not a budget, it is a wall.
//
// So: the defaults do not move, a caller who knows what they are asking for can raise the limit for
// one call, and there is a hard ceiling no caller can exceed.

// The absolute cap. Roughly 50k tokens: deliberately uncomfortable, but survivable, and it means a
// mistyped max_body_chars cannot pull a two megabyte body into a context window.
const CEILING = 200000;

const DEFAULTS = {
  // A row inside a multi-row listing, where the row multiplier does the damage.
  list: 600,
  // Today's detail:"full" row. Unchanged, deliberately.
  record: 2000,
  // A read that returns exactly ONE record, so the multiplier is 1 and the budget can be real.
  single: 10000,
};

// resolveLimit clamps a caller-supplied budget, mirroring clampLimit's contract in truncate.js so
// there is one idiom for a bounded numeric parameter.
//
// rows matters: max_body_chars is a PER FIELD number, and threading it into a projection that runs
// once per row multiplies it. Dividing by the row count keeps the total bounded whatever the caller
// asks for, so raising the limit on a wide listing degrades gracefully instead of exploding.
function resolveLimit(requested, fallback, rows = 1) {
  const asked = parseInt(requested, 10);
  const base = Number.isFinite(asked) && asked > 0 ? Math.min(asked, CEILING) : fallback;
  const spread = Math.max(1, rows);
  if (spread === 1) return base;
  return Math.max(fallback, Math.floor(Math.min(base, CEILING / spread)));
}

// clip trims text to a budget and says so, in one marker format.
//
// With opts.match it stops trimming from the front and instead returns the WINDOW around the first
// case-insensitive hit, which is what makes a large body useful without transferring it: the caller
// who knows they are looking for `name="csrf"` gets the bytes around it rather than the first 2000
// characters of boilerplate head and nav.
function clip(text, limit, opts = {}) {
  if (typeof text !== 'string') return text;
  const budget = Number.isFinite(limit) && limit > 0 ? limit : DEFAULTS.record;

  const needle = typeof opts.match === 'string' ? opts.match.trim() : '';
  if (needle) {
    const at = text.toLowerCase().indexOf(needle.toLowerCase());
    if (at < 0) {
      return `[no match for ${JSON.stringify(needle)} in ${text.length} chars]`;
    }
    const window = Number.isFinite(opts.window) && opts.window > 0
      ? Math.min(opts.window, CEILING)
      : 400;
    const start = Math.max(0, at - window);
    const end = Math.min(text.length, at + needle.length + window);
    const head = start > 0 ? `[...${start} chars before...]\n` : '';
    const tail = end < text.length ? `\n[...${text.length - end} chars after...]` : '';
    return head + text.slice(start, end) + tail;
  }

  if (text.length <= budget) return text;
  return text.slice(0, budget) + `\n... [truncated, ${text.length - budget} chars remaining]`;
}

// bodyOptions reads the three parameters every body-returning tool now accepts.
function bodyOptions(params = {}, fallback = DEFAULTS.record, rows = 1) {
  return {
    limit: resolveLimit(params.max_body_chars, fallback, rows),
    match: params.body_match,
    window: params.body_match_window,
  };
}

module.exports = { CEILING, DEFAULTS, resolveLimit, clip, bodyOptions };
