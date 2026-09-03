// How much of a row an MCP client gets when it did not ask for more.
//
// The measured failure: manage_attack_vectors action=list against the Juice Shop target could not
// return forty rows. Serialised, forty vectors came to 41243 characters and fifty to 50519, because
// raw_request was projected onto every row and there was NO parameter that could switch it off. The
// only lever was max_results, which shrinks the answer rather than the row, so the way to see the
// list was to stop seeing most of it. Several other list calls hit the same ceiling and auto-spilled
// to files, which is worse than either: the agent then has a file path where it wanted data.
//
// clip.js already owns the other half of this, how much of ONE body a caller sees. This owns which
// fields exist at all. They are different questions: clipping a 2592 character raw_request to 600
// still spends 600 characters per row saying something the caller did not ask for, and forty of
// those is the whole problem.
//
// The rule: a list is compact unless asked otherwise, "full" is what a caller asks for once it knows
// which rows it wants, and a compact row still reports the SIZE of what was left out so nobody has
// to guess whether asking for full is worth the budget.

// The two levels, matching the vocabulary authz.js, endpoints.js and manualcrawl.js already use.
// Deliberately not a third level: a vocabulary an agent has to look up is a vocabulary it gets wrong.
const DETAIL_LEVELS = ['compact', 'full'];

function isFull(params) {
  return Boolean(params) && params.detail === 'full';
}

// dropEmpty removes the keys that carry no information.
//
// Empty is not free. A vector row with notes:"", port:null and parameters:[] spends roughly eighty
// characters saying nothing, and over two hundred rows that is sixteen kilobytes of a budget that was
// already the binding constraint. false and 0 are KEPT: those are answers.
function dropEmpty(row) {
  if (!row || typeof row !== 'object' || Array.isArray(row)) return row;
  const out = {};
  for (const [key, value] of Object.entries(row)) {
    if (value === undefined || value === null || value === '') continue;
    if (Array.isArray(value) && value.length === 0) continue;
    out[key] = value;
  }
  return out;
}

// withoutHeavy replaces a heavy field with its size.
//
// Reporting the size rather than dropping the field silently is the point. A caller looking at
// raw_request_chars: 2592 knows both that bytes exist and what asking for them costs; a caller
// looking at a row where raw_request is simply absent cannot tell that from a vector that never had
// one, which is the same class of ambiguity as a scan with no findings and no verdict.
function withoutHeavy(row, fields) {
  const out = { ...row };
  for (const field of fields) {
    const value = out[field];
    delete out[field];
    if (typeof value === 'string' && value.length > 0) {
      out[`${field}_chars`] = value.length;
    } else if (Array.isArray(value) && value.length > 0) {
      out[`${field}_count`] = value.length;
    }
  }
  return out;
}

// pick projects a row down to a named field set, for the lists whose weight is width rather than one
// large field. fuzz findings is the example: no single heavy column, twenty two columns per row and
// sixty one rows, which is 41565 characters before the response is even pretty printed.
function pick(row, fields) {
  const out = {};
  for (const field of fields) {
    if (row[field] !== undefined) out[field] = row[field];
  }
  return out;
}

// detailDescription keeps every tool's wording consistent, so an agent learns the parameter once.
function detailDescription(compactSays, fullSays) {
  return `compact (default) ${compactSays} full ${fullSays} ` +
    'A list is compact by default because the cost of a row is multiplied by the row count, and a ' +
    'listing that exceeds the MCP output cap returns nothing usable at all.';
}

module.exports = { DETAIL_LEVELS, isFull, dropEmpty, withoutHeavy, pick, detailDescription };
