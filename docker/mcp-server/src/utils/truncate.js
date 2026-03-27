const DEFAULT_MAX_RESULTS = 50;

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

function truncateText(text, maxLength = 2000) {
  if (text.length <= maxLength) return text;
  return text.slice(0, maxLength) + `\n... [truncated, ${text.length - maxLength} chars remaining]`;
}

module.exports = { limitResults, truncateText };
