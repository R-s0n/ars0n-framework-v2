// Amass stores DNS records in the `dns_records.record` column as a single composite arrow-string,
// e.g. "floqast.app (FQDN) --> ns_record --> ns-1589.awsdns-06.co.uk (FQDN)" or
// "app.example.com (FQDN) --> a_record --> 203.0.113.10 (IPAddress)". There is no separate
// record_name / record_value column (an earlier version of the MCP queries assumed there was,
// which threw "column does not exist" and silently returned nothing). parseAmassRecord splits the
// arrow-string back into {name, value} so callers can work with structured data.
function parseAmassRecord(record) {
  if (!record || typeof record !== 'string') {
    return { name: null, value: null, raw: record || null };
  }
  // Strip the trailing type annotation like " (FQDN)" / " (IPAddress)" / " (RIROrg)".
  const strip = (s) => (s || '').replace(/\s*\((?:FQDN|IPAddress|RIROrg|Netblock|ASN)\)\s*$/i, '').trim();
  const parts = record.split('-->').map((s) => s.trim());
  if (parts.length >= 3) {
    // name --> <type>_record --> value
    return { name: strip(parts[0]), value: strip(parts[parts.length - 1]), raw: record };
  }
  if (parts.length === 2) {
    return { name: strip(parts[0]), value: strip(parts[1]), raw: record };
  }
  return { name: null, value: strip(parts[0]), raw: record };
}

module.exports = { parseAmassRecord };
