// Which scope target types can ever populate which data store.
//
// The three workflows write to disjoint sets of tables. Wildcard consolidation writes
// consolidated_subdomains, and its httpx and metadata steps write target_urls. The Company workflow
// writes consolidated_company_domains, consolidated_network_ranges and, through its IP/port scan,
// live_web_servers. The URL workflow writes discovered_endpoints, consolidated_url_endpoints,
// consolidated_url_parameters and attack_vectors, and never writes a row into target_urls or
// consolidated_subdomains.
//
// Counting a store the target's type cannot populate always returns 0, and a 0 that means "this
// workflow does not produce that" is indistinguishable from a 0 that means "the scan ran and found
// nothing". Against the URL target http://10.0.0.18:3000, which held 196 consolidated endpoints and
// 202 attack vectors, get_attack_surface answered 0 subdomains, 0 target URLs and 0 live servers,
// and get_target_summary answered target_urls: 0. Both read as an untouched target, which is the
// opposite of the truth and the exact confusion this framework exists to remove.

const STORE_OWNERS = {
  consolidated_subdomains: {
    types: ['Wildcard'],
    produced_by: 'Wildcard subdomain consolidation',
  },
  target_urls: {
    types: ['Wildcard', 'Company'],
    produced_by: 'the httpx and metadata steps of the Wildcard and Company workflows',
  },
  consolidated_company_domains: {
    types: ['Company'],
    produced_by: 'Company domain discovery and consolidation',
  },
  consolidated_network_ranges: {
    types: ['Company'],
    produced_by: 'Company network range discovery and consolidation',
  },
  live_web_servers: {
    types: ['Company'],
    produced_by: 'the Company IP/port scan',
  },
  discovered_endpoints: {
    types: ['URL'],
    produced_by: 'the URL workflow crawlers (katana, linkfinder, waybackurls, gau, gospider)',
  },
  consolidated_url_endpoints: {
    types: ['URL'],
    produced_by: 'URL workflow endpoint consolidation',
  },
  consolidated_url_parameters: {
    types: ['URL'],
    produced_by: 'URL workflow endpoint consolidation',
  },
  attack_vectors: {
    types: ['URL'],
    produced_by: 'the URL workflow attack surface step',
  },
};

// Stores whose rows are not a plain COUNT keyed by scope_target_id.
//
// live_web_servers has no scope_target_id column at all; it reaches its scope target through the
// IP/port scan that found it. Counting it with the obvious WHERE threw, the throw was caught, and
// the caller was handed 0, so "0 live servers" was a swallowed error rather than a measurement.
// consolidated_url_parameters hangs off the endpoint that owns it. The two endpoint stores are
// soft-deleted, and counting rows an operator has deleted would not match what the UI shows.
const COUNT_SQL = {
  live_web_servers:
    `SELECT COUNT(*) AS count FROM live_web_servers lws
       JOIN ip_port_scans ips ON lws.scan_id = ips.scan_id
      WHERE ips.scope_target_id = $1`,
  consolidated_url_parameters:
    `SELECT COUNT(*) AS count FROM consolidated_url_parameters p
       JOIN consolidated_url_endpoints e ON e.id = p.endpoint_id
      WHERE e.scope_target_id = $1 AND e.deleted_at IS NULL`,
  consolidated_url_endpoints:
    'SELECT COUNT(*) AS count FROM consolidated_url_endpoints WHERE scope_target_id = $1 AND deleted_at IS NULL',
  attack_vectors:
    'SELECT COUNT(*) AS count FROM attack_vectors WHERE scope_target_id = $1 AND deleted_at IS NULL',
};

function storeApplies(store, targetType) {
  const owner = STORE_OWNERS[store];
  // An unknown store is treated as applicable: guessing "not applicable" would hide real data,
  // which is a worse failure than reporting a count nobody asked for.
  if (!owner) return true;
  return owner.types.includes(targetType);
}

// The value a count is replaced with when the store cannot apply. It is an object rather than null
// so that the answer carries its own explanation to wherever it is read.
function notApplicable(store, targetType) {
  const owner = STORE_OWNERS[store];
  if (!owner) return { applicable: false, reason: `${store} does not apply to a ${targetType} target.` };
  return {
    applicable: false,
    store,
    reason: `${store} is written by ${owner.produced_by}, which only runs for ${owner.types.join(' and ')} targets. `
      + `This is a ${targetType} target, so the count is 0 regardless of what has been scanned here.`,
  };
}

// Counts one store, or explains why it does not apply. Returns { applicable: false, ... } for a
// store this target type cannot populate, { error } when the query itself failed, and a plain
// number otherwise. A failed query must never come back as 0: that is how a broken query becomes
// "nothing found".
async function countStore(query, store, targetType, targetId, sql) {
  if (!storeApplies(store, targetType)) return notApplicable(store, targetType);
  const text = sql || COUNT_SQL[store] || `SELECT COUNT(*) AS count FROM ${store} WHERE scope_target_id = $1`;
  try {
    const res = await query(text, [targetId]);
    return parseInt(res.rows[0]?.count || '0', 10);
  } catch (err) {
    return { error: String(err.message || err), store };
  }
}

module.exports = { STORE_OWNERS, COUNT_SQL, storeApplies, notApplicable, countStore };
