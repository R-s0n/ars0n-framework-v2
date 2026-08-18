const { z } = require('zod');
const { apiGet, apiPost, apiDelete } = require('../api');
const { limitResults, clampLimit } = require('../utils/truncate');

// Three screens of the URL workflow that had no MCP equivalent: each crawler's Results modal, the
// Manage Attack Surface modal, and the Client Identity modal's candidate list. All three are things
// a human can already do in the web UI, so an agent has to be able to do them too, including the
// writes: an agent that can read the attack surface but not add a host to it, or read identifier
// candidates but not run the detector that produces them, still has to stop and ask a human.
//
// These proxy the Go API rather than reading Postgres. That is not a style preference here either.
// Adding an attack surface asset runs a per-type path that validates the CIDR, parses the IP,
// lowercases the FQDN, strips the AS prefix, guesses the cloud provider from the hostname and
// upserts on a three-column conflict key; auto-detect walks every stored capture through the URL,
// header and body extractors and dedupes on endpoint+method+value. A second implementation of
// either drifts from the first without anyone noticing, and the drift shows up as an asset the UI
// cannot see or a duplicate identifier the promote step trips over.
//
// Size is the constraint coming back. A crawler scan routinely discovers tens of thousands of
// endpoints and an attack surface asset row carries whois, SSL, DNS and raw response headers, so
// nothing returns whole: the verbose half of every row sits behind detail:"full", JSON blobs are
// clipped, and every list runs through limitResults.

// The ceiling on anything stored as a free-form blob, applied per field.
const BLOB_LIMIT = 2000;

// The scan_type the discovered_endpoints rows are tagged with, mapped to the route that lists that
// tool's scans. Note that the two names differ: the tag is the bare tool name, while four of the
// five scan routes carry a -url suffix and waybackurls does not. Guessing either from the other is
// how an agent ends up fetching an empty list from a route that returns 200.
const CRAWLERS = {
  katana: '/scopetarget/{id}/scans/katana-url',
  gospider: '/scopetarget/{id}/scans/gospider-url',
  linkfinder: '/scopetarget/{id}/scans/linkfinder-url',
  gau: '/scopetarget/{id}/scans/gau-url',
  waybackurls: '/scopetarget/{id}/scans/waybackurls',
};

const ASSET_TYPES = ['asn', 'network_range', 'ip_address', 'fqdn', 'cloud_asset', 'live_web_server'];

// === Per-scan discovered endpoints =============================================================

const getDiscoveredEndpointsSchema = z.object({
  target_id: z.string().uuid().describe(
    'The scope target UUID. Always pass this: it is what lets the tool find the scan for you, and ' +
    'it is the only thing an agent reliably has.'),
  tool: z.enum(['katana', 'gospider', 'linkfinder', 'gau', 'waybackurls']).describe(
    'Which crawler\'s results to read. katana and gospider actively crawl the site, linkfinder ' +
    'pulls endpoints out of JavaScript, and gau and waybackurls are archive lookups that never ' +
    'touch the target, so an archive hit is a URL that existed once, not one that exists now. ' +
    'Each tool records its own rows, so the same URL can appear under several of them.'),
  scan_id: z.string().uuid().optional().describe(
    'A specific run. Omit it and the newest successful run of that tool on this target is used, ' +
    'which is what the Results modal shows. Pass it only when comparing an older run against the ' +
    'current one; you can get run ids from get_target_scans.'),
  reach: z.enum(['direct', 'adjacent']).optional().describe(
    'direct: endpoints on the scope target itself. adjacent: endpoints on another host the pages ' +
    'referenced, which is where third-party and sibling-domain surface shows up. Default: both.'),
  pattern: z.string().optional().describe(
    'Substring match on the URL, domain, path or normalized path, matching the modal\'s search ' +
    'box. Searching only the URL would miss a bare domain or a templated path.'),
  include_parameters: z.boolean().optional().describe(
    'Include the parameters discovered on each endpoint (default false, they are verbose). Turn ' +
    'it on when you are looking for injection candidates rather than counting surface: the ' +
    'parameter names and their example values are the reason to read a gau or waybackurls run.'),
  max_results: z.number().optional().describe('Maximum rows (default 50, max 1000)'),
});

async function getDiscoveredEndpoints(params) {
  let scanId = params.scan_id;
  let scan;

  if (!scanId) {
    const scans = await apiGet(CRAWLERS[params.tool].replace('{id}', params.target_id));
    const rows = Array.isArray(scans) ? scans : [];
    if (!rows.length) {
      return { status: 'not_run', note: `No ${params.tool} scan has run on this target yet.` };
    }
    // The route already orders newest first, so rows[0] is what the UI calls the most recent scan.
    // A successful run is preferred over it, though, because the newest run is often one that is
    // still going or that failed, and both write no rows. Returning an empty list from those reads
    // as "this tool found nothing" when the truth is "this tool has not finished".
    scan = rows.find((s) => s.status === 'success') || rows[0];
    scanId = scan.scan_id;
  }

  const qs = new URLSearchParams({ scan_type: params.tool });
  if (params.reach) qs.set('is_direct', params.reach === 'direct' ? 'true' : 'false');
  const endpoints = await apiGet(`/discovered-endpoints/${scanId}?${qs.toString()}`);

  let rows = Array.isArray(endpoints) ? endpoints : [];
  if (params.pattern) {
    const needle = params.pattern.replace(/\*/g, '').toLowerCase();
    rows = rows.filter((e) =>
      (e.url || '').toLowerCase().includes(needle) ||
      (e.domain || '').toLowerCase().includes(needle) ||
      (e.path || '').toLowerCase().includes(needle) ||
      (e.normalized_path || '').toLowerCase().includes(needle));
  }

  const withParams = !!params.include_parameters;
  const projected = rows.map((e) => clean({
    id: e.id,
    url: e.url,
    domain: e.domain,
    path: e.path,
    // What the path looks like with its variable segments collapsed. Two rows sharing one of these
    // are the same handler with different ids, which is the difference between 400 endpoints and
    // one endpoint seen 400 times.
    normalized_path: e.normalized_path,
    status_code: e.status_code,
    // Never stripped, because false is the whole point of the field and an absent is_direct would
    // read as direct.
    is_direct: e.is_direct === true,
    created_at: e.created_at,
    parameters: withParams ? emptyToUndefined(e.parameters) : undefined,
  }));

  return {
    ...clean({
      // Which run this came from, always, so a caller can tell a stale run from a fresh one and can
      // pass the same scan_id back to compare after a re-crawl.
      scan: scan ? clean({
        scan_id: scan.scan_id,
        status: scan.status,
        url: scan.url,
        execution_time: scan.execution_time,
        created_at: scan.created_at,
        error: clip(scan.error, BLOB_LIMIT),
      }) : { scan_id: scanId },
      note: scan && scan.status !== 'success'
        ? `The newest ${params.tool} run is "${scan.status}" and no successful run exists, so these ` +
          'rows are whatever it managed to write before stopping.'
        : undefined,
    }),
    direct_count: rows.filter((e) => e.is_direct === true).length,
    adjacent_count: rows.filter((e) => e.is_direct !== true).length,
    ...limitResults(projected, clampLimit(params.max_results)),
  };
}

// === Attack surface assets =====================================================================

const manageAttackSurfaceAssetsSchema = z.object({
  action: z.enum(['counts', 'list', 'add', 'delete']).describe(
    'counts: how many assets of each type the target has. Cheap, and the right first call, because ' +
    'the full list can be thousands of rows. ' +
    'list: the assets themselves, filterable by type and by a substring search. ' +
    'add: put an asset in by hand. This is how you record something the consolidation never found, ' +
    'for example a host named in a program scope page that no enumeration source returns. ' +
    'delete: remove assets. Note that a later Consolidate Attack Surface run rebuilds the whole ' +
    'set from the scan tables, so deleting an asset that a scan still reports brings it back; to ' +
    'make a removal stick, fix whatever discovered it.'),

  target_id: z.string().uuid().optional().describe(
    'The scope target UUID. Required for counts, list and add. Not used by delete, which addresses ' +
    'assets by their own ids.'),

  asset_type: z.enum(ASSET_TYPES).optional().describe(
    'Required on add, optional as a list filter. asn: an autonomous system, given as AS15169 or ' +
    'bare 15169. network_range: a CIDR block, validated on the way in. ip_address: a single v4 or ' +
    'v6 address. fqdn: a hostname, lowercased on the way in. cloud_asset: a bucket or storage ' +
    'hostname; the provider is inferred from the name. live_web_server: a URL, and https:// is ' +
    'prepended when you leave the scheme off.'),
  asset_identifier: z.string().optional().describe(
    'add: the asset itself, e.g. AS15169, 192.0.2.0/24, 192.0.2.10, app.example.com, ' +
    'bucket.s3.amazonaws.com, https://app.example.com. Matched against asset_type, so a value that ' +
    'does not parse as that type is rejected rather than stored wrong.'),
  asset_identifiers: z.array(z.string()).optional().describe(
    'add: several assets of the same asset_type in one call. Each is added independently, so one ' +
    'bad value does not lose the rest; the failures come back with their reasons.'),
  asset_id: z.string().uuid().optional().describe('delete: a single asset id'),
  asset_ids: z.array(z.string().uuid()).optional().describe(
    'delete: several asset ids at once, which is what the modal\'s checkbox selection does.'),

  pattern: z.string().optional().describe(
    'list: substring match across the identifier and the type-specific fields the modal searches, ' +
    'which is ASN number and organization, CIDR block, IP, FQDN, URL, domain and cloud provider.'),
  detail: z.enum(['compact', 'full']).optional().describe(
    'compact (default) returns the identity of each asset plus the fields that belong to its own ' +
    'type; an asset row has a column for every type and only one family is ever populated. full ' +
    'adds the enrichment: DNS record sets, whois, SSL certificate details, response headers, ' +
    'findings and the parent/child relationships. Very large over a whole target, so narrow with ' +
    'asset_type or pattern first.'),
  max_results: z.number().optional().describe('list: maximum rows (default 50, max 1000)'),
});

async function manageAttackSurfaceAssets(params) {
  switch (params.action) {
    case 'counts': {
      if (!params.target_id) return { error: 'counts needs target_id' };
      const counts = await apiGet(`/attack-surface-asset-counts/${params.target_id}`);
      // The counts route answers with plural keys (asns, fqdns, network_ranges) while every other
      // route in this group speaks the singular asset_type (asn, fqdn, network_range). The totals
      // are echoed back under the singular names so a caller can feed one straight into the next
      // call without translating, and the original shape is kept alongside it.
      const singular = {
        asn: counts.asns || 0,
        network_range: counts.network_ranges || 0,
        ip_address: counts.ip_addresses || 0,
        fqdn: counts.fqdns || 0,
        cloud_asset: counts.cloud_assets || 0,
        live_web_server: counts.live_web_servers || 0,
      };
      return {
        by_asset_type: singular,
        total: Object.values(singular).reduce((a, b) => a + b, 0),
      };
    }

    case 'list': {
      if (!params.target_id) return { error: 'list needs target_id' };
      const out = await apiGet(`/attack-surface-assets/${params.target_id}`);
      let rows = Array.isArray(out) ? out : (out?.assets || []);

      if (params.asset_type) rows = rows.filter((a) => a.asset_type === params.asset_type);
      if (params.pattern) {
        const needle = params.pattern.replace(/\*/g, '').toLowerCase();
        rows = rows.filter((a) => [
          a.asset_identifier, a.asn_number, a.asn_organization, a.cidr_block,
          a.ip_address, a.fqdn, a.url, a.domain, a.cloud_provider,
        ].filter(Boolean).join(' ').toLowerCase().includes(needle));
      }

      const full = params.detail === 'full';
      const projected = rows.map((a) => compactAsset(a, full));
      return limitResults(projected, clampLimit(params.max_results));
    }

    case 'add': {
      if (!params.target_id) return { error: 'add needs target_id' };
      if (!params.asset_type) return { error: 'add needs asset_type' };
      const identifiers = [
        ...(params.asset_identifier ? [params.asset_identifier] : []),
        ...(params.asset_identifiers || []),
      ].map((s) => String(s).trim()).filter(Boolean);
      if (!identifiers.length) {
        return { error: 'add needs asset_identifier, or asset_identifiers for several at once' };
      }

      const added = [];
      const failed = [];
      for (const identifier of identifiers) {
        // One POST each, because the route takes one asset. Failures are collected rather than
        // thrown: a batch where one CIDR is malformed should still add the other nine, and the
        // caller needs to know which one was rejected and why.
        try {
          const out = await apiPost('/attack-surface-assets/add', {
            scope_target_id: params.target_id,
            asset_type: params.asset_type,
            asset_identifier: identifier,
          });
          added.push({ id: out.id, asset_identifier: identifier });
        } catch (err) {
          failed.push({ asset_identifier: identifier, error: apiError(err) });
        }
      }

      return clean({
        asset_type: params.asset_type,
        added: added.length,
        assets: added,
        failed: failed.length ? failed : undefined,
        // The insert upserts on (scope_target_id, asset_type, asset_identifier), so re-adding an
        // existing asset succeeds and only touches its timestamp. That is not an error, but it is
        // also not a new asset, and the response cannot tell the two apart.
        note: added.length
          ? 'Assets already present were refreshed rather than duplicated.'
          : undefined,
      });
    }

    case 'delete': {
      const ids = [
        ...(params.asset_id ? [params.asset_id] : []),
        ...(params.asset_ids || []),
      ];
      if (!ids.length) return { error: 'delete needs asset_id, or asset_ids for several at once' };

      const deleted = [];
      const failed = [];
      for (const id of ids) {
        try {
          await apiDelete(`/attack-surface-assets/${id}`);
          deleted.push(id);
        } catch (err) {
          failed.push({ asset_id: id, error: apiError(err) });
        }
      }
      return clean({
        deleted: deleted.length,
        asset_ids: deleted,
        failed: failed.length ? failed : undefined,
        note: 'A later Consolidate Attack Surface run rebuilds the set from the scan tables and ' +
              'will restore anything a scan still reports.',
      });
    }

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// === Client identifiers ========================================================================

const manageClientIdentifiersSchema = z.object({
  action: z.enum(['list', 'create', 'delete', 'auto_detect']).describe(
    'list: the candidate identifiers recorded on this target. ' +
    'create: record one by hand, which is what selecting a value in the Client Identity modal ' +
    'does. Reach for it when you have spotted something the detector missed, for example an id ' +
    'buried in a custom header or an encoded field. ' +
    'delete: drop candidates that turned out to be noise, such as a version string or a locale ' +
    'code that merely looked like an id. ' +
    'auto_detect: sweep the traffic already recorded for this target and record every value shaped ' +
    'like an object reference. Reads only stored captures, so it sends nothing to the target and ' +
    'costs nothing there; run it as soon as a manual crawl has recorded anything.'),

  target_id: z.string().uuid().optional().describe(
    'The scope target UUID. Required for list, create and auto_detect. Not used by delete, which ' +
    'addresses identifiers by their own ids.'),

  endpoint_url: z.string().optional().describe(
    'create: the request this value was seen on. Required, because an identifier is only ' +
    'meaningful with the endpoint it appeared in; the same UUID in a URL path and in a response ' +
    'body are two different testing opportunities. Doubles as a list filter (exact match).'),
  method: z.string().optional().describe(
    'create: the HTTP verb of that request, defaulting to GET. Doubles as a list filter.'),
  value: z.string().optional().describe(
    'create: the identifier value itself, e.g. 4187, 9f2c-4b1a-a03d, dXNlcjoxMjM=. Required. This ' +
    'is the thing you would swap for another account\'s equivalent to test access control.'),
  source: z.enum(['request', 'decoded', 'auto']).optional().describe(
    'Where the value came from. request: read straight off the request line, headers or body. ' +
    'decoded: lifted out of a JWT claim or a base64 blob, which is the signed-token case and the ' +
    'one worth checking for a missing signature check. auto: written by auto_detect. Defaults to ' +
    'request on create; doubles as a list filter.'),
  label: z.string().optional().describe(
    'create: a short note on where it sat, e.g. "path segment", "query param userId", "response ' +
    'body". auto_detect fills this in itself, and it is what tells you later whether the value was ' +
    'something the client sent or something the server handed back.'),

  id: z.string().uuid().optional().describe('delete: a single client identifier id'),
  ids: z.array(z.string().uuid()).optional().describe('delete: several identifier ids at once'),

  pattern: z.string().optional().describe(
    'list: substring match on the value, the endpoint URL or the label.'),
  max_results: z.number().optional().describe('list: maximum rows (default 50, max 1000)'),
});

async function manageClientIdentifiers(params) {
  switch (params.action) {
    case 'list': {
      if (!params.target_id) return { error: 'list needs target_id' };
      let rows = await fetchIdentifiers(params.target_id);

      if (params.source) rows = rows.filter((i) => (i.source || '') === params.source);
      if (params.endpoint_url) rows = rows.filter((i) => i.endpoint_url === params.endpoint_url);
      if (params.method) {
        rows = rows.filter((i) => (i.method || '').toUpperCase() === params.method.toUpperCase());
      }
      if (params.pattern) {
        const needle = params.pattern.replace(/\*/g, '').toLowerCase();
        rows = rows.filter((i) =>
          (i.value || '').toLowerCase().includes(needle) ||
          (i.endpoint_url || '').toLowerCase().includes(needle) ||
          (i.label || '').toLowerCase().includes(needle));
      }

      const projected = rows.map(compactIdentifier);
      return {
        // Candidates cluster: one endpoint with thirty of them is a listing page echoing every row
        // it rendered, which is a different thing from thirty endpoints with one each.
        endpoints: [...new Set(rows.map((i) => i.endpoint_url).filter(Boolean))].length,
        ...limitResults(projected, clampLimit(params.max_results)),
      };
    }

    case 'create': {
      if (!params.target_id) return { error: 'create needs target_id' };
      if (!params.endpoint_url) return { error: 'create needs endpoint_url' };
      if (!params.value) return { error: 'create needs value' };
      const created = await apiPost(`/authz/client-identifiers/${params.target_id}`, {
        endpoint_url: params.endpoint_url,
        method: params.method || 'GET',
        value: params.value,
        source: params.source || 'request',
        label: params.label || '',
      });
      return compactIdentifier(created);
    }

    case 'delete': {
      const ids = [
        ...(params.id ? [params.id] : []),
        ...(params.ids || []),
      ];
      if (!ids.length) return { error: 'delete needs id, or ids for several at once' };

      const deleted = [];
      const failed = [];
      for (const id of ids) {
        try {
          await apiDelete(`/authz/client-identifiers/id/${id}`);
          deleted.push(id);
        } catch (err) {
          failed.push({ id, error: apiError(err) });
        }
      }
      return clean({ deleted: deleted.length, ids: deleted, failed: failed.length ? failed : undefined });
    }

    case 'auto_detect': {
      if (!params.target_id) return { error: 'auto_detect needs target_id' };
      const out = await apiPost(`/authz/client-identifiers/${params.target_id}/auto-detect`, {});
      const scanned = out.captures_scanned || 0;
      const found = out.candidates_found || 0;
      const inserted = out.inserted || 0;
      return clean({
        captures_scanned: scanned,
        candidates_found: found,
        inserted,
        // The insert skips rows that already exist, so found and inserted differ on every run after
        // the first. Without saying so, a second run reporting inserted: 0 reads as a failure.
        already_recorded: found - inserted,
        note: scanned === 0
          ? 'No recorded traffic on this target, so there was nothing to scan. Run a manual crawl ' +
            'first; auto-detect only reads captures that are already stored.'
          : undefined,
      });
    }

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// === projections ===============================================================================

// An attack surface asset is one wide row with a column for every asset type, so only one family of
// fields is ever populated on a given asset. Returning the whole row means six blocks of nulls per
// asset across thousands of assets, so compact form returns the identity plus the block that
// belongs to this asset's own type.
function compactAsset(a, full) {
  if (!a || typeof a !== 'object') return a;

  const byType = {
    asn: {
      asn_number: a.asn_number,
      asn_organization: a.asn_organization,
      asn_description: a.asn_description,
      asn_country: a.asn_country,
    },
    // Only the CIDR. The asset row also has subnet_size and the two responsive counts, but the read
    // route does not select them, so listing them here would promise a caller fields that never
    // arrive.
    network_range: {
      cidr_block: a.cidr_block,
    },
    ip_address: {
      ip_address: a.ip_address,
      ip_type: a.ip_type,
    },
    live_web_server: {
      url: a.url,
      domain: a.domain,
      port: a.port,
      protocol: a.protocol,
      status_code: a.status_code,
      title: a.title,
      web_server: a.web_server,
      technologies: a.technologies,
      content_length: a.content_length,
      response_time_ms: a.response_time_ms,
    },
    cloud_asset: {
      domain: a.domain,
      cloud_provider: a.cloud_provider,
      cloud_service_type: a.cloud_service_type,
      cloud_region: a.cloud_region,
    },
    fqdn: {
      fqdn: a.fqdn,
      root_domain: a.root_domain,
      subdomain: a.subdomain,
      resolved_ips: a.resolved_ips,
      registrar: a.registrar,
    },
  };

  return clean({
    id: a.id,
    asset_type: a.asset_type,
    asset_identifier: a.asset_identifier,
    asset_subtype: a.asset_subtype,
    ...(byType[a.asset_type] || {}),
    last_updated: a.last_updated,

    ...(full ? {
      created_at: a.created_at,
      screenshot_path: a.screenshot_path,
      ssl_info: clipBlob(a.ssl_info),
      ssl_certificate: clipBlob(a.ssl_certificate),
      ssl_expiry_date: a.ssl_expiry_date,
      ssl_issuer: a.ssl_issuer,
      ssl_subject: a.ssl_subject,
      ssl_version: a.ssl_version,
      ssl_cipher_suite: a.ssl_cipher_suite,
      ssl_protocols: emptyToUndefined(a.ssl_protocols),
      http_response_headers: clipBlob(a.http_response_headers),
      findings_json: clipBlob(a.findings_json),
      whois_info: clipBlob(a.whois_info),
      creation_date: a.creation_date,
      expiration_date: a.expiration_date,
      updated_date: a.updated_date,
      name_servers: emptyToUndefined(a.name_servers),
      status: emptyToUndefined(a.status),
      mail_servers: emptyToUndefined(a.mail_servers),
      spf_record: a.spf_record,
      dkim_record: a.dkim_record,
      dmarc_record: a.dmarc_record,
      caa_records: emptyToUndefined(a.caa_records),
      txt_records: emptyToUndefined(a.txt_records),
      mx_records: emptyToUndefined(a.mx_records),
      ns_records: emptyToUndefined(a.ns_records),
      a_records: emptyToUndefined(a.a_records),
      aaaa_records: emptyToUndefined(a.aaaa_records),
      cname_records: emptyToUndefined(a.cname_records),
      ptr_records: emptyToUndefined(a.ptr_records),
      srv_records: emptyToUndefined(a.srv_records),
      soa_record: clipBlob(a.soa_record),
      dns_records: emptyToUndefined(a.dns_records),
      // What this asset hangs off, e.g. the ASN an IP sits in or the FQDN a web server serves.
      // Reading the surface as a graph rather than six flat lists starts here.
      relationships: emptyToUndefined(a.relationships),
      last_dns_scan: a.last_dns_scan,
      last_ssl_scan: a.last_ssl_scan,
      last_whois_scan: a.last_whois_scan,
    } : {}),
  });
}

function compactIdentifier(i) {
  if (!i || typeof i !== 'object') return i;
  return clean({
    id: i.id,
    endpoint_url: i.endpoint_url,
    method: i.method,
    value: clip(i.value, BLOB_LIMIT),
    source: i.source,
    label: i.label,
    created_at: i.created_at,
  });
}

// === helpers ===================================================================================

async function fetchIdentifiers(targetID) {
  const rows = await apiGet(`/authz/client-identifiers/${targetID}`);
  return Array.isArray(rows) ? rows : (rows?.identifiers || []);
}

// Shallow on purpose, applied to the rows built above rather than to anything that came back from
// the API untouched. false and 0 survive: is_direct:false and status_code:0 both mean something.
function clean(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v === null || v === undefined || v === '') continue;
    if (Array.isArray(v) && v.length === 0) continue;
    if (typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === 0) continue;
    out[k] = v;
  }
  return out;
}

// Empty arrays are noise at this volume: an asset with no TXT, MX, NS or CAA records would
// otherwise carry four empty lists per row across thousands of rows.
function emptyToUndefined(v) {
  return Array.isArray(v) && v.length ? v : undefined;
}

function clip(text, limit) {
  if (typeof text !== 'string' || !text) return undefined;
  if (text.length <= limit) return text;
  return text.slice(0, limit) + `\n... [truncated, ${text.length - limit} chars remaining]`;
}

// Whois records, SSL certificate details and captured response headers are free-form JSON written
// by whatever enrichment produced them, so they are measured serialised rather than field by field.
// Replaced wholesale when too big, because half a JSON object is worse than a string: a caller
// would parse it and act on a structure that is missing keys.
function clipBlob(blob) {
  if (!blob || typeof blob !== 'object') return undefined;
  const s = JSON.stringify(blob);
  if (s.length <= BLOB_LIMIT) return blob;
  return { truncated: true, size: s.length, preview: s.slice(0, BLOB_LIMIT) };
}

// Strips the transport wrapper off a thrown API error. "API POST /attack-surface-assets/add failed
// (500): Failed to add network range: invalid CIDR notation" is plumbing around the one clause that
// actually tells the caller what to fix.
function apiError(err) {
  const raw = String(err && err.message ? err.message : err);
  const m = raw.match(/failed \((\d+)\):\s*([\s\S]*)$/);
  return clip((m ? m[2] : raw).trim(), BLOB_LIMIT);
}

module.exports = {
  getDiscoveredEndpointsSchema, getDiscoveredEndpoints,
  manageAttackSurfaceAssetsSchema, manageAttackSurfaceAssets,
  manageClientIdentifiersSchema, manageClientIdentifiers,
};
