const { DOMAIN_OF } = require('./index');   // no cycle: guidance/index never requires memory

const TIERS = { PERMANENT: 'PERMANENT', SCOPE_TARGET: 'SCOPE_TARGET', STRATEGY: 'STRATEGY' };
const DEFAULT_TIER = TIERS.STRATEGY;

// tier is derived here from DOMAIN_OF; it is NEVER added to ATTACHED_FIELDS (that would ship it to the
// client and re-add the per-call token tax this feature exists to cut). Server-side bookkeeping only.
const MANIFEST = {
  head: {                                   // head fields attached in index.js attachGuidance
    keep_hunting: TIERS.PERMANENT,
    role_hint:    TIERS.PERMANENT,
    goal:         TIERS.SCOPE_TARGET,
    guidance:     TIERS.STRATEGY,
  },
  domain: {                                 // the four guidance domain files
    recon:    TIERS.SCOPE_TARGET,
    data:     TIERS.SCOPE_TARGET,
    scanning: TIERS.STRATEGY,
    workflow: TIERS.STRATEGY,
  },
  store: {                                  // durable in-repo stores
    methodology:  TIERS.PERMANENT,
    workflowbook: TIERS.PERMANENT,
  },
};

function tierOfTool(tool) {                 // (string) -> tier
  const domain = DOMAIN_OF[tool];
  return (domain && MANIFEST.domain[domain]) || DEFAULT_TIER;
}
function tierOfHead(field) {                // (string) -> tier
  return MANIFEST.head[field] || DEFAULT_TIER;
}

module.exports = { TIERS, DEFAULT_TIER, MANIFEST, tierOfTool, tierOfHead };
