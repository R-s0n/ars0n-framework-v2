const { z } = require('zod');
const session = require('../guidance/session');

// ENV-gated like GOAL_GATE: default off/advisory so the model cannot thrash eviction to dodge the
// keep-hunting layer. Operator-controlled (read from the environment, not AI-callable).
const STRATEGY_GATE = String(process.env.CONTEXT_STRATEGY_GATE || 'off').toLowerCase() === 'on'
  ? 'on' : 'off';

const manageContextSchema = z.object({
  action: z.enum(['budget', 'set_strategy']).describe(
    'budget: a read-only accounting report of server-output chars by tier/topic/tool (a FLOOR, never a gate). ' +
    'set_strategy: record a hunting strategy change; when CONTEXT_STRATEGY_GATE=on it also drops STRATEGY-tier ' +
    'lessons (stop re-serving + re-teach) and returns a compaction summary. Default off is advisory.'),
  strategy: z.string().optional().describe('set_strategy: the new strategy id/label.'),
});

async function manageContext(params, extra) {
  const key = session.principalFor(extra, params);
  if (params.action === 'budget') return json(session.budget(key));
  if (params.action === 'set_strategy') {
    if (STRATEGY_GATE === 'off') {
      // Advisory: persist the label so budget().strategy reflects it, but do NOT evict (no reclaim).
      session.recordStrategy(key, params.strategy);
      return json({ gate: 'CONTEXT_STRATEGY_GATE=off (advisory)',
        note: 'Strategy recorded for the report only; no eviction performed. Operator must set the gate to on to reclaim.',
        strategy: params.strategy || null });
    }
    return json(session.setStrategy(key, params.strategy));
  }
  return json({ error: `unknown action: ${params.action}` });
}
function json(o) { return { content: [{ type: 'text', text: JSON.stringify(o, null, 2) }] }; }
module.exports = { manageContextSchema, manageContext };
