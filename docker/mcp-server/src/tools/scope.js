const { z } = require('zod');
const { apiPost, apiGet, apiPut, apiDelete } = require('../api');
const { query } = require('../db');
const { limitResults, trimScanRecords } = require('../utils/truncate');

// === Add Scope Target ===
const addTargetSchema = z.object({
  type: z.enum(['Company', 'Wildcard', 'URL']).describe('Target type: Company (org with on-prem infra), Wildcard (*.domain.com), or URL (single application)'),
  scope_target: z.string().describe('The target value (e.g. "Acme Corp", "*.example.com", "https://app.example.com")'),
  mode: z.enum(['Passive', 'Active']).optional().describe(
    'Passive (default) or Active. These are the only values the database accepts; the enum here previously read bb/pentest, which made every add_target call fail with a bare 500.')
});

async function addTarget(params) {
  const result = await apiPost('/scopetarget/add', {
    type: params.type,
    scope_target: params.scope_target,
    mode: params.mode || 'bb',
  });
  return result;
}

// === Delete Scope Target ===
const deleteTargetSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID to delete'),
});

async function deleteTarget(params) {
  const result = await apiDelete(`/scopetarget/delete/${params.target_id}`);
  return result;
}

// === Activate Scope Target ===
const activateTargetSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID to activate'),
});

async function activateTarget(params) {
  const result = await apiPost(`/scopetarget/${params.target_id}/activate`);
  return result;
}

// === Get All Scans for Target ===
const getTargetScansSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
});

async function getTargetScans(params) {
  // Trim the inline raw scan output — this endpoint returns every scan's full result and can be
  // hundreds of KB, which overflows the model context.
  const result = await apiGet(`/scopetarget/${params.target_id}/scans`);
  return trimScanRecords(result);
}

// === Update ROI Score ===
const updateRoiScoreSchema = z.object({
  url_id: z.string().uuid().describe('The target URL UUID'),
  roi_score: z.number().min(0).max(100).describe('ROI score (0-100) indicating bug bounty value'),
});

async function updateRoiScore(params) {
  const result = await apiPut(`/api/target-urls/${params.url_id}/roi-score`, {
    roi_score: params.roi_score,
  });
  return result;
}

// === Delete Target URL ===
const deleteTargetUrlSchema = z.object({
  url_id: z.string().uuid().describe('The target URL UUID to delete'),
});

async function deleteTargetUrl(params) {
  const result = await apiDelete(`/api/target-urls/${params.url_id}`);
  return result;
}

module.exports = {
  addTargetSchema, addTarget,
  deleteTargetSchema, deleteTarget,
  activateTargetSchema, activateTarget,
  getTargetScansSchema, getTargetScans,
  updateRoiScoreSchema, updateRoiScore,
  deleteTargetUrlSchema, deleteTargetUrl,
};
