const { z } = require('zod');
const { apiGet, apiPost, apiPut, apiDelete } = require('../api');

// Settings tools give an MCP client parity with the web UI's Settings modal: read + modify Rate
// Limits, Custom HTTP, Burp, recon API keys, and AI provider keys. These proxy the same Go
// endpoints the UI uses. The MCP Server section (mcp_server_config) is intentionally read-only —
// you can't safely reconfigure the MCP server through itself — so it's returned by get_settings
// but there is no tool to modify it.

const RATE_LIMIT_KEYS = [
  'amass_rate_limit', 'httpx_rate_limit', 'subfinder_rate_limit', 'gau_rate_limit',
  'sublist3r_rate_limit', 'ctl_rate_limit', 'shuffledns_rate_limit', 'cewl_rate_limit',
  'gospider_rate_limit', 'subdomainizer_rate_limit', 'nuclei_screenshot_rate_limit',
];

// Show only the last 4 characters of a secret (mirrors the Go API's masking).
function maskSecret(v) {
  if (!v || typeof v !== 'string') return v;
  if (v.length <= 4) return '*'.repeat(v.length);
  return '*'.repeat(v.length - 4) + v.slice(-4);
}

// === Read all settings ===
const getSettingsSchema = z.object({});

async function getSettings() {
  const [userSettings, apiKeys, aiApiKeys, mcpConfig] = await Promise.all([
    apiGet('/user/settings').catch((e) => ({ error: e.message })),
    apiGet('/api/api-keys').catch(() => []),
    apiGet('/api/ai-api-keys').catch(() => []),
    apiGet('/api/mcp-config').catch((e) => ({ error: e.message })),
  ]);

  const us = userSettings || {};
  const rateLimits = {};
  for (const k of RATE_LIMIT_KEYS) rateLimits[k] = us[k];

  return {
    rate_limits: rateLimits,
    custom_http: {
      custom_user_agent: us.custom_user_agent || '',
      custom_header: us.custom_header || '',
    },
    burp_suite: {
      burp_proxy_ip: us.burp_proxy_ip,
      burp_proxy_port: us.burp_proxy_port,
      burp_api_ip: us.burp_api_ip,
      burp_api_port: us.burp_api_port,
      burp_api_key: maskSecret(us.burp_api_key),
    },
    api_keys: apiKeys || [],
    ai_api_keys: aiApiKeys || [],
    mcp_server_config: {
      ...(mcpConfig || {}),
      _note: 'Read-only via MCP. Change the MCP Server settings in the web UI (Settings > MCP Server).',
    },
  };
}

// === Update user_settings (rate limits / custom HTTP / Burp) ===
// Every field optional; only what you pass is changed. NOTE: the Go endpoint full-replaces the
// row (omitted fields reset to defaults), so we read the current settings and merge before POSTing.
const updateSettingsSchema = z.object({
  amass_rate_limit: z.number().int().min(1).optional(),
  httpx_rate_limit: z.number().int().min(1).optional(),
  subfinder_rate_limit: z.number().int().min(1).optional(),
  gau_rate_limit: z.number().int().min(1).optional(),
  sublist3r_rate_limit: z.number().int().min(1).optional(),
  ctl_rate_limit: z.number().int().min(1).optional(),
  shuffledns_rate_limit: z.number().int().min(1).optional(),
  cewl_rate_limit: z.number().int().min(1).optional(),
  gospider_rate_limit: z.number().int().min(1).optional(),
  subdomainizer_rate_limit: z.number().int().min(1).optional(),
  nuclei_screenshot_rate_limit: z.number().int().min(1).optional(),
  custom_user_agent: z.string().optional(),
  custom_header: z.string().optional(),
  burp_proxy_ip: z.string().optional(),
  burp_proxy_port: z.number().int().min(1).max(65535).optional(),
  burp_api_ip: z.string().optional(),
  burp_api_port: z.number().int().min(1).max(65535).optional(),
  burp_api_key: z.string().optional(),
});

async function updateSettings(params) {
  const current = await apiGet('/user/settings');
  const merged = { ...current, ...params };
  await apiPost('/user/settings', merged);
  const out = { ...merged };
  if (out.burp_api_key) out.burp_api_key = maskSecret(out.burp_api_key);
  return { status: 'success', updated_fields: Object.keys(params), settings: out };
}

// === Recon API keys (SecurityTrails, Shodan, GitHub, Censys, etc.) ===
const setApiKeySchema = z.object({
  tool_name: z.string().describe('Tool the key is for (e.g. "SecurityTrails", "Shodan", "GitHub", "Censys")'),
  api_key_name: z.string().describe('A label for this key (unique per tool)'),
  api_key: z.string().describe('The API key value'),
  app_id: z.string().optional().describe('App ID — only for providers like Censys that use ID/secret pairs'),
  app_secret: z.string().optional().describe('App Secret — only for providers like Censys'),
});

async function setApiKey(params) {
  const keyValues = {
    api_key: params.api_key,
    app_id: params.app_id || '',
    app_secret: params.app_secret || '',
  };
  const existing = (await apiGet('/api/api-keys').catch(() => [])) || [];
  const match = existing.find(
    (k) => k.tool_name === params.tool_name && k.api_key_name === params.api_key_name
  );
  if (match) {
    // The recon-key PUT stores api_key_value as a JSON string of the key_values object.
    await apiPut(`/api/api-keys/${match.id}`, {
      api_key_name: params.api_key_name,
      api_key_value: JSON.stringify(keyValues),
    });
    return { status: 'updated', tool_name: params.tool_name, api_key_name: params.api_key_name };
  }
  await apiPost('/api/api-keys', {
    tool_name: params.tool_name,
    api_key_name: params.api_key_name,
    key_values: keyValues,
  });
  return { status: 'created', tool_name: params.tool_name, api_key_name: params.api_key_name };
}

const deleteApiKeySchema = z.object({
  id: z.string().optional().describe('The API key id (from get_settings). Or supply tool_name + api_key_name.'),
  tool_name: z.string().optional(),
  api_key_name: z.string().optional(),
});

async function deleteApiKey(params) {
  let id = params.id;
  if (!id) {
    if (!params.tool_name || !params.api_key_name) {
      return { error: 'Provide either id, or both tool_name and api_key_name.' };
    }
    const existing = (await apiGet('/api/api-keys').catch(() => [])) || [];
    const match = existing.find(
      (k) => k.tool_name === params.tool_name && k.api_key_name === params.api_key_name
    );
    if (!match) {
      return { error: `No API key found for tool_name=${params.tool_name}, api_key_name=${params.api_key_name}.` };
    }
    id = match.id;
  }
  await apiDelete(`/api/api-keys/${id}`);
  return { status: 'deleted', id };
}

// === AI provider API keys (OpenAI, Anthropic, Google, Azure OpenAI, etc.) ===
const setAiApiKeySchema = z.object({
  provider: z.string().describe('AI provider (e.g. "OpenAI", "Anthropic", "Google", "Azure OpenAI", "Mistral AI")'),
  api_key_name: z.string().describe('A label for this key (unique per provider)'),
  api_key: z.string().describe('The API key value'),
  organization_id: z.string().optional().describe('OpenAI organization id (optional)'),
  project_id: z.string().optional().describe('Google project id (optional)'),
  endpoint: z.string().optional().describe('Azure OpenAI endpoint URL (required for Azure OpenAI)'),
});

async function setAiApiKey(params) {
  const keyValues = { api_key: params.api_key };
  if (params.organization_id) keyValues.organization_id = params.organization_id;
  if (params.project_id) keyValues.project_id = params.project_id;
  if (params.endpoint) keyValues.endpoint = params.endpoint;

  const existing = (await apiGet('/api/ai-api-keys').catch(() => [])) || [];
  const match = existing.find(
    (k) => k.provider === params.provider && k.api_key_name === params.api_key_name
  );
  if (match) {
    await apiPut(`/api/ai-api-keys/${match.id}`, {
      api_key_name: params.api_key_name,
      key_values: keyValues,
    });
    return { status: 'updated', provider: params.provider, api_key_name: params.api_key_name };
  }
  await apiPost('/api/ai-api-keys', {
    provider: params.provider,
    api_key_name: params.api_key_name,
    key_values: keyValues,
  });
  return { status: 'created', provider: params.provider, api_key_name: params.api_key_name };
}

const deleteAiApiKeySchema = z.object({
  id: z.string().optional().describe('The AI API key id (from get_settings). Or supply provider + api_key_name.'),
  provider: z.string().optional(),
  api_key_name: z.string().optional(),
});

async function deleteAiApiKey(params) {
  let id = params.id;
  if (!id) {
    if (!params.provider || !params.api_key_name) {
      return { error: 'Provide either id, or both provider and api_key_name.' };
    }
    const existing = (await apiGet('/api/ai-api-keys').catch(() => [])) || [];
    const match = existing.find(
      (k) => k.provider === params.provider && k.api_key_name === params.api_key_name
    );
    if (!match) {
      return { error: `No AI API key found for provider=${params.provider}, api_key_name=${params.api_key_name}.` };
    }
    id = match.id;
  }
  await apiDelete(`/api/ai-api-keys/${id}`);
  return { status: 'deleted', id };
}

module.exports = {
  getSettingsSchema, getSettings,
  updateSettingsSchema, updateSettings,
  setApiKeySchema, setApiKey,
  deleteApiKeySchema, deleteApiKey,
  setAiApiKeySchema, setAiApiKey,
  deleteAiApiKeySchema, deleteAiApiKey,
};
