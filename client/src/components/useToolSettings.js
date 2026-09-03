import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  asList,
  attributeServerMessage,
  buildSettingsPayload,
  invalidFields,
  isTruthy,
} from './toolOptionSchema';

// ONE hook behind both tool settings screens.
//
// The Wildcard modal and the Company modal had a copy each of the load / edit / validate / save
// cycle, and they had already diverged: only one of them knew about float, and only one of them knew
// about inert_when_values. Both endpoints serve the SAME option shape, so there is no honest reason
// for two implementations, and two implementations of a form that claims to be generated from one
// vocabulary is how the vocabulary stops being one.
//
// `base` is the registry: 'wildcard-tools' or 'company-tools'. Nothing else differs.

const registryCache = {};

async function loadRegistryMeanings(base) {
  if (registryCache[base]) return registryCache[base];
  const res = await fetch(`/api/${base}`);
  if (!res.ok) throw new Error('registry unavailable');
  const data = await res.json();
  registryCache[base] = {
    provenance: data.provenance_meaning || {},
    ownedFlags: data.owned_flags_meaning || '',
    note: data.note || '',
    noCommandLine: data.no_command_line_note || '',
  };
  return registryCache[base];
}

// Exported for the tests, which would otherwise see one suite's cached registry in the next.
export function resetRegistryCache() {
  Object.keys(registryCache).forEach((k) => delete registryCache[k]);
}

export function useToolSettings({ base, idPrefix, activeTarget, toolKey, show }) {
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [noticeVariant, setNoticeVariant] = useState('success');
  const [data, setData] = useState(null);
  const [meanings, setMeanings] = useState(null);
  // Held as strings (and arrays, for lists) while editing, so a half typed number is not coerced
  // under the operator's cursor. Converted on save, which is also where an empty field means "not
  // set" rather than zero.
  const [values, setValues] = useState({});
  // Which fields the operator has finished with. An error is only SHOWN for a field that was already
  // stored, that has been left, or that is standing between them and a save they just attempted.
  // Anything else would put a red message under a field somebody is still halfway through typing.
  const [touched, setTouched] = useState({});
  // The server's refusal, split across the fields it names. Cleared for a field as soon as it is
  // edited, because a refusal of a value that is no longer there is just noise.
  const [serverFieldErrors, setServerFieldErrors] = useState({});
  // Stored keys the CURRENT vocabulary has no entry for. They cannot be sent back: this endpoint
  // REFUSES an unknown key rather than storing it, so carrying them would 400 every save. They are
  // shown instead, because silently dropping a stored value is the deception this screen exists to
  // avoid.
  const [orphaned, setOrphaned] = useState([]);

  const load = useCallback(async () => {
    if (!activeTarget?.id || !toolKey) return;
    setLoading(true);
    setError('');
    setNotice('');
    setServerFieldErrors({});
    try {
      const res = await fetch(`/api/${base}/${activeTarget.id}/${toolKey}/settings`);
      // Not every failure is JSON: an api container that predates these routes answers with nginx's
      // plain text 404, and "Unexpected token < in JSON" would tell the operator nothing about that.
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(body.message
          || `Could not load these settings (HTTP ${res.status}). If this is a 404, the API does not have this tool registry yet.`);
        setData(null);
        return;
      }
      setData(body);

      const options = body.options || {};
      const editing = {};
      const seen = {};
      const unknown = [];
      Object.entries(body.settings || {}).forEach(([k, v]) => {
        const meta = options[k];
        if (!meta) { unknown.push(k); return; }
        // A value that is already STORED is a committed decision, so anything wrong with it is shown
        // straight away rather than waiting for the operator to touch a field they did not set.
        seen[k] = true;
        if (meta.kind === 'bool') { editing[k] = v === true ? 'true' : v === false ? 'false' : ''; return; }
        if (meta.kind === 'list') { editing[k] = asList(v); return; }
        editing[k] = String(v);
      });
      setValues(editing);
      setTouched(seen);
      setOrphaned(unknown.sort());
    } catch (err) {
      setError('Could not load these settings: ' + err.message);
    } finally {
      setLoading(false);
    }
  }, [base, activeTarget, toolKey]);

  useEffect(() => { if (show) load(); }, [show, load]);

  useEffect(() => {
    if (!show) return;
    loadRegistryMeanings(base).then(setMeanings).catch(() => {
      // The legend is explanatory. The form works without it, and every option still carries its own
      // provenance badge.
    });
  }, [show, base]);

  const setValue = useCallback((key, v) => {
    setValues((prev) => ({ ...prev, [key]: v }));
    setServerFieldErrors((prev) => (prev[key] ? { ...prev, [key]: '' } : prev));
  }, []);

  const markTouched = useCallback((key) => {
    setTouched((prev) => (prev[key] ? prev : { ...prev, [key]: true }));
  }, []);

  const options = useMemo(() => data?.options || {}, [data]);
  const groups = useMemo(() => data?.groups || [], [data]);
  const ownedFlags = useMemo(() => data?.owned_flags || {}, [data]);

  // What cannot take effect given what is on the form RIGHT NOW, rather than given what was last
  // saved. Declared by the vocabulary as requires_key / inert_when_key / inert_when_values, so
  // toggling the governing control un-greys the dependent field immediately instead of after a save.
  const inertReason = useCallback((key) => {
    const meta = options[key] || {};
    if (meta.requires_key && !isTruthy(values[meta.requires_key])) {
      const dep = options[meta.requires_key];
      return `Does nothing unless "${dep?.label || meta.requires_key}" is on. Turn that on to use this.`;
    }
    if (meta.inert_when_key) {
      const dep = options[meta.inert_when_key];
      const gates = meta.inert_when_values || [];
      const got = String(values[meta.inert_when_key] ?? '').trim();
      if (gates.length > 0) {
        if (gates.some((g) => String(g).toLowerCase() === got.toLowerCase())) {
          return `Does nothing while "${dep?.label || meta.inert_when_key}" is ${got}. Change that to use this.`;
        }
      } else if (isTruthy(values[meta.inert_when_key])) {
        return `Does nothing while "${dep?.label || meta.inert_when_key}" is on. Turn that off to use this.`;
      }
    }
    return '';
  }, [options, values]);

  // Everything the SERVER would refuse, worked out here so the operator is told before a round trip
  // rather than after one. The server still decides: this only stops a save that is certain to fail.
  const clientErrors = useMemo(
    () => invalidFields(options, values, (k) => Boolean(inertReason(k))),
    [options, values, inertReason],
  );

  const invalidKeys = useMemo(
    () => Object.keys(clientErrors).sort((a, b) => (options[a]?.label || a).localeCompare(options[b]?.label || b)),
    [clientErrors, options],
  );

  const serverErrorFor = useCallback((key) => serverFieldErrors[key] || '', [serverFieldErrors]);
  const isTouched = useCallback((key) => Boolean(touched[key]), [touched]);
  const errorFor = useCallback(
    (key) => serverFieldErrors[key] || (touched[key] ? clientErrors[key] || '' : ''),
    [serverFieldErrors, touched, clientErrors],
  );

  const save = useCallback(async () => {
    if (!activeTarget?.id || !toolKey) return false;
    if (Object.keys(clientErrors).length > 0) {
      // Reveal every problem at once. Silently refusing to save is the worst of both worlds.
      setTouched((prev) => {
        const next = { ...prev };
        Object.keys(clientErrors).forEach((k) => { next[k] = true; });
        return next;
      });
      return false;
    }

    setSaving(true);
    setError('');
    setNotice('');
    setServerFieldErrors({});
    try {
      // replace, not merge: this form has just shown the operator every field the vocabulary has, so
      // it IS the whole state. Merging would make a field they cleared indistinguishable from one
      // they never touched.
      const res = await fetch(`/api/${base}/${activeTarget.id}/${toolKey}/settings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ settings: buildSettingsPayload(options, values), replace: true }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        // The server refuses a framework-owned flag, an unknown key, an unacceptable value and a
        // value measured to empty a scan, each with the reason. That reason is put on the FIELD it
        // names, because that is where the operator can act on it; whatever is about the request
        // rather than about a field stays at the top.
        const message = body.message || `Could not save these settings (HTTP ${res.status}).`;
        const { fields, rest } = attributeServerMessage(message, options);
        setServerFieldErrors(fields);
        setTouched((prev) => {
          const next = { ...prev };
          Object.keys(fields).forEach((k) => { next[k] = true; });
          return next;
        });
        setError(rest || (Object.keys(fields).length === 0 ? message : ''));
        return false;
      }
      const parts = [];
      if (body.inert_warning) parts.push(body.inert_warning);
      if (body.advisory_warning) parts.push(body.advisory_warning);
      if (Array.isArray(body.compose_warnings)) parts.push(...body.compose_warnings);
      if (body.pending_wiring) parts.push(body.pending_wiring);
      // A save that came back with warnings SUCCEEDED, but it is not the same event as a clean one,
      // and colouring both green is how a compose warning goes unread.
      setNoticeVariant(parts.length ? 'warning' : 'success');
      setNotice(parts.length ? parts.join(' ') : 'Saved.');
      await load();
      return true;
    } catch (err) {
      setError('Could not save these settings: ' + err.message);
      return false;
    } finally {
      setSaving(false);
    }
  }, [base, activeTarget, toolKey, options, values, clientErrors, load]);

  // Groups in the order the SERVER declares them. Anything whose group is not in that list is still
  // rendered, in a section at the end, because an option the operator cannot see is worse than an
  // untidy screen.
  const sections = useMemo(() => {
    const byLabel = (a, b) => (options[a]?.label || a).localeCompare(options[b]?.label || b);
    const out = groups.map((g) => ({
      group: g,
      keys: Object.keys(options).filter((k) => options[k]?.group === g).sort(byLabel),
    }));
    const placed = new Set(out.flatMap((s) => s.keys));
    const stray = Object.keys(options).filter((k) => !placed.has(k)).sort(byLabel);
    if (stray.length) out.push({ group: 'Ungrouped', keys: stray });
    return out.filter((s) => s.keys.length > 0);
  }, [options, groups]);

  const configuredCount = useMemo(
    () => Object.keys(buildSettingsPayload(options, values)).length,
    [options, values],
  );

  return {
    base,
    idPrefix,
    loading,
    saving,
    error,
    notice,
    noticeVariant,
    setError,
    setNotice,
    data,
    meanings,
    values,
    setValue,
    markTouched,
    errorFor,
    serverErrorFor,
    isTouched,
    clientErrors,
    invalidKeys,
    orphaned,
    options,
    sections,
    ownedFlags,
    ownedFlagKeys: Object.keys(ownedFlags).sort(),
    inertReason,
    save,
    reload: load,
    clearAll: () => { setValues({}); setServerFieldErrors({}); },
    configuredCount,
    optionCount: Object.keys(options).length,
    hasVocabulary: Object.keys(options).length > 0,
    toolKey,
  };
}

export default useToolSettings;
