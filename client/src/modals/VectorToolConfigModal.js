import { Modal, Button, Form, Spinner, Alert, Nav, Badge } from 'react-bootstrap';
import { useState, useEffect, useCallback, useMemo } from 'react';

// One XSS tool's settings, for one target.
//
// THE FORM IS GENERATED FROM THE SERVER'S VOCABULARY. Nothing in this file lists a flag: the
// controls, their types, their groups and their placeholder text all arrive from
// GET /xss/{id}/{tool}/settings, which serves the same option map the command composer reads and the
// same store manage_xss writes. A hand-written form would be a second copy of that list, and the two
// only have to disagree once for an operator to set something here that no scan ever reads.
//
// That shared store is also why a change made here is visible to the MCP server immediately, and the
// other way round. There is one copy, not a UI copy and an agent copy.

const ACCENT = '#dc3545';

const POINT_LABEL = {
  query: 'query', body: 'body', header: 'header', cookie: 'cookie', path: 'path',
};

function VectorToolConfigModal({ show, handleClose, activeTarget, tool, category }) {
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [meta, setMeta] = useState({});
  const [groups, setGroups] = useState([]);
  const [eligibility, setEligibility] = useState(null);
  const [note, setNote] = useState('');
  const [tab, setTab] = useState('');
  // Held as strings while editing, so a half-typed number is not coerced under the operator's
  // cursor. Converted on save, which is also where empty means "not set" rather than zero.
  const [values, setValues] = useState({});
  // Anything the server sent that this modal has no metadata for. Carried through a save untouched:
  // this form saves with replace, so without it, opening the modal and pressing Save would DELETE a
  // key set through manage_xss simply because the modal never drew it.
  const [carried, setCarried] = useState({});

  const toolKey = tool?.key;

  const load = useCallback(async () => {
    if (!activeTarget || !toolKey) return;
    setLoading(true);
    setError('');
    setNotice('');
    try {
      const res = await fetch(`/api/${category}/${activeTarget.id}/${toolKey}/settings`);
      if (!res.ok) {
        setError(`Could not load the ${tool?.name || toolKey} settings for this target.`);
        return;
      }
      const data = await res.json();
      const options = data.options || {};
      setMeta(options);
      setGroups(data.groups || []);
      setEligibility(data.eligibility || null);
      setNote(data.note || '');
      setTab((prev) => ((data.groups || []).includes(prev) ? prev : (data.groups || [])[0] || ''));

      const asText = {};
      const keep = {};
      Object.entries(data.settings || {}).forEach(([k, v]) => {
        if (!options[k]) { keep[k] = v; return; }
        if (typeof v === 'boolean') { asText[k] = v; return; }
        // A repeatable option is stored as an array and edited as one value per line, because that
        // is the only shape in which a value containing a comma survives the round trip.
        asText[k] = Array.isArray(v) ? v.join('\n') : String(v);
      });
      setValues(asText);
      setCarried(keep);
    } catch (err) {
      setError('Could not load these settings: ' + err.message);
    } finally {
      setLoading(false);
    }
  }, [activeTarget, toolKey, tool, category]);

  useEffect(() => { if (show) load(); }, [show, load]);

  const setValue = (key, v) => setValues((prev) => ({ ...prev, [key]: v }));

  const save = async () => {
    if (!activeTarget || !toolKey) return;
    setSaving(true);
    setError('');
    setNotice('');
    try {
      const payload = { ...carried };
      Object.entries(values).forEach(([key, raw]) => {
        const m = meta[key];
        if (!m) return;
        if (m.kind === 'bool') {
          if (raw === true) payload[key] = true;
          return;
        }
        const text = String(raw ?? '').trim();
        if (text === '') return;
        if (m.repeatable) {
          const items = text.split('\n').map((s) => s.trim()).filter(Boolean);
          if (items.length) payload[key] = items;
          return;
        }
        if (m.kind === 'int') { payload[key] = parseInt(text, 10); return; }
        if (m.kind === 'float') { payload[key] = parseFloat(text); return; }
        payload[key] = text;
      });

      // replace, not merge: this form has just shown every field, so it IS the whole state. Merging
      // would make a field the operator cleared indistinguishable from one they never touched.
      const res = await fetch(`/api/${category}/${activeTarget.id}/${toolKey}/settings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ settings: payload, replace: true }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.message || 'Could not save these settings.');
        return;
      }
      // The blinding warning wins over the generic one. It is the only message here that says the
      // scan will now report clean for vectors it never sent.
      setNotice(data.blinded_warning || data.warning || 'Saved.');
      await load();
    } catch (err) {
      setError('Could not save these settings: ' + err.message);
    } finally {
      setSaving(false);
    }
  };

  const renderControl = (key) => {
    const m = meta[key] || {};

    let control;
    if (m.kind === 'bool') {
      control = (
        <Form.Check
          type="switch"
          id={`xss-${toolKey}-${key}`}
          checked={values[key] === true}
          label={values[key] === true ? 'on' : (m.placeholder ? `default: ${m.placeholder}` : 'off')}
          onChange={(e) => setValue(key, e.target.checked ? true : undefined)}
          className="text-white-50"
        />
      );
    } else if (m.kind === 'enum') {
      control = (
        <Form.Select
          size="sm"
          value={values[key] ?? ''}
          onChange={(e) => setValue(key, e.target.value || undefined)}
        >
          <option value="">{m.placeholder ? `default: ${m.placeholder}` : 'not set'}</option>
          {(m.choices || []).map((c) => <option key={c} value={c}>{c}</option>)}
        </Form.Select>
      );
    } else if (m.repeatable) {
      control = (
        <Form.Control
          className="custom-input"
          size="sm"
          as="textarea"
          rows={2}
          placeholder={m.placeholder ? `${m.placeholder} (one per line)` : 'one per line'}
          value={values[key] ?? ''}
          onChange={(e) => setValue(key, e.target.value)}
        />
      );
    } else {
      control = (
        <Form.Control
          className="custom-input"
          size="sm"
          type={m.kind === 'int' || m.kind === 'float' ? 'number' : 'text'}
          step={m.kind === 'float' ? '0.1' : undefined}
          placeholder={m.placeholder || 'not set'}
          value={values[key] ?? ''}
          onChange={(e) => setValue(key, e.target.value)}
        />
      );
    }

    return (
      <div key={key} className="mb-3">
        <div className="d-flex align-items-baseline gap-2 mb-1 flex-wrap">
          <span className="text-white" style={{ fontSize: '0.85rem', fontWeight: 600 }}>
            {m.label || key}
          </span>
          {m.flag && (
            <code style={{ fontSize: '0.7rem', color: 'rgba(255,255,255,0.35)' }}>{m.flag}</code>
          )}
          <code style={{ fontSize: '0.7rem', color: 'rgba(255,255,255,0.25)' }}>{key}</code>
        </div>
        {control}
        {m.choices && m.kind === 'csv' && (
          <div className="text-white-50 mt-1" style={{ fontSize: '0.7rem' }}>
            Comma separated. Options: {m.choices.join(', ')}
          </div>
        )}
      </div>
    );
  };

  const keysInTab = useMemo(
    () => Object.keys(meta).filter((k) => meta[k]?.group === tab).sort(
      (a, b) => (meta[a].label || a).localeCompare(meta[b].label || b)),
    [meta, tab],
  );

  const blinded = eligibility?.blinded || {};
  const hasBlinding = Object.keys(blinded).length > 0;

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="xl" scrollable>
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">{tool?.name || 'XSS tool'} settings</Modal.Title>
      </Modal.Header>
      <Modal.Body style={{ minHeight: '60vh' }}>
        {loading ? (
          <div className="text-center py-5"><Spinner animation="border" variant="danger" /></div>
        ) : (
          <>
            {error && <Alert variant="danger" className="py-2">{error}</Alert>}
            {notice && <Alert variant="secondary" className="py-2">{notice}</Alert>}

            {/* What a scan with these settings would actually cover. On the settings screen rather
                than only on the results screen, because it is these controls that change it. */}
            {eligibility && (
              <div className="mb-3 p-3 rounded" style={{ background: 'rgba(255,255,255,0.03)' }}>
                <div className="d-flex align-items-baseline gap-3 flex-wrap">
                  <span className="text-white" style={{ fontSize: '1.4rem', fontWeight: 600 }}>
                    {eligibility.eligible}
                    <span className="text-white-50" style={{ fontSize: '1rem' }}>
                      {' '}of {eligibility.total}
                    </span>
                  </span>
                  <span className="text-white-50" style={{ fontSize: '0.8rem' }}>
                    attack vectors can be tested by {tool?.name}
                  </span>
                  {(eligibility.reachable || []).map((p) => (
                    <Badge key={p} bg="dark" className="text-white-50 border border-secondary">
                      {POINT_LABEL[p] || p}
                    </Badge>
                  ))}
                </div>
                {eligibility.limitation && (
                  <div className="text-white-50 mt-2" style={{ fontSize: '0.78rem' }}>
                    {eligibility.limitation}
                  </div>
                )}
                {hasBlinding && (
                  <Alert variant="warning" className="py-2 mt-2 mb-0" style={{ fontSize: '0.78rem' }}>
                    {Object.entries(blinded).map(([point, keys]) => (
                      <div key={point}>
                        {keys.join(' and ')}{' '}
                        {point === 'all'
                          ? 'stops this tool sending payloads at all.'
                          : `makes every ${point} vector untestable.`}
                        {' '}Those vectors are reported as skipped rather than clean.
                      </div>
                    ))}
                  </Alert>
                )}
              </div>
            )}

            <Nav variant="tabs" activeKey={tab} onSelect={(k) => k && setTab(k)} className="mb-3">
              {groups.map((g) => {
                const count = Object.keys(meta).filter(
                  (k) => meta[k]?.group === g && values[k] !== undefined && values[k] !== '',
                ).length;
                return (
                  <Nav.Item key={g}>
                    <Nav.Link
                      eventKey={g}
                      style={tab === g ? { color: ACCENT, borderColor: 'rgba(220,53,69,0.4)' } : {}}
                    >
                      {g}
                      {count > 0 && (
                        <span className="ms-2 text-white-50" style={{ fontSize: '0.7rem' }}>
                          {count}
                        </span>
                      )}
                    </Nav.Link>
                  </Nav.Item>
                );
              })}
            </Nav>

            <Form>{keysInTab.map(renderControl)}</Form>

            {note && (
              <div className="text-white-50 mt-3" style={{ fontSize: '0.75rem' }}>{note}</div>
            )}
          </>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="outline-secondary" onClick={() => setValues({})} disabled={saving}>
          Clear all
        </Button>
        <Button variant="outline-secondary" onClick={handleClose} disabled={saving}>Close</Button>
        <Button variant="danger" onClick={save} disabled={saving || loading}>
          {saving ? 'Saving...' : 'Save'}
        </Button>
      </Modal.Footer>
    </Modal>
  );
}

export default VectorToolConfigModal;
