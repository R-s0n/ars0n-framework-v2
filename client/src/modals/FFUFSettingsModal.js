import { Modal, Button, Form, Spinner, Alert, Nav } from 'react-bootstrap';
import { useState, useEffect, useCallback, useMemo } from 'react';

// Flow-wide ffuf settings: what every step of this target's flow does unless the step says otherwise.
//
// THE FORM IS GENERATED FROM THE SERVER'S OWN VOCABULARY. Nothing here lists ffuf's options: the
// controls, their types, their groups and their documentation all arrive from GET /fuzz/{id}/settings,
// which serves the same FuzzOptionKeys the composer reads and the same store manage_fuzz writes. A
// hand-written form would be a second copy of that list, and the two only have to disagree once for
// an operator to set something in this modal that no scan ever reads.
//
// It is also why a setting changed here is visible to the MCP server immediately and the other way
// round. There is one store, not a UI copy and an agent copy.

const ACCENT = '#dc3545';

// Groups the server serves that this modal does not show.
//
// This screen is ffuf's flags. "Framework" holds the framework's own switches (evidence capture,
// session tokens, the noise guard), which are not ffuf settings and are set per step in Configure or
// through manage_fuzz. "Refused" holds the options this composer cannot honour, which are still
// refused on save and still documented in the option reference; a tab of permanently disabled
// controls is not information, it is furniture.
const HIDDEN_GROUPS = new Set(['Framework', 'Refused']);

// The server sends every option including the ones the composer refuses. They are shown, disabled,
// with the reason: a setting that cannot work needs to be visible as impossible rather than absent
// and quietly wished for.
const isRefused = (meta) => meta?.kind === 'unsupported';

function FFUFSettingsModal({ show, handleClose, activeTarget }) {
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [docs, setDocs] = useState({});
  const [meta, setMeta] = useState({});
  const [groups, setGroups] = useState([]);
  const [overrides, setOverrides] = useState({});
  const [stepCount, setStepCount] = useState(0);
  const [note, setNote] = useState('');
  const [tab, setTab] = useState('');
  // Values are held as STRINGS while editing, so a half-typed number is not repeatedly coerced under
  // the operator's cursor. They are converted on save, which is also where empty means "not set".
  const [values, setValues] = useState({});
  // Settings this modal does not display: the hidden groups, and any key it has no metadata for.
  //
  // They are carried through a save UNTOUCHED. This form saves with replace, because a field the
  // operator cleared has to be distinguishable from one they never touched; without this, opening the
  // modal and pressing Save would DELETE a noiseGuard or a captureEvidence set through manage_fuzz,
  // simply because the modal never drew it.
  const [carried, setCarried] = useState({});

  const load = useCallback(async () => {
    if (!activeTarget) return;
    setLoading(true);
    setError('');
    setNotice('');
    try {
      const res = await fetch(`/api/fuzz/${activeTarget.id}/settings`);
      if (!res.ok) {
        setError('Could not load the ffuf settings for this target.');
        return;
      }
      const data = await res.json();
      setDocs(data.options || {});
      setMeta(data.meta || {});
      setGroups(data.groups || []);
      setOverrides(data.step_overrides || {});
      setStepCount(data.step_count || 0);
      setNote(data.note || '');
      const shown = (data.groups || []).filter((g) => !HIDDEN_GROUPS.has(g));
      setTab((prev) => (shown.includes(prev) ? prev : shown[0] || ''));

      const asText = {};
      const keep = {};
      Object.entries(data.settings || {}).forEach(([k, v]) => {
        const group = (data.meta || {})[k]?.group;
        if (!group || HIDDEN_GROUPS.has(group)) {
          keep[k] = v;
          return;
        }
        asText[k] = typeof v === 'boolean' ? v : String(v);
      });
      setValues(asText);
      setCarried(keep);
    } catch (err) {
      setError('Could not load the ffuf settings: ' + err.message);
    } finally {
      setLoading(false);
    }
  }, [activeTarget]);

  useEffect(() => { if (show) load(); }, [show, load]);

  const setValue = (key, v) => setValues((prev) => ({ ...prev, [key]: v }));

  const clearAll = () => setValues({});

  const save = async () => {
    if (!activeTarget) return;
    setSaving(true);
    setError('');
    setNotice('');
    try {
      // Converted here rather than as the operator types. An empty field means the setting is not
      // set, which is different from zero: threads 0 is a value ffuf would be given, and a blank
      // threads box means "let the step or ffuf decide".
      // Anything this modal did not draw goes back exactly as it arrived.
      const payload = { ...carried };
      Object.entries(values).forEach(([key, raw]) => {
        const kind = meta[key]?.kind;
        if (isRefused(meta[key])) return;
        if (kind === 'bool') {
          if (raw === true || raw === false) payload[key] = raw;
          return;
        }
        const text = String(raw ?? '').trim();
        if (text === '') return;
        payload[key] = kind === 'int' ? Number(text) : text;
      });

      // replace, not merge: this form has just shown every field, so it IS the whole state. Merging
      // would make a field the operator cleared indistinguishable from one they never touched.
      const res = await fetch(`/api/fuzz/${activeTarget.id}/settings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ settings: payload, replace: true }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.message || 'Could not save these settings.');
        return;
      }
      setNotice(data.warning || 'Saved. Every ffuf step that does not set these itself now uses them.');
      await load();
    } catch (err) {
      setError('Could not save these settings: ' + err.message);
    } finally {
      setSaving(false);
    }
  };

  const renderControl = (key) => {
    const m = meta[key] || {};
    const doc = docs[key] || '';
    const overriddenBy = overrides[key] || [];
    const refused = isRefused(m);

    let control;
    if (refused) {
      control = (
        <Form.Control size="sm" disabled value="not available" readOnly />
      );
    } else if (m.kind === 'bool') {
      control = (
        <Form.Check
          type="switch"
          id={`ffuf-setting-${key}`}
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
    } else {
      control = (
        <Form.Control
          className="custom-input"
          size="sm"
          type={m.kind === 'int' ? 'number' : 'text'}
          min={m.kind === 'int' ? 0 : undefined}
          placeholder={m.placeholder || 'not set'}
          value={values[key] ?? ''}
          onChange={(e) => setValue(key, e.target.value)}
        />
      );
    }

    return (
      <div key={key} className="mb-3">
        <div className="d-flex align-items-baseline gap-2 mb-1">
          <span className="text-white" style={{ fontSize: '0.85rem', fontWeight: 600 }}>
            {m.label || key}
          </span>
          {m.flag && (
            <code style={{ fontSize: '0.7rem', color: 'rgba(255,255,255,0.35)' }}>{m.flag}</code>
          )}
          <code style={{ fontSize: '0.7rem', color: 'rgba(255,255,255,0.25)' }}>{key}</code>
        </div>
        {control}
        {/* The server's own words for this option, not a paraphrase. This is the same text the agent
            reads through option_reference, which is the point: one explanation, one behaviour. */}
        <div className="text-white-50 mt-1" style={{ fontSize: '0.7rem', lineHeight: 1.35 }}>
          {doc}
        </div>
        {overriddenBy.length > 0 && (
          <div className="mt-1" style={{ fontSize: '0.7rem', color: ACCENT }}>
            Overridden by {overriddenBy.length === 1 ? 'step' : 'steps'} {overriddenBy.join(', ')}, which
            set this themselves and win over the default.
          </div>
        )}
      </div>
    );
  };

  const keysInGroup = useCallback((group) => Object.keys(meta)
    .filter((k) => meta[k].group === group)
    .sort((a, b) => (meta[a].label || a).localeCompare(meta[b].label || b)), [meta]);

  // How many settings each tab currently holds a value for. Without it, finding which of nine tabs a
  // setting was left on means opening all nine.
  const setCounts = useMemo(() => {
    const counts = {};
    Object.keys(values).forEach((key) => {
      const v = values[key];
      const isSet = typeof v === 'boolean' ? v : String(v ?? '').trim() !== '';
      if (!isSet) return;
      const group = meta[key]?.group;
      if (group) counts[group] = (counts[group] || 0) + 1;
    });
    return counts;
  }, [values, meta]);

  const tabs = useMemo(
    () => groups.filter((g) => !HIDDEN_GROUPS.has(g) && keysInGroup(g).length > 0),
    [groups, keysInGroup],
  );

  return (
    <Modal
      data-bs-theme="dark"
      show={show}
      onHide={handleClose}
      size="xl"
      dialogClassName="modal-90w"
      scrollable
    >
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">FFUF Settings</Modal.Title>
      </Modal.Header>

      <Modal.Body>
        {loading ? (
          <div className="text-center py-5">
            <Spinner animation="border" variant="danger" />
          </div>
        ) : (
          <>
            <div className="text-white-50 mb-3" style={{ fontSize: '0.8rem' }}>
              {note}
              {stepCount > 0 && (
                <> Currently {stepCount} ffuf step{stepCount === 1 ? '' : 's'} in this flow.</>
              )}
            </div>

            {error && <Alert variant="danger" className="py-2">{error}</Alert>}
            {notice && (
              <Alert variant="dark" className="py-2 text-white-50"
                style={{ border: `1px solid ${ACCENT}` }}>{notice}</Alert>
            )}

            {/* One tab per category rather than one long scroll: these are nine unrelated groups of
                knobs, and finding the filters by scrolling past the connection settings is not
                reading, it is hunting. */}
            <Nav
              variant="tabs"
              activeKey={tab}
              onSelect={(k) => k && setTab(k)}
              className="mb-3 flex-nowrap"
              style={{ overflowX: 'auto', borderBottom: '1px solid rgba(255,255,255,0.12)' }}
            >
              {tabs.map((group) => (
                <Nav.Item key={group}>
                  <Nav.Link eventKey={group} style={{ whiteSpace: 'nowrap' }}>
                    {group}
                    {setCounts[group] > 0 && (
                      <span
                        className="ms-2"
                        style={{
                          fontSize: '0.68rem', padding: '0.05rem 0.4rem', borderRadius: '0.6rem',
                          backgroundColor: ACCENT, color: '#fff',
                        }}
                      >{setCounts[group]}</span>
                    )}
                  </Nav.Link>
                </Nav.Item>
              ))}
            </Nav>

            {/* Three columns on a wide modal, so even the largest group is one screenful and the
                modal does not resize as tabs are switched. */}
            <div className="row g-4" style={{ minHeight: '46vh' }}>
              {[0, 1, 2].map((column) => (
                <div className="col-xl-4 col-lg-6" key={column}>
                  {keysInGroup(tab).filter((_, i) => i % 3 === column).map(renderControl)}
                </div>
              ))}
            </div>
          </>
        )}
      </Modal.Body>

      <Modal.Footer className="d-flex justify-content-between">
        <Button variant="outline-secondary" size="sm" onClick={clearAll} disabled={loading || saving}>
          Clear all
        </Button>
        <div className="d-flex gap-2">
          <Button variant="outline-secondary" onClick={handleClose}>Close</Button>
          <Button variant="danger" onClick={save} disabled={loading || saving || !activeTarget}>
            {saving ? <Spinner animation="border" size="sm" /> : 'Save Settings'}
          </Button>
        </div>
      </Modal.Footer>
    </Modal>
  );
}

export default FFUFSettingsModal;
