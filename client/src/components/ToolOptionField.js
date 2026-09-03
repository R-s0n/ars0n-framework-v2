import { useState } from 'react';
import { Badge, Button, Form } from 'react-bootstrap';
import {
  asList,
  constraintSummary,
  hazardOf,
  isNumericKind,
  stepFor,
} from './toolOptionSchema';

// ONE field renderer, shared by the Wildcard and the Company settings screens.
//
// It is one file on purpose. There were two copies of this logic and they had already started to
// differ (one knew about float and min_items, the other did not), and two copies of a form that
// claims to be generated from a single server vocabulary is the exact drift the vocabulary exists to
// prevent.
//
// The control does the work. A number is a number input carrying the schema's min, max and step; an
// enum is a select built from choices, so a value outside them cannot be typed; a switch has the
// three states the store really has; a list is a list control that knows how many entries it needs.
// Validation is inline, on the field, and silent while the value is fine.

const PROVENANCE_STYLE = {
  measured: { bg: 'success', border: 'rgba(25,135,84,0.55)' },
  runner: { bg: 'info', border: 'rgba(13,202,240,0.45)' },
  unverified: { bg: 'warning', border: 'rgba(255,193,7,0.75)' },
};
export const provenanceStyle = (p) => PROVENANCE_STYLE[p] || { bg: 'secondary', border: 'rgba(255,255,255,0.15)' };

const HELP = { fontSize: '0.75rem' };
const NOTE = { fontSize: '0.74rem' };

// A switch with the three states the store really has. "Not set" is not the same answer as "off":
// several of these are hardcoded ON by the runner today, so an operator needs to be able to store an
// explicit false rather than only being able to fail to store a true.
function TriStateSwitch({ id, label, value, onChange, onBlur, disabled }) {
  const current = value === 'true' ? 'true' : value === 'false' ? 'false' : '';
  const choices = [
    { v: '', suffix: 'unset', label: 'Not set' },
    { v: 'true', suffix: 'on', label: 'On' },
    { v: 'false', suffix: 'off', label: 'Off' },
  ];
  return (
    <div className="btn-group btn-group-sm" role="group" id={id} aria-label={label}>
      {choices.map((c) => (
        <span key={c.suffix}>
          <input
            type="radio"
            className="btn-check"
            name={id}
            id={`${id}-${c.suffix}`}
            autoComplete="off"
            disabled={disabled}
            checked={current === c.v}
            onChange={() => onChange(c.v)}
            onBlur={onBlur}
          />
          <label
            className={`btn btn-sm ${current === c.v ? 'btn-danger' : 'btn-outline-secondary'}`}
            htmlFor={`${id}-${c.suffix}`}
            style={{ fontSize: '0.76rem' }}
          >
            {c.label}
          </label>
        </span>
      ))}
    </div>
  );
}

// A list of names the tool knows. Picked, never typed: both measured tools with a name list DROP an
// unrecognised name silently rather than erroring, so a free text box here would be a coverage change
// with no symptom.
function ChoiceList({ id, choices, selected, onChange, onBlur, disabled, invalid, describedBy }) {
  return (
    <div
      className="border rounded p-2"
      style={{
        borderColor: invalid ? 'var(--bs-danger)' : 'rgba(255,255,255,0.1)',
        maxHeight: '210px',
        overflowY: 'auto',
      }}
      onBlur={onBlur}
      aria-describedby={describedBy}
    >
      <div className="d-flex flex-wrap">
        {choices.map((c) => (
          <div key={c} style={{ width: '33%', minWidth: '150px' }}>
            <Form.Check
              type="checkbox"
              id={`${id}-${c}`}
              label={c}
              disabled={disabled}
              checked={selected.includes(c)}
              className="text-white-50"
              style={{ fontSize: '0.78rem' }}
              onChange={(e) => onChange(
                e.target.checked ? [...selected, c] : selected.filter((s) => s !== c),
              )}
            />
          </div>
        ))}
      </div>
      <div className="d-flex gap-3 mt-1">
        <Button
          variant="link"
          size="sm"
          className="text-white-50 p-0"
          style={{ fontSize: '0.72rem' }}
          disabled={disabled || selected.length === choices.length}
          onClick={() => onChange([...choices])}
        >
          select all
        </Button>
        <Button
          variant="link"
          size="sm"
          className="text-white-50 p-0"
          style={{ fontSize: '0.72rem' }}
          disabled={disabled || selected.length === 0}
          onClick={() => onChange([])}
        >
          clear
        </Button>
        <span className="text-white-50 ms-auto" style={{ fontSize: '0.72rem' }}>
          {selected.length === 0
            ? 'none selected, so the tool uses its own list'
            : `${selected.length} of ${choices.length} selected`}
        </span>
      </div>
    </div>
  );
}

// A list of free text entries. A textarea would be a text box that happens to be split on newlines;
// this is a control that knows it holds a list, so the count is visible, a duplicate cannot be added
// twice, and min_items has something to count.
function FreeList({ id, items, onChange, onBlur, disabled, invalid, minItems, placeholder, describedBy }) {
  const [draft, setDraft] = useState('');

  // NEWLINES SEPARATE ENTRIES; COMMAS DO NOT. Several of these lists hold values that legitimately
  // contain a comma - a header line such as `Accept: text/html,application/xhtml`, a regex with a
  // {2,3} repetition, a Shodan query - and splitting on commas would quietly turn one entry into two
  // and change what the scan sends. A pasted multi-line list still becomes one entry per line.
  const addAll = (text) => {
    const next = String(text)
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean)
      .filter((v, i, all) => all.indexOf(v) === i && !items.includes(v));
    if (next.length === 0) return false;
    onChange([...items, ...next]);
    return true;
  };

  const commit = () => { addAll(draft); setDraft(''); };

  // A single-line input silently strips newlines out of a pasted block, so a list copied from a
  // terminal would arrive as one run-together entry. Splitting it here is the only way the paste
  // does what it looks like it did.
  const onPaste = (e) => {
    const text = e.clipboardData?.getData('text') ?? '';
    if (!text.includes('\n')) return;
    e.preventDefault();
    addAll(text);
    setDraft('');
  };

  return (
    <div>
      <div className="d-flex gap-2">
        <Form.Control
          id={id}
          className="custom-input"
          size="sm"
          type="text"
          disabled={disabled}
          isInvalid={invalid}
          aria-invalid={invalid || undefined}
          aria-describedby={describedBy}
          placeholder={placeholder || 'type a value and press Enter'}
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onPaste={onPaste}
          onBlur={() => { commit(); if (onBlur) onBlur(); }}
          onKeyDown={(e) => {
            if (e.key === 'Enter') { e.preventDefault(); commit(); }
          }}
        />
        <Button variant="outline-secondary" size="sm" disabled={disabled || draft.trim() === ''} onClick={commit}>
          Add
        </Button>
      </div>
      {items.length > 0 && (
        <div className="d-flex flex-wrap gap-1 mt-2">
          {items.map((v) => (
            <span
              key={v}
              className="badge d-inline-flex align-items-center gap-1"
              style={{ background: 'rgba(255,255,255,0.08)', color: 'rgba(255,255,255,0.85)', fontWeight: 400 }}
            >
              {v}
              <button
                type="button"
                className="btn-close btn-close-white"
                style={{ fontSize: '0.5rem' }}
                aria-label={`remove ${v}`}
                disabled={disabled}
                onClick={() => onChange(items.filter((x) => x !== v))}
              />
            </span>
          ))}
        </div>
      )}
      <div className="text-white-50 mt-1" style={{ fontSize: '0.72rem' }}>
        {items.length === 0
          ? 'Empty, so the tool uses its own default.'
          : `${items.length} entr${items.length === 1 ? 'y' : 'ies'}${
            minItems !== undefined ? `, at least ${minItems} needed` : ''}`}
      </div>
    </div>
  );
}

export function ToolOptionControl({ id, meta, value, onChange, onBlur, disabled, invalid, describedBy }) {
  if (meta.kind === 'bool') {
    return (
      <TriStateSwitch
        id={id}
        label={meta.label}
        value={value}
        onChange={onChange}
        onBlur={onBlur}
        disabled={disabled}
      />
    );
  }

  if (meta.kind === 'enum') {
    const choices = meta.choices || [];
    const current = String(value ?? '');
    // A stored value the vocabulary no longer offers would otherwise render as an empty select and be
    // silently rewritten by the next save. It is kept, shown, and marked instead.
    const stray = current !== '' && !choices.includes(current);
    return (
      <Form.Select
        id={id}
        size="sm"
        className="custom-input"
        disabled={disabled}
        isInvalid={invalid}
        aria-invalid={invalid || undefined}
        aria-describedby={describedBy}
        value={current}
        onChange={(e) => onChange(e.target.value)}
        onBlur={onBlur}
      >
        <option value="">Not set</option>
        {choices.map((c) => <option key={c} value={c}>{c}</option>)}
        {stray && <option value={current}>{current} (stored, not a value this tool accepts)</option>}
      </Form.Select>
    );
  }

  if (meta.kind === 'list') {
    const items = asList(value);
    const choices = meta.choices || [];
    if (choices.length > 0) {
      return (
        <ChoiceList
          id={id}
          choices={choices}
          selected={items}
          onChange={onChange}
          onBlur={onBlur}
          disabled={disabled}
          invalid={invalid}
          describedBy={describedBy}
          minItems={meta.min_items}
        />
      );
    }
    return (
      <FreeList
        id={id}
        items={items}
        onChange={onChange}
        onBlur={onBlur}
        disabled={disabled}
        invalid={invalid}
        describedBy={describedBy}
        minItems={meta.min_items}
      />
    );
  }

  const numeric = isNumericKind(meta.kind);
  return (
    <Form.Control
      id={id}
      className="custom-input"
      size="sm"
      type={numeric ? 'number' : 'text'}
      step={stepFor(meta)}
      min={numeric && meta.min !== undefined ? meta.min : undefined}
      max={numeric && meta.max !== undefined ? meta.max : undefined}
      disabled={disabled}
      isInvalid={invalid}
      aria-invalid={invalid || undefined}
      aria-describedby={describedBy}
      placeholder="not set"
      value={value ?? ''}
      onChange={(e) => onChange(e.target.value)}
      onBlur={onBlur}
    />
  );
}

// ToolOptionField is one option: what it is, the control for it, what is wrong with it right now,
// and everything the registry measured about it.
//
// The order below is the order an operator needs it in. What is WRONG comes first, because it is the
// only part that asks them to do something. Everything else is help text - the same size, the same
// colour, no icons and no boxes - because it is context, not a problem.
export function ToolOptionField({
  idPrefix,
  optionKey,
  meta,
  value,
  onChange,
  onBlur,
  inertReason,
  clientError,
  serverError,
  advisory,
  provenanceMeaning,
  showError,
}) {
  const id = `${idPrefix}-${optionKey}`;
  const style = provenanceStyle(meta.provenance);
  const disabled = Boolean(inertReason);
  const problem = serverError || (showError ? clientError : '');
  const range = constraintSummary(meta);
  // An inert field is already disabled and already explained. A second, louder note on top of that
  // would be a warning about a control the operator cannot even reach.
  const hazard = disabled ? null : hazardOf(meta);

  return (
    <div
      className="mb-3 ps-3"
      style={{ borderLeft: `3px solid ${style.border}`, opacity: disabled ? 0.55 : 1 }}
    >
      <div className="d-flex align-items-baseline gap-2 mb-1 flex-wrap">
        {/* A switch is a group of three radios rather than one control, so the label names the group
            instead of pointing at whichever radio happens to be first. */}
        <Form.Label
          htmlFor={meta.kind === 'bool' ? undefined : id}
          className="text-white mb-0"
          style={{ fontSize: '0.88rem', fontWeight: 600 }}
        >
          {meta.label || optionKey}
        </Form.Label>
        {meta.flag && (
          <code style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.4)' }}>{meta.flag}</code>
        )}
        <code style={{ fontSize: '0.7rem', color: 'rgba(255,255,255,0.25)' }}>{optionKey}</code>
        {meta.provenance && (
          <Badge
            bg={style.bg}
            text={style.bg === 'warning' ? 'dark' : undefined}
            style={{ fontSize: '0.62rem' }}
            title={provenanceMeaning || ''}
          >
            {meta.provenance}
          </Badge>
        )}
        {meta.unit && (
          <span className="text-white-50" style={{ fontSize: '0.72rem' }}>in {meta.unit}</span>
        )}
        {range && (
          <span className="text-white-50" style={{ fontSize: '0.72rem' }}>({range})</span>
        )}
        {!meta.flag && (
          <span
            className="text-white-50"
            style={{ fontSize: '0.7rem' }}
            title="No command-line flag: this changes what the runner does, not what it passes."
          >
            no flag
          </span>
        )}
      </div>

      <ToolOptionControl
        id={id}
        meta={meta}
        value={value}
        onChange={onChange}
        onBlur={onBlur}
        disabled={disabled}
        invalid={Boolean(problem)}
        describedBy={problem ? `${id}-error` : undefined}
      />

      {/* The only red on this screen, and only while the value is actually wrong. The server's own
          refusal is preferred over the client's guess at it, because the server is the authority. */}
      {problem && (
        <div
          id={`${id}-error`}
          className="invalid-feedback d-block"
          data-testid={`error-${optionKey}`}
          style={NOTE}
        >
          {problem}
        </div>
      )}

      {/* Inert: the control is disabled, and this is the one quiet line saying what to turn on. */}
      {inertReason && (
        <div className="text-white-50 mt-1" style={NOTE}>{inertReason}</div>
      )}

      {/* The sparing case. Not an Alert, not a box: one line, for an option that acts on the live
          estate, throws real findings away, or silently defeats another setting. */}
      {hazard && (
        <div className="mt-1 d-flex gap-2" style={{ ...NOTE, color: '#ffc107' }}>
          <i className="bi bi-exclamation-triangle-fill" style={{ lineHeight: '1.4' }} />
          <span><strong>{hazard.label}.</strong> {hazard.text}</span>
        </div>
      )}

      {meta.placeholder && (
        <div className="text-white-50 mt-1" style={HELP}>
          <span style={{ color: 'rgba(255,255,255,0.75)' }}>If you leave this alone: </span>
          {meta.placeholder}
        </div>
      )}

      {meta.why && <div className="text-white-50 mt-1" style={HELP}>{meta.why}</div>}

      {/* The measured caveat. It is kept in full - it is expensive knowledge and most of these
          screens' value is in it - but it is help text, because describing a constraint is not the
          same thing as reporting an error. */}
      {meta.danger && !hazard && (
        <div className="text-white-50 mt-1" style={HELP}>{meta.danger}</div>
      )}

      {meta.shadowed_by && (
        <div className="text-white-50 mt-1" style={HELP}>
          Competes with the existing setting <code>{meta.shadowed_by}</code>. Two screens can disagree
          about this value.
        </div>
      )}

      {/* Reported by the server against the SAVED settings: in effect, and doing something other than
          what it looks like. Distinct from inert on purpose - an inert option does NOTHING, an
          advisory option does something else. */}
      {advisory && (
        <div className="mt-1" style={{ ...NOTE, color: '#0dcaf0' }}>{advisory}</div>
      )}
    </div>
  );
}

// ToolOptionRow binds the field renderer to one control object from useToolSettings, so neither
// settings screen has to know how a field is put together. Both screens use this exact component.
export function ToolOptionRow({ ctl, optionKey }) {
  const meta = ctl.options[optionKey] || {};
  // A click on a switch, a select or a tick box IS the finished interaction; there is no half-typed
  // state to protect anyone from, so anything wrong with the result is said immediately. Text and
  // number fields wait for the operator to leave them, because marking "7" as too small while they
  // are on their way to "70" is the same nagging this screen was rebuilt to stop.
  const commitsOnChange = meta.kind === 'bool' || meta.kind === 'enum' || meta.kind === 'list';
  return (
    <ToolOptionField
      idPrefix={ctl.idPrefix}
      optionKey={optionKey}
      meta={meta}
      value={ctl.values[optionKey]}
      onChange={(v) => {
        ctl.setValue(optionKey, v);
        if (commitsOnChange) ctl.markTouched(optionKey);
      }}
      onBlur={() => ctl.markTouched(optionKey)}
      inertReason={ctl.inertReason(optionKey)}
      clientError={ctl.clientErrors[optionKey]}
      serverError={ctl.serverErrorFor(optionKey)}
      showError={ctl.isTouched(optionKey)}
      advisory={ctl.data?.advisories?.[optionKey]}
      provenanceMeaning={ctl.meanings?.provenance?.[meta.provenance] || ''}
    />
  );
}

// ProvenanceLegend is the server's own definition of each provenance value. Without it "unverified"
// is just a colour.
export function ProvenanceLegend({ meanings }) {
  if (!meanings?.provenance) return null;
  return (
    <div className="mb-3 p-2 rounded border" style={{ borderColor: 'rgba(255,255,255,0.08)' }}>
      {Object.entries(meanings.provenance).map(([name, why]) => (
        <div key={name} className="d-flex gap-2 mb-1" style={{ fontSize: '0.73rem' }}>
          <Badge
            bg={provenanceStyle(name).bg}
            text={provenanceStyle(name).bg === 'warning' ? 'dark' : undefined}
            style={{ fontSize: '0.62rem', height: 'fit-content' }}
          >
            {name}
          </Badge>
          <span className="text-white-50">{why}</span>
        </div>
      ))}
    </div>
  );
}

// BlockedSaveNote names what is standing between the operator and a save, so a disabled button is
// never a dead end. It says WHICH fields, because on a screen with forty options "something is
// invalid" is not an answer.
export function BlockedSaveNote({ ctl, className = '' }) {
  if (ctl.invalidKeys.length === 0) return null;
  const names = ctl.invalidKeys.map((k) => ctl.options[k]?.label || k);
  return (
    <span className={`text-danger ${className}`} style={{ fontSize: '0.76rem' }}>
      <i className="bi bi-exclamation-circle me-1" />
      Fix {names.slice(0, 3).join(', ')}
      {names.length > 3 ? ` and ${names.length - 3} more` : ''} to save.
    </span>
  );
}

export default ToolOptionField;
