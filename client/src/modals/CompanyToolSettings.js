import { Alert, Button, Form, Spinner } from 'react-bootstrap';
import { useToolSettings } from '../components/useToolSettings';
import { ToolOptionRow, ProvenanceLegend, BlockedSaveNote } from '../components/ToolOptionField';

// Re-exported so a modal that already imports its settings parts from here keeps one import.
export { ToolOptionRow, ProvenanceLegend, BlockedSaveNote };

// The Company workflow's tool settings, rendered ENTIRELY from the server's vocabulary.
//
// Nothing here names a flag, a tool, an option or a group: the sections, the controls, their types,
// their defaults, their caveats, their provenance and the framework-owned flag list all arrive from
// GET /company-tools/{id}/{tool}/settings, which serves the same option map the MCP company tool
// reads and writes into the same rows. If you find yourself typing a flag name into this file, the
// option belongs in server/utils/companyOptions*.go instead.
//
// The state machine and the field renderer are SHARED with the Wildcard screen
// (client/src/components/useToolSettings.js and client/src/components/ToolOptionField.js). They used
// to be a copy each and the copies had already drifted.
//
// WHY THIS IS A SET OF PARTS RATHER THAN ONE MODAL. Three Company tools already have a config modal
// that selects TARGETS (AmassEnumConfigModal, DNSxConfigModal, KatanaCompanyConfigModal) and the
// on-prem scanner needed one built from scratch. Those pickers must keep working exactly as they do
// now, so the settings arrive as extra TABS beside them rather than as a second modal an operator
// has to know exists. One hook holds the state for a whole modal; each tab renders one server
// declared group of it. There is still only one vocabulary and one save.
//
// WHAT AN ALERT IS FOR ON THIS SCREEN. Almost nothing. An alert is reserved for something that is
// wrong or that makes the whole screen a lie: a refused save, and a store the runner does not read
// yet. Everything the registry measured about an option - including its `danger` sentence, which
// most options carry - is HELP TEXT, because describing a constraint is not reporting an error. The
// constraints themselves are enforced by the controls and by the server.

const ACCENT = '#dc3545';

// The first sentence of a long server note, so a permanent note can lead with a short honest line and
// keep the rest one click away. Used for Limitation, which for the on-prem scanner is the paragraph
// that answers "where are the nmap options" and must not be truncated away entirely.
const firstSentence = (text) => {
  const s = String(text || '');
  if (s.length <= 190) return { head: s, rest: '' };
  const cut = s.indexOf('. ');
  if (cut === -1 || cut > 400) return { head: s.slice(0, 190) + '...', rest: s };
  return { head: s.slice(0, cut + 1), rest: s.slice(cut + 2) };
};

// useCompanyToolSettings holds one tool's whole configuration for one target.
//
// One instance per MODAL, not per tab: every tab edits the same values object and the single save
// posts all of them, so a tab an operator never opened cannot silently drop what it contains.
export function useCompanyToolSettings({ activeTarget, toolKey, show }) {
  return useToolSettings({
    base: 'company-tools',
    idPrefix: `company-${toolKey}`,
    activeTarget,
    toolKey,
    show,
  });
}

// ---------------------------------------------------------------------------------------------
// Rendering. Every piece below draws only what the server sent.
// ---------------------------------------------------------------------------------------------

// CompanyToolStatusStrip is the part every settings tab repeats.
//
// It is deliberately short. Only two things here are alerts: a refusal, which is an error, and a
// store the runner does not read yet, which makes every field on the screen a promise the framework
// does not keep. A LIMITATION IS NOT AN ERROR - it is context about what the tool is - so it reads
// as quiet text with the long tail one click away.
export function CompanyToolStatusStrip({ ctl }) {
  const data = ctl.data;
  const limitation = firstSentence(data?.limitation);

  return (
    <>
      {ctl.error && <Alert variant="danger" className="py-2" style={{ fontSize: '0.82rem' }}>{ctl.error}</Alert>}
      {ctl.notice && (
        <Alert variant={ctl.noticeVariant} className="py-2" style={{ fontSize: '0.82rem' }}>
          {ctl.notice}
        </Alert>
      )}

      {/* Stored, but nothing reads it yet. Said on every read and every save rather than hidden,
          because a configured scan that silently runs the hardcoded command line is exactly the
          deception this store exists to prevent. */}
      {data?.runner_reads_settings === false && data?.pending_wiring && (
        <Alert variant="warning" className="py-2" style={{ fontSize: '0.78rem' }}>
          <i className="bi bi-exclamation-triangle-fill me-2" />
          {data.pending_wiring}
        </Alert>
      )}

      {ctl.orphaned.length > 0 && (
        <Alert variant="warning" className="py-2" style={{ fontSize: '0.78rem' }}>
          Stored for this target but not in the current vocabulary: <code>{ctl.orphaned.join(', ')}</code>.
          Nothing reads them, this endpoint refuses them on save, and saving will therefore remove them.
        </Alert>
      )}

      {data?.limitation && (
        <div className="text-white-50 mb-3" style={{ fontSize: '0.78rem' }}>
          {limitation.rest ? (
            <details>
              <summary style={{ cursor: 'pointer' }}>{limitation.head}</summary>
              <div className="mt-2">{limitation.rest}</div>
            </details>
          ) : limitation.head}
        </div>
      )}

      {/* nuclei is the case: its settings deliberately live in the wildcard store because ONE runner
          serves both workflows. An operator editing the same row from two screens has to be told. */}
      {data?.settings_store_note && (
        <div className="text-white-50 mb-3" style={{ fontSize: '0.78rem' }}>
          <i className="bi bi-hdd-stack me-2" />
          Stored in <code>{data.settings_store}</code>. {data.settings_store_note}
        </div>
      )}
    </>
  );
}

// CompanyToolSettingsPane is ONE server declared group: the contents of one settings tab.
export function CompanyToolSettingsPane({ ctl, group }) {
  if (ctl.loading) {
    return <div className="text-center py-5"><Spinner animation="border" variant="danger" /></div>;
  }
  const section = ctl.sections.find((s) => s.group === group);
  return (
    <>
      <CompanyToolStatusStrip ctl={ctl} />
      {!section ? (
        <div className="text-white-50" style={{ fontSize: '0.8rem' }}>
          The server sent no options for this group.
        </div>
      ) : (
        <Form noValidate>
          <h6 className="pb-2 mb-3" style={{ color: ACCENT, borderBottom: '1px solid rgba(220,53,69,0.3)' }}>
            {section.group}
            <span className="text-white-50 ms-2" style={{ fontSize: '0.75rem' }}>
              {section.keys.length} option{section.keys.length === 1 ? '' : 's'}
            </span>
          </h6>
          {section.keys.map((k) => <ToolOptionRow key={k} ctl={ctl} optionKey={k} />)}
        </Form>
      )}
    </>
  );
}

// CompanyToolReferencePane is the read-only half: what actually runs, what the framework sets
// itself and why, what these settings compose to, and what was measured about the tool.
//
// The owned flag list is here because without it the screen reads as half finished rather than as
// deliberate: an operator looking for a flag that is missing needs to be told it is refused, and why.
export function CompanyToolReferencePane({ ctl }) {
  const data = ctl.data;
  if (ctl.loading) {
    return <div className="text-center py-5"><Spinner animation="border" variant="danger" /></div>;
  }
  if (!data) {
    return <CompanyToolStatusStrip ctl={ctl} />;
  }

  return (
    <>
      <CompanyToolStatusStrip ctl={ctl} />

      {/* What this actually runs, so the vocabulary can be checked against the truth in one hop
          rather than taken on trust. */}
      <div className="mb-3 p-3 rounded" style={{ background: 'rgba(255,255,255,0.03)' }}>
        <div className="text-white-50" style={{ fontSize: '0.76rem' }}>
          {data.tool_name && <div>Tool: {data.tool_name}{data.step ? ` (step ${data.step} of the Company workflow, ${data.phase})` : ''}</div>}
          {data.container && <div>Container: <code>{data.container}</code></div>}
          {data.image && <div>Image: <code>{data.image}</code></div>}
          {data.version && <div>Version: {data.version}</div>}
          {data.invocation && <div>Runner: <code>{data.invocation}</code></div>}
          {data.settings_store && <div>Settings store: <code>{data.settings_store}</code></div>}
        </div>
        {data.note && (
          <div className="text-white-50 mt-2" style={{ fontSize: '0.76rem' }}>{data.note}</div>
        )}
      </div>

      {/* Where the "which targets" question is answered, in the server's words. An operator who
          cannot find a target picker has to be told which screen owns it, not left to conclude the
          feature is missing. */}
      {data.target_selection && (
        <div className="mb-3 p-3 rounded border" style={{ borderColor: 'rgba(255,255,255,0.08)' }}>
          <div className="text-white mb-1" style={{ fontSize: '0.8rem', fontWeight: 600 }}>
            Target selection
          </div>
          <div className="text-white-50" style={{ fontSize: '0.76rem' }}>
            {data.target_selection.table
              ? <>Owned by <code>{data.target_selection.table}</code>. </>
              : null}
            {data.target_selection.note}
          </div>
        </div>
      )}

      <ProvenanceLegend meanings={ctl.meanings} />

      {ctl.ownedFlagKeys.length > 0 && (
        <div className="mb-4">
          <h6 className="text-white-50 pb-2 mb-2" style={{ borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
            The framework sets these {ctl.ownedFlagKeys.length} value
            {ctl.ownedFlagKeys.length === 1 ? '' : 's'} itself
          </h6>
          {ctl.meanings?.ownedFlags && (
            <div className="text-white-50 mb-2" style={{ fontSize: '0.75rem' }}>
              {ctl.meanings.ownedFlags}
            </div>
          )}
          <div
            className="border rounded p-2"
            style={{ borderColor: 'rgba(255,255,255,0.08)', maxHeight: '320px', overflowY: 'auto' }}
          >
            {ctl.ownedFlagKeys.map((flag) => (
              <div key={flag} className="mb-2" style={{ fontSize: '0.74rem' }}>
                <code style={{ color: 'rgba(255,255,255,0.6)' }}>{flag}</code>
                <div className="text-white-50">{ctl.ownedFlags[flag]}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* What these settings compose to. A settings screen that cannot show what it will run is a
          screen the operator has to take on trust. Correctly empty for the tools that have no
          command line at all, which their limitation says. */}
      {ctl.hasVocabulary && Array.isArray(data.would_add_args) && (
        <div className="mb-4">
          <div className="text-white-50 mb-1" style={{ fontSize: '0.75rem' }}>
            Arguments the SAVED settings add to the command line:
          </div>
          <code className="text-break" style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.6)' }}>
            {data.would_add_args.length ? data.would_add_args.join(' ') : 'none'}
          </code>
          {Array.isArray(data.compose_warnings) && data.compose_warnings.map((wmsg, i) => (
            <div key={i} className="mt-1" style={{ fontSize: '0.74rem', color: '#ffc107' }}>{wmsg}</div>
          ))}
        </div>
      )}

      {data.notes && (
        <details>
          <summary className="text-white-50" style={{ fontSize: '0.8rem', cursor: 'pointer' }}>
            What was measured about {data.tool_name || ctl.toolKey}
          </summary>
          <div className="text-white-50 mt-2" style={{ fontSize: '0.75rem', whiteSpace: 'pre-wrap' }}>
            {data.notes}
          </div>
        </details>
      )}
    </>
  );
}

// CompanyToolSettingsFooter is the save row for the settings tabs. Deliberately separate from the
// target picker's own footer: the two save into different stores, and one button doing both would
// make a refused tool setting look like a failed target selection.
export function CompanyToolSettingsFooter({ ctl, onClose, note }) {
  const blocked = ctl.invalidKeys.length > 0;
  return (
    <div className="d-flex justify-content-between align-items-center w-100">
      <span className="text-white-50 small">
        {ctl.hasVocabulary
          ? `${ctl.configuredCount} of ${ctl.optionCount} options set`
          : 'No configurable options'}
        {/* Said out loud because the alternative is silent loss: an operator who edits the picker,
            switches tab and saves here would otherwise close the modal believing both halves were
            written. */}
        {note ? <span className="ms-2">{note}</span> : null}
        <BlockedSaveNote ctl={ctl} className="ms-2" />
      </span>
      <div className="d-flex gap-2">
        {ctl.hasVocabulary && (
          <Button variant="outline-secondary" onClick={ctl.clearAll} disabled={ctl.saving}>
            Clear all
          </Button>
        )}
        <Button variant="secondary" onClick={onClose} disabled={ctl.saving}>Close</Button>
        {ctl.hasVocabulary && (
          <Button
            variant="danger"
            onClick={ctl.save}
            disabled={ctl.saving || ctl.loading || blocked}
            title={blocked ? 'One or more values would be refused. The fields are marked.' : undefined}
          >
            {ctl.saving ? (
              <><Spinner animation="border" size="sm" className="me-2" />Saving...</>
            ) : 'Save Settings'}
          </Button>
        )}
      </div>
    </div>
  );
}
