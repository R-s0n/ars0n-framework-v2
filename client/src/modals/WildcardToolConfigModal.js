import { Modal, Button, Form, Spinner, Alert } from 'react-bootstrap';
import { useToolSettings } from '../components/useToolSettings';
import {
  ToolOptionRow,
  ProvenanceLegend,
  BlockedSaveNote,
} from '../components/ToolOptionField';

// One Wildcard workflow tool's settings, for one target.
//
// THE FORM IS GENERATED FROM THE SERVER'S VOCABULARY. Nothing in this file names a flag, a tool or an
// option: the sections, the controls, their types, their defaults, their caveats and the
// framework-owned flag list all arrive from GET /wildcard-tools/{id}/{tool}/settings, which serves the
// same option map the MCP wildcard tool reads and writes into the same rows.
//
// That is the whole point of the design the operator asked for: "it is just ONE configuration, but it
// can be changed both ways". A hand-written form here would be a SECOND copy of that vocabulary, and
// two copies only have to disagree once for an operator to set something on this screen that no scan
// ever reads. If you find yourself typing a flag name into this file, the option belongs in
// server/utils/wildcardOptions.go instead.
//
// The state machine and the field renderer are the SAME ones the Company screen uses
// (client/src/components/useToolSettings.js, client/src/components/ToolOptionField.js). They were a
// copy each and the copies had already drifted, which for a screen whose entire claim is "there is
// only one configuration" is the one defect that matters.
//
// The three things this screen exists to make visible, all of which are measured rather than assumed:
//   - what NOT setting an option does, because an empty field is a decision, not a gap;
//   - PROVENANCE, because an option nobody proved must not look like one that was probed;
//   - what an option really costs, because the dominant failure mode in this workflow is not an
//     error: it is a tool that exits 0, prints nothing, and gets stored as a clean scan.
//
// That last one is help text, not an error. It used to render as an <Alert variant="danger"> under
// every option that carried one, which on the live registry is 130 of 175 options - a wall of red
// under a tool that was working perfectly, describing constraints the server already enforces. The
// constraints are now enforced by the CONTROLS and validated inline; the measured prose stayed.

const ACCENT = '#dc3545';

function WildcardToolConfigModal({ show, handleClose, activeTarget, tool, onDelegate }) {
  const toolKey = tool?.key;
  // The card's label is only a fallback for the moment before the response lands. The name shown is
  // the SERVER's, so a tool the registry calls something else is never given a second name here.
  const toolName = tool?.name || toolKey;

  const ctl = useToolSettings({
    base: 'wildcard-tools',
    idPrefix: `wildcard-${toolKey}`,
    activeTarget,
    toolKey,
    show,
  });

  const { data, options, sections, ownedFlags, ownedFlagKeys, hasVocabulary } = ctl;
  const displayName = data?.tool_name || toolName;
  const blocked = ctl.invalidKeys.length > 0;

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="xl" scrollable>
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          {displayName} configuration
          {data?.step ? (
            <span className="text-white-50 ms-2" style={{ fontSize: '0.9rem' }}>
              step {data.step} &middot; {data.phase}
            </span>
          ) : null}
        </Modal.Title>
      </Modal.Header>
      <Modal.Body style={{ minHeight: '60vh' }}>
        {ctl.loading ? (
          <div className="text-center py-5"><Spinner animation="border" variant="danger" /></div>
        ) : (
          <>
            {/* The only two alerts on this screen. One is a refusal, which is an error. The other says
                the runner does not read this store yet, which makes every field below a promise the
                framework does not keep. */}
            {ctl.error && <Alert variant="danger" className="py-2">{ctl.error}</Alert>}
            {ctl.notice && <Alert variant={ctl.noticeVariant} className="py-2">{ctl.notice}</Alert>}

            {data && (
              <>
                {/* What this actually runs, so the vocabulary can be checked against the truth in one
                    hop rather than taken on trust. */}
                <div className="mb-3 p-3 rounded" style={{ background: 'rgba(255,255,255,0.03)' }}>
                  <div className="text-white-50" style={{ fontSize: '0.76rem' }}>
                    {data.container && <div>Container: <code>{data.container}</code></div>}
                    {data.image && <div>Image: <code>{data.image}</code></div>}
                    {data.version && <div>Version: {data.version}</div>}
                    {data.invocation && <div>Runner: <code>{data.invocation}</code></div>}
                  </div>
                  {data.note && (
                    <div className="text-white-50 mt-2" style={{ fontSize: '0.76rem' }}>{data.note}</div>
                  )}
                </div>

                {/* Stored, but nothing reads it yet. Said on every read and every save rather than
                    hidden, because a configured scan that silently runs the hardcoded command line is
                    exactly the deception this store exists to prevent. */}
                {data.runner_reads_settings === false && data.pending_wiring && (
                  <Alert variant="warning" className="py-2" style={{ fontSize: '0.8rem' }}>
                    <i className="bi bi-exclamation-triangle-fill me-2" />
                    {data.pending_wiring}
                  </Alert>
                )}

                {ctl.orphaned.length > 0 && (
                  <Alert variant="warning" className="py-2" style={{ fontSize: '0.78rem' }}>
                    Stored for this target but not in the current vocabulary:{' '}
                    <code>{ctl.orphaned.join(', ')}</code>. Nothing reads them, this endpoint refuses
                    them on save, and saving this form will therefore remove them.
                  </Alert>
                )}

                {/* A limitation is CONTEXT, not an error: it says what the tool is and is not. Quiet
                    text, in the server's own words. */}
                {data.limitation && (
                  <div className="text-white-50 mb-3" style={{ fontSize: '0.8rem' }}>{data.limitation}</div>
                )}

                {/* httpx is the case: it already has a wired configuration store, so this screen links
                    out instead of growing a second vocabulary that can drift from the first. */}
                {data.delegates_to && (
                  <div className="mb-3">
                    <Button
                      variant="outline-danger"
                      onClick={() => onDelegate && onDelegate(data.delegates_to, data)}
                      disabled={!onDelegate}
                    >
                      <i className="bi bi-box-arrow-up-right me-2" />
                      Open the existing {data.delegates_to} configuration
                    </Button>
                    {!onDelegate && (
                      <div className="text-white-50 mt-2" style={{ fontSize: '0.76rem' }}>
                        This tool is configured through <code>{data.delegates_to}</code>.
                      </div>
                    )}
                  </div>
                )}

                {/* The legend, in the server's own words. Without it "unverified" is just a colour. */}
                {hasVocabulary && <ProvenanceLegend meanings={ctl.meanings} />}

                {hasVocabulary && (
                  <Form noValidate>
                    {sections.map((section) => (
                      <div key={section.group} className="mb-4">
                        <h6
                          className="pb-2 mb-3"
                          style={{ color: ACCENT, borderBottom: '1px solid rgba(220,53,69,0.3)' }}
                        >
                          {section.group}
                          <span className="text-white-50 ms-2" style={{ fontSize: '0.75rem' }}>
                            {section.keys.length} option{section.keys.length === 1 ? '' : 's'}
                          </span>
                        </h6>
                        {section.keys.map((k) => <ToolOptionRow key={k} ctl={ctl} optionKey={k} />)}
                      </div>
                    ))}
                  </Form>
                )}

                {/* Why a flag the operator expected is missing. Without this the screen reads as
                    incomplete rather than as deliberate. */}
                {ownedFlagKeys.length > 0 && (
                  <div className="mt-4">
                    <h6 className="text-white-50 pb-2 mb-2" style={{ borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
                      The framework sets these {ownedFlagKeys.length} flag
                      {ownedFlagKeys.length === 1 ? '' : 's'} itself
                    </h6>
                    {ctl.meanings?.ownedFlags && (
                      <div className="text-white-50 mb-2" style={{ fontSize: '0.75rem' }}>
                        {ctl.meanings.ownedFlags}
                      </div>
                    )}
                    <div
                      className="border rounded p-2"
                      style={{ borderColor: 'rgba(255,255,255,0.08)', maxHeight: '260px', overflowY: 'auto' }}
                    >
                      {ownedFlagKeys.map((flag) => (
                        <div key={flag} className="mb-2" style={{ fontSize: '0.74rem' }}>
                          <code style={{ color: 'rgba(255,255,255,0.6)' }}>{flag}</code>
                          <div className="text-white-50">{ownedFlags[flag]}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* What these settings compose to. A settings screen that cannot show what it will run
                    is a screen the operator has to take on trust. */}
                {hasVocabulary && Array.isArray(data.would_add_args) && (
                  <div className="mt-4">
                    <div className="text-white-50 mb-1" style={{ fontSize: '0.75rem' }}>
                      Arguments the saved settings add to the command line:
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
                  <details className="mt-4">
                    <summary className="text-white-50" style={{ fontSize: '0.8rem', cursor: 'pointer' }}>
                      What was measured about {displayName}
                    </summary>
                    <div
                      className="text-white-50 mt-2"
                      style={{ fontSize: '0.75rem', whiteSpace: 'pre-wrap' }}
                    >
                      {data.notes}
                    </div>
                  </details>
                )}
              </>
            )}
          </>
        )}
      </Modal.Body>
      <Modal.Footer>
        {hasVocabulary && (
          <span className="text-white-50 me-auto" style={{ fontSize: '0.76rem' }}>
            {ctl.configuredCount} of {Object.keys(options).length} options set
            <BlockedSaveNote ctl={ctl} className="ms-2" />
          </span>
        )}
        {hasVocabulary && (
          <Button variant="outline-secondary" onClick={ctl.clearAll} disabled={ctl.saving}>
            Clear all
          </Button>
        )}
        <Button variant="outline-secondary" onClick={handleClose} disabled={ctl.saving}>Close</Button>
        {hasVocabulary && (
          <Button
            variant="danger"
            onClick={ctl.save}
            disabled={ctl.saving || ctl.loading || blocked}
            title={blocked ? 'One or more values would be refused. The fields are marked.' : undefined}
          >
            {ctl.saving ? 'Saving...' : 'Save'}
          </Button>
        )}
      </Modal.Footer>
    </Modal>
  );
}

export default WildcardToolConfigModal;
