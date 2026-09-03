import { useEffect, useState } from 'react';
import { Modal, Tab, Tabs, Spinner } from 'react-bootstrap';
import {
  useCompanyToolSettings,
  CompanyToolSettingsPane,
  CompanyToolReferencePane,
  CompanyToolSettingsFooter,
  CompanyToolStatusStrip,
} from './CompanyToolSettings';

// ONE configuration modal for every Company workflow tool that has no target picker of its own.
//
// It renders whatever GET /company-tools/{id}/{tool}/settings describes and nothing else: one tab
// per group the SERVER declares, plus a read only tab for what actually runs and what the framework
// sets itself. There is no per-tool screen here to fall out of step with the server's vocabulary or
// with the MCP company tool that reads and writes the same rows.
//
// Used by Amass Intel, Metabigor and the Company Nuclei "Settings" button. Nuclei's Configure button
// (targets and templates) is a DIFFERENT screen and stays exactly where it is: two screens that both
// set templates is how a configuration comes to contradict itself, and the registry deliberately
// owns neither of those here.

function CompanyToolConfigModal({ show, handleClose, activeTarget, tool }) {
  const ctl = useCompanyToolSettings({ activeTarget, toolKey: tool?.key, show });
  const [tab, setTab] = useState('');

  // Reset to the first tab whenever a different tool is opened, so the modal never opens on a group
  // the new tool does not have.
  useEffect(() => { setTab(''); }, [tool?.key, show]);

  const sections = ctl.sections;
  const activeKey = tab || (sections[0] ? `group:${sections[0].group}` : 'reference');
  const displayName = ctl.data?.tool_name || tool?.name || tool?.key || 'tool';

  return (
    <Modal
      show={show}
      onHide={handleClose}
      size="xl"
      data-bs-theme="dark"
      className="modal-90w"
      scrollable
    >
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-sliders me-2" />
          {displayName} settings
          {ctl.data?.phase ? (
            <span className="text-white-50 ms-2" style={{ fontSize: '0.9rem' }}>
              step {ctl.data.step} &middot; {ctl.data.phase}
            </span>
          ) : null}
        </Modal.Title>
      </Modal.Header>
      <Modal.Body style={{ minHeight: '55vh' }}>
        {ctl.loading ? (
          <div className="text-center py-5"><Spinner animation="border" variant="danger" /></div>
        ) : !ctl.data ? (
          <CompanyToolStatusStrip ctl={ctl} />
        ) : (
          <Tabs activeKey={activeKey} onSelect={(k) => setTab(k || '')} className="mb-3">
            {sections.map((section) => (
              <Tab
                key={section.group}
                eventKey={`group:${section.group}`}
                title={`${section.group} (${section.keys.length})`}
              >
                <CompanyToolSettingsPane ctl={ctl} group={section.group} />
              </Tab>
            ))}
            <Tab eventKey="reference" title="What runs & what is fixed">
              <CompanyToolReferencePane ctl={ctl} />
            </Tab>
          </Tabs>
        )}

        {/* A tool with nothing to configure is a legitimate answer and must be distinguishable from
            a tool nobody has got round to. The server says which it is; this only renders it. */}
        {ctl.data && !ctl.hasVocabulary && !ctl.data.limitation && (
          <div className="text-white-50" style={{ fontSize: '0.8rem' }}>
            The registry lists no configurable options for {displayName}.
          </div>
        )}
      </Modal.Body>
      <Modal.Footer>
        <CompanyToolSettingsFooter ctl={ctl} onClose={handleClose} />
      </Modal.Footer>
    </Modal>
  );
}

export default CompanyToolConfigModal;
