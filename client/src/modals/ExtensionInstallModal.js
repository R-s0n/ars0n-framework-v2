import React from 'react';
import { Modal, Button, Alert } from 'react-bootstrap';

const ExtensionInstallModal = ({ show, onHide }) => {
  return (
    <Modal show={show} onHide={onHide} size="lg">
      <Modal.Header closeButton className="bg-dark text-white">
        <Modal.Title>
          <i className="bi bi-puzzle me-2"></i>
          Install Chrome Extension
        </Modal.Title>
      </Modal.Header>
      <Modal.Body className="bg-dark text-white">
        <Alert variant="info">
          <i className="bi bi-info-circle me-2"></i>
          The ARS0N Framework Manual Crawling Extension allows you to capture HTTP traffic while manually browsing a target application.
        </Alert>

        <h5 className="text-danger mb-3">Installation Steps</h5>

        <div className="mb-4">
          <h6 className="text-warning">Step 1: Locate the Extension Files</h6>
          <p>The extension files are located in the <code className="text-info">extension/</code> folder of your ARS0N Framework installation:</p>
          <pre className="bg-darker p-3 rounded text-light">
            <code>ars0n-framework-v2/extension/</code>
          </pre>
          <p className="small text-muted">This folder contains all the necessary files: manifest.json, background.js, popup.html, content.js, and icons.</p>
        </div>

        <div className="mb-4">
          <h6 className="text-warning">Step 2: Open Chrome Extensions Page</h6>
          <ol className="text-light">
            <li>Open Google Chrome browser</li>
            <li>Navigate to <code className="text-info">chrome://extensions/</code> in the address bar</li>
            <li>Or click the three dots menu → <strong>Extensions</strong> → <strong>Manage Extensions</strong></li>
          </ol>
        </div>

        <div className="mb-4">
          <h6 className="text-warning">Step 3: Enable Developer Mode</h6>
          <ol className="text-light">
            <li>Look for the <strong>"Developer mode"</strong> toggle in the top-right corner of the Extensions page</li>
            <li>Click the toggle to turn it <strong className="text-success">ON</strong></li>
            <li>You should see additional options appear: "Load unpacked", "Pack extension", etc.</li>
          </ol>
          <Alert variant="warning" className="mt-2">
            <small>
              <i className="bi bi-exclamation-triangle me-2"></i>
              Developer mode is required to load unpacked extensions
            </small>
          </Alert>
        </div>

        <div className="mb-4">
          <h6 className="text-warning">Step 4: Load the Extension</h6>
          <ol className="text-light">
            <li>Click the <strong>"Load unpacked"</strong> button that appeared in the top-left</li>
            <li>A file browser window will open</li>
            <li>Navigate to your ARS0N Framework installation directory</li>
            <li>Select the <code className="text-info">extension/</code> folder (the folder itself, not individual files)</li>
            <li>Click <strong>"Select Folder"</strong></li>
          </ol>
          <p className="small text-muted mt-2">
            Example path: <code>C:\Users\YourName\ars0n-framework-v2\extension\</code>
          </p>
        </div>

        <div className="mb-4">
          <h6 className="text-warning">Step 5: Verify Installation</h6>
          <ol className="text-light">
            <li>The extension should now appear in your list of installed extensions</li>
            <li>Look for <strong className="text-danger">"Ars0n Framework - Manual Crawling"</strong></li>
            <li>Make sure it's <strong className="text-success">enabled</strong> (toggle should be blue/on)</li>
            <li>You should see the extension icon in your Chrome toolbar (you may need to pin it)</li>
          </ol>
        </div>

        <div className="mb-4">
          <h6 className="text-warning">Step 6: Configure Extension Settings</h6>
          <ol className="text-light">
            <li>Click the extension icon in the Chrome toolbar</li>
            <li>Click the gear/settings icon in the popup</li>
            <li>Set the <strong>Framework URL</strong> to match your framework installation:</li>
          </ol>
          <pre className="bg-darker p-3 rounded text-light mt-2">
            <code>http://localhost</code>
          </pre>
          <p className="small text-muted">
            If you're running the framework on a different port or host, update the URL accordingly (e.g., http://localhost:8080)
          </p>
        </div>

        <div className="mb-4">
          <h6 className="text-warning">Step 7: Start Capturing Traffic</h6>
          <ol className="text-light">
            <li>In the ARS0N Framework, select a target from your scope list</li>
            <li>Navigate to the target URL in Chrome</li>
            <li>Click the extension icon to open the popup</li>
            <li>The target should be automatically selected (if not, select it from the dropdown)</li>
            <li>Click <strong className="text-danger">"Start Capture"</strong></li>
            <li>Browse the target application normally - all HTTP traffic will be captured</li>
            <li>Click <strong>"Stop Capture"</strong> when finished</li>
            <li>View results in the framework by clicking <strong>"View Results"</strong></li>
          </ol>
        </div>

        <Alert variant="success">
          <strong><i className="bi bi-check-circle me-2"></i>Tips for Best Results:</strong>
          <ul className="mb-0 mt-2 small">
            <li>Capture traffic for authenticated areas by logging in first, then starting capture</li>
            <li>Navigate through different sections of the application to discover all endpoints</li>
            <li>Submit forms, perform searches, and interact with dynamic content</li>
            <li>The extension captures GET/POST parameters, request/response headers, and body content</li>
            <li>You can stop and start capture multiple times - all data is saved to the same session</li>
          </ul>
        </Alert>

        <Alert variant="warning" className="mt-3">
          <strong><i className="bi bi-exclamation-triangle me-2"></i>Troubleshooting:</strong>
          <ul className="mb-0 mt-2 small">
            <li><strong>Extension won't load:</strong> Make sure you selected the entire extension folder, not individual files</li>
            <li><strong>Can't connect to framework:</strong> Verify the Framework URL in extension settings matches your installation</li>
            <li><strong>No targets showing:</strong> Make sure you have created URL-type targets in your scope</li>
            <li><strong>Not capturing requests:</strong> Check that the page URL matches your target URL (including www/non-www)</li>
            <li><strong>Extension conflicts:</strong> If you have password managers like LastPass, try using Incognito mode with only the ARS0N extension enabled</li>
          </ul>
        </Alert>
      </Modal.Body>
      <Modal.Footer className="bg-dark text-white">
        <Button variant="outline-secondary" onClick={onHide}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

export default ExtensionInstallModal;
