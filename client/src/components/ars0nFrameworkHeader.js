import { Row, Col, Button } from 'react-bootstrap';

function Ars0nFrameworkHeader({ onSettingsClick, onExportClick, onImportClick, onToolsClick }) {
  return (
    <Row className="align-items-center mb-3">
      <Col xs="auto">
        <img src="/images/logo.avif" alt="Logo" style={{ height: '60px' }} />
      </Col>
      <Col xs="auto" className="ms-auto d-flex justify-content-end">
        <Button 
          variant="link" 
          className="text-white p-1"
          onClick={() => window.open('https://www.youtube.com/@rs0n_live', '_blank')}
          title="YouTube Channel"
        >
          <i className="bi bi-youtube" style={{ fontSize: '1.5rem' }}></i>
        </Button>
        <Button 
          variant="link" 
          className="text-white p-1"
          onClick={() => window.open('https://github.com/R-s0n', '_blank')}
          title="GitHub Profile"
        >
          <i className="bi bi-github" style={{ fontSize: '1.5rem' }}></i>
        </Button>
        <Button 
          variant="link" 
          className="text-white p-1"
          onClick={() => window.open('https://coff.ee/rs0n.evolv3', '_blank')}
          title="Buy Me a Coffee"
        >
          <i className="bi bi-cup-hot" style={{ fontSize: '1.5rem' }}></i>
        </Button>
        <Button 
          variant="link" 
          className="text-white p-1"
          onClick={onImportClick}
          title="Import Database"
        >
          <i className="bi bi-download" style={{ fontSize: '1.5rem' }}></i>
        </Button>
        <Button 
          variant="link" 
          className="text-white p-1"
          onClick={onExportClick}
          title="Export Data"
        >
          <i className="bi bi-upload" style={{ fontSize: '1.5rem' }}></i>
        </Button>
        <Button 
          variant="link" 
          className="text-white p-1"
          onClick={onToolsClick}
          title="Tools & Utilities"
        >
          <i className="bi bi-tools" style={{ fontSize: '1.5rem' }}></i>
        </Button>
        <Button 
          variant="link" 
          className="text-white p-1"
          onClick={onSettingsClick}
          title="Settings"
        >
          <i className="bi bi-gear" style={{ fontSize: '1.5rem' }}></i>
        </Button>
      </Col>
    </Row>
  );
}

export default Ars0nFrameworkHeader;
