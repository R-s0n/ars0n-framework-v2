import { useState, useEffect, useRef, useCallback, useMemo, lazy, Suspense } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import useTargetURLs, { targetURLsKey } from './hooks/useTargetURLs.js';
import { cancelAllScanPolls } from './utils/scanPolling.js';
import { DEFAULT_NUCLEI_TEMPLATES, DEFAULT_NUCLEI_SEVERITIES } from './utils/nucleiDefaults';
import { getHttpxResultsCount, calculateEstimatedScanTime } from './utils/scanMetrics.js';
import AddScopeTargetModal from './modals/addScopeTargetModal.js';
import SelectActiveScopeTargetModal from './modals/selectActiveScopeTargetModal.js';
import { DNSRecordsModal, SubdomainsModal, CloudDomainsModal, InfrastructureMapModal } from './modals/amassModals.js';
import { AmassIntelResultsModal, AmassIntelHistoryModal } from './modals/amassIntelModals.js';
import { HttpxResultsModal } from './modals/httpxModals.js';
import { GauResultsModal } from './modals/gauModals.js';
import { Sublist3rResultsModal } from './modals/sublist3rModals.js';
import { AssetfinderResultsModal } from './modals/assetfinderModals.js';
import { SubfinderResultsModal } from './modals/subfinderModals.js';
import { ShuffleDNSResultsModal } from './modals/shuffleDNSModals.js';
import ScreenshotResultsModal from './modals/ScreenshotResultsModal.js';
import SettingsModal from './modals/SettingsModal.js';
import ToolsModal from './modals/ToolsModal.js';
import NotesModal from './modals/NotesModal.js';
import Ars0nFrameworkHeader from './components/ars0nFrameworkHeader.js';
import ManageScopeTargets from './components/manageScopeTargets.js';
import fetchAmassScans from './utils/fetchAmassScans.js';
import {
  Container,
  Fade,
  Card,
  Row,
  Col,
  Button,
  ListGroup,
  Modal,
  Table,
  Toast,
  ToastContainer,
  Spinner,
  ProgressBar,
  Alert,
  Badge,
  Accordion,
} from 'react-bootstrap';
import 'bootstrap/dist/css/bootstrap.min.css';
import 'bootstrap-icons/font/bootstrap-icons.css';
import initiateAmassScan from './utils/initiateAmassScan';
import monitorScanStatus from './utils/monitorScanStatus';
import validateInput from './utils/validateInput.js';
import {
  getTypeIcon,
  getLastScanDate,
  getLatestScanStatus,
  getLatestScanTime,
  getLatestScanId,
  getExecutionTime,
  getResultLength,
  copyToClipboard,
} from './utils/miscUtils.js';
import { MdCopyAll, MdCheckCircle, MdWarning } from 'react-icons/md';
import initiateHttpxScan from './utils/initiateHttpxScan';
import monitorHttpxScanStatus from './utils/monitorHttpxScanStatus';
import initiateGauScan from './utils/initiateGauScan.js';
import monitorGauScanStatus from './utils/monitorGauScanStatus';
import initiateSublist3rScan from './utils/initiateSublist3rScan';
import monitorSublist3rScanStatus from './utils/monitorSublist3rScanStatus';
import initiateAssetfinderScan from './utils/initiateAssetfinderScan';
import monitorAssetfinderScanStatus from './utils/monitorAssetfinderScanStatus';
import initiateCTLScan from './utils/initiateCTLScan';
import monitorCTLScanStatus from './utils/monitorCTLScanStatus';
import initiateSubfinderScan from './utils/initiateSubfinderScan';
import monitorSubfinderScanStatus from './utils/monitorSubfinderScanStatus';
import { CTLResultsModal } from './modals/CTLResultsModal';
import { ReconResultsModal } from './modals/ReconResultsModal';
import { UniqueSubdomainsModal } from './modals/UniqueSubdomainsModal';
import consolidateSubdomains from './utils/consolidateSubdomains.js';
import fetchConsolidatedSubdomains from './utils/fetchConsolidatedSubdomains.js';
import consolidateCompanyDomains from './utils/consolidateCompanyDomains.js';
import consolidateAttackSurface from './utils/consolidateAttackSurface.js';
import investigateFQDNs from './utils/investigateFQDNs.js';
import fetchConsolidatedCompanyDomains from './utils/fetchConsolidatedCompanyDomains.js';
import fetchAttackSurfaceAssetCounts from './utils/fetchAttackSurfaceAssetCounts.js';
import consolidateNetworkRanges from './utils/consolidateNetworkRanges.js';
import fetchConsolidatedNetworkRanges from './utils/fetchConsolidatedNetworkRanges.js';
import monitorShuffleDNSScanStatus from './utils/monitorShuffleDNSScanStatus';
import initiateShuffleDNSScan from './utils/initiateShuffleDNSScan';
import initiateCeWLScan from './utils/initiateCeWLScan';
import monitorCeWLScanStatus from './utils/monitorCeWLScanStatus';
import { CeWLResultsModal } from './modals/cewlModals';
import { GoSpiderResultsModal } from './modals/gospiderModals';
import initiateGoSpiderScan from './utils/initiateGoSpiderScan';
import monitorGoSpiderScanStatus from './utils/monitorGoSpiderScanStatus';
import { SubdomainizerResultsModal } from './modals/subdomainizerModals';
import initiateSubdomainizerScan from './utils/initiateSubdomainizerScan';
import monitorSubdomainizerScanStatus from './utils/monitorSubdomainizerScanStatus';
import initiateNucleiScan from './utils/initiateNucleiScan';
import monitorNucleiScanStatus from './utils/monitorNucleiScanStatus';
import initiateNucleiScreenshotScan from './utils/initiateNucleiScreenshotScan';
import monitorNucleiScreenshotScanStatus from './utils/monitorNucleiScreenshotScanStatus';
import initiateMetaDataScan, { initiateCompanyMetaDataScan, cancelMetaDataScan } from './utils/initiateMetaDataScan';
import monitorMetaDataScanStatus, { monitorCompanyMetaDataScanStatus } from './utils/monitorMetaDataScanStatus';
import fetchHttpxScans from './utils/fetchHttpxScans';
import {
  AUTO_SCAN_STEPS,
  resumeAutoScan as resumeAutoScanUtil,
  startAutoScan as startAutoScanUtil
} from './utils/wildcardAutoScan';
import getAutoScanSteps from './utils/autoScanSteps';
import fetchAmassIntelScans from './utils/fetchAmassIntelScans';
import monitorAmassIntelScanStatus from './utils/monitorAmassIntelScanStatus';
import initiateAmassIntelScan from './utils/initiateAmassIntelScan';
import initiateCTLCompanyScan from './utils/initiateCTLCompanyScan';
import monitorCTLCompanyScanStatus from './utils/monitorCTLCompanyScanStatus';
import { CTLCompanyResultsModal, CTLCompanyHistoryModal } from './modals/CTLCompanyResultsModal';
import { CloudEnumResultsModal, CloudEnumHistoryModal } from './modals/CloudEnumResultsModal';
import CloudEnumConfigModal from './modals/CloudEnumConfigModal';
import NucleiConfigModal from './modals/NucleiConfigModal';
import { NucleiResultsModal, NucleiHistoryModal } from './modals/NucleiResultsModal';
import monitorMetabigorCompanyScanStatus from './utils/monitorMetabigorCompanyScanStatus';
import initiateMetabigorCompanyScan from './utils/initiateMetabigorCompanyScan';
import { MetabigorCompanyResultsModal, MetabigorCompanyHistoryModal } from './modals/MetabigorCompanyResultsModal';
import APIKeysConfigModal from './modals/APIKeysConfigModal.js';
import ReverseWhoisModal from './modals/ReverseWhoisModal.js';
import initiateSecurityTrailsCompanyScan from './utils/initiateSecurityTrailsCompanyScan';
import monitorSecurityTrailsCompanyScanStatus from './utils/monitorSecurityTrailsCompanyScanStatus';
import { SecurityTrailsCompanyResultsModal, SecurityTrailsCompanyHistoryModal } from './modals/SecurityTrailsCompanyResultsModal';
import { CensysCompanyResultsModal, CensysCompanyHistoryModal } from './modals/CensysCompanyResultsModal';
import initiateCensysCompanyScan from './utils/initiateCensysCompanyScan';
import monitorCensysCompanyScanStatus from './utils/monitorCensysCompanyScanStatus';
import initiateGitHubReconScan from './utils/initiateGitHubReconScan';
import monitorGitHubReconScanStatus from './utils/monitorGitHubReconScanStatus';
import { GitHubReconResultsModal, GitHubReconHistoryModal } from './modals/GitHubReconResultsModal';
import { ShodanCompanyResultsModal, ShodanCompanyHistoryModal } from './modals/ShodanCompanyResultsModal';
import monitorShodanCompanyScanStatus from './utils/monitorShodanCompanyScanStatus.js';
import initiateShodanCompanyScan from './utils/initiateShodanCompanyScan';
import AddWildcardTargetsModal from './modals/AddWildcardTargetsModal.js';
import ExploreAttackSurfaceModal from './modals/ExploreAttackSurfaceModal.js';
import GlobalScansModal from './modals/GlobalScansModal.js';
import initiateInvestigateScan from './utils/initiateInvestigateScan';
import monitorInvestigateScanStatus from './utils/monitorInvestigateScanStatus';
import TrimRootDomainsModal from './modals/TrimRootDomainsModal.js';
import TrimNetworkRangesModal from './modals/TrimNetworkRangesModal.js';
import LiveWebServersResultsModal from './modals/LiveWebServersResultsModal.js';
import AmassEnumConfigModal from './modals/AmassEnumConfigModal.js';
import ConfigureHttpxModal from './modals/ConfigureHttpxModal.js';
import AmassIntelConfigModal from './modals/AmassIntelConfigModal.js';
import DNSxConfigModal from './modals/DNSxConfigModal.js';
import fetchMetabigorCompanyScans from './utils/fetchMetabigorCompanyScans';

import monitorIPPortScanStatus from './utils/monitorIPPortScanStatus';
import initiateIPPortScan from './utils/initiateIPPortScan';
import fetchIPPortScans from './utils/fetchIPPortScans';

import { AmassEnumCompanyResultsModal } from './modals/AmassEnumCompanyResultsModal.js';
import { AmassEnumCompanyHistoryModal } from './modals/AmassEnumCompanyHistoryModal.js';
import { initiateAmassEnumCompanyScan } from './utils/initiateAmassEnumCompanyScan.js';

// Add DNSx imports
import { DNSxCompanyResultsModal } from './modals/DNSxCompanyResultsModal.js';
import { DNSxCompanyHistoryModal } from './modals/DNSxCompanyHistoryModal.js';
import { initiateDNSxCompanyScan } from './utils/initiateDNSxCompanyScan.js';

// Add Katana Company imports
import KatanaCompanyConfigModal from './modals/KatanaCompanyConfigModal.js';
import KatanaCompanyResultsModal from './modals/KatanaCompanyResultsModal.js';
import { KatanaCompanyHistoryModal } from './modals/KatanaCompanyHistoryModal.js';
import { initiateKatanaCompanyScan } from './utils/initiateKatanaCompanyScan.js';
import monitorKatanaCompanyScanStatus from './utils/monitorKatanaCompanyScanStatus.js';

// Add Cloud Enum imports
import initiateCloudEnumScan from './utils/initiateCloudEnumScan';
import monitorCloudEnumScanStatus from './utils/monitorCloudEnumScanStatus';

// Add Attack Surface Visualization import
import AttackSurfaceVisualizationModal from './modals/AttackSurfaceVisualizationModal.js';
import ManageAttackSurfaceModal from './modals/ManageAttackSurfaceModal.js';

// Add URL workflow imports
import initiateKatanaURLScan from './utils/initiateKatanaURLScan';
import monitorKatanaURLScanStatus from './utils/monitorKatanaURLScanStatus';
import initiateLinkFinderURLScan from './utils/initiateLinkFinderURLScan';
import monitorLinkFinderURLScanStatus from './utils/monitorLinkFinderURLScanStatus';
import initiateWaybackURLsScan from './utils/initiateWaybackURLsScan';
import monitorWaybackURLsScanStatus from './utils/monitorWaybackURLsScanStatus';
import initiateGAUURLScan from './utils/initiateGAUURLScan';
import monitorGAUURLScanStatus from './utils/monitorGAUURLScanStatus';
import initiateGoSpiderURLScan from './utils/initiateGoSpiderURLScan';
import monitorGoSpiderURLScanStatus from './utils/monitorGoSpiderURLScanStatus';
import initiateFFUFURLScan from './utils/initiateFFUFURLScan';
import monitorFFUFURLScanStatus from './utils/monitorFFUFURLScanStatus';
import { KatanaURLResultsModal } from './modals/KatanaURLResultsModal';
import { LinkFinderURLResultsModal } from './modals/LinkFinderURLResultsModal';
import { WaybackURLsResultsModal } from './modals/WaybackURLsResultsModal';
import { GAUURLResultsModal } from './modals/GAUURLResultsModal';
import { GoSpiderURLResultsModal } from './modals/GoSpiderURLResultsModal';
import { FFUFURLResultsModal } from './modals/FFUFURLResultsModal';
import initiateWAFProbeScan from './utils/initiateWAFProbeScan';
import monitorWAFProbeScanStatus from './utils/monitorWAFProbeScanStatus';
import { WAFProbeResultsModal } from './modals/WAFProbeResultsModal';
import { WAFProbeConfigModal } from './modals/WAFProbeConfigModal';
import { CrawlerConfigModal } from './modals/CrawlerConfigModal';
import initiateArjunScan from './utils/initiateArjunScan';
import monitorArjunScanStatus from './utils/monitorArjunScanStatus';
import initiateX8Scan from './utils/initiateX8Scan';
import monitorX8ScanStatus from './utils/monitorX8ScanStatus';
import { ArjunConfigModal } from './modals/ArjunConfigModal';
import { ArjunResultsModal } from './modals/ArjunResultsModal';
import { X8ConfigModal } from './modals/X8ConfigModal';
import { X8ResultsModal } from './modals/X8ResultsModal';
import { ApplicationQuestionsModal } from './modals/ApplicationQuestionsModal';
import { MechanismsModal } from './modals/MechanismsModal';
import { NotableObjectsModal } from './modals/NotableObjectsModal';
import { SecurityControlsModal } from './modals/SecurityControlsModal';
import { ThreatModelModal } from './modals/ThreatModelModal';
import { FFUFConfigModal } from './modals/FFUFConfigModal';
import FFUFSettingsModal from './modals/FFUFSettingsModal';
import AddAttackVectorModal from './modals/AddAttackVectorModal';
import AttackVectorsModal from './modals/AttackVectorsModal';
import AttackToolCard from './components/AttackToolCard';
import { ATTACK_TOOL_SECTIONS } from './data/attackTools';
import { WIRED_CATEGORIES } from './data/wiredCategories';
import VectorToolConfigModal from './modals/VectorToolConfigModal';
import VectorToolResultsModal from './modals/VectorToolResultsModal';
import WildcardToolConfigModal from './modals/WildcardToolConfigModal';
import CompanyToolConfigModal from './modals/CompanyToolConfigModal';
import IPPortScanConfigModal from './modals/IPPortScanConfigModal';
import SectionWebhookModal from './modals/SectionWebhookModal';
import ManualCrawlResultsModal from './modals/ManualCrawlResultsModal';
import AuthFlowModal from './modals/AuthFlowModal';
import RecordAuthFlowsModal from './modals/RecordAuthFlowsModal';
import ManualAuthFlowModal from './modals/ManualAuthFlowModal';
import ManageSessionsModal from './modals/ManageSessionsModal';
import RefreshSessionModal from './modals/RefreshSessionModal';
import ClientIdentityPatternsModal from './modals/ClientIdentityPatternsModal';
import PolicyAccessModal from './modals/PolicyAccessModal';
import RoleAccessModal from './modals/RoleAccessModal';
import DiscretionaryAccessModal from './modals/DiscretionaryAccessModal';
import PossibleAttacksModal from './modals/PossibleAttacksModal';
import ExtensionInstallModal from './modals/ExtensionInstallModal';
import ManageEndpointsModal from './modals/ManageEndpointsModal';
import EndpointScanResultsModal from './modals/EndpointScanResultsModal';
import { attacks as ATTACK_CATALOG } from './data/attacks';

const ExportModal = lazy(() => import('./modals/ExportModal.js'));
const ImportModal = lazy(() => import('./modals/ImportModal.js'));
const WelcomeModal = lazy(() => import('./modals/WelcomeModal.js'));
// Which sections have their Config, Scan and Results built, and which category each tool belongs to.
//
// Derived from the section list rather than typed again, so wiring a new section up is adding its
// key here once the server side exists. The category is what the API routes are keyed on, so a tool
// in the wrong section would call /xss/ for a SQL scanner and get a 404 rather than a wrong answer.
// Sections whose tools share a setting that belongs to the section rather than to any one of them.
// The label is what the button says.
const SECTION_SETTINGS_BUTTON = { 'redirect-ssrf': 'Configure Webhook' };

// How a threat model entry's test status is shown. A threat is grey until somebody has actually run
// it, green when the attack worked, red when it was run and did not. The point of the colour is that
// a model which is still entirely grey is one nobody has acted on, which should be obvious at a glance
// without opening anything. Rows written before this column existed come back without it, so anything
// unrecognised falls back to untested rather than rendering uncoloured.
// validated carries a className instead of a plain border: a landed attack is the whole point of the
// exercise and gets the glow treatment from index.css, which owns the animation because keyframes
// cannot be expressed as an inline style.
const THREAT_TEST_STATUS = {
  untested: { border: '#6c757d', badge: 'secondary', label: 'Untested', className: '' },
  validated: { border: '#20c997', badge: 'success', label: 'Validated', className: 'threat-validated' },
  rejected: { border: '#dc3545', badge: 'danger', label: 'Rejected', className: '' },
};
const threatTestStatus = (status) => THREAT_TEST_STATUS[status] || THREAT_TEST_STATUS.untested;

// Severity, as rendered in the accordion header. Explicit hex rather than Bootstrap contextual
// colours because bg="warning" and bg="danger" are the same two colours the test-status badge and
// the glow already use, and three different meanings sharing two colours is unreadable at a glance.
// An unset severity renders nothing at all: a missing triage decision must not look like a low one.
// Every threat cites one entry from the Possible Attacks catalogue. Resolving the name here rather
// than reading a stored copy means renaming an attack in attacks.js updates every threat that cites
// it, and a threat whose attack id no longer exists degrades to its own descriptor instead of
// rendering a dangling label.
const ATTACK_NAME_BY_ID = ATTACK_CATALOG.reduce((acc, a) => { acc[a.id] = a.name; return acc; }, {});

// "Cross-Site Scripting (XSS) - Product Search on Search Query": the attack first, because that is
// what the reader is scanning for, then what makes this instance of it specific.
const threatTitle = (threat) => {
  const specific = `${threat.mechanism || 'Unnamed mechanism'}${threat.target_object ? ` on ${threat.target_object}` : ''}`;
  // A catalogue citation resolves through the local catalogue so renames propagate without a
  // refetch; an ad hoc name is carried on the threat itself. attack_name is the API's own
  // resolution of the same pair and backs both up.
  const attackName = ATTACK_NAME_BY_ID[threat.attack_id] || threat.attack_custom_name || threat.attack_name || '';
  return attackName ? `${attackName} - ${specific}` : specific;
};

const THREAT_SEVERITY = {
  critical:      { label: 'Critical',      bg: '#7f1d1d', fg: '#fecaca' },
  high:          { label: 'High',          bg: '#9a3412', fg: '#fed7aa' },
  moderate:      { label: 'Moderate',      bg: '#854d0e', fg: '#fde68a' },
  low:           { label: 'Low',           bg: '#1e3a5f', fg: '#bfdbfe' },
  informational: { label: 'Informational', bg: '#334155', fg: '#cbd5e1' },
};
const threatSeverity = (v) => THREAT_SEVERITY[String(v || '').toLowerCase()] || null;

const VECTOR_TOOL_CATEGORY = new Map(
  ATTACK_TOOL_SECTIONS
    .filter((section) => WIRED_CATEGORIES.includes(section.key))
    .flatMap((section) => section.tools.map((tool) => [tool.key, section.key])),
);

const LaunchPadModal = lazy(() => import('./modals/LaunchPadModal.js'));
const ConfigUploadModal = lazy(() => import('./modals/ConfigUploadModal.js'));
const APIIntegrationModal = lazy(() => import('./modals/APIIntegrationModal.js'));
const GoogleDorkingModal = lazy(() => import('./modals/GoogleDorkingModal.js'));
const MetaDataModal = lazy(() => import('./modals/MetaDataModal.js'));
const ConfigureMetaDataModal = lazy(() => import('./modals/ConfigureMetaDataModal.js'));
const ROIReport = lazy(() => import('./components/ROIReport'));
const HelpMeLearnLazy = lazy(() => import('./components/HelpMeLearn'));

const HelpMeLearn = ({ section }) => (
  <Suspense fallback={<div style={{ height: '24px' }} />}>
    <HelpMeLearnLazy section={section} />
  </Suspense>
);

// Every URL-discovery tool writes the same summary sentence, so the count is parsed in one place
// rather than five copies of the same regex.
function countURLToolEndpoints(scan) {
  if (!scan || !scan.result) return 0;
  // TWO summary shapes are in play and this has to read both. The live-target crawlers write
  // "Found N direct endpoints and M adjacent endpoints with parameters". The archive tools query
  // several hosts per run and write "Found N direct and M adjacent endpoints across H of T hosts"
  // so the host count has somewhere to live. Matching only the first shape reported 0 on both
  // archive cards while their scans were finding hundreds of endpoints, which reads as a broken
  // tool rather than a parser that stopped matching.
  const match = String(scan.result).match(/Found (\d+) direct(?: endpoints)? and (\d+) adjacent endpoints/);
  return match ? parseInt(match[1], 10) + parseInt(match[2], 10) : 0;
}

// One card for every tool in both URL-discovery rows. `onConfig` is optional: the archive tools
// have nothing to configure because they never talk to the target.
const URLToolCard = ({ tool }) => (
  <Col className="mb-3">
    <Card className="shadow-sm h-100 text-center" style={{ minHeight: '250px' }}>
      <Card.Body className="d-flex flex-column">
        <Card.Title className="text-danger mb-3">
          <a href={tool.link} className="text-danger text-decoration-none"
             target="_blank" rel="noopener noreferrer">
            {tool.name}
          </a>
        </Card.Title>
        <Card.Text className="text-white small fst-italic">
          {tool.description}
        </Card.Text>
        {/* Everything below the description is pinned to the bottom of the card, so the metric sits
            the SAME distance above the buttons on every card regardless of how long the description
            is. Metrics outside this block drift with the text above them. */}
        <div className="mt-auto">
          {/* An optional second metric, rendered to the LEFT of the result count. Tools that do not
              set one keep the single centred metric they had, so this cannot shift the cards that
              were not asked to change. Row/Col with card-metric-label is the same shape the
              multi-metric cards elsewhere use, so the label wrapping rules apply here too. */}
          {tool.secondaryLabel ? (
            <Row className="text-center align-items-start mb-3">
              <Col className="card-metric">
                <div className="text-danger fw-bold fs-4">{tool.secondaryCount}</div>
                <div className="text-muted small card-metric-label">{tool.secondaryLabel}</div>
              </Col>
              <Col className="card-metric">
                <div className="text-danger fw-bold fs-4">{tool.resultCount || 0}</div>
                <div className="text-muted small card-metric-label">{tool.resultLabel}</div>
              </Col>
            </Row>
          ) : (
            <div className="card-metric mb-3">
              <div className="text-danger fw-bold fs-4">{tool.resultCount || 0}</div>
              <div className="text-muted small card-metric-label">{tool.resultLabel}</div>
            </div>
          )}
          <div className="d-flex justify-content-center gap-2">
            {tool.onConfig && (
              <Button variant="outline-danger" className="flex-fill" onClick={tool.onConfig}
                      disabled={!tool.isActive || tool.isScanning}>
                Config
              </Button>
            )}
            <Button variant="outline-danger" className="flex-fill" onClick={tool.onScan}
                    disabled={!tool.isActive || tool.isScanning}>
              <div className="btn-content">
                {tool.isScanning ? <Spinner animation="border" size="sm" /> : 'Scan'}
              </div>
            </Button>
            <Button variant="outline-danger" className="flex-fill" onClick={tool.onResults}
                    disabled={!tool.status || tool.status !== 'success'}>
              Results
            </Button>
          </div>
        </div>
      </Card.Body>
    </Card>
  </Col>
);

function App() {
  const [showScanHistoryModal, setShowScanHistoryModal] = useState(false);
  const [showRawResultsModal, setShowRawResultsModal] = useState(false);
  const [showDNSRecordsModal, setShowDNSRecordsModal] = useState(false);
  const [scanHistory, setScanHistory] = useState([]);
  const [rawResults, setRawResults] = useState([]);
  const [dnsRecords, setDnsRecords] = useState([]);
  const [showModal, setShowModal] = useState(false);
  const [showActiveModal, setShowActiveModal] = useState(false);
  const [showExportModal, setShowExportModal] = useState(false);
  const [showImportModal, setShowImportModal] = useState(false);
  const [showWelcomeModal, setShowWelcomeModal] = useState(false);
  const [showLaunchPadModal, setShowLaunchPadModal] = useState(false);
  const [showConfigUploadModal, setShowConfigUploadModal] = useState(false);
  const [showAPIIntegrationModal, setShowAPIIntegrationModal] = useState(false);
  const [selections, setSelections] = useState({
    type: '',
    inputText: '',
  });
  const [scopeTargets, setScopeTargets] = useState([]);
  const [activeTarget, setActiveTarget] = useState(null);
  const [amassScans, setAmassScans] = useState([]);
  const [errorMessage, setErrorMessage] = useState('');
  const [fadeIn, setFadeIn] = useState(false);
  const [mostRecentAmassScanStatus, setMostRecentAmassScanStatus] = useState(null);
  const [mostRecentAmassScan, setMostRecentAmassScan] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [amassIntelScans, setAmassIntelScans] = useState([]);
  const [mostRecentAmassIntelScanStatus, setMostRecentAmassIntelScanStatus] = useState(null);
  const [mostRecentAmassIntelScan, setMostRecentAmassIntelScan] = useState(null);
  const [isAmassIntelScanning, setIsAmassIntelScanning] = useState(false);
  const [showAmassIntelResultsModal, setShowAmassIntelResultsModal] = useState(false);
  const [showAmassIntelHistoryModal, setShowAmassIntelHistoryModal] = useState(false);
  const [amassIntelNetworkRanges, setAmassIntelNetworkRanges] = useState([]);
  const [metabigorNetworkRanges, setMetabigorNetworkRanges] = useState([]);
  const [subdomains, setSubdomains] = useState([]);
  const [showSubdomainsModal, setShowSubdomainsModal] = useState(false);
  const [cloudDomains, setCloudDomains] = useState([]);
  const [showCloudDomainsModal, setShowCloudDomainsModal] = useState(false);
  const [showToast, setShowToast] = useState(false);
  const [toastMessage, setToastMessage] = useState('');
  const [toastTitle, setToastTitle] = useState('Success');
  // Success or warning. The toast was success-only, so anything that went wrong had nowhere to go but
  // a blocking alert() the operator had to dismiss before they could carry on.
  const [toastVariant, setToastVariant] = useState('success');
  const [showInfraModal, setShowInfraModal] = useState(false);
  const [httpxScans, setHttpxScans] = useState([]);
  const [mostRecentHttpxScanStatus, setMostRecentHttpxScanStatus] = useState(null);
  const [mostRecentHttpxScan, setMostRecentHttpxScan] = useState(null);
  const [isHttpxScanning, setIsHttpxScanning] = useState(false);
  const [showHttpxResultsModal, setShowHttpxResultsModal] = useState(false);
  const [gauScans, setGauScans] = useState([]);
  const [mostRecentGauScanStatus, setMostRecentGauScanStatus] = useState(null);
  const [mostRecentGauScan, setMostRecentGauScan] = useState(null);
  const [isGauScanning, setIsGauScanning] = useState(false);
  const [showGauResultsModal, setShowGauResultsModal] = useState(false);
  const [sublist3rScans, setSublist3rScans] = useState([]);
  const [mostRecentSublist3rScanStatus, setMostRecentSublist3rScanStatus] = useState(null);
  const [mostRecentSublist3rScan, setMostRecentSublist3rScan] = useState(null);
  const [isSublist3rScanning, setIsSublist3rScanning] = useState(false);
  const [showSublist3rResultsModal, setShowSublist3rResultsModal] = useState(false);
  const [assetfinderScans, setAssetfinderScans] = useState([]);
  const [mostRecentAssetfinderScanStatus, setMostRecentAssetfinderScanStatus] = useState(null);
  const [mostRecentAssetfinderScan, setMostRecentAssetfinderScan] = useState(null);
  const [isAssetfinderScanning, setIsAssetfinderScanning] = useState(false);
  const [showAssetfinderResultsModal, setShowAssetfinderResultsModal] = useState(false);
  const [showCTLResultsModal, setShowCTLResultsModal] = useState(false);
  const [showCTLApiErrorModal, setShowCTLApiErrorModal] = useState(false);
  const [ctlScans, setCTLScans] = useState([]);
  const [isCTLScanning, setIsCTLScanning] = useState(false);
  const [mostRecentCTLScan, setMostRecentCTLScan] = useState(null);
  const [mostRecentCTLScanStatus, setMostRecentCTLScanStatus] = useState(null);
  const [showSubfinderResultsModal, setShowSubfinderResultsModal] = useState(false);
  const [subfinderScans, setSubfinderScans] = useState([]);
  const [mostRecentSubfinderScanStatus, setMostRecentSubfinderScanStatus] = useState(null);
  const [mostRecentSubfinderScan, setMostRecentSubfinderScan] = useState(null);
  const [isSubfinderScanning, setIsSubfinderScanning] = useState(false);
  const [showShuffleDNSResultsModal, setShowShuffleDNSResultsModal] = useState(false);
  const [shuffleDNSScans, setShuffleDNSScans] = useState([]);
  const [mostRecentShuffleDNSScanStatus, setMostRecentShuffleDNSScanStatus] = useState(null);
  const [mostRecentShuffleDNSScan, setMostRecentShuffleDNSScan] = useState(null);
  const [isShuffleDNSScanning, setIsShuffleDNSScanning] = useState(false);
  const [showReconResultsModal, setShowReconResultsModal] = useState(false);
  const [consolidatedSubdomains, setConsolidatedSubdomains] = useState([]);
  const [isConsolidating, setIsConsolidating] = useState(false);
  const [consolidatedCount, setConsolidatedCount] = useState(0);
  const [consolidatedCompanyDomains, setConsolidatedCompanyDomains] = useState([]);
  const [consolidatedCompanyDomainsCount, setConsolidatedCompanyDomainsCount] = useState(0);
  const [isConsolidatingCompanyDomains, setIsConsolidatingCompanyDomains] = useState(false);
  const [consolidatedNetworkRanges, setConsolidatedNetworkRanges] = useState([]);
  const [consolidatedNetworkRangesCount, setConsolidatedNetworkRangesCount] = useState(0);
  const [isConsolidatingNetworkRanges, setIsConsolidatingNetworkRanges] = useState(false);
  const [isConsolidatingAttackSurface, setIsConsolidatingAttackSurface] = useState(false);
  const [isInvestigatingFQDNs, setIsInvestigatingFQDNs] = useState(false);
  const [consolidatedAttackSurfaceResult, setConsolidatedAttackSurfaceResult] = useState(null);
  const [attackSurfaceASNsCount, setAttackSurfaceASNsCount] = useState(0);
  const [attackSurfaceNetworkRangesCount, setAttackSurfaceNetworkRangesCount] = useState(0);
  const [attackSurfaceIPAddressesCount, setAttackSurfaceIPAddressesCount] = useState(0);
  const [attackSurfaceLiveWebServersCount, setAttackSurfaceLiveWebServersCount] = useState(0);
  const [attackSurfaceCloudAssetsCount, setAttackSurfaceCloudAssetsCount] = useState(0);
  const [attackSurfaceFQDNsCount, setAttackSurfaceFQDNsCount] = useState(0);
  const [showUniqueSubdomainsModal, setShowUniqueSubdomainsModal] = useState(false);
  const [showConfigureHttpxModal, setShowConfigureHttpxModal] = useState(false);
  const [httpxScanConfig, setHttpxScanConfig] = useState(null);
  const [mostRecentCeWLScanStatus, setMostRecentCeWLScanStatus] = useState(null);
  const [mostRecentCeWLScan, setMostRecentCeWLScan] = useState(null);
  const [isCeWLScanning, setIsCeWLScanning] = useState(false);
  const [showCeWLResultsModal, setShowCeWLResultsModal] = useState(false);
  const [cewlScans, setCeWLScans] = useState([]);
  const [mostRecentShuffleDNSCustomScan, setMostRecentShuffleDNSCustomScan] = useState(null);
  const [mostRecentShuffleDNSCustomScanStatus, setMostRecentShuffleDNSCustomScanStatus] = useState(null);
  const [showGoSpiderResultsModal, setShowGoSpiderResultsModal] = useState(false);
  const [gospiderScans, setGoSpiderScans] = useState([]);
  const [mostRecentGoSpiderScanStatus, setMostRecentGoSpiderScanStatus] = useState(null);
  const [mostRecentGoSpiderScan, setMostRecentGoSpiderScan] = useState(null);
  const [isGoSpiderScanning, setIsGoSpiderScanning] = useState(false);
  const [showSubdomainizerResultsModal, setShowSubdomainizerResultsModal] = useState(false);
  const [subdomainizerScans, setSubdomainizerScans] = useState([]);
  const [mostRecentSubdomainizerScanStatus, setMostRecentSubdomainizerScanStatus] = useState(null);
  const [mostRecentSubdomainizerScan, setMostRecentSubdomainizerScan] = useState(null);
  const [isSubdomainizerScanning, setIsSubdomainizerScanning] = useState(false);
  const [showScreenshotResultsModal, setShowScreenshotResultsModal] = useState(false);
  const [nucleiScreenshotScans, setNucleiScreenshotScans] = useState([]);
  const [mostRecentNucleiScreenshotScanStatus, setMostRecentNucleiScreenshotScanStatus] = useState(null);
  const [mostRecentNucleiScreenshotScan, setMostRecentNucleiScreenshotScan] = useState(null);
  const [isNucleiScreenshotScanning, setIsNucleiScreenshotScanning] = useState(false);
  const [investigateScans, setInvestigateScans] = useState([]);
  const [mostRecentInvestigateScanStatus, setMostRecentInvestigateScanStatus] = useState(null);
  const [mostRecentInvestigateScan, setMostRecentInvestigateScan] = useState(null);
  const [isInvestigateScanning, setIsInvestigateScanning] = useState(false);
  const [targetURLs, setTargetURLs] = useState([]);
  const [showROIReport, setShowROIReport] = useState(false);
  const [selectedTargetURL, setSelectedTargetURL] = useState(null);
  const [shuffleDNSCustomScans, setShuffleDNSCustomScans] = useState([]);
  const [showSettingsModal, setShowSettingsModal] = useState(false);
  const [showToolsModal, setShowToolsModal] = useState(false);
  const [toolsModalInitialUrls, setToolsModalInitialUrls] = useState('');
  const [toolsModalInitialTab, setToolsModalInitialTab] = useState('url-populator');
  const [isAutoScanning, setIsAutoScanning] = useState(false);
  const [autoScanCurrentStep, setAutoScanCurrentStep] = useState(AUTO_SCAN_STEPS.IDLE);
  const [autoScanTargetId, setAutoScanTargetId] = useState(null);
  const [autoScanSessionId, setAutoScanSessionId] = useState(null);
  const [showAutoScanHistoryModal, setShowAutoScanHistoryModal] = useState(false);
  const [autoScanSessions, setAutoScanSessions] = useState([]);
  // Add these state variables near the other auto scan related states
  const [isAutoScanPaused, setIsAutoScanPaused] = useState(false);
  const [isAutoScanPausing, setIsAutoScanPausing] = useState(false);
  const [isAutoScanCancelling, setIsAutoScanCancelling] = useState(false);

  const [showGlobalScansModal, setShowGlobalScansModal] = useState(false);
  const [showNotesModal, setShowNotesModal] = useState(false);
  const [isWildfireRunning, setIsWildfireRunning] = useState(false);
  const [, setWildfireCancelled] = useState(false);
  const [wildfireProgress, setWildfireProgress] = useState(null);
  const wildfireCancelledRef = useRef(false);

  // Slowburn state
  const [isSlowburnRunning, setIsSlowburnRunning] = useState(false);
  const [slowburnProgress, setSlowburnProgress] = useState(null);
  const slowburnCancelledRef = useRef(false);
  const activeTargetRef = useRef(null);
  const httpxScanConfigRef = useRef(null);
  activeTargetRef.current = activeTarget;
  httpxScanConfigRef.current = httpxScanConfig;

  const [ctlCompanyScans, setCTLCompanyScans] = useState([]);
  const [mostRecentCTLCompanyScanStatus, setMostRecentCTLCompanyScanStatus] = useState(null);
  const [mostRecentCTLCompanyScan, setMostRecentCTLCompanyScan] = useState(null);
  const [isCTLCompanyScanning, setIsCTLCompanyScanning] = useState(false);
  const [showCTLCompanyResultsModal, setShowCTLCompanyResultsModal] = useState(false);
  const [showCTLCompanyHistoryModal, setShowCTLCompanyHistoryModal] = useState(false);
  const [metabigorCompanyScans, setMetabigorCompanyScans] = useState([]);
  const [mostRecentMetabigorCompanyScanStatus, setMostRecentMetabigorCompanyScanStatus] = useState(null);
  const [mostRecentMetabigorCompanyScan, setMostRecentMetabigorCompanyScan] = useState(null);
  const [isMetabigorCompanyScanning, setIsMetabigorCompanyScanning] = useState(false);
  const [showMetabigorCompanyResultsModal, setShowMetabigorCompanyResultsModal] = useState(false);
  const [showMetabigorCompanyHistoryModal, setShowMetabigorCompanyHistoryModal] = useState(false);
  const [googleDorkingScans, setGoogleDorkingScans] = useState([]);
  const [mostRecentGoogleDorkingScanStatus, setMostRecentGoogleDorkingScanStatus] = useState(null);
  const [mostRecentGoogleDorkingScan, setMostRecentGoogleDorkingScan] = useState(null);
  const [isGoogleDorkingScanning, setIsGoogleDorkingScanning] = useState(false);
  const [showGoogleDorkingResultsModal, setShowGoogleDorkingResultsModal] = useState(false);
  const [showGoogleDorkingHistoryModal, setShowGoogleDorkingHistoryModal] = useState(false);
  const [showGoogleDorkingManualModal, setShowGoogleDorkingManualModal] = useState(false);
  const [googleDorkingDomains, setGoogleDorkingDomains] = useState([]);
  const [googleDorkingError, setGoogleDorkingError] = useState('');
  const [showAPIKeysConfigModal, setShowAPIKeysConfigModal] = useState(false);
  const [settingsModalInitialTab, setSettingsModalInitialTab] = useState('rate-limits');
  const [showReverseWhoisResultsModal, setShowReverseWhoisResultsModal] = useState(false);
  const [showReverseWhoisManualModal, setShowReverseWhoisManualModal] = useState(false);
  const [reverseWhoisDomains, setReverseWhoisDomains] = useState([]);
  const [reverseWhoisError, setReverseWhoisError] = useState('');
  const [securityTrailsCompanyScans, setSecurityTrailsCompanyScans] = useState([]);
  const [mostRecentSecurityTrailsCompanyScan, setMostRecentSecurityTrailsCompanyScan] = useState(null);
  const [mostRecentSecurityTrailsCompanyScanStatus, setMostRecentSecurityTrailsCompanyScanStatus] = useState(null);
  const [isSecurityTrailsCompanyScanning, setIsSecurityTrailsCompanyScanning] = useState(false);
  const [showSecurityTrailsCompanyResultsModal, setShowSecurityTrailsCompanyResultsModal] = useState(false);
  // Add state for history modal
  const [showSecurityTrailsCompanyHistoryModal, setShowSecurityTrailsCompanyHistoryModal] = useState(false);
  const [hasSecurityTrailsApiKey, setHasSecurityTrailsApiKey] = useState(false);
  const [showCensysCompanyResultsModal, setShowCensysCompanyResultsModal] = useState(false);
  const [showCensysCompanyHistoryModal, setShowCensysCompanyHistoryModal] = useState(false);
  const [censysCompanyScans, setCensysCompanyScans] = useState([]);
  const [mostRecentCensysCompanyScan, setMostRecentCensysCompanyScan] = useState(null);
  const [mostRecentCensysCompanyScanStatus, setMostRecentCensysCompanyScanStatus] = useState(null);
  const [isCensysCompanyScanning, setIsCensysCompanyScanning] = useState(false);
  const [hasCensysApiKey, setHasCensysApiKey] = useState(false);
  const [showGitHubReconResultsModal, setShowGitHubReconResultsModal] = useState(false);
  const [showGitHubReconHistoryModal, setShowGitHubReconHistoryModal] = useState(false);
  const [gitHubReconScans, setGitHubReconScans] = useState([]);
  const [mostRecentGitHubReconScan, setMostRecentGitHubReconScan] = useState(null);
  const [mostRecentGitHubReconScanStatus, setMostRecentGitHubReconScanStatus] = useState(null);
  const [isGitHubReconScanning, setIsGitHubReconScanning] = useState(false);
  const [hasGitHubApiKey, setHasGitHubApiKey] = useState(false);
  const [showShodanCompanyResultsModal, setShowShodanCompanyResultsModal] = useState(false);
  const [showShodanCompanyHistoryModal, setShowShodanCompanyHistoryModal] = useState(false);
  const [shodanCompanyScans, setShodanCompanyScans] = useState([]);
  const [mostRecentShodanCompanyScan, setMostRecentShodanCompanyScan] = useState(null);
  const [mostRecentShodanCompanyScanStatus, setMostRecentShodanCompanyScanStatus] = useState(null);
  const [isShodanCompanyScanning, setIsShodanCompanyScanning] = useState(false);
  const [hasShodanApiKey, setHasShodanApiKey] = useState(false);
  const [showAddWildcardTargetsModal, setShowAddWildcardTargetsModal] = useState(false);
  const [showTrimRootDomainsModal, setShowTrimRootDomainsModal] = useState(false);
  const [showTrimNetworkRangesModal, setShowTrimNetworkRangesModal] = useState(false);
  const [rootDomainsByTool, setRootDomainsByTool] = useState({});
  const [showLiveWebServersResultsModal, setShowLiveWebServersResultsModal] = useState(false);
  const [showAmassEnumConfigModal, setShowAmassEnumConfigModal] = useState(false);
  const [amassEnumSelectedDomainsCount, setAmassEnumSelectedDomainsCount] = useState(0);
  const [amassEnumScannedDomainsCount, setAmassEnumScannedDomainsCount] = useState(0);

  const [amassEnumWildcardDomainsCount, setAmassEnumWildcardDomainsCount] = useState(0);
  const [showAmassEnumCompanyResultsModal, setShowAmassEnumCompanyResultsModal] = useState(false);
  const [showAmassEnumCompanyHistoryModal, setShowAmassEnumCompanyHistoryModal] = useState(false);
  const [amassEnumCompanyScans, setAmassEnumCompanyScans] = useState([]);
  const [mostRecentAmassEnumCompanyScan, setMostRecentAmassEnumCompanyScan] = useState(null);
  const [mostRecentAmassEnumCompanyScanStatus, setMostRecentAmassEnumCompanyScanStatus] = useState(null);
  const [isAmassEnumCompanyScanning, setIsAmassEnumCompanyScanning] = useState(false);
  const [amassEnumCompanyCloudDomains, setAmassEnumCompanyCloudDomains] = useState([]);
  const [showAmassIntelConfigModal, setShowAmassIntelConfigModal] = useState(false);
  const [amassIntelSelectedNetworkRangesCount, setAmassIntelSelectedNetworkRangesCount] = useState(0);
  const [showDNSxConfigModal, setShowDNSxConfigModal] = useState(false);
  // Removed unused DNSx wildcard targets variable - replaced with domains count below
  const [ipPortScans, setIPPortScans] = useState([]);
  const [mostRecentIPPortScan, setMostRecentIPPortScan] = useState(null);
  const [mostRecentIPPortScanStatus, setMostRecentIPPortScanStatus] = useState(null);
  const [isIPPortScanning, setIsIPPortScanning] = useState(false);
  const [MetaDataScans, setMetaDataScans] = useState([]);
  const [mostRecentMetaDataScanStatus, setMostRecentMetaDataScanStatus] = useState(null);
  const [mostRecentMetaDataScan, setMostRecentMetaDataScan] = useState(null);
  const [isMetaDataScanning, setIsMetaDataScanning] = useState(false);
  const [showMetaDataModal, setShowMetaDataModal] = useState(false);
  const [showConfigureMetaDataModal, setShowConfigureMetaDataModal] = useState(false);

  // G1.7: react-query backs the heavy target-urls reads (Metadata / ROI / Metadata-config). Each
  // query is enabled only while its modal is open and is keyed to the active target, so switching
  // targets cancels the in-flight request (no stale overwrites), concurrent callers de-dup, and
  // reopening is cache-fast. Results are mirrored into the shared `targetURLs` state the modals
  // already consume, so the modals stay unchanged. Optimistic edits (delete / scan-complete) go
  // through the wrapped setters below so the cache stays in sync with the mirror.
  const queryClient = useQueryClient();

  const configureMetaDataQuery = useTargetURLs(activeTarget?.id, {
    projection: 'lean',
    enabled: showConfigureMetaDataModal,
  });
  const metaDataQuery = useTargetURLs(activeTarget?.id, {
    projection: 'meta',
    enabled: showMetaDataModal,
  });
  const roiReportQuery = useTargetURLs(activeTarget?.id, {
    projection: 'no-screenshot',
    enabled: showROIReport,
  });

  useEffect(() => {
    if (showConfigureMetaDataModal && configureMetaDataQuery.data) {
      setTargetURLs(configureMetaDataQuery.data);
    }
  }, [showConfigureMetaDataModal, configureMetaDataQuery.data]);

  useEffect(() => {
    if (showMetaDataModal && metaDataQuery.data) {
      setTargetURLs(metaDataQuery.data);
    }
  }, [showMetaDataModal, metaDataQuery.data]);

  useEffect(() => {
    if (showROIReport && roiReportQuery.data) {
      setTargetURLs(roiReportQuery.data);
    }
  }, [showROIReport, roiReportQuery.data]);

  // Wrapped setters for the modals that edit the list optimistically (delete a row, or the
  // scan-complete refresh): update the shared mirror AND the matching react-query cache entry so
  // reopening the screen doesn't resurrect a just-deleted row from a stale cache.
  const setMetaDataTargetURLs = useCallback((value) => {
    setTargetURLs(value);
    if (activeTarget?.id) {
      queryClient.setQueryData(targetURLsKey(activeTarget.id, 'meta'), value);
    }
  }, [activeTarget, queryClient]);

  const setRoiTargetURLs = useCallback((value) => {
    setTargetURLs(value);
    if (activeTarget?.id) {
      queryClient.setQueryData(targetURLsKey(activeTarget.id, 'no-screenshot'), value);
    }
  }, [activeTarget, queryClient]);

  // G1.9: cancel every scheduled scan poll when the active target changes (or on unmount). React
  // runs all effect cleanups before any setups in a commit, so this fires before the monitor
  // effects below restart polling for the new target — the previous target's recursive
  // setTimeout chains (now routed through the cancelable pollTimeout) stop instead of leaking and
  // racing. This bounds the live-timer count regardless of how many times the user switches.
  useEffect(() => {
    return () => {
      cancelAllScanPolls();
    };
  }, [activeTarget]);

  const [metaDataScanConfigs, setMetaDataScanConfigs] = useState({});
  const [companyMetaDataScans, setCompanyMetaDataScans] = useState([]);
  const [mostRecentCompanyMetaDataScanStatus, setMostRecentCompanyMetaDataScanStatus] = useState(null);
  const [mostRecentCompanyMetaDataScan, setMostRecentCompanyMetaDataScan] = useState(null);
  const [isCompanyMetaDataScanning, setIsCompanyMetaDataScanning] = useState(false);
  const [companyMetaDataResults, setCompanyMetaDataResults] = useState([]);

  // DNSx Company scan state variables
  const [dnsxSelectedDomainsCount, setDnsxSelectedDomainsCount] = useState(0);
  const [dnsxScannedDomainsCount, setDnsxScannedDomainsCount] = useState(0);

  const [dnsxWildcardDomainsCount, setDnsxWildcardDomainsCount] = useState(0);
  const [showDNSxCompanyResultsModal, setShowDNSxCompanyResultsModal] = useState(false);
  const [showDNSxCompanyHistoryModal, setShowDNSxCompanyHistoryModal] = useState(false);
  const [dnsxCompanyScans, setDnsxCompanyScans] = useState([]);
  const [mostRecentDNSxCompanyScan, setMostRecentDNSxCompanyScan] = useState(null);
  const [mostRecentDNSxCompanyScanStatus, setMostRecentDNSxCompanyScanStatus] = useState(null);
  const [isDNSxCompanyScanning, setIsDNSxCompanyScanning] = useState(false);
  const [dnsxCompanyDnsRecords, setDnsxCompanyDnsRecords] = useState([]);

  const [cloudEnumScans, setCloudEnumScans] = useState([]);
  const [mostRecentCloudEnumScanStatus, setMostRecentCloudEnumScanStatus] = useState(null);
  const [mostRecentCloudEnumScan, setMostRecentCloudEnumScan] = useState(null);
  const [isCloudEnumScanning, setIsCloudEnumScanning] = useState(false);
  const [showCloudEnumResultsModal, setShowCloudEnumResultsModal] = useState(false);
  const [showCloudEnumHistoryModal, setShowCloudEnumHistoryModal] = useState(false);
  const [showCloudEnumConfigModal, setShowCloudEnumConfigModal] = useState(false);
  const [showNucleiConfigModal, setShowNucleiConfigModal] = useState(false);
  const [nucleiScans, setNucleiScans] = useState([]);
  const [mostRecentNucleiScan, setMostRecentNucleiScan] = useState(null);
  const [mostRecentNucleiScanStatus, setMostRecentNucleiScanStatus] = useState(null);
  const [isNucleiScanning, setIsNucleiScanning] = useState(false);
  const [nucleiConfig, setNucleiConfig] = useState(null);
  const [showNucleiResultsModal, setShowNucleiResultsModal] = useState(false);
  const [showNucleiHistoryModal, setShowNucleiHistoryModal] = useState(false);
  const [activeNucleiScan, setActiveNucleiScan] = useState(null);

  const [showWildcardNucleiConfigModal, setShowWildcardNucleiConfigModal] = useState(false);
  const [wildcardNucleiScans, setWildcardNucleiScans] = useState([]);
  const [mostRecentWildcardNucleiScan, setMostRecentWildcardNucleiScan] = useState(null);
  const [mostRecentWildcardNucleiScanStatus, setMostRecentWildcardNucleiScanStatus] = useState(null);
  const [isWildcardNucleiScanning, setIsWildcardNucleiScanning] = useState(false);
  const [wildcardNucleiConfig, setWildcardNucleiConfig] = useState(null);
  const [showWildcardNucleiResultsModal, setShowWildcardNucleiResultsModal] = useState(false);
  const [showWildcardNucleiHistoryModal, setShowWildcardNucleiHistoryModal] = useState(false);
  const [activeWildcardNucleiScan, setActiveWildcardNucleiScan] = useState(null);

  // Which Wildcard workflow tool the generic configuration modal is showing, as {key, name}. ONE modal
  // for every tool in the workflow: it renders whatever GET /wildcard-tools describes, so there is no
  // per-tool screen here to fall out of step with the server's vocabulary or with the MCP tool that
  // reads and writes the same rows.
  const [wildcardConfigTool, setWildcardConfigTool] = useState(null);

  // Which COMPANY workflow tool the generic configuration modal is showing, as {key, name}. Same
  // design as the Wildcard one above and for the same reason: it renders whatever GET /company-tools
  // describes, so there is no per-tool screen here to fall out of step with the server's vocabulary
  // or with the MCP company tool that reads and writes the same rows.
  //
  // The three Company tools that already own a target picker (Amass Enum, DNSx, Katana) do NOT use
  // this modal: their settings are extra tabs inside the picker they already have, so an operator
  // never has to know that two screens configure one tool.
  const [companyConfigTool, setCompanyConfigTool] = useState(null);

  // The on-prem IP/port scanner's own modal, which is not this generic one because it also has to
  // show WHICH network ranges and addresses the next scan will actually reach.
  const [showIPPortScanConfigModal, setShowIPPortScanConfigModal] = useState(false);

  // Katana Company state variables
  const [katanaCompanyScans, setKatanaCompanyScans] = useState([]);
  const [mostRecentKatanaCompanyScanStatus, setMostRecentKatanaCompanyScanStatus] = useState(null);
  const [mostRecentKatanaCompanyScan, setMostRecentKatanaCompanyScan] = useState(null);
  const [isKatanaCompanyScanning, setIsKatanaCompanyScanning] = useState(false);
  const [showKatanaCompanyResultsModal, setShowKatanaCompanyResultsModal] = useState(false);
  const [showKatanaCompanyHistoryModal, setShowKatanaCompanyHistoryModal] = useState(false);
  const [showKatanaCompanyConfigModal, setShowKatanaCompanyConfigModal] = useState(false);
  const [showExploreAttackSurfaceModal, setShowExploreAttackSurfaceModal] = useState(false);
  const [showAttackSurfaceVisualizationModal, setShowAttackSurfaceVisualizationModal] = useState(false);
  const [showManageAttackSurfaceModal, setShowManageAttackSurfaceModal] = useState(false);
  const [katanaCompanyCloudAssets, setKatanaCompanyCloudAssets] = useState([]);
  
  const [katanaURLScans, setKatanaURLScans] = useState([]);
  const [mostRecentKatanaURLScanStatus, setMostRecentKatanaURLScanStatus] = useState(null);
  const [mostRecentKatanaURLScan, setMostRecentKatanaURLScan] = useState(null);
  const [isKatanaURLScanning, setIsKatanaURLScanning] = useState(false);
  
  const [linkFinderURLScans, setLinkFinderURLScans] = useState([]);
  const [mostRecentLinkFinderURLScanStatus, setMostRecentLinkFinderURLScanStatus] = useState(null);
  const [mostRecentLinkFinderURLScan, setMostRecentLinkFinderURLScan] = useState(null);
  const [isLinkFinderURLScanning, setIsLinkFinderURLScanning] = useState(false);
  
  const [waybackURLsScans, setWaybackURLsScans] = useState([]);
  const [mostRecentWaybackURLsScanStatus, setMostRecentWaybackURLsScanStatus] = useState(null);
  const [mostRecentWaybackURLsScan, setMostRecentWaybackURLsScan] = useState(null);
  const [isWaybackURLsScanning, setIsWaybackURLsScanning] = useState(false);
  
  const [gauURLScans, setGAUURLScans] = useState([]);
  const [mostRecentGAUURLScanStatus, setMostRecentGAUURLScanStatus] = useState(null);
  const [mostRecentGAUURLScan, setMostRecentGAUURLScan] = useState(null);
  const [isGAUURLScanning, setIsGAUURLScanning] = useState(false);
  
  const [goSpiderURLScans, setGoSpiderURLScans] = useState([]);
  const [mostRecentGoSpiderURLScanStatus, setMostRecentGoSpiderURLScanStatus] = useState(null);
  const [mostRecentGoSpiderURLScan, setMostRecentGoSpiderURLScan] = useState(null);
  const [isGoSpiderURLScanning, setIsGoSpiderURLScanning] = useState(false);
  
  const [ffufURLScans, setFFUFURLScans] = useState([]);
  const [mostRecentFFUFURLScanStatus, setMostRecentFFUFURLScanStatus] = useState(null);
  const [mostRecentFFUFURLScan, setMostRecentFFUFURLScan] = useState(null);
  const [isFFUFURLScanning, setIsFFUFURLScanning] = useState(false);

  const [wafProbeScans, setWAFProbeScans] = useState([]);
  const [mostRecentWAFProbeScanStatus, setMostRecentWAFProbeScanStatus] = useState(null);
  const [mostRecentWAFProbeScan, setMostRecentWAFProbeScan] = useState(null);
  const [isWAFProbeScanning, setIsWAFProbeScanning] = useState(false);

  const [arjunScans, setArjunScans] = useState([]);
  const [mostRecentArjunScanStatus, setMostRecentArjunScanStatus] = useState(null);
  const [mostRecentArjunScan, setMostRecentArjunScan] = useState(null);
  const [isArjunScanning, setIsArjunScanning] = useState(false);
  
  
  const [x8Scans, setX8Scans] = useState([]);
  const [mostRecentX8ScanStatus, setMostRecentX8ScanStatus] = useState(null);
  const [mostRecentX8Scan, setMostRecentX8Scan] = useState(null);
  const [isX8Scanning, setIsX8Scanning] = useState(false);
  
  const [showKatanaURLResultsModal, setShowKatanaURLResultsModal] = useState(false);
  const [showLinkFinderURLResultsModal, setShowLinkFinderURLResultsModal] = useState(false);
  const [showWaybackURLsResultsModal, setShowWaybackURLsResultsModal] = useState(false);
  const [showGAUURLResultsModal, setShowGAUURLResultsModal] = useState(false);
  const [showGoSpiderURLResultsModal, setShowGoSpiderURLResultsModal] = useState(false);
  const [showFFUFURLResultsModal, setShowFFUFURLResultsModal] = useState(false);
  const [showWAFProbeResultsModal, setShowWAFProbeResultsModal] = useState(false);
  const [showWAFProbeConfigModal, setShowWAFProbeConfigModal] = useState(false);
  // A refused run is not a failure to report to the console. The message names the budget that is
  // short and the value that would clear it, which is only useful on screen.
  const [wafProbeRunError, setWafProbeRunError] = useState('');
  // How many endpoints are currently SELECTED to be scanned, read from the saved config rather than
  // from any scan. It is the only one of the four card numbers that describes intent instead of
  // history, which is why it is not derived from wafProbeScans.
  const [wafProbeTargetCount, setWafProbeTargetCount] = useState(null);

  // A 1-second tick, running ONLY while an Amass scan is in flight.
  //
  // The card cannot use getLatestScanTime for a running scan: that reads execution_time, which the
  // server writes when the scan FINISHES. Mid-run it is empty, so the card would show "---" or, if
  // the row had not been replaced yet, the PREVIOUS scan's duration presented as the current one.
  // Elapsed time is derived from the running scan's created_at instead, and this tick is what makes
  // it advance.
  const [scanClockTick, setScanClockTick] = useState(0);
  const amassScanRunning = isScanning || mostRecentAmassScanStatus === 'pending';
  useEffect(() => {
    if (!amassScanRunning) return undefined;
    const t = setInterval(() => setScanClockTick((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, [amassScanRunning]);

  const amassElapsed = useMemo(() => {
    if (!amassScanRunning) return null;
    const startedAt = mostRecentAmassScan?.created_at;
    if (!startedAt) return null;
    const secs = Math.max(0, Math.floor((Date.now() - new Date(startedAt).getTime()) / 1000));
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    const s = secs % 60;
    return h > 0
      ? `${h}h ${String(m).padStart(2, '0')}m`
      : `${m}m ${String(s).padStart(2, '0')}s`;
    // scanClockTick is the whole point of the dependency: it is what re-renders the clock.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [amassScanRunning, mostRecentAmassScan, scanClockTick]);
  // Which crawler's config modal is open, or null. One piece of state for all three, since only
  // one can be open at a time.
  const [crawlerConfigTool, setCrawlerConfigTool] = useState(null);
  // How many hosts each archive tool will actually query, versus how many it could. The default
  // host mode resolves at RUN time, so this is read from the server rather than derived from the
  // saved config: a config that says "default" does not itself know the number.
  const [archiveHostCounts, setArchiveHostCounts] = useState({
    waybackurls: null, gau: null,
  });
  // How much JavaScript LinkFinder will actually read, against how much has been discovered. The
  // two differ by default: the cap is 50 and truncation is silent, so without this the card cannot
  // distinguish a target with 50 bundles from one with 900.
  const [linkFinderJS, setLinkFinderJS] = useState(null);

  const [showArjunConfigModal, setShowArjunConfigModal] = useState(false);
  const [showArjunResultsModal, setShowArjunResultsModal] = useState(false);
  const [showX8ConfigModal, setShowX8ConfigModal] = useState(false);
  const [showX8ResultsModal, setShowX8ResultsModal] = useState(false);
  const [showApplicationQuestionsModal, setShowApplicationQuestionsModal] = useState(false);
  const [showMechanismsModal, setShowMechanismsModal] = useState(false);
  const [showNotableObjectsModal, setShowNotableObjectsModal] = useState(false);
  const [showSecurityControlsModal, setShowSecurityControlsModal] = useState(false);
  const [showThreatModelModal, setShowThreatModelModal] = useState(false);
  const [showFFUFConfigModal, setShowFFUFConfigModal] = useState(false);
  const [showFFUFSettingsModal, setShowFFUFSettingsModal] = useState(false);
  const [showManualCrawlResultsModal, setShowManualCrawlResultsModal] = useState(false);
  const [showExtensionInstallModal, setShowExtensionInstallModal] = useState(false);
  const [manualCrawlConnected, setManualCrawlConnected] = useState(false);
  // Split the same way every other URL-workflow tool splits its results: direct is the scope
  // target's own host, adjacent is any other in-scope host (typically a separate API domain).
  // Previous liveness, so the card can refresh its counts the moment a recording stops rather
  // than sitting on stale numbers until the target is switched.
  const manualCrawlWasLiveRef = useRef(false);
  const manualCrawlRefreshTimeoutRef = useRef(null);
  const [manualCrawlDirectCount, setManualCrawlDirectCount] = useState(0);
  const [manualCrawlAdjacentCount, setManualCrawlAdjacentCount] = useState(0);
  // Distinct non-target hosts seen. This is the number that matters most for what to test next:
  // each one is a separate application surface the target talks to.
  const [manualCrawlAdjacentHostCount, setManualCrawlAdjacentHostCount] = useState(0);
  const [manualCrawlSessionCount, setManualCrawlSessionCount] = useState(0);
  const [showManageEndpointsModal, setShowManageEndpointsModal] = useState(false);
  const [consolidatedEndpointCount, setConsolidatedEndpointCount] = useState(0);
  const [isConsolidatingEndpoints, setIsConsolidatingEndpoints] = useState(false);
  // The latest validation scan, which drives the card's counts and the Investigate gate.
  const [endpointValidation, setEndpointValidation] = useState(null);
  // The combined run: Validate, then Investigate whatever Validate did not rule out. One record so
  // the card can show which phase is moving and the Results modal can show both from one run.
  const [endpointScanRun, setEndpointScanRun] = useState(null);
  const [isEndpointScanRunning, setIsEndpointScanRunning] = useState(false);
  const [showEndpointScanResultsModal, setShowEndpointScanResultsModal] = useState(false);
  // Surfaced on the card. A refusal to run is the most useful message this workflow produces and
  // it must not be swallowed into the console.
  const [endpointWorkflowError, setEndpointWorkflowError] = useState('');
  const [mechanismsForThreatModel, setMechanismsForThreatModel] = useState([]);
  const [notableObjectsForThreatModel, setNotableObjectsForThreatModel] = useState([]);
  const [securityControlsForThreatModel, setSecurityControlsForThreatModel] = useState([]);
  const [threatModelCounts, setThreatModelCounts] = useState({ questions: 0, mechanisms: 0, notableObjects: 0, securityControls: 0 });
  // The documented threats themselves, grouped by STRIDE category. Separate from the counts above,
  // which only measure the four supporting collections and say nothing about whether any threat has
  // actually been written.
  const [threatModelResults, setThreatModelResults] = useState({});
  const [showAuthFlowModal, setShowAuthFlowModal] = useState(false);
  const [authFlowCategory, setAuthFlowCategory] = useState('login');
  const [showClientIdentityModal, setShowClientIdentityModal] = useState(false);
  const [showPossibleAttacksModal, setShowPossibleAttacksModal] = useState(false);
  const [possibleAttacksCategory, setPossibleAttacksCategory] = useState(null);
  const [headerCookieCounts, setHeaderCookieCounts] = useState({ hidden_headers: 0, hidden_cookies: 0, client_side: 0, server_side: 0 });
  const [authzCounts, setAuthzCounts] = useState(
    { patterns: 0, parameter: 0, rules: 0, forbidden: 0 });
  const [showPolicyAccessModal, setShowPolicyAccessModal] = useState(false);
  const [showRoleAccessModal, setShowRoleAccessModal] = useState(false);
  const [showDiscretionaryAccessModal, setShowDiscretionaryAccessModal] = useState(false);
  const [authFlowCounts, setAuthFlowCounts] = useState(
    { register: 0, login: 0, mfa_otp: 0, magic_link: 0, reset: 0, total: 0, recorded: 0 });
  // Session tokens the operator has saved, and how many are switched on. Active is the number that
  // decides whether every other scan runs authenticated or against a login wall.
  const [sessionTokenCounts, setSessionTokenCounts] = useState({ total: 0, active: 0 });
  const [showRecordAuthFlowsModal, setShowRecordAuthFlowsModal] = useState(false);
  const [showManualAuthFlowModal, setShowManualAuthFlowModal] = useState(false);
  const [showManageSessionsModal, setShowManageSessionsModal] = useState(false);
  const [showRefreshSessionModal, setShowRefreshSessionModal] = useState(false);
  
  const handleCloseSubdomainsModal = () => setShowSubdomainsModal(false);
  const handleCloseCloudDomainsModal = () => setShowCloudDomainsModal(false);
  const handleCloseUniqueSubdomainsModal = () => setShowUniqueSubdomainsModal(false);
  const handleCloseMetaDataModal = () => setShowMetaDataModal(false);
  
  const handleOpenConfigureMetaDataModal = () => {
    // G1.7: target-urls are loaded by configureMetaDataQuery (enabled on open), not fetched here.
    setShowConfigureMetaDataModal(true);
  };
  
  const handleCloseConfigureMetaDataModal = () => setShowConfigureMetaDataModal(false);
  
  const handleSaveMetaDataConfig = (config) => {
    if (!activeTarget) return;
    setMetaDataScanConfigs(prev => ({
      ...prev,
      [activeTarget.id]: config
    }));
  };
  
  const handleCloseToolsModal = () => {
    setShowToolsModal(false);
    setToolsModalInitialUrls('');
    setToolsModalInitialTab('url-populator');
  };

  const handleCloseSettingsModal = () => {
    setShowSettingsModal(false);
    const checkApiKeys = async () => {
      try {
        const response = await fetch(
          `/api/api/api-keys`
        );
        if (!response.ok) {
          throw new Error('Failed to fetch API keys');
        }
        const data = await response.json();
        
        // Check SecurityTrails API key based on localStorage selection
        const selectedSecurityTrailsKey = localStorage.getItem('selectedApiKey_SecurityTrails');
        const hasSecurityTrailsKey = selectedSecurityTrailsKey && 
          Array.isArray(data) && 
          data.some(key => 
            key.tool_name === 'SecurityTrails' && 
            key.api_key_name === selectedSecurityTrailsKey &&
            key.key_values?.api_key?.trim() !== ''
          );
        setHasSecurityTrailsApiKey(hasSecurityTrailsKey);
        
        // Check GitHub API key based on localStorage selection
        const selectedGitHubKey = localStorage.getItem('selectedApiKey_GitHub');
        const hasGitHubKey = selectedGitHubKey && 
          Array.isArray(data) && 
          data.some(key => 
            key.tool_name === 'GitHub' && 
            key.api_key_name === selectedGitHubKey &&
            key.key_values?.api_key?.trim() !== ''
          );
        setHasGitHubApiKey(hasGitHubKey);
        
        // Check Censys API key based on localStorage selection
        const selectedCensysKey = localStorage.getItem('selectedApiKey_Censys');
        const hasCensysKey = selectedCensysKey && 
          Array.isArray(data) && 
          data.some(key => 
            key.tool_name === 'Censys' && 
            key.api_key_name === selectedCensysKey &&
            key.key_values?.app_id?.trim() !== '' && 
            key.key_values?.app_secret?.trim() !== ''
          );
        setHasCensysApiKey(hasCensysKey);
        
        // Check Shodan API key based on localStorage selection
        const selectedShodanKey = localStorage.getItem('selectedApiKey_Shodan');
        const hasShodanKey = selectedShodanKey && 
          Array.isArray(data) && 
          data.some(key => 
            key.tool_name === 'Shodan' && 
            key.api_key_name === selectedShodanKey &&
            key.key_values?.api_key?.trim() !== ''
          );
        setHasShodanApiKey(hasShodanKey);
      } catch (error) {
        console.error('[API-KEYS] Error checking API keys:', error);
        setHasSecurityTrailsApiKey(false);
        setHasGitHubApiKey(false);
        setHasCensysApiKey(false);
        setHasShodanApiKey(false);
      }
    };
    checkApiKeys();
  };
  const handleCloseExportModal = () => {
    setShowExportModal(false);
  };
  const handleCloseSecurityTrailsCompanyResultsModal = () => setShowSecurityTrailsCompanyResultsModal(false);
  const handleOpenSecurityTrailsCompanyResultsModal = () => setShowSecurityTrailsCompanyResultsModal(true);
  // Add handler for history modal
  const handleCloseSecurityTrailsCompanyHistoryModal = () => setShowSecurityTrailsCompanyHistoryModal(false);
  const handleOpenSecurityTrailsCompanyHistoryModal = () => setShowSecurityTrailsCompanyHistoryModal(true);
  const handleCloseCensysCompanyResultsModal = () => setShowCensysCompanyResultsModal(false);
  const handleOpenCensysCompanyResultsModal = () => setShowCensysCompanyResultsModal(true);
  const handleCloseCensysCompanyHistoryModal = () => setShowCensysCompanyHistoryModal(false);
  const handleOpenCensysCompanyHistoryModal = () => setShowCensysCompanyHistoryModal(true);
  const handleCloseGitHubReconResultsModal = () => setShowGitHubReconResultsModal(false);
  const handleOpenGitHubReconResultsModal = () => setShowGitHubReconResultsModal(true);
  const handleCloseGitHubReconHistoryModal = () => setShowGitHubReconHistoryModal(false);
  const handleOpenGitHubReconHistoryModal = () => setShowGitHubReconHistoryModal(true);
  const handleCloseShodanCompanyResultsModal = () => setShowShodanCompanyResultsModal(false);
  const handleOpenShodanCompanyResultsModal = () => setShowShodanCompanyResultsModal(true);

  const handleCloseShodanCompanyHistoryModal = () => setShowShodanCompanyHistoryModal(false);
  const handleOpenShodanCompanyHistoryModal = () => setShowShodanCompanyHistoryModal(true);

  const handleCloseAddWildcardTargetsModal = () => setShowAddWildcardTargetsModal(false);
  const handleOpenAddWildcardTargetsModal = () => setShowAddWildcardTargetsModal(true);

  const handleCloseTrimRootDomainsModal = () => setShowTrimRootDomainsModal(false);
  const handleOpenTrimRootDomainsModal = () => setShowTrimRootDomainsModal(true);

  const handleCloseTrimNetworkRangesModal = () => setShowTrimNetworkRangesModal(false);
  const handleOpenTrimNetworkRangesModal = () => setShowTrimNetworkRangesModal(true);

  const handleCloseLiveWebServersResultsModal = () => setShowLiveWebServersResultsModal(false);
  const handleOpenLiveWebServersResultsModal = () => setShowLiveWebServersResultsModal(true);

  const handleCloseAmassEnumConfigModal = () => setShowAmassEnumConfigModal(false);
  const handleOpenAmassEnumConfigModal = () => setShowAmassEnumConfigModal(true);

  const handleCloseAmassEnumCompanyResultsModal = () => setShowAmassEnumCompanyResultsModal(false);
  const handleOpenAmassEnumCompanyResultsModal = () => setShowAmassEnumCompanyResultsModal(true);
  
  const handleCloseAmassEnumCompanyHistoryModal = () => setShowAmassEnumCompanyHistoryModal(false);
  const handleOpenAmassEnumCompanyHistoryModal = () => setShowAmassEnumCompanyHistoryModal(true);

  const handleAmassEnumConfigSave = async (config) => {
    if (config && config.domains) {
      setAmassEnumSelectedDomainsCount(config.domains.length);
    }
    // Reload the complete config to recalculate wildcard domains count
    await loadAmassEnumConfig();
  };

  const loadAmassEnumConfig = async () => {
    if (!activeTarget?.id) return;

    try {
      const response = await fetch(
        `/api/amass-enum-config/${activeTarget.id}`
      );
      
      if (response.ok) {
        const config = await response.json();
        if (config.domains && Array.isArray(config.domains)) {
          setAmassEnumSelectedDomainsCount(config.domains.length);
        } else {
          setAmassEnumSelectedDomainsCount(0);
        }
        
        // Always calculate wildcard domains count from discovered domains
        if (config.wildcard_domains && Array.isArray(config.wildcard_domains) && config.wildcard_domains.length > 0) {
          try {
            // Fetch all scope targets to find wildcard targets
            const scopeTargetsResponse = await fetch(
              `/api/scopetarget/read`
            );
            
            if (scopeTargetsResponse.ok) {
              const scopeTargetsData = await scopeTargetsResponse.json();
              const targets = Array.isArray(scopeTargetsData) ? scopeTargetsData : scopeTargetsData.targets;
              
              if (targets && Array.isArray(targets)) {
                let totalDiscoveredDomains = 0;
                
                // Find wildcard targets that match our saved wildcard domains
                const wildcardTargets = targets.filter(target => {
                  if (!target || target.type !== 'Wildcard') return false;
                  
                  const rootDomainFromWildcard = target.scope_target.startsWith('*.') 
                    ? target.scope_target.substring(2) 
                    : target.scope_target;
                  
                  return config.wildcard_domains.includes(rootDomainFromWildcard);
                });
                
                // Count discovered domains from each wildcard target
                for (const wildcardTarget of wildcardTargets) {
                  try {
                    const liveWebServersResponse = await fetch(
                      `/api/api/scope-targets/${wildcardTarget.id}/target-urls`
                    );
                    
                    if (liveWebServersResponse.ok) {
                      const liveWebServersData = await liveWebServersResponse.json();
                      const targetUrls = Array.isArray(liveWebServersData) ? liveWebServersData : liveWebServersData.target_urls;
                      
                      if (targetUrls && Array.isArray(targetUrls)) {
                        const discoveredDomains = Array.from(new Set(
                          targetUrls
                            .map(url => {
                              try {
                                if (!url || !url.url) return null;
                                const urlObj = new URL(url.url);
                                return urlObj.hostname;
                              } catch {
                                return null;
                              }
                            })
                            .filter(domain => domain && domain !== wildcardTarget.scope_target)
                        ));
                        
                        totalDiscoveredDomains += discoveredDomains.length;
                      }
                    }
                  } catch (error) {
                    console.error(`Error fetching wildcard domains for ${wildcardTarget.scope_target}:`, error);
                  }
                }
                
                setAmassEnumWildcardDomainsCount(totalDiscoveredDomains);
              } else {
                setAmassEnumWildcardDomainsCount(0);
              }
            } else {
              setAmassEnumWildcardDomainsCount(0);
            }
          } catch (error) {
            console.error('Error calculating wildcard domains count:', error);
            setAmassEnumWildcardDomainsCount(0);
          }
        } else {
          setAmassEnumWildcardDomainsCount(0);
        }
      } else {
        setAmassEnumSelectedDomainsCount(0);
        setAmassEnumWildcardDomainsCount(0);
      }
    } catch (error) {
      console.error('Error loading Amass Enum config:', error);
      setAmassEnumSelectedDomainsCount(0);
      setAmassEnumWildcardDomainsCount(0);
    }
  };

  // Update scanned domains count and cloud domains when scan status changes
  useEffect(() => {
    const updateScanResults = async () => {
      if (activeTarget && mostRecentAmassEnumCompanyScan && mostRecentAmassEnumCompanyScan.scan_id && !isAmassEnumCompanyScanning && mostRecentAmassEnumCompanyScanStatus === 'success') {
        try {
          // Fetch raw results count
          const rawResultsResponse = await fetch(
            `/api/amass-enum-company/${mostRecentAmassEnumCompanyScan.scan_id}/raw-results`
          );
          if (rawResultsResponse.ok) {
            const rawResults = await rawResultsResponse.json();
            // Count unique domains from raw results, not total number of results
            const uniqueDomains = rawResults ? [...new Set(rawResults.map(result => result.domain))].length : 0;
            setAmassEnumScannedDomainsCount(uniqueDomains);
          }

          // Fetch cloud domains count
          const cloudDomainsResponse = await fetch(
            `/api/amass-enum-company/${mostRecentAmassEnumCompanyScan.scan_id}/cloud-domains`
          );
          if (cloudDomainsResponse.ok) {
            const cloudDomains = await cloudDomainsResponse.json();
            setAmassEnumCompanyCloudDomains(cloudDomains || []);
          }
        } catch (error) {
          console.error('Error updating scan results:', error);
        }
      }
    };
    
    updateScanResults();
  }, [mostRecentAmassEnumCompanyScan, mostRecentAmassEnumCompanyScanStatus, isAmassEnumCompanyScanning]); // Removed activeTarget to prevent race condition

  // Update DNSx scan results when scan status changes
  useEffect(() => {
    const updateDNSxScanResults = async () => {
      if (activeTarget && mostRecentDNSxCompanyScan && mostRecentDNSxCompanyScan.scan_id && mostRecentDNSxCompanyScanStatus === 'success') {
        try {
          // Get the actual number of root domains that were scanned from the scan configuration
          // instead of counting discovered DNS records from raw results
          if (mostRecentDNSxCompanyScan.domains && Array.isArray(mostRecentDNSxCompanyScan.domains)) {
            setDnsxScannedDomainsCount(mostRecentDNSxCompanyScan.domains.length);
          } else {
            setDnsxScannedDomainsCount(0);
          }

          // Fetch DNS records count
          const dnsRecordsResponse = await fetch(
            `/api/dnsx-company/${mostRecentDNSxCompanyScan.scan_id}/dns-records`
          );
          if (dnsRecordsResponse.ok) {
            const dnsRecords = await dnsRecordsResponse.json();
            setDnsxCompanyDnsRecords(dnsRecords || []);
          }
        } catch (error) {
          console.error('Error updating DNSx scan results:', error);
        }
      }
    };
    
    updateDNSxScanResults();
  }, [mostRecentDNSxCompanyScan, mostRecentDNSxCompanyScanStatus]); // Removed activeTarget to prevent race condition

  const handleCloseAmassIntelConfigModal = () => setShowAmassIntelConfigModal(false);
  const handleOpenAmassIntelConfigModal = () => setShowAmassIntelConfigModal(true);

  const handleAmassIntelConfigSave = (config) => {
    if (config && config.network_ranges) {
      setAmassIntelSelectedNetworkRangesCount(config.network_ranges.length);
    }
  };

  const loadAmassIntelConfig = async () => {
    if (!activeTarget?.id) return;

    try {
      const response = await fetch(
        `/api/amass-intel-config/${activeTarget.id}`
      );
      
      if (response.ok) {
        const config = await response.json();
        if (config.network_ranges && Array.isArray(config.network_ranges)) {
          setAmassIntelSelectedNetworkRangesCount(config.network_ranges.length);
        } else {
          setAmassIntelSelectedNetworkRangesCount(0);
        }
      } else {
        setAmassIntelSelectedNetworkRangesCount(0);
      }
    } catch (error) {
      console.error('Error loading Amass Intel config:', error);
      setAmassIntelSelectedNetworkRangesCount(0);
    }
  };


  const handleConsolidateNetworkRanges = async () => {
    if (!activeTarget) return;
    
    setIsConsolidatingNetworkRanges(true);
    try {
      const result = await consolidateNetworkRanges(activeTarget);
      if (result) {
        await fetchConsolidatedNetworkRanges(activeTarget, setConsolidatedNetworkRanges, setConsolidatedNetworkRangesCount);
      }
    } catch (error) {
      console.error('Error during network range consolidation:', error);
    } finally {
      setIsConsolidatingNetworkRanges(false);
    }
  };

  const handleDiscoverLiveIPs = async () => {
    if (!activeTarget) {
      console.warn('No active target available for IP/Port scan');
      return;
    }

    try {
      setIsIPPortScanning(true);
      const response = await initiateIPPortScan(activeTarget.id);
      console.log('IP/Port scan initiated:', response);

      // Start monitoring the scan status
      if (response.scan_id) {
        monitorIPPortScanStatus(
          response.scan_id,
          (statusData) => {
            setMostRecentIPPortScanStatus(statusData);
            console.log('IP/Port scan status update:', statusData);
          },
          (completedData) => {
            console.log('IP/Port scan completed:', completedData);
            setMostRecentIPPortScan(completedData);
            setIsIPPortScanning(false);
            // Refresh IP/Port scans list
            fetchIPPortScans(activeTarget, setIPPortScans, setMostRecentIPPortScan, setMostRecentIPPortScanStatus);
          },
          (error) => {
            console.error('IP/Port scan error:', error);
            setIsIPPortScanning(false);
          }
        );
      }
    } catch (error) {
      console.error('Error initiating IP/Port scan:', error);
      setIsIPPortScanning(false);
    }
  };

  const handlePortScanning = async () => {
    if (!activeTarget || !mostRecentIPPortScan || !mostRecentIPPortScan.scan_id) {
      console.error('Cannot initiate Company metadata scan: missing activeTarget or IP/Port scan');
      return;
    }

    console.log('Initiating Company metadata scan for IP/Port scan:', mostRecentIPPortScan.scan_id);
    
    try {
      setIsCompanyMetaDataScanning(true);
      
      const result = await initiateCompanyMetaDataScan(
        activeTarget,
        mostRecentIPPortScan.scan_id,
        monitorCompanyMetaDataScanStatus,
        setIsCompanyMetaDataScanning,
        setCompanyMetaDataScans,
        setMostRecentCompanyMetaDataScanStatus,
        setMostRecentCompanyMetaDataScan
      );
      
      if (result && result.success) {
        console.log('Company metadata scan initiated successfully');
      } else {
        console.error('Failed to initiate Company metadata scan');
        setIsCompanyMetaDataScanning(false);
      }
    } catch (error) {
      console.error('Error initiating Company metadata scan:', error);
      setIsCompanyMetaDataScanning(false);
    }
  };

  const handleLiveWebServersResults = () => {
    setShowLiveWebServersResultsModal(true);
  };

  const handleInvestigateRootDomains = () => {
    initiateInvestigateScan(
      activeTarget,
      monitorInvestigateScanStatus,
      setIsInvestigateScanning,
      setInvestigateScans,
      setMostRecentInvestigateScanStatus,
      setMostRecentInvestigateScan
    );
  };

  const handleValidateRootDomains = () => {
    console.log('Validate Root Domains clicked');
  };

  const handleAddWildcardTarget = async (domain) => {
    try {
      const response = await fetch(`/api/scopetarget/add`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type: 'Wildcard',
          mode: 'Passive',
          scope_target: domain,
          active: false,
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to add wildcard target');
      }

      await fetchScopeTargets();
      setToastTitle('Success');
      setToastMessage(`Added ${domain} as Wildcard target successfully`);
      setShowToast(true);
      setTimeout(() => setShowToast(false), 3000);
    } catch (error) {
      console.error('Error adding wildcard target:', error);
      throw error;
    }
  };

  useEffect(() => {
    fetchScopeTargets();
  }, [isScanning]);

  useEffect(() => {
    if (activeTarget && amassScans.length > 0) {
      setScanHistory(amassScans);
    }
  }, [activeTarget, amassScans, isScanning]);

  // Load Amass Enum config when component mounts and activeTarget becomes available
  useEffect(() => {
    if (activeTarget) {
      loadAmassEnumConfig();
    }
  }, [activeTarget?.id]); // Run when activeTarget.id changes (including initial load)

  // Load Amass Intel config when component mounts and activeTarget becomes available
  useEffect(() => {
    if (activeTarget) {
      loadAmassIntelConfig();
    }
  }, [activeTarget?.id]); // Run when activeTarget.id changes (including initial load)

  // Load DNSx config when component mounts and activeTarget becomes available
  useEffect(() => {
    if (activeTarget) {
      loadDNSxConfig();
    }
  }, [activeTarget?.id]); // Run when activeTarget.id changes (including initial load)

  // Load consolidated endpoint count when activeTarget changes
  useEffect(() => {
    if (activeTarget) {
      loadConsolidatedEndpointCount();
    } else {
      setConsolidatedEndpointCount(0);
    }
  }, [activeTarget?.id]);

  useEffect(() => {
    if (activeTarget) {
      fetchAmassScans(activeTarget, setAmassScans, setMostRecentAmassScan, setMostRecentAmassScanStatus, setDnsRecords, setSubdomains, setCloudDomains);
              fetchAmassIntelScans(activeTarget, setAmassIntelScans, setMostRecentAmassIntelScan, setMostRecentAmassIntelScanStatus, setAmassIntelNetworkRanges);
      fetchMetabigorCompanyScans(activeTarget, setMetabigorCompanyScans, setMostRecentMetabigorCompanyScan, setMostRecentMetabigorCompanyScanStatus, setMetabigorNetworkRanges);
      fetchHttpxScans(activeTarget, setHttpxScans, setMostRecentHttpxScan, setMostRecentHttpxScanStatus);
      fetchConsolidatedSubdomains(activeTarget, setConsolidatedSubdomains, setConsolidatedCount);
      fetchConsolidatedCompanyDomains(activeTarget, setConsolidatedCompanyDomains, setConsolidatedCompanyDomainsCount);
      fetchConsolidatedNetworkRanges(activeTarget, setConsolidatedNetworkRanges, setConsolidatedNetworkRangesCount);
      fetchAttackSurfaceAssetCounts(activeTarget, setAttackSurfaceASNsCount, setAttackSurfaceNetworkRangesCount, setAttackSurfaceIPAddressesCount, setAttackSurfaceLiveWebServersCount, setAttackSurfaceCloudAssetsCount, setAttackSurfaceFQDNsCount);
      // G1.8: AmassEnum/Intel/DNSx config already load via their own dedicated
      // [activeTarget?.id] effects above; the duplicate calls here were removed (storm cut).
      fetchGoogleDorkingDomains();
      fetchReverseWhoisDomains();
      fetchIPPortScans(activeTarget, setIPPortScans, setMostRecentIPPortScan, setMostRecentIPPortScanStatus);
      fetchNucleiScans(activeTarget, setNucleiScans, setMostRecentNucleiScan, setMostRecentNucleiScanStatus, setActiveNucleiScan);
      if (activeTarget.type === 'Wildcard') {
        fetchNucleiScans(activeTarget, setWildcardNucleiScans, setMostRecentWildcardNucleiScan, setMostRecentWildcardNucleiScanStatus, setActiveWildcardNucleiScan);
      }
    }
  }, [activeTarget]);

  useEffect(() => {
    if (activeTarget) {
      monitorScanStatus(
        activeTarget,
        setAmassScans,
        setMostRecentAmassScan,
        setIsScanning,
        setMostRecentAmassScanStatus,
        setDnsRecords,
        setSubdomains,
        setCloudDomains
      );
    }
  }, [activeTarget]);

  useEffect(() => {
    if (activeTarget) {
      monitorAmassIntelScanStatus(
        activeTarget,
        setAmassIntelScans,
        setMostRecentAmassIntelScan,
        setIsAmassIntelScanning,
        setMostRecentAmassIntelScanStatus,
        setAmassIntelNetworkRanges
      );
    }
  }, [activeTarget]);

  useEffect(() => {
    if (activeTarget) {
      monitorMetabigorCompanyScanStatus(
        activeTarget,
        setMetabigorCompanyScans,
        setMostRecentMetabigorCompanyScan,
        setIsMetabigorCompanyScanning,
        setMostRecentMetabigorCompanyScanStatus,
        setMetabigorNetworkRanges
      );
    }
  }, [activeTarget]);

  useEffect(() => {
    if (activeTarget) {
      monitorHttpxScanStatus(
        activeTarget,
        setHttpxScans,
        setMostRecentHttpxScan,
        setIsHttpxScanning,
        setMostRecentHttpxScanStatus
      );
    }
  }, [activeTarget]);

  useEffect(() => {
    if (activeTarget) {
      monitorGauScanStatus(
        activeTarget,
        setGauScans,
        setMostRecentGauScan,
        setIsGauScanning,
        setMostRecentGauScanStatus
      );
    }
  }, [activeTarget]);

  useEffect(() => {
    if (activeTarget) {
      monitorSublist3rScanStatus(
        activeTarget,
        setSublist3rScans,
        setMostRecentSublist3rScan,
        setIsSublist3rScanning,
        setMostRecentSublist3rScanStatus
      );
    }
  }, [activeTarget]);

  useEffect(() => {
    if (activeTarget) {
      monitorAssetfinderScanStatus(
        activeTarget,
        setAssetfinderScans,
        setMostRecentAssetfinderScan,
        setIsAssetfinderScanning,
        setMostRecentAssetfinderScanStatus
      );
    }
  }, [activeTarget]);

  useEffect(() => {
    if (activeTarget) {
      monitorCTLScanStatus(
        activeTarget,
        setCTLScans,
        setMostRecentCTLScan,
        setIsCTLScanning,
        setMostRecentCTLScanStatus
      );
    }
  }, [activeTarget]);

  useEffect(() => {
    if (activeTarget) {
      monitorSubfinderScanStatus(
        activeTarget,
        setSubfinderScans,
        setMostRecentSubfinderScan,
        setIsSubfinderScanning,
        setMostRecentSubfinderScanStatus
      );
    }
  }, [activeTarget]);

  useEffect(() => {
    if (activeTarget && activeTarget.type === 'URL') {
      monitorArjunScanStatus(
        activeTarget,
        setArjunScans,
        setMostRecentArjunScan,
        setIsArjunScanning,
        setMostRecentArjunScanStatus
      );
    }
  }, [activeTarget]);

  useEffect(() => {
    if (activeTarget && activeTarget.type === 'URL') {
      monitorX8ScanStatus(
        activeTarget,
        setX8Scans,
        setMostRecentX8Scan,
        setIsX8Scanning,
        setMostRecentX8ScanStatus
      );
    }
  }, [activeTarget]);

  useEffect(() => {
    if (activeTarget) {
      monitorShuffleDNSScanStatus(
        activeTarget,
        setShuffleDNSScans,
        setMostRecentShuffleDNSScan,
        setIsShuffleDNSScanning,
        setMostRecentShuffleDNSScanStatus
      );
    }
  }, [activeTarget]);

  useEffect(() => {
    if (activeTarget) {
      monitorCeWLScanStatus(
        activeTarget,
        setCeWLScans,
        setMostRecentCeWLScan,
        setIsCeWLScanning,
        setMostRecentCeWLScanStatus
      );
    }
  }, [activeTarget]);

  useEffect(() => {
    if (activeTarget) {
      const fetchCustomShuffleDNSScans = async () => {
        try {
          const response = await fetch(
            `/api/api/scope-targets/${activeTarget.id}/shufflednscustom-scans`
          );
          if (!response.ok) {
            throw new Error('Failed to fetch custom ShuffleDNS scans');
          }
          const scans = await response.json();
          if (scans && scans.length > 0) {
            const mostRecentScan = scans[0]; // Scans are ordered by created_at DESC
            setMostRecentShuffleDNSCustomScan(mostRecentScan);
            setMostRecentShuffleDNSCustomScanStatus(mostRecentScan.status);
            
            // If scan is complete and we were previously scanning, stop scanning
            if (isCeWLScanning && (mostRecentScan.status === 'success' || mostRecentScan.status === 'failed')) {
              setIsCeWLScanning(false);
            }
          }
        } catch (error) {
          console.error('Error fetching custom ShuffleDNS scans:', error);
        }
      };

      // Start polling if we're in the SHUFFLEDNS_CEWL step of auto scan OR if CeWL is scanning manually
      if ((isAutoScanning && autoScanCurrentStep === AUTO_SCAN_STEPS.SHUFFLEDNS_CEWL) || isCeWLScanning) {
        fetchCustomShuffleDNSScans();
        const interval = setInterval(fetchCustomShuffleDNSScans, 5000);
        return () => clearInterval(interval);
      } else {
        // If not in auto scan and not scanning, just fetch once
        fetchCustomShuffleDNSScans();
      }
    }
  }, [activeTarget, isAutoScanning, autoScanCurrentStep, isCeWLScanning]);

  // Add new useEffect for monitoring consolidated subdomains after scans complete
  useEffect(() => {
    if (activeTarget && (
      mostRecentAmassScanStatus === 'success' ||
      mostRecentSublist3rScanStatus === 'completed' ||
      mostRecentAssetfinderScanStatus === 'success' ||
      mostRecentGauScanStatus === 'success' ||
      mostRecentCTLScanStatus === 'success' ||
      mostRecentSubfinderScanStatus === 'success' ||
      mostRecentShuffleDNSScanStatus === 'success' ||
      mostRecentShuffleDNSCustomScanStatus === 'success'
    )) {
      fetchConsolidatedSubdomains(activeTarget, setConsolidatedSubdomains, setConsolidatedCount);
      fetchConsolidatedCompanyDomains(activeTarget, setConsolidatedCompanyDomains, setConsolidatedCompanyDomainsCount);
    }
  }, [
    activeTarget,
    mostRecentAmassScanStatus,
    mostRecentSublist3rScanStatus,
    mostRecentAssetfinderScanStatus,
    mostRecentGauScanStatus,
    mostRecentCTLScanStatus,
    mostRecentSubfinderScanStatus,
    mostRecentShuffleDNSScanStatus,
    mostRecentShuffleDNSCustomScanStatus
  ]);

  // Add a useEffect to resume an in-progress Auto Scan after page refresh
  useEffect(() => {
    if (activeTarget && activeTarget.id) {
      // Fetch the current step from the API
      const fetchAndCheckAutoScanState = async () => {
        try {
          // First check if there's an active session for this target
          const sessionResponse = await fetch(
            `/api/api/auto-scan/sessions?target_id=${activeTarget.id}`
          );
          
          if (sessionResponse.ok) {
            const sessions = await sessionResponse.json();
            const runningSession = Array.isArray(sessions) && sessions.length > 0 
              ? sessions.find(s => s.status === 'running' || s.status === 'pending')
              : null;
              
            if (runningSession) {
              console.log(`Found in-progress Auto Scan session: ${runningSession.id}`);
              setAutoScanSessionId(runningSession.id);
            }
          }
          
          // Then check the current step
          const response = await fetch(
            `/api/api/auto-scan-state/${activeTarget.id}`
          );
          
          if (response.ok) {
            const data = await response.json();
            const currentStep = data.current_step;
            
            if (currentStep && currentStep !== AUTO_SCAN_STEPS.IDLE && currentStep !== AUTO_SCAN_STEPS.COMPLETED) {
              console.log(`Detected in-progress Auto Scan (step: ${currentStep}). Attempting to resume...`);
              setIsAutoScanning(true);
              resumeAutoScan(currentStep);
            }
          }
        } catch (error) {
          console.error('Error checking auto scan state:', error);
        }
      };
      
      fetchAndCheckAutoScanState();
    }
  }, []);

  const resumeAutoScan = async (fromStep) => {
    resumeAutoScanUtil(
      fromStep,
      activeTarget,
      () => getAutoScanSteps(
          activeTarget,
        setAutoScanCurrentStep,
        // Scanning states
        setIsScanning,
        setIsSublist3rScanning,
        setIsAssetfinderScanning,
          setIsGauScanning,
          setIsCTLScanning,
          setIsSubfinderScanning,
        setIsConsolidating,
          setIsHttpxScanning,
        setIsShuffleDNSScanning,
        setIsCeWLScanning,
        setIsGoSpiderScanning,
        setIsSubdomainizerScanning,
          setIsNucleiScreenshotScanning,
          setIsMetaDataScanning,
        // Scans state updaters
        setAmassScans,
        setSublist3rScans,
        setAssetfinderScans,
        setGauScans,
        setCTLScans,
        setSubfinderScans,
        setHttpxScans,
        setShuffleDNSScans,
        setCeWLScans,
        setGoSpiderScans,
        setSubdomainizerScans,
        setNucleiScreenshotScans,
          setMetaDataScans,
        setSubdomains,
        setShuffleDNSCustomScans,
        // Most recent scan updaters
        setMostRecentAmassScan,
        setMostRecentSublist3rScan,
        setMostRecentAssetfinderScan,
        setMostRecentGauScan,
        setMostRecentCTLScan,
        setMostRecentSubfinderScan,
        setMostRecentHttpxScan,
        setMostRecentShuffleDNSScan,
        setMostRecentCeWLScan,
        setMostRecentGoSpiderScan,
        setMostRecentSubdomainizerScan,
        setMostRecentNucleiScreenshotScan,
        setMostRecentMetaDataScan,
        setMostRecentShuffleDNSCustomScan,
        // Status updaters
        setMostRecentAmassScanStatus,
        setMostRecentSublist3rScanStatus,
        setMostRecentAssetfinderScanStatus,
        setMostRecentGauScanStatus,
        setMostRecentCTLScanStatus,
        setMostRecentSubfinderScanStatus,
        setMostRecentHttpxScanStatus,
        setMostRecentShuffleDNSScanStatus,
        setMostRecentCeWLScanStatus,
        setMostRecentGoSpiderScanStatus,
        setMostRecentSubdomainizerScanStatus,
        setMostRecentNucleiScreenshotScanStatus,
          setMostRecentMetaDataScanStatus,
        setMostRecentShuffleDNSCustomScanStatus,
        handleConsolidate,
        undefined,
        undefined,
        setIsWildcardNucleiScanning,
        setWildcardNucleiScans,
        setMostRecentWildcardNucleiScan,
        setMostRecentWildcardNucleiScanStatus,
        httpxScanConfig,
        setActiveWildcardNucleiScan
      ),
      consolidatedSubdomains,
      mostRecentHttpxScan,
      autoScanSessionId,
      setIsAutoScanning,
      setAutoScanCurrentStep
    );
  };

  // Open Modal Handlers

  const handleOpenScanHistoryModal = () => {
    setScanHistory(amassScans)
    setShowScanHistoryModal(true);
  };

  const handleOpenRawResultsModal = () => {
    if (amassScans.length > 0) {
      const mostRecentScan = amassScans.reduce((latest, scan) => {
        const scanDate = new Date(scan.created_at);
        return scanDate > new Date(latest.created_at) ? scan : latest;
      }, amassScans[0]);

      const rawResults = mostRecentScan.result ? mostRecentScan.result.split('\n') : [];
      setRawResults(rawResults);
      setShowRawResultsModal(true);
    } else {
      setShowRawResultsModal(true);
      console.warn("No scans available for raw results");
    }
  };

  const handleOpenSubdomainsModal = async () => {
    if (amassScans.length > 0) {
      const mostRecentScan = amassScans.reduce((latest, scan) => {
        const scanDate = new Date(scan.created_at);
        return scanDate > new Date(latest.created_at) ? scan : latest;
      }, amassScans[0]);

      try {
        const response = await fetch(
          `/api/amass/${mostRecentScan.scan_id}/subdomain`
        );
        if (!response.ok) {
          throw new Error('Failed to fetch subdomains');
        }
        const subdomainsData = await response.json();
        setSubdomains(subdomainsData);
        setShowSubdomainsModal(true);
      } catch (error) {
        setShowSubdomainsModal(true);
        console.error("Error fetching subdomains:", error);
      }
    } else {
      setShowSubdomainsModal(true);
      console.warn("No scans available for subdomains");
    }
  };

  const handleOpenCloudDomainsModal = async () => {
    if (amassScans.length > 0) {
      const mostRecentScan = amassScans.reduce((latest, scan) => {
        const scanDate = new Date(scan.created_at);
        return scanDate > new Date(latest.created_at) ? scan : latest;
      }, amassScans[0]);

      try {
        const response = await fetch(
          `/api/amass/${mostRecentScan.scan_id}/cloud`
        );
        if (!response.ok) {
          throw new Error('Failed to fetch cloud domains');
        }
        const cloudData = await response.json();

        const formattedCloudDomains = [];
        if (cloudData.aws_domains) {
          formattedCloudDomains.push(...cloudData.aws_domains.map((name) => ({ type: 'AWS', name })));
        }
        if (cloudData.azure_domains) {
          formattedCloudDomains.push(...cloudData.azure_domains.map((name) => ({ type: 'Azure', name })));
        }
        if (cloudData.gcp_domains) {
          formattedCloudDomains.push(...cloudData.gcp_domains.map((name) => ({ type: 'GCP', name })));
        }

        setCloudDomains(formattedCloudDomains);
        setShowCloudDomainsModal(true);
      } catch (error) {
        setCloudDomains([]);
        setShowCloudDomainsModal(true);
        console.error("Error fetching cloud domains:", error);
      }
    } else {
      setCloudDomains([]);
      setShowCloudDomainsModal(true);
      console.warn("No scans available for cloud domains");
    }
  };

  const handleOpenDNSRecordsModal = async () => {
    if (amassScans.length > 0) {
      const mostRecentScan = amassScans.reduce((latest, scan) => {
        const scanDate = new Date(scan.created_at);
        return scanDate > new Date(latest.created_at) ? scan : latest;
      }, amassScans[0]);

      try {
        const response = await fetch(
          `/api/amass/${mostRecentScan.scan_id}/dns`
        );
        if (!response.ok) {
          throw new Error('Failed to fetch DNS records');
        }
        const dnsData = await response.json();
        if (dnsData !== null) {
          setDnsRecords(dnsData);
        } else {
          setDnsRecords([]);
        }
        setShowDNSRecordsModal(true);
      } catch (error) {
        setShowDNSRecordsModal(true);
        console.error("Error fetching DNS records:", error);
      }
    } else {
      setShowDNSRecordsModal(true);
      console.warn("No scans available for DNS records");
    }
  };

  const handleClose = () => {
    setShowModal(false);
    setErrorMessage('');
  };

  const handleActiveModalClose = () => {
    setShowActiveModal(false);
  };

  const handleActiveModalOpen = () => {
    setShowActiveModal(true);
  };

  const handleOpen = () => {
    setSelections({ type: '', inputText: '' });
    setShowModal(true);
  };

  const handleSubmit = async () => {
    if (selections.type && selections.inputText) {
      const isValid = validateInput(selections.type, selections.inputText);
      if (!isValid.valid) {
        setErrorMessage(isValid.message);
        return;
      }

      try {
        const response = await fetch(`/api/scopetarget/add`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            type: selections.type,
            mode: 'Passive',
            scope_target: selections.inputText,
            active: false,
          }),
        });

        if (!response.ok) {
          throw new Error('Network response was not ok');
        }

        await fetchScopeTargets();
        handleClose();
        setSelections({
          type: '',
          inputText: '',
        });
      } catch (error) {
        console.error('Error:', error);
        setErrorMessage('Failed to save scope target');
      }
    } else {
      setErrorMessage('Please fill in all fields');
    }
  };

  const handleDelete = async (targetId = null) => {
    const idToDelete = targetId || activeTarget?.id;
    if (!idToDelete) return;

    try {
      const response = await fetch(`/api/scopetarget/delete/${idToDelete}`, {
        method: 'DELETE',
      });

      if (!response.ok) {
        throw new Error('Failed to delete scope target');
      }

      setScopeTargets((prev) => {
        const updatedTargets = prev.filter((target) => target.id !== idToDelete);
        
        if (activeTarget?.id === idToDelete) {
          const newActiveTarget = updatedTargets.length > 0 ? updatedTargets[0] : null;
          setActiveTarget(newActiveTarget);
          if (!newActiveTarget && showActiveModal) {
            setShowActiveModal(false);
            setShowModal(true);
          }
        }
        
        return updatedTargets;
      });
    } catch (error) {
      console.error('Error deleting scope target:', error);
    }
  };

  const fetchScopeTargets = async () => {
    try {
      const response = await fetch(
        `/api/scopetarget/read`
      );
      if (!response.ok) {
        throw new Error('Failed to fetch scope targets');
      }
      const data = await response.json();
      setScopeTargets(data || []);
      setFadeIn(true);
      
      const bblpDismissed = localStorage.getItem('bblp_modal_dismissed');
      if (!bblpDismissed) {
        setShowLaunchPadModal(true);
      }

      if (data && data.length > 0) {
        const activeTargets = data.filter(target => target.active);
        
        if (activeTargets.length === 1) {
          setActiveTarget(activeTargets[0]);
        } else {
          setActiveTarget(data[0]);
          try {
            await fetch(
              `/api/scopetarget/${data[0].id}/activate`,
              {
                method: 'POST',
              }
            );
          } catch (error) {
            console.error('Error setting active scope target:', error);
          }
        }
      } else if (bblpDismissed) {
        setShowWelcomeModal(true);
      }
    } catch (error) {
      console.error('Error fetching scope targets:', error);
      setScopeTargets([]);
    }
  };

  const handleActiveSelect = async (target) => {
    // Reset all scan-related states
    setAmassScans([]);
    setAmassIntelScans([]);
    setDnsRecords([]);
    setSubdomains([]);
    setCloudDomains([]);
    setMostRecentAmassScan(null);
    setMostRecentAmassScanStatus(null);
    setMostRecentAmassIntelScan(null);
    setMostRecentAmassIntelScanStatus(null);
    setMostRecentMetabigorCompanyScan(null);
    setMostRecentMetabigorCompanyScanStatus(null);
    setAmassIntelNetworkRanges([]);
    setMetabigorNetworkRanges([]);
    setAmassEnumSelectedDomainsCount(0);
    setHttpxScans([]);
    setMostRecentHttpxScan(null);
    setMostRecentHttpxScanStatus(null);
    setGauScans([]);
    setMostRecentGauScan(null);
    setMostRecentGauScanStatus(null);
    setScanHistory([]);
    setRawResults([]);
    setConsolidatedCount(0);
    setNucleiScreenshotScans([]);
    setMostRecentNucleiScreenshotScan(null);
    setMostRecentNucleiScreenshotScanStatus(null);
    setMetaDataScans([]);
    setMostRecentMetaDataScan(null);
    setMostRecentMetaDataScanStatus(null);
    setCeWLScans([]);
    setMostRecentCeWLScan(null);
    setMostRecentCeWLScanStatus(null);
    setShuffleDNSScans([]);
    setMostRecentShuffleDNSScan(null);
    setMostRecentShuffleDNSScanStatus(null);
    setShuffleDNSCustomScans([]);
    setMostRecentShuffleDNSCustomScan(null);
    setMostRecentShuffleDNSCustomScanStatus(null);
    setNucleiScans([]);
    setMostRecentNucleiScan(null);
    setMostRecentNucleiScanStatus(null);
    setActiveNucleiScan(null);
    setWildcardNucleiScans([]);
    setMostRecentWildcardNucleiScan(null);
    setMostRecentWildcardNucleiScanStatus(null);
    setActiveWildcardNucleiScan(null);
    setAutoScanSessions([]);
    setAutoScanSessionId(null);
    setAutoScanCurrentStep(AUTO_SCAN_STEPS.IDLE);
    setIsAutoScanning(false);
    setIsAutoScanPaused(false);
    setIsAutoScanPausing(false);
    setIsAutoScanCancelling(false);
    setGoogleDorkingDomains([]);
    setGoogleDorkingError('');
    setReverseWhoisDomains([]);
    setReverseWhoisError('');
    
    // Reset company scan states
    setSecurityTrailsCompanyScans([]);
    setMostRecentSecurityTrailsCompanyScan(null);
    setMostRecentSecurityTrailsCompanyScanStatus(null);
    setCensysCompanyScans([]);
    setMostRecentCensysCompanyScan(null);
    setMostRecentCensysCompanyScanStatus(null);
    setShodanCompanyScans([]);
    setMostRecentShodanCompanyScan(null);
    setMostRecentShodanCompanyScanStatus(null);
    setGitHubReconScans([]);
    setMostRecentGitHubReconScan(null);
    setMostRecentGitHubReconScanStatus(null);
    
    setActiveTarget(target);
    
    // Update the backend to set this target as active
    try {
      const response = await fetch(
        `/api/scopetarget/${target.id}/activate`,
        {
          method: 'POST',
        }
      );
      if (!response.ok) {
        throw new Error('Failed to update active scope target');
      }
      // Update the local scope targets list to reflect the change
      setScopeTargets(prev => prev.map(t => ({
        ...t,
        active: t.id === target.id
      })));

      // Fetch new scan data for the new active target
      if (target.id) {
        // Fetch screenshot scans
        const screenshotResponse = await fetch(
          `/api/scopetarget/${target.id}/scans/nuclei-screenshot`
        );
        if (screenshotResponse.ok) {
          const screenshotData = await screenshotResponse.json();
          setNucleiScreenshotScans(screenshotData);
          if (screenshotData && screenshotData.length > 0) {
            setMostRecentNucleiScreenshotScan(screenshotData[0]);
            setMostRecentNucleiScreenshotScanStatus(screenshotData[0].status);
          }
        }

        // Fetch metadata scans
        const metadataResponse = await fetch(
          `/api/scopetarget/${target.id}/scans/metadata`
        );
        if (metadataResponse.ok) {
          const metadataData = await metadataResponse.json();
          setMetaDataScans(metadataData);
          if (metadataData && metadataData.length > 0) {
            setMostRecentMetaDataScan(metadataData[0]);
            setMostRecentMetaDataScanStatus(metadataData[0].status);
          }
        }

        // Fetch CEWL scans
        const cewlResponse = await fetch(
          `/api/scopetarget/${target.id}/scans/cewl`
        );
        if (cewlResponse.ok) {
          const cewlData = await cewlResponse.json();
          setCeWLScans(cewlData);
          if (cewlData && cewlData.length > 0) {
            setMostRecentCeWLScan(cewlData[0]);
            setMostRecentCeWLScanStatus(cewlData[0].status);
          }
        }

        // Fetch ShuffleDNS scans
        const shufflednsResponse = await fetch(
          `/api/scopetarget/${target.id}/scans/shuffledns`
        );
        if (shufflednsResponse.ok) {
          const shufflednsData = await shufflednsResponse.json();
          setShuffleDNSScans(shufflednsData);
          if (shufflednsData && shufflednsData.length > 0) {
            setMostRecentShuffleDNSScan(shufflednsData[0]);
            setMostRecentShuffleDNSScanStatus(shufflednsData[0].status);
          }
        }

        // Fetch ShuffleDNS Custom scans
        const shufflednsCustomResponse = await fetch(
          `/api/api/scope-targets/${target.id}/shufflednscustom-scans`
        );
        if (shufflednsCustomResponse.ok) {
          const shufflednsCustomData = await shufflednsCustomResponse.json();
          setShuffleDNSCustomScans(shufflednsCustomData);
          if (shufflednsCustomData && shufflednsCustomData.length > 0) {
            setMostRecentShuffleDNSCustomScan(shufflednsCustomData[0]);
            setMostRecentShuffleDNSCustomScanStatus(shufflednsCustomData[0].status);
          }
        }

        // Fetch SecurityTrails Company scans
        const securitytrailsResponse = await fetch(
          `/api/scopetarget/${target.id}/scans/securitytrails-company`
        );
        if (securitytrailsResponse.ok) {
          const securitytrailsData = await securitytrailsResponse.json();
          if (Array.isArray(securitytrailsData)) {
            setSecurityTrailsCompanyScans(securitytrailsData);
            if (securitytrailsData.length > 0) {
              const mostRecentScan = securitytrailsData.reduce((latest, scan) => {
                const scanDate = new Date(scan.created_at);
                return scanDate > new Date(latest.created_at) ? scan : latest;
              }, securitytrailsData[0]);
              setMostRecentSecurityTrailsCompanyScan(mostRecentScan);
              setMostRecentSecurityTrailsCompanyScanStatus(mostRecentScan.status);
            }
          }
        }

        // Fetch Censys Company scans
        const censysResponse = await fetch(
          `/api/scopetarget/${target.id}/scans/censys-company`
        );
        if (censysResponse.ok) {
          const censysData = await censysResponse.json();
          if (Array.isArray(censysData)) {
            setCensysCompanyScans(censysData);
            if (censysData.length > 0) {
              const mostRecentScan = censysData.reduce((latest, scan) => {
                const scanDate = new Date(scan.created_at);
                return scanDate > new Date(latest.created_at) ? scan : latest;
              }, censysData[0]);
              setMostRecentCensysCompanyScan(mostRecentScan);
              setMostRecentCensysCompanyScanStatus(mostRecentScan.status);
            }
          }
        }

        // Fetch Shodan Company scans
        const shodanResponse = await fetch(
          `/api/scopetarget/${target.id}/scans/shodan-company`
        );
        if (shodanResponse.ok) {
          const shodanData = await shodanResponse.json();
          if (Array.isArray(shodanData)) {
            setShodanCompanyScans(shodanData);
            if (shodanData.length > 0) {
              const mostRecentScan = shodanData.reduce((latest, scan) => {
                const scanDate = new Date(scan.created_at);
                return scanDate > new Date(latest.created_at) ? scan : latest;
              }, shodanData[0]);
              setMostRecentShodanCompanyScan(mostRecentScan);
              setMostRecentShodanCompanyScanStatus(mostRecentScan.status);
            }
          }
        }

        // Fetch GitHub Recon scans
        const githubResponse = await fetch(
          `/api/scopetarget/${target.id}/scans/github-recon`
        );
        if (githubResponse.ok) {
          const githubData = await githubResponse.json();
          if (Array.isArray(githubData)) {
            setGitHubReconScans(githubData);
            if (githubData.length > 0) {
              const mostRecentScan = githubData.reduce((latest, scan) => {
                const scanDate = new Date(scan.created_at);
                return scanDate > new Date(latest.created_at) ? scan : latest;
              }, githubData[0]);
              setMostRecentGitHubReconScan(mostRecentScan);
              setMostRecentGitHubReconScanStatus(mostRecentScan.status);
            }
          }
        }
      }
    } catch (error) {
      console.error('Error updating active scope target:', error);
    }
  };

  const handleSelect = (key, value) => {
    setSelections((prev) => ({ ...prev, [key]: value }));
    setErrorMessage('');
  };

  const handleCloseScanHistoryModal = () => setShowScanHistoryModal(false);
  const handleCloseRawResultsModal = () => setShowRawResultsModal(false);
  const handleCloseDNSRecordsModal = () => setShowDNSRecordsModal(false);


  const startAmassScan = () => {
    initiateAmassScan(activeTarget, monitorScanStatus, setIsScanning, setAmassScans, setMostRecentAmassScanStatus, setDnsRecords, setSubdomains, setCloudDomains, setMostRecentAmassScan)
  }

  const startAmassIntelScan = () => {
    initiateAmassIntelScan(activeTarget, monitorAmassIntelScanStatus, setIsAmassIntelScanning, setAmassIntelScans, setMostRecentAmassIntelScanStatus, setMostRecentAmassIntelScan, setAmassIntelNetworkRanges)
  }

  const handleOpenAmassIntelResultsModal = () => setShowAmassIntelResultsModal(true);
  const handleCloseAmassIntelResultsModal = () => setShowAmassIntelResultsModal(false);
  
  const handleOpenAmassIntelHistoryModal = () => setShowAmassIntelHistoryModal(true);
  const handleCloseAmassIntelHistoryModal = () => setShowAmassIntelHistoryModal(false);

  const startAutoScan = async () => {
    const currentTarget = activeTargetRef.current;
    const currentHttpxConfig = httpxScanConfigRef.current;

    if (!currentTarget) {
      console.error('[AutoScan] No active target');
      return;
    }

    console.log(`[AutoScan] Starting Auto Scan for target: ${currentTarget.scope_target}`);

    setAutoScanCurrentStep(AUTO_SCAN_STEPS.IDLE);
    setIsAutoScanning(false);
    setIsAutoScanPaused(false);
    setIsAutoScanPausing(false);
    setIsAutoScanCancelling(false);
    setIsConsolidating(false);
    setIsScanning(false);
    setIsSublist3rScanning(false);
    setIsAssetfinderScanning(false);
    setIsGauScanning(false);
    setIsCTLScanning(false);
    setIsSubfinderScanning(false);
    setIsHttpxScanning(false);
    setIsShuffleDNSScanning(false);
    setIsCeWLScanning(false);
    setIsGoSpiderScanning(false);
    setIsSubdomainizerScanning(false);
    setIsNucleiScreenshotScanning(false);
    setIsMetaDataScanning(false);
    setIsWildcardNucleiScanning(false);

    await new Promise(resolve => setTimeout(resolve, 100));

    try {
      const response = await fetch(
        `/api/api/auto-scan-config`
      );
      if (!response.ok) {
        throw new Error('Failed to fetch auto scan config');
      }
      const config = await response.json();
      console.log('[AutoScan] Config received from backend:', config);
      const sessionResp = await fetch(
        `/api/api/auto-scan/session/start`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            scope_target_id: currentTarget.id,
            config_snapshot: config
          })
        }
      );
      if (!sessionResp.ok) throw new Error('Failed to create auto scan session');
      const sessionData = await sessionResp.json();
      console.error(sessionData)
      setAutoScanSessionId(sessionData.session_id);

      setIsAutoScanning(true);

      startAutoScanUtil(
        currentTarget,
        setIsAutoScanning,
        setAutoScanCurrentStep,
        setAutoScanTargetId,
        () => getAutoScanSteps(
          currentTarget,
          setAutoScanCurrentStep,
          setIsScanning,
          setIsSublist3rScanning,
          setIsAssetfinderScanning,
          setIsGauScanning,
          setIsCTLScanning,
          setIsSubfinderScanning,
          setIsConsolidating,
          setIsHttpxScanning,
          setIsShuffleDNSScanning,
          setIsCeWLScanning,
          setIsGoSpiderScanning,
          setIsSubdomainizerScanning,
          setIsNucleiScreenshotScanning,
          setIsMetaDataScanning,
          setAmassScans,
          setSublist3rScans,
          setAssetfinderScans,
          setGauScans,
          setCTLScans,
          setSubfinderScans,
          setHttpxScans,
          setShuffleDNSScans,
          setCeWLScans,
          setGoSpiderScans,
          setSubdomainizerScans,
          setNucleiScreenshotScans,
          setMetaDataScans,
          setSubdomains,
          setShuffleDNSCustomScans,
          setMostRecentAmassScan,
          setMostRecentSublist3rScan,
          setMostRecentAssetfinderScan,
          setMostRecentGauScan,
          setMostRecentCTLScan,
          setMostRecentSubfinderScan,
          setMostRecentHttpxScan,
          setMostRecentShuffleDNSScan,
          setMostRecentCeWLScan,
          setMostRecentGoSpiderScan,
          setMostRecentSubdomainizerScan,
          setMostRecentNucleiScreenshotScan,
          setMostRecentMetaDataScan,
          setMostRecentShuffleDNSCustomScan,
          setMostRecentAmassScanStatus,
          setMostRecentSublist3rScanStatus,
          setMostRecentAssetfinderScanStatus,
          setMostRecentGauScanStatus,
          setMostRecentCTLScanStatus,
          setMostRecentSubfinderScanStatus,
          setMostRecentHttpxScanStatus,
          setMostRecentShuffleDNSScanStatus,
          setMostRecentCeWLScanStatus,
          setMostRecentGoSpiderScanStatus,
          setMostRecentSubdomainizerScanStatus,
          setMostRecentNucleiScreenshotScanStatus,
          setMostRecentMetaDataScanStatus,
          setMostRecentShuffleDNSCustomScanStatus,
          handleConsolidate,
          config,
          sessionData.session_id,
          setIsWildcardNucleiScanning,
          setWildcardNucleiScans,
          setMostRecentWildcardNucleiScan,
          setMostRecentWildcardNucleiScanStatus,
          currentHttpxConfig,
          setActiveWildcardNucleiScan
        ),
        consolidatedSubdomains,
        mostRecentHttpxScan,
        sessionData.session_id
      );
    } catch (error) {
      console.error('[AutoScan] Error fetching config or starting scan:', error);
    }
  };

  const waitForAutoScanCompletion = async (targetId) => {
    let phase = 'waiting_for_idle';
    let pollCount = 0;

    return new Promise((resolve) => {
      const checkState = async () => {
        if (wildfireCancelledRef.current) {
          resolve('cancelled');
          return;
        }
        pollCount++;
        try {
          const response = await fetch(`/api/api/auto-scan-state/${targetId}`);
          if (response.ok) {
            const state = await response.json();

            if (state.is_cancelled) {
              resolve('cancelled');
              return;
            }

            // If scan is paused (limit hit), cancel it and skip to next target
            if (state.is_paused && phase === 'waiting_for_complete') {
              console.log(`[Wildfire] Scan for ${targetId} paused due to limits at step ${state.current_step}. Skipping to next target.`);
              try {
                await fetch(`/api/api/auto-scan-state/${targetId}`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({
                    current_step: 'completed',
                    is_paused: false,
                    is_cancelled: false
                  })
                });
              } catch (err) {
                console.error('[Wildfire] Error unpausing/completing scan:', err);
              }
              resolve('limit_skipped');
              return;
            }

            const step = state.current_step;
            console.log(`[Wildfire] Poll #${pollCount} for ${targetId}: step=${step}, phase=${phase}`);

            if (phase === 'waiting_for_idle') {
              if (step === 'idle') {
                phase = 'waiting_for_start';
                console.log(`[Wildfire] Scan reset to idle for ${targetId}, waiting for first step...`);
              } else if (step && step !== 'completed') {
                phase = 'waiting_for_complete';
                console.log(`[Wildfire] Scan already running for ${targetId}, step: ${step}`);
              } else if (step === 'completed' && pollCount > 12) {
                console.log(`[Wildfire] Scan for ${targetId} appears already completed (timeout fallback)`);
                resolve('completed');
                return;
              }
            } else if (phase === 'waiting_for_start') {
              if (step && step !== 'idle' && step !== 'completed') {
                phase = 'waiting_for_complete';
                console.log(`[Wildfire] Scan started for ${targetId}, step: ${step}`);
              } else if (step === 'completed') {
                console.log(`[Wildfire] Scan for ${targetId} completed (fast finish after idle)`);
                resolve('completed');
                return;
              }
            } else if (phase === 'waiting_for_complete') {
              if (step === 'completed') {
                console.log(`[Wildfire] Scan completed for ${targetId}`);
                resolve('completed');
                return;
              }
            }
          }
        } catch (err) {
          console.error('[Wildfire] Error checking auto scan state:', err);
        }
        setTimeout(checkState, 3000);
      };
      setTimeout(checkState, 2000);
    });
  };

  const startWildfire = async (targets) => {
    setIsWildfireRunning(true);
    setWildfireCancelled(false);
    wildfireCancelledRef.current = false;
    setShowGlobalScansModal(true);

    setWildfireProgress({
      targets,
      totalTargets: targets.length,
      currentIndex: 0,
      currentTarget: targets[0]
    });

    for (let i = 0; i < targets.length; i++) {
      if (wildfireCancelledRef.current) {
        console.log('[Wildfire] Cancelled by user.');
        break;
      }

      const target = targets[i];
      console.log(`[Wildfire] Starting target ${i + 1}/${targets.length}: ${target.scope_target}`);

      setWildfireProgress({
        targets,
        totalTargets: targets.length,
        currentIndex: i,
        currentTarget: target
      });

      await handleActiveSelect(target);
      await new Promise(resolve => setTimeout(resolve, 2000));

      if (wildfireCancelledRef.current) break;

      await startAutoScan();
      await new Promise(resolve => setTimeout(resolve, 3000));

      if (wildfireCancelledRef.current) break;

      const result = await waitForAutoScanCompletion(target.id);
      console.log(`[Wildfire] Target ${target.scope_target} finished with result: ${result}`);

      if (result === 'limit_skipped') {
        setWildfireProgress(prev => prev ? {
          ...prev,
          limitSkipped: { ...(prev.limitSkipped || {}), [target.id]: true }
        } : null);
      }

      if (result === 'cancelled' && wildfireCancelledRef.current) break;

      await new Promise(resolve => setTimeout(resolve, 2000));
    }

    setWildfireProgress(prev => prev ? {
      ...prev,
      currentIndex: prev.totalTargets
    } : null);

    setIsWildfireRunning(false);
    console.log('[Wildfire] All targets completed.');
  };

  const cancelWildfire = async () => {
    wildfireCancelledRef.current = true;
    setWildfireCancelled(true);

    if (activeTarget && isAutoScanning) {
      try {
        await fetch(`/api/api/auto-scan-state/${activeTarget.id}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            current_step: autoScanCurrentStep,
            is_paused: false,
            is_cancelled: true
          })
        });
      } catch (err) {
        console.error('[Wildfire] Error cancelling current auto scan:', err);
      }
    }
  };

  const addSlowburnLog = (progressSetter, message, type = 'info') => {
    const time = new Date().toLocaleTimeString();
    progressSetter(prev => prev ? {
      ...prev,
      log: [...(prev.log || []), { time, message, type }]
    } : null);
  };

  const startSlowburn = async (config) => {
    const { apiKey, bountyOnly } = config;
    setIsSlowburnRunning(true);
    slowburnCancelledRef.current = false;
    setShowGlobalScansModal(true);

    setSlowburnProgress({
      programsScanned: 0,
      targetsScanned: 0,
      currentProgram: null,
      currentTarget: null,
      scannedTargets: [],
      lastCompletedTarget: null,
      log: []
    });

    addSlowburnLog(setSlowburnProgress, 'Slowburn scan started', 'info');

    let programsScanned = 0;
    let targetsScanned = 0;
    const scannedTargets = [];

    // Discover total pages on first fetch
    let maxPage = 1;
    let discoveredMaxPage = false;

    while (!slowburnCancelledRef.current) {
      try {
        // Fetch a random program
        addSlowburnLog(setSlowburnProgress, 'Fetching random program from HackerOne...', 'info');

        const randomPage = discoveredMaxPage ? Math.floor(Math.random() * maxPage) + 1 : 1;
        const programsRes = await fetch(`/api/api/hackerone/programs?page[size]=100&page[number]=${randomPage}`, {
          headers: { 'X-HackerOne-API-Key': apiKey }
        });

        if (!programsRes.ok) {
          addSlowburnLog(setSlowburnProgress, `Failed to fetch programs (page ${randomPage}), retrying...`, 'error');
          await new Promise(r => setTimeout(r, 5000));
          continue;
        }

        const programsData = await programsRes.json();
        const programs = programsData.data || [];

        // Discover max page from pagination links
        if (!discoveredMaxPage && programsData.links) {
          const lastLink = programsData.links.last || '';
          const pageMatch = lastLink.match(/page%5Bnumber%5D=(\d+)|page\[number\]=(\d+)/);
          if (pageMatch) {
            maxPage = parseInt(pageMatch[1] || pageMatch[2], 10);
          } else if (programs.length > 0) {
            // Estimate: if first page is full, assume a few pages exist
            maxPage = programs.length >= 100 ? 5 : 1;
          }
          discoveredMaxPage = true;
          addSlowburnLog(setSlowburnProgress, `Discovered ${maxPage} page(s) of programs`, 'info');
        }

        if (programs.length === 0) {
          // Reduce max page if we hit an empty page
          if (randomPage > 1) maxPage = randomPage - 1;
          addSlowburnLog(setSlowburnProgress, `No programs found on page ${randomPage}, trying another page...`, 'info');
          continue;
        }

        // Pick a random program from the page
        const randomProgram = programs[Math.floor(Math.random() * programs.length)];
        const handle = randomProgram.attributes?.handle || randomProgram.id;

        // Check bounty filter
        if (bountyOnly) {
          const offersBounty = randomProgram.attributes?.offers_bounties;
          if (!offersBounty) {
            addSlowburnLog(setSlowburnProgress, `Skipping ${handle} (no bounty)`, 'info');
            continue;
          }
        }

        addSlowburnLog(setSlowburnProgress, `Selected program: ${handle}`, 'info');
        setSlowburnProgress(prev => prev ? { ...prev, currentProgram: handle } : null);

        if (slowburnCancelledRef.current) break;

        // Fetch program details with structured scopes
        const programRes = await fetch(`/api/api/hackerone/program?handle=${encodeURIComponent(handle)}`, {
          headers: { 'X-HackerOne-API-Key': apiKey }
        });

        if (!programRes.ok) {
          addSlowburnLog(setSlowburnProgress, `Failed to fetch program details for ${handle}`, 'error');
          continue;
        }

        const programData = await programRes.json();
        // Scopes are in relationships.structured_scopes.data, not in included
        const structuredScopes = programData.relationships?.structured_scopes?.data || [];

        // Find wildcard scope targets
        const wildcardScopes = structuredScopes.filter(item => {
          if (item.type !== 'structured-scope') return false;
          const attrs = item.attributes || {};
          if (attrs.eligible_for_submission !== true) return false;
          const assetType = (attrs.asset_type || '').toUpperCase();
          const identifier = attrs.asset_identifier || '';
          return (assetType === 'URL' || assetType === 'DOMAIN' || assetType === 'WILDCARD') &&
                 identifier.startsWith('*.');
        });

        if (wildcardScopes.length === 0) {
          addSlowburnLog(setSlowburnProgress, `No wildcard targets found for ${handle}, moving on...`, 'info');
          continue;
        }

        addSlowburnLog(setSlowburnProgress, `Found ${wildcardScopes.length} wildcard target(s) for ${handle}`, 'success');
        programsScanned++;
        setSlowburnProgress(prev => prev ? { ...prev, programsScanned } : null);

        // Scan each wildcard target
        for (const scope of wildcardScopes) {
          if (slowburnCancelledRef.current) break;

          const domain = scope.attributes.asset_identifier;
          addSlowburnLog(setSlowburnProgress, `Adding and scanning ${domain}...`, 'info');
          setSlowburnProgress(prev => prev ? { ...prev, currentTarget: domain } : null);

          // Add the wildcard target to the framework
          try {
            const addRes = await fetch('/api/scopetarget/add', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                type: 'Wildcard',
                mode: 'Passive',
                scope_target: domain,
                active: false,
              }),
            });

            if (!addRes.ok) {
              // Target might already exist, try to find it
              addSlowburnLog(setSlowburnProgress, `Target ${domain} may already exist, looking up...`, 'info');
            } else {
              addSlowburnLog(setSlowburnProgress, `Added ${domain} as Wildcard target`, 'success');
            }

            // Refresh scope targets and find the one we just added
            await fetchScopeTargets();
            await new Promise(r => setTimeout(r, 1000));

            // Find the target we just added (refetch latest)
            const readRes = await fetch('/api/scopetarget/read');
            const allTargets = readRes.ok ? await readRes.json() : [];
            const matchedTarget = allTargets.find(t => t.scope_target === domain && t.type === 'Wildcard');

            if (!matchedTarget) {
              addSlowburnLog(setSlowburnProgress, `Could not find target ${domain} after adding, skipping...`, 'error');
              continue;
            }

            if (slowburnCancelledRef.current) break;

            // Select this target as active
            await handleActiveSelect(matchedTarget);
            await new Promise(r => setTimeout(r, 2000));

            if (slowburnCancelledRef.current) break;

            // Start auto scan
            addSlowburnLog(setSlowburnProgress, `Starting Auto Scan for ${domain}...`, 'info');
            await startAutoScan();
            await new Promise(r => setTimeout(r, 3000));

            if (slowburnCancelledRef.current) break;

            // Wait for completion
            const result = await waitForSlowburnScanCompletion(matchedTarget.id);
            if (result === 'limit_skipped') {
              addSlowburnLog(setSlowburnProgress, `${domain} — limit reached, skipping to next target`, 'info');
            } else {
              addSlowburnLog(setSlowburnProgress, `${domain} finished: ${result}`, result === 'completed' ? 'success' : 'info');
            }

            // Fetch stats for completed target
            const statsRes = await Promise.all([
              fetch(`/api/consolidated-subdomains/${matchedTarget.id}`).catch(() => null),
              fetch(`/api/scopetarget/${matchedTarget.id}/scans/httpx`).catch(() => null),
              fetch(`/api/scopetarget/${matchedTarget.id}/scans/nuclei`).catch(() => null),
            ]);

            let subdomains = 0, webServers = 0, nucleiTotal = 0;
            if (statsRes[0]?.ok) {
              const d = await statsRes[0].json();
              subdomains = d.count || 0;
            }
            if (statsRes[1]?.ok) {
              const d = await statsRes[1].json();
              if (d.scans?.length > 0) {
                const latest = d.scans.reduce((a, b) => new Date(b.created_at) > new Date(a.created_at) ? b : a);
                webServers = latest.result ? latest.result.split('\n').filter(l => l.trim()).length : 0;
              }
            }
            if (statsRes[2]?.ok) {
              const scans = await statsRes[2].json();
              if (Array.isArray(scans)) {
                const successScans = scans.filter(sc => sc.status === 'success' && sc.result);
                if (successScans.length > 0) {
                  const latest = successScans.reduce((a, b) => new Date(b.created_at) > new Date(a.created_at) ? b : a);
                  try {
                    const findings = JSON.parse(latest.result);
                    nucleiTotal = Array.isArray(findings) ? findings.length : 0;
                  } catch {}
                }
              }
            }

            addSlowburnLog(setSlowburnProgress, `${domain} results — ${subdomains} subdomains, ${webServers} live servers, ${nucleiTotal} nuclei findings`, 'success');

            targetsScanned++;
            const targetEntry = { program: handle, target: domain, subdomains, webServers, nucleiTotal };
            scannedTargets.push(targetEntry);

            setSlowburnProgress(prev => prev ? {
              ...prev,
              targetsScanned,
              scannedTargets: [...scannedTargets],
              lastCompletedTarget: domain,
              currentTarget: null
            } : null);

            await new Promise(r => setTimeout(r, 2000));

          } catch (err) {
            addSlowburnLog(setSlowburnProgress, `Error scanning ${domain}: ${err.message}`, 'error');
            console.error('[Slowburn] Error scanning target:', err);
          }
        }

      } catch (err) {
        addSlowburnLog(setSlowburnProgress, `Unexpected error: ${err.message}`, 'error');
        console.error('[Slowburn] Unexpected error:', err);
        await new Promise(r => setTimeout(r, 5000));
      }
    }

    addSlowburnLog(setSlowburnProgress, 'Slowburn scan stopped', 'info');
    setIsSlowburnRunning(false);
    console.log('[Slowburn] Scan stopped.');
  };

  const waitForSlowburnScanCompletion = async (targetId) => {
    let phase = 'waiting_for_idle';
    let pollCount = 0;

    return new Promise((resolve) => {
      const checkState = async () => {
        if (slowburnCancelledRef.current) {
          resolve('cancelled');
          return;
        }
        pollCount++;
        try {
          const response = await fetch(`/api/api/auto-scan-state/${targetId}`);
          if (response.ok) {
            const state = await response.json();

            if (state.is_cancelled) {
              resolve('cancelled');
              return;
            }

            // If scan is paused (limit hit), cancel it and skip to next target
            if (state.is_paused && phase === 'waiting_for_complete') {
              console.log(`[Slowburn] Scan for ${targetId} paused due to limits at step ${state.current_step}. Skipping to next target.`);
              addSlowburnLog(setSlowburnProgress, `Subdomain/web server limit reached at ${state.current_step}. Skipping to next target.`, 'info');
              try {
                await fetch(`/api/api/auto-scan-state/${targetId}`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({
                    current_step: 'completed',
                    is_paused: false,
                    is_cancelled: false
                  })
                });
              } catch (err) {
                console.error('[Slowburn] Error unpausing/completing scan:', err);
              }
              resolve('limit_skipped');
              return;
            }

            const step = state.current_step;

            if (phase === 'waiting_for_idle') {
              if (step === 'idle') {
                phase = 'waiting_for_start';
              } else if (step && step !== 'completed') {
                phase = 'waiting_for_complete';
              } else if (step === 'completed' && pollCount > 12) {
                resolve('completed');
                return;
              }
            } else if (phase === 'waiting_for_start') {
              if (step && step !== 'idle' && step !== 'completed') {
                phase = 'waiting_for_complete';
              } else if (step === 'completed') {
                resolve('completed');
                return;
              }
            } else if (phase === 'waiting_for_complete') {
              if (step === 'completed') {
                resolve('completed');
                return;
              }
            }
          }
        } catch (err) {
          console.error('[Slowburn] Error checking auto scan state:', err);
        }
        setTimeout(checkState, 3000);
      };
      setTimeout(checkState, 2000);
    });
  };

  const cancelSlowburn = async () => {
    slowburnCancelledRef.current = true;
    addSlowburnLog(setSlowburnProgress, 'Cancelling Slowburn scan...', 'info');

    if (activeTarget && isAutoScanning) {
      try {
        await fetch(`/api/api/auto-scan-state/${activeTarget.id}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            current_step: autoScanCurrentStep,
            is_paused: false,
            is_cancelled: true
          })
        });
      } catch (err) {
        console.error('[Slowburn] Error cancelling current auto scan:', err);
      }
    }
  };

  const startHttpxScan = () => {
    initiateHttpxScan(
      activeTarget,
      monitorHttpxScanStatus,
      setIsHttpxScanning,
      setHttpxScans,
      setMostRecentHttpxScanStatus,
      setMostRecentHttpxScan,
      null,
      httpxScanConfig
    );
  };

  const startGauScan = () => {
    initiateGauScan(
      activeTarget,
      monitorGauScanStatus,
      setIsGauScanning,
      setGauScans,
      setMostRecentGauScanStatus,
      setMostRecentGauScan
    );
  };

  const startSublist3rScan = () => {
    initiateSublist3rScan(
      activeTarget,
      monitorSublist3rScanStatus,
      setIsSublist3rScanning,
      setSublist3rScans,
      setMostRecentSublist3rScanStatus,
      setMostRecentSublist3rScan
    );
  };

  const startAssetfinderScan = () => {
    initiateAssetfinderScan(
      activeTarget,
      monitorAssetfinderScanStatus,
      setIsAssetfinderScanning,
      setAssetfinderScans,
      setMostRecentAssetfinderScanStatus,
      setMostRecentAssetfinderScan
    );
  };

  const startCTLScan = () => {
    initiateCTLScan(
      activeTarget,
      monitorCTLScanStatus,
      setIsCTLScanning,
      setCTLScans,
      setMostRecentCTLScanStatus,
      setMostRecentCTLScan
    );
  };

  const startCTLCompanyScan = () => {
    initiateCTLCompanyScan(
      activeTarget,
      monitorCTLCompanyScanStatus,
      setIsCTLCompanyScanning,
      setCTLCompanyScans,
      setMostRecentCTLCompanyScanStatus,
      setMostRecentCTLCompanyScan
    );
  };

  const startCloudEnumScan = () => {
    initiateCloudEnumScan(
      activeTarget,
      monitorCloudEnumScanStatus,
      setIsCloudEnumScanning,
      setCloudEnumScans,
      setMostRecentCloudEnumScanStatus,
      setMostRecentCloudEnumScan
    );
  };

  const startMetabigorCompanyScan = () => {
    initiateMetabigorCompanyScan(
      activeTarget,
      monitorMetabigorCompanyScanStatus,
      setIsMetabigorCompanyScanning,
      setMetabigorCompanyScans,
      setMostRecentMetabigorCompanyScanStatus,
      setMostRecentMetabigorCompanyScan,
      setMetabigorNetworkRanges
    );
  };

  const startSubfinderScan = () => {
    initiateSubfinderScan(
      activeTarget,
      monitorSubfinderScanStatus,
      setIsSubfinderScanning,
      setSubfinderScans,
      setMostRecentSubfinderScanStatus,
      setMostRecentSubfinderScan
    );
  };

  const startShuffleDNSScan = () => {
    initiateShuffleDNSScan(
      activeTarget,
      monitorShuffleDNSScanStatus,
      setIsShuffleDNSScanning,
      setShuffleDNSScans,
      setMostRecentShuffleDNSScanStatus,
      setMostRecentShuffleDNSScan
    );
  };

  const startCeWLScan = () => {
    initiateCeWLScan(
      activeTarget,
      monitorCeWLScanStatus, // poll the actual CeWL scan status so the spinner stops on completion
      setIsCeWLScanning,
      setCeWLScans,
      setMostRecentCeWLScanStatus,
      setMostRecentCeWLScan
    );
  };

  const startGoSpiderScan = () => {
    initiateGoSpiderScan(
      activeTarget,
      monitorGoSpiderScanStatus,
      setIsGoSpiderScanning,
      setGoSpiderScans,
      setMostRecentGoSpiderScanStatus,
      setMostRecentGoSpiderScan
    );
  };

  const startSubdomainizerScan = () => {
    initiateSubdomainizerScan(
      activeTarget,
      monitorSubdomainizerScanStatus,
      setIsSubdomainizerScanning,
      setSubdomainizerScans,
      setMostRecentSubdomainizerScanStatus,
      setMostRecentSubdomainizerScan
    );
  };

  const renderScanId = (scanId) => {
    if (scanId === 'No scans available' || scanId === 'No scan ID available') {
      return <span>{scanId}</span>;
    }
    
    const handleCopy = async () => {
      const success = await copyToClipboard(scanId);
      if (success) {
        setToastTitle('Success');
        setToastMessage('Scan ID copied to clipboard');
        setShowToast(true);
        setTimeout(() => setShowToast(false), 3000); // Hide after 3 seconds
      }
    };

    return (
      <span className="scan-id-container">
        {scanId}
        <button 
          onClick={handleCopy}
          className="copy-button"
          title="Copy Scan ID"
          style={{
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            padding: '4px',
          }}
        >
          <MdCopyAll size={14} />
        </button>
      </span>
    );
  };

  const handleOpenInfraModal = () => setShowInfraModal(true);
  const handleCloseInfraModal = () => setShowInfraModal(false);

  const handleCloseHttpxResultsModal = () => setShowHttpxResultsModal(false);
  const handleOpenHttpxResultsModal = () => setShowHttpxResultsModal(true);

  const handleCloseGauResultsModal = () => setShowGauResultsModal(false);
  const handleOpenGauResultsModal = () => setShowGauResultsModal(true);

  const handleCloseSublist3rResultsModal = () => setShowSublist3rResultsModal(false);
  const handleOpenSublist3rResultsModal = () => setShowSublist3rResultsModal(true);

  const handleCloseAssetfinderResultsModal = () => setShowAssetfinderResultsModal(false);
  const handleOpenAssetfinderResultsModal = () => setShowAssetfinderResultsModal(true);

  const handleCloseCTLResultsModal = () => setShowCTLResultsModal(false);
  const handleOpenCTLResultsModal = () => setShowCTLResultsModal(true);

  const handleCloseCTLCompanyResultsModal = () => setShowCTLCompanyResultsModal(false);
  const handleOpenCTLCompanyResultsModal = () => setShowCTLCompanyResultsModal(true);
  
  const handleCloseCTLCompanyHistoryModal = () => setShowCTLCompanyHistoryModal(false);
  const handleOpenCTLCompanyHistoryModal = () => setShowCTLCompanyHistoryModal(true);

    const handleCloseCloudEnumResultsModal = () => setShowCloudEnumResultsModal(false);
  const handleOpenCloudEnumResultsModal = () => setShowCloudEnumResultsModal(true);

  const handleCloseCloudEnumHistoryModal = () => setShowCloudEnumHistoryModal(false);
  const handleOpenCloudEnumHistoryModal = () => setShowCloudEnumHistoryModal(true);

  const handleCloseCloudEnumConfigModal = () => setShowCloudEnumConfigModal(false);
  const handleOpenCloudEnumConfigModal = () => setShowCloudEnumConfigModal(true);

  const handleCloudEnumConfigSave = async (config) => {
    console.log('Cloud Enum configuration saved:', config);
    // Configuration is already saved in the modal, just close it
    setShowCloudEnumConfigModal(false);
  };

  const handleCloseNucleiConfigModal = () => setShowNucleiConfigModal(false);
  const handleOpenNucleiConfigModal = () => setShowNucleiConfigModal(true);

  const loadNucleiConfig = async () => {
    if (!activeTarget?.id) return;


    try {
      const response = await fetch(
        `/api/nuclei-config/${activeTarget.id}`
      );

      if (response.ok) {
        const config = await response.json();

        if (!config.templates || config.templates.length === 0) {
          config.templates = DEFAULT_NUCLEI_TEMPLATES;
        }
        if (!config.severities || config.severities.length === 0) {
          config.severities = DEFAULT_NUCLEI_SEVERITIES;
        }

        if (!config.targets || config.targets.length === 0) {
          try {
            let autoTargets = [];
            if (activeTarget.type === 'Wildcard') {
              const targetsResp = await fetch(`/api/scopetarget/${activeTarget.id}/wildcard-nuclei-targets`);
              if (targetsResp.ok) {
                const data = await targetsResp.json();
                autoTargets = (data.targets || []).filter(Boolean);
              }
            } else {
              const assetsResp = await fetch(`/api/attack-surface-assets/${activeTarget.id}`);
              if (assetsResp.ok) {
                const data = await assetsResp.json();
                if (data.assets && Array.isArray(data.assets)) {
                  autoTargets = data.assets.map(a => a.id).filter(Boolean);
                }
              }
            }

            if (autoTargets.length > 0) {
              config.targets = autoTargets;
              config.target_mode = activeTarget.type === 'Wildcard' ? 'httpx_targets' : 'attack_surface';

              await fetch(`/api/nuclei-config/${activeTarget.id}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config),
              });
            }
          } catch (targetErr) {
            console.error('Error auto-populating Nuclei targets:', targetErr);
          }
        }

        setNucleiConfig(config);
      }
    } catch (error) {
      console.error('Error loading Nuclei config:', error);
    }
  };

  const handleNucleiConfigSave = async (config) => {
    console.log('Nuclei configuration saved:', config);
    setNucleiConfig(config);
    setShowNucleiConfigModal(false);
  };

  const isNucleiScanDisabled = () => {
    if (!nucleiConfig || !nucleiConfig.targets || !Array.isArray(nucleiConfig.targets) || nucleiConfig.targets.length === 0) return true;
    const hasCategories = nucleiConfig.templates && Array.isArray(nucleiConfig.templates) && nucleiConfig.templates.length > 0;
    const hasIndividualTemplates = nucleiConfig.template_ids && Array.isArray(nucleiConfig.template_ids) && nucleiConfig.template_ids.length > 0;
    return !hasCategories && !hasIndividualTemplates;
  };

  const getNucleiSelectedTargetsCount = () => {
    if (!nucleiConfig?.targets || !Array.isArray(nucleiConfig.targets)) return 0;
    return nucleiConfig.targets.length;
  };

  const getNucleiSelectedTemplatesCount = () => {
    let count = 0;
    if (nucleiConfig?.templates && Array.isArray(nucleiConfig.templates)) count += nucleiConfig.templates.length;
    if (nucleiConfig?.template_ids && Array.isArray(nucleiConfig.template_ids)) count += nucleiConfig.template_ids.length;
    return count;
  };

  const getNucleiEstimatedScanTime = () => {
    const targetCount = getNucleiSelectedTargetsCount();
    const templateCount = getNucleiSelectedTemplatesCount();
    
    if (targetCount === 0 || templateCount === 0) return "0 min";
    
    const estimatedSeconds = (targetCount * templateCount) * 0.5;
    const estimatedMinutes = Math.ceil(estimatedSeconds / 60);
    
    if (estimatedMinutes < 60) {
      return `${estimatedMinutes} min`;
    } else {
      const hours = Math.floor(estimatedMinutes / 60);
      const remainingMinutes = estimatedMinutes % 60;
      return remainingMinutes > 0 ? `${hours}h ${remainingMinutes}m` : `${hours}h`;
    }
  };

  const getNucleiTotalFindings = () => {
    if (!mostRecentNucleiScan?.result) return 0;
    
    try {
      let findings = [];
      if (typeof mostRecentNucleiScan.result === 'string') {
        findings = JSON.parse(mostRecentNucleiScan.result);
      } else if (Array.isArray(mostRecentNucleiScan.result)) {
        findings = mostRecentNucleiScan.result;
      }
      return Array.isArray(findings) ? findings.length : 0;
    } catch (error) {
      return 0;
    }
  };

  const getNucleiImpactfulFindings = () => {
    if (!mostRecentNucleiScan?.result) return 0;
    
    try {
      let findings = [];
      if (typeof mostRecentNucleiScan.result === 'string') {
        findings = JSON.parse(mostRecentNucleiScan.result);
      } else if (Array.isArray(mostRecentNucleiScan.result)) {
        findings = mostRecentNucleiScan.result;
      }
      
      if (!Array.isArray(findings)) return 0;
      
      console.log('[getNucleiImpactfulFindings] Total findings:', findings.length);
      
      const impactfulFindings = findings.filter(finding => {
        const severity = finding.info?.severity?.toLowerCase();
        const isImpactful = severity && severity !== 'info' && severity !== 'informational';
        if (isImpactful) {
          console.log('[getNucleiImpactfulFindings] Impactful finding:', {
            template: finding.template_id,
            severity: severity,
            name: finding.info?.name
          });
        }
        return isImpactful;
      });
      
      console.log('[getNucleiImpactfulFindings] Impactful findings count:', impactfulFindings.length);
      return impactfulFindings.length;
    } catch (error) {
      console.error('[getNucleiImpactfulFindings] Error:', error);
      return 0;
    }
  };

  const handleOpenNucleiResultsModal = () => setShowNucleiResultsModal(true);
  const handleCloseNucleiResultsModal = () => setShowNucleiResultsModal(false);

  const handleOpenNucleiHistoryModal = () => setShowNucleiHistoryModal(true);
  const handleCloseNucleiHistoryModal = () => setShowNucleiHistoryModal(false);

  const handleCloseWildcardNucleiConfigModal = () => setShowWildcardNucleiConfigModal(false);
  const handleOpenWildcardNucleiConfigModal = () => setShowWildcardNucleiConfigModal(true);

  const loadWildcardNucleiConfig = async () => {
    if (!activeTarget?.id) return;


    try {
      const response = await fetch(`/api/nuclei-config/${activeTarget.id}`);
      if (response.ok) {
        const config = await response.json();
        let needsSave = false;

        if (!config.templates || config.templates.length === 0) {
          config.templates = DEFAULT_NUCLEI_TEMPLATES;
          needsSave = true;
        }
        if (!config.severities || config.severities.length === 0) {
          config.severities = DEFAULT_NUCLEI_SEVERITIES;
          needsSave = true;
        }

        if (!config.targets || config.targets.length === 0) {
          try {
            const targetsResponse = await fetch(`/api/scopetarget/${activeTarget.id}/wildcard-nuclei-targets`);
            if (targetsResponse.ok) {
              const targetsData = await targetsResponse.json();
              const httpxTargets = (targetsData.targets || []).filter(Boolean);
              if (httpxTargets.length > 0) {
                config.targets = httpxTargets;
                config.target_mode = 'httpx_targets';
                needsSave = true;
              }
            }
          } catch (targetErr) {
            console.error('Error auto-populating Nuclei targets:', targetErr);
          }
        }

        if (needsSave && config.targets && config.targets.length > 0) {
          await fetch(`/api/nuclei-config/${activeTarget.id}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config),
          });
        }

        setWildcardNucleiConfig(config);
      }
    } catch (error) {
      console.error('Error loading Wildcard Nuclei config:', error);
    }
  };

  const handleWildcardNucleiConfigSave = async (config) => {
    setWildcardNucleiConfig(config);
    setShowWildcardNucleiConfigModal(false);
  };

  const isWildcardNucleiScanDisabled = () => {
    return !wildcardNucleiConfig ||
           !wildcardNucleiConfig.targets ||
           !Array.isArray(wildcardNucleiConfig.targets) ||
           wildcardNucleiConfig.targets.length === 0 ||
           ((!wildcardNucleiConfig.templates || !Array.isArray(wildcardNucleiConfig.templates) || wildcardNucleiConfig.templates.length === 0) &&
            (!wildcardNucleiConfig.template_ids || !Array.isArray(wildcardNucleiConfig.template_ids) || wildcardNucleiConfig.template_ids.length === 0));
  };

  const getWildcardNucleiSelectedTargetsCount = () => {
    if (!wildcardNucleiConfig?.targets || !Array.isArray(wildcardNucleiConfig.targets)) return 0;
    return wildcardNucleiConfig.targets.length;
  };

  const getWildcardNucleiSelectedTemplatesCount = () => {
    let count = 0;
    if (wildcardNucleiConfig?.templates && Array.isArray(wildcardNucleiConfig.templates)) count += wildcardNucleiConfig.templates.length;
    if (wildcardNucleiConfig?.template_ids && Array.isArray(wildcardNucleiConfig.template_ids)) count += wildcardNucleiConfig.template_ids.length;
    return count;
  };

  const getWildcardNucleiTotalFindings = () => {
    if (!mostRecentWildcardNucleiScan?.result) return 0;
    try {
      let findings = [];
      if (typeof mostRecentWildcardNucleiScan.result === 'string') {
        findings = JSON.parse(mostRecentWildcardNucleiScan.result);
      } else if (Array.isArray(mostRecentWildcardNucleiScan.result)) {
        findings = mostRecentWildcardNucleiScan.result;
      }
      return Array.isArray(findings) ? findings.length : 0;
    } catch (error) { return 0; }
  };

  const getWildcardNucleiImpactfulFindings = () => {
    if (!mostRecentWildcardNucleiScan?.result) return 0;
    try {
      let findings = [];
      if (typeof mostRecentWildcardNucleiScan.result === 'string') {
        findings = JSON.parse(mostRecentWildcardNucleiScan.result);
      } else if (Array.isArray(mostRecentWildcardNucleiScan.result)) {
        findings = mostRecentWildcardNucleiScan.result;
      }
      if (!Array.isArray(findings)) return 0;
      return findings.filter(f => {
        const sev = f.info?.severity?.toLowerCase();
        return sev && sev !== 'info' && sev !== 'informational';
      }).length;
    } catch (error) { return 0; }
  };

  const handleOpenWildcardNucleiResultsModal = () => setShowWildcardNucleiResultsModal(true);
  const handleCloseWildcardNucleiResultsModal = () => setShowWildcardNucleiResultsModal(false);

  const handleOpenWildcardNucleiHistoryModal = () => setShowWildcardNucleiHistoryModal(true);
  const handleCloseWildcardNucleiHistoryModal = () => setShowWildcardNucleiHistoryModal(false);

  const startWildcardNucleiScan = () => {
    initiateNucleiScan(
      activeTarget,
      monitorNucleiScanStatus,
      setIsWildcardNucleiScanning,
      setWildcardNucleiScans,
      setMostRecentWildcardNucleiScanStatus,
      setMostRecentWildcardNucleiScan,
      setActiveWildcardNucleiScan
    );
  };

  const handleCloseKatanaCompanyResultsModal = () => setShowKatanaCompanyResultsModal(false);
  const handleOpenKatanaCompanyResultsModal = () => setShowKatanaCompanyResultsModal(true);

  const handleCloseKatanaCompanyHistoryModal = () => setShowKatanaCompanyHistoryModal(false);
  const handleOpenKatanaCompanyHistoryModal = () => setShowKatanaCompanyHistoryModal(true);

  const handleCloseKatanaCompanyConfigModal = () => setShowKatanaCompanyConfigModal(false);
  const handleCloseExploreAttackSurfaceModal = () => setShowExploreAttackSurfaceModal(false);
  const handleOpenExploreAttackSurfaceModal = () => setShowExploreAttackSurfaceModal(true);
  const handleCloseAttackSurfaceVisualizationModal = () => setShowAttackSurfaceVisualizationModal(false);
  const handleOpenAttackSurfaceVisualizationModal = () => setShowAttackSurfaceVisualizationModal(true);
  const handleCloseManageAttackSurfaceModal = () => setShowManageAttackSurfaceModal(false);
  const handleOpenManageAttackSurfaceModal = () => setShowManageAttackSurfaceModal(true);
  const handleAttackSurfaceAssetChange = () => {
    if (activeTarget) {
      fetchAttackSurfaceAssetCounts(activeTarget, setAttackSurfaceASNsCount, setAttackSurfaceNetworkRangesCount, setAttackSurfaceIPAddressesCount, setAttackSurfaceLiveWebServersCount, setAttackSurfaceCloudAssetsCount, setAttackSurfaceFQDNsCount);
    }
  };
  const handleOpenKatanaCompanyConfigModal = () => setShowKatanaCompanyConfigModal(true);

  const handleKatanaCompanyConfigSave = async (config) => {
    console.log('Katana Company config saved:', config);
  };

  const startKatanaCompanyScan = async () => {
    if (!activeTarget) {
      console.error('No active target selected');
      return;
    }

    try {
      const response = await fetch(
        `/api/katana-company-config/${activeTarget.id}`
      );
      
      if (!response.ok) {
        console.error('No Katana Company configuration found');
        setToastTitle('Configuration Required');
        setToastMessage('Please configure domains in the Katana Company configuration before starting the scan.');
        setShowToast(true);
        setTimeout(() => setShowToast(false), 5000);
        return;
      }

          const config = await response.json();
    
    // Combine all selected domains from different sources
    const allDomains = [
      ...(config.selected_domains || []),
      ...(config.selected_wildcard_domains || []),
      ...(config.selected_live_web_servers || [])
    ];
    
    if (!allDomains || allDomains.length === 0) {
      console.error('No domains configured for Katana Company scan');
      setToastTitle('Configuration Required');
      setToastMessage('Please select domains in the Katana Company configuration before starting the scan.');
      setShowToast(true);
      setTimeout(() => setShowToast(false), 5000);
      return;
    }

    await initiateKatanaCompanyScan(
      activeTarget,
      allDomains,
        setIsKatanaCompanyScanning,
        setKatanaCompanyScans,
        setMostRecentKatanaCompanyScan,
        setMostRecentKatanaCompanyScanStatus,
        setKatanaCompanyCloudAssets
      );
    } catch (error) {
      console.error('Error starting Katana Company scan:', error);
      setToastTitle('Error');
      setToastMessage('Failed to start Katana Company scan. Please try again.');
      setShowToast(true);
      setTimeout(() => setShowToast(false), 5000);
    }
  };

  const handleCloseMetabigorCompanyResultsModal = () => setShowMetabigorCompanyResultsModal(false);
  const handleOpenMetabigorCompanyResultsModal = () => setShowMetabigorCompanyResultsModal(true);
  
  const handleCloseMetabigorCompanyHistoryModal = () => setShowMetabigorCompanyHistoryModal(false);
  const handleOpenMetabigorCompanyHistoryModal = () => setShowMetabigorCompanyHistoryModal(true);

  const handleCloseGoogleDorkingResultsModal = () => setShowGoogleDorkingResultsModal(false);
  const handleOpenGoogleDorkingResultsModal = () => setShowGoogleDorkingResultsModal(true);
  
  const handleCloseGoogleDorkingHistoryModal = () => setShowGoogleDorkingHistoryModal(false);
  const handleOpenGoogleDorkingHistoryModal = () => setShowGoogleDorkingHistoryModal(true);

  const handleCloseGoogleDorkingManualModal = () => setShowGoogleDorkingManualModal(false);
  const handleOpenGoogleDorkingManualModal = () => setShowGoogleDorkingManualModal(true);

  const startGoogleDorkingManualScan = () => {
    setShowGoogleDorkingManualModal(true);
  };

  const handleGoogleDorkingDomainAdd = async (domain) => {
    if (!activeTarget) {
      setGoogleDorkingError('No active target selected');
      return;
    }

    // Check if domain already exists in the current list
    const domainExists = googleDorkingDomains.some(existingDomain => 
      existingDomain.domain.toLowerCase() === domain.toLowerCase()
    );

    if (domainExists) {
      setGoogleDorkingError(`Domain "${domain}" already exists in the list`);
      return;
    }

    try {
      const response = await fetch(`/api/api/google-dorking-domains`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          scope_target_id: activeTarget.id,
          domain: domain,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to add domain');
      }

      // Refresh the domains list
      await fetchGoogleDorkingDomains();
      setGoogleDorkingError('');
      setToastTitle('Success');
      setToastMessage('Domain added successfully');
      setShowToast(true);
      setTimeout(() => setShowToast(false), 3000);
    } catch (error) {
      console.error('Error adding domain:', error);
      setGoogleDorkingError(error.message || 'Failed to add domain');
    }
  };

  const fetchGoogleDorkingDomains = async () => {
    if (!activeTarget) return;

    try {
      const response = await fetch(
        `/api/api/google-dorking-domains/${activeTarget.id}`
      );
      if (response.ok) {
        const domains = await response.json();
        setGoogleDorkingDomains(domains);
      }
    } catch (error) {
      console.error('Error fetching Google dorking domains:', error);
    }
  };

  const fetchNucleiScans = async (activeTarget, setNucleiScans, setMostRecentNucleiScan, setMostRecentNucleiScanStatus, setActiveNucleiScan) => {
    if (!activeTarget) return;

    try {
      console.log('[fetchNucleiScans] Fetching nuclei scans for target:', activeTarget.id);
      const response = await fetch(
        `/api/scopetarget/${activeTarget.id}/scans/nuclei`
      );

      if (response.ok) {
        const scans = await response.json();
        console.log('[fetchNucleiScans] Received nuclei scans:', scans);
        
        if (Array.isArray(scans)) {
          setNucleiScans(scans);
          
          if (scans.length > 0) {
            const mostRecentScan = scans[0]; // Assuming scans are sorted by most recent first
            console.log('[fetchNucleiScans] Most recent scan:', mostRecentScan);
            setMostRecentNucleiScan(mostRecentScan);
            setMostRecentNucleiScanStatus(mostRecentScan.status);
            setActiveNucleiScan(mostRecentScan);
          } else {
            console.log('[fetchNucleiScans] No nuclei scans found');
            setMostRecentNucleiScan(null);
            setMostRecentNucleiScanStatus(null);
            setActiveNucleiScan(null);
          }
        }
      } else {
        console.error('[fetchNucleiScans] Failed to fetch nuclei scans:', response.status, response.statusText);
      }
    } catch (error) {
      console.error('[fetchNucleiScans] Error fetching nuclei scans:', error);
    }
  };

  const deleteGoogleDorkingDomain = async (domainId) => {
    try {
      const response = await fetch(
        `/api/api/google-dorking-domains/${domainId}`,
        { method: 'DELETE' }
      );

      if (!response.ok) {
        throw new Error('Failed to delete domain');
      }

      // Refresh the domains list
      await fetchGoogleDorkingDomains();
      setToastTitle('Success');
      setToastMessage('Domain deleted successfully');
      setShowToast(true);
      setTimeout(() => setShowToast(false), 3000);
    } catch (error) {
      console.error('Error deleting domain:', error);
      setGoogleDorkingError('Failed to delete domain');
    }
  };

  const handleCloseSubfinderResultsModal = () => setShowSubfinderResultsModal(false);
  const handleOpenSubfinderResultsModal = () => setShowSubfinderResultsModal(true);

  const handleCloseShuffleDNSResultsModal = () => setShowShuffleDNSResultsModal(false);
  const handleOpenShuffleDNSResultsModal = () => setShowShuffleDNSResultsModal(true);

  const handleCloseReconResultsModal = () => setShowReconResultsModal(false);
  const handleOpenReconResultsModal = () => setShowReconResultsModal(true);

  const handleConsolidate = async () => {
    const target = activeTargetRef.current;
    if (!target) return;
    
    setIsConsolidating(true);
    try {
      const result = await consolidateSubdomains(target);
      if (result) {
        await fetchConsolidatedSubdomains(target, setConsolidatedSubdomains, setConsolidatedCount);
      }
    } catch (error) {
      console.error('Error during consolidation:', error);
    } finally {
      setIsConsolidating(false);
    }
  };

  const handleConsolidateCompanyDomains = async () => {
    if (!activeTarget) return;
    
    setIsConsolidatingCompanyDomains(true);
    try {
      const result = await consolidateCompanyDomains(activeTarget);
      if (result) {
        await fetchConsolidatedCompanyDomains(activeTarget, setConsolidatedCompanyDomains, setConsolidatedCompanyDomainsCount);
      }
    } catch (error) {
      console.error('Error during company domain consolidation:', error);
    } finally {
      setIsConsolidatingCompanyDomains(false);
    }
  };

  const handleConsolidateAttackSurface = async () => {
    if (!activeTarget) return;
    
    setIsConsolidatingAttackSurface(true);
    try {
      const result = await consolidateAttackSurface(activeTarget);
      if (result) {
        console.log('Attack surface consolidation result:', result);
        setConsolidatedAttackSurfaceResult(result);
        
        // Fetch updated counts after consolidation
        try {
          const response = await fetch(
            `/api/attack-surface-asset-counts/${activeTarget.id}`,
            {
              method: 'GET',
              headers: {
                'Content-Type': 'application/json',
              },
            }
          );
          
          if (response.ok) {
            const data = await response.json();
            setAttackSurfaceASNsCount(data.asns || 0);
            setAttackSurfaceNetworkRangesCount(data.network_ranges || 0);
            setAttackSurfaceIPAddressesCount(data.ip_addresses || 0);
            setAttackSurfaceLiveWebServersCount(data.live_web_servers || 0);
            setAttackSurfaceCloudAssetsCount(data.cloud_assets || 0);
            setAttackSurfaceFQDNsCount(data.fqdns || 0);
          }
        } catch (countError) {
          console.error('Error fetching attack surface asset counts:', countError);
        }
      }
    } catch (error) {
      console.error('Error during attack surface consolidation:', error);
    } finally {
      setIsConsolidatingAttackSurface(false);
    }
  };

  const handleInvestigateFQDNs = async () => {
    if (!activeTarget) return;
    
    setIsInvestigatingFQDNs(true);
    try {
      const result = await investigateFQDNs(activeTarget);
      if (result) {
        console.log('FQDN investigation result:', result);
        
        // Fetch updated counts after investigation
        try {
          const response = await fetch(
            `/api/attack-surface-asset-counts/${activeTarget.id}`,
            {
              method: 'GET',
              headers: {
                'Content-Type': 'application/json',
              },
            }
          );
          
          if (response.ok) {
            const data = await response.json();
            setAttackSurfaceASNsCount(data.asns || 0);
            setAttackSurfaceNetworkRangesCount(data.network_ranges || 0);
            setAttackSurfaceIPAddressesCount(data.ip_addresses || 0);
            setAttackSurfaceLiveWebServersCount(data.live_web_servers || 0);
            setAttackSurfaceCloudAssetsCount(data.cloud_assets || 0);
            setAttackSurfaceFQDNsCount(data.fqdns || 0);
          }
        } catch (error) {
          console.error('Error fetching updated asset counts:', error);
        }
      }
    } catch (error) {
      console.error('Error investigating FQDNs:', error);
    } finally {
      setIsInvestigatingFQDNs(false);
    }
  };

  const handleOpenUniqueSubdomainsModal = () => setShowUniqueSubdomainsModal(true);
  const handleOpenConfigureHttpxModal = () => setShowConfigureHttpxModal(true);
  const handleCloseConfigureHttpxModal = () => setShowConfigureHttpxModal(false);
  const handleSaveHttpxConfig = async (config) => {
    setHttpxScanConfig(config);
    if (activeTarget?.id) {
      try {
        await fetch(`/api/httpx-config/${activeTarget.id}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(config),
        });
      } catch (err) {
        console.error('Error saving HTTPX config to server:', err);
      }
    }
  };

  const loadHttpxConfig = async () => {
    if (!activeTarget?.id) return;
    try {
      const response = await fetch(`/api/httpx-config/${activeTarget.id}`);
      if (response.ok) {
        const config = await response.json();
        if (config && Object.keys(config).length > 0) {
          setHttpxScanConfig(config);
        }
      }
    } catch (err) {
      console.error('Error loading HTTPX config:', err);
    }
  };

  const handleOpenCeWLResultsModal = () => setShowCeWLResultsModal(true);
  const handleCloseCeWLResultsModal = () => setShowCeWLResultsModal(false);

  const handleCloseGoSpiderResultsModal = () => setShowGoSpiderResultsModal(false);
  const handleOpenGoSpiderResultsModal = () => setShowGoSpiderResultsModal(true);

  const handleCloseSubdomainizerResultsModal = () => setShowSubdomainizerResultsModal(false);
  const handleOpenSubdomainizerResultsModal = () => setShowSubdomainizerResultsModal(true);

  // Add this useEffect with the other useEffects
  useEffect(() => {
    if (activeTarget) {
      monitorGoSpiderScanStatus(
        activeTarget,
        setGoSpiderScans,
        setMostRecentGoSpiderScan,
        setIsGoSpiderScanning,
        setMostRecentGoSpiderScanStatus
      );
    }
  }, [activeTarget]);

  useEffect(() => {
    if (activeTarget) {
      monitorSubdomainizerScanStatus(
        activeTarget,
        setSubdomainizerScans,
        setMostRecentSubdomainizerScan,
        setIsSubdomainizerScanning,
        setMostRecentSubdomainizerScanStatus
      );
    }
  }, [activeTarget]);

  useEffect(() => {
    if (activeTarget) {
      monitorCTLCompanyScanStatus(
        activeTarget,
        setCTLCompanyScans,
        setMostRecentCTLCompanyScan,
        setIsCTLCompanyScanning,
        setMostRecentCTLCompanyScanStatus
      );
    }
  }, [activeTarget]);

  useEffect(() => {
    if (activeTarget) {
      monitorCloudEnumScanStatus(
        activeTarget,
        setCloudEnumScans,
        setMostRecentCloudEnumScan,
        setIsCloudEnumScanning,
        setMostRecentCloudEnumScanStatus
      );
    }
  }, [activeTarget]);

  // G1.8: removed a duplicate Metabigor company monitor effect here — it was identical to the
  // one in the main monitor cluster above and doubled Metabigor polling on every target switch.

  const handleCloseScreenshotResultsModal = () => setShowScreenshotResultsModal(false);
  const handleOpenScreenshotResultsModal = () => setShowScreenshotResultsModal(true);

  const startNucleiScreenshotScan = () => {
    initiateNucleiScreenshotScan(
      activeTarget,
      monitorNucleiScreenshotScanStatus,
      setIsNucleiScreenshotScanning,
      setNucleiScreenshotScans,
      setMostRecentNucleiScreenshotScanStatus,
      setMostRecentNucleiScreenshotScan
    );
  };

  useEffect(() => {
    if (activeTarget) {
      monitorNucleiScreenshotScanStatus(
        activeTarget,
        setNucleiScreenshotScans,
        setMostRecentNucleiScreenshotScan,
        setIsNucleiScreenshotScanning,
        setMostRecentNucleiScreenshotScanStatus
      );
    }
  }, [activeTarget]);

  const startMetaDataScan = async () => {
    console.log('[DEBUG] startMetaDataScan called');
    console.log('[DEBUG] isMetaDataScanning:', isMetaDataScanning);
    console.log('[DEBUG] mostRecentMetaDataScanStatus:', mostRecentMetaDataScanStatus);
    console.log('[DEBUG] mostRecentMetaDataScan:', mostRecentMetaDataScan);
    
    if (isMetaDataScanning || mostRecentMetaDataScanStatus === "pending" || mostRecentMetaDataScanStatus === "running") {
      console.log('[DEBUG] Scan is running, attempting to cancel...');
      if (mostRecentMetaDataScan && mostRecentMetaDataScan.scan_id) {
        console.log('[DEBUG] Cancelling metadata scan with ID:', mostRecentMetaDataScan.scan_id);
        const result = await cancelMetaDataScan(mostRecentMetaDataScan.scan_id);
        console.log('[DEBUG] Cancel result:', result);
        if (result.success) {
          console.log('[DEBUG] Metadata scan cancellation requested successfully');
          monitorMetaDataScanStatus(
            activeTarget,
            setMetaDataScans,
            setMostRecentMetaDataScan,
            setIsMetaDataScanning,
            setMostRecentMetaDataScanStatus
          );
        } else {
          console.error('[DEBUG] Failed to cancel metadata scan:', result.error);
        }
      } else {
        console.log('[DEBUG] No scan_id available in mostRecentMetaDataScan');
      }
      return;
    }

    console.log('[DEBUG] Starting new metadata scan...');

    const config = activeTarget ? metaDataScanConfigs[activeTarget.id] : null;
    initiateMetaDataScan(
      activeTarget,
      monitorMetaDataScanStatus,
      setIsMetaDataScanning,
      setMetaDataScans,
      setMostRecentMetaDataScanStatus,
      setMostRecentMetaDataScan,
      null,
      config
    );
  };

  useEffect(() => {
    if (activeTarget) {
      monitorMetaDataScanStatus(
        activeTarget,
        setMetaDataScans,
        setMostRecentMetaDataScan,
        setIsMetaDataScanning,
        setMostRecentMetaDataScanStatus
      );
    }
  }, [activeTarget]);

  const [metaDataElapsedTime, setMetaDataElapsedTime] = useState('0m 00s');

  useEffect(() => {
    let intervalId;
    if ((mostRecentMetaDataScanStatus === 'running' || mostRecentMetaDataScanStatus === 'pending' || mostRecentMetaDataScanStatus === 'cancelling') && 
        mostRecentMetaDataScan && mostRecentMetaDataScan.created_at) {
      intervalId = setInterval(() => {
        const elapsed = Math.floor((new Date() - new Date(mostRecentMetaDataScan.created_at)) / 1000);
        const minutes = Math.floor(elapsed / 60);
        const seconds = elapsed % 60;
        setMetaDataElapsedTime(`${minutes}m ${seconds.toString().padStart(2, '0')}s`);
      }, 1000);
    }
    return () => {
      if (intervalId) clearInterval(intervalId);
    };
  }, [mostRecentMetaDataScanStatus, mostRecentMetaDataScan]);

  useEffect(() => {
    if (activeTarget && activeTarget.id) {
      monitorInvestigateScanStatus(
        activeTarget,
        setInvestigateScans,
        setMostRecentInvestigateScan,
        setIsInvestigateScanning,
        setMostRecentInvestigateScanStatus
      );
    }
  }, [activeTarget]);

  const handleOpenMetaDataModal = () => {
    // G1.7: target-urls are loaded by metaDataQuery (projection 'meta' — no screenshot/body),
    // enabled on open. Cancel-on-switch + caching are handled by react-query.
    setShowMetaDataModal(true);
  };

  const handleOpenROIReport = () => {
    // G1.7: target-urls are loaded by roiReportQuery (projection 'no-screenshot' — keeps the
    // HTTP body for client-side scoring, drops base64 screenshots), enabled on open.
    setShowROIReport(true);
  };

  const handleCloseROIReport = () => {
    setShowROIReport(false);
  };

  const handleOpenSettingsModal = () => {
    setShowSettingsModal(true);
  };

  const handleOpenToolsModal = () => {
    setShowToolsModal(true);
  };

  const handleOpenToolsModalWithUrls = (urls) => {
    setToolsModalInitialUrls(urls);
    setToolsModalInitialTab('url-populator');
    setShowToolsModal(true);
  };

  const handleOpenExportModal = () => {
    setShowExportModal(true);
  };

  const handleOpenImportModal = () => {
    setShowImportModal(true);
  };

  const handleCloseImportModal = () => {
    setShowImportModal(false);
  };

  const handleCloseWelcomeModal = () => {
    setShowWelcomeModal(false);
  };

  const handleCloseLaunchPadModal = () => {
    setShowLaunchPadModal(false);
    if (scopeTargets.length === 0) {
      setShowWelcomeModal(true);
    }
  };

  const handleCloseConfigUploadModal = () => {
    setShowConfigUploadModal(false);
  };

  const handleCloseAPIIntegrationModal = () => {
    setShowAPIIntegrationModal(false);
  };

  const handleWelcomeAddScopeTarget = () => {
    setShowWelcomeModal(false);
    setShowModal(true);
  };

  const handleWelcomeImportData = () => {
    setShowWelcomeModal(false);
    setShowImportModal(true);
  };

  const handleWelcomeUploadConfig = () => {
    setShowWelcomeModal(false);
    setShowConfigUploadModal(true);
  };

  const handleWelcomeUseAPI = () => {
    setShowWelcomeModal(false);
    setShowAPIIntegrationModal(true);
  };

  const handleImportSuccess = async (result) => {
    await fetchScopeTargets();
  };

  const handleConfigUploadSuccess = async (result) => {
    await fetchScopeTargets();
  };

  const handleAPIIntegrationSuccess = async (result) => {
    await fetchScopeTargets();
  };

  const handleBackToWelcome = () => {
    setShowModal(false);
    setShowImportModal(false);
    setShowConfigUploadModal(false);
    setShowAPIIntegrationModal(false);
    setShowWelcomeModal(true);
  };

  const handleOpenSettingsOnAPIKeysTab = () => {
    setShowAPIKeysConfigModal(false);
    setSettingsModalInitialTab('api-keys');
    setShowSettingsModal(true);
  };

  // Add scroll position restoration
  useEffect(() => {
    const handleBeforeUnload = () => {
      sessionStorage.setItem('scrollPosition', window.scrollY.toString());
    };

    const restoreScrollPosition = () => {
      const scrollPosition = sessionStorage.getItem('scrollPosition');
      if (scrollPosition) {
        window.scrollTo({
          top: parseInt(scrollPosition, 10),
          behavior: 'smooth'
        });
      }
    };

    window.addEventListener('beforeunload', handleBeforeUnload);
    restoreScrollPosition();

    return () => {
      window.removeEventListener('beforeunload', handleBeforeUnload);
    };
  }, []);

  const fetchAutoScanState = async (targetId) => {
    if (!targetId) return;
    
    try {
      const response = await fetch(
        `/api/api/auto-scan-state/${targetId}`
      );
      
      if (response.ok) {
        const data = await response.json();
        setAutoScanCurrentStep(data.current_step || AUTO_SCAN_STEPS.IDLE);
        setAutoScanTargetId(targetId);
      }
    } catch (error) {
      console.error('Error fetching auto scan state:', error);
    }
  };

  // Fetch auto scan state whenever the active target changes
  useEffect(() => {
    if (activeTarget && activeTarget.id) {
      fetchAutoScanState(activeTarget.id);
    }
  }, [activeTarget]);

  const handleOpenAutoScanHistoryModal = async () => {
    if (!activeTarget || !activeTarget.id) return;
    try {
      const response = await fetch(
        `/api/api/auto-scan/sessions?target_id=${activeTarget.id}`
      );
      if (response.ok) {
        const rawData = await response.json();
        
        // Process and format the data for display
        const formattedData = Array.isArray(rawData) ? rawData.map(session => {
          // Format start time
          const startTime = new Date(session.started_at);
          const formattedStartTime = startTime.toLocaleString();
          
          // Format end time if available
          let formattedEndTime = "";
          let durationStr = "";
          
          if (session.ended_at) {
            const endTime = new Date(session.ended_at);
            formattedEndTime = endTime.toLocaleString();
            
            // Calculate duration
            const durationMs = endTime - startTime;
            const durationMins = Math.floor(durationMs / 60000);
            const durationSecs = Math.floor((durationMs % 60000) / 1000);
            durationStr = `${durationMins}m ${durationSecs < 10 ? '0' : ''}${durationSecs}s`;
          }
          
          // Parse config snapshot from the session
          let config = {};
          try {
            if (session.config_snapshot) {
              if (typeof session.config_snapshot === 'string') {
                config = JSON.parse(session.config_snapshot);
              } else {
                config = session.config_snapshot;
              }
            }
          } catch (e) {
            console.error("Error parsing config snapshot:", e);
            config = {};
          }
          
          return {
            session_id: session.id,
            start_time: formattedStartTime,
            end_time: formattedEndTime,
            duration: durationStr,
            status: session.status || "running",
            final_consolidated_subdomains: session.final_consolidated_subdomains || 0,
            final_live_web_servers: session.final_live_web_servers || 0,
            config: {
              amass: config.amass !== false,
              sublist3r: config.sublist3r !== false,
              assetfinder: config.assetfinder !== false,
              gau: config.gau !== false,
              ctl: config.ctl !== false,
              subfinder: config.subfinder !== false,
              consolidate_round1: config.consolidate_httpx_round1 !== false,
              httpx_round1: config.consolidate_httpx_round1 !== false,
              shuffledns: config.shuffledns !== false,
              cewl: config.cewl !== false,
              consolidate_round2: config.consolidate_httpx_round2 !== false,
              httpx_round2: config.consolidate_httpx_round2 !== false,
              gospider: config.gospider !== false,
              subdomainizer: config.subdomainizer !== false,
              consolidate_round3: config.consolidate_httpx_round3 !== false,
              httpx_round3: config.consolidate_httpx_round3 !== false,
              metadata: (config.metadata !== false) || (config.nuclei_screenshot !== false),
              nuclei_screenshot: (config.metadata !== false) || (config.nuclei_screenshot !== false)
            }
          };
        }) : [];
        
        setAutoScanSessions(formattedData);
        
        // The config_snapshot is stored in the database during auto scan session creation
        // and allows us to display which tools were enabled for each historical scan
        console.log('[Auto Scan History] Loaded session data with tool configuration information');
      } else {
        setAutoScanSessions([]);
      }
    } catch (error) {
      console.error("Error fetching auto scan sessions:", error);
      setAutoScanSessions([]);
    }
    setShowAutoScanHistoryModal(true);
  };

  const handleCloseAutoScanHistoryModal = () => setShowAutoScanHistoryModal(false);

  // Add this useEffect to poll for auto scan state changes
  useEffect(() => {
    if (isAutoScanning && activeTarget && activeTarget.id) {
      const interval = setInterval(async () => {
        try {
          const response = await fetch(
            `/api/api/auto-scan-state/${activeTarget.id}`
          );
          
          if (response.ok) {
            const data = await response.json();
            
            // Update pause state
            if (data.is_paused && !isAutoScanPaused) {
              setIsAutoScanPaused(true);
              setIsAutoScanPausing(false);
            } else if (!data.is_paused && isAutoScanPaused) {
              setIsAutoScanPaused(false);
            }
            
            // Update cancel state - reset to false when the scan is no longer running
            // This will switch the button back to "Cancel" after successful cancellation
            if (data.is_cancelled && !isAutoScanCancelling) {
              setIsAutoScanCancelling(true);
            } else if (!isAutoScanning && isAutoScanCancelling) {
              setIsAutoScanCancelling(false);
            }
            
            // If scan completed, reset states
            if (data.current_step === AUTO_SCAN_STEPS.COMPLETED) {
              setIsAutoScanPaused(false);
              setIsAutoScanPausing(false);
              setIsAutoScanCancelling(false);
            }
          }
        } catch (error) {
          console.error('Error polling auto scan state:', error);
        }
      }, 2000);
      
      return () => clearInterval(interval);
    } else if (!isAutoScanning && isAutoScanCancelling) {
      // Reset the cancelling state when the scan is no longer running
      setIsAutoScanCancelling(false);
    }
  }, [isAutoScanning, activeTarget, isAutoScanPaused, isAutoScanPausing, isAutoScanCancelling]);

  const handleCloseReverseWhoisResultsModal = () => setShowReverseWhoisResultsModal(false);
  const handleOpenReverseWhoisResultsModal = () => setShowReverseWhoisResultsModal(true);

  const handleCloseReverseWhoisManualModal = () => setShowReverseWhoisManualModal(false);
  const handleOpenReverseWhoisManualModal = () => setShowReverseWhoisManualModal(true);

  const startReverseWhoisManualScan = () => {
    setShowReverseWhoisManualModal(true);
  };

  const handleReverseWhoisDomainAdd = async (domain) => {
    if (!activeTarget) {
      setReverseWhoisError('No active target selected');
      return;
    }

    // Check if domain already exists in the current list
    const domainExists = reverseWhoisDomains.some(existingDomain => 
      existingDomain.domain.toLowerCase() === domain.toLowerCase()
    );

    if (domainExists) {
      setReverseWhoisError(`Domain "${domain}" already exists in the list`);
      return;
    }

    try {
      const response = await fetch(`/api/api/reverse-whois-domains`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          scope_target_id: activeTarget.id,
          domain: domain,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to add domain');
      }

      // Refresh the domains list
      await fetchReverseWhoisDomains();
      setReverseWhoisError('');
      setToastTitle('Success');
      setToastMessage('Domain added successfully');
      setShowToast(true);
      setTimeout(() => setShowToast(false), 3000);
    } catch (error) {
      console.error('Error adding domain:', error);
      setReverseWhoisError(error.message || 'Failed to add domain');
    }
  };

  const fetchReverseWhoisDomains = async () => {
    if (!activeTarget) return;

    try {
      const response = await fetch(
        `/api/api/reverse-whois-domains/${activeTarget.id}`
      );
      if (response.ok) {
        const domains = await response.json();
        setReverseWhoisDomains(domains);
      }
    } catch (error) {
      console.error('Error fetching reverse whois domains:', error);
    }
  };

  const deleteReverseWhoisDomain = async (domainId) => {
    try {
      const response = await fetch(
        `/api/api/reverse-whois-domains/${domainId}`,
        { method: 'DELETE' }
      );

      if (!response.ok) {
        throw new Error('Failed to delete domain');
      }

      // Refresh the domains list
      await fetchReverseWhoisDomains();
      setToastTitle('Success');
      setToastMessage('Domain deleted successfully');
      setShowToast(true);
      setTimeout(() => setShowToast(false), 3000);
    } catch (error) {
      console.error('Error deleting domain:', error);
      setReverseWhoisError('Failed to delete domain');
    }
  };

  const startSecurityTrailsCompanyScan = () => {
    initiateSecurityTrailsCompanyScan(
      activeTarget,
      monitorSecurityTrailsCompanyScanStatus,
      setIsSecurityTrailsCompanyScanning,
      setSecurityTrailsCompanyScans,
      setMostRecentSecurityTrailsCompanyScanStatus,
      setMostRecentSecurityTrailsCompanyScan
    );
  };

  useEffect(() => {
    if (activeTarget) {
      const fetchSecurityTrailsCompanyScans = async () => {
        try {
          const response = await fetch(
            `/api/scopetarget/${activeTarget.id}/scans/securitytrails-company`
          );
          if (!response.ok) {
            throw new Error('Failed to fetch SecurityTrails Company scans');
          }
          const scans = await response.json();
          if (Array.isArray(scans)) {
            setSecurityTrailsCompanyScans(scans);
            if (scans.length > 0) {
              const mostRecentScan = scans.reduce((latest, scan) => {
                const scanDate = new Date(scan.created_at);
                return scanDate > new Date(latest.created_at) ? scan : latest;
              }, scans[0]);
              setMostRecentSecurityTrailsCompanyScan(mostRecentScan);
              setMostRecentSecurityTrailsCompanyScanStatus(mostRecentScan.status);
            }
          }
        } catch (error) {
          console.error('[SECURITYTRAILS-COMPANY] Error fetching scans:', error);
        }
      };
      fetchSecurityTrailsCompanyScans();
    }
  }, [activeTarget]);

  useEffect(() => {
    const checkAllApiKeys = async () => {
      try {
        const response = await fetch(
          `/api/api/api-keys`
        );
        if (!response.ok) {
          throw new Error('Failed to fetch API keys');
        }
        const data = await response.json();
        
        // Check SecurityTrails API key based on localStorage selection
        const selectedSecurityTrailsKey = localStorage.getItem('selectedApiKey_SecurityTrails');
        const hasSecurityTrailsKey = selectedSecurityTrailsKey && 
          Array.isArray(data) && 
          data.some(key => 
            key.tool_name === 'SecurityTrails' && 
            key.api_key_name === selectedSecurityTrailsKey &&
            key.key_values?.api_key?.trim() !== ''
          );
        setHasSecurityTrailsApiKey(hasSecurityTrailsKey);
        
        // Check GitHub API key based on localStorage selection
        const selectedGitHubKey = localStorage.getItem('selectedApiKey_GitHub');
        const hasGitHubKey = selectedGitHubKey && 
          Array.isArray(data) && 
          data.some(key => 
            key.tool_name === 'GitHub' && 
            key.api_key_name === selectedGitHubKey &&
            key.key_values?.api_key?.trim() !== ''
          );
        setHasGitHubApiKey(hasGitHubKey);
        
        // Check Censys API key based on localStorage selection
        const selectedCensysKey = localStorage.getItem('selectedApiKey_Censys');
        const hasCensysKey = selectedCensysKey && 
          Array.isArray(data) && 
          data.some(key => 
            key.tool_name === 'Censys' && 
            key.api_key_name === selectedCensysKey &&
            key.key_values?.app_id?.trim() !== '' && 
            key.key_values?.app_secret?.trim() !== ''
          );
        setHasCensysApiKey(hasCensysKey);
        
        // Check Shodan API key based on localStorage selection
        const selectedShodanKey = localStorage.getItem('selectedApiKey_Shodan');
        const hasShodanKey = selectedShodanKey && 
          Array.isArray(data) && 
          data.some(key => 
            key.tool_name === 'Shodan' && 
            key.api_key_name === selectedShodanKey &&
            key.key_values?.api_key?.trim() !== ''
          );
        setHasShodanApiKey(hasShodanKey);
      } catch (error) {
        console.error('[API-KEYS] Error checking API keys on mount:', error);
        setHasSecurityTrailsApiKey(false);
        setHasGitHubApiKey(false);
        setHasCensysApiKey(false);
        setHasShodanApiKey(false);
      }
    };
    checkAllApiKeys();
  }, []);

  const handleApiKeySelected = (hasKey, toolName) => {
    if (toolName === 'securitytrails') {
      setHasSecurityTrailsApiKey(hasKey);
    } else if (toolName === 'github') {
      setHasGitHubApiKey(hasKey);
    } else if (toolName === 'censys') {
      setHasCensysApiKey(hasKey);
    } else if (toolName === 'shodan') {
      setHasShodanApiKey(hasKey);
    }
  };

  const handleApiKeyDeleted = async () => {
    // Re-check all API keys when one is deleted
    try {
      const response = await fetch(
        `/api/api/api-keys`
      );
      if (!response.ok) {
        throw new Error('Failed to fetch API keys');
      }
      const data = await response.json();
      
      // Check SecurityTrails API key based on localStorage selection
      const selectedSecurityTrailsKey = localStorage.getItem('selectedApiKey_SecurityTrails');
      const hasSecurityTrailsKey = selectedSecurityTrailsKey && 
        Array.isArray(data) && 
        data.some(key => 
          key.tool_name === 'SecurityTrails' && 
          key.api_key_name === selectedSecurityTrailsKey &&
          key.key_values?.api_key?.trim() !== ''
        );
      
      // If the selected key no longer exists, remove it from localStorage
      if (selectedSecurityTrailsKey && !hasSecurityTrailsKey) {
        localStorage.removeItem('selectedApiKey_SecurityTrails');
      }
      setHasSecurityTrailsApiKey(hasSecurityTrailsKey);
      
      // Check GitHub API key based on localStorage selection
      const selectedGitHubKey = localStorage.getItem('selectedApiKey_GitHub');
      const hasGitHubKey = selectedGitHubKey && 
        Array.isArray(data) && 
        data.some(key => 
          key.tool_name === 'GitHub' && 
          key.api_key_name === selectedGitHubKey &&
          key.key_values?.api_key?.trim() !== ''
        );
      
      // If the selected key no longer exists, remove it from localStorage
      if (selectedGitHubKey && !hasGitHubKey) {
        localStorage.removeItem('selectedApiKey_GitHub');
      }
      setHasGitHubApiKey(hasGitHubKey);
      
      // Check Censys API key based on localStorage selection
      const selectedCensysKey = localStorage.getItem('selectedApiKey_Censys');
      const hasCensysKey = selectedCensysKey && 
        Array.isArray(data) && 
        data.some(key => 
          key.tool_name === 'Censys' && 
          key.api_key_name === selectedCensysKey &&
          key.key_values?.app_id?.trim() !== '' && 
          key.key_values?.app_secret?.trim() !== ''
        );
      
      // If the selected key no longer exists, remove it from localStorage
      if (selectedCensysKey && !hasCensysKey) {
        localStorage.removeItem('selectedApiKey_Censys');
      }
      setHasCensysApiKey(hasCensysKey);
      
      // Check Shodan API key based on localStorage selection
      const selectedShodanKey = localStorage.getItem('selectedApiKey_Shodan');
      const hasShodanKey = selectedShodanKey && 
        Array.isArray(data) && 
        data.some(key => 
          key.tool_name === 'Shodan' && 
          key.api_key_name === selectedShodanKey &&
          key.key_values?.api_key?.trim() !== ''
        );
      
      // If the selected key no longer exists, remove it from localStorage
      if (selectedShodanKey && !hasShodanKey) {
        localStorage.removeItem('selectedApiKey_Shodan');
      }
      setHasShodanApiKey(hasShodanKey);
    } catch (error) {
      console.error('[API-KEYS] Error checking API keys after deletion:', error);
      setHasSecurityTrailsApiKey(false);
      setHasGitHubApiKey(false);
      setHasCensysApiKey(false);
      setHasShodanApiKey(false);
    }
  };

  useEffect(() => {
    if (activeTarget) {
      const fetchCensysCompanyScans = async () => {
        try {
          const response = await fetch(
            `/api/scopetarget/${activeTarget.id}/scans/censys-company`
          );
          if (!response.ok) {
            throw new Error('Failed to fetch Censys Company scans');
          }
          const scans = await response.json();
          if (Array.isArray(scans)) {
            setCensysCompanyScans(scans);
            if (scans.length > 0) {
              const mostRecentScan = scans.reduce((latest, scan) => {
                const scanDate = new Date(scan.created_at);
                return scanDate > new Date(latest.created_at) ? scan : latest;
              }, scans[0]);
              setMostRecentCensysCompanyScan(mostRecentScan);
              setMostRecentCensysCompanyScanStatus(mostRecentScan.status);
            }
          }
        } catch (error) {
          console.error('[CENSYS-COMPANY] Error fetching scans:', error);
        }
      };
      fetchCensysCompanyScans();
    }
  }, [activeTarget]);

  useEffect(() => {
    if (activeTarget) {
      const fetchShodanCompanyScans = async () => {
        try {
          const response = await fetch(
            `/api/scopetarget/${activeTarget.id}/scans/shodan-company`
          );
          if (!response.ok) {
            throw new Error('Failed to fetch Shodan Company scans');
          }
          const scans = await response.json();
          if (Array.isArray(scans)) {
            setShodanCompanyScans(scans);
            if (scans.length > 0) {
              const mostRecentScan = scans.reduce((latest, scan) => {
                const scanDate = new Date(scan.created_at);
                return scanDate > new Date(latest.created_at) ? scan : latest;
              }, scans[0]);
              setMostRecentShodanCompanyScan(mostRecentScan);
              setMostRecentShodanCompanyScanStatus(mostRecentScan.status);
            }
          }
        } catch (error) {
          console.error('[SHODAN-COMPANY] Error fetching scans:', error);
        }
      };
      fetchShodanCompanyScans();
    }
  }, [activeTarget]);

  // Amass Enum Company scans useEffect
  useEffect(() => {
    // Immediately reset counts when target changes to prevent showing stale data
    setAmassEnumScannedDomainsCount(0);
    setAmassEnumCompanyCloudDomains([]);
    setMostRecentAmassEnumCompanyScan(null);
    setMostRecentAmassEnumCompanyScanStatus(null);
    
    if (activeTarget && !isAmassEnumCompanyScanning) { // Only fetch when not actively scanning
      const fetchAmassEnumCompanyScans = async () => {
        try {
          const response = await fetch(
            `/api/scopetarget/${activeTarget.id}/scans/amass-enum-company`
          );
          if (!response.ok) {
            throw new Error('Failed to fetch Amass Enum Company scans');
          }
          const scans = await response.json();
          if (Array.isArray(scans)) {
            setAmassEnumCompanyScans(scans);
            if (scans.length > 0) {
              const mostRecentScan = scans.reduce((latest, scan) => {
                const scanDate = new Date(scan.created_at);
                return scanDate > new Date(latest.created_at) ? scan : latest;
              }, scans[0]);
              setMostRecentAmassEnumCompanyScan(mostRecentScan);
              setMostRecentAmassEnumCompanyScanStatus(mostRecentScan.status);
              
              // Fetch raw results to get actual scanned domains count
              if (mostRecentScan.scan_id) {
                const rawResultsResponse = await fetch(
                  `/api/amass-enum-company/${mostRecentScan.scan_id}/raw-results`
                );
                if (rawResultsResponse.ok) {
                  const rawResults = await rawResultsResponse.json();
                  // Count unique domains from raw results, not total number of results
                  const uniqueDomains = rawResults ? [...new Set(rawResults.map(result => result.domain))].length : 0;
                  setAmassEnumScannedDomainsCount(uniqueDomains);
                } else {
                  setAmassEnumScannedDomainsCount(0);
                }

                // Fetch cloud domains for the main card display
                const cloudDomainsResponse = await fetch(
                  `/api/amass-enum-company/${mostRecentScan.scan_id}/cloud-domains`
                );
                if (cloudDomainsResponse.ok) {
                  const cloudDomains = await cloudDomainsResponse.json();
                  setAmassEnumCompanyCloudDomains(cloudDomains || []);
                } else {
                  setAmassEnumCompanyCloudDomains([]);
                }
              }
            }
          }
        } catch (error) {
          console.error('[AMASS-ENUM-COMPANY] Error fetching scans:', error);
          setAmassEnumScannedDomainsCount(0);
          setAmassEnumCompanyCloudDomains([]);
        }
      };
      fetchAmassEnumCompanyScans();
    }
  }, [activeTarget, isAmassEnumCompanyScanning]); // Add isAmassEnumCompanyScanning dependency

  // DNSx Company scans useEffect  
  useEffect(() => {
    // Immediately reset counts when target changes to prevent showing stale data
    setDnsxScannedDomainsCount(0);
    setDnsxCompanyDnsRecords([]);
    setMostRecentDNSxCompanyScan(null);
    setMostRecentDNSxCompanyScanStatus(null);
    
    if (activeTarget) {
      const fetchDNSxCompanyScans = async () => {
        try {
          const response = await fetch(
            `/api/scopetarget/${activeTarget.id}/scans/dnsx-company`
          );
          if (!response.ok) {
            throw new Error('Failed to fetch DNSx Company scans');
          }
          const scans = await response.json();
          if (Array.isArray(scans)) {
            setDnsxCompanyScans(scans);
            if (scans.length > 0) {
              // API returns scans in descending order (newest first), so just use the first one
              const mostRecentScan = scans[0];
              setMostRecentDNSxCompanyScan(mostRecentScan);
              setMostRecentDNSxCompanyScanStatus(mostRecentScan.status);
              
              // Fetch raw results to get actual scanned domains count
              if (mostRecentScan.scan_id) {
                // Get the actual number of root domains that were scanned from the scan configuration
                // instead of counting discovered DNS records from raw results
                if (mostRecentScan.domains && Array.isArray(mostRecentScan.domains)) {
                  setDnsxScannedDomainsCount(mostRecentScan.domains.length);
                } else {
                  setDnsxScannedDomainsCount(0);
                }

                // Fetch DNS records for the main card display
                const dnsRecordsResponse = await fetch(
                  `/api/dnsx-company/${mostRecentScan.scan_id}/dns-records`
                );
                if (dnsRecordsResponse.ok) {
                  const dnsRecords = await dnsRecordsResponse.json();
                  setDnsxCompanyDnsRecords(dnsRecords || []);
                } else {
                  setDnsxCompanyDnsRecords([]);
                }
              }
            }
          }
        } catch (error) {
          console.error('[DNSX-COMPANY] Error fetching scans:', error);
          setDnsxScannedDomainsCount(0);
          setDnsxCompanyDnsRecords([]);
        }
      };
      fetchDNSxCompanyScans();
    }
  }, [activeTarget]);

  // URL Workflow scans useEffect hooks
  useEffect(() => {
    if (activeTarget && activeTarget.type === 'URL') {
      monitorKatanaURLScanStatus(
        activeTarget,
        setKatanaURLScans,
        setMostRecentKatanaURLScan,
        setIsKatanaURLScanning,
        setMostRecentKatanaURLScanStatus
      );
    }
  }, [activeTarget]);

  useEffect(() => {
    if (activeTarget && activeTarget.type === 'URL') {
      monitorLinkFinderURLScanStatus(
        activeTarget,
        setLinkFinderURLScans,
        setMostRecentLinkFinderURLScan,
        setIsLinkFinderURLScanning,
        setMostRecentLinkFinderURLScanStatus
      );
    }
  }, [activeTarget]);

  useEffect(() => {
    if (activeTarget && activeTarget.type === 'URL') {
      monitorWaybackURLsScanStatus(
        activeTarget,
        setWaybackURLsScans,
        setMostRecentWaybackURLsScan,
        setIsWaybackURLsScanning,
        setMostRecentWaybackURLsScanStatus
      );
    }
  }, [activeTarget]);

  useEffect(() => {
    if (activeTarget && activeTarget.type === 'URL') {
      monitorGAUURLScanStatus(
        activeTarget,
        setGAUURLScans,
        setMostRecentGAUURLScan,
        setIsGAUURLScanning,
        setMostRecentGAUURLScanStatus
      );
    }
  }, [activeTarget]);

  useEffect(() => {
    if (activeTarget && activeTarget.type === 'URL') {
      monitorGoSpiderURLScanStatus(
        activeTarget,
        setGoSpiderURLScans,
        setMostRecentGoSpiderURLScan,
        setIsGoSpiderURLScanning,
        setMostRecentGoSpiderURLScanStatus
      );
    }
  }, [activeTarget]);

  useEffect(() => {
    if (activeTarget && activeTarget.type === 'URL') {
      monitorFFUFURLScanStatus(
        activeTarget,
        setFFUFURLScans,
        setMostRecentFFUFURLScan,
        setIsFFUFURLScanning,
        setMostRecentFFUFURLScanStatus
      );
    }
  }, [activeTarget]);

  useEffect(() => {
    if (activeTarget && activeTarget.type === 'URL') {
      monitorWAFProbeScanStatus(
        activeTarget,
        setWAFProbeScans,
        setMostRecentWAFProbeScan,
        setIsWAFProbeScanning,
        setMostRecentWAFProbeScanStatus
      );
    }
  }, [activeTarget]);

  // Katana Company scans useEffect
  useEffect(() => {
    if (activeTarget) {
      const fetchKatanaCompanyScans = async () => {
        try {
          const response = await fetch(
            `/api/scopetarget/${activeTarget.id}/scans/katana-company`
          );
          if (!response.ok) {
            throw new Error('Failed to fetch Katana Company scans');
          }
          const scans = await response.json();
          if (Array.isArray(scans)) {
            setKatanaCompanyScans(scans);
            if (scans.length > 0) {
              const mostRecentScan = scans[0];
              setMostRecentKatanaCompanyScan(mostRecentScan);
              setMostRecentKatanaCompanyScanStatus(mostRecentScan.status);
              
              // Fetch accumulated cloud assets from the backend API
              try {
                const assetsResponse = await fetch(
                  `/api/katana-company/${mostRecentScan.scan_id}/cloud-assets`
                );
                if (assetsResponse.ok) {
                  const assets = await assetsResponse.json();
                  setKatanaCompanyCloudAssets(assets || []);
                } else {
                  console.error('[KATANA-COMPANY] Failed to fetch cloud assets');
                  setKatanaCompanyCloudAssets([]);
                }
              } catch (error) {
                console.error('[KATANA-COMPANY] Error fetching cloud assets:', error);
                setKatanaCompanyCloudAssets([]);
              }
            } else {
              setKatanaCompanyCloudAssets([]);
            }
          }
        } catch (error) {
          console.error('[KATANA-COMPANY] Error fetching scans:', error);
          setKatanaCompanyCloudAssets([]);
        }
      };
      fetchKatanaCompanyScans();
    }
  }, [activeTarget]);

  useEffect(() => {
    if (activeTarget) {
      loadNucleiConfig();
      loadHttpxConfig();
      if (activeTarget.type === 'Wildcard') {
        loadWildcardNucleiConfig();
      }
    }
  }, [activeTarget]);

  const startNucleiScan = () => {
    initiateNucleiScan(
      activeTarget,
      monitorNucleiScanStatus,
      setIsNucleiScanning,
      setNucleiScans,
      setMostRecentNucleiScanStatus,
      setMostRecentNucleiScan,
      setActiveNucleiScan
    );
  };

  const startCensysCompanyScan = () => {
    initiateCensysCompanyScan(
      activeTarget,
      monitorCensysCompanyScanStatus,
      setIsCensysCompanyScanning,
      setCensysCompanyScans,
      setMostRecentCensysCompanyScanStatus,
      setMostRecentCensysCompanyScan
    );
  };

  const startShodanCompanyScan = () => {
    initiateShodanCompanyScan(
      activeTarget,
      monitorShodanCompanyScanStatus,
      setIsShodanCompanyScanning,
      setShodanCompanyScans,
      setMostRecentShodanCompanyScanStatus,
      setMostRecentShodanCompanyScan
    );
  };

  const startGitHubReconScan = () => {
    initiateGitHubReconScan(
      activeTarget,
      monitorGitHubReconScanStatus,
      setIsGitHubReconScanning,
      setGitHubReconScans,
      setMostRecentGitHubReconScanStatus,
      setMostRecentGitHubReconScan
    );
  };

  const startKatanaURLScan = () => {
    initiateKatanaURLScan(
      activeTarget,
      setIsKatanaURLScanning,
      setKatanaURLScans,
      setMostRecentKatanaURLScan,
      setMostRecentKatanaURLScanStatus
    );
  };

  const startLinkFinderURLScan = () => {
    initiateLinkFinderURLScan(
      activeTarget,
      setIsLinkFinderURLScanning,
      setLinkFinderURLScans,
      setMostRecentLinkFinderURLScan,
      setMostRecentLinkFinderURLScanStatus
    );
  };

  const startWaybackURLsScan = () => {
    initiateWaybackURLsScan(
      activeTarget,
      setIsWaybackURLsScanning,
      setWaybackURLsScans,
      setMostRecentWaybackURLsScan,
      setMostRecentWaybackURLsScanStatus
    );
  };

  const startGAUURLScan = () => {
    initiateGAUURLScan(
      activeTarget,
      setIsGAUURLScanning,
      setGAUURLScans,
      setMostRecentGAUURLScan,
      setMostRecentGAUURLScanStatus
    );
  };

  const startGoSpiderURLScan = () => {
    initiateGoSpiderURLScan(
      activeTarget,
      setIsGoSpiderURLScanning,
      setGoSpiderURLScans,
      setMostRecentGoSpiderURLScan,
      setMostRecentGoSpiderURLScanStatus
    );
  };

  const startFFUFURLScan = () => {
    initiateFFUFURLScan(
      activeTarget,
      setIsFFUFURLScanning,
      setFFUFURLScans,
      setMostRecentFFUFURLScan,
      setMostRecentFFUFURLScanStatus
    );
  };

  // Reloaded whenever the target changes or the config is saved, so the card's "configured" number
  // reflects what the next run will actually do rather than what the last one did.
  const loadWAFProbeTargetCount = useCallback(async () => {
    if (!activeTarget?.id) { setWafProbeTargetCount(null); return; }
    try {
      const res = await fetch(`/api/waf-probe/config/${activeTarget.id}`);
      if (!res.ok) { setWafProbeTargetCount(0); return; }
      const cfg = await res.json();
      setWafProbeTargetCount((cfg?.targets || []).filter((t) => t && t.url).length);
    } catch (e) {
      // Null, not zero: "we could not read it" must not render as "none configured".
      setWafProbeTargetCount(null);
    }
  }, [activeTarget]);

  useEffect(() => { void loadWAFProbeTargetCount(); }, [loadWAFProbeTargetCount]);

  const startWAFProbeScan = (configOverride = null) => {
    setWafProbeRunError('');
    initiateWAFProbeScan(
      activeTarget,
      setIsWAFProbeScanning,
      setWAFProbeScans,
      setMostRecentWAFProbeScan,
      setMostRecentWAFProbeScanStatus,
      configOverride,
      setWafProbeRunError
    );
  };

  // What the card shows at a glance. The ordering answers "can I start the next tool, and at what
  // rate", which is the only question this card exists to answer. Everything else is in the modal.
  //
  // The rate and its confidence are one fact, never two. "5 req/s" alone would let an assumed
  // default read as a measurement, which is the most expensive mistake this card could make.
  const wafProbeCard = useMemo(() => {
    // How many endpoints the LATEST run actually scanned. Counted from the scans sharing the newest
    // run_id, and only those carrying a result: a scan still pending or one that died before
    // producing anything has not scanned its endpoint, and counting it would overstate coverage.
    const scans = Array.isArray(wafProbeScans) ? wafProbeScans : [];
    const newestRunId = scans.find((s) => s?.run_id)?.run_id || null;
    const newestRun = newestRunId ? scans.filter((s) => s.run_id === newestRunId) : [];
    const targetsScanned = newestRunId
      ? newestRun.filter((s) => s.result).length
      // A single-endpoint run predates run_id, so one completed scan is one endpoint scanned.
      : (scans[0]?.result ? 1 : 0);

    // How many endpoints the IN-FLIGHT run covers, counted from its scan rows rather than from the
    // saved config. A run started with inline endpoints (the MCP run tools, or any API caller) never
    // writes to the config, so the card would otherwise report "0 configured" while visibly scanning
    // two of them. During a run the run's own target set IS the operative intent.
    const targetsInFlightRun = newestRun.some((s) => s.status === 'pending' || s.status === 'running')
      ? newestRun.length
      : 0;

    const empty = {
      state: 'none', rate: null, rateNote: null, rateMeasured: false,
      threads: null, blockers: 0, topBlocker: null, posture: null,
      runStatus: null, at: null, targetsScanned, targetsInFlightRun,
    };
    const raw = mostRecentWAFProbeScan?.result;
    if (!raw) {
      if (mostRecentWAFProbeScanStatus === 'error') return { ...empty, state: 'error' };
      return { ...empty, state: mostRecentWAFProbeScanStatus ? 'noresult' : 'none' };
    }

    let p;
    try {
      p = typeof raw === 'string' ? JSON.parse(raw) : raw;
    } catch (e) {
      return { ...empty, state: 'unreadable' };
    }

    // A result stored before the rewrite has no verdict block. Say so rather than reading v1
    // fields that no longer mean what they used to.
    if (!p.verdict) return { ...empty, state: 'legacy', at: mostRecentWAFProbeScan?.created_at };

    const v = p.verdict;
    const conf = v.safe_rps_confidence;
    const p0 = (v.will_break || []).find((w) => w.tier === 'P0');

    return {
      state: 'ok',
      rate: v.safe_rps || null,
      rateMeasured: conf === 'measured',
      rateNote: !v.safe_rps ? 'none established'
        : conf === 'measured' ? (v.safe_rps_verified ? 'measured & validated' : 'measured')
        : conf === 'inferred' ? 'inferred, not re-verified'
        : 'assumed, not measured',
      threads: v.safe_concurrency || null,
      blockers: v.counts?.p0 || 0,
      // The title, not the count. "Configured URL is not the canonical one" tells the operator
      // what to fix; "2 critical" sends them hunting through a modal for it.
      topBlocker: p0 ? p0.title : null,
      posture: v.posture || null,
      runStatus: p.run?.status || null,
      at: mostRecentWAFProbeScan?.created_at,
      targetsScanned,
      targetsInFlightRun,
      // The three things the card's own description promises to answer. Each is rendered only when
      // the probe actually established it, because "not measured" and "measured as none" are
      // different answers and the card must not blur them.
      concurrency: v.safe_concurrency || null,
      // Routing: whether every Host under the domain reaches the same application, which decides
      // whether subdomain-oriented discovery means anything on this target.
      //
      // Mapped from the probe's own verdict strings rather than compared against a guessed one. The
      // real value is "wildcard_vhost", and an === 'wildcard' test silently rendered the OPPOSITE
      // answer. Anything unrecognised renders nothing at all: a routing claim the probe did not make
      // is worse than a blank line.
      // The probe emits exactly two values here (tests_protocol.py:412): wildcard_vhost when almost
      // every Host tried returned the baseline application, specific_vhost otherwise. Read from the
      // source rather than guessed: an === 'wildcard' test rendered the OPPOSITE answer, and a
      // startsWith('wildcard') test silently dropped specific_vhost entirely.
      hostRoutingText: (() => {
        switch (p.results?.wildcard_host_routing?.verdict) {
          case 'wildcard_vhost':
            return 'Any Host under this domain serves the same application';
          case 'specific_vhost':
            return 'Hosts route to distinct applications';
          default:
            return null;
        }
      })(),
      // Volume: whether a rate limit was found at all, as opposed to a rate being assumed.
      rateLimited: p.results?.load_ramp?.verdict
        ? p.results.load_ramp.verdict !== 'no_limit_observed'
        : null,
    };
  }, [mostRecentWAFProbeScan, mostRecentWAFProbeScanStatus, wafProbeScans]);

  // How the probe's posture reads on the card. The wording is the operator's answer to "will my
  // scans get blocked", not the probe's internal enum.
  const WAF_POSTURE = {
    DEFENDED: { text: 'Actively blocking payloads', className: 'text-danger', icon: 'bi-shield-fill-exclamation' },
    PARTIALLY_DEFENDED: { text: 'Blocks some payload classes', className: 'text-warning', icon: 'bi-shield-fill' },
    OPEN: { text: 'No inline blocking observed', className: 'text-success', icon: 'bi-shield-slash' },
    INCONCLUSIVE: { text: 'Blocking behaviour inconclusive', className: 'text-muted', icon: 'bi-question-circle' },
    UNKNOWN: { text: 'Blocking not characterised', className: 'text-muted', icon: 'bi-question-circle' },
    REFUSED: { text: 'Probe refused to run', className: 'text-muted', icon: 'bi-slash-circle' },
  };

  // All three FFUF phases on the card. A scan that ran and found nothing must not look identical
  // to one that was never run, which is what a bare "Endpoints: 0" did.
  // Accumulated across every run of the flow, which is the point of the composer: a re-run adds
  // what is new instead of replacing what was there.
  const [ffufFindingCount, setFfufFindingCount] = useState(null);
  const [isFFUFFlowRunning, setIsFFUFFlowRunning] = useState(false);

  // Two numbers, because one of them was actively misleading on its own. `total` counts every row
  // ever stored, and a step pointed at an endpoint behind an expired credential contributes one row
  // per wordlist word: 5080 "findings" of which 4997 were the same 401. `notable` is total minus each
  // step's own baseline response, which is the count worth putting on a card.
  const [ffufNotableCount, setFfufNotableCount] = useState(null);

  const loadFuzzFindingCount = useCallback(async () => {
    if (!activeTarget) return;
    try {
      // limit=1 because only the counts are wanted here; the summary is computed over the whole set
      // server-side, so pulling rows to throw away would be waste.
      const res = await fetch(`/api/fuzz/${activeTarget.id}/findings?tool=ffuf&limit=1`);
      if (res.ok) {
        const data = await res.json();
        setFfufFindingCount(data.total || 0);
        setFfufNotableCount(data.summary && typeof data.summary.notable === 'number'
          ? data.summary.notable : null);
      }
    } catch (err) {
      console.error('Error loading fuzz findings:', err);
    }
  }, [activeTarget]);

  useEffect(() => { loadFuzzFindingCount(); }, [loadFuzzFindingCount]);

  // What the flow is doing, read from the server rather than remembered from a click.
  //
  // A run belongs to the target, not to the browser tab that started it: reloading the page used to
  // show an idle card over a running scan, and a run started from the MCP was invisible here
  // entirely. Polling one endpoint fixes both, and is also how the card knows how many steps the
  // flow has when nothing is running.
  const [ffufRun, setFfufRun] = useState(null);
  const [ffufFlowSteps, setFfufFlowSteps] = useState({ enabled: 0, total: 0 });

  // Raising a toast, in one call.
  //
  // A warning stays up far longer than a success, because they are read differently: a success is
  // confirmation of something you just did and already expected, and a warning is news. The blocked
  // step message in particular is several lines naming which rounds will not run, and three seconds
  // is not enough to read that, which is the reason it used to be an alert() instead.
  const notify = useCallback((title, message, variant = 'success') => {
    setToastTitle(title);
    setToastMessage(message);
    setToastVariant(variant);
    setShowToast(true);
    setTimeout(() => setShowToast(false), variant === 'warning' ? 12000 : 3000);
  }, []);

  const loadFuzzRunState = useCallback(async () => {
    if (!activeTarget) return null;
    try {
      const res = await fetch(`/api/fuzz/${activeTarget.id}/latest-run`);
      if (!res.ok) return null;
      const data = await res.json();
      setFfufFlowSteps({ enabled: data.enabled_steps || 0, total: data.total_steps || 0 });
      setFfufRun(data.run || null);
      return data.run || null;
    } catch {
      return null;
    }
  }, [activeTarget]);

  // Poll while something is running, and once on arrival to discover a run already in flight.
  useEffect(() => {
    let live = true;
    let timer = null;
    const tick = async () => {
      const run = await loadFuzzRunState();
      if (!live) return;
      if (run && run.running) {
        timer = setTimeout(tick, 3000);
      } else if (run && !run.running) {
        loadFuzzFindingCount();
      }
    };
    tick();
    return () => { live = false; if (timer) clearTimeout(timer); };
  }, [loadFuzzRunState, loadFuzzFindingCount]);

  const isFFUFRunning = !!(ffufRun && ffufRun.running) || isFFUFFlowRunning;

  // How much of the discovered surface each parameter tool is actually pointed at.
  //
  // "Parameters: 8" says nothing about coverage: eight found across every endpoint in scope and eight
  // found across two of nineteen are different results, and only one of them means the surface has
  // been looked at. The selection lives server-side, which is also what the scan reads, so the card
  // and the run cannot disagree about what is enabled.
  const [paramTargetCounts, setParamTargetCounts] = useState({ arjun: null, x8: null });

  const loadParamTargetCounts = useCallback(async () => {
    if (!activeTarget) return;
    const next = {};
    await Promise.all(['arjun', 'x8'].map(async (tool) => {
      try {
        const res = await fetch(`/api/param-enum/${activeTarget.id}/targets?tool=${tool}`);
        if (res.ok) {
          const data = await res.json();
          next[tool] = { enabled: data.enabled || 0, total: data.total || 0 };
        }
      } catch {
        next[tool] = null;
      }
    }));
    setParamTargetCounts((prev) => ({ ...prev, ...next }));
  }, [activeTarget]);

  useEffect(() => { loadParamTargetCounts(); }, [loadParamTargetCounts]);

  // The Scan button runs the flow. Each round is an independent ffuf invocation run in order.
  const startFFUFFlow = async () => {
    if (!activeTarget) return;
    const go = async (acknowledge) => {
      const res = await fetch(`/api/fuzz/${activeTarget.id}/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tool: 'ffuf', acknowledge }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.status === 409 && data.acknowledgeable) {
        if (window.confirm(data.reason + ' Run it anyway?')) return go(true);
        return null;
      }
      // A second run of the same flow is refused rather than queued: two would send twice the paced
      // rate at one target.
      if (res.status === 409) {
        notify('Already running', data.reason || 'A run for this flow is already going.', 'warning');
        return null;
      }
      if (!res.ok) {
        notify('Flow did not start',
          data.message || data.reason || 'The flow could not start', 'warning');
        return null;
      }
      return data;
    };

    setIsFFUFFlowRunning(true);
    const started = await go(false);
    if (!started) { setIsFFUFFlowRunning(false); return; }

    // Steps refused before the run started were reported here and thrown away, so a three-step flow
    // that ran one step looked like a clean run. Saying it at the moment the operator clicked is the
    // only point where they can still do something about it.
    if (started.blocked && started.blocked.length > 0) {
      const covered = `${started.steps} of ${started.steps + started.blocked.length}`;
      notify(`Covering ${covered} steps`,
        `${started.blocked.length} step(s) will not run:\n\n${started.blocked.join('\n\n')}`,
        'warning');
    }

    // Progress is read from the server by the latest-run effect, which polls for as long as anything
    // is running and picks up runs this tab did not start. All this has to do is stop claiming to be
    // running once that effect has something to say.
    await loadFuzzRunState();
    setIsFFUFFlowRunning(false);
  };

  const startArjunScan = () => {
    initiateArjunScan(
      activeTarget,
      setIsArjunScanning,
      setArjunScans,
      setMostRecentArjunScan,
      setMostRecentArjunScanStatus
    );
  };

  const startX8Scan = () => {
    initiateX8Scan(
      activeTarget,
      setIsX8Scanning,
      setX8Scans,
      setMostRecentX8Scan,
      setMostRecentX8ScanStatus
    );
  };

  const handleOpenKatanaURLResultsModal = () => setShowKatanaURLResultsModal(true);
  const handleCloseKatanaURLResultsModal = () => setShowKatanaURLResultsModal(false);
  const handleOpenLinkFinderURLResultsModal = () => setShowLinkFinderURLResultsModal(true);
  const handleCloseLinkFinderURLResultsModal = () => setShowLinkFinderURLResultsModal(false);
  const handleOpenWaybackURLsResultsModal = () => setShowWaybackURLsResultsModal(true);
  const handleCloseWaybackURLsResultsModal = () => setShowWaybackURLsResultsModal(false);
  
  const handleOpenArjunConfigModal = () => setShowArjunConfigModal(true);
  const handleCloseArjunConfigModal = () => setShowArjunConfigModal(false);
  const handleOpenArjunResultsModal = () => setShowArjunResultsModal(true);
  const handleCloseArjunResultsModal = () => setShowArjunResultsModal(false);
  
  
  const handleOpenX8ConfigModal = () => setShowX8ConfigModal(true);
  const handleCloseX8ConfigModal = () => setShowX8ConfigModal(false);
  const handleOpenX8ResultsModal = () => setShowX8ResultsModal(true);
  const handleCloseX8ResultsModal = () => setShowX8ResultsModal(false);
  const handleOpenGAUURLResultsModal = () => setShowGAUURLResultsModal(true);
  const handleCloseGAUURLResultsModal = () => setShowGAUURLResultsModal(false);
  const handleOpenGoSpiderURLResultsModal = () => setShowGoSpiderURLResultsModal(true);
  const handleCloseGoSpiderURLResultsModal = () => setShowGoSpiderURLResultsModal(false);
  const handleOpenFFUFURLResultsModal = () => setShowFFUFURLResultsModal(true);
  const handleCloseFFUFURLResultsModal = () => setShowFFUFURLResultsModal(false);
  // Header/Cookie fuzzing modes for FFUF. Backend wiring for these modes is pending;
  // the Configure modal (Headers/Cookies tabs) and Results modal tabs are in place.
  const handleOpenWAFProbeResultsModal = () => setShowWAFProbeResultsModal(true);
  const handleCloseWAFProbeResultsModal = () => setShowWAFProbeResultsModal(false);
  const handleOpenManualCrawlResultsModal = async () => {
    setShowManualCrawlResultsModal(true);
    if (activeTarget) {
      checkManualCrawlConnection();
      loadManualCrawlMetrics();
    }
  };
  const handleCloseManualCrawlResultsModal = () => {
    setShowManualCrawlResultsModal(false);
    loadManualCrawlMetrics();
  };
  
  const handleOpenExtensionInstallModal = () => setShowExtensionInstallModal(true);
  const handleCloseExtensionInstallModal = () => setShowExtensionInstallModal(false);

  // Consolidate is asynchronous now, because folding tens of thousands of archive rows inside an
  // HTTP handler ties up the connection until the browser gives up.
  const handleConsolidateEndpoints = async () => {
    if (!activeTarget) return;

    setIsConsolidatingEndpoints(true);
    setEndpointWorkflowError('');
    try {
      const response = await fetch(`/api/consolidated-endpoints/${activeTarget.id}/consolidate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      if (!response.ok) throw new Error(await response.text() || 'Failed to start consolidation');

      const { scan_id: scanId } = await response.json();

      const poll = async () => {
        try {
          const statusResp = await fetch(
            `/api/consolidated-endpoints/${activeTarget.id}/status/${scanId}`);
          if (!statusResp.ok) throw new Error('Lost track of the consolidation run');
          const status = await statusResp.json();

          if (status.status === 'success') {
            setConsolidatedEndpointCount(status.endpoint_count || 0);
            setIsConsolidatingEndpoints(false);
            loadEndpointValidationSummary();
          } else if (status.status === 'error') {
            setEndpointWorkflowError(status.error || 'Consolidation failed');
            setIsConsolidatingEndpoints(false);
          } else {
            setTimeout(poll, 1500);
          }
        } catch (err) {
          setEndpointWorkflowError(err.message);
          setIsConsolidatingEndpoints(false);
        }
      };
      poll();
    } catch (err) {
      setEndpointWorkflowError(err.message);
      setIsConsolidatingEndpoints(false);
    }
  };

  // Investigate is both phases as one run: Validate, then Investigate whatever Validate did not
  // rule out.
  //
  // They were two buttons, and the ordering was left to the operator. Investigating first on a
  // target that answers 200 with its login page for every path produces several thousand copies of
  // one page presented as several thousand findings, and nothing on screen says so.
  const handleInvestigateEndpoints = async (acknowledge = false) => {
    if (!activeTarget) return;

    setIsEndpointScanRunning(true);
    setEndpointWorkflowError('');
    try {
      const response = await fetch(`/api/endpoint-scan/${activeTarget.id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ acknowledge })
      });

      if (response.status === 409) {
        // Either a competing scan, or the probe found the saved credentials are dead. Both are
        // worth surfacing verbatim; a generic failure hides the one thing the operator can act on.
        let reason = await response.text();
        try { reason = JSON.parse(reason).reason || reason; } catch (e) { /* plain text */ }
        setEndpointWorkflowError(reason);
        setIsEndpointScanRunning(false);
        return;
      }
      if (!response.ok) throw new Error(await response.text() || 'Failed to start the endpoint scan');

      const { run_id: runId } = await response.json();

      const poll = async () => {
        try {
          const statusResp = await fetch(`/api/endpoint-scan/${activeTarget.id}/status/${runId}`);
          if (!statusResp.ok) throw new Error('Lost track of the endpoint scan');
          const status = await statusResp.json();
          setEndpointScanRun(status);

          if (['success', 'partial', 'aborted', 'error'].includes(status.status)) {
            setIsEndpointScanRunning(false);
            if (status.status === 'error') {
              setEndpointWorkflowError(status.error || 'The endpoint scan failed');
            }
            loadEndpointValidationSummary();
            loadConsolidatedEndpointCount();
          } else {
            setTimeout(poll, 2000);
          }
        } catch (err) {
          setEndpointWorkflowError(err.message);
          setIsEndpointScanRunning(false);
        }
      };
      poll();
    } catch (err) {
      setEndpointWorkflowError(err.message);
      setIsEndpointScanRunning(false);
    }
  };

  const endpointValidationCounts = useMemo(
    () => endpointValidation?.counts || {}, [endpointValidation]);

  // A count of zero is a measurement. A dash means nothing has looked yet.
  //
  // The counts map only carries the verdicts that actually occurred, so `counts.unverified ?? '-'`
  // rendered a dash on a run where nothing was unverified, which reads as "not measured" when it
  // is in fact the best possible outcome.
  const verdictCount = useCallback((key) => (
    endpointValidation && endpointValidation.status !== 'not_run'
      ? (endpointValidationCounts[key] ?? 0)
      : '-'
  ), [endpointValidation, endpointValidationCounts]);

  // The label on the Investigate button while it runs. One button covering two phases has to say
  // which one is moving, or a run that spends twenty minutes in phase 1 looks hung.
  const endpointScanProgressLabel = useMemo(() => {
    if (!isEndpointScanRunning) return '';
    const phase = endpointScanRun?.phase;
    if (phase === 'validate') {
      const v = endpointScanRun?.validation;
      return v?.processed_endpoints
        ? `Validating ${v.processed_endpoints}/${v.total_endpoints}`
        : 'Validating...';
    }
    if (phase === 'investigate') {
      const i = endpointScanRun?.investigation;
      return i?.processed_endpoints
        ? `Investigating ${i.processed_endpoints}/${i.total_endpoints}`
        : 'Investigating...';
    }
    return 'Starting...';
  }, [isEndpointScanRunning, endpointScanRun]);

  const loadEndpointValidationSummary = useCallback(async () => {
    if (!activeTarget) return;
    try {
      const resp = await fetch(`/api/endpoint-validation/${activeTarget.id}/latest`);
      if (resp.ok) setEndpointValidation(await resp.json());
    } catch (err) {
      // A target that has never been validated is the normal case, not an error.
    }
  }, [activeTarget]);

  const loadEndpointScanRun = useCallback(async () => {
    if (!activeTarget) return;
    try {
      const resp = await fetch(`/api/endpoint-scan/${activeTarget.id}/latest`);
      if (resp.ok) {
        const run = await resp.json();
        setEndpointScanRun(run.status === 'not_run' ? null : run);
      }
    } catch (err) {
      // A target that has never been scanned is the normal case, not an error.
    }
  }, [activeTarget]);

  // Declared after loadEndpointValidationSummary and loadEndpointScanRun on purpose. A hook's
  // dependency array is evaluated while the component body runs, so referencing a callback above
  // its own const declaration throws a temporal dead zone error and nothing renders at all.
  useEffect(() => { loadEndpointValidationSummary(); }, [loadEndpointValidationSummary]);
  useEffect(() => { loadEndpointScanRun(); }, [loadEndpointScanRun]);

  const handleOpenManageEndpointsModal = async () => {
    setShowManageEndpointsModal(true);
    if (activeTarget) {
      loadConsolidatedEndpointCount();
    }
  };

  const handleCloseManageEndpointsModal = () => setShowManageEndpointsModal(false);

  const handleOpenEndpointScanResultsModal = () => setShowEndpointScanResultsModal(true);
  const handleCloseEndpointScanResultsModal = () => {
    setShowEndpointScanResultsModal(false);
    // An override applied from Manage Endpoints changes the verdicts behind these counts, so the
    // card is refreshed on close rather than left showing what was true when the modal opened.
    loadEndpointValidationSummary();
  };

  const loadConsolidatedEndpointCount = async () => {
    if (!activeTarget) return;
    
    try {
      const response = await fetch(`/api/consolidated-endpoints/${activeTarget.id}`);
      if (response.ok) {
        const data = await response.json();
        setConsolidatedEndpointCount(data.length || 0);
      }
    } catch (err) {
      console.error('Error loading consolidated endpoint count:', err);
    }
  };
  
  const handleOpenTargetUrl = () => {
    if (activeTarget && activeTarget.scope_target) {
      window.open(activeTarget.scope_target, '_blank');
    }
  };

  const loadManualCrawlMetrics = async () => {
    if (!activeTarget) {
      setManualCrawlSessionCount(0);
      setManualCrawlDirectCount(0);
      setManualCrawlAdjacentCount(0);
      setManualCrawlAdjacentHostCount(0);
      return;
    }
    
    try {
      const [sessionsResponse, endpointsResponse] = await Promise.all([
        fetch(`/api/manual-crawl/sessions/${activeTarget.id}`),
        fetch(`/api/manual-crawl/endpoints/${activeTarget.id}`)
      ]);
      
      if (sessionsResponse.ok) {
        const sessions = await sessionsResponse.json();
        setManualCrawlSessionCount(sessions?.length || 0);
      } else {
        setManualCrawlSessionCount(0);
      }
      
      if (endpointsResponse.ok) {
        const endpoints = await endpointsResponse.json();
        const list = Array.isArray(endpoints) ? endpoints : [];
        const adjacent = list.filter((e) => !e.is_direct);
        setManualCrawlDirectCount(list.filter((e) => e.is_direct).length);
        setManualCrawlAdjacentCount(adjacent.length);
        setManualCrawlAdjacentHostCount(
          new Set(adjacent.map((e) => e.host).filter(Boolean)).size
        );
      } else {
        setManualCrawlDirectCount(0);
        setManualCrawlAdjacentCount(0);
        setManualCrawlAdjacentHostCount(0);
      }
    } catch (err) {
      console.error('Error loading manual crawl metrics:', err);
      setManualCrawlSessionCount(0);
      setManualCrawlDirectCount(0);
      setManualCrawlAdjacentCount(0);
      setManualCrawlAdjacentHostCount(0);
    }
  };

  const checkManualCrawlConnection = async () => {
    if (!activeTarget) return;
    try {
      const response = await fetch(`/api/manual-crawl/sessions/${activeTarget.id}`);
      if (response.ok) {
        const sessions = await response.json();
        // `is_live` is heartbeat-derived, not just status='active'. A browser extension whose MV3
        // service worker was terminated leaves the row 'active' forever, which used to make this
        // card claim it was recording when nothing was being captured.
        const hasLive = Array.isArray(sessions) && sessions.some(s => s.is_live);

        // Recording just ended. Pull the counts immediately, then once more shortly after: the
        // extension flushes its remaining queue around the same moment it stops, so the last batch
        // can land a beat after the session is marked complete.
        if (manualCrawlWasLiveRef.current && !hasLive) {
          loadManualCrawlMetrics();
          clearTimeout(manualCrawlRefreshTimeoutRef.current);
          manualCrawlRefreshTimeoutRef.current = setTimeout(loadManualCrawlMetrics, 3000);
        }
        manualCrawlWasLiveRef.current = hasLive;

        setManualCrawlConnected(hasLive);
      } else {
        manualCrawlWasLiveRef.current = false;
        setManualCrawlConnected(false);
      }
    } catch (err) {
      console.error('Error checking manual crawl connection:', err);
      setManualCrawlConnected(false);
    }
  };

  useEffect(() => {
    manualCrawlWasLiveRef.current = false;

    if (activeTarget) {
      loadManualCrawlMetrics();
      if (activeTarget.type === 'URL') {
        checkManualCrawlConnection();
        // Poll the counts alongside liveness so the card tracks a recording as it happens, not
        // only after the target is switched.
        const interval = setInterval(() => {
          checkManualCrawlConnection();
          loadManualCrawlMetrics();
        }, 15000);
        return () => {
          clearInterval(interval);
          // Cancel the post-stop refresh: it closes over this render's target, so letting it fire
          // after a target switch would write the previous target's counts onto the new card.
          clearTimeout(manualCrawlRefreshTimeoutRef.current);
        };
      }
    } else {
      setManualCrawlDirectCount(0);
      setManualCrawlAdjacentCount(0);
      setManualCrawlAdjacentHostCount(0);
      setManualCrawlSessionCount(0);
    }
  }, [activeTarget]);
  const handleOpenApplicationQuestionsModal = () => setShowApplicationQuestionsModal(true);
  const handleCloseApplicationQuestionsModal = () => { setShowApplicationQuestionsModal(false); fetchThreatModelCounts(); };
  const handleOpenMechanismsModal = () => setShowMechanismsModal(true);
  const handleCloseMechanismsModal = () => { setShowMechanismsModal(false); fetchThreatModelCounts(); };
  const handleOpenNotableObjectsModal = () => setShowNotableObjectsModal(true);
  const handleCloseNotableObjectsModal = () => { setShowNotableObjectsModal(false); fetchThreatModelCounts(); };
  const handleOpenSecurityControlsModal = () => setShowSecurityControlsModal(true);
  const handleCloseSecurityControlsModal = () => { setShowSecurityControlsModal(false); fetchThreatModelCounts(); };
  const handleOpenThreatModelModal = async () => {
    setShowThreatModelModal(true);
    if (activeTarget) {
      try {
        const mechanismsResponse = await fetch(
          `/api/mechanisms/${activeTarget.id}/examples`
        );
        if (mechanismsResponse.ok) {
          const mechanismsData = await mechanismsResponse.json();
          const uniqueMechanisms = [...new Set(mechanismsData.map(m => m.mechanism))];
          setMechanismsForThreatModel(uniqueMechanisms);
        }
      } catch (error) {
        console.error('Error fetching mechanisms:', error);
      }
      
      try {
        const objectsResponse = await fetch(
          `/api/notable-objects/${activeTarget.id}`
        );
        if (objectsResponse.ok) {
          const objectsData = await objectsResponse.json();
          const objectNames = objectsData.map(o => o.object_name);
          setNotableObjectsForThreatModel(objectNames);
        }
      } catch (error) {
        console.error('Error fetching notable objects:', error);
      }

      try {
        const controlsResponse = await fetch(
          `/api/security-controls/${activeTarget.id}/notes`
        );
        if (controlsResponse.ok) {
          const controlsData = await controlsResponse.json();
          const uniqueControls = [...new Set(controlsData.map(c => c.control_name))];
          setSecurityControlsForThreatModel(uniqueControls);
        }
      } catch (error) {
        console.error('Error fetching security controls:', error);
      }
    }
  };
  // Re-read on close so a threat added or deleted in the modal is reflected in the results section
  // below it without a page reload.
  const handleCloseThreatModelModal = () => {
    setShowThreatModelModal(false);
    fetchThreatModelResults();
  };
  const handleOpenPossibleAttacksModal = (category) => {
    setPossibleAttacksCategory(category && category.key ? category.key : category);
    setShowPossibleAttacksModal(true);
  };
  const handleClosePossibleAttacksModal = () => setShowPossibleAttacksModal(false);
  // Attack Vectors: one request carrying user-controlled input, identified by verb, host, path, the
  // parameter in play and where the payload goes.
  const [attackVectorCounts, setAttackVectorCounts] = useState({});
  // Per-insertion-point counts and the named gaps. Every scan below is bounded by this: a point with
  // no vectors will be reported clean by every tool in every section, for the sole reason that
  // nothing was ever sent there.
  const [attackVectorCoverage, setAttackVectorCoverage] = useState(null);
  const [isConsolidatingAttackVectors, setIsConsolidatingAttackVectors] = useState(false);
  const [showAddAttackVectorModal, setShowAddAttackVectorModal] = useState(false);
  const [showAttackVectorsModal, setShowAttackVectorsModal] = useState(false);

  // XSS. One status object per tool, keyed by tool key, holding both the eligibility figures (which
  // exist before any scan has run, so the card can say 27/71 up front) and the latest run.
  const [vectorToolStatus, setVectorToolStatus] = useState({});
  const [vectorTool, setVectorTool] = useState(null);
  const [showVectorConfigModal, setShowVectorConfigModal] = useState(false);
  const [showVectorResultsModal, setShowVectorResultsModal] = useState(false);
  const [webhookSection, setWebhookSection] = useState(null);

  const loadAttackVectorCounts = useCallback(async () => {
    if (!activeTarget) return;
    try {
      const res = await fetch(`/api/attack-vectors/${activeTarget.id}/summary`);
      if (res.ok) setAttackVectorCounts(await res.json());
      // Coverage is fetched alongside the totals because a total on its own is misleading: 54
      // vectors reads as thorough right up until you notice that none of them is a header.
      const cov = await fetch(`/api/attack-vectors/${activeTarget.id}/coverage`);
      if (cov.ok) setAttackVectorCoverage(await cov.json());
    } catch {
      // A target that has never been consolidated has no summary, which the card shows as dashes.
    }
  }, [activeTarget]);

  useEffect(() => { loadAttackVectorCounts(); }, [loadAttackVectorCounts]);

  const handleConsolidateAttackVectors = async () => {
    if (!activeTarget) return;
    setIsConsolidatingAttackVectors(true);
    try {
      const res = await fetch(`/api/attack-vectors/${activeTarget.id}/consolidate`, { method: 'POST' });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        notify('Consolidation failed', data.message || 'Attack vectors could not be consolidated.',
          'warning');
        return;
      }
      await loadAttackVectorCounts();
      notify('Attack vectors consolidated', data.summary
        || `${data.total ?? 0} unique vectors across ${data.hosts ?? 0} host(s).`);
    } catch (err) {
      notify('Consolidation failed', err.message, 'warning');
    } finally {
      setIsConsolidatingAttackVectors(false);
    }
  };

  // Declared ABOVE everything that names it. A const arrow referenced from a dependency array before
  // its own declaration is a ReferenceError on every render, which compiles clean and white-screens
  // the whole workflow; this file has been broken that way once already.
  const loadVectorToolStatus = useCallback(async (toolKey) => {
    const category = VECTOR_TOOL_CATEGORY.get(toolKey);
    if (!activeTarget || !category) return;
    try {
      const res = await fetch(`/api/${category}/${activeTarget.id}/${toolKey}/status`);
      if (!res.ok) return;
      const data = await res.json();
      setVectorToolStatus((prev) => ({ ...prev, [toolKey]: data }));
    } catch {
      // A status poll that fails leaves the last known numbers on the card, which is better than
      // blanking them: the scan is still running, we just did not hear back this time.
    }
  }, [activeTarget]);

  // Whether to poll at all, derived so the effect below is KEYED on it. Reading this inside the
  // effect instead would mean the effect never re-runs when a scan starts, the interval is never
  // created, and the card sits at 0 of 63 until the operator reopens the page.
  const anyVectorToolRunning = useMemo(
    () => Object.values(vectorToolStatus).some((s) => s?.scan?.status === 'running'),
    [vectorToolStatus],
  );

  // Once on arrival, so the cards carry their eligibility figures before the operator presses
  // anything: 27 of 71 is the fact that makes the Scan button honest.
  useEffect(() => {
    if (!activeTarget) return;
    VECTOR_TOOL_CATEGORY.forEach((_category, key) => loadVectorToolStatus(key));
  }, [activeTarget, loadVectorToolStatus]);

  useEffect(() => {
    if (!activeTarget || !anyVectorToolRunning) return undefined;
    const timer = setInterval(() => {
      VECTOR_TOOL_CATEGORY.forEach((_category, key) => loadVectorToolStatus(key));
    }, 3000);
    return () => clearInterval(timer);
  }, [activeTarget, anyVectorToolRunning, loadVectorToolStatus]);

  // The tools that are actually built. Everything else still says so rather than opening an empty
  // modal, because a Config screen with no settings in it is harder to read than a message.
  const startVectorToolScan = async (tool) => {
    const category = VECTOR_TOOL_CATEGORY.get(tool.key);
    if (!activeTarget || !category) return;
    try {
      const res = await fetch(`/api/${category}/${activeTarget.id}/${tool.key}/scan`, { method: 'POST' });
      const data = await res.json();
      if (!res.ok) {
        notify(`${tool.name} scan failed`, data.message || 'The scan could not be started.', 'warning');
        return;
      }
      await loadVectorToolStatus(tool.key);
    } catch (err) {
      notify(`${tool.name} scan failed`, err.message, 'warning');
    }
  };

  const handleAttackToolAction = (action, tool) => {
    if (VECTOR_TOOL_CATEGORY.has(tool.key)) {
      if (action === 'Config') { setVectorTool(tool); setShowVectorConfigModal(true); return; }
      if (action === 'Results') { setVectorTool(tool); setShowVectorResultsModal(true); return; }
      startVectorToolScan(tool);
      return;
    }
    notify(`${tool.name}: ${action} not wired up yet`,
      `The card is in place; ${action.toLowerCase()} for ${tool.name} is not built yet.`, 'warning');
  };

  const handleAddAttackVectorManually = () => setShowAddAttackVectorModal(true);
  const handleOpenUniqueAttackVectorsModal = () => setShowAttackVectorsModal(true);
  const handleOpenAuthFlowModal = (categoryKey) => {
    setAuthFlowCategory(categoryKey);
    setShowAuthFlowModal(true);
  };
  const handleCloseAuthFlowModal = () => setShowAuthFlowModal(false);

  // The four Authentication buttons. Each close refreshes the counts on the card, because every one
  // of these modals can change them and a stale card is how an operator concludes nothing happened.
  const handleOpenRecordAuthFlowsModal = () => setShowRecordAuthFlowsModal(true);
  const handleCloseRecordAuthFlowsModal = () => {
    setShowRecordAuthFlowsModal(false); fetchAuthFlowCounts(); fetchSessionTokenCounts();
  };
  const handleOpenManualAuthFlowModal = () => setShowManualAuthFlowModal(true);
  const handleCloseManualAuthFlowModal = () => {
    setShowManualAuthFlowModal(false); fetchAuthFlowCounts();
  };
  const handleOpenManageSessionsModal = () => setShowManageSessionsModal(true);
  const handleCloseManageSessionsModal = () => {
    setShowManageSessionsModal(false); fetchSessionTokenCounts();
  };
  const handleOpenRefreshSessionModal = () => setShowRefreshSessionModal(true);
  const handleCloseRefreshSessionModal = () => {
    setShowRefreshSessionModal(false); fetchSessionTokenCounts();
  };
  const handleOpenClientIdentityModal = () => setShowClientIdentityModal(true);
  const handleCloseClientIdentityModal = () => { setShowClientIdentityModal(false); fetchAuthzCounts(); };
  // Possible IDOR Targets = saved client identifiers; Possible ACV Targets is a placeholder until the
  // access-control (Policy/Role/Discretionary) work lands.
  const fetchAuthzCounts = async (targetId) => {
    const id = targetId || (activeTarget && activeTarget.id);
    if (!id) { setAuthzCounts({ patterns: 0, parameter: 0, rules: 0, forbidden: 0 }); return; }
    try {
      const res = await fetch(`/api/authz/summary/${id}`);
      if (!res.ok) return;
      const d = await res.json();
      const ip = d.identity_patterns || {};
      const pol = d.policy || {};
      const rbac = d.rbac || {};
      const dac = d.dac || {};
      setAuthzCounts({
        patterns: ip.total || 0,
        parameter: ip.parameter || 0,
        // One number for "rules modelled" across the three access-control schemes, because the
        // card has room for one and the operator cares whether the model exists at all, not
        // whether it happens to live in the policy tab or the role tab.
        rules: (pol.permissions || 0) + (rbac.roles || 0) * (rbac.actions || 0) + (dac.levels || 0),
        forbidden: rbac.forbidden_cells || 0,
      });
    } catch (error) { console.error('Error fetching authorization counts:', error); }
  };
  // Each close refreshes the card, because every one of these modals changes the counts on it.
  const handleOpenPolicyAccessModal = () => setShowPolicyAccessModal(true);
  const handleClosePolicyAccessModal = () => { setShowPolicyAccessModal(false); fetchAuthzCounts(); };
  const handleOpenRoleAccessModal = () => setShowRoleAccessModal(true);
  const handleCloseRoleAccessModal = () => { setShowRoleAccessModal(false); fetchAuthzCounts(); };
  const handleOpenDiscretionaryAccessModal = () => setShowDiscretionaryAccessModal(true);
  const handleCloseDiscretionaryAccessModal = () => {
    setShowDiscretionaryAccessModal(false); fetchAuthzCounts();
  };
  const handleHeaderCookieAction = (action) => {
    // Placeholder — Header/Cookie Enumeration (fuzzing, investigate, results) will be built here soon.
    console.log('[Header/Cookie Enumeration] action:', action);
  };
  // Per-category count of documented auth flows for the active target, shown on the Authentication card.
  const fetchAuthFlowCounts = async (targetId) => {
    const id = targetId || (activeTarget && activeTarget.id);
    if (!id) {
      setAuthFlowCounts({ register: 0, login: 0, mfa_otp: 0, magic_link: 0, reset: 0, total: 0, recorded: 0 });
      return;
    }
    try {
      const res = await fetch(`/api/auth-flows/${id}`);
      if (res.ok) {
        const data = await res.json();
        const counts = { register: 0, login: 0, mfa_otp: 0, magic_link: 0, reset: 0, total: 0, recorded: 0 };
        if (Array.isArray(data)) {
          data.forEach((f) => {
            if (counts[f.category] !== undefined) counts[f.category] += 1;
            counts.total += 1;
            // Where the flow came from decides whether it can be trusted to replay: a recorded
            // flow is what the browser really did, a manual one is what somebody typed.
            if (f.source === 'recorded') counts.recorded += 1;
          });
        }
        setAuthFlowCounts(counts);
      }
    } catch (error) { console.error('Error fetching auth flow counts:', error); }
  };

  const fetchSessionTokenCounts = async (targetId) => {
    const id = targetId || (activeTarget && activeTarget.id);
    if (!id) { setSessionTokenCounts({ total: 0, active: 0 }); return; }
    try {
      const res = await fetch(`/api/session-tokens/target/${id}`);
      if (res.ok) {
        const data = await res.json();
        const list = Array.isArray(data) ? data : (data?.tokens || []);
        setSessionTokenCounts({ total: list.length, active: list.filter((t) => t.is_active).length });
      }
    } catch (error) { console.error('Error fetching session token counts:', error); }
  };
  // Count how many threat-model items have actually been filled out for the active target, so the
  // STRIDE card can surface real progress instead of a static legend.
  const fetchThreatModelCounts = async (targetId) => {
    const id = targetId || (activeTarget && activeTarget.id);
    if (!id) {
      setThreatModelCounts({ questions: 0, mechanisms: 0, notableObjects: 0, securityControls: 0 });
      return;
    }
    const counts = { questions: 0, mechanisms: 0, notableObjects: 0, securityControls: 0 };
    try {
      const res = await fetch(`/api/application-questions/${id}/answers`);
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data)) counts.questions = new Set(data.map((a) => a.question)).size;
      }
    } catch (error) { console.error('Error fetching application questions count:', error); }
    try {
      const res = await fetch(`/api/mechanisms/${id}/examples`);
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data)) counts.mechanisms = new Set(data.map((m) => m.mechanism)).size;
      }
    } catch (error) { console.error('Error fetching mechanisms count:', error); }
    try {
      const res = await fetch(`/api/notable-objects/${id}`);
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data)) counts.notableObjects = data.length;
      }
    } catch (error) { console.error('Error fetching notable objects count:', error); }
    try {
      const res = await fetch(`/api/security-controls/${id}/notes`);
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data)) counts.securityControls = new Set(data.map((c) => c.control_name)).size;
      }
    } catch (error) { console.error('Error fetching security controls count:', error); }
    setThreatModelCounts(counts);
  };
  // steps and security_controls are stored as JSON TEXT and come back from the API as strings, so
  // they are parsed once here rather than in the render. A row whose JSON is malformed keeps the
  // rest of the threat: losing a whole finding because one column will not parse is worse than
  // showing it with an empty step list.
  const parseThreatJSON = (value, fallback) => {
    if (!value) return fallback;
    if (Array.isArray(value)) return value;
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed : fallback;
    } catch (error) {
      console.error('Error parsing threat model JSON column:', error);
      return fallback;
    }
  };
  // threatModelResults is keyed by STRIDE category, so the total is the sum of the six buckets.
  const threatModelResultCount = Object.values(threatModelResults || {})
    .reduce((total, list) => total + (Array.isArray(list) ? list.length : 0), 0);
  // Refreshed on target change and after a Configure save, because changing the selection is the
  // one action that moves this number.
  const fetchArchiveHostCounts = async (targetId) => {
    const id = targetId || (activeTarget && activeTarget.id);
    if (!id) {
      setArchiveHostCounts({ waybackurls: null, gau: null });
      return;
    }
    const next = {};
    await Promise.all(['waybackurls', 'gau'].map(async (tool) => {
      try {
        const res = await fetch(`/api/archive-hosts/${tool}/${id}`);
        if (!res.ok) { next[tool] = null; return; }
        const data = await res.json();
        next[tool] = { selected: data.selected_count ?? 0, total: data.total ?? 0 };
      } catch (error) {
        // A target with no host list yet is normal, not an error worth surfacing on a card.
        next[tool] = null;
      }
    }));
    setArchiveHostCounts(next);

    try {
      const res = await fetch(`/api/linkfinder-js-files/${id}`);
      setLinkFinderJS(res.ok ? await res.json() : null);
    } catch (error) {
      setLinkFinderJS(null);
    }
  };

  const fetchThreatModelResults = async (targetId) => {
    const id = targetId || (activeTarget && activeTarget.id);
    if (!id) {
      setThreatModelResults({});
      return;
    }
    try {
      const res = await fetch(`/api/threat-model/${id}`);
      if (!res.ok) throw new Error(`threat model request failed: ${res.status}`);
      const data = await res.json();
      const grouped = {};
      if (Array.isArray(data)) {
        data.forEach((threat) => {
          const key = threat.category;
          if (!key) return;
          if (!grouped[key]) grouped[key] = [];
          grouped[key].push({
            ...threat,
            steps: parseThreatJSON(threat.steps, []),
            security_controls: parseThreatJSON(threat.security_controls, []),
          });
        });
      }
      setThreatModelResults(grouped);
    } catch (error) {
      console.error('Error fetching threat model results:', error);
      setThreatModelResults({});
    }
  };
  // Flips one threat between untested, validated and rejected. This goes to its own route rather than
  // the normal PUT, because that one replaces every column and demands category and url: marking a
  // threat tested is a one-field change and should not risk rewriting prose the click never read.
  const handleSetThreatTestStatus = async (threatId, testStatus) => {
    if (!threatId) return;
    try {
      const res = await fetch(`/api/threat-model/${threatId}/test-status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ test_status: testStatus }),
      });
      if (!res.ok) throw new Error(`set test status failed: ${res.status}`);
      // Patch the one row in place instead of refetching the whole model. The accordion is
      // uncontrolled, so a refetch here would collapse every open item the operator was reading.
      setThreatModelResults((prev) => {
        const next = {};
        Object.keys(prev).forEach((key) => {
          next[key] = prev[key].map((t) => (
            t.id === threatId ? { ...t, test_status: testStatus } : t
          ));
        });
        return next;
      });
    } catch (error) {
      console.error('Error setting threat test status:', error);
    }
  };

  useEffect(() => {
    fetchThreatModelCounts();
    fetchThreatModelResults();
    fetchArchiveHostCounts();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTarget]);
  useEffect(() => {
    setHeaderCookieCounts({ hidden_headers: 0, hidden_cookies: 0, client_side: 0, server_side: 0 });
    fetchAuthzCounts();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTarget]);
  useEffect(() => {
    fetchAuthFlowCounts();
    fetchSessionTokenCounts();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTarget]);
  const handleOpenFFUFConfigModal = () => setShowFFUFConfigModal(true);
  const handleCloseFFUFConfigModal = () => setShowFFUFConfigModal(false);
  const handleOpenFFUFSettingsModal = () => setShowFFUFSettingsModal(true);
  const handleCloseFFUFSettingsModal = () => setShowFFUFSettingsModal(false);

  useEffect(() => {
    if (activeTarget) {
      monitorGitHubReconScanStatus(
        activeTarget,
        setGitHubReconScans,
        setMostRecentGitHubReconScan,
        setIsGitHubReconScanning,
        setMostRecentGitHubReconScanStatus
      );
    }
  }, [activeTarget]);

  useEffect(() => {
    if (activeTarget) {
      monitorShodanCompanyScanStatus(
        activeTarget,
        setShodanCompanyScans,
        setMostRecentShodanCompanyScan,
        setIsShodanCompanyScanning,
        setMostRecentShodanCompanyScanStatus
      );
    }
  }, [activeTarget]);

  useEffect(() => {
    if (activeTarget) {
      monitorKatanaCompanyScanStatus(
        activeTarget,
        setKatanaCompanyScans,
        setMostRecentKatanaCompanyScan,
        setIsKatanaCompanyScanning,
        setMostRecentKatanaCompanyScanStatus,
        setKatanaCompanyCloudAssets
      );
    }
  }, [activeTarget]);

  const handleDomainsDeleted = async () => {
    if (activeTarget) {
      try {
        // Refresh individual tool scan data to update domain counts on cards
        
        // Refresh Google Dorking domains
        await fetchGoogleDorkingDomains();
        
        // Refresh Reverse Whois domains  
        await fetchReverseWhoisDomains();
        
        // Refresh CTL Company scans
        monitorCTLCompanyScanStatus(
          activeTarget,
          setCTLCompanyScans,
          setMostRecentCTLCompanyScan,
          setIsCTLCompanyScanning,
          setMostRecentCTLCompanyScanStatus
        );
        
        // Refresh SecurityTrails Company scans
        monitorSecurityTrailsCompanyScanStatus(
          activeTarget,
          setSecurityTrailsCompanyScans,
          setMostRecentSecurityTrailsCompanyScan,
          setIsSecurityTrailsCompanyScanning,
          setMostRecentSecurityTrailsCompanyScanStatus
        );
        
        // Refresh Censys Company scans
        monitorCensysCompanyScanStatus(
          activeTarget,
          setCensysCompanyScans,
          setMostRecentCensysCompanyScan,
          setIsCensysCompanyScanning,
          setMostRecentCensysCompanyScanStatus
        );
        
        // Refresh GitHub Recon scans
        monitorGitHubReconScanStatus(
          activeTarget,
          setGitHubReconScans,
          setMostRecentGitHubReconScan,
          setIsGitHubReconScanning,
          setMostRecentGitHubReconScanStatus
        );
        
        // Refresh Shodan Company scans
        monitorShodanCompanyScanStatus(
          activeTarget,
          setShodanCompanyScans,
          setMostRecentShodanCompanyScan,
          setIsShodanCompanyScanning,
          setMostRecentShodanCompanyScanStatus
        );
        
        // Refresh DNSx Company scans
        const fetchDNSxCompanyScansRefresh = async () => {
          try {
            const response = await fetch(
              `/api/scopetarget/${activeTarget.id}/scans/dnsx-company`
            );
            if (!response.ok) {
              throw new Error('Failed to fetch DNSx Company scans');
            }
            const scans = await response.json();
            if (Array.isArray(scans)) {
              setDnsxCompanyScans(scans);
              if (scans.length > 0) {
                const mostRecentScan = scans[0];
                setMostRecentDNSxCompanyScan(mostRecentScan);
                setMostRecentDNSxCompanyScanStatus(mostRecentScan.status);
              }
            }
          } catch (error) {
            console.error('[DNSX-COMPANY] Error refreshing scans:', error);
          }
        };
        fetchDNSxCompanyScansRefresh();
        
        // Refresh Katana Company scans
        const fetchKatanaCompanyScansRefresh = async () => {
          try {
            const response = await fetch(
              `/api/scopetarget/${activeTarget.id}/scans/katana-company`
            );
            if (!response.ok) {
              throw new Error('Failed to fetch Katana Company scans');
            }
            const scans = await response.json();
            if (Array.isArray(scans)) {
              setKatanaCompanyScans(scans);
              if (scans.length > 0) {
                const mostRecentScan = scans[0];
                setMostRecentKatanaCompanyScan(mostRecentScan);
                setMostRecentKatanaCompanyScanStatus(mostRecentScan.status);
                
                // Fetch accumulated cloud assets for the card count
                try {
                  const assetsResponse = await fetch(
                    `/api/katana-company/target/${activeTarget.id}/cloud-assets`
                  );
                  if (assetsResponse.ok) {
                    const assets = await assetsResponse.json();
                    setKatanaCompanyCloudAssets(assets || []);
                  } else {
                    setKatanaCompanyCloudAssets([]);
                  }
                } catch (error) {
                  console.error('[KATANA-COMPANY] Error fetching cloud assets:', error);
                  setKatanaCompanyCloudAssets([]);
                }
              } else {
                setKatanaCompanyCloudAssets([]);
              }
            }
          } catch (error) {
            console.error('[KATANA-COMPANY] Error refreshing scans:', error);
          }
        };
        fetchKatanaCompanyScansRefresh();
        
      } catch (error) {
        console.error('Error refreshing individual tool scan data after deletion:', error);
      }
    }
  };

  const handleCloseDNSxConfigModal = () => setShowDNSxConfigModal(false);
  const handleOpenDNSxConfigModal = () => setShowDNSxConfigModal(true);

  const handleDNSxConfigSave = async (config) => {
    if (config && config.domains) {
      setDnsxSelectedDomainsCount(config.domains.length);
    }
    // Reload the complete config to recalculate wildcard domains count
    await loadDNSxConfig();
  };

  const loadDNSxConfig = async () => {
    if (!activeTarget?.id) return;

    try {
      const response = await fetch(
        `/api/dnsx-config/${activeTarget.id}`
      );
      
      if (response.ok) {
        const config = await response.json();
        if (config.domains && Array.isArray(config.domains)) {
          setDnsxSelectedDomainsCount(config.domains.length);
        } else {
          setDnsxSelectedDomainsCount(0);
        }
        
        // Always calculate wildcard domains count from discovered domains
        if (config.wildcard_domains && Array.isArray(config.wildcard_domains) && config.wildcard_domains.length > 0) {
          try {
            // Fetch all scope targets to find wildcard targets
            const scopeTargetsResponse = await fetch(
              `/api/scopetarget/read`
            );
            
            if (scopeTargetsResponse.ok) {
              const scopeTargetsData = await scopeTargetsResponse.json();
              const targets = Array.isArray(scopeTargetsData) ? scopeTargetsData : scopeTargetsData.targets;
              
              if (targets && Array.isArray(targets)) {
                let totalDiscoveredDomains = 0;
                
                // Find wildcard targets that match our saved wildcard domains
                const wildcardTargets = targets.filter(target => {
                  if (!target || target.type !== 'Wildcard') return false;
                  
                  const rootDomainFromWildcard = target.scope_target.startsWith('*.') 
                    ? target.scope_target.substring(2) 
                    : target.scope_target;
                  
                  return config.wildcard_domains.includes(rootDomainFromWildcard);
                });
                
                // Count discovered domains from each wildcard target
                for (const wildcardTarget of wildcardTargets) {
                  try {
                    const liveWebServersResponse = await fetch(
                      `/api/api/scope-targets/${wildcardTarget.id}/target-urls`
                    );
                    
                    if (liveWebServersResponse.ok) {
                      const liveWebServersData = await liveWebServersResponse.json();
                      const targetUrls = Array.isArray(liveWebServersData) ? liveWebServersData : liveWebServersData.target_urls;
                      
                      if (targetUrls && Array.isArray(targetUrls)) {
                        const discoveredDomains = Array.from(new Set(
                          targetUrls
                            .map(url => {
                              try {
                                if (!url || !url.url) return null;
                                const urlObj = new URL(url.url);
                                return urlObj.hostname;
                              } catch {
                                return null;
                              }
                            })
                            .filter(domain => domain && domain !== wildcardTarget.scope_target)
                        ));
                        
                        totalDiscoveredDomains += discoveredDomains.length;
                      }
                    }
                  } catch (error) {
                    console.error(`Error fetching wildcard domains for ${wildcardTarget.scope_target}:`, error);
                  }
                }
                
                setDnsxWildcardDomainsCount(totalDiscoveredDomains);
              } else {
                setDnsxWildcardDomainsCount(0);
              }
            } else {
              setDnsxWildcardDomainsCount(0);
            }
          } catch (error) {
            console.error('Error calculating wildcard domains count:', error);
            setDnsxWildcardDomainsCount(0);
          }
        } else {
          setDnsxWildcardDomainsCount(0);
        }
      } else {
        setDnsxSelectedDomainsCount(0);
        setDnsxWildcardDomainsCount(0);
      }
    } catch (error) {
      console.error('Error loading DNSx config:', error);
      setDnsxSelectedDomainsCount(0);
      setDnsxWildcardDomainsCount(0);
    }
  };

  // Add DNSx Company handlers
  const handleCloseDNSxCompanyResultsModal = () => setShowDNSxCompanyResultsModal(false);
  const handleOpenDNSxCompanyResultsModal = () => setShowDNSxCompanyResultsModal(true);
  
  const handleCloseDNSxCompanyHistoryModal = () => setShowDNSxCompanyHistoryModal(false);
  const handleOpenDNSxCompanyHistoryModal = () => setShowDNSxCompanyHistoryModal(true);

  const startDNSxCompanyScan = async () => {
    if (!activeTarget) {
      console.error('No active target selected');
      return;
    }

    try {
      const response = await fetch(
        `/api/dnsx-config/${activeTarget.id}`
      );
      
      if (!response.ok) {
        console.error('No DNSx configuration found');
        setToastTitle('Configuration Required');
        setToastMessage('Please configure domains in the DNSx configuration before starting the scan.');
        setShowToast(true);
        setTimeout(() => setShowToast(false), 5000);
        return;
      }

      const config = await response.json();
      
      if (!config.domains || config.domains.length === 0) {
        console.error('No domains configured for DNSx scan');
        setToastTitle('Configuration Required');
        setToastMessage('Please select domains in the DNSx configuration before starting the scan.');
        setShowToast(true);
        setTimeout(() => setShowToast(false), 5000);
        return;
      }

      await initiateDNSxCompanyScan(
        activeTarget,
        config.domains,
        setIsDNSxCompanyScanning,
        setDnsxCompanyScans,
        setMostRecentDNSxCompanyScan,
        setMostRecentDNSxCompanyScanStatus,
        setDnsxCompanyDnsRecords
      );
    } catch (error) {
      console.error('Error starting DNSx Company scan:', error);
      setToastTitle('Error');
      setToastMessage('Failed to start DNSx scan. Please try again.');
      setShowToast(true);
      setTimeout(() => setShowToast(false), 5000);
    }
  };

  const handleTrimNetworkRanges = () => {
    handleOpenTrimNetworkRangesModal();
  };

  const startAmassEnumCompanyScan = async () => {
    if (!activeTarget) {
      console.error('No active target selected');
      return;
    }

    try {
      const response = await fetch(
        `/api/amass-enum-config/${activeTarget.id}`
      );
      
      if (!response.ok) {
        console.error('No Amass Enum configuration found');
        setToastTitle('Configuration Required');
        setToastMessage('Please configure domains in the Amass Enum configuration before starting the scan.');
        setShowToast(true);
        setTimeout(() => setShowToast(false), 5000);
        return;
      }

      const config = await response.json();
      
      if (!config.domains || config.domains.length === 0) {
        console.error('No domains configured for Amass Enum scan');
        setToastTitle('Configuration Required');
        setToastMessage('Please select domains in the Amass Enum configuration before starting the scan.');
        setShowToast(true);
        setTimeout(() => setShowToast(false), 5000);
        return;
      }

      await initiateAmassEnumCompanyScan(
        activeTarget,
        config.domains,
        setIsAmassEnumCompanyScanning,
        setAmassEnumCompanyScans,
        setMostRecentAmassEnumCompanyScan,
        setMostRecentAmassEnumCompanyScanStatus,
        setAmassEnumCompanyCloudDomains
      );
    } catch (error) {
      console.error('Error starting Amass Enum Company scan:', error);
      setToastTitle('Error');
      setToastMessage('Failed to start Amass Enum scan. Please try again.');
      setShowToast(true);
      setTimeout(() => setShowToast(false), 5000);
    }
  };

  // G1.8: three identical duplicate Amass-Enum-Company scan effects were removed here (they
  // were exact copies of the canonical "Amass Enum Company scans useEffect" above and fired the
  // same ~3 network calls each on every target switch). The canonical one remains.

  return (
    <Container data-bs-theme="dark" className="App" style={{ padding: '20px' }}>
      <style>
        {`
          .modal-90w {
            max-width: 95% !important;
            width: 95% !important;
          }
        `}
      </style>
      <Ars0nFrameworkHeader 
        onSettingsClick={handleOpenSettingsModal} 
        onToolsClick={handleOpenToolsModal}
        onExportClick={handleOpenExportModal}
        onImportClick={handleOpenImportModal}
        onGlobalScansClick={() => setShowGlobalScansModal(true)}
        onNotesClick={() => setShowNotesModal(true)}
        isGlobalScanRunning={isWildfireRunning || isSlowburnRunning}
      />

      <ToastContainer 
        position="bottom-center"
        style={{ 
          position: 'fixed', 
          bottom: 20,
          left: '50%',
          transform: 'translateX(-50%)',
          zIndex: 1000,
          minWidth: '300px'
        }}
      >
        <Toast 
          show={showToast} 
          onClose={() => setShowToast(false)}
          className={`custom-toast ${!showToast ? 'hide' : ''}`}
          autohide
          delay={toastVariant === 'warning' ? 12000 : 3000}
        >
          <Toast.Header>
            {toastVariant === 'warning' ? (
              <MdWarning className="me-2" size={20} color="#ff0000" />
            ) : (
              <MdCheckCircle
                className="success-icon me-2"
                size={20}
                color="#ff0000"
              />
            )}
            <strong className="me-auto" style={{ 
              color: '#ff0000',
              fontSize: '0.95rem',
              letterSpacing: '0.5px'
            }}>
              {toastTitle}
            </strong>
          </Toast.Header>
          <Toast.Body style={{ color: '#ffffff' }}>
            <div className="d-flex align-items-center">
              {/* pre-wrap because a warning may name several steps, one per line. */}
              <span style={{ whiteSpace: 'pre-wrap' }}>{toastMessage}</span>
            </div>
          </Toast.Body>
        </Toast>
      </ToastContainer>

      <AddScopeTargetModal
        show={showModal}
        handleClose={handleClose}
        selections={selections}
        handleSelect={handleSelect}
        handleFormSubmit={handleSubmit}
        errorMessage={errorMessage}
        showBackButton={true}
        onBackClick={handleBackToWelcome}
      />

      <SelectActiveScopeTargetModal
        showActiveModal={showActiveModal}
        handleActiveModalClose={handleActiveModalClose}
        scopeTargets={scopeTargets}
        activeTarget={activeTarget}
        handleActiveSelect={handleActiveSelect}
        handleDelete={handleDelete}
      />

      <GlobalScansModal
        show={showGlobalScansModal}
        handleClose={() => setShowGlobalScansModal(false)}
        scopeTargets={scopeTargets}
        isWildfireRunning={isWildfireRunning}
        wildfireProgress={wildfireProgress}
        onStartWildfire={startWildfire}
        onCancelWildfire={cancelWildfire}
        isSlowburnRunning={isSlowburnRunning}
        slowburnProgress={slowburnProgress}
        onStartSlowburn={startSlowburn}
        onCancelSlowburn={cancelSlowburn}
        setShowToast={setShowToast}
        autoScanCurrentStep={autoScanCurrentStep}
        consolidatedCount={consolidatedCount}
        mostRecentHttpxScan={mostRecentHttpxScan}
      />

      <SettingsModal
        show={showSettingsModal}
        handleClose={handleCloseSettingsModal}
        initialTab={settingsModalInitialTab}
        onApiKeyDeleted={handleApiKeyDeleted}
      />

      <ToolsModal
        show={showToolsModal}
        handleClose={handleCloseToolsModal}
        initialTab={toolsModalInitialTab}
        initialUrls={toolsModalInitialUrls}
      />

      <Suspense fallback={<div />}>
        <ExportModal
          show={showExportModal}
          handleClose={handleCloseExportModal}
        />
      </Suspense>

      <Suspense fallback={<div />}>
        <ImportModal
          show={showImportModal}
          handleClose={handleCloseImportModal}
          onSuccess={handleImportSuccess}
          showBackButton={scopeTargets.length === 0}
          onBackClick={handleBackToWelcome}
        />
      </Suspense>

      <Suspense fallback={<div />}>
        <LaunchPadModal
          show={showLaunchPadModal}
          handleClose={handleCloseLaunchPadModal}
        />
      </Suspense>

      <Suspense fallback={<div />}>
        <WelcomeModal
          show={showWelcomeModal}
          handleClose={handleCloseWelcomeModal}
          onAddScopeTarget={handleWelcomeAddScopeTarget}
          onImportData={handleWelcomeImportData}
          onUploadConfig={handleWelcomeUploadConfig}
          onUseAPI={handleWelcomeUseAPI}
        />
      </Suspense>

      <Suspense fallback={<div />}>
        <ConfigUploadModal
          show={showConfigUploadModal}
          handleClose={handleCloseConfigUploadModal}
          onSuccess={handleConfigUploadSuccess}
          showBackButton={scopeTargets.length === 0}
          onBackClick={handleBackToWelcome}
        />
      </Suspense>

      <Suspense fallback={<div />}>
        <APIIntegrationModal
          show={showAPIIntegrationModal}
          handleClose={handleCloseAPIIntegrationModal}
          onSuccess={handleAPIIntegrationSuccess}
          showBackButton={scopeTargets.length === 0}
          onBackClick={handleBackToWelcome}
        />
      </Suspense>

      <Modal data-bs-theme="dark" show={showScanHistoryModal} onHide={handleCloseScanHistoryModal} size="xl">
        <Modal.Header closeButton>
          <Modal.Title className='text-danger'>Scan History</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <Table striped bordered hover>
            <thead>
              <tr>
                <th>Scan ID</th>
                <th>Execution Time</th>
                <th>Number of Results</th>
                <th>Created At</th>
              </tr>
            </thead>
            <tbody>
              {scanHistory.map((scan) => (
                <tr key={scan.scan_id}>
                  <td>{scan.scan_id || "ERROR"}</td>
                  <td>{getExecutionTime(scan.execution_time) || "---"}</td>
                  <td>{getResultLength(scan) || "---"}</td>
                  <td>{Date(scan.created_at) || "ERROR"}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Modal.Body>
      </Modal>

      <Modal data-bs-theme="dark" show={showRawResultsModal} onHide={handleCloseRawResultsModal} size="lg">
        <Modal.Header closeButton>
          <Modal.Title className='text-danger'>Raw Results</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <ListGroup>
            {rawResults.map((result, index) => (
              <ListGroup.Item key={index} className="text-white bg-dark">
                {result}
              </ListGroup.Item>
            ))}
          </ListGroup>
        </Modal.Body>
      </Modal>

      <DNSRecordsModal
        showDNSRecordsModal={showDNSRecordsModal}
        handleCloseDNSRecordsModal={handleCloseDNSRecordsModal}
        dnsRecords={dnsRecords}
      />

      <SubdomainsModal
        showSubdomainsModal={showSubdomainsModal}
        handleCloseSubdomainsModal={handleCloseSubdomainsModal}
        subdomains={subdomains}
      />

      <CloudDomainsModal
        showCloudDomainsModal={showCloudDomainsModal}
        handleCloseCloudDomainsModal={handleCloseCloudDomainsModal}
        cloudDomains={cloudDomains}
      />

      <InfrastructureMapModal
        showInfraModal={showInfraModal}
        handleCloseInfraModal={handleCloseInfraModal}
        scanId={getLatestScanId(amassScans)}
      />

      <AmassIntelResultsModal
        showAmassIntelResultsModal={showAmassIntelResultsModal}
        handleCloseAmassIntelResultsModal={handleCloseAmassIntelResultsModal}
        amassIntelResults={mostRecentAmassIntelScan}
        setShowToast={setShowToast}
      />

      <AmassIntelHistoryModal
        showAmassIntelHistoryModal={showAmassIntelHistoryModal}
        handleCloseAmassIntelHistoryModal={handleCloseAmassIntelHistoryModal}
        amassIntelScans={amassIntelScans}
      />

      <HttpxResultsModal
        showHttpxResultsModal={showHttpxResultsModal}
        handleCloseHttpxResultsModal={handleCloseHttpxResultsModal}
        httpxResults={mostRecentHttpxScan}
        onPopulateBurp={handleOpenToolsModalWithUrls}
      />

      <GauResultsModal
        showGauResultsModal={showGauResultsModal}
        handleCloseGauResultsModal={handleCloseGauResultsModal}
        gauResults={mostRecentGauScan}
      />

      <Sublist3rResultsModal
        showSublist3rResultsModal={showSublist3rResultsModal}
        handleCloseSublist3rResultsModal={handleCloseSublist3rResultsModal}
        sublist3rResults={mostRecentSublist3rScan}
      />

      <AssetfinderResultsModal
        showAssetfinderResultsModal={showAssetfinderResultsModal}
        handleCloseAssetfinderResultsModal={handleCloseAssetfinderResultsModal}
        assetfinderResults={mostRecentAssetfinderScan}
      />

      <CTLResultsModal
        showCTLResultsModal={showCTLResultsModal}
        handleCloseCTLResultsModal={handleCloseCTLResultsModal}
        ctlResults={mostRecentCTLScan}
      />

      <Modal show={showCTLApiErrorModal} onHide={() => setShowCTLApiErrorModal(false)} centered>
        <Modal.Header closeButton className="bg-dark border-secondary">
          <Modal.Title className="d-flex align-items-center gap-2">
            <i className="bi bi-exclamation-triangle-fill" style={{ color: '#ff9800' }} />
            <span className="text-white">CTL Scan — API Issue</span>
          </Modal.Title>
        </Modal.Header>
        <Modal.Body className="bg-dark text-white">
          <p>
            The CTL (Certificate Transparency Log) scan works by making an HTTP request to{' '}
            <a href="https://crt.sh" target="_blank" rel="noopener noreferrer" className="text-danger">crt.sh</a>,
            a public API that indexes SSL/TLS certificates from Certificate Transparency logs.
          </p>
          <p>
            The scan failed because the crt.sh API returned an error
            {(() => {
              const errScan = mostRecentCTLScan?.status === 'error' ? mostRecentCTLScan
                : mostRecentCTLCompanyScan?.status === 'error' ? mostRecentCTLCompanyScan : null;
              if (errScan?.stderr) {
                const match = errScan.stderr.match(/status code[:\s]*(\d+)/i);
                if (match) return <> (<code>HTTP {match[1]}</code>)</>;
              }
              return null;
            })()}.
            This typically happens when:
          </p>
          <ul>
            <li><strong>Rate limiting (429)</strong> — Too many requests have been made to crt.sh in a short period.</li>
            <li><strong>Server overload (503)</strong> — The crt.sh service is temporarily overwhelmed by traffic.</li>
            <li><strong>Timeout</strong> — The API took too long to respond for a large domain.</li>
          </ul>
          <p className="mb-0">
            This is not a bug in the framework. Simply <strong>wait a few minutes and try the scan again</strong>.
            The crt.sh API is a free community resource and occasionally struggles under heavy load.
          </p>
        </Modal.Body>
        <Modal.Footer className="bg-dark border-secondary">
          <Button variant="outline-danger" onClick={() => setShowCTLApiErrorModal(false)}>Got it</Button>
        </Modal.Footer>
      </Modal>

      <CTLCompanyResultsModal
        showCTLCompanyResultsModal={showCTLCompanyResultsModal}
        handleCloseCTLCompanyResultsModal={handleCloseCTLCompanyResultsModal}
        ctlCompanyResults={mostRecentCTLCompanyScan}
        setShowToast={setShowToast}
      />

      <CTLCompanyHistoryModal
        showCTLCompanyHistoryModal={showCTLCompanyHistoryModal}
        handleCloseCTLCompanyHistoryModal={handleCloseCTLCompanyHistoryModal}
        ctlCompanyScans={ctlCompanyScans}
      />

      <CloudEnumResultsModal
        showCloudEnumResultsModal={showCloudEnumResultsModal}
        handleCloseCloudEnumResultsModal={handleCloseCloudEnumResultsModal}
        cloudEnumResults={mostRecentCloudEnumScan}
        setShowToast={setShowToast}
      />

      <CloudEnumHistoryModal
        showCloudEnumHistoryModal={showCloudEnumHistoryModal}
        handleCloseCloudEnumHistoryModal={handleCloseCloudEnumHistoryModal}
        cloudEnumScans={cloudEnumScans}
      />

      <AmassEnumCompanyResultsModal
        show={showAmassEnumCompanyResultsModal}
        handleClose={handleCloseAmassEnumCompanyResultsModal}
        activeTarget={activeTarget}
        mostRecentAmassEnumCompanyScan={mostRecentAmassEnumCompanyScan}
      />

      <AmassEnumCompanyHistoryModal
        show={showAmassEnumCompanyHistoryModal}
        handleClose={handleCloseAmassEnumCompanyHistoryModal}
        scans={amassEnumCompanyScans}
      />

      <DNSxCompanyResultsModal
        show={showDNSxCompanyResultsModal}
        handleClose={handleCloseDNSxCompanyResultsModal}
        activeTarget={activeTarget}
        mostRecentDNSxCompanyScan={mostRecentDNSxCompanyScan}
      />

      <DNSxCompanyHistoryModal
        show={showDNSxCompanyHistoryModal}
        handleClose={handleCloseDNSxCompanyHistoryModal}
        scans={dnsxCompanyScans}
      />

      <SubfinderResultsModal
        showSubfinderResultsModal={showSubfinderResultsModal}
        handleCloseSubfinderResultsModal={handleCloseSubfinderResultsModal}
        subfinderResults={mostRecentSubfinderScan}
      />

      <ShuffleDNSResultsModal
        showShuffleDNSResultsModal={showShuffleDNSResultsModal}
        handleCloseShuffleDNSResultsModal={handleCloseShuffleDNSResultsModal}
        shuffleDNSResults={mostRecentShuffleDNSScan}
      />

      <ReconResultsModal
        showReconResultsModal={showReconResultsModal}
        handleCloseReconResultsModal={handleCloseReconResultsModal}
        amassResults={{ status: mostRecentAmassScan?.status, result: subdomains, execution_time: mostRecentAmassScan?.execution_time }}
        sublist3rResults={mostRecentSublist3rScan}
        assetfinderResults={mostRecentAssetfinderScan}
        gauResults={mostRecentGauScan}
        ctlResults={mostRecentCTLScan}
        subfinderResults={mostRecentSubfinderScan}
        shuffleDNSResults={mostRecentShuffleDNSScan}
        gospiderResults={mostRecentGoSpiderScan}
        subdomainizerResults={mostRecentSubdomainizerScan}
        cewlResults={mostRecentShuffleDNSCustomScan}
      />

      <UniqueSubdomainsModal
        showUniqueSubdomainsModal={showUniqueSubdomainsModal}
        handleCloseUniqueSubdomainsModal={handleCloseUniqueSubdomainsModal}
        consolidatedSubdomains={consolidatedSubdomains}
        setShowToast={setShowToast}
      />

      <ConfigureHttpxModal
        show={showConfigureHttpxModal}
        handleClose={handleCloseConfigureHttpxModal}
        httpxConfig={httpxScanConfig}
        onSaveConfig={handleSaveHttpxConfig}
      />

      <CeWLResultsModal
        showCeWLResultsModal={showCeWLResultsModal}
        handleCloseCeWLResultsModal={handleCloseCeWLResultsModal}
        cewlResults={mostRecentShuffleDNSCustomScan}
      />

      <GoSpiderResultsModal
        showGoSpiderResultsModal={showGoSpiderResultsModal}
        handleCloseGoSpiderResultsModal={handleCloseGoSpiderResultsModal}
        gospiderResults={mostRecentGoSpiderScan}
      />

      <SubdomainizerResultsModal
        showSubdomainizerResultsModal={showSubdomainizerResultsModal}
        handleCloseSubdomainizerResultsModal={handleCloseSubdomainizerResultsModal}
        subdomainizerResults={mostRecentSubdomainizerScan}
      />

      <ScreenshotResultsModal
        showScreenshotResultsModal={showScreenshotResultsModal}
        handleCloseScreenshotResultsModal={handleCloseScreenshotResultsModal}
        activeTarget={activeTarget}
        onPopulateBurp={handleOpenToolsModalWithUrls}
      />

      <Fade in={fadeIn}>
        <ManageScopeTargets
          handleOpen={handleOpen}
          handleActiveModalOpen={handleActiveModalOpen}
          activeTarget={activeTarget}
          scopeTargets={scopeTargets}
          getTypeIcon={getTypeIcon}
          onAutoScan={startAutoScan}
          isAutoScanning={isAutoScanning}
          isAutoScanPaused={isAutoScanPaused}
          isAutoScanPausing={isAutoScanPausing}
          isAutoScanCancelling={isAutoScanCancelling}
          setIsAutoScanPausing={setIsAutoScanPausing}
          setIsAutoScanCancelling={setIsAutoScanCancelling}
          autoScanCurrentStep={autoScanCurrentStep}
          mostRecentGauScanStatus={mostRecentGauScanStatus}
          consolidatedSubdomains={consolidatedSubdomains}
          mostRecentHttpxScan={mostRecentHttpxScan}
          onOpenAutoScanHistory={handleOpenAutoScanHistoryModal}
        />
      </Fade>

      {activeTarget && (
        <Fade className="mt-3" in={fadeIn}>
          <div>
            {activeTarget.type === 'Company' && (
              <div className="mb-4">
                <h3 className="text-danger mb-3">Company</h3>
                <h4 className="text-secondary mb-3 fs-5">ASN (On-Prem) Network Ranges</h4>
                <HelpMeLearn section="companyNetworkRanges" />
                <Row className="mb-4">
                  {[
                    {
                      name: 'Amass Intel',
                      link: 'https://github.com/OWASP/Amass',
                      description: 'Intelligence gathering and ASN enumeration for comprehensive network range discovery.',
                      isActive: true,
                      status: mostRecentAmassIntelScanStatus,
                      isScanning: isAmassIntelScanning,
                      onScan: startAmassIntelScan,
                      onResults: handleOpenAmassIntelResultsModal,
                      onHistory: handleOpenAmassIntelHistoryModal,
                      resultCount: (() => {
                        // If no scan exists, show 0 immediately
                        if (!mostRecentAmassIntelScan) return 0;
                        // If scan exists but state not yet populated, show 0 while fetching
                        return amassIntelNetworkRanges.length;
                      })(),
                      resultLabel: 'Network Ranges',
                      // The key this step is registered under in the server's Company tool registry.
                      // The modal asks the server what this tool can be configured with; nothing
                      // about its options lives in this file.
                      configTool: { key: 'amass_intel', name: 'Amass Intel' }
                    },
                    {
                      name: 'Metabigor',
                      link: 'https://github.com/j3ssie/metabigor',
                      description: 'OSINT tool for network intelligence gathering including ASN and IP range discovery.',
                      isActive: true,
                      status: mostRecentMetabigorCompanyScanStatus,
                      isScanning: isMetabigorCompanyScanning,
                      onScan: startMetabigorCompanyScan,
                      onResults: handleOpenMetabigorCompanyResultsModal,
                      onHistory: handleOpenMetabigorCompanyHistoryModal,
                      resultCount: (() => {
                        // If no scan exists, show 0 immediately  
                        if (!mostRecentMetabigorCompanyScan) return 0;
                        // If scan exists but state not yet populated, show 0 while fetching
                        return metabigorNetworkRanges.length;
                      })(),
                      resultLabel: 'Network Ranges',
                      configTool: { key: 'metabigor_company', name: 'Metabigor' }
                    }
                  ].map((tool, index) => (
                    <Col md={6} key={index}>
                      <Card className="shadow-sm h-100 text-center" style={{ minHeight: '250px' }}>
                        <Card.Body className="d-flex flex-column">
                          <Card.Title className="text-danger mb-3">
                            <a href={tool.link} className="text-danger text-decoration-none">
                              {tool.name}
                            </a>
                          </Card.Title>
                          <Card.Text className="text-white small fst-italic">
                            {tool.description}
                          </Card.Text>
                          <div className="mt-auto">
                            <div className="card-metric mb-3">
                              <div className="text-danger fw-bold fs-4">{tool.resultCount || 0}</div>
                              <div className="text-muted small card-metric-label">{tool.resultLabel}</div>
                            </div>
                            <div className="d-flex justify-content-between gap-2">
                              <Button
                                variant="outline-danger"
                                className="flex-fill"
                                onClick={tool.onHistory}
                              >
                                History
                              </Button>
                              {/* Between History and Scan, as asked. The modal is generic: it draws
                                  whatever the server's Company tool registry describes for this key,
                                  so no option, flag or default is named in this file. */}
                              {tool.configTool && (
                                <Button
                                  variant="outline-danger"
                                  className="flex-fill"
                                  onClick={() => setCompanyConfigTool(tool.configTool)}
                                >
                                  Config
                                </Button>
                              )}
                              <Button
                                variant="outline-danger"
                                className="flex-fill"
                                onClick={tool.onScan}
                                disabled={!tool.isActive || tool.disabled || tool.isScanning}
                                title={tool.disabledMessage}
                              >
                                <div className="btn-content">
                                  {tool.isScanning ? (
                                    <Spinner animation="border" size="sm" />
                                  ) : (
                                    'Scan'
                                  )}
                                </div>
                              </Button>
                              <Button 
                                variant="outline-danger" 
                                className="flex-fill" 
                                onClick={tool.onResults}
                              >
                                Results
                              </Button>
                            </div>
                          </div>
                        </Card.Body>
                      </Card>
                    </Col>
                  ))}
                </Row>
                
                <h4 className="text-secondary mb-3 fs-5">Discover Live Web Servers (On-Prem)</h4>
                <HelpMeLearn section="companyLiveWebServers" />
                <Row className="mb-4">
                  <Col>
                    <Card className="shadow-sm h-100 text-center" style={{ minHeight: '200px' }}>
                      <Card.Body className="d-flex flex-column">
                        <Card.Title className="text-danger fs-4 mb-3">Discover Live Web Servers (On-Prem)</Card.Title>
                        <Card.Text className="text-white small fst-italic mb-4">
                          Process discovered network ranges to identify live IP addresses and perform port scanning to discover active web servers within the organization's infrastructure.
                        </Card.Text>
                        <div className="text-danger mb-4">
                          <div className="row">
                            <div className="col">
                              <div className="text-danger fw-bold fs-4">{consolidatedNetworkRangesCount}</div>
                              <div className="text-muted small card-metric-label">Network Ranges</div>
                            </div>
                            <div className="col">
                              <div className="text-danger fw-bold fs-4">{calculateEstimatedScanTime(consolidatedNetworkRanges)}</div>
                              <div className="text-muted small card-metric-label">Est. Scan Time</div>
                            </div>
                            <div className="col">
                              <div className="text-danger fw-bold fs-4">{mostRecentIPPortScan?.live_web_servers_found || 0}</div>
                              <div className="text-muted small card-metric-label">Live Web Servers</div>
                            </div>
                          </div>
                        </div>
                        <div className="d-flex justify-content-between mt-auto gap-2">
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill" 
                            onClick={handleTrimNetworkRanges}
                          >
                            Trim Network Ranges
                          </Button>
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill" 
                            onClick={handleConsolidateNetworkRanges}
                            disabled={isConsolidatingNetworkRanges}
                          >
                            <div className="btn-content">
                              {isConsolidatingNetworkRanges ? (
                                <div className="spinner"></div>
                              ) : 'Consolidate'}
                            </div>
                          </Button>
                          {/* The scanner's own configuration: which ranges and addresses the next
                              scan reaches, plus host discovery, port scanning, the web service probe
                              and concurrency. Every field on it comes from the server's registry. */}
                          <Button
                            variant="outline-danger"
                            className="flex-fill"
                            onClick={() => setShowIPPortScanConfigModal(true)}
                          >
                            Configure
                          </Button>
                          <Button
                            variant="outline-danger"
                            className="flex-fill"
                            onClick={handleDiscoverLiveIPs}
                            disabled={isIPPortScanning}
                          >
                            <div className="btn-content">
                              {isIPPortScanning ? (
                                <div className="spinner"></div>
                              ) : 'IP/Port Scan'}
                            </div>
                          </Button>
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill"
                            onClick={handlePortScanning}
                            disabled={isCompanyMetaDataScanning || 
                                     mostRecentCompanyMetaDataScanStatus === "pending" || 
                                     mostRecentCompanyMetaDataScanStatus === "running" ||
                                     !mostRecentIPPortScan?.live_web_servers_found ||
                                     mostRecentIPPortScan?.live_web_servers_found === 0}
                          >
                            <div className="btn-content">
                              {isCompanyMetaDataScanning || mostRecentCompanyMetaDataScanStatus === "pending" || mostRecentCompanyMetaDataScanStatus === "running" ? (
                                <div className="spinner"></div>
                              ) : 'Gather Metadata'}
                            </div>
                          </Button>
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill"
                            onClick={handleLiveWebServersResults}
                            disabled={!mostRecentIPPortScan || !mostRecentIPPortScan.scan_id}
                          >
                            Results
                          </Button>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>
                <h4 className="text-secondary mb-3 fs-5">Root Domain Discovery (No API Key)</h4>
                <HelpMeLearn section="companyRootDomainDiscovery" />
                <Row className="row-cols-3 g-3 mb-4">
                  {[
                    { 
                      name: 'Google Dorking', 
                      link: 'https://www.google.com',
                      description: 'Advanced Google search techniques to discover company domains, subdomains, and exposed information using search operators.',
                      isActive: true,
                      status: mostRecentGoogleDorkingScanStatus,
                      isScanning: isGoogleDorkingScanning,
                      onManual: startGoogleDorkingManualScan,
                      onResults: handleOpenGoogleDorkingResultsModal,
                      onHistory: handleOpenGoogleDorkingHistoryModal,
                      resultCount: googleDorkingDomains.length,
                      isGoogleDorking: true
                    },
                    { 
                      name: 'CRT', 
                      link: 'https://crt.sh',
                      description: 'Certificate Transparency logs analysis for company domain discovery.',
                      isActive: true,
                      status: mostRecentCTLCompanyScanStatus,
                      isScanning: isCTLCompanyScanning,
                      onScan: startCTLCompanyScan,
                      onResults: handleOpenCTLCompanyResultsModal,
                      onHistory: handleOpenCTLCompanyHistoryModal,
                      resultCount: mostRecentCTLCompanyScan && mostRecentCTLCompanyScan.result ? 
                        mostRecentCTLCompanyScan.result.split('\n').filter(line => line.trim()).length : 0,
                      apiError: mostRecentCTLCompanyScanStatus === 'error',
                      onApiError: () => setShowCTLApiErrorModal(true)
                    },
                    { 
                      name: 'Reverse Whois', 
                      link: 'https://www.whoxy.com/reverse-whois/',
                      description: 'Reverse WHOIS lookup using Whoxy to find other domains registered by the same entity or contact information.',
                      isActive: true,
                      status: null,
                      isScanning: false,
                      onManual: startReverseWhoisManualScan,
                      onResults: handleOpenReverseWhoisResultsModal,
                      resultCount: reverseWhoisDomains.length,
                      isReverseWhois: true
                    }
                  ].map((tool, index) => (
                    <Col key={index}>
                      <Card className="shadow-sm h-100 text-center" style={{ minHeight: '250px' }}>
                        <Card.Body className="d-flex flex-column">
                          <Card.Title className="text-danger mb-3 d-flex align-items-center justify-content-center gap-2">
                            <a href={tool.link} className="text-danger text-decoration-none">
                              {tool.name}
                            </a>
                            {tool.apiError && (
                              <i
                                className="bi bi-exclamation-triangle-fill"
                                style={{ color: '#ff9800', cursor: 'pointer', fontSize: '1.1rem' }}
                                title="API error — click for details"
                                onClick={(e) => { e.stopPropagation(); tool.onApiError(); }}
                              />
                            )}
                          </Card.Title>
                          <Card.Text className="text-white small fst-italic">
                            {tool.description}
                          </Card.Text>
                          <div className="mt-auto">
                            <div className="card-metric mb-3">
                              <div className="text-danger fw-bold fs-4">{tool.resultCount || 0}</div>
                              <div className="text-muted small card-metric-label">Domains</div>
                            </div>
                            {tool.isGoogleDorking ? (
                              <div className="d-flex justify-content-between gap-2">
                                <Button
                                  variant="outline-danger"
                                  className="flex-fill"
                                  onClick={tool.onManual}
                                >
                                  Manual
                                </Button>
                                <Button 
                                  variant="outline-danger" 
                                  className="flex-fill" 
                                  onClick={tool.onResults}
                                >
                                  Results
                                </Button>
                              </div>
                            ) : tool.isReverseWhois ? (
                              <div className="d-flex justify-content-between gap-2">
                                <Button
                                  variant="outline-danger"
                                  className="flex-fill"
                                  onClick={tool.onManual}
                                >
                                  Manual
                                </Button>
                                <Button 
                                  variant="outline-danger" 
                                  className="flex-fill" 
                                  onClick={tool.onResults}
                                >
                                  Results
                                </Button>
                              </div>
                            ) : (
                              <div className="d-flex justify-content-between gap-2">
                                <Button 
                                  variant="outline-danger" 
                                  className="flex-fill" 
                                  onClick={tool.onHistory}
                                >
                                  History
                                </Button>
                                <Button
                                  variant="outline-danger"
                                  className="flex-fill"
                                  onClick={tool.onScan}
                                  disabled={tool.isScanning || tool.status === "pending"}
                                >
                                  <div className="btn-content">
                                    {tool.isScanning || tool.status === "pending" ? (
                                      <div className="spinner"></div>
                                    ) : 'Scan'}
                                  </div>
                                </Button>
                                <Button 
                                  variant="outline-danger" 
                                  className="flex-fill" 
                                  onClick={tool.onResults}
                                >
                                  Results
                                </Button>
                              </div>
                            )}
                          </div>
                        </Card.Body>
                      </Card>
                    </Col>
                  ))}
                </Row>
                
                <div className="d-flex justify-content-between align-items-center mb-3">
                  <h4 className="text-secondary fs-5 mb-0">Root Domain Discovery (API Key)</h4>
                  <Button 
                    variant="outline-danger" 
                    size="sm"
                    onClick={() => setShowAPIKeysConfigModal(true)}
                  >
                    Configure API Keys
                  </Button>
                </div>
                <HelpMeLearn section="companyRootDomainDiscoveryAPI" />
                <Row className="row-cols-4 g-3 mb-4">
                  {[
                    { 
                      name: 'SecurityTrails', 
                      link: 'https://securitytrails.com',
                      description: 'SecurityTrails is a comprehensive DNS, domain, and IP data provider that helps security teams discover and monitor their digital assets.',
                      isActive: true,
                      status: mostRecentSecurityTrailsCompanyScanStatus,
                      isScanning: isSecurityTrailsCompanyScanning,
                      onScan: startSecurityTrailsCompanyScan,
                      onResults: handleOpenSecurityTrailsCompanyResultsModal,
                      onHistory: handleOpenSecurityTrailsCompanyHistoryModal,
                      resultCount: mostRecentSecurityTrailsCompanyScan && mostRecentSecurityTrailsCompanyScan.result ? 
                        (() => {
                          try {
                            const parsed = JSON.parse(mostRecentSecurityTrailsCompanyScan.result);
                            return parsed && parsed.domains ? parsed.domains.length : 0;
                          } catch (e) {
                            return 0;
                          }
                        })() : 0,
                      disabled: !hasSecurityTrailsApiKey,
                      disabledMessage: !hasSecurityTrailsApiKey ? 'SecurityTrails API key not configured' : null
                    },
                    { 
                      name: 'GitHub Recon Tools', 
                      link: 'https://github.com/gwen001/github-search',
                      description: 'Looks for organization mentions and domain patterns in public GitHub repos to discover config files, email addresses, or links to other root domains.',
                      isActive: true,
                      status: mostRecentGitHubReconScanStatus,
                      isScanning: isGitHubReconScanning,
                      onScan: startGitHubReconScan,
                      onResults: handleOpenGitHubReconResultsModal,
                      onHistory: handleOpenGitHubReconHistoryModal,
                      resultCount: mostRecentGitHubReconScan && mostRecentGitHubReconScan.result ? 
                        (() => {
                          try {
                            // Handle null, undefined, or empty string cases
                            if (!mostRecentGitHubReconScan.result || mostRecentGitHubReconScan.result === '' || 
                                mostRecentGitHubReconScan.result === 'undefined' || mostRecentGitHubReconScan.result === 'null') {
                              return 0;
                            }
                            
                            const parsed = JSON.parse(mostRecentGitHubReconScan.result);
                            
                            // Handle different possible result structures
                            if (Array.isArray(parsed)) {
                              return parsed.length;
                            } else if (parsed.domains && Array.isArray(parsed.domains)) {
                              return parsed.domains.length;
                            }
                            
                            return 0;
                          } catch (e) {
                            return 0;
                          }
                        })() : 0,
                      disabled: !hasGitHubApiKey,
                      disabledMessage: !hasGitHubApiKey ? 'GitHub API key not configured' : null
                    },
                    { 
                      name: 'Shodan CLI / API', 
                      link: 'https://shodan.io',
                      description: 'Search engine for internet-connected devices and services.',
                      isActive: true,
                      status: mostRecentShodanCompanyScanStatus,
                      isScanning: isShodanCompanyScanning,
                      onScan: startShodanCompanyScan,
                      onResults: handleOpenShodanCompanyResultsModal,
                      onHistory: handleOpenShodanCompanyHistoryModal,
                      resultCount: mostRecentShodanCompanyScan && mostRecentShodanCompanyScan.result ? 
                        (() => {
                          try {
                            const parsed = JSON.parse(mostRecentShodanCompanyScan.result);
                            return parsed && parsed.domains ? parsed.domains.length : 0;
                          } catch (e) {
                            return 0;
                          }
                        })() : 0,
                      disabled: !hasShodanApiKey,
                      disabledMessage: !hasShodanApiKey ? 'Shodan API key not configured' : null
                    },
                    { 
                      name: 'Censys', 
                      link: 'https://censys.io',
                      description: 'Censys helps security teams discover, monitor, and analyze assets to prevent exposure and reduce risk.',
                      isActive: true,
                      status: mostRecentCensysCompanyScanStatus,
                      isScanning: isCensysCompanyScanning,
                      onScan: startCensysCompanyScan,
                      onResults: handleOpenCensysCompanyResultsModal,
                      onHistory: handleOpenCensysCompanyHistoryModal,
                      resultCount: mostRecentCensysCompanyScan && mostRecentCensysCompanyScan.result ? 
                        (() => {
                          try {
                            const parsed = JSON.parse(mostRecentCensysCompanyScan.result);
                            return parsed && parsed.domains ? parsed.domains.length : 0;
                          } catch (e) {
                            return 0;
                          }
                        })() : 0,
                      disabled: !hasCensysApiKey,
                      disabledMessage: !hasCensysApiKey ? 'Censys API key not configured' : null
                    },
                  ].map((tool, index) => (
                    <Col key={index}>
                      <Card className="shadow-sm h-100 text-center position-relative" style={{ minHeight: '250px' }}>
                        {(tool.name === 'Shodan CLI / API' || tool.name === 'Censys') && (
                          <div className="position-absolute" style={{ top: '10px', right: '10px', zIndex: 1 }}>
                            <i className="bi bi-currency-dollar text-danger" style={{ fontSize: '1.2rem' }} title="Requires paid API key"></i>
                          </div>
                        )}
                        <Card.Body className="d-flex flex-column">
                          <Card.Title className="text-danger mb-3">
                            <a href={tool.link} className="text-danger text-decoration-none">
                              {tool.name}
                            </a>
                          </Card.Title>
                          <Card.Text className="text-white small fst-italic">
                            {tool.description}
                          </Card.Text>
                          <div className="mt-auto">
                            <div className="card-metric mb-3">
                              <div className="text-danger fw-bold fs-4">{tool.resultCount || 0}</div>
                              <div className="text-muted small card-metric-label">Domains</div>
                            </div>
                            <div className="d-flex justify-content-between gap-2">
                              <Button 
                                variant="outline-danger" 
                                className="flex-fill" 
                                onClick={tool.onHistory}
                              >
                                History
                              </Button>
                              <Button
                                variant="outline-danger"
                                className="flex-fill"
                                onClick={tool.onScan}
                                disabled={!tool.isActive || tool.disabled || tool.isScanning}
                                title={tool.disabledMessage}
                              >
                                <div className="btn-content">
                                  {tool.isScanning ? (
                                    <div className="spinner"></div>
                                  ) : (
                                    'Scan'
                                  )}
                                </div>
                              </Button>
                              <Button 
                                variant="outline-danger" 
                                className="flex-fill" 
                                onClick={tool.onResults}
                              >
                                Results
                              </Button>
                            </div>
                          </div>
                        </Card.Body>
                      </Card>
                    </Col>
                  ))}
                </Row>
                
                <h4 className="text-secondary mb-3 fs-5">Consolidate Root Domains</h4>
                <HelpMeLearn section="companyConsolidateRootDomains" />
                <Row className="mb-4">
                  <Col>
                    <Card className="shadow-sm h-100 text-center" style={{ minHeight: '200px' }}>
                      <Card.Body className="d-flex flex-column">
                        <Card.Title className="text-danger fs-4 mb-3">Consolidate Root Domains</Card.Title>
                        <Card.Text className="text-white small fst-italic mb-4">
                          Each tool has discovered root domains for the company. Consolidate them into a single list of unique domains and then add them as Wildcard targets for subdomain enumeration.
                        </Card.Text>
                        <div className="text-danger mb-4">
                          <div className="row">
                            <div className="col">
                              <div className="text-danger fw-bold fs-4">{consolidatedCompanyDomainsCount}</div>
                              <div className="text-muted small card-metric-label">Unique Root Domains</div>
                            </div>
                            <div className="col">
                              <div className="text-danger fw-bold fs-4">{
                                scopeTargets.filter(target => {
                                  if (target.type !== 'Wildcard' || !target.scope_target) return false;
                                  
                                  // Remove *. prefix if present to get the base domain
                                  const baseDomain = target.scope_target.startsWith('*.') 
                                    ? target.scope_target.substring(2) 
                                    : target.scope_target;
                                  
                                  // Check if this domain exists in consolidated company domains
                                  return consolidatedCompanyDomains.some(item => {
                                    const domain = typeof item === 'string' ? item : item.domain;
                                    return domain && domain.toLowerCase() === baseDomain.toLowerCase();
                                  });
                                }).length
                              }</div>
                              <div className="text-muted small card-metric-label">Wildcard Targets Created</div>
                            </div>
                          </div>
                        </div>
                        <div className="d-flex justify-content-between mt-auto gap-2">
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill" 
                            onClick={handleOpenTrimRootDomainsModal}
                          >
                            Trim Root Domains
                          </Button>
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill" 
                            onClick={handleConsolidateCompanyDomains}
                            disabled={isConsolidatingCompanyDomains}
                          >
                            <div className="btn-content">
                              {isConsolidatingCompanyDomains ? (
                                <div className="spinner"></div>
                              ) : 'Consolidate'}
                            </div>
                          </Button>
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill"
                            onClick={handleInvestigateRootDomains}
                            disabled={consolidatedCompanyDomainsCount === 0 || isInvestigateScanning}
                          >
                            <div className="btn-content">
                              {isInvestigateScanning ? (
                                <div className="spinner"></div>
                              ) : 'Investigate'}
                            </div>
                          </Button>
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill"
                            onClick={handleValidateRootDomains}
                            disabled={true}
                          >
                            Validate
                          </Button>
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill"
                            onClick={handleOpenAddWildcardTargetsModal}
                            disabled={consolidatedCompanyDomainsCount === 0}
                          >
                            Add Wildcard Target
                          </Button>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>
                
                <h4 className="text-secondary mb-3 fs-5">Cloud Asset Enumeration (DNS)</h4>
                <HelpMeLearn section="companySubdomainEnumeration" />
                <Row className="row-cols-2 g-3 mb-4">
                  <Col>
                    <Card className="shadow-sm h-100 text-center" style={{ minHeight: '300px' }}>
                      <Card.Body className="d-flex flex-column">
                        <Card.Title className="text-danger fs-4 mb-3">
                          <a href="https://github.com/OWASP/Amass" className="text-danger text-decoration-none">
                            Amass Enum
                          </a>
                        </Card.Title>
                        <Card.Text className="text-white small fst-italic mb-4">
                          Advanced DNS enumeration and cloud asset discovery using multiple techniques including DNS brute-forcing, reverse DNS, and certificate transparency.
                        </Card.Text>
                        <div className="text-danger mb-4">
                          <div className="row">
                            <div className="col">
                              <div className="text-danger fw-bold fs-4">{amassEnumScannedDomainsCount}</div>
                              <div className="text-muted small card-metric-label">Company Domains Scanned</div>
                            </div>
                            <div className="col">
                              <div className="text-danger fw-bold fs-4">{amassEnumCompanyCloudDomains?.length || 0}</div>
                              <div className="text-muted small card-metric-label">Cloud Assets Discovered</div>
                            </div>
                          </div>
                        </div>
                        <div className="d-flex justify-content-between mt-auto gap-2">
                          <Button variant="outline-danger" className="flex-fill" onClick={handleOpenAmassEnumConfigModal}>Config</Button>
                          <Button variant="outline-danger" className="flex-fill" onClick={handleOpenAmassEnumCompanyHistoryModal}>History</Button>
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill"
                            onClick={startAmassEnumCompanyScan}
                            disabled={isAmassEnumCompanyScanning || mostRecentAmassEnumCompanyScanStatus === "pending" || mostRecentAmassEnumCompanyScanStatus === "running"}
                          >
                            <div className="btn-content">
                              {isAmassEnumCompanyScanning || mostRecentAmassEnumCompanyScanStatus === "pending" || mostRecentAmassEnumCompanyScanStatus === "running" ? (
                                <Spinner animation="border" size="sm" />
                              ) : (
                                'Scan'
                              )}
                            </div>
                          </Button>
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill" 
                            onClick={handleOpenAmassEnumCompanyResultsModal}
                          >
                            Results
                          </Button>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                  <Col>
                    <Card className="shadow-sm h-100 text-center" style={{ minHeight: '300px' }}>
                      <Card.Body className="d-flex flex-column">
                        <Card.Title className="text-danger fs-4 mb-3">
                          <a href="https://github.com/projectdiscovery/dnsx" className="text-danger text-decoration-none">
                            DNSx
                          </a>
                        </Card.Title>
                        <Card.Text className="text-white small fst-italic mb-4">
                          Fast and multi-purpose DNS toolkit for running multiple DNS queries and comprehensive DNS record discovery through advanced resolution techniques.
                        </Card.Text>
                        <div className="text-danger mb-4">
                          <div className="row">
                            <div className="col">
                              <div className="text-danger fw-bold fs-4">{dnsxScannedDomainsCount}</div>
                              <div className="text-muted small card-metric-label">Company Domains Scanned</div>
                            </div>
                            <div className="col">
                              <div className="text-danger fw-bold fs-4">{dnsxCompanyDnsRecords?.length || 0}</div>
                              <div className="text-muted small card-metric-label">DNS Records Discovered</div>
                            </div>
                          </div>
                        </div>
                        <div className="d-flex justify-content-between mt-auto gap-2">
                          <Button variant="outline-danger" className="flex-fill" onClick={handleOpenDNSxConfigModal}>Config</Button>
                          <Button variant="outline-danger" className="flex-fill" onClick={handleOpenDNSxCompanyHistoryModal}>History</Button>
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill"
                            onClick={startDNSxCompanyScan}
                            disabled={isDNSxCompanyScanning || mostRecentDNSxCompanyScanStatus === "pending" || mostRecentDNSxCompanyScanStatus === "running"}
                          >
                            <div className="btn-content">
                              {isDNSxCompanyScanning || mostRecentDNSxCompanyScanStatus === "pending" || mostRecentDNSxCompanyScanStatus === "running" ? (
                                <Spinner animation="border" size="sm" />
                              ) : (
                                'Scan'
                              )}
                            </div>
                          </Button>
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill" 
                            onClick={handleOpenDNSxCompanyResultsModal}
                          >
                            Results
                          </Button>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>

                <h4 className="text-secondary mb-3 fs-5">Cloud Asset Enumeration (Brute-Force & Crawl)</h4>
                <HelpMeLearn section="companyBruteForceCrawl" />
                <Row className="row-cols-2 g-3 mb-4">
                  <Col>
                    <Card className="shadow-sm h-100 text-center" style={{ minHeight: '300px' }}>
                      <Card.Body className="d-flex flex-column">
                        <Card.Title className="text-danger fs-4 mb-3">
                          <a href="https://github.com/initstring/cloud_enum" className="text-danger text-decoration-none">
                            Cloud Enum
                          </a>
                        </Card.Title>
                        <Card.Text className="text-white small fst-italic mb-4">
                          Multi-cloud OSINT tool for enumerating public resources in AWS, Azure, and Google Cloud through brute-force techniques.
                        </Card.Text>
                        <div className="text-danger mb-4">
                          <div className="text-danger fw-bold fs-4">{(() => {
                            if (!mostRecentCloudEnumScan?.result) return 0;
                            try {
                              // Backend stores results as JSON array string, not newline-delimited JSON
                              const cloudAssets = JSON.parse(mostRecentCloudEnumScan.result);
                              if (Array.isArray(cloudAssets)) {
                                return cloudAssets.filter(asset => asset.platform && asset.target).length;
                              }
                              return 0;
                            } catch (error) {
                              return 0;
                            }
                          })()}</div>
                          <div className="text-muted small card-metric-label">Cloud Assets Discovered</div>
                        </div>
                        <div className="d-flex justify-content-between mt-auto gap-2">
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill"
                            onClick={handleOpenCloudEnumConfigModal}
                          >
                            Config
                          </Button>
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill"
                            onClick={handleOpenCloudEnumHistoryModal}
                          >
                            History
                          </Button>
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill"
                            onClick={startCloudEnumScan}
                            disabled={isCloudEnumScanning || mostRecentCloudEnumScanStatus === "pending" || mostRecentCloudEnumScanStatus === "running"}
                          >
                            {isCloudEnumScanning || mostRecentCloudEnumScanStatus === "pending" || mostRecentCloudEnumScanStatus === "running" ? (
                              <Spinner animation="border" size="sm" />
                            ) : (
                              'Scan'
                            )}
                          </Button>
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill"
                            onClick={handleOpenCloudEnumResultsModal}
                          >
                            Results
                          </Button>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                  <Col>
                    <Card className="shadow-sm h-100 text-center" style={{ minHeight: '300px' }}>
                      <Card.Body className="d-flex flex-column">
                        <Card.Title className="text-danger fs-4 mb-3">
                          <a href="https://github.com/projectdiscovery/katana" className="text-danger text-decoration-none">
                            Katana
                          </a>
                        </Card.Title>
                        <Card.Text className="text-white small fst-italic mb-4">
                          Next-generation crawling and spidering framework designed for comprehensive web asset discovery and enumeration through intelligent crawling techniques.
                        </Card.Text>
                        <div className="text-danger mb-4">
                          <div className="text-danger fw-bold fs-4">{katanaCompanyCloudAssets ? katanaCompanyCloudAssets.length : 0}</div>
                          <div className="text-muted small card-metric-label">Cloud Assets Discovered</div>
                        </div>
                        <div className="d-flex justify-content-between mt-auto gap-2">
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill"
                            onClick={handleOpenKatanaCompanyConfigModal}
                          >
                            Config
                          </Button>
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill"
                            onClick={handleOpenKatanaCompanyHistoryModal}
                          >
                            History
                          </Button>
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill"
                            onClick={startKatanaCompanyScan}
                            disabled={isKatanaCompanyScanning || mostRecentKatanaCompanyScanStatus === "pending" || mostRecentKatanaCompanyScanStatus === "running"}
                          >
                            {isKatanaCompanyScanning || mostRecentKatanaCompanyScanStatus === "pending" || mostRecentKatanaCompanyScanStatus === "running" ? (
                              <Spinner animation="border" size="sm" />
                            ) : (
                              'Scan'
                            )}
                          </Button>
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill"
                            onClick={handleOpenKatanaCompanyResultsModal}
                          >
                            Results
                          </Button>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>

                <h4 className="text-secondary mb-3 fs-5">{activeTarget.scope_target}'s Full Attack Surface</h4>
                <HelpMeLearn section="companyDecisionPoint" />
                <Row className="mb-4">
                  <Col>
                  <Card className="shadow-sm h-100 text-center" style={{ minHeight: '200px' }}>
                    <Card.Body className="d-flex flex-column">
                      <Card.Title className="text-danger fs-4 mb-3">{activeTarget.scope_target}'s Full Attack Surface</Card.Title>
                      <Card.Text className="text-white small fst-italic mb-4">
                        Comprehensive attack surface management and analysis for your company's digital footprint across all discovered assets, domains, and cloud resources.
                      </Card.Text>
                      <div className="text-danger mb-4">
                        <div className="row row-cols-6">
                          <div className="col">
                            <div className="text-danger fw-bold fs-4">{attackSurfaceASNsCount}</div>
                            <div className="text-muted small card-metric-label">Autonomous System Numbers (ASNs)</div>
                          </div>
                          <div className="col">
                            <div className="text-danger fw-bold fs-4">{attackSurfaceNetworkRangesCount}</div>
                            <div className="text-muted small card-metric-label">Network Ranges</div>
                          </div>
                          <div className="col">
                            <div className="text-danger fw-bold fs-4">{attackSurfaceIPAddressesCount}</div>
                            <div className="text-muted small card-metric-label">IP Addresses</div>
                          </div>
                          <div className="col">
                            <div className="text-danger fw-bold fs-4">{attackSurfaceFQDNsCount}</div>
                            <div className="text-muted small card-metric-label">Domain Names</div>
                          </div>
                          <div className="col">
                            <div className="text-danger fw-bold fs-4">{attackSurfaceCloudAssetsCount}</div>
                            <div className="text-muted small card-metric-label">Cloud Asset Domains</div>
                          </div>
                          <div className="col">
                            <div className="text-danger fw-bold fs-4">{attackSurfaceLiveWebServersCount}</div>
                            <div className="text-muted small card-metric-label">Live Web Servers</div>
                          </div>
                        </div>
                      </div>
                      <div className="d-flex justify-content-between mt-auto gap-2">
                        <Button 
                          variant="outline-danger" 
                          className="flex-fill" 
                          onClick={handleConsolidateAttackSurface}
                          disabled={isConsolidatingAttackSurface}
                        >
                          {isConsolidatingAttackSurface ? (
                            <div className="spinner"></div>
                          ) : (
                            'Consolidate'
                          )}
                        </Button>
                        <Button 
                          variant="outline-danger" 
                          className="flex-fill" 
                          onClick={handleOpenManageAttackSurfaceModal}
                        >
                          Manage
                        </Button>
                        <Button 
                          variant="outline-danger" 
                          className="flex-fill" 
                          onClick={handleInvestigateFQDNs}
                          disabled={isInvestigatingFQDNs}
                        >
                          {isInvestigatingFQDNs ? (
                            <div className="spinner"></div>
                          ) : (
                            'Investigate'
                          )}
                        </Button>
                        <Button variant="outline-danger" className="flex-fill" onClick={handleOpenExploreAttackSurfaceModal}>Explore</Button>
                        <Button variant="outline-danger" className="flex-fill" onClick={handleOpenAttackSurfaceVisualizationModal}>Visualize</Button>
                      </div>
                    </Card.Body>
                  </Card>
                  </Col>
                </Row>

                <h4 className="text-secondary mb-3 fs-5">Nuclei Scanning</h4>
                <HelpMeLearn section="companyNucleiScanning" />
                <Row className="mb-4">
                  <Col>
                  <Card className="shadow-sm h-100 text-center" style={{ minHeight: '200px' }}>
                      <Card.Body className="d-flex flex-column">
                        <Card.Title className="text-danger fs-4 mb-3">
                          <a href="https://github.com/projectdiscovery/nuclei" className="text-danger text-decoration-none">
                            Nuclei Scanning
                          </a>
                        </Card.Title>
                        <Card.Text className="text-white small fst-italic mb-4">
                          Comprehensive vulnerability scanning across your entire company attack surface using Nuclei templates to identify security issues and potential bug bounty targets.
                        </Card.Text>
                        <div className="text-danger mb-4">
                          <div className="row row-cols-5">
                            <div className="col">
                              <div className="text-danger fw-bold fs-4">{getNucleiSelectedTargetsCount()}</div>
                              <div className="text-muted small card-metric-label">Selected Targets</div>
                            </div>
                            <div className="col">
                              <div className="text-danger fw-bold fs-4">{getNucleiSelectedTemplatesCount()}</div>
                              <div className="text-muted small card-metric-label">Selected Templates</div>
                            </div>
                            <div className="col">
                              <div className="text-danger fw-bold fs-4">{getNucleiEstimatedScanTime()}</div>
                              <div className="text-muted small card-metric-label">Estimated Scan Time</div>
                            </div>
                            <div className="col">
                              <div className="text-danger fw-bold fs-4">{getNucleiTotalFindings()}</div>
                              <div className="text-muted small card-metric-label">Total Findings</div>
                            </div>
                            <div className="col">
                              <div className="text-danger fw-bold fs-4">{getNucleiImpactfulFindings()}</div>
                              <div className="text-muted small card-metric-label">Impactful Findings</div>
                            </div>
                          </div>
                        </div>
                        <div className="d-flex justify-content-between mt-auto gap-2">
                          <Button variant="outline-danger" className="flex-fill" onClick={handleOpenNucleiHistoryModal}>History</Button>
                          {/* Settings is the ENGINE flags (rate, concurrency, timeouts, retries).
                              Configure, next to it, is the existing targets-and-templates screen and
                              is untouched: two screens that both set templates is how a
                              configuration comes to contradict itself.

                              These settings deliberately live in wildcard_tool_settings, because ONE
                              nuclei runner serves both workflows and it loads by scope target id
                              alone. The modal says so on every tab. */}
                          <Button variant="outline-danger" className="flex-fill" onClick={() => setCompanyConfigTool({ key: 'nuclei', name: 'Nuclei' })}>Settings</Button>
                          <Button variant="outline-danger" className="flex-fill" onClick={handleOpenNucleiConfigModal}>Configure</Button>
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill"
                            disabled={isNucleiScanDisabled() || isNucleiScanning}
                            onClick={startNucleiScan}
                          >
                            {isNucleiScanning ? (
                              <Spinner animation="border" size="sm" />
                            ) : (
                              'Scan'
                            )}
                          </Button>
                          <Button variant="outline-danger" className="flex-fill" onClick={handleOpenNucleiResultsModal}>Results</Button>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>
              </div>
            )}
            {activeTarget.type === 'Wildcard' && (
              <div className="mb-4">
                <h3 className="text-danger mb-3">Wildcard</h3>
                <HelpMeLearn section="amass" />
                <Row className="mb-4">
                  <Col>
                    <Card className="shadow-sm" style={{ minHeight: '250px' }}>
                      <Card.Body className="d-flex flex-column justify-content-between">
                        <div>
                          <Card.Title className="text-danger fs-3 mb-3 text-center">
                            <a href="https://github.com/OWASP/Amass" className="text-danger text-decoration-none">
                              Amass Enum
                            </a>
                          </Card.Title>
                          <Card.Text className="text-white small fst-italic text-center">
                            A powerful subdomain enumeration and OSINT tool for in-depth reconnaissance.
                          </Card.Text>
                          {/* Liveness on its own row, the same shape as the Manual Crawling card:
                              it is a status, not a number, and it is the first thing an operator
                              looks for. While a scan runs this shows its elapsed time, so a long
                              Amass run is visibly progressing rather than merely "not finished". */}
                          <div className="text-center mt-2">
                            {amassScanRunning ? (
                              <div className="text-danger">
                                <Spinner animation="border" size="sm" className="me-2" />
                                <strong>Scan Running</strong>
                                {/* Live elapsed, not execution_time: that field is only written when
                                    the scan completes. Omitted rather than faked if the start time
                                    is unavailable. */}
                                {amassElapsed && <span className="text-muted ms-2">{amassElapsed}</span>}
                              </div>
                            ) : (
                              <div className="text-muted">
                                <i className="bi bi-circle-fill me-2" style={{ fontSize: '0.6rem' }}></i>
                                No Scan Running
                              </div>
                            )}
                          </div>

                          {/* The four numbers this tool produces, in the same big-number shape as
                              every other card in the three workflows. The scan id, status and
                              timestamp that used to share this space are still one click away in
                              Scan History, which is where a value nobody reads at a glance belongs. */}
                          <div className="mt-3 mb-3">
                            <Row className="text-center align-items-start">
                              <Col>
                                <div className="text-danger fw-bold fs-4">
                                  {getResultLength(scanHistory[scanHistory.length - 1]) || 0}
                                </div>
                                <div className="text-muted small card-metric-label">Total Results</div>
                              </Col>
                              <Col>
                                <div className={`fw-bold fs-4 ${cloudDomains.length ? 'text-danger' : 'text-secondary'}`}>
                                  {cloudDomains.length || 0}
                                </div>
                                <div className="text-muted small card-metric-label">Cloud Domains</div>
                              </Col>
                              <Col>
                                <div className={`fw-bold fs-4 ${subdomains.length ? 'text-danger' : 'text-secondary'}`}>
                                  {subdomains.length || 0}
                                </div>
                                <div className="text-muted small card-metric-label">Subdomains</div>
                              </Col>
                              <Col>
                                <div className={`fw-bold fs-4 ${dnsRecords.length ? 'text-danger' : 'text-secondary'}`}>
                                  {dnsRecords.length || 0}
                                </div>
                                <div className="text-muted small card-metric-label">DNS Records</div>
                              </Col>
                            </Row>
                          </div>
                        </div>
                        <div className="d-flex justify-content-between w-100 mt-3 gap-2">
                          <Button variant="outline-danger" className="flex-fill" onClick={() => setWildcardConfigTool({ key: 'amass', name: 'Amass' })}>&nbsp;&nbsp;&nbsp;Configure&nbsp;&nbsp;&nbsp;</Button>
                          <Button variant="outline-danger" className="flex-fill" onClick={handleOpenScanHistoryModal}>&nbsp;&nbsp;&nbsp;Scan History&nbsp;&nbsp;&nbsp;</Button>
                          <Button variant="outline-danger" className="flex-fill" onClick={handleOpenRawResultsModal}>&nbsp;&nbsp;&nbsp;Raw Results&nbsp;&nbsp;&nbsp;</Button>
                          <Button variant="outline-danger" className="flex-fill" onClick={handleOpenInfraModal}>Infrastructure</Button>
                          <Button variant="outline-danger" className="flex-fill" onClick={handleOpenDNSRecordsModal}>&nbsp;&nbsp;&nbsp;DNS Records&nbsp;&nbsp;&nbsp;</Button>
                          <Button variant="outline-danger" className="flex-fill" onClick={handleOpenSubdomainsModal}>&nbsp;&nbsp;&nbsp;Subdomains&nbsp;&nbsp;&nbsp;</Button>
                          <Button variant="outline-danger" className="flex-fill" onClick={handleOpenCloudDomainsModal}>&nbsp;&nbsp;Cloud Domains&nbsp;&nbsp;</Button>
                          <Button
                            variant="outline-danger"
                            className="flex-fill"
                            onClick={startAmassScan}
                            disabled={isScanning || mostRecentAmassScanStatus === "pending" ? true : false}
                          >
                            <div className="btn-content">
                              {isScanning || mostRecentAmassScanStatus === "pending" ? (
                                <div className="spinner"></div>
                              ) : 'Scan'}
                            </div>
                          </Button>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>
                <h4 className="text-secondary mb-3 fs-5">Subdomain Scraping</h4>
                <HelpMeLearn section="subdomainScraping" />
                <Row className="row-cols-5 g-3 mb-4">
                  {[
                    { name: 'Passive OSINT',
                      link: 'https://sidxparab.gitbook.io/subdomain-enumeration-guide/passive-enumeration/passive-sources',
                      isActive: true,
                      // The key this step is registered under in the server's Wildcard tool registry.
                      // The modal asks the server what that tool can be configured with; nothing about
                      // its options is decided here.
                      configTool: 'sublist3r',
                      status: mostRecentSublist3rScanStatus,
                      isScanning: isSublist3rScanning,
                      onScan: startSublist3rScan,
                      onResults: handleOpenSublist3rResultsModal,
                      resultCount: mostRecentSublist3rScan && mostRecentSublist3rScan.result ? 
                        mostRecentSublist3rScan.result.split('\n').filter(line => line.trim()).length : 0
                    },
                    { name: 'Assetfinder',
                      link: 'https://github.com/tomnomnom/assetfinder',
                      isActive: true,
                      configTool: 'assetfinder',
                      status: mostRecentAssetfinderScanStatus,
                      isScanning: isAssetfinderScanning,
                      onScan: startAssetfinderScan,
                      onResults: handleOpenAssetfinderResultsModal,
                      resultCount: mostRecentAssetfinderScan && mostRecentAssetfinderScan.result ? 
                        mostRecentAssetfinderScan.result.split('\n').filter(line => line.trim()).length : 0
                    },
                    { 
                      name: 'GAU',
                      link: 'https://github.com/lc/gau',
                      isActive: true,
                      configTool: 'gau',
                      status: mostRecentGauScanStatus,
                      isScanning: isGauScanning,
                      onScan: startGauScan,
                      onResults: handleOpenGauResultsModal,
                      resultCount: mostRecentGauScan && mostRecentGauScan.result ? 
                        (() => {
                          try {
                            const results = mostRecentGauScan.result.split('\n')
                              .filter(line => line.trim())
                              .map(line => JSON.parse(line));
                            const subdomainSet = new Set();
                            results.forEach(result => {
                              try {
                                const url = new URL(result.url);
                                subdomainSet.add(url.hostname);
                              } catch (e) {}
                            });
                            return subdomainSet.size;
                          } catch (e) {
                            return 0;
                          }
                        })() : 0
                    },
                    { 
                      name: 'CTL',
                      link: 'https://github.com/hannob/tlshelpers',
                      isActive: true,
                      configTool: 'ctl',
                      status: mostRecentCTLScanStatus,
                      isScanning: isCTLScanning,
                      onScan: startCTLScan,
                      onResults: handleOpenCTLResultsModal,
                      resultCount: mostRecentCTLScan && mostRecentCTLScan.result ? 
                        mostRecentCTLScan.result.split('\n').filter(line => line.trim()).length : 0,
                      apiError: mostRecentCTLScanStatus === 'error',
                      onApiError: () => setShowCTLApiErrorModal(true)
                    },
                    { name: 'Subfinder',
                      link: 'https://github.com/projectdiscovery/subfinder',
                      isActive: true,
                      configTool: 'subfinder',
                      status: mostRecentSubfinderScanStatus,
                      isScanning: isSubfinderScanning,
                      onScan: startSubfinderScan,
                      onResults: handleOpenSubfinderResultsModal,
                      resultCount: mostRecentSubfinderScan && mostRecentSubfinderScan.result ? 
                        mostRecentSubfinderScan.result.split('\n').filter(line => line.trim()).length : 0
                    }
                  ].map((tool, index) => (
                    <Col key={index}>
                      <Card className="shadow-sm h-100 text-center" style={{ minHeight: '250px' }}>
                        <Card.Body className="d-flex flex-column">
                          <Card.Title className="text-danger mb-3 d-flex align-items-center justify-content-center gap-2">
                            <a href={tool.link} className="text-danger text-decoration-none">
                              {tool.name}
                            </a>
                            {tool.apiError && (
                              <i
                                className="bi bi-exclamation-triangle-fill"
                                style={{ color: '#ff9800', cursor: 'pointer', fontSize: '1.1rem' }}
                                title="API error — click for details"
                                onClick={(e) => { e.stopPropagation(); tool.onApiError(); }}
                              />
                            )}
                          </Card.Title>
                          <Card.Text className="text-white small fst-italic">
                            {tool.name === 'GAU' ? 'Get All URLs - Fetch known URLs from AlienVault\'s Open Threat Exchange, the Wayback Machine, and Common Crawl.' : tool.name === 'Passive OSINT' ? 'Unions subdomains from multiple free, key-less passive OSINT sources.' : 'A subdomain enumeration tool that uses OSINT techniques.'}
                          </Card.Text>
                          <div className="mt-auto">
                            <div className="card-metric mb-3">
                              <div className="text-danger fw-bold fs-4">{tool.resultCount || 0}</div>
                              <div className="text-muted small card-metric-label">Subdomains</div>
                            </div>
                            {/* Three EQUAL-WIDTH icon buttons: gear, play, list. flex 1 1 0 gives
                                each exactly a third of the row whatever it contains, so they stay
                                the same size as one another. With all three as icons there is no
                                text to fit, which is what row-cols-5 could not afford: a fifth of a
                                card leaves about 41px of usable width once .btn padding is taken,
                                and "Results" does not fit in that at a readable size.
                                Every button carries title (hover) and aria-label (screen reader)
                                with the full word, because an icon alone is not a label. */}
                            <div className="d-flex gap-2 flex-nowrap btn-scrape-row">
                              <Button
                                variant="outline-danger"
                                className="btn-scrape"
                                onClick={() => setWildcardConfigTool({ key: tool.configTool, name: tool.name })}
                                disabled={!tool.isActive || !tool.configTool}
                                title="Config"
                                aria-label="Config"
                              >
                                <i className="bi bi-gear-fill"></i>
                              </Button>
                              <Button
                                variant="outline-danger"
                                className="btn-scrape"
                                onClick={tool.onScan}
                                disabled={!tool.isActive || tool.isScanning || tool.status === "pending"}
                                title="Scan"
                                aria-label="Scan"
                              >
                                <div className="btn-content">
                                  {tool.isScanning || tool.status === "pending"
                                    ? <div className="spinner"></div>
                                    : <i className="bi bi-play-fill"></i>}
                                </div>
                              </Button>
                              <Button
                                variant="outline-danger"
                                className="btn-scrape"
                                onClick={tool.onResults}
                                disabled={!tool.isActive}
                                title="Results"
                                aria-label="Results"
                              >
                                <i className="bi bi-list-ul"></i>
                              </Button>
                            </div>
                          </div>
                        </Card.Body>
                      </Card>
                    </Col>
                  ))}
                </Row>
                <h4 className="text-secondary mb-3 fs-5">Consolidate Subdomains & Discover Live Web Servers - Round 1</h4>
                <HelpMeLearn section="consolidationRound1" />
                <Row className="mb-4">
                  <Col>
                    <Card className="shadow-sm h-100 text-center" style={{ minHeight: '200px' }}>
                      <Card.Body className="d-flex flex-column">
                        <Card.Title className="text-danger fs-4 mb-3">Consolidate Subdomains & Discover Live Web Servers</Card.Title>
                        <Card.Text className="text-white small fst-italic mb-4">
                          Each tool has discovered a list of subdomains. Review the results, consolidate them into a single list, and discover live web servers.
                        </Card.Text>
                        <div className="text-danger mb-4">
                          <div className="row">
                            <div className="col">
                              <div className="text-danger fw-bold fs-4">{consolidatedCount}</div>
                              <div className="text-muted small card-metric-label">Unique Subdomains</div>
                            </div>
                            <div className="col">
                              <div className="text-danger fw-bold fs-4">{getHttpxResultsCount(mostRecentHttpxScan)}</div>
                              <div className="text-muted small card-metric-label">Live Web Servers</div>
                            </div>
                          </div>
                        </div>
                        <div className="d-flex justify-content-between mt-auto gap-2">
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill" 
                            onClick={handleConsolidate}
                            disabled={isConsolidating}
                          >
                            <div className="btn-content">
                              {isConsolidating ? (
                                <div className="spinner"></div>
                              ) : 'Consolidate'}
                            </div>
                          </Button>
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill"
                            onClick={handleOpenUniqueSubdomainsModal}
                            disabled={consolidatedSubdomains.length === 0}
                          >
                            Unique Subdomains
                          </Button>
                          <Button
                            variant="outline-danger"
                            className="flex-fill"
                            onClick={handleOpenConfigureHttpxModal}
                          >
                            {httpxScanConfig ? 'HTTPX Config' : 'Configure HTTPX'}
                          </Button>
                          <Button
                            variant="outline-danger"
                            className="flex-fill"
                            onClick={startHttpxScan}
                            disabled={isHttpxScanning || mostRecentHttpxScanStatus === "pending" || consolidatedSubdomains.length === 0}
                          >
                            <div className="btn-content">
                              {isHttpxScanning || mostRecentHttpxScanStatus === "pending" ? (
                                <div className="spinner"></div>
                              ) : 'HTTPX Scan'}
                            </div>
                          </Button>
                          <Button variant="outline-danger" className="flex-fill" onClick={handleOpenHttpxResultsModal}>Live Web Servers</Button>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>
                <h4 className="text-secondary mb-3 fs-5">Brute-Force</h4>
                <HelpMeLearn section="bruteForce" />
                <Row className="justify-content-between mb-4">
                  {[
                    { 
                      name: 'ShuffleDNS',
                      link: 'https://github.com/projectdiscovery/shuffledns',
                      isActive: true,
                      configTool: 'shuffledns',
                      status: mostRecentShuffleDNSScanStatus,
                      isScanning: isShuffleDNSScanning,
                      onScan: startShuffleDNSScan,
                      onResults: handleOpenShuffleDNSResultsModal,
                      resultCount: mostRecentShuffleDNSScan && mostRecentShuffleDNSScan.result ? 
                        mostRecentShuffleDNSScan.result.split('\n').filter(line => line.trim()).length : 0
                    },
                    { 
                      name: 'CeWL',
                      link: 'https://github.com/digininja/CeWL',
                      isActive: true,
                      configTool: 'cewl',
                      status: mostRecentCeWLScanStatus,
                      isScanning: isCeWLScanning,
                      onScan: startCeWLScan,
                      onResults: handleOpenCeWLResultsModal,
                      resultCount: mostRecentShuffleDNSCustomScan && mostRecentShuffleDNSCustomScan.result ? 
                        mostRecentShuffleDNSCustomScan.result.split('\n').filter(line => line.trim()).length : 0
                    }
                  ].map((tool, index) => (
                    <Col md={6} className="mb-4" key={index}>
                      <Card className="shadow-sm h-100 text-center" style={{ minHeight: '150px' }}>
                        <Card.Body className="d-flex flex-column">
                          <Card.Title className="text-danger mb-3">
                            <a href={tool.link} className="text-danger text-decoration-none">
                              {tool.name}
                            </a>
                          </Card.Title>
                          <Card.Text className="text-white small fst-italic">
                            {tool.name === 'ShuffleDNS' ? 
                              'A subdomain resolver tool that utilizes massdns for resolving subdomains.' :
                              'A custom word list generator for target-specific wordlists.'}
                          </Card.Text>
                          {tool.isActive && (
                            <div className="card-metric mb-3">
                              <div className="text-danger fw-bold fs-4">{tool.resultCount || 0}</div>
                              <div className="text-muted small card-metric-label">Subdomains</div>
                            </div>
                          )}
                          <div className="d-flex justify-content-between mt-auto gap-2">
                            <Button
                              variant="outline-danger"
                              className="flex-fill"
                              onClick={() => setWildcardConfigTool({ key: tool.configTool, name: tool.name })}
                              disabled={!tool.configTool}
                            >
                              Config
                            </Button>
                            <Button
                              variant="outline-danger"
                              className="flex-fill"
                              onClick={tool.onScan}
                              disabled={!tool.isActive || tool.isScanning || tool.status === "pending"}
                            >
                              <div className="btn-content">
                                {tool.isScanning || tool.status === "pending" ? (
                                  <div className="spinner"></div>
                                ) : 'Scan'}
                              </div>
                            </Button>
                            <Button
                              variant="outline-danger"
                              className="flex-fill"
                              onClick={tool.onResults}
                              disabled={!tool.isActive || !tool.resultCount}
                            >
                              Results
                            </Button>
                          </div>
                        </Card.Body>
                      </Card>
                    </Col>
                  ))}
                </Row>
                <h4 className="text-secondary mb-3 fs-5">Consolidate Subdomains & Discover Live Web Servers - Round 2</h4>
                <HelpMeLearn section="consolidationRound2" />
                <Row className="mb-4">
                  <Col>
                    <Card className="shadow-sm h-100 text-center" style={{ minHeight: '200px' }}>
                      <Card.Body className="d-flex flex-column">
                        <Card.Title className="text-danger fs-4 mb-3">Consolidate Subdomains & Discover Live Web Servers</Card.Title>
                        <Card.Text className="text-white small fst-italic mb-4">
                          Each tool has discovered a list of subdomains. Review the results, consolidate them into a single list, and discover live web servers.
                        </Card.Text>
                        <div className="text-danger mb-4">
                          <div className="row">
                            <div className="col">
                              <div className="text-danger fw-bold fs-4">{consolidatedCount}</div>
                              <div className="text-muted small card-metric-label">Unique Subdomains</div>
                            </div>
                            <div className="col">
                              <div className="text-danger fw-bold fs-4">{getHttpxResultsCount(mostRecentHttpxScan)}</div>
                              <div className="text-muted small card-metric-label">Live Web Servers</div>
                            </div>
                          </div>
                        </div>
                        <div className="d-flex justify-content-between mt-auto gap-2">
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill" 
                            onClick={handleConsolidate}
                            disabled={isConsolidating}
                          >
                            <div className="btn-content">
                              {isConsolidating ? (
                                <div className="spinner"></div>
                              ) : 'Consolidate'}
                            </div>
                          </Button>
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill"
                            onClick={handleOpenUniqueSubdomainsModal}
                            disabled={consolidatedSubdomains.length === 0}
                          >
                            Unique Subdomains
                          </Button>
                          <Button
                            variant="outline-danger"
                            className="flex-fill"
                            onClick={handleOpenConfigureHttpxModal}
                          >
                            {httpxScanConfig ? 'HTTPX Config' : 'Configure HTTPX'}
                          </Button>
                          <Button
                            variant="outline-danger"
                            className="flex-fill"
                            onClick={startHttpxScan}
                            disabled={isHttpxScanning || mostRecentHttpxScanStatus === "pending" || consolidatedSubdomains.length === 0}
                          >
                            <div className="btn-content">
                              {isHttpxScanning || mostRecentHttpxScanStatus === "pending" ? (
                                <div className="spinner"></div>
                              ) : 'HTTPX Scan'}
                            </div>
                          </Button>
                          <Button variant="outline-danger" className="flex-fill" onClick={handleOpenHttpxResultsModal}>Live Web Servers</Button>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>
                <h4 className="text-secondary mb-3 fs-5">JavaScript/Link Discovery</h4>
                <HelpMeLearn section="javascriptDiscovery" />
                <Row className="justify-content-between mb-4">
                  {[
                    { 
                      name: 'GoSpider',
                      link: 'https://github.com/jaeles-project/gospider',
                      isActive: true,
                      configTool: 'gospider',
                      status: mostRecentGoSpiderScanStatus,
                      isScanning: isGoSpiderScanning,
                      onScan: startGoSpiderScan,
                      onResults: handleOpenGoSpiderResultsModal,
                      resultCount: mostRecentGoSpiderScan && mostRecentGoSpiderScan.result ? 
                        mostRecentGoSpiderScan.result.split('\n').filter(line => line.trim()).length : 0
                    },
                    { 
                      name: 'Subdomainizer',
                      link: 'https://github.com/nsonaniya2010/SubDomainizer',
                      isActive: true,
                      configTool: 'subdomainizer',
                      status: mostRecentSubdomainizerScanStatus,
                      isScanning: isSubdomainizerScanning,
                      onScan: startSubdomainizerScan,
                      onResults: handleOpenSubdomainizerResultsModal,
                      resultCount: mostRecentSubdomainizerScan && mostRecentSubdomainizerScan.result ? 
                        mostRecentSubdomainizerScan.result.split('\n').filter(line => line.trim()).length : 0
                    }
                  ].map((tool, index) => (
                    <Col md={6} className="mb-4" key={index}>
                      <Card className="shadow-sm h-100 text-center" style={{ minHeight: '150px' }}>
                        <Card.Body className="d-flex flex-column">
                          <Card.Title className="text-danger mb-3">
                            <a href={tool.link} className="text-danger text-decoration-none">
                              {tool.name}
                            </a>
                          </Card.Title>
                          <Card.Text className="text-white small fst-italic">
                            A fast web spider written in Go for web scraping and crawling.
                          </Card.Text>
                          {tool.isActive && (
                            <div className="card-metric mb-3">
                              <div className="text-danger fw-bold fs-4">{tool.resultCount || 0}</div>
                              <div className="text-muted small card-metric-label">Subdomains</div>
                            </div>
                          )}
                          <div className="d-flex justify-content-between mt-auto gap-2">
                            <Button
                              variant="outline-danger"
                              className="flex-fill"
                              onClick={() => setWildcardConfigTool({ key: tool.configTool, name: tool.name })}
                              disabled={!tool.configTool}
                            >
                              Config
                            </Button>
                            <Button
                              variant="outline-danger"
                              className="flex-fill"
                              onClick={tool.onScan}
                              disabled={!tool.isActive || tool.isScanning || tool.status === "pending"}
                            >
                              <div className="btn-content">
                                {tool.isScanning || tool.status === "pending" ? (
                                  <div className="spinner"></div>
                                ) : 'Scan'}
                              </div>
                            </Button>
                            <Button
                              variant="outline-danger"
                              className="flex-fill"
                              onClick={tool.onResults}
                              disabled={!tool.isActive || !tool.resultCount}
                            >
                              Results
                            </Button>
                          </div>
                        </Card.Body>
                      </Card>
                    </Col>
                  ))}
                </Row>
                <h4 className="text-secondary mb-3 fs-5">Consolidate Subdomains & Discover Live Web Servers - Round 3</h4>
                <HelpMeLearn section="consolidationRound3" />
                <Row className="mb-4">
                  <Col>
                    <Card className="shadow-sm h-100 text-center" style={{ minHeight: '200px' }}>
                      <Card.Body className="d-flex flex-column">
                        <Card.Title className="text-danger fs-4 mb-3">Subdomain Discovery Results</Card.Title>
                        <Card.Text className="text-white small fst-italic mb-4">
                          Each tool has discovered additional subdomains through JavaScript analysis and link discovery. Review the results, consolidate them into a single list, and discover live web servers.
                        </Card.Text>
                        <div className="text-danger mb-4">
                          <div className="row">
                            <div className="col">
                              <div className="text-danger fw-bold fs-4">{consolidatedCount}</div>
                              <div className="text-muted small card-metric-label">Unique Subdomains</div>
                            </div>
                            <div className="col">
                              <div className="text-danger fw-bold fs-4">{getHttpxResultsCount(mostRecentHttpxScan)}</div>
                              <div className="text-muted small card-metric-label">Live Web Servers</div>
                            </div>
                          </div>
                        </div>
                        <div className="d-flex justify-content-between mt-auto gap-2">
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill" 
                            onClick={handleConsolidate}
                            disabled={isConsolidating}
                          >
                            <div className="btn-content">
                              {isConsolidating ? (
                                <div className="spinner"></div>
                              ) : 'Consolidate'}
                            </div>
                          </Button>
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill"
                            onClick={handleOpenUniqueSubdomainsModal}
                            disabled={consolidatedSubdomains.length === 0}
                          >
                            Unique Subdomains
                          </Button>
                          <Button
                            variant="outline-danger"
                            className="flex-fill"
                            onClick={handleOpenConfigureHttpxModal}
                          >
                            {httpxScanConfig ? 'HTTPX Config' : 'Configure HTTPX'}
                          </Button>
                          <Button
                            variant="outline-danger"
                            className="flex-fill"
                            onClick={startHttpxScan}
                            disabled={isHttpxScanning || mostRecentHttpxScanStatus === "pending" || consolidatedSubdomains.length === 0}
                          >
                            <div className="btn-content">
                              {isHttpxScanning || mostRecentHttpxScanStatus === "pending" ? (
                                <div className="spinner"></div>
                              ) : 'HTTPX Scan'}
                            </div>
                          </Button>
                          <Button variant="outline-danger" className="flex-fill" onClick={handleOpenHttpxResultsModal}>Live Web Servers</Button>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>
                <h4 className="text-secondary mb-3 fs-3 text-center">DECISION POINT</h4>
                <HelpMeLearn section="decisionPoint" />
                <Row className="mb-4">
                  <Col>
                    <Card className="shadow-sm" style={{ minHeight: '250px' }}>
                      <Card.Body className="d-flex flex-column justify-content-between">
                        <div>
                          <Card.Title className="text-danger fs-3 mb-3 text-center">MetaData Reconnaissance</Card.Title>
                          <Card.Text className="text-white small fst-italic text-center mb-3">
                            Gather comprehensive intelligence about each web application to identify high-value targets for bug bounty hunting.
                          </Card.Text>
                          
                          {/* Show alert if viewing data from cancelled scan */}
                          {mostRecentMetaDataScan && mostRecentMetaDataScan.status === 'cancelled' && (
                            <Alert variant="warning" className="small mb-3 py-2">
                              <i className="bi bi-info-circle me-2"></i>
                              <strong>Partial Data:</strong> This scan was cancelled. You can view the data collected before cancellation.
                            </Alert>
                          )}
                          
                          {/* MetaData Scan Progress Section */}
                          <div className="mb-3">
                            <div className="d-flex justify-content-between align-items-center mb-2">
                              <div className="d-flex flex-column">
                                <div className="d-flex align-items-center mb-1">
                                  <span className={`fw-bold text-${
                                    mostRecentMetaDataScanStatus === 'running' || mostRecentMetaDataScanStatus === 'pending' ? 'danger' : 
                                    mostRecentMetaDataScanStatus === 'cancelling' ? 'warning' :
                                    mostRecentMetaDataScanStatus === 'success' ? 'success' : 
                                    mostRecentMetaDataScanStatus === 'cancelled' ? 'secondary' :
                                    mostRecentMetaDataScanStatus === 'error' || mostRecentMetaDataScanStatus === 'failed' ? 'danger' :
                                    'secondary'
                                  }`}>
                                    Status: {
                                      mostRecentMetaDataScanStatus === 'running' || mostRecentMetaDataScanStatus === 'pending' ? 'Running' :
                                      mostRecentMetaDataScanStatus === 'cancelling' ? 'Cancelling' :
                                      mostRecentMetaDataScanStatus === 'success' ? 'Completed' :
                                      mostRecentMetaDataScanStatus === 'cancelled' ? 'Cancelled' :
                                      mostRecentMetaDataScanStatus === 'error' || mostRecentMetaDataScanStatus === 'failed' ? 'Failed' :
                                      'Ready'
                                    }
                                  </span>
                                  {(mostRecentMetaDataScanStatus === 'running' || mostRecentMetaDataScanStatus === 'pending' || mostRecentMetaDataScanStatus === 'cancelling') && 
                                    <Spinner animation="border" size="sm" variant="danger" className="ms-2" />
                                  }
                                </div>
                                {mostRecentMetaDataScan && mostRecentMetaDataScan.created_at && (
                                  <div className="mb-1">
                                    <span className="text-white-50 small">Start Time: </span>
                                    <span className="text-white small">{new Date(mostRecentMetaDataScan.created_at).toLocaleTimeString()}</span>
                                  </div>
                                )}
                                {(mostRecentMetaDataScanStatus === 'running' || mostRecentMetaDataScanStatus === 'pending' || mostRecentMetaDataScanStatus === 'cancelling') && mostRecentMetaDataScan && mostRecentMetaDataScan.created_at && (
                                  <div className="mb-1">
                                    <span className="text-white-50 small">Elapsed: </span>
                                    <span className="text-white small">{metaDataElapsedTime}</span>
                                  </div>
                                )}
                              </div>
                              <div className="text-end">
                                {mostRecentMetaDataScan && mostRecentMetaDataScan.execution_time && (
                                  <div className="text-white-50 small">
                                    Duration: {mostRecentMetaDataScan.execution_time}
                                  </div>
                                )}
                              </div>
                            </div>
                            
                            {/* Current Step and URL Display */}
                            {(mostRecentMetaDataScanStatus === 'running' || mostRecentMetaDataScanStatus === 'pending' || mostRecentMetaDataScanStatus === 'cancelling') && (
                              <div className="mt-2 mb-2">
                                <div className="d-flex justify-content-between align-items-center">
                                  <div className="text-white-50 small">
                                    <span className={`text-${mostRecentMetaDataScanStatus === 'cancelling' ? 'warning' : 'danger'}`}>●</span>
                                    {mostRecentMetaDataScan && mostRecentMetaDataScan.current_step && (
                                      <span className="ms-2">
                                        {mostRecentMetaDataScan.current_step === 'initializing' ? 'Initializing scan...' :
                                         mostRecentMetaDataScan.current_step === 'screenshots' ? 'Capturing screenshots' :
                                         mostRecentMetaDataScan.current_step === 'katana' ? 'Web crawling with Katana' :
                                         mostRecentMetaDataScan.current_step === 'ssl' ? 'Analyzing SSL/TLS certificates' :
                                         mostRecentMetaDataScan.current_step === 'technology' ? 'Detecting technologies' :
                                         mostRecentMetaDataScan.current_step === 'ffuf' ? 'Directory fuzzing' :
                                         mostRecentMetaDataScan.current_step}
                                      </span>
                                    )}
                                  </div>
                                </div>
                                {mostRecentMetaDataScan && mostRecentMetaDataScan.current_url && (
                                  <div className="text-white-50 small mt-1" style={{ 
                                    overflow: 'hidden', 
                                    textOverflow: 'ellipsis',
                                    whiteSpace: 'nowrap'
                                  }}>
                                    <span className="text-secondary">↳</span> {mostRecentMetaDataScan.current_url}
                                  </div>
                                )}
                              </div>
                            )}
                            
                            {/* Progress Bar */}
                            {(mostRecentMetaDataScanStatus === 'running' || mostRecentMetaDataScanStatus === 'pending' || mostRecentMetaDataScanStatus === 'cancelling') && mostRecentMetaDataScan && (
                              <div className="mt-2">
                                <div className="d-flex justify-content-between mb-1">
                                  <span className="text-white-50 small">Overall Progress</span>
                                  <span className="text-white small">
                                    {mostRecentMetaDataScan.total_urls > 0 
                                      ? (() => {
                                          let config = null;
                                          try {
                                            config = mostRecentMetaDataScan.config ? JSON.parse(mostRecentMetaDataScan.config) : null;
                                          } catch (e) {
                                            config = null;
                                          }
                                          
                                          const enabledSteps = config?.steps || {
                                            screenshots: true,
                                            technology: true,
                                            ssl: true,
                                            katana: false,
                                            ffuf: false
                                          };
                                          
                                        const allStepWeights = {
                                          'initializing': 2,
                                          'screenshots': 25,
                                          'katana': 30,
                                          'technology': 15,
                                          'ssl': 20,
                                          'ffuf': 30
                                        };
                                        
                                        const activeSteps = Object.keys(enabledSteps).filter(key => enabledSteps[key] && allStepWeights[key]);
                                        const totalWeight = activeSteps.reduce((sum, step) => sum + allStepWeights[step], 0) + allStepWeights['initializing'];
                                        
                                        const normalizedWeights = {};
                                        normalizedWeights['initializing'] = (allStepWeights['initializing'] / totalWeight) * 95;
                                        activeSteps.forEach(step => {
                                          normalizedWeights[step] = (allStepWeights[step] / totalWeight) * 95;
                                        });
                                        
                                        const stepOrder = ['initializing', 'screenshots', 'katana', 'ssl', 'technology', 'ffuf'];
                                        const activeStepOrder = ['initializing'].concat(stepOrder.slice(1).filter(s => activeSteps.includes(s)));
                                        
                                        const completedStepsProgress = {};
                                        let accumulated = 0;
                                        activeStepOrder.forEach(step => {
                                          completedStepsProgress[step] = accumulated;
                                          accumulated += normalizedWeights[step];
                                        });
                                        
                                        const currentStep = mostRecentMetaDataScan.current_step || 'initializing';
                                        const baseProgress = completedStepsProgress[currentStep] || 0;
                                        const currentStepWeight = normalizedWeights[currentStep] || 0;
                                        const stepProgress = mostRecentMetaDataScan.processed_urls > 0 
                                          ? (mostRecentMetaDataScan.processed_urls / mostRecentMetaDataScan.total_urls) * currentStepWeight
                                          : 0;
                                        
                                        return Math.min(Math.round(baseProgress + stepProgress), 95);
                                        })()
                                      : 5}%
                                  </span>
                                </div>
                                <ProgressBar 
                                  now={mostRecentMetaDataScan.total_urls > 0 
                                    ? (() => {
                                        let config = null;
                                        try {
                                          config = mostRecentMetaDataScan.config ? JSON.parse(mostRecentMetaDataScan.config) : null;
                                        } catch (e) {
                                          config = null;
                                        }
                                        
                                        const enabledSteps = config?.steps || {
                                          screenshots: true,
                                          technology: true,
                                          ssl: true,
                                          katana: false,
                                          ffuf: false
                                        };
                                        
                                        const allStepWeights = {
                                          'initializing': 2,
                                          'screenshots': 25,
                                          'katana': 30,
                                          'technology': 15,
                                          'ssl': 20,
                                          'ffuf': 30
                                        };
                                        
                                        const activeSteps = Object.keys(enabledSteps).filter(key => enabledSteps[key] && allStepWeights[key]);
                                        const totalWeight = activeSteps.reduce((sum, step) => sum + allStepWeights[step], 0) + allStepWeights['initializing'];
                                        
                                        const normalizedWeights = {};
                                        normalizedWeights['initializing'] = (allStepWeights['initializing'] / totalWeight) * 95;
                                        activeSteps.forEach(step => {
                                          normalizedWeights[step] = (allStepWeights[step] / totalWeight) * 95;
                                        });
                                        
                                        const stepOrder = ['initializing', 'screenshots', 'katana', 'ssl', 'technology', 'ffuf'];
                                        const activeStepOrder = ['initializing'].concat(stepOrder.slice(1).filter(s => activeSteps.includes(s)));
                                        
                                        const completedStepsProgress = {};
                                        let accumulated = 0;
                                        activeStepOrder.forEach(step => {
                                          completedStepsProgress[step] = accumulated;
                                          accumulated += normalizedWeights[step];
                                        });
                                        
                                        const currentStep = mostRecentMetaDataScan.current_step || 'initializing';
                                        const baseProgress = completedStepsProgress[currentStep] || 0;
                                        const currentStepWeight = normalizedWeights[currentStep] || 0;
                                        const stepProgress = mostRecentMetaDataScan.processed_urls > 0 
                                          ? (mostRecentMetaDataScan.processed_urls / mostRecentMetaDataScan.total_urls) * currentStepWeight
                                          : 0;
                                        
                                        return Math.min(Math.round(baseProgress + stepProgress), 95);
                                      })()
                                    : 5}
                                  variant={mostRecentMetaDataScanStatus === 'cancelling' ? 'warning' : 'danger'}
                                  className="bg-dark" 
                                  style={{ height: '8px' }}
                                  animated={mostRecentMetaDataScanStatus !== 'cancelling'}
                                />
                              </div>
                            )}
                          </div>
                        </div>
                        
                        {/* Action Buttons */}
                        <div className="d-flex flex-column gap-3 w-100 mt-3">
                          <div className="d-flex justify-content-between gap-2">
                            <Button variant="outline-danger" className="flex-fill" onClick={handleOpenReconResultsModal}>Recon Results</Button>
                            <Button 
                              variant="outline-danger" 
                              className="flex-fill"
                              onClick={handleOpenConfigureMetaDataModal}
                              disabled={!mostRecentHttpxScan || 
                                      mostRecentHttpxScan.status !== "success" || 
                                      !httpxScans || 
                                      httpxScans.length === 0}
                            >
                              Configure
                            </Button>
                            <Button 
                              variant={(isMetaDataScanning || mostRecentMetaDataScanStatus === "pending" || mostRecentMetaDataScanStatus === "running" || mostRecentMetaDataScanStatus === "cancelling") ? "danger" : "outline-danger"}
                              className="flex-fill"
                              onClick={() => startMetaDataScan()}
                              disabled={
                                mostRecentMetaDataScanStatus === "cancelling" ? true :
                                (isMetaDataScanning || mostRecentMetaDataScanStatus === "pending" || mostRecentMetaDataScanStatus === "running") 
                                  ? false 
                                  : (!mostRecentHttpxScan || 
                                     mostRecentHttpxScan.status !== "success" || 
                                     !httpxScans || 
                                     httpxScans.length === 0)
                              }
                              style={{
                                cursor: (isMetaDataScanning || mostRecentMetaDataScanStatus === "pending" || mostRecentMetaDataScanStatus === "running") ? "pointer" : undefined
                              }}
                            >
                              <div className="btn-content">
                                {mostRecentMetaDataScanStatus === "cancelling" ? (
                                  <>
                                    <div className="spinner"></div>
                                    <span style={{ marginLeft: '8px' }}>Cancelling...</span>
                                  </>
                                ) : (isMetaDataScanning || mostRecentMetaDataScanStatus === "pending" || mostRecentMetaDataScanStatus === "running") ? (
                                  <>
                                    <div className="spinner"></div>
                                    <span style={{ marginLeft: '8px' }}>Cancel Scan</span>
                                  </>
                                ) : 'Gather Metadata'}
                              </div>
                            </Button>
                            <Button 
                              variant="outline-danger" 
                              className="flex-fill"
                              onClick={handleOpenMetaDataModal}
                              disabled={!mostRecentMetaDataScan || 
                                      (mostRecentMetaDataScan.status !== "success" && 
                                       mostRecentMetaDataScan.status !== "cancelled")}
                            >
                              View Metadata
                            </Button>
                            <Button 
                              variant="outline-danger" 
                              className="flex-fill"
                              onClick={handleOpenROIReport}
                              disabled={!mostRecentMetaDataScan || 
                                      (mostRecentMetaDataScan.status !== "success" && 
                                       mostRecentMetaDataScan.status !== "cancelled")}
                            >
                              ROI Report
                            </Button>
                          </div>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>

                <h4 className="text-secondary mb-3 fs-5">Nuclei Scanning</h4>
                <HelpMeLearn section="wildcardNucleiScanning" />
                <Row className="mb-4">
                  <Col>
                  <Card className="shadow-sm h-100 text-center" style={{ minHeight: '200px' }}>
                      <Card.Body className="d-flex flex-column">
                        <Card.Title className="text-danger fs-4 mb-3">
                          <a href="https://github.com/projectdiscovery/nuclei" className="text-danger text-decoration-none">
                            Nuclei Scanning
                          </a>
                        </Card.Title>
                        <Card.Text className="text-white small fst-italic mb-4">
                          Scan your live web servers for vulnerabilities using Nuclei templates. Configure individual templates, categories, and advanced settings for targeted security testing.
                        </Card.Text>
                        <div className="text-danger mb-4">
                          <div className="row row-cols-4">
                            <div className="col">
                              <div className="text-danger fw-bold fs-4">{getWildcardNucleiSelectedTargetsCount()}</div>
                              <div className="text-muted small card-metric-label">Selected Targets</div>
                            </div>
                            <div className="col">
                              <div className="text-danger fw-bold fs-4">{getWildcardNucleiSelectedTemplatesCount()}</div>
                              <div className="text-muted small card-metric-label">Selected Templates</div>
                            </div>
                            <div className="col">
                              <div className="text-danger fw-bold fs-4">{getWildcardNucleiTotalFindings()}</div>
                              <div className="text-muted small card-metric-label">Total Findings</div>
                            </div>
                            <div className="col">
                              <div className="text-danger fw-bold fs-4">{getWildcardNucleiImpactfulFindings()}</div>
                              <div className="text-muted small card-metric-label">Impactful Findings</div>
                            </div>
                          </div>
                        </div>
                        <div className="d-flex justify-content-between mt-auto gap-2">
                          <Button variant="outline-danger" className="flex-fill" onClick={handleOpenWildcardNucleiHistoryModal}>History</Button>
                          {/* Settings is the ENGINE flags (rate, concurrency, timeouts, retries).
                              Configure, next to it, is the existing targets-and-templates screen and is
                              untouched: two screens that both set templates is how a configuration comes
                              to contradict itself, so the registry deliberately owns neither here. */}
                          <Button variant="outline-danger" className="flex-fill" onClick={() => setWildcardConfigTool({ key: 'nuclei', name: 'Nuclei' })}>Settings</Button>
                          <Button variant="outline-danger" className="flex-fill" onClick={handleOpenWildcardNucleiConfigModal}>Configure</Button>
                          <Button 
                            variant="outline-danger" 
                            className="flex-fill"
                            disabled={isWildcardNucleiScanDisabled() || isWildcardNucleiScanning}
                            onClick={startWildcardNucleiScan}
                          >
                            {isWildcardNucleiScanning ? (
                              <Spinner animation="border" size="sm" />
                            ) : (
                              'Scan'
                            )}
                          </Button>
                          <Button variant="outline-danger" className="flex-fill" onClick={handleOpenWildcardNucleiResultsModal}>Results</Button>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>
              </div>
            )}
            {activeTarget.type === 'URL' && (
              <div className="mb-4">
                <h3 className="text-danger mb-3">URL</h3>
                <h4 className="text-secondary mb-3 fs-5">Starting Point</h4>
                <HelpMeLearn section="urlManualCrawling" />
                <Row className="mb-4">
                  <Col md={6}>
                    <Card className="shadow-sm h-100 text-center" style={{ minHeight: '200px' }}>
                      <Card.Body className="d-flex flex-column">
                        <Card.Title className="text-danger mb-3">
                          Manual Crawling
                        </Card.Title>
                        <Card.Text className="text-white small fst-italic">
                          Manually browse the application to discover authenticated areas, dynamic content, and endpoints that automated tools miss. Navigate as a real user to capture hidden functionality and attack surfaces.
                        </Card.Text>
                        {/* Liveness gets its own row above the counts: it is a status, not a number,
                            and it is heartbeat-derived so it reflects whether the extension is
                            genuinely recording right now. */}
                        <div className="text-center mt-2">
                          {manualCrawlConnected ? (
                            <div className="text-success">
                              <i className="bi bi-record-circle-fill me-2" style={{ fontSize: '0.8rem' }}></i>
                              <strong>Actively Recording Session</strong>
                            </div>
                          ) : (
                            <div className="text-muted">
                              <i className="bi bi-circle-fill me-2" style={{ fontSize: '0.6rem' }}></i>
                              No Active Recording
                            </div>
                          )}
                        </div>
                        <div className="mt-auto pt-3 mb-3">
                          <Row className="text-center align-items-center">
                            <Col>
                              <div className="text-danger fw-bold fs-4">{manualCrawlDirectCount}</div>
                              <div className="text-muted small card-metric-label">Direct Endpoints</div>
                            </Col>
                            <Col>
                              <div className="text-danger fw-bold fs-4">{manualCrawlAdjacentCount}</div>
                              <div className="text-muted small card-metric-label">Adjacent Endpoints</div>
                            </Col>
                            <Col>
                              <div className="text-danger fw-bold fs-4">{manualCrawlAdjacentHostCount}</div>
                              <div className="text-muted small card-metric-label">Adjacent Hosts</div>
                            </Col>
                            <Col>
                              <div className="text-danger fw-bold fs-4">{manualCrawlSessionCount}</div>
                              <div className="text-muted small card-metric-label">Crawl Sessions</div>
                            </Col>
                          </Row>
                        </div>
                        <div className="card-actions">
                          <Row className="g-2">
                            <Col>
                              <Button
                                variant="outline-danger"
                                className="w-100"
                                onClick={handleOpenExtensionInstallModal}
                              >
                                Install Extension
                              </Button>
                            </Col>
                            <Col>
                              <Button
                                variant="outline-danger"
                                className="w-100"
                                onClick={handleOpenTargetUrl}
                                disabled={!activeTarget || !activeTarget.scope_target}
                              >
                                Crawl Target URL
                              </Button>
                            </Col>
                            <Col>
                              <Button
                                variant="outline-danger"
                                className="w-100"
                                onClick={handleOpenManualCrawlResultsModal}
                              >
                                View Results
                              </Button>
                            </Col>
                          </Row>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                  <Col md={6}>
                    <Card className="shadow-sm h-100 text-center" style={{ minHeight: '200px' }}>
                      <Card.Body className="d-flex flex-column">
                        <Card.Title className="text-danger mb-3">Routing & WAF Probe</Card.Title>
                        <Card.Text className="text-white small fst-italic">
                          Characterize how the target routes requests, handles volume, and blocks traffic, then apply the measured limits to every tool in the workflow.
                        </Card.Text>
                        {/* The blocker gets its own row above the counts, same as the recording
                            indicator on the crawl card: it is the one thing that makes every
                            number below it moot, so it must not be a badge tucked beside them. */}
                        <div className="text-center mt-2">
                          {isWAFProbeScanning ? (
                            <div className="text-muted">
                              <Spinner animation="border" size="sm" className="me-2" />
                              Probing the target
                            </div>
                          ) : wafProbeCard.topBlocker ? (
                            <div className="text-danger">
                              <i className="bi bi-exclamation-triangle-fill me-2" style={{ fontSize: '0.8rem' }}></i>
                              <strong>{wafProbeCard.topBlocker}</strong>
                            </div>
                          ) : wafProbeCard.state === 'ok' && wafProbeCard.blockers > 0 ? (
                            // Guards against the message and the count contradicting each other if
                            // a blocker is ever counted without surfacing a title.
                            <div className="text-danger">
                              <i className="bi bi-exclamation-triangle-fill me-2" style={{ fontSize: '0.8rem' }}></i>
                              <strong>{wafProbeCard.blockers} finding(s) will break your scans</strong>
                            </div>
                          ) : wafProbeCard.posture && WAF_POSTURE[wafProbeCard.posture] ? (
                            // The card promises to characterise how the target BLOCKS traffic, and
                            // until now it never showed the answer: posture was computed and thrown
                            // away. With no blocker to report this is the most useful line the probe
                            // produces, so it takes the same slot rather than a badge beside the
                            // numbers.
                            <div className={WAF_POSTURE[wafProbeCard.posture].className}>
                              <i className={`bi ${WAF_POSTURE[wafProbeCard.posture].icon} me-2`} style={{ fontSize: '0.8rem' }}></i>
                              <strong>{WAF_POSTURE[wafProbeCard.posture].text}</strong>
                            </div>
                          ) : (
                            <div className="text-muted">
                              <i className="bi bi-circle-fill me-2" style={{ fontSize: '0.6rem' }}></i>
                              Never probed
                            </div>
                          )}
                        </div>

                        {/* The other two things the description promises: how it ROUTES and how it
                            handles VOLUME. Each renders only once the probe has established it, so an
                            un-run card stays honest rather than showing reassuring defaults. */}
                        {wafProbeCard.state === 'ok' && (
                          <div className="text-center mt-2 d-flex flex-column gap-1">
                            {wafProbeCard.rateLimited !== null && (
                              <div className="text-muted" style={{ fontSize: '0.75rem' }}>
                                <i className="bi bi-speedometer2 me-2"></i>
                                {wafProbeCard.rateLimited
                                  ? 'Rate limiting observed under load'
                                  : 'No rate limiting observed under load'}
                                {wafProbeCard.concurrency
                                  ? ` · throughput plateaus at ${wafProbeCard.concurrency} concurrent`
                                  : ''}
                              </div>
                            )}
                            {wafProbeCard.hostRoutingText && (
                              <div className="text-muted" style={{ fontSize: '0.75rem' }}>
                                <i className="bi bi-diagram-3 me-2"></i>
                                {wafProbeCard.hostRoutingText}
                              </div>
                            )}
                          </div>
                        )}

                        <div className="mt-auto pt-3 mb-3">
                          <Row className="text-center align-items-start">
                            <Col>
                              {/* Intent, not history: how many endpoints the NEXT run will cover. */}
                              <div className={`fw-bold fs-4 ${(wafProbeCard.targetsInFlightRun || wafProbeTargetCount) ? 'text-danger' : 'text-secondary'}`}>
                                {wafProbeCard.targetsInFlightRun
                                  || (wafProbeTargetCount === null ? '-' : wafProbeTargetCount)}
                              </div>
                              <div className="text-muted small card-metric-label">Targets Configured</div>
                            </Col>
                            <Col>
                              <div className={`fw-bold fs-4 ${wafProbeCard.targetsScanned ? 'text-danger' : 'text-secondary'}`}>
                                {wafProbeCard.targetsScanned || '-'}
                              </div>
                              <div className="text-muted small card-metric-label">Targets Scanned</div>
                            </Col>
                            <Col title={wafProbeCard.rateNote || undefined}>
                              {/* Muted when the rate is not a measurement, so an assumed default
                                  cannot be mistaken for something the probe observed. The confidence
                                  wording moved off the card into this tooltip: the distinction between
                                  a measured rate and an assumed one still matters, it just no longer
                                  needs a permanent line. */}
                              <div className={`fw-bold fs-4 ${wafProbeCard.rateMeasured ? 'text-danger' : 'text-secondary'}`}>
                                {wafProbeCard.rate ? `${wafProbeCard.rate}` : '-'}
                              </div>
                              <div className="text-muted small card-metric-label">Recommended Req/s</div>
                            </Col>
                            <Col>
                              <div className={`fw-bold fs-4 ${wafProbeCard.blockers ? 'text-danger' : 'text-secondary'}`}>
                                {wafProbeCard.state === 'ok' ? wafProbeCard.blockers : '-'}
                              </div>
                              <div className="text-muted small card-metric-label">Blockers</div>
                              {wafProbeCard.blockers > 0 && (
                                <div className="text-muted" style={{ fontSize: '0.68rem' }}>
                                  will break scans
                                </div>
                              )}
                            </Col>
                          </Row>
                        </div>

                        <div className="card-actions">
                          {wafProbeRunError && (
                            <Alert variant="danger" className="py-1 px-2 mb-2"
                                   style={{ fontSize: '0.7rem' }}
                                   dismissible onClose={() => setWafProbeRunError('')}>
                              {wafProbeRunError}
                            </Alert>
                          )}
                          <div className="d-flex justify-content-center gap-2">
                            <Button
                              variant="outline-danger"
                              className="flex-fill"
                              onClick={() => setShowWAFProbeConfigModal(true)}
                              disabled={!activeTarget || isWAFProbeScanning}
                            >
                              Configure
                            </Button>
                            <Button
                              variant="outline-danger"
                              className="flex-fill"
                              onClick={() => startWAFProbeScan()}
                              disabled={!activeTarget || isWAFProbeScanning}
                            >
                              <div className="btn-content">
                                {isWAFProbeScanning ? (
                                  <Spinner animation="border" size="sm" />
                                ) : (
                                  'Scan'
                                )}
                              </div>
                            </Button>
                            <Button
                              variant="outline-danger"
                              className="flex-fill"
                              onClick={handleOpenWAFProbeResultsModal}
                              // Any scan with a result is worth opening, not just the newest. In a
                              // multi-endpoint run the newest scan is the LAST endpoint, which sits
                              // pending while the earlier ones finish; keying off it alone disabled
                              // this button for most of a run that already had results to show.
                              disabled={!wafProbeScans.some((s) => s?.result)}
                            >
                              Results
                            </Button>
                          </div>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>

                <h4 className="text-secondary mb-3 fs-5 mt-4">Authentication</h4>
                <HelpMeLearn section="urlAuthentication" />
                <Row className="mb-4">
                  <Col md={12}>
                    <Card className="shadow-sm h-100 text-center" style={{ minHeight: '200px' }}>
                      <Card.Body className="d-flex flex-column">
                        <Card.Title className="text-danger mb-3">
                          Authentication
                        </Card.Title>
                        <Card.Text className="text-white small fst-italic">
                          Record a real authentication against the target with the browser extension, or write the requests out by hand, then keep the session tokens those flows produce. Every token is tied to the flow that can mint another one, so when a session dies the framework can go and get a new one instead of quietly testing a login wall.
                        </Card.Text>
                        <Row className="g-3 justify-content-center mt-1 mb-2">
                          <Col xs={6} md={3}>
                            <div className="fs-3 fw-bold text-danger">{authFlowCounts.total ?? 0}</div>
                            <div className="text-white small pb-4">Auth Flows</div>
                          </Col>
                          <Col xs={6} md={3}>
                            <div className="fs-3 fw-bold text-danger">{authFlowCounts.recorded ?? 0}</div>
                            <div className="text-white small pb-4">Recorded</div>
                          </Col>
                          <Col xs={6} md={3}>
                            <div className="fs-3 fw-bold text-danger">{sessionTokenCounts.total ?? 0}</div>
                            <div className="text-white small pb-4">Session Tokens</div>
                          </Col>
                          <Col xs={6} md={3}>
                            {/* Active is the number that matters: it is what the other tools will
                                actually send. Zero active tokens with a full list is the state that
                                makes every scan report a login wall. */}
                            <div className={`fs-3 fw-bold ${(sessionTokenCounts.active ?? 0) > 0 ? 'text-danger' : 'text-secondary'}`}>
                              {sessionTokenCounts.active ?? 0}
                            </div>
                            <div className="text-white small pb-4">Active</div>
                          </Col>
                        </Row>
                        <div className="mt-auto">
                          <Row className="g-2">
                            <Col>
                              <Button variant="outline-danger" className="w-100"
                                      onClick={handleOpenRecordAuthFlowsModal} disabled={!activeTarget}>
                                Record Auth Flows
                              </Button>
                            </Col>
                            <Col>
                              <Button variant="outline-danger" className="w-100"
                                      onClick={handleOpenManualAuthFlowModal} disabled={!activeTarget}>
                                Manual Auth Flows
                              </Button>
                            </Col>
                            <Col>
                              <Button variant="outline-danger" className="w-100"
                                      onClick={handleOpenManageSessionsModal} disabled={!activeTarget}>
                                Manage Sessions
                              </Button>
                            </Col>
                            <Col>
                              <Button variant="outline-danger" className="w-100"
                                      onClick={handleOpenRefreshSessionModal} disabled={!activeTarget}>
                                Refresh Session
                              </Button>
                            </Col>
                          </Row>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>

                <h4 className="text-secondary mb-3 fs-5 mt-4">Authorization</h4>
                <HelpMeLearn section="urlAuthorization" />
                <Row className="mb-4">
                  <Col md={12}>
                    <Card className="shadow-sm h-100 text-center" style={{ minHeight: '200px' }}>
                      <Card.Body className="d-flex flex-column">
                        <Card.Title className="text-danger mb-3">
                          Authorization
                        </Card.Title>
                        <Card.Text className="text-white small fst-italic">
                          Model how this application decides who may do what, so later testing knows what should have been refused. Identity patterns record how the server works out who is asking and how much of that the caller controls; the three access-control sections record the rules the application claims to enforce.
                        </Card.Text>
                        <Row className="g-3 justify-content-center mt-1 mb-2">
                          <Col xs={6} md={3}>
                            {/* Parameter-based identity is the count that matters here: it is the
                                one where the caller controls the id outright, so it is where IDOR
                                testing actually starts. */}
                            <div className="fs-3 fw-bold text-danger">{authzCounts.parameter ?? 0}</div>
                            <div className="text-white small pb-4">Attacker-Controlled IDs</div>
                          </Col>
                          <Col xs={6} md={3}>
                            <div className="fs-3 fw-bold text-danger">{authzCounts.patterns ?? 0}</div>
                            <div className="text-white small pb-4">Identity Patterns</div>
                          </Col>
                          <Col xs={6} md={3}>
                            <div className="fs-3 fw-bold text-danger">{authzCounts.rules ?? 0}</div>
                            <div className="text-white small pb-4">Access Rules Modelled</div>
                          </Col>
                          <Col xs={6} md={3}>
                            {/* Forbidden cells are the only ones whose violation is automatically a
                                finding, so they get their own number. */}
                            <div className="fs-3 fw-bold text-danger">{authzCounts.forbidden ?? 0}</div>
                            <div className="text-white small pb-4">Forbidden Actions</div>
                          </Col>
                        </Row>
                        <div className="mt-auto">
                          <Row className="g-2">
                            <Col>
                              <Button variant="outline-danger" className="w-100"
                                      onClick={handleOpenClientIdentityModal} disabled={!activeTarget}>
                                Client Identity Patterns
                              </Button>
                            </Col>
                            <Col>
                              <Button variant="outline-danger" className="w-100"
                                      onClick={handleOpenPolicyAccessModal} disabled={!activeTarget}>
                                Policy-Based Access Controls
                              </Button>
                            </Col>
                            <Col>
                              <Button variant="outline-danger" className="w-100"
                                      onClick={handleOpenRoleAccessModal} disabled={!activeTarget}>
                                Role-Based Access Controls
                              </Button>
                            </Col>
                            <Col>
                              <Button variant="outline-danger" className="w-100"
                                      onClick={handleOpenDiscretionaryAccessModal} disabled={!activeTarget}>
                                Discretionary Access Controls
                              </Button>
                            </Col>
                          </Row>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>

                {/* Split in two because the two halves cost completely different things. Nothing
                    in the first row crawls the application: Waybackurls and GAU read public
                    archives, and LinkFinder reads JavaScript that has already been fetched. The
                    second row walks the live target and has to be paced by what the probe measured. */}
                <h4 className="text-secondary mb-3 fs-5 mt-4">Archive &amp; JavaScript Mining</h4>
                <HelpMeLearn section="urlDiscovery" />
                <Row className="mb-4">
                  {[
                    {
                      name: 'Waybackurls',
                      link: 'https://github.com/tomnomnom/waybackurls',
                      description: 'Fetch every URL the Wayback Machine knows about. Configure which hosts it asks about: by default the direct host and every in-scope adjacent host, queried one at a time. Queries the archive, never the target.',
                      isActive: true,
                      status: mostRecentWaybackURLsScanStatus,
                      isScanning: isWaybackURLsScanning,
                      onScan: startWaybackURLsScan,
                      onResults: handleOpenWaybackURLsResultsModal,
                      onConfig: () => setCrawlerConfigTool('waybackurls'),
                      secondaryLabel: 'Scan Targets',
                      secondaryCount: (archiveHostCounts.waybackurls
                        ? `${archiveHostCounts.waybackurls.selected} / ${archiveHostCounts.waybackurls.total}`
                        : '-'),
                      resultCount: countURLToolEndpoints(mostRecentWaybackURLsScan),
                      resultLabel: 'Endpoints'
                    },
                    {
                      name: 'LinkFinder',
                      link: 'https://github.com/GerbenJavado/LinkFinder',
                      description: 'Reads crawled JS files',
                      isActive: true,
                      status: mostRecentLinkFinderURLScanStatus,
                      isScanning: isLinkFinderURLScanning,
                      onScan: startLinkFinderURLScan,
                      onResults: handleOpenLinkFinderURLResultsModal,
                      onConfig: () => setCrawlerConfigTool('linkfinder'),
                      secondaryLabel: 'JS Files',
                      // scanned / available, not available alone. LinkFinder reads discovered
                      // JavaScript by default but stops at maxJsFiles and never says so, so the
                      // ratio is the only place the truncation shows.
                      secondaryCount: (linkFinderJS
                        ? `${linkFinderJS.scanned} / ${linkFinderJS.available}`
                        : '-'),
                      resultCount: countURLToolEndpoints(mostRecentLinkFinderURLScan),
                      resultLabel: 'Endpoints'
                    },
                    {
                      name: 'GAU',
                      link: 'https://github.com/lc/gau',
                      description: 'Get All URLs - Fetch known URLs from AlienVault\'s OTX, Wayback Machine, and Common Crawl. Queries archives, never the target.',
                      isActive: true,
                      status: mostRecentGAUURLScanStatus,
                      isScanning: isGAUURLScanning,
                      onScan: startGAUURLScan,
                      onResults: handleOpenGAUURLResultsModal,
                      onConfig: () => setCrawlerConfigTool('gau'),
                      secondaryLabel: 'Scan Targets',
                      secondaryCount: (archiveHostCounts.gau
                        ? `${archiveHostCounts.gau.selected} / ${archiveHostCounts.gau.total}`
                        : '-'),
                      resultCount: countURLToolEndpoints(mostRecentGAUURLScan),
                      resultLabel: 'Endpoints'
                    }
                  ].map((tool) => (
                    <URLToolCard key={tool.name} tool={tool} />
                  ))}
                </Row>

                <h4 className="text-secondary mb-3 fs-5 mt-4">Live Target Crawling</h4>
                <HelpMeLearn section="urlDiscovery" />
                <Row className="mb-4">
                  {[
                    {
                      name: 'Katana',
                      link: 'https://github.com/projectdiscovery/katana',
                      description: 'A next-generation crawling and spidering framework for discovering URLs and endpoints. Every request hits the target, so pace it with the probe.',
                      isActive: true,
                      status: mostRecentKatanaURLScanStatus,
                      isScanning: isKatanaURLScanning,
                      onScan: startKatanaURLScan,
                      onResults: handleOpenKatanaURLResultsModal,
                      onConfig: () => setCrawlerConfigTool('katana'),
                      resultCount: countURLToolEndpoints(mostRecentKatanaURLScan),
                      resultLabel: 'Endpoints'
                    },
                    {
                      name: 'GoSpider',
                      link: 'https://github.com/jaeles-project/gospider',
                      description: 'Fast Go-based web crawler for large-scale link enumeration with concurrent crawling and third-party source integration.',
                      isActive: true,
                      status: mostRecentGoSpiderURLScanStatus,
                      isScanning: isGoSpiderURLScanning,
                      onScan: startGoSpiderURLScan,
                      onResults: handleOpenGoSpiderURLResultsModal,
                      onConfig: () => setCrawlerConfigTool('gospider'),
                      resultCount: countURLToolEndpoints(mostRecentGoSpiderURLScan),
                      resultLabel: 'Endpoints'
                    }
                  ].map((tool) => (
                    <URLToolCard key={tool.name} tool={tool} />
                  ))}
                </Row>

                <h4 className="text-secondary mb-3 fs-5 mt-4">Target URL Endpoints</h4>
                <HelpMeLearn section="urlTargetEndpoints" />
                <Row className="mb-4">
                  <Col md={12}>
                    <Card className="shadow-sm h-100 text-center" style={{ minHeight: '250px' }}>
                      <Card.Body className="d-flex flex-column">
                        <Card.Title className="text-danger mb-3">
                          Consolidate Endpoints
                        </Card.Title>
                        <Card.Text className="text-white small fst-italic">
                          Fold everything the crawlers, the archives and the manual crawl found into one list of unique endpoint and verb combinations. Investigate then runs both halves as one scan: it validates each endpoint against a control taken from its own directory to separate real pages from the target's catch-all, then gathers detail on everything validation did not rule out.
                        </Card.Text>

                        {/* A refusal to run is the most useful thing this workflow says. It belongs
                            on the card, not in the console. */}
                        {endpointWorkflowError && (
                          <Alert variant="warning" className="py-2 small text-start mb-2"
                                 dismissible onClose={() => setEndpointWorkflowError('')}>
                            {endpointWorkflowError}
                          </Alert>
                        )}

                        <div className="mt-auto pt-3 mb-3">
                          <Row className="text-center align-items-start">
                            <Col>
                              <div className="text-danger fw-bold fs-4">{consolidatedEndpointCount}</div>
                              <div className="text-muted small card-metric-label">Endpoints</div>
                              <div className="text-muted" style={{ fontSize: '0.68rem' }}>
                                unique url + verb
                              </div>
                            </Col>
                            <Col>
                              <div className="text-danger fw-bold fs-4">
                                {verdictCount('valid')}
                              </div>
                              <div className="text-muted small card-metric-label">Valid</div>
                              <div className="text-muted" style={{ fontSize: '0.68rem' }}>
                                distinct real pages
                              </div>
                            </Col>
                            <Col>
                              <div className="text-secondary fw-bold fs-4">
                                {verdictCount('unverified')}
                              </div>
                              <div className="text-muted small card-metric-label">Unverified</div>
                              <div className="text-muted" style={{ fontSize: '0.68rem' }}>
                                still tested
                              </div>
                            </Col>
                            <Col>
                              <div className="text-secondary fw-bold fs-4">
                                {verdictCount('ruled_out')}
                              </div>
                              <div className="text-muted small card-metric-label">Ruled Out</div>
                              <div className="text-muted" style={{ fontSize: '0.68rem' }}>
                                catch-all or gone
                              </div>
                            </Col>
                          </Row>
                        </div>

                        <div className="card-actions">
                          <div className="d-flex gap-2">
                            <Button
                              variant="outline-danger"
                              className="flex-fill"
                              onClick={handleConsolidateEndpoints}
                              disabled={!activeTarget || isConsolidatingEndpoints || isEndpointScanRunning}
                            >
                              {isConsolidatingEndpoints ? (
                                <><Spinner animation="border" size="sm" className="me-2" />Consolidating...</>
                              ) : (
                                'Consolidate'
                              )}
                            </Button>
                            {/* One button for both phases. Validate cannot be run out of order or
                                skipped, because investigating an unvalidated target profiles its
                                catch-all page once per endpoint and reports it as findings. */}
                            <Button
                              variant="outline-danger"
                              className="flex-fill"
                              onClick={() => handleInvestigateEndpoints()}
                              disabled={!activeTarget || isEndpointScanRunning || isConsolidatingEndpoints || consolidatedEndpointCount === 0}
                            >
                              {isEndpointScanRunning ? (
                                <><Spinner animation="border" size="sm" className="me-2" />
                                  {endpointScanProgressLabel}</>
                              ) : (
                                'Investigate'
                              )}
                            </Button>
                            <Button
                              variant="outline-danger"
                              className="flex-fill"
                              onClick={handleOpenEndpointScanResultsModal}
                              disabled={!activeTarget || !endpointScanRun}
                            >
                              Results
                            </Button>
                            <Button
                              variant="outline-danger"
                              className="flex-fill"
                              onClick={handleOpenManageEndpointsModal}
                              disabled={!activeTarget}
                            >
                              Manage Endpoints
                            </Button>
                          </div>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>

                {/* Both sections guess at input the app never advertised. They are split by HOW they
                    guess, because that decides what a run costs and what its output means.

                    Chunking sends a batch of candidate names at once and bisects the batch when the
                    response changes, so it finds parameters in a number of requests closer to the log
                    of the wordlist than to its length. Brute force sends one request per word. */}
                <h4 className="text-secondary mb-3 fs-5 mt-4">Hidden Attack Vector Fuzzing - Chunking</h4>
                <HelpMeLearn section="urlHiddenAttackVectorFuzzingChunking" />
                <Row className="mb-4">
                  <Col md={6}>
                    <Card className="shadow-sm h-100 text-center" style={{ minHeight: '250px' }}>
                      <Card.Body className="d-flex flex-column">
                        <Card.Title className="text-danger mb-3">
                          <a href="https://github.com/s0md3v/Arjun" className="text-danger text-decoration-none" target="_blank" rel="noopener noreferrer">
                            Arjun
                          </a>
                        </Card.Title>
                        <Card.Text className="text-white small fst-italic">
                          Brute-forces hidden HTTP parameters (GET/POST/JSON/XML) using a large built-in wordlist. Fast and accurate.
                        </Card.Text>
                        <div className="mt-auto pt-3 mb-3">
                          <Row className="text-center align-items-center">
                            <Col>
                              <div className="text-danger fw-bold fs-4">
                                {paramTargetCounts.arjun
                                  ? `${paramTargetCounts.arjun.enabled}/${paramTargetCounts.arjun.total}`
                                  : '-'}
                              </div>
                              <div className="text-muted small card-metric-label">Targets Enabled</div>
                            </Col>
                            <Col>
                              <div className="text-danger fw-bold fs-4">
                                {mostRecentArjunScan?.parameters_found || 0}
                              </div>
                              <div className="text-muted small card-metric-label">Parameters Found</div>
                            </Col>
                          </Row>
                        </div>
                        <div className="card-actions">
                          {/* Config, Scan, Results: the order the operator actually works in. */}
                          <div className="d-flex justify-content-center gap-2">
                            <Button
                              variant="outline-danger"
                              className="flex-fill"
                              onClick={handleOpenArjunConfigModal}
                              disabled={!activeTarget}
                            >
                              Config
                            </Button>
                            <Button
                              variant="outline-danger"
                              className="flex-fill"
                              onClick={startArjunScan}
                              disabled={!activeTarget || isArjunScanning}
                            >
                              <div className="btn-content">
                                {isArjunScanning ? (
                                  <Spinner animation="border" size="sm" />
                                ) : (
                                  'Scan'
                                )}
                              </div>
                            </Button>
                            <Button
                              variant="outline-danger"
                              className="flex-fill"
                              onClick={handleOpenArjunResultsModal}
                              disabled={!activeTarget || mostRecentArjunScanStatus !== 'success'}
                            >
                              Results
                            </Button>
                          </div>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>

                  {/* x8 sits beside Arjun rather than with FFUF: both ask "does this endpoint read a
                      parameter it never advertised", and both answer it a batch at a time. x8 differs
                      in WHERE it injects, not in how it searches. */}
                  <Col md={6}>
                    <Card className="shadow-sm h-100 text-center" style={{ minHeight: '250px' }}>
                      <Card.Body className="d-flex flex-column">
                        <Card.Title className="text-danger mb-3">
                          <a href="https://github.com/Sh1Yo/x8" className="text-danger text-decoration-none" target="_blank" rel="noopener noreferrer">
                            x8
                          </a>
                        </Card.Title>
                        <Card.Text className="text-white small fst-italic">
                          Rust parameter fuzzer that injects candidates into the query, body, headers or cookies, learns the target's normal response variation, then bisects a batch to find which parameter caused a difference.
                        </Card.Text>
                        <div className="mt-auto pt-3 mb-3">
                          <Row className="text-center align-items-center">
                            <Col>
                              {/* While a run is going this becomes the endpoint counter: a pass covers
                                  up to four injection places and takes as long as it takes, so it is
                                  the difference between "working" and "hung" from the operator's
                                  side. */}
                              <div className="text-danger fw-bold fs-4">
                                {isX8Scanning && mostRecentX8Scan?.total_endpoints
                                  ? `${mostRecentX8Scan.processed_endpoints || 0}/${mostRecentX8Scan.total_endpoints}`
                                  : paramTargetCounts.x8
                                    ? `${paramTargetCounts.x8.enabled}/${paramTargetCounts.x8.total}`
                                    : '-'}
                              </div>
                              <div className="text-muted small card-metric-label">
                                {isX8Scanning && mostRecentX8Scan?.total_endpoints
                                  ? 'Endpoints Scanned' : 'Targets Enabled'}
                              </div>
                            </Col>
                            <Col>
                              <div className="text-danger fw-bold fs-4">
                                {mostRecentX8Scan?.parameters_found || 0}
                              </div>
                              <div className="text-muted small card-metric-label">Parameters Found</div>
                            </Col>
                          </Row>
                          {!isX8Scanning && mostRecentX8ScanStatus === 'partial' && (
                            <div className="text-danger small text-center mt-2">
                              Some passes failed
                            </div>
                          )}
                          {!isX8Scanning && mostRecentX8ScanStatus === 'error' && (
                            <div className="text-danger small text-center mt-2">Scan failed</div>
                          )}
                        </div>
                        <div className="card-actions">
                          <div className="d-flex justify-content-center gap-2">
                            <Button
                              variant="outline-danger"
                              className="flex-fill"
                              onClick={handleOpenX8ConfigModal}
                              disabled={!activeTarget}
                            >
                              Config
                            </Button>
                            <Button
                              variant="outline-danger"
                              className="flex-fill"
                              onClick={startX8Scan}
                              disabled={!activeTarget || isX8Scanning}
                            >
                              <div className="btn-content">
                                {isX8Scanning ? (
                                  <Spinner animation="border" size="sm" />
                                ) : (
                                  'Scan'
                                )}
                              </div>
                            </Button>
                            {/* 'partial' counts: it means one pass failed and the others produced
                                real findings, so gating on 'success' alone made those findings
                                unreachable. 'error' is also allowed through, because the modal is
                                where the failure reason is shown. */}
                            <Button
                              variant="outline-danger"
                              className="flex-fill"
                              onClick={handleOpenX8ResultsModal}
                              disabled={!activeTarget || !mostRecentX8Scan ||
                                mostRecentX8ScanStatus === 'pending' ||
                                mostRecentX8ScanStatus === 'running'}
                            >
                              Results
                            </Button>
                          </div>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>

                {/* FFUF is on its own because it is the only tool here that spends one request per
                    word. That is what makes its settings and its wordlist worth a screen of their
                    own: the difference between a good filter and none is thousands of requests and a
                    result set nobody can read. */}
                <h4 className="text-secondary mb-3 fs-5 mt-4">Hidden Attack Vector Fuzzing - Brute Force</h4>
                <HelpMeLearn section="urlHiddenAttackVectorFuzzingBruteForce" />
                <Row className="mb-4">
                  <Col md={12}>
                    <Card className="shadow-sm h-100 text-center" style={{ minHeight: '250px' }}>
                      <Card.Body className="d-flex flex-column">
                        <Card.Title className="text-danger mb-3">
                          <a href="https://github.com/ffuf/ffuf" className="text-danger text-decoration-none" target="_blank" rel="noopener noreferrer">
                            FFUF
                          </a>
                        </Card.Title>
                        <Card.Text className="text-white small fst-italic">
                          Fast web fuzzer written in Go. Brute force endpoints, parameters, directories, and more with custom wordlists and extensive filtering options.
                        </Card.Text>
                        <div className="mt-auto pt-3 mb-3">
                          <Row className="text-center align-items-center">
                            <Col>
                              <div className="text-danger fw-bold fs-4">
                                {ffufFlowSteps.total > 0
                                  ? `${ffufFlowSteps.enabled}/${ffufFlowSteps.total}`
                                  : '-'}
                              </div>
                              <div className="text-muted small card-metric-label">Scans Enabled</div>
                            </Col>
                            <Col>
                              <div className="text-danger fw-bold fs-4">
                                {ffufNotableCount === null ? (ffufFindingCount ?? 0) : ffufNotableCount}
                              </div>
                              <div className="text-muted small card-metric-label">
                                {ffufNotableCount !== null && ffufNotableCount !== ffufFindingCount
                                  ? `Worth Review (${ffufFindingCount} stored)`
                                  : 'Findings'}
                              </div>
                            </Col>
                          </Row>

                          {/* What the flow is doing, while it does it. A spinner on the button said
                              only "something is happening", which on a flow of nine rounds against
                              several hosts, each of which can take many minutes, is the same as
                              saying nothing. */}
                          {isFFUFRunning && (
                            <div className="mt-3">
                              <div className="d-flex justify-content-between align-items-baseline">
                                <span className="text-white small">
                                  {ffufRun?.steps_total
                                    ? `Scan ${Math.min((ffufRun.steps_done || 0) + 1, ffufRun.steps_total)} of ${ffufRun.steps_total}`
                                    : 'Starting'}
                                </span>
                                <span className="text-white-50" style={{ fontSize: '0.75rem' }}>
                                  {ffufRun?.findings_new > 0 ? `${ffufRun.findings_new} new` : ''}
                                </span>
                              </div>
                              {ffufRun?.current_step && (
                                <div className="text-white-50 text-truncate"
                                  style={{ fontSize: '0.72rem' }}
                                  title={`${ffufRun.current_step.name} on ${ffufRun.current_step.host}`}>
                                  {ffufRun.current_step.name || 'unnamed step'}
                                  {ffufRun.current_step.host ? ` on ${ffufRun.current_step.host}` : ''}
                                </div>
                              )}
                              <div className="progress mt-1" style={{ height: '4px' }}>
                                <div className="progress-bar bg-danger"
                                  style={{
                                    width: `${ffufRun?.steps_total
                                      ? Math.round(((ffufRun.steps_done || 0) / ffufRun.steps_total) * 100)
                                      : 0}%`,
                                  }} />
                              </div>
                            </div>
                          )}

                          {/* A run that refused steps, or ended badly, said so once in an alert the
                              operator may not have been looking at. */}
                          {!isFFUFRunning && ffufRun && ffufRun.steps_blocked > 0 && (
                            <div className="text-danger small text-center mt-2">
                              {ffufRun.steps_blocked} step(s) were refused before the last run started
                            </div>
                          )}
                          {!isFFUFRunning && ffufRun && ffufRun.status === 'error' && (
                            <div className="text-danger small text-center mt-2">Last run failed</div>
                          )}
                          {!isFFUFRunning && ffufRun && ffufRun.status === 'cancelled' && (
                            <div className="text-white-50 small text-center mt-2">
                              Last run was cancelled
                            </div>
                          )}
                        </div>
                        <div className="card-actions">
                          {/* Settings, Configure, Scan, Results: settings first because they apply to
                              every round the flow contains, so they are the thing to get right before
                              building any of them. One Scan button, because which of endpoints,
                              headers and cookies gets fuzzed is a configuration decision rather than
                              three separate buttons. */}
                          <div className="d-flex justify-content-center gap-2">
                            <Button
                              variant="outline-danger"
                              className="flex-fill"
                              onClick={handleOpenFFUFSettingsModal}
                              disabled={!activeTarget}
                            >
                              Settings
                            </Button>
                            <Button
                              variant="outline-danger"
                              className="flex-fill"
                              onClick={handleOpenFFUFConfigModal}
                              disabled={!activeTarget}
                            >
                              Configure
                            </Button>
                            <Button
                              variant="outline-danger"
                              className="flex-fill"
                              onClick={startFFUFFlow}
                              disabled={!activeTarget || isFFUFRunning}
                            >
                              <div className="btn-content">
                                {isFFUFRunning ? (
                                  <Spinner animation="border" size="sm" />
                                ) : (
                                  'Scan'
                                )}
                              </div>
                            </Button>
                            <Button
                              variant="outline-danger"
                              className="flex-fill"
                              onClick={handleOpenFFUFURLResultsModal}
                              disabled={!activeTarget}
                            >
                              Results
                            </Button>
                          </div>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>

                <h4 className="text-secondary mb-3 fs-5 mt-4">Consolidate Attack Vectors</h4>
                <HelpMeLearn section="urlConsolidateAttackVectors" />
                <Row className="mb-4">
                  <Col md={12}>
                    <Card className="shadow-sm h-100 text-center" style={{ minHeight: '200px' }}>
                      <Card.Body className="d-flex flex-column">
                        <Card.Title className="text-danger mb-3">
                          Consolidate Attack Vectors
                        </Card.Title>
                        <Card.Text className="text-white small fst-italic">
                          An attack vector is one request carrying user-controlled input the application
                          actually processes: a verb, a host, a path, the parameters in play, and the
                          single place a payload goes. Consolidate folds everything the crawls, the
                          archives, Arjun, x8 and FFUF found into one list of unique vectors to test.
                        </Card.Text>
                        {/* Metrics and buttons in one bottom-pinned block so the label row sits the
                            same distance above the buttons as it does on every other card. */}
                        <div className="mt-auto">
                          {/* TOTAL first, then coverage BY INSERTION POINT. The five points sum to
                              the total, so showing the total alongside them says how much work there
                              is AND what it covers. A point at zero is greyed rather than explained:
                              it is the reason every tool below will report nothing wrong with that
                              insertion point. */}
                          {attackVectorCoverage && (
                            <Row className="text-center align-items-center mb-3">
                              <Col>
                                {/* The server's own total, not a client-side sum of the five points.
                                    They do agree today, but a vector whose insertion point the
                                    coverage endpoint does not enumerate would be silently dropped
                                    from a summed figure while still being scanned. */}
                                <div className={`fw-bold fs-4 ${attackVectorCounts.total > 0 ? 'text-danger' : 'text-secondary'}`}>
                                  {attackVectorCounts.total ?? 0}
                                </div>
                                <div className="text-muted small card-metric-label">Total Vectors</div>
                              </Col>
                              {(attackVectorCoverage.points || []).map((point) => {
                                const n = (attackVectorCoverage.by_insertion_point || {})[point] ?? 0;
                                return (
                                  <Col key={point}>
                                    <div className={`fw-bold fs-4 ${n > 0 ? 'text-danger' : 'text-secondary'}`}>
                                      {n}
                                    </div>
                                    <div className="text-muted small card-metric-label">{point}</div>
                                  </Col>
                                );
                              })}
                            </Row>
                          )}
                          <Row className="g-2">
                            <Col>
                              <Button variant="outline-danger" className="w-100"
                                onClick={handleConsolidateAttackVectors}
                                disabled={!activeTarget || isConsolidatingAttackVectors}>
                                <div className="btn-content">
                                  {isConsolidatingAttackVectors
                                    ? <Spinner animation="border" size="sm" />
                                    : 'Consolidate'}
                                </div>
                              </Button>
                            </Col>
                            <Col>
                              <Button variant="outline-danger" className="w-100"
                                onClick={handleAddAttackVectorManually} disabled={!activeTarget}>
                                Add Manually
                              </Button>
                            </Col>
                            <Col>
                              <Button variant="outline-danger" className="w-100"
                                onClick={handleOpenUniqueAttackVectorsModal} disabled={!activeTarget}>
                                Unique Attack Vectors
                              </Button>
                            </Col>
                          </Row>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>

                {/* Testing the vectors. Each section is one vulnerability class and the tools that
                    find it; the cards come from data/attackTools.js so a tool is added by editing
                    data rather than by copying a hundred lines of markup. */}
                {ATTACK_TOOL_SECTIONS.map((section) => (
                  <div key={section.key}>
                    <div className="d-flex align-items-center justify-content-between mt-4 mb-3">
                      <h4 className="text-secondary fs-5 mb-0">{section.title}</h4>
                      {SECTION_SETTINGS_BUTTON[section.key] && (
                        <Button
                          variant="outline-danger"
                          size="sm"
                          disabled={!activeTarget}
                          onClick={() => setWebhookSection(section)}
                        >
                          {SECTION_SETTINGS_BUTTON[section.key]}
                        </Button>
                      )}
                    </div>
                    {/* Keyed off the same section key the cards come from, so adding a section to
                        attackTools.js and adding its lessons is all it takes. An unknown key
                        renders nothing rather than breaking the page. */}
                    <HelpMeLearn section={`attackTools:${section.key}`} />
                    <Row className="mb-4">
                      {section.tools.map((tool) => (
                        <Col md={section.tools.length >= 3 ? 4 : 6} key={tool.key}>
                          <AttackToolCard
                            tool={tool}
                            status={vectorToolStatus[tool.key]}
                            disabled={!activeTarget}
                            onConfig={(t) => handleAttackToolAction('Config', t)}
                            onScan={(t) => handleAttackToolAction('Scan', t)}
                            onResults={(t) => handleAttackToolAction('Results', t)}
                          />
                        </Col>
                      ))}
                    </Row>
                  </div>
                ))}

                <h4 className="text-secondary mb-3 fs-5 mt-4">Threat Modeling</h4>
                <HelpMeLearn section="threatModeling" />
                <Row className="mb-4">
                  <Col md={12}>
                    <Card className="shadow-sm h-100 text-center" style={{ minHeight: '200px' }}>
                      <Card.Body className="d-flex flex-column">
                        <Card.Title className="text-danger mb-3">
                          STRIDE Threat Model
                        </Card.Title>
                        <Card.Text className="text-white small fst-italic">
                          Perform comprehensive threat modeling using the STRIDE methodology to identify security threats across six categories. The counts below reflect the threat-model details filled out for this target so far.
                        </Card.Text>
                        {/* xs={2} md={5} rather than per-Col widths, because five equal columns do not
                            divide into Bootstrap's twelve and md={2} would wrap the longer labels. */}
                        <Row xs={2} md={5} className="g-3 justify-content-center mt-1 mb-2">
                          <Col>
                            <div className="fs-3 fw-bold text-danger">{threatModelCounts.questions}</div>
                            <div className="text-white small pb-4">High-Level Questions</div>
                          </Col>
                          <Col>
                            <div className="fs-3 fw-bold text-danger">{threatModelCounts.mechanisms}</div>
                            <div className="text-white small pb-4">Mechanisms</div>
                          </Col>
                          <Col>
                            <div className="fs-3 fw-bold text-danger">{threatModelCounts.notableObjects}</div>
                            <div className="text-white small pb-4">Notable Objects</div>
                          </Col>
                          <Col>
                            <div className="fs-3 fw-bold text-danger">{threatModelCounts.securityControls}</div>
                            <div className="text-white small pb-4">Security Controls</div>
                          </Col>
                          {/* Derived from the results already loaded for the accordion below rather than
                              counted by a separate request, so the two can never disagree and adding or
                              deleting a threat in the modal moves this number on close. */}
                          <Col>
                            <div className="fs-3 fw-bold text-danger">{threatModelResultCount}</div>
                            <div className="text-white small pb-4">Results</div>
                          </Col>
                        </Row>
                        <div className="mt-auto">
                          <Row className="g-2">
                            <Col>
                              <Button
                                variant="outline-danger"
                                className="w-100"
                                onClick={handleOpenApplicationQuestionsModal}
                              >
                                High-Level Questions
                              </Button>
                            </Col>
                            <Col>
                              <Button
                                variant="outline-danger"
                                className="w-100"
                                onClick={handleOpenMechanismsModal}
                              >
                                Mechanisms
                              </Button>
                            </Col>
                            <Col>
                              <Button
                                variant="outline-danger"
                                className="w-100"
                                onClick={handleOpenNotableObjectsModal}
                              >
                                Notable Objects
                              </Button>
                            </Col>
                            <Col>
                              <Button
                                variant="outline-danger"
                                className="w-100"
                                onClick={handleOpenSecurityControlsModal}
                              >
                                Security Controls
                              </Button>
                            </Col>
                            <Col>
                              <Button
                                variant="outline-danger"
                                className="w-100"
                                onClick={handleOpenThreatModelModal}
                              >
                                Threat Model
                              </Button>
                            </Col>
                          </Row>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>

                <h4 className="text-secondary mb-3 fs-5 mt-4">Threat Model Results</h4>
                <HelpMeLearn section="urlThreatModelResults" />
                {[
                  { key: 'spoofing', label: '(S)poofing', desc: 'Impersonation of users, systems, or data' },
                  { key: 'tampering', label: '(T)ampering', desc: 'Malicious modification of data or code' },
                  { key: 'repudiation', label: '(R)epudiation', desc: 'Denial of actions without proper logging' },
                  { key: 'information_disclosure', label: '(I)nformation Disclosure', desc: 'Exposure of sensitive information' },
                  { key: 'denial_of_service', label: '(D)enial of Service', desc: 'Preventing legitimate access' },
                  { key: 'elevation_of_privilege', label: '(E)levation of Privilege', desc: 'Gaining unauthorized elevated permissions' }
                ].map((cat) => (
                  <Row className="mb-4" key={cat.key}>
                    <Col md={12}>
                      <Card className="shadow-sm">
                        <Card.Body>
                          <div className="d-flex justify-content-between align-items-start mb-1">
                            <Card.Title className="text-danger mb-0">
                              {cat.label}
                              {(threatModelResults[cat.key] || []).length > 0 && (
                                <span className="text-white-50 ms-2" style={{ fontSize: '0.8rem', fontWeight: 400 }}>
                                  {(threatModelResults[cat.key] || []).length} documented
                                </span>
                              )}
                            </Card.Title>
                            <Button
                              variant="outline-danger"
                              size="sm"
                              onClick={() => handleOpenPossibleAttacksModal(cat)}
                            >
                              Possible Attacks
                            </Button>
                          </div>
                          <Card.Text className="text-white-50 small fst-italic mb-3">
                            {cat.desc}
                          </Card.Text>
                          {(threatModelResults[cat.key] || []).length === 0 ? (
                            <div className="text-center text-white-50 py-4">
                              There are currently no Threat Model results for this section.
                            </div>
                          ) : (
                            <Accordion data-bs-theme="dark" alwaysOpen>
                              {(threatModelResults[cat.key] || []).map((threat, threatIndex) => (
                                <Accordion.Item
                                  eventKey={String(threatIndex)}
                                  key={threat.id || threatIndex}
                                  className={threatTestStatus(threat.test_status).className}
                                  style={{
                                    // The glowing state owns its own border in CSS, so only the two
                                    // quiet states set one here.
                                    ...(threatTestStatus(threat.test_status).className
                                      ? {}
                                      : { border: `1px solid ${threatTestStatus(threat.test_status).border}` }),
                                    marginBottom: '0.5rem',
                                  }}
                                >
                                  <Accordion.Header>
                                    <div className="d-flex justify-content-between align-items-start w-100 pe-2" style={{ gap: '12px' }}>
                                      <div className="d-flex flex-column text-start">
                                        {/* Severity and authentication sit side by side on one row above the
                                            mechanism, so this strip lays out horizontally while the column
                                            around it keeps stacking. It wraps rather than squeezing the
                                            badges when the header is narrow. */}
                                        {(threatSeverity(threat.severity) || typeof threat.authenticated === 'boolean') && (
                                          <div className="d-flex flex-wrap align-items-center mb-1" style={{ gap: '0.25rem' }}>
                                            {threatSeverity(threat.severity) && (
                                              <span
                                                style={{
                                                  backgroundColor: threatSeverity(threat.severity).bg,
                                                  color: threatSeverity(threat.severity).fg,
                                                  fontSize: '0.68rem',
                                                  fontWeight: 700,
                                                  letterSpacing: '0.06em',
                                                  padding: '0.15rem 0.5rem',
                                                  borderRadius: '0.25rem',
                                                  textTransform: 'uppercase',
                                                }}
                                              >
                                                {threatSeverity(threat.severity).label}
                                              </span>
                                            )}
                                            {/* Only a real boolean renders. A null means nobody has decided yet,
                                                and a green "Unauthenticated" badge would assert the attack needs
                                                no credential rather than admit the question is still open. */}
                                            {typeof threat.authenticated === 'boolean' && (
                                              <span
                                                style={{
                                                  backgroundColor: threat.authenticated ? '#7f1d1d' : '#14532d',
                                                  color: threat.authenticated ? '#fecaca' : '#bbf7d0',
                                                  fontSize: '0.68rem',
                                                  fontWeight: 700,
                                                  letterSpacing: '0.06em',
                                                  padding: '0.15rem 0.5rem',
                                                  borderRadius: '0.25rem',
                                                  textTransform: 'uppercase',
                                                }}
                                                title={threat.authenticated
                                                  ? 'The attacker must already hold an authenticated session'
                                                  : 'Reachable with no credential at all'}
                                              >
                                                {threat.authenticated ? 'Auth Required' : 'Unauthenticated'}
                                              </span>
                                            )}
                                          </div>
                                        )}
                                        <span className="text-danger" style={{ fontSize: '0.9rem' }}>
                                          {threatTitle(threat)}
                                        </span>
                                        <span className="text-white-50" style={{ fontSize: '0.75rem', wordBreak: 'break-all' }}>
                                          {threat.url}
                                        </span>
                                      </div>
                                      <Badge
                                        bg={threatTestStatus(threat.test_status).badge}
                                        className="flex-shrink-0 d-flex align-items-center gap-1"
                                        style={threat.test_status === 'validated'
                                          ? {
                                              // Explicit colour rather than bg="success": the glow uses the
                                              // brighter #20c997 because #198754 barely reads on the dark
                                              // card, and a badge in a different green to its own halo
                                              // looks like a mistake.
                                              backgroundColor: '#20c997',
                                              color: '#04231a',
                                              fontWeight: 600,
                                              fontSize: '0.8rem',
                                              padding: '0.4em 0.7em',
                                              boxShadow: '0 0 12px rgba(32,201,151,0.95)',
                                            }
                                          : undefined}
                                      >
                                        {threat.test_status === 'validated' && (
                                          <i className="bi bi-trophy-fill" />
                                        )}
                                        {threatTestStatus(threat.test_status).label}
                                      </Badge>
                                    </div>
                                  </Accordion.Header>
                                  <Accordion.Body className="bg-dark">
                                    {/* Only the glowing state needs the panel; on a quiet item it would
                                        be a box around nothing. */}
                                    <div className={threatTestStatus(threat.test_status).className ? 'threat-body-panel' : ''}>
                                    {/* Deliberately repeats the accordion header. Once the item is open the
                                        header is easy to lose track of, especially on the long entries, so
                                        the reader gets told again what they are looking at. Rendered on
                                        every item, not just the glowing ones, so the layout does not
                                        change shape depending on test status. */}
                                    <div className="mb-3 pb-2 border-bottom border-secondary">
                                      <div className="text-danger" style={{ fontSize: '0.95rem', fontWeight: 600 }}>
                                        {threatTitle(threat)}
                                      </div>
                                    </div>
                                    {/* The two reader-facing sections come FIRST. Before these, the only
                                        way to learn what a threat actually was involved reading a
                                        numbered attack procedure, which is a lot of work for a
                                        question that deserves one line. */}
                                    {threat.one_sentence && (
                                      <div className="mb-3">
                                        <div className="text-white-50 mb-1" style={{ fontSize: '0.72rem', letterSpacing: '0.04em' }}>
                                          DESCRIBE THE ATTACK IN ONE SENTENCE
                                        </div>
                                        <div className="text-white" style={{ fontSize: '0.95rem', fontWeight: 500, lineHeight: 1.5 }}>
                                          {threat.one_sentence}
                                        </div>
                                      </div>
                                    )}
                                    {threat.summary && (
                                      <div className="mb-3">
                                        <div className="text-white-50 mb-1" style={{ fontSize: '0.72rem', letterSpacing: '0.04em' }}>
                                          SUMMARY
                                        </div>
                                        <div className="text-white" style={{ fontSize: '0.85rem', lineHeight: 1.6 }}>
                                          {threat.summary}
                                        </div>
                                      </div>
                                    )}
                                    {threat.url && (
                                      <div className="mb-3">
                                        <div className="text-white-50 mb-1" style={{ fontSize: '0.72rem', letterSpacing: '0.04em' }}>
                                          WHERE
                                        </div>
                                        <a
                                          href={threat.url}
                                          target="_blank"
                                          rel="noopener noreferrer"
                                          className="text-info"
                                          style={{ fontSize: '0.8rem', wordBreak: 'break-all' }}
                                        >
                                          {threat.url}
                                        </a>
                                      </div>
                                    )}
                                    {threat.steps.length > 0 && (
                                      <div className="mb-3">
                                        <div className="text-white-50 mb-1" style={{ fontSize: '0.72rem', letterSpacing: '0.04em' }}>
                                          HOW THE ATTACK IS CARRIED OUT
                                        </div>
                                        <ol className="text-white ps-3 mb-0" style={{ fontSize: '0.82rem' }}>
                                          {threat.steps.map((step, stepIndex) => (
                                            <li key={stepIndex} className="mb-2">{step}</li>
                                          ))}
                                        </ol>
                                      </div>
                                    )}
                                    {(threat.impact_customer_data || threat.impact_attacker_scope || threat.impact_company_reputation) && (
                                      <div className="mb-3">
                                        <div className="text-white-50 mb-2" style={{ fontSize: '0.72rem', letterSpacing: '0.04em' }}>
                                          IMPACT
                                        </div>
                                        {[
                                          { label: 'Customer data', text: threat.impact_customer_data },
                                          { label: 'Attacker scope', text: threat.impact_attacker_scope },
                                          { label: 'Company reputation', text: threat.impact_company_reputation },
                                        ].filter((row) => row.text).map((row) => (
                                          <div key={row.label} className="mb-2">
                                            <div className="text-warning" style={{ fontSize: '0.74rem' }}>{row.label}</div>
                                            <div className="text-white" style={{ fontSize: '0.82rem' }}>{row.text}</div>
                                          </div>
                                        ))}
                                      </div>
                                    )}
                                    {threat.security_controls.length > 0 && (
                                      <div>
                                        <div className="text-white-50 mb-2" style={{ fontSize: '0.72rem', letterSpacing: '0.04em' }}>
                                          SECURITY CONTROLS IN THE WAY
                                        </div>
                                        {threat.security_controls.map((sc, scIndex) => (
                                          <div key={scIndex} className="mb-2">
                                            <div className="text-warning" style={{ fontSize: '0.74rem' }}>
                                              {sc.control || 'Unnamed control'}
                                            </div>
                                            {sc.explanation && (
                                              <div className="text-white" style={{ fontSize: '0.82rem' }}>{sc.explanation}</div>
                                            )}
                                          </div>
                                        ))}
                                      </div>
                                    )}
                                    <div className="d-flex align-items-center gap-2 mt-3 pt-3 border-top border-secondary">
                                      <span className="text-white-50" style={{ fontSize: '0.72rem', letterSpacing: '0.04em' }}>
                                        TESTED?
                                      </span>
                                      <Button
                                        variant={threat.test_status === 'validated' ? 'success' : 'outline-success'}
                                        size="sm"
                                        onClick={() => handleSetThreatTestStatus(threat.id, 'validated')}
                                      >
                                        Validate
                                      </Button>
                                      <Button
                                        variant={threat.test_status === 'rejected' ? 'danger' : 'outline-danger'}
                                        size="sm"
                                        onClick={() => handleSetThreatTestStatus(threat.id, 'rejected')}
                                      >
                                        Reject
                                      </Button>
                                      {threat.test_status && threat.test_status !== 'untested' && (
                                        <Button
                                          variant="outline-secondary"
                                          size="sm"
                                          onClick={() => handleSetThreatTestStatus(threat.id, 'untested')}
                                        >
                                          Clear
                                        </Button>
                                      )}
                                    </div>
                                    </div>
                                  </Accordion.Body>
                                </Accordion.Item>
                              ))}
                            </Accordion>
                          )}
                        </Card.Body>
                      </Card>
                    </Col>
                  </Row>
                ))}
              </div>
            )}
          </div>
        </Fade>
      )}
      <Suspense fallback={<div />}>
        <MetaDataModal
          showMetaDataModal={showMetaDataModal}
          handleCloseMetaDataModal={handleCloseMetaDataModal}
          metaDataResults={mostRecentMetaDataScan}
          targetURLs={targetURLs}
          setTargetURLs={setMetaDataTargetURLs}
          fetchScopeTargets={fetchScopeTargets}
          onPopulateBurp={handleOpenToolsModalWithUrls}
        />
      </Suspense>
      <Suspense fallback={<div />}>
        <ConfigureMetaDataModal
          show={showConfigureMetaDataModal}
          handleClose={handleCloseConfigureMetaDataModal}
          targetURLs={targetURLs}
          onSaveConfig={handleSaveMetaDataConfig}
          currentConfig={activeTarget ? metaDataScanConfigs[activeTarget.id] : null}
        />
      </Suspense>
      <Suspense fallback={<div />}>
        <ROIReport
          show={showROIReport}
          onHide={handleCloseROIReport}
          targetURLs={targetURLs}
          setTargetURLs={setRoiTargetURLs}
          fetchScopeTargets={fetchScopeTargets}
        />
      </Suspense>
      <Modal data-bs-theme="dark" show={showAutoScanHistoryModal} onHide={handleCloseAutoScanHistoryModal} size="xl" dialogClassName="modal-90w">
        <Modal.Header closeButton>
          <Modal.Title className='text-danger'>Auto Scan History</Modal.Title>
        </Modal.Header>
        <Modal.Body style={{overflowX: 'auto'}}>
          <Table striped bordered hover responsive>
            <thead>
              <tr>
                <th className="text-center">Start Time</th>
                <th className="text-center">Duration</th>
                <th className="text-center">Status</th>
                <th className="text-center">Consolidated Subdomains</th>
                <th className="text-center">Live Web Servers</th>
                <th colSpan={6} className="text-center bg-dark border-danger">Subdomain Scraping</th>
                <th className="text-center bg-dark border-danger">R1</th>
                <th colSpan={2} className="text-center bg-dark border-danger">Brute Force</th>
                <th className="text-center bg-dark border-danger">R2</th>
                <th colSpan={2} className="text-center bg-dark border-danger">JS/Link Discovery</th>
                <th className="text-center bg-dark border-danger">R3</th>
                <th className="text-center bg-dark border-danger">Metadata</th>
              </tr>
              <tr>
                <th colSpan={5}></th>
                <th className="text-center" style={{width: '40px'}}>AM</th>
                <th className="text-center" style={{width: '40px'}}>SL3</th>
                <th className="text-center" style={{width: '40px'}}>AF</th>
                <th className="text-center" style={{width: '40px'}}>GAU</th>
                <th className="text-center" style={{width: '40px'}}>CTL</th>
                <th className="text-center" style={{width: '40px'}}>SF</th>
                <th className="text-center" style={{width: '40px'}}>HX1</th>
                <th className="text-center" style={{width: '40px'}}>SDS</th>
                <th className="text-center" style={{width: '40px'}}>CWL</th>
                <th className="text-center" style={{width: '40px'}}>HX2</th>
                <th className="text-center" style={{width: '40px'}}>GS</th>
                <th className="text-center" style={{width: '40px'}}>SDZ</th>
                <th className="text-center" style={{width: '40px'}}>HX3</th>
                <th className="text-center" style={{width: '40px'}}>MD</th>
              </tr>
            </thead>
            <tbody>
              {(!autoScanSessions || autoScanSessions.length === 0) ? (
                <tr>
                  <td colSpan={19} className="text-center text-white-50">
                    No auto scan sessions found for this target.
                  </td>
                </tr>
              ) : (
                autoScanSessions.map((session) => (
                  <tr key={session.session_id}>
                    <td>{session.start_time}</td>
                    <td>{session.duration || '-'}</td>
                    <td>
                      <span className={`text-${session.status === 'completed' ? 'success' : session.status === 'cancelled' ? 'warning' : 'primary'}`}>
                        {session.status.charAt(0).toUpperCase() + session.status.slice(1)}
                      </span>
                    </td>
                    <td className="text-center"><strong>{session.final_consolidated_subdomains || '0'}</strong></td>
                    <td className="text-center"><strong>{session.final_live_web_servers || '0'}</strong></td>
                    <td className="text-center">{session.config?.amass ? <span className="text-success fw-bold">✓</span> : <span className="text-secondary">-</span>}</td>
                    <td className="text-center">{session.config?.sublist3r ? <span className="text-success fw-bold">✓</span> : <span className="text-secondary">-</span>}</td>
                    <td className="text-center">{session.config?.assetfinder ? <span className="text-success fw-bold">✓</span> : <span className="text-secondary">-</span>}</td>
                    <td className="text-center">{session.config?.gau ? <span className="text-success fw-bold">✓</span> : <span className="text-secondary">-</span>}</td>
                    <td className="text-center">{session.config?.ctl ? <span className="text-success fw-bold">✓</span> : <span className="text-secondary">-</span>}</td>
                    <td className="text-center">{session.config?.subfinder ? <span className="text-success fw-bold">✓</span> : <span className="text-secondary">-</span>}</td>
                    <td className="text-center">{session.config?.httpx_round1 ? <span className="text-success fw-bold">✓</span> : <span className="text-secondary">-</span>}</td>
                    <td className="text-center">{session.config?.shuffledns ? <span className="text-success fw-bold">✓</span> : <span className="text-secondary">-</span>}</td>
                    <td className="text-center">{session.config?.cewl ? <span className="text-success fw-bold">✓</span> : <span className="text-secondary">-</span>}</td>
                    <td className="text-center">{session.config?.httpx_round2 ? <span className="text-success fw-bold">✓</span> : <span className="text-secondary">-</span>}</td>
                    <td className="text-center">{session.config?.gospider ? <span className="text-success fw-bold">✓</span> : <span className="text-secondary">-</span>}</td>
                    <td className="text-center">{session.config?.subdomainizer ? <span className="text-success fw-bold">✓</span> : <span className="text-secondary">-</span>}</td>
                    <td className="text-center">{session.config?.httpx_round3 ? <span className="text-success fw-bold">✓</span> : <span className="text-secondary">-</span>}</td>
                    <td className="text-center">{(session.config?.metadata || session.config?.nuclei_screenshot) ? <span className="text-success fw-bold">✓</span> : <span className="text-secondary">-</span>}</td>
                  </tr>
                ))
              )}
            </tbody>
          </Table>
        </Modal.Body>
      </Modal>
      <CTLCompanyHistoryModal
        showCTLCompanyHistoryModal={showCTLCompanyHistoryModal}
        handleCloseCTLCompanyHistoryModal={handleCloseCTLCompanyHistoryModal}
        ctlCompanyScans={ctlCompanyScans}
      />

      <MetabigorCompanyResultsModal
        showMetabigorCompanyResultsModal={showMetabigorCompanyResultsModal}
        handleCloseMetabigorCompanyResultsModal={handleCloseMetabigorCompanyResultsModal}
        metabigorCompanyResults={mostRecentMetabigorCompanyScan}
        setShowToast={setShowToast}
      />

      <MetabigorCompanyHistoryModal
        showMetabigorCompanyHistoryModal={showMetabigorCompanyHistoryModal}
        handleCloseMetabigorCompanyHistoryModal={handleCloseMetabigorCompanyHistoryModal}
        metabigorCompanyScans={metabigorCompanyScans}
      />

      <Modal data-bs-theme="dark" show={showGoogleDorkingResultsModal} onHide={handleCloseGoogleDorkingResultsModal} size="lg">
        <Modal.Header closeButton>
          <Modal.Title className='text-danger'>Google Dorking Results</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {googleDorkingDomains.length === 0 ? (
            <div className="text-center py-4">
              <p className="text-white">No domains discovered yet.</p>
              <p className="text-white-50 small">
                Use the Manual Google Dorking tool to discover and add company domains.
              </p>
            </div>
          ) : (
            <div>
              <p className="text-white mb-3">
                Discovered domains for <strong>{activeTarget?.scope_target}</strong>:
              </p>
              <ListGroup variant="flush">
                {googleDorkingDomains.map((domainData) => (
                  <ListGroup.Item 
                    key={domainData.id} 
                    className="bg-dark border-secondary d-flex justify-content-between align-items-center"
                  >
                    <div>
                      <span className="text-white">{domainData.domain}</span>
                      <br />
                      <div className="text-muted small card-metric-label">
                        Added: {new Date(domainData.created_at).toLocaleDateString()}
                      </div>
                    </div>
                    <Button 
                      variant="outline-danger" 
                      size="sm"
                      onClick={() => deleteGoogleDorkingDomain(domainData.id)}
                      title="Delete domain"
                    >
                      <i className="bi bi-trash"></i>
                    </Button>
                  </ListGroup.Item>
                ))}
              </ListGroup>
              <div className="mt-3 text-center">
                <div className="text-muted small card-metric-label">
                  Total domains discovered: {googleDorkingDomains.length}
                </div>
              </div>
            </div>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={handleCloseGoogleDorkingResultsModal}>
            Close
          </Button>
        </Modal.Footer>
      </Modal>

      <Modal data-bs-theme="dark" show={showReverseWhoisResultsModal} onHide={handleCloseReverseWhoisResultsModal} size="lg">
        <Modal.Header closeButton>
          <Modal.Title className='text-danger'>Reverse Whois Results</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {reverseWhoisDomains.length === 0 ? (
            <div className="text-center py-4">
              <p className="text-white">No domains discovered yet.</p>
              <p className="text-white-50 small">
                Use the Manual Reverse Whois tool to discover and add company domains.
              </p>
            </div>
          ) : (
            <div>
              <p className="text-white mb-3">
                Discovered domains for <strong>{activeTarget?.scope_target}</strong>:
              </p>
              <ListGroup variant="flush">
                {reverseWhoisDomains.map((domainData) => (
                  <ListGroup.Item 
                    key={domainData.id} 
                    className="bg-dark border-secondary d-flex justify-content-between align-items-center"
                  >
                    <div>
                      <span className="text-white">{domainData.domain}</span>
                      <br />
                      <div className="text-muted small card-metric-label">
                        Added: {new Date(domainData.created_at).toLocaleDateString()}
                      </div>
                    </div>
                    <Button 
                      variant="outline-danger" 
                      size="sm"
                      onClick={() => deleteReverseWhoisDomain(domainData.id)}
                      title="Delete domain"
                    >
                      <i className="bi bi-trash"></i>
                    </Button>
                  </ListGroup.Item>
                ))}
              </ListGroup>
              <div className="mt-3 text-center">
                <div className="text-muted small card-metric-label">
                  Total domains discovered: {reverseWhoisDomains.length}
                </div>
              </div>
            </div>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={handleCloseReverseWhoisResultsModal}>
            Close
          </Button>
        </Modal.Footer>
      </Modal>

      <Modal data-bs-theme="dark" show={showGoogleDorkingHistoryModal} onHide={handleCloseGoogleDorkingHistoryModal} size="lg">
        <Modal.Header closeButton>
          <Modal.Title className='text-danger'>Google Dorking History</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p className="text-white">Google Dorking scan history will be displayed here once functionality is implemented.</p>
        </Modal.Body>
      </Modal>

      <Suspense fallback={<div />}>
        <GoogleDorkingModal
          show={showGoogleDorkingManualModal}
          handleClose={handleCloseGoogleDorkingManualModal}
        companyName={activeTarget?.scope_target || ''}
        onDomainAdd={handleGoogleDorkingDomainAdd}
        error={googleDorkingError}
        onClearError={() => setGoogleDorkingError('')}
        />
      </Suspense>

      <ReverseWhoisModal
        show={showReverseWhoisManualModal}
        handleClose={handleCloseReverseWhoisManualModal}
        companyName={activeTarget?.scope_target || ''}
        onDomainAdd={handleReverseWhoisDomainAdd}
        error={reverseWhoisError}
        onClearError={() => setReverseWhoisError('')}
      />

      <SubfinderResultsModal
        showSubfinderResultsModal={showSubfinderResultsModal}
        handleCloseSubfinderResultsModal={handleCloseSubfinderResultsModal}
        subfinderResults={mostRecentSubfinderScan}
      />

      <APIKeysConfigModal
        show={showAPIKeysConfigModal}
        handleClose={() => setShowAPIKeysConfigModal(false)}
        onOpenSettings={() => {
          setShowAPIKeysConfigModal(false);
          setSettingsModalInitialTab('api-keys');
          setShowSettingsModal(true);
        }}
        onApiKeySelected={handleApiKeySelected}
      />

      {showSecurityTrailsCompanyResultsModal && (
        <SecurityTrailsCompanyResultsModal
          show={showSecurityTrailsCompanyResultsModal}
          handleClose={handleCloseSecurityTrailsCompanyResultsModal}
          scan={mostRecentSecurityTrailsCompanyScan}
        />
      )}

      <SecurityTrailsCompanyHistoryModal
        show={showSecurityTrailsCompanyHistoryModal}
        handleClose={handleCloseSecurityTrailsCompanyHistoryModal}
        scans={securityTrailsCompanyScans}
      />

      <CensysCompanyResultsModal
        show={showCensysCompanyResultsModal}
        handleClose={handleCloseCensysCompanyResultsModal}
        scan={mostRecentCensysCompanyScan}
        setShowToast={setShowToast}
      />

      <CensysCompanyHistoryModal
        show={showCensysCompanyHistoryModal}
        handleClose={handleCloseCensysCompanyHistoryModal}
        scans={censysCompanyScans}
      />
      <GitHubReconResultsModal
        show={showGitHubReconResultsModal}
        handleClose={handleCloseGitHubReconResultsModal}
        scan={mostRecentGitHubReconScan}
        setShowToast={setShowToast}
      />
      <GitHubReconHistoryModal
        show={showGitHubReconHistoryModal}
        handleClose={handleCloseGitHubReconHistoryModal}
        scans={gitHubReconScans}
      />
      <ShodanCompanyResultsModal
        show={showShodanCompanyResultsModal}
        handleClose={handleCloseShodanCompanyResultsModal}
        scan={mostRecentShodanCompanyScan}
        setShowToast={setShowToast}
      />
      <ShodanCompanyHistoryModal
        show={showShodanCompanyHistoryModal}
        handleClose={handleCloseShodanCompanyHistoryModal}
        scans={shodanCompanyScans}
      />
      <AddWildcardTargetsModal
        show={showAddWildcardTargetsModal}
        handleClose={handleCloseAddWildcardTargetsModal}
        consolidatedCompanyDomains={consolidatedCompanyDomains}
        onAddWildcardTarget={handleAddWildcardTarget}
        scopeTargets={scopeTargets}
        fetchScopeTargets={fetchScopeTargets}
        investigateResults={mostRecentInvestigateScan?.result ? JSON.parse(mostRecentInvestigateScan.result) : []}
      />
      <TrimRootDomainsModal
        show={showTrimRootDomainsModal}
        handleClose={handleCloseTrimRootDomainsModal}
        activeTarget={activeTarget}
        onDomainsDeleted={handleDomainsDeleted}
      />
      <TrimNetworkRangesModal
        show={showTrimNetworkRangesModal}
        handleClose={handleCloseTrimNetworkRangesModal}
        activeTarget={activeTarget}
        onDomainsDeleted={handleDomainsDeleted}
      />
      <LiveWebServersResultsModal
        show={showLiveWebServersResultsModal}
        onHide={handleCloseLiveWebServersResultsModal}
        activeTarget={activeTarget}
        consolidatedNetworkRanges={consolidatedNetworkRanges}
        mostRecentIPPortScan={mostRecentIPPortScan}
        onPopulateBurp={handleOpenToolsModalWithUrls}
      />
      <AmassEnumConfigModal
        show={showAmassEnumConfigModal}
        handleClose={handleCloseAmassEnumConfigModal}
        activeTarget={activeTarget}
        consolidatedCompanyDomains={consolidatedCompanyDomains}
        onSaveConfig={handleAmassEnumConfigSave}
      />
      <AmassIntelConfigModal
        show={showAmassIntelConfigModal}
        handleClose={handleCloseAmassIntelConfigModal}
        activeTarget={activeTarget}
        consolidatedNetworkRanges={consolidatedNetworkRanges}
        onSaveConfig={handleAmassIntelConfigSave}
      />
      <DNSxConfigModal
        show={showDNSxConfigModal}
        handleClose={handleCloseDNSxConfigModal}
        activeTarget={activeTarget}
        scopeTargets={scopeTargets}
        consolidatedCompanyDomains={consolidatedCompanyDomains}
        onSaveConfig={handleDNSxConfigSave}
      />

      <CloudEnumConfigModal
        show={showCloudEnumConfigModal}
        handleClose={handleCloseCloudEnumConfigModal}
        activeTarget={activeTarget}
        onSaveConfig={handleCloudEnumConfigSave}
      />

      <NucleiConfigModal
        show={showNucleiConfigModal}
        handleClose={handleCloseNucleiConfigModal}
        activeTarget={activeTarget}
        onSaveConfig={handleNucleiConfigSave}
        mode="company"
      />

      <NucleiConfigModal
        show={showWildcardNucleiConfigModal}
        handleClose={handleCloseWildcardNucleiConfigModal}
        activeTarget={activeTarget}
        onSaveConfig={handleWildcardNucleiConfigSave}
        mode="wildcard"
      />

      <KatanaCompanyConfigModal
        show={showKatanaCompanyConfigModal}
        handleClose={handleCloseKatanaCompanyConfigModal}
        activeTarget={activeTarget}
        consolidatedCompanyDomains={consolidatedCompanyDomains}
        onSaveConfig={handleKatanaCompanyConfigSave}
      />

      <KatanaCompanyResultsModal
        show={showKatanaCompanyResultsModal}
        handleClose={handleCloseKatanaCompanyResultsModal}
        activeTarget={activeTarget}
        mostRecentKatanaCompanyScan={mostRecentKatanaCompanyScan}
      />

      <KatanaCompanyHistoryModal
        show={showKatanaCompanyHistoryModal}
        handleClose={handleCloseKatanaCompanyHistoryModal}
        scans={katanaCompanyScans}
      />

      <KatanaURLResultsModal
        show={showKatanaURLResultsModal}
        handleClose={handleCloseKatanaURLResultsModal}
        activeTarget={activeTarget}
        mostRecentKatanaURLScan={mostRecentKatanaURLScan}
      />

      <LinkFinderURLResultsModal
        show={showLinkFinderURLResultsModal}
        handleClose={handleCloseLinkFinderURLResultsModal}
        activeTarget={activeTarget}
        mostRecentLinkFinderURLScan={mostRecentLinkFinderURLScan}
      />

      <WaybackURLsResultsModal
        show={showWaybackURLsResultsModal}
        handleClose={handleCloseWaybackURLsResultsModal}
        activeTarget={activeTarget}
        mostRecentWaybackURLsScan={mostRecentWaybackURLsScan}
      />

      <GAUURLResultsModal
        show={showGAUURLResultsModal}
        handleClose={handleCloseGAUURLResultsModal}
        activeTarget={activeTarget}
        mostRecentGAUURLScan={mostRecentGAUURLScan}
      />

      <GoSpiderURLResultsModal
        show={showGoSpiderURLResultsModal}
        handleClose={handleCloseGoSpiderURLResultsModal}
        activeTarget={activeTarget}
        mostRecentGoSpiderURLScan={mostRecentGoSpiderURLScan}
      />

      <ArjunConfigModal
        show={showArjunConfigModal}
        handleClose={handleCloseArjunConfigModal}
        activeTarget={activeTarget}
      />

      <ArjunResultsModal
        show={showArjunResultsModal}
        handleClose={handleCloseArjunResultsModal}
        activeTarget={activeTarget}
        mostRecentArjunScan={mostRecentArjunScan}
      />

      <X8ConfigModal
        show={showX8ConfigModal}
        handleClose={handleCloseX8ConfigModal}
        activeTarget={activeTarget}
      />

      <X8ResultsModal
        show={showX8ResultsModal}
        handleClose={handleCloseX8ResultsModal}
        activeTarget={activeTarget}
        mostRecentX8Scan={mostRecentX8Scan}
      />

      <FFUFURLResultsModal
        show={showFFUFURLResultsModal}
        handleClose={handleCloseFFUFURLResultsModal}
        activeTarget={activeTarget}
        mostRecentFFUFURLScan={mostRecentFFUFURLScan}
        // Dismissing findings inside the modal changes the numbers the card is showing. Without this
        // the card kept the count it fetched when the target was selected, so triaging a page of noise
        // left the card advertising findings the list no longer contains.
        onFindingsChanged={loadFuzzFindingCount}
      />

      <WAFProbeResultsModal
        show={showWAFProbeResultsModal}
        handleClose={handleCloseWAFProbeResultsModal}
        activeTarget={activeTarget}
        mostRecentWAFProbeScan={mostRecentWAFProbeScan}
        wafProbeScans={wafProbeScans}
      />

      <WAFProbeConfigModal
        show={showWAFProbeConfigModal}
        handleClose={() => setShowWAFProbeConfigModal(false)}
        activeTarget={activeTarget}
        // Saving is the only thing that changes the configured count, so the card is refreshed here
        // rather than polled.
        onSaved={() => void loadWAFProbeTargetCount()}
        onRunNow={(cfg) => startWAFProbeScan(cfg)}
      />

      <CrawlerConfigModal
        show={!!crawlerConfigTool}
        handleClose={() => setCrawlerConfigTool(null)}
        activeTarget={activeTarget}
        tool={crawlerConfigTool}
        onSaved={() => fetchArchiveHostCounts()}
      />

      <ApplicationQuestionsModal
        show={showApplicationQuestionsModal}
        handleClose={handleCloseApplicationQuestionsModal}
        activeTarget={activeTarget}
      />

      <MechanismsModal
        show={showMechanismsModal}
        handleClose={handleCloseMechanismsModal}
        activeTarget={activeTarget}
      />

      <NotableObjectsModal
        show={showNotableObjectsModal}
        handleClose={handleCloseNotableObjectsModal}
        activeTarget={activeTarget}
      />

      <SecurityControlsModal
        show={showSecurityControlsModal}
        handleClose={handleCloseSecurityControlsModal}
        activeTarget={activeTarget}
      />

      <ThreatModelModal
        show={showThreatModelModal}
        handleClose={handleCloseThreatModelModal}
        activeTarget={activeTarget}
        mechanisms={mechanismsForThreatModel}
        notableObjects={notableObjectsForThreatModel}
        securityControls={securityControlsForThreatModel}
      />

      <AuthFlowModal
        show={showAuthFlowModal}
        handleClose={handleCloseAuthFlowModal}
        category={authFlowCategory}
        activeTarget={activeTarget}
        onFlowsChange={fetchAuthFlowCounts}
      />

      <RecordAuthFlowsModal
        show={showRecordAuthFlowsModal}
        handleClose={handleCloseRecordAuthFlowsModal}
        scopeTargetId={activeTarget?.id}
        scopeTargetUrl={activeTarget?.scope_target}
      />

      <ManualAuthFlowModal
        show={showManualAuthFlowModal}
        handleClose={handleCloseManualAuthFlowModal}
        scopeTargetId={activeTarget?.id}
        scopeTargetUrl={activeTarget?.scope_target}
      />

      <ManageSessionsModal
        show={showManageSessionsModal}
        handleClose={handleCloseManageSessionsModal}
        scopeTargetId={activeTarget?.id}
        scopeTargetUrl={activeTarget?.scope_target}
      />

      <RefreshSessionModal
        show={showRefreshSessionModal}
        handleClose={handleCloseRefreshSessionModal}
        scopeTargetId={activeTarget?.id}
        scopeTargetUrl={activeTarget?.scope_target}
      />

      <ClientIdentityPatternsModal
        show={showClientIdentityModal}
        handleClose={handleCloseClientIdentityModal}
        scopeTargetId={activeTarget?.id}
        scopeTargetUrl={activeTarget?.scope_target}
      />

      <PolicyAccessModal
        show={showPolicyAccessModal}
        handleClose={handleClosePolicyAccessModal}
        scopeTargetId={activeTarget?.id}
      />

      <RoleAccessModal
        show={showRoleAccessModal}
        handleClose={handleCloseRoleAccessModal}
        scopeTargetId={activeTarget?.id}
      />

      <DiscretionaryAccessModal
        show={showDiscretionaryAccessModal}
        handleClose={handleCloseDiscretionaryAccessModal}
        scopeTargetId={activeTarget?.id}
      />

      <PossibleAttacksModal
        show={showPossibleAttacksModal}
        handleClose={handleClosePossibleAttacksModal}
        category={possibleAttacksCategory}
      />

      <ManualCrawlResultsModal
        show={showManualCrawlResultsModal}
        onHide={handleCloseManualCrawlResultsModal}
        scopeTargetId={activeTarget?.id}
      />

      <ExtensionInstallModal
        show={showExtensionInstallModal}
        onHide={handleCloseExtensionInstallModal}
      />

      <ManageEndpointsModal
        show={showManageEndpointsModal}
        onHide={handleCloseManageEndpointsModal}
        scopeTargetId={activeTarget?.id}
      />

      <EndpointScanResultsModal
        show={showEndpointScanResultsModal}
        handleClose={handleCloseEndpointScanResultsModal}
        scopeTargetId={activeTarget?.id}
      />

      <FFUFConfigModal
        show={showFFUFConfigModal}
        handleClose={handleCloseFFUFConfigModal}
        activeTarget={activeTarget}
      />

      <FFUFSettingsModal
        show={showFFUFSettingsModal}
        handleClose={handleCloseFFUFSettingsModal}
        activeTarget={activeTarget}
      />

      <AddAttackVectorModal
        show={showAddAttackVectorModal}
        handleClose={() => setShowAddAttackVectorModal(false)}
        activeTarget={activeTarget}
        onAdded={loadAttackVectorCounts}
      />

      <AttackVectorsModal
        show={showAttackVectorsModal}
        handleClose={() => setShowAttackVectorsModal(false)}
        activeTarget={activeTarget}
        onChanged={loadAttackVectorCounts}
      />

      {/* Reloaded on close because saving a setting can change how many vectors are eligible: turning
          on skipReflectionPath takes every path vector out of the run, and the card has to say so. */}
      <VectorToolConfigModal
        show={showVectorConfigModal}
        handleClose={() => {
          setShowVectorConfigModal(false);
          if (vectorTool) loadVectorToolStatus(vectorTool.key);
        }}
        activeTarget={activeTarget}
        tool={vectorTool}
        category={vectorTool ? VECTOR_TOOL_CATEGORY.get(vectorTool.key) : undefined}
      />

      <WildcardToolConfigModal
        show={wildcardConfigTool !== null}
        handleClose={() => setWildcardConfigTool(null)}
        activeTarget={activeTarget}
        tool={wildcardConfigTool}
        onDelegate={(store) => {
          // A tool that already HAS a wired configuration store is linked to, never re-implemented.
          // httpx_configs is the case: a second httpx vocabulary would be the drift this whole design
          // exists to prevent.
          if (store === 'httpx_configs') {
            setWildcardConfigTool(null);
            handleOpenConfigureHttpxModal();
          }
        }}
      />

      {/* The Company workflow's generic tool configuration. Same design as the Wildcard modal above:
          it renders the server's vocabulary and keeps no list of its own, so this screen and the MCP
          company tool cannot drift apart. Used by Amass Intel, Metabigor and Nuclei's Settings
          button; the three tools that already own a target picker carry their settings as extra tabs
          inside that picker instead. */}
      <CompanyToolConfigModal
        show={companyConfigTool !== null}
        handleClose={() => setCompanyConfigTool(null)}
        activeTarget={activeTarget}
        tool={companyConfigTool}
      />

      <IPPortScanConfigModal
        show={showIPPortScanConfigModal}
        handleClose={() => setShowIPPortScanConfigModal(false)}
        activeTarget={activeTarget}
        // Removing a range at the source is the only thing that really changes what this scan
        // touches, so the modal links to the screen that does it rather than growing a tick box the
        // runner would not read.
        onTrimNetworkRanges={handleTrimNetworkRanges}
      />

      <SectionWebhookModal
        show={webhookSection !== null}
        handleClose={() => {
          const closing = webhookSection;
          setWebhookSection(null);
          // Reloaded on close because configuring the webhook is what makes this section's tools
          // eligible, and the cards have to stop saying zero the moment it is filled in.
          if (closing) {
            (closing.tools || []).forEach((tool) => loadVectorToolStatus(tool.key));
          }
        }}
        activeTarget={activeTarget}
        category={webhookSection?.key}
        title={webhookSection?.title}
      />

      <VectorToolResultsModal
        show={showVectorResultsModal}
        handleClose={() => setShowVectorResultsModal(false)}
        activeTarget={activeTarget}
        tool={vectorTool}
        category={vectorTool ? VECTOR_TOOL_CATEGORY.get(vectorTool.key) : undefined}
      />

      <ExploreAttackSurfaceModal
        show={showExploreAttackSurfaceModal}
        handleClose={handleCloseExploreAttackSurfaceModal}
        activeTarget={activeTarget}
      />

      <ManageAttackSurfaceModal
        show={showManageAttackSurfaceModal}
        handleClose={handleCloseManageAttackSurfaceModal}
        activeTarget={activeTarget}
        onAssetChange={handleAttackSurfaceAssetChange}
      />

      <AttackSurfaceVisualizationModal
         show={showAttackSurfaceVisualizationModal}
         onHide={handleCloseAttackSurfaceVisualizationModal}
         scopeTargetId={activeTarget?.id}
         scopeTargetName={activeTarget?.scope_target}
       />
      <NucleiResultsModal
        show={showNucleiResultsModal}
        handleClose={handleCloseNucleiResultsModal}
        scan={activeNucleiScan}
        scans={nucleiScans}
        activeNucleiScan={activeNucleiScan}
        setActiveNucleiScan={setActiveNucleiScan}
        setShowToast={setShowToast}
      />

      <NucleiHistoryModal
        show={showNucleiHistoryModal}
        handleClose={handleCloseNucleiHistoryModal}
        scans={nucleiScans}
      />

      <NucleiResultsModal
        show={showWildcardNucleiResultsModal}
        handleClose={handleCloseWildcardNucleiResultsModal}
        scan={activeWildcardNucleiScan}
        scans={wildcardNucleiScans}
        activeNucleiScan={activeWildcardNucleiScan}
        setActiveNucleiScan={setActiveWildcardNucleiScan}
        setShowToast={setShowToast}
      />

      <NucleiHistoryModal
        show={showWildcardNucleiHistoryModal}
        handleClose={handleCloseWildcardNucleiHistoryModal}
        scans={wildcardNucleiScans}
      />

      {/* Reached from the header rather than a target card, so it takes the whole target list and
          picks its own. handleClose only flips the flag: the modal guards unsaved edits itself. */}
      <NotesModal
        show={showNotesModal}
        handleClose={() => setShowNotesModal(false)}
        scopeTargets={scopeTargets}
        activeTarget={activeTarget}
      />
    </Container>
  );
}

export default App;