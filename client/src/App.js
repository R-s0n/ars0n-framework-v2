﻿import { useState, useEffect } from 'react';
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
import ExportModal from './modals/ExportModal.js';
import GoogleDorkingModal from './modals/GoogleDorkingModal.js';
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
  Accordion,
  Modal,
  Table,
  Toast,
  ToastContainer,
  Spinner,
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
import { MdCopyAll, MdCheckCircle } from 'react-icons/md';
import initiateHttpxScan from './utils/initiateHttpxScan';
import monitorHttpxScanStatus from './utils/monitorHttpxScanStatus';
import initiateGauScan from './utils/initiateGauScan.js';
import monitorGauScanStatus from './utils/monitorGauScanStatus.js';
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
import fetchConsolidatedCompanyDomains from './utils/fetchConsolidatedCompanyDomains.js';
import consolidateNetworkRanges from './utils/consolidateNetworkRanges.js';
import fetchConsolidatedNetworkRanges from './utils/fetchConsolidatedNetworkRanges.js';
import monitorShuffleDNSScanStatus from './utils/monitorShuffleDNSScanStatus.js';
import initiateShuffleDNSScan from './utils/initiateShuffleDNSScan.js';
import initiateCeWLScan from './utils/initiateCeWLScan';
import monitorCeWLScanStatus from './utils/monitorCeWLScanStatus';
import { CeWLResultsModal } from './modals/cewlModals';
import { GoSpiderResultsModal } from './modals/gospiderModals';
import initiateGoSpiderScan from './utils/initiateGoSpiderScan';
import monitorGoSpiderScanStatus from './utils/monitorGoSpiderScanStatus';
import { SubdomainizerResultsModal } from './modals/subdomainizerModals';
import initiateSubdomainizerScan from './utils/initiateSubdomainizerScan';
import monitorSubdomainizerScanStatus from './utils/monitorSubdomainizerScanStatus';
import initiateNucleiScreenshotScan from './utils/initiateNucleiScreenshotScan';
import monitorNucleiScreenshotScanStatus from './utils/monitorNucleiScreenshotScanStatus';
import initiateMetaDataScan, { initiateCompanyMetaDataScan } from './utils/initiateMetaDataScan';
import monitorMetaDataScanStatus, { monitorCompanyMetaDataScanStatus } from './utils/monitorMetaDataScanStatus';
import MetaDataModal from './modals/MetaDataModal.js';
import fetchHttpxScans from './utils/fetchHttpxScans';
import ROIReport from './components/ROIReport';
import HelpMeLearn from './components/HelpMeLearn';
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
import initiateInvestigateScan from './utils/initiateInvestigateScan';
import monitorInvestigateScanStatus from './utils/monitorInvestigateScanStatus';
import TrimRootDomainsModal from './modals/TrimRootDomainsModal.js';
import TrimNetworkRangesModal from './modals/TrimNetworkRangesModal.js';
import LiveWebServersResultsModal from './modals/LiveWebServersResultsModal.js';
import fetchMetabigorCompanyScans from './utils/fetchMetabigorCompanyScans';

import monitorIPPortScanStatus from './utils/monitorIPPortScanStatus';
import initiateIPPortScan from './utils/initiateIPPortScan';
import fetchIPPortScans from './utils/fetchIPPortScans';

// Add helper function
const getHttpxResultsCount = (scan) => {
  if (!scan?.result?.String) return 0;
  return scan.result.String.split('\n').filter(line => line.trim()).length;
};

// Add helper function to get network ranges count for Amass Intel
const getAmassIntelNetworkRangesCount = (networkRanges) => {
  return Array.isArray(networkRanges) ? networkRanges.length : 0;
};

// Add helper function to get network ranges count for Metabigor
const getMetabigorNetworkRangesCount = (networkRanges) => {
  return Array.isArray(networkRanges) ? networkRanges.length : 0;
};

// Calculate estimated IP/Port scan time based on network ranges
const calculateEstimatedScanTime = (networkRanges) => {
  if (!Array.isArray(networkRanges) || networkRanges.length === 0) {
    return "N/A";
  }

  let totalIPs = 0;
  
  networkRanges.forEach(range => {
    const cidr = range.cidr_block;
    if (!cidr) return;
    
    try {
      // Parse CIDR notation (e.g., "192.168.1.0/24")
      const [ip, prefixLength] = cidr.split('/');
      const prefix = parseInt(prefixLength, 10);
      
      if (prefix >= 0 && prefix <= 32) {
        // Calculate number of possible IPs in this CIDR block
        const hostBits = 32 - prefix;
        const possibleIPs = Math.pow(2, hostBits);
        totalIPs += possibleIPs;
      }
    } catch (error) {
      console.error('Error parsing CIDR:', cidr, error);
    }
  });

  // Apply the algorithm: 1 second timeout per IP, assume 20% go through port scan
  const estimatedSeconds = totalIPs * 1 * 0.2;
  
  // Format the time nicely
  if (estimatedSeconds < 60) {
    return `${Math.round(estimatedSeconds)}s`;
  } else if (estimatedSeconds < 3600) {
    const minutes = Math.round(estimatedSeconds / 60);
    return `${minutes}m`;
  } else if (estimatedSeconds < 86400) {
    const hours = Math.round(estimatedSeconds / 3600);
    return `${hours}h`;
  } else {
    const days = Math.round(estimatedSeconds / 86400);
    return `${days}d`;
  }
};

// Add this function before the App component
const calculateROIScore = (targetURL) => {
  let score = 50;
  
  const sslIssues = [
    targetURL.has_deprecated_tls,
    targetURL.has_expired_ssl,
    targetURL.has_mismatched_ssl,
    targetURL.has_revoked_ssl,
    targetURL.has_self_signed_ssl,
    targetURL.has_untrusted_root_ssl
  ].filter(Boolean).length;
  
  if (sslIssues > 0) {
    score += sslIssues * 25;
  }
  
  let katanaCount = 0;
  if (targetURL.katana_results) {
    if (Array.isArray(targetURL.katana_results)) {
      katanaCount = targetURL.katana_results.length;
    } else if (typeof targetURL.katana_results === 'string') {
      if (targetURL.katana_results.startsWith('[') || targetURL.katana_results.startsWith('{')) {
        try {
          const parsed = JSON.parse(targetURL.katana_results);
          katanaCount = Array.isArray(parsed) ? parsed.length : 1;
        } catch {
          katanaCount = targetURL.katana_results.split('\n').filter(line => line.trim()).length;
        }
      } else {
        katanaCount = targetURL.katana_results.split('\n').filter(line => line.trim()).length;
      }
    }
  }

  if (katanaCount > 0) {
    score += katanaCount;
  }

  let ffufCount = 0;
  if (targetURL.ffuf_results) {
    if (typeof targetURL.ffuf_results === 'object') {
      ffufCount = targetURL.ffuf_results.endpoints?.length || Object.keys(targetURL.ffuf_results).length || 0;
    } else if (typeof targetURL.ffuf_results === 'string') {
      try {
        const parsed = JSON.parse(targetURL.ffuf_results);
        ffufCount = parsed.endpoints?.length || Object.keys(parsed).length || 0;
      } catch {
        ffufCount = targetURL.ffuf_results.split('\n').filter(line => line.trim()).length;
      }
    }
  }
  
  if (ffufCount > 3) {
    const extraEndpoints = ffufCount - 3;
    const fuzzPoints = Math.min(15, extraEndpoints * 3);
    score += fuzzPoints;
  }
  
  const techCount = targetURL.technologies?.length || 0;
  if (techCount > 0) {
    score += techCount * 3;
  }
  
  if (targetURL.status_code === 200 && katanaCount > 10) {
    try {
      const headers = typeof targetURL.http_response_headers === 'string' 
        ? JSON.parse(targetURL.http_response_headers)
        : targetURL.http_response_headers;
      
      const hasCSP = Object.keys(headers || {}).some(header => 
        header.toLowerCase() === 'content-security-policy'
      );
      
      if (!hasCSP) {
        score += 10;
      }
    } catch (error) {
      console.error('Error checking CSP header:', error);
    }
  }
  
  try {
    const headers = typeof targetURL.http_response_headers === 'string'
      ? JSON.parse(targetURL.http_response_headers)
      : targetURL.http_response_headers;
    
    const hasCachingHeaders = Object.keys(headers || {}).some(header => {
      const headerLower = header.toLowerCase();
      return ['cache-control', 'etag', 'expires', 'vary'].includes(headerLower);
    });
    
    if (hasCachingHeaders) {
      score += 10;
    }
  } catch (error) {
    console.error('Error checking caching headers:', error);
  }
  
  return Math.max(0, Math.round(score));
};

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
  const [showUniqueSubdomainsModal, setShowUniqueSubdomainsModal] = useState(false);
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
  const [ipPortScans, setIPPortScans] = useState([]);
  const [mostRecentIPPortScan, setMostRecentIPPortScan] = useState(null);
  const [mostRecentIPPortScanStatus, setMostRecentIPPortScanStatus] = useState(null);
  const [isIPPortScanning, setIsIPPortScanning] = useState(false);
  const [MetaDataScans, setMetaDataScans] = useState([]);
  const [mostRecentMetaDataScanStatus, setMostRecentMetaDataScanStatus] = useState(null);
  const [mostRecentMetaDataScan, setMostRecentMetaDataScan] = useState(null);
  const [isMetaDataScanning, setIsMetaDataScanning] = useState(false);
  const [showMetaDataModal, setShowMetaDataModal] = useState(false);
  const [companyMetaDataScans, setCompanyMetaDataScans] = useState([]);
  const [mostRecentCompanyMetaDataScanStatus, setMostRecentCompanyMetaDataScanStatus] = useState(null);
  const [mostRecentCompanyMetaDataScan, setMostRecentCompanyMetaDataScan] = useState(null);
  const [isCompanyMetaDataScanning, setIsCompanyMetaDataScanning] = useState(false);
  const [companyMetaDataResults, setCompanyMetaDataResults] = useState([]);


  const handleCloseSubdomainsModal = () => setShowSubdomainsModal(false);
  const handleCloseCloudDomainsModal = () => setShowCloudDomainsModal(false);
  const handleCloseUniqueSubdomainsModal = () => setShowUniqueSubdomainsModal(false);
  const handleCloseMetaDataModal = () => setShowMetaDataModal(false);
  const handleCloseSettingsModal = () => {
    setShowSettingsModal(false);
    const checkApiKeys = async () => {
      try {
        const response = await fetch(
          `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/api-keys`
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

  const handleTrimNetworkRanges = () => {
    handleOpenTrimNetworkRangesModal();
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
      const response = await fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/add`, {
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

  useEffect(() => {
    if (activeTarget) {
      fetchAmassScans(activeTarget, setAmassScans, setMostRecentAmassScan, setMostRecentAmassScanStatus, setDnsRecords, setSubdomains, setCloudDomains);
              fetchAmassIntelScans(activeTarget, setAmassIntelScans, setMostRecentAmassIntelScan, setMostRecentAmassIntelScanStatus, setAmassIntelNetworkRanges);
      fetchMetabigorCompanyScans(activeTarget, setMetabigorCompanyScans, setMostRecentMetabigorCompanyScan, setMostRecentMetabigorCompanyScanStatus, setMetabigorNetworkRanges);
      fetchHttpxScans(activeTarget, setHttpxScans, setMostRecentHttpxScan, setMostRecentHttpxScanStatus);
      fetchConsolidatedSubdomains(activeTarget, setConsolidatedSubdomains, setConsolidatedCount);
      fetchConsolidatedCompanyDomains(activeTarget, setConsolidatedCompanyDomains, setConsolidatedCompanyDomainsCount);
      fetchConsolidatedNetworkRanges(activeTarget, setConsolidatedNetworkRanges, setConsolidatedNetworkRangesCount);
      fetchGoogleDorkingDomains();
      fetchReverseWhoisDomains();
      fetchIPPortScans(activeTarget, setIPPortScans, setMostRecentIPPortScan, setMostRecentIPPortScanStatus);
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
            `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/scope-targets/${activeTarget.id}/shufflednscustom-scans`
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
            `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/auto-scan/sessions?target_id=${activeTarget.id}`
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
            `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/auto-scan-state/${activeTarget.id}`
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
        // Other functions
        handleConsolidate
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
          `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/amass/${mostRecentScan.scan_id}/subdomain`
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
          `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/amass/${mostRecentScan.scan_id}/cloud`
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
          `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/amass/${mostRecentScan.scan_id}/dns`
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
        const response = await fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/add`, {
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

  const handleDelete = async () => {
    if (!activeTarget) return;

    try {
      const response = await fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/delete/${activeTarget.id}`, {
        method: 'DELETE',
      });

      if (!response.ok) {
        throw new Error('Failed to delete scope target');
      }

      setScopeTargets((prev) => {
        const updatedTargets = prev.filter((target) => target.id !== activeTarget.id);
        const newActiveTarget = updatedTargets.length > 0 ? updatedTargets[0] : null;
        setActiveTarget(newActiveTarget);
        if (!newActiveTarget && showActiveModal) {
          setShowActiveModal(false);
          setShowModal(true);
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
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/read`
      );
      if (!response.ok) {
        throw new Error('Failed to fetch scope targets');
      }
      const data = await response.json();
      setScopeTargets(data || []);
      setFadeIn(true);
      
      if (data && data.length > 0) {
        // Find the active scope target
        const activeTargets = data.filter(target => target.active);
        
        if (activeTargets.length === 1) {
          // One active target found, use it
          setActiveTarget(activeTargets[0]);
        } else {
          // No active target or multiple active targets, use first target and set it as active
          setActiveTarget(data[0]);
          // Call the API to set the first target as active
          try {
            await fetch(
              `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${data[0].id}/activate`,
              {
                method: 'POST',
              }
            );
          } catch (error) {
            console.error('Error setting active scope target:', error);
          }
        }
      } else {
        setShowModal(true);
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
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${target.id}/activate`,
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
          `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${target.id}/scans/nuclei-screenshot`
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
          `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${target.id}/scans/metadata`
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
          `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${target.id}/scans/cewl`
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
          `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${target.id}/scans/shuffledns`
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
          `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/scope-targets/${target.id}/shufflednscustom-scans`
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
          `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${target.id}/scans/securitytrails-company`
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
          `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${target.id}/scans/censys-company`
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
          `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${target.id}/scans/shodan-company`
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
          `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${target.id}/scans/github-recon`
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
    console.log('[AutoScan] Starting Auto Scan. Fetching config from backend...');
    
    // Reset all scan-related states to avoid state persistence between scans
    setAutoScanCurrentStep(AUTO_SCAN_STEPS.IDLE);
    setIsAutoScanning(false);
    setIsAutoScanPaused(false);
    setIsAutoScanPausing(false);
    setIsAutoScanCancelling(false);
    
    // Only reset consolidation state, not the actual subdomains
    setIsConsolidating(false);
    
    // Reset individual scan states
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
    
    // Add a small delay to ensure state is fully reset
    await new Promise(resolve => setTimeout(resolve, 100));

    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/auto-scan-config`
      );
      if (!response.ok) {
        throw new Error('Failed to fetch auto scan config');
      }
      const config = await response.json();
      console.log('[AutoScan] Config received from backend:', config);
      // Create session
      const sessionResp = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/auto-scan/session/start`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            scope_target_id: activeTarget.id,
            config_snapshot: config
          })
        }
      );
      if (!sessionResp.ok) throw new Error('Failed to create auto scan session');
      const sessionData = await sessionResp.json();
      console.error(sessionData)
      setAutoScanSessionId(sessionData.session_id);
      
      // Now set isAutoScanning to true after all resets and config fetching
      setIsAutoScanning(true);
      
      startAutoScanUtil(
        activeTarget,
        setIsAutoScanning,
        setAutoScanCurrentStep,
        setAutoScanTargetId,
        () => getAutoScanSteps(
          activeTarget,
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
          sessionData.session_id // pass session id
        ),
        consolidatedSubdomains, // pass consolidated subdomains
        mostRecentHttpxScan, // pass most recent httpx scan
        sessionData.session_id // pass session id
      );
    } catch (error) {
      console.error('[AutoScan] Error fetching config or starting scan:', error);
    }
  };

  const startHttpxScan = () => {
    initiateHttpxScan(
      activeTarget,
      monitorHttpxScanStatus,
      setIsHttpxScanning,
      setHttpxScans,
      setMostRecentHttpxScanStatus,
      setMostRecentHttpxScan
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
      null, // Don't use old monitoring - we handle this in the shufflednscustom useEffect now
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
      const response = await fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/google-dorking-domains`, {
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
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/google-dorking-domains/${activeTarget.id}`
      );
      if (response.ok) {
        const domains = await response.json();
        setGoogleDorkingDomains(domains);
      }
    } catch (error) {
      console.error('Error fetching Google dorking domains:', error);
    }
  };

  const deleteGoogleDorkingDomain = async (domainId) => {
    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/google-dorking-domains/${domainId}`,
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
    if (!activeTarget) return;
    
    setIsConsolidating(true);
    try {
      const result = await consolidateSubdomains(activeTarget);
      if (result) {
        await fetchConsolidatedSubdomains(activeTarget, setConsolidatedSubdomains, setConsolidatedCount);
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

  const handleOpenUniqueSubdomainsModal = () => setShowUniqueSubdomainsModal(true);

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
      monitorMetabigorCompanyScanStatus(
        activeTarget,
        setMetabigorCompanyScans,
        setMostRecentMetabigorCompanyScan,
        setIsMetabigorCompanyScanning,
        setMostRecentMetabigorCompanyScanStatus
      );
    }
  }, [activeTarget]);

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

  const startMetaDataScan = () => {
    initiateMetaDataScan(
      activeTarget,
      monitorMetaDataScanStatus,
      setIsMetaDataScanning,
      setMetaDataScans,
      setMostRecentMetaDataScanStatus,
      setMostRecentMetaDataScan
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

  const handleOpenMetaDataModal = async () => {
    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/scope-targets/${activeTarget.id}/target-urls`
      );
      if (!response.ok) {
        throw new Error('Failed to fetch target URLs');
      }
      const data = await response.json();
      setTargetURLs(data);
      setShowMetaDataModal(true);
    } catch (error) {
      console.error('Error fetching target URLs:', error);
    }
  };

  const handleOpenROIReport = async () => {
    try {
      // First, get the latest target URLs
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/scope-targets/${activeTarget.id}/target-urls`
      );
      if (!response.ok) {
        throw new Error('Failed to fetch target URLs');
      }
      const data = await response.json();

      // Calculate and update ROI scores for each target
      const updatePromises = data.map(async (target) => {
        const score = calculateROIScore(target);
        const updateResponse = await fetch(
          `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/target-urls/${target.id}/roi-score`,
          {
            method: 'PUT',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ roi_score: score }),
          }
        );
        if (!updateResponse.ok) {
          console.error(`Failed to update ROI score for target ${target.id}`);
        }
      });

      // Wait for all updates to complete
      await Promise.all(updatePromises);

      // Fetch the updated target URLs
      const updatedResponse = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/scope-targets/${activeTarget.id}/target-urls`
      );
      if (!updatedResponse.ok) {
        throw new Error('Failed to fetch updated target URLs');
      }
      const updatedData = await updatedResponse.json();
      setTargetURLs(updatedData);
      setShowROIReport(true);
    } catch (error) {
      console.error('Error preparing ROI report:', error);
    }
  };

  const handleCloseROIReport = () => {
    setShowROIReport(false);
  };

  const handleOpenSettingsModal = () => {
    setShowSettingsModal(true);
  };

  const handleOpenExportModal = () => {
    setShowExportModal(true);
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
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/auto-scan-state/${targetId}`
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
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/auto-scan/sessions?target_id=${activeTarget.id}`
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
              nuclei_screenshot: config.nuclei_screenshot !== false,
              metadata: config.metadata !== false
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
            `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/auto-scan-state/${activeTarget.id}`
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
      const response = await fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/reverse-whois-domains`, {
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
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/reverse-whois-domains/${activeTarget.id}`
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
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/reverse-whois-domains/${domainId}`,
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
            `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${activeTarget.id}/scans/securitytrails-company`
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
          `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/api-keys`
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
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/api-keys`
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
            `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${activeTarget.id}/scans/censys-company`
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
            `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${activeTarget.id}/scans/shodan-company`
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
        
      } catch (error) {
        console.error('Error refreshing individual tool scan data after deletion:', error);
      }
    }
  };

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
        onExportClick={handleOpenExportModal}
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
          delay={3000}
        >
          <Toast.Header>
            <MdCheckCircle 
              className="success-icon me-2" 
              size={20} 
              color="#ff0000"
            />
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
              <span>{toastMessage}</span>
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
      />

      <SelectActiveScopeTargetModal
        showActiveModal={showActiveModal}
        handleActiveModalClose={handleActiveModalClose}
        scopeTargets={scopeTargets}
        activeTarget={activeTarget}
        handleActiveSelect={handleActiveSelect}
        handleDelete={handleDelete}
      />

      <SettingsModal
        show={showSettingsModal}
        handleClose={handleCloseSettingsModal}
        initialTab={settingsModalInitialTab}
        onApiKeyDeleted={handleApiKeyDeleted}
      />

      <ExportModal
        show={showExportModal}
        handleClose={handleCloseExportModal}
      />

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
                <h4 className="text-secondary mb-3 fs-5">Root Domain Discovery (No API Key)</h4>
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
                        mostRecentCTLCompanyScan.result.split('\n').filter(line => line.trim()).length : 0
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
                          <Card.Title className="text-danger mb-3">
                            <a href={tool.link} className="text-danger text-decoration-none">
                              {tool.name}
                            </a>
                          </Card.Title>
                          <Card.Text className="text-white small fst-italic">
                            {tool.description}
                          </Card.Text>
                          <div className="mt-auto">
                            <Card.Text className="text-white small mb-3">
                              Domains: {tool.resultCount || "0"}
                            </Card.Text>
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
                            <Card.Text className="text-white small mb-3">
                              Domains: {tool.resultCount || "0"}
                            </Card.Text>
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
                              <h3 className="mb-0">{consolidatedCompanyDomainsCount}</h3>
                              <small className="text-white-50">Unique Root Domains</small>
                            </div>
                            <div className="col">
                              <h3 className="mb-0">{
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
                              }</h3>
                              <small className="text-white-50">Wildcard Targets Created</small>
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
                
                <h4 className="text-secondary mb-3 fs-5">ASN (On-Prem) Network Ranges</h4>
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
                      resultLabel: 'Network Ranges'
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
                      resultLabel: 'Network Ranges'
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
                            <Card.Text className="text-white small mb-3">
                              {tool.resultLabel}: {tool.resultCount || "0"}
                            </Card.Text>
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
                              <h3 className="mb-0">{consolidatedNetworkRangesCount}</h3>
                              <small className="text-white-50">Network Ranges</small>
                            </div>
                            <div className="col">
                              <h3 className="mb-0">{calculateEstimatedScanTime(consolidatedNetworkRanges)}</h3>
                              <small className="text-white-50">Est. Scan Time</small>
                            </div>
                            <div className="col">
                              <h3 className="mb-0">{mostRecentIPPortScan?.live_web_servers_found || 0}</h3>
                              <small className="text-white-50">Live Web Servers</small>
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
                          <Card.Text className="text-white small d-flex justify-content-between">
                            <span>Last Scanned: &nbsp;&nbsp;{getLastScanDate(amassScans)}</span>
                            <span>Total Results: {getResultLength(scanHistory[scanHistory.length - 1]) || "N/a"}</span>
                          </Card.Text>
                          <Card.Text className="text-white small d-flex justify-content-between">
                            <span>Last Scan Status: &nbsp;&nbsp;{getLatestScanStatus(amassScans)}</span>
                            <span>Cloud Domains: {cloudDomains.length || "0"}</span>
                          </Card.Text>
                          <Card.Text className="text-white small d-flex justify-content-between">
                            <span>Scan Time: &nbsp;&nbsp;{getExecutionTime(getLatestScanTime(amassScans))}</span>
                            <span>Subdomains: {subdomains.length || "0"}</span>
                          </Card.Text>
                          <Card.Text className="text-white small d-flex justify-content-between mb-3">
                            <span>Scan ID: {renderScanId(getLatestScanId(amassScans))}</span>
                            <span>DNS Records: {dnsRecords.length}</span>
                          </Card.Text>
                        </div>
                        <div className="d-flex justify-content-between w-100 mt-3 gap-2">
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
                    { name: 'Sublist3r', 
                      link: 'https://github.com/huntergregal/Sublist3r',
                      isActive: true,
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
                      status: mostRecentCTLScanStatus,
                      isScanning: isCTLScanning,
                      onScan: startCTLScan,
                      onResults: handleOpenCTLResultsModal,
                      resultCount: mostRecentCTLScan && mostRecentCTLScan.result ? 
                        mostRecentCTLScan.result.split('\n').filter(line => line.trim()).length : 0
                    },
                    { name: 'Subfinder', 
                      link: 'https://github.com/projectdiscovery/subfinder',
                      isActive: true,
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
                          <Card.Title className="text-danger mb-3">
                            <a href={tool.link} className="text-danger text-decoration-none">
                              {tool.name}
                            </a>
                          </Card.Title>
                          <Card.Text className="text-white small fst-italic">
                            {tool.name === 'GAU' ? 'Get All URLs - Fetch known URLs from AlienVault\'s Open Threat Exchange, the Wayback Machine, and Common Crawl.' : 'A subdomain enumeration tool that uses OSINT techniques.'}
                          </Card.Text>
                          <div className="mt-auto">
                            <Card.Text className="text-white small mb-3">
                              Subdomains: {tool.resultCount || "0"}
                            </Card.Text>
                            <div className="d-flex justify-content-between gap-2">
                              {tool.isActive ? (
                                <>
                                  <Button 
                                    variant="outline-danger" 
                                    className="flex-fill" 
                                    onClick={tool.onResults}
                                  >
                                    Results
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
                                </>
                              ) : (
                                <>
                                  <Button variant="outline-danger" className="flex-fill" disabled>Results</Button>
                                  <Button variant="outline-danger" className="flex-fill" disabled>Scan</Button>
                                </>
                              )}
                            </div>
                          </div>
                        </Card.Body>
                      </Card>
                    </Col>
                  ))}
                </Row>
                <h4 className="text-secondary mb-3 fs-5">Consolidate Subdomains & Discover Live Web Servers - Round 1</h4>
                <Accordion data-bs-theme="dark" className="mb-3">
                  <Accordion.Item eventKey="0">
                    <Accordion.Header className="fs-5">Help Me Learn!</Accordion.Header>
                    <Accordion.Body className="bg-dark">
                      <ListGroup as="ul" variant="flush">
                        <ListGroup.Item as="li" className="bg-dark text-white">
                          Major learning topic one{' '}
                          <a href="https://example.com/topic1" className="text-danger text-decoration-none">
                            Learn More
                          </a>
                          <ListGroup as="ul" variant="flush" className="mt-2">
                            <ListGroup.Item as="li" className="bg-dark text-white fst-italic">
                              Minor Topic one{' '}
                              <a href="#" className="text-danger text-decoration-none">
                                Learn More
                              </a>
                            </ListGroup.Item>
                          </ListGroup>
                        </ListGroup.Item>
                        <ListGroup.Item as="li" className="bg-dark text-white">
                          Major learning topic two{' '}
                          <a href="https://example.com/topic2" className="text-danger text-decoration-none">
                            Learn More
                          </a>
                        </ListGroup.Item>
                      </ListGroup>
                    </Accordion.Body>
                  </Accordion.Item>
                </Accordion>
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
                              <h3 className="mb-0">{consolidatedCount}</h3>
                              <small className="text-white-50">Unique Subdomains</small>
                            </div>
                            <div className="col">
                              <h3 className="mb-0">{getHttpxResultsCount(mostRecentHttpxScan)}</h3>
                              <small className="text-white-50">Live Web Servers</small>
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
                            <Card.Text className="text-white small mb-3">
                              Subdomains: {tool.resultCount || "0"}
                            </Card.Text>
                          )}
                          <div className="d-flex justify-content-between mt-auto gap-2">
                            <Button 
                              variant="outline-danger" 
                              className="flex-fill"
                              onClick={tool.onResults}
                              disabled={!tool.isActive || !tool.resultCount}
                            >
                              Results
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
                          </div>
                        </Card.Body>
                      </Card>
                    </Col>
                  ))}
                </Row>
                <h4 className="text-secondary mb-3 fs-5">Consolidate Subdomains & Discover Live Web Servers - Round 2</h4>
                <Accordion data-bs-theme="dark" className="mb-3">
                  <Accordion.Item eventKey="0">
                    <Accordion.Header className="fs-5">Help Me Learn!</Accordion.Header>
                    <Accordion.Body className="bg-dark">
                      <ListGroup as="ul" variant="flush">
                        <ListGroup.Item as="li" className="bg-dark text-white">
                          Major learning topic one{' '}
                          <a href="https://example.com/topic1" className="text-danger text-decoration-none">
                            Learn More
                          </a>
                          <ListGroup as="ul" variant="flush" className="mt-2">
                            <ListGroup.Item as="li" className="bg-dark text-white fst-italic">
                              Minor Topic one{' '}
                              <a href="#" className="text-danger text-decoration-none">
                                Learn More
                              </a>
                            </ListGroup.Item>
                          </ListGroup>
                        </ListGroup.Item>
                        <ListGroup.Item as="li" className="bg-dark text-white">
                          Major learning topic two{' '}
                          <a href="https://example.com/topic2" className="text-danger text-decoration-none">
                            Learn More
                          </a>
                        </ListGroup.Item>
                      </ListGroup>
                    </Accordion.Body>
                  </Accordion.Item>
                </Accordion>
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
                              <h3 className="mb-0">{consolidatedCount}</h3>
                              <small className="text-white-50">Unique Subdomains</small>
                            </div>
                            <div className="col">
                              <h3 className="mb-0">{getHttpxResultsCount(mostRecentHttpxScan)}</h3>
                              <small className="text-white-50">Live Web Servers</small>
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
                            <Card.Text className="text-white small mb-3">
                              Subdomains: {tool.resultCount || "0"}
                            </Card.Text>
                          )}
                          <div className="d-flex justify-content-between mt-auto gap-2">
                            <Button 
                              variant="outline-danger" 
                              className="flex-fill"
                              onClick={tool.onResults}
                              disabled={!tool.isActive || !tool.resultCount}
                            >
                              Results
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
                          </div>
                        </Card.Body>
                      </Card>
                    </Col>
                  ))}
                </Row>
                <h4 className="text-secondary mb-3 fs-5">Consolidate Subdomains & Discover Live Web Servers - Round 3</h4>
                <Accordion data-bs-theme="dark" className="mb-3">
                  <Accordion.Item eventKey="0">
                    <Accordion.Header className="fs-5">Help Me Learn!</Accordion.Header>
                    <Accordion.Body className="bg-dark">
                      <ListGroup as="ul" variant="flush">
                        <ListGroup.Item as="li" className="bg-dark text-white">
                          Major learning topic one{' '}
                          <a href="https://example.com/topic1" className="text-danger text-decoration-none">
                            Learn More
                          </a>
                          <ListGroup as="ul" variant="flush" className="mt-2">
                            <ListGroup.Item as="li" className="bg-dark text-white fst-italic">
                              Minor Topic one{' '}
                              <a href="#" className="text-danger text-decoration-none">
                                Learn More
                              </a>
                            </ListGroup.Item>
                          </ListGroup>
                        </ListGroup.Item>
                        <ListGroup.Item as="li" className="bg-dark text-white">
                          Major learning topic two{' '}
                          <a href="https://example.com/topic2" className="text-danger text-decoration-none">
                            Learn More
                          </a>
                        </ListGroup.Item>
                      </ListGroup>
                    </Accordion.Body>
                  </Accordion.Item>
                </Accordion>
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
                              <h3 className="mb-0">{consolidatedCount}</h3>
                              <small className="text-white-50">Unique Subdomains</small>
                            </div>
                            <div className="col">
                              <h3 className="mb-0">{getHttpxResultsCount(mostRecentHttpxScan)}</h3>
                              <small className="text-white-50">Live Web Servers</small>
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
                      <Card.Body className="d-flex flex-column justify-content-between text-center">
                        <div>
                          <Card.Title className="text-danger fs-3 mb-3">Add URL Scope Target</Card.Title>
                          <Card.Text className="text-white small fst-italic">
                            We now have a list of unique subdomains pointing to live web servers. The next step is to take screenshots of each web application and gather data to identify the target that will give us the greatest ROI as a bug bounty hunter. Focus on signs that the target may have vulnerabilities, may not be maintained, or offers a large attack surface.
                          </Card.Text>
                          <div className="d-flex justify-content-around mt-4 mb-4">
                            <div className="text-center px-4">
                              <div className="digital-clock text-danger fw-bold" style={{
                                fontFamily: "'Digital-7', monospace",
                                fontSize: "2.5rem",
                                textShadow: "0 0 10px rgba(255, 0, 0, 0.5)",
                                letterSpacing: "2px"
                              }}>
                                {mostRecentNucleiScreenshotScan ? 
                                  Math.floor((new Date() - new Date(mostRecentNucleiScreenshotScan.created_at)) / (1000 * 60 * 60 * 24)) : 
                                  '∞'}
                              </div>
                              <div className="text-white small mt-2">day{mostRecentNucleiScreenshotScan && 
                                Math.floor((new Date() - new Date(mostRecentNucleiScreenshotScan.created_at)) / (1000 * 60 * 60 * 24)) !== 1 ? 's' : ''} since last Screenshots</div>
                            </div>
                            <div className="text-center px-4">
                              <div className="digital-clock text-danger fw-bold" style={{
                                fontFamily: "'Digital-7', monospace",
                                fontSize: "2.5rem",
                                textShadow: "0 0 10px rgba(255, 0, 0, 0.5)",
                                letterSpacing: "2px"
                              }}>
                                {mostRecentMetaDataScan ? 
                                  Math.floor((new Date() - new Date(mostRecentMetaDataScan.created_at)) / (1000 * 60 * 60 * 24)) : 
                                  '∞'}
                              </div>
                              <div className="text-white small mt-2">day{mostRecentMetaDataScan && 
                                Math.floor((new Date() - new Date(mostRecentMetaDataScan.created_at)) / (1000 * 60 * 60 * 24)) !== 1 ? 's' : ''} since last MetaData</div>
                            </div>
                          </div>
                        </div>
                        <div className="d-flex flex-column gap-3 w-100 mt-3">
                          <div className="d-flex justify-content-between gap-2">
                            <Button variant="outline-danger" className="flex-fill" onClick={handleOpenReconResultsModal}>Recon Results</Button>
                            <Button 
                              variant="outline-danger" 
                              className="flex-fill"
                              onClick={startNucleiScreenshotScan}
                              disabled={!mostRecentHttpxScan || 
                                      mostRecentHttpxScan.status !== "success" || 
                                      !httpxScans || 
                                      httpxScans.length === 0}
                            >
                              <div className="btn-content">
                                {isNucleiScreenshotScanning || mostRecentNucleiScreenshotScanStatus === "pending" ? (
                                  <div className="spinner"></div>
                                ) : 'Take Screenshots'}
                              </div>
                            </Button>
                            <Button 
                              variant="outline-danger" 
                              className="flex-fill"
                              onClick={handleOpenScreenshotResultsModal}
                              disabled={!mostRecentNucleiScreenshotScan || mostRecentNucleiScreenshotScan.status !== "success"}
                            >
                              View Screenshots
                            </Button>
                            <Button 
                              variant="outline-danger" 
                              className="flex-fill"
                              onClick={startMetaDataScan}
                              disabled={!mostRecentHttpxScan || 
                                      mostRecentHttpxScan.status !== "success" || 
                                      !httpxScans || 
                                      httpxScans.length === 0}
                            >
                              <div className="btn-content">
                                {isMetaDataScanning || mostRecentMetaDataScanStatus === "pending" || mostRecentMetaDataScanStatus === "running" ? (
                                  <div className="spinner"></div>
                                ) : 'Gather Metadata'}
                              </div>
                            </Button>
                            <Button 
                              variant="outline-danger" 
                              className="flex-fill"
                              onClick={handleOpenMetaDataModal}
                              disabled={!mostRecentMetaDataScan || mostRecentMetaDataScan.status !== "success"}
                            >
                              View Metadata
                            </Button>
                            <Button 
                              variant="outline-danger" 
                              className="flex-fill"
                              onClick={handleOpenROIReport}
                              disabled={!mostRecentNucleiScreenshotScan || 
                                      mostRecentNucleiScreenshotScan.status !== "success" || 
                                      !mostRecentMetaDataScan || 
                                      mostRecentMetaDataScan.status !== "success"}
                            >
                              ROI Report
                            </Button>
                          </div>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>
              </div>
            )}
            {activeTarget.type === 'URL' && (
              <div className="mb-4">
                <h3 className="text-danger">URL</h3>
                <Row>
                  <Col md={12}>
                    <Card className="mb-3 shadow-sm">
                      <Card.Body className="text-center">
                        <Card.Title className="text-danger mb-4">Coming Soon!</Card.Title>
                        <Card.Text>
                          The URL workflow is currently under development. rs0n is working hard to create powerful features for analyzing individual target URLs.
                        </Card.Text>
                        <Card.Text className="text-muted fst-italic mt-4">
                          Please note that rs0n maintains this tool while balancing a full-time job and family life. This is a passion project provided free to the community, and your patience and kindness are greatly appreciated! 💝
                        </Card.Text>
                        <Card.Text className="text-danger mt-4">
                          In the meantime, try out our fully-featured Wildcard workflow - it's packed with powerful reconnaissance capabilities!
                        </Card.Text>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>
              </div>
            )}
          </div>
        </Fade>
      )}
      <MetaDataModal
        showMetaDataModal={showMetaDataModal}
        handleCloseMetaDataModal={handleCloseMetaDataModal}
        metaDataResults={mostRecentMetaDataScan}
        targetURLs={targetURLs}
        setTargetURLs={setTargetURLs}
      />
      <ROIReport
        show={showROIReport}
        onHide={handleCloseROIReport}
        targetURLs={targetURLs}
      />
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
                <th colSpan={2} className="text-center bg-dark border-danger">Analysis</th>
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
                <th className="text-center" style={{width: '40px'}}>NSC</th>
                <th className="text-center" style={{width: '40px'}}>MD</th>
              </tr>
            </thead>
            <tbody>
              {(!autoScanSessions || autoScanSessions.length === 0) ? (
                <tr>
                  <td colSpan={20} className="text-center text-white-50">
                    No auto scan sessions found for this target.
                  </td>
                </tr>
              ) : (
                autoScanSessions.map((session) => (
                  <tr key={session.session_id}>
                    <td>{session.start_time}</td>
                    <td>{session.duration || '—'}</td>
                    <td>
                      <span className={`text-${session.status === 'completed' ? 'success' : session.status === 'cancelled' ? 'warning' : 'primary'}`}>
                        {session.status.charAt(0).toUpperCase() + session.status.slice(1)}
                      </span>
                    </td>
                    <td className="text-center"><strong>{session.final_consolidated_subdomains || '—'}</strong></td>
                    <td className="text-center"><strong>{session.final_live_web_servers || '—'}</strong></td>
                    <td className="text-center">{session.config?.amass ? <span className="text-danger fw-bold">✓</span> : ''}</td>
                    <td className="text-center">{session.config?.sublist3r ? <span className="text-danger fw-bold">✓</span> : ''}</td>
                    <td className="text-center">{session.config?.assetfinder ? <span className="text-danger fw-bold">✓</span> : ''}</td>
                    <td className="text-center">{session.config?.gau ? <span className="text-danger fw-bold">✓</span> : ''}</td>
                    <td className="text-center">{session.config?.ctl ? <span className="text-danger fw-bold">✓</span> : ''}</td>
                    <td className="text-center">{session.config?.subfinder ? <span className="text-danger fw-bold">✓</span> : ''}</td>
                    <td className="text-center">{session.config?.httpx_round1 ? <span className="text-danger fw-bold">✓</span> : ''}</td>
                    <td className="text-center">{session.config?.shuffledns ? <span className="text-danger fw-bold">✓</span> : ''}</td>
                    <td className="text-center">{session.config?.cewl ? <span className="text-danger fw-bold">✓</span> : ''}</td>
                    <td className="text-center">{session.config?.httpx_round2 ? <span className="text-danger fw-bold">✓</span> : ''}</td>
                    <td className="text-center">{session.config?.gospider ? <span className="text-danger fw-bold">✓</span> : ''}</td>
                    <td className="text-center">{session.config?.subdomainizer ? <span className="text-danger fw-bold">✓</span> : ''}</td>
                    <td className="text-center">{session.config?.httpx_round3 ? <span className="text-danger fw-bold">✓</span> : ''}</td>
                    <td className="text-center">{session.config?.nuclei_screenshot ? <span className="text-danger fw-bold">✓</span> : ''}</td>
                    <td className="text-center">{session.config?.metadata ? <span className="text-danger fw-bold">✓</span> : ''}</td>
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
                      <small className="text-white-50">
                        Added: {new Date(domainData.created_at).toLocaleDateString()}
                      </small>
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
                <small className="text-white-50">
                  Total domains discovered: {googleDorkingDomains.length}
                </small>
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
                      <small className="text-white-50">
                        Added: {new Date(domainData.created_at).toLocaleDateString()}
                      </small>
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
                <small className="text-white-50">
                  Total domains discovered: {reverseWhoisDomains.length}
                </small>
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

      <GoogleDorkingModal
        show={showGoogleDorkingManualModal}
        handleClose={handleCloseGoogleDorkingManualModal}
        companyName={activeTarget?.scope_target || ''}
        onDomainAdd={handleGoogleDorkingDomainAdd}
        error={googleDorkingError}
        onClearError={() => setGoogleDorkingError('')}
      />

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
      />

    </Container>
  );
}

export default App;