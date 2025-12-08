import React, { useState, useEffect } from 'react';
import { Modal, Button, Form, Table, Badge, Row, Col, Alert, Nav, InputGroup, Spinner } from 'react-bootstrap';
import fetchAttackSurfaceAssets from '../utils/fetchAttackSurfaceAssets';

const ExploreAttackSurfaceModal = ({ 
  show, 
  handleClose, 
  activeTarget 
}) => {
  const [attackSurfaceAssets, setAttackSurfaceAssets] = useState([]);
  const [filteredAssets, setFilteredAssets] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [sortColumn, setSortColumn] = useState('asset_type');
  const [sortDirection, setSortDirection] = useState('asc');
  const [activeTab, setActiveTab] = useState('asn');
  const [filters, setFilters] = useState([{ searchTerm: '', isNegative: false }]);
  const [isPopulatingBurpsuite, setIsPopulatingBurpsuite] = useState(false);

  const assetTypes = [
    { key: 'asn', label: 'Autonomous System Numbers (ASNs)', count: 0 },
    { key: 'network_range', label: 'Network Ranges', count: 0 },
    { key: 'ip_address', label: 'IP Addresses', count: 0 },
    { key: 'fqdn', label: 'Domain Names', count: 0 },
    { key: 'cloud_asset', label: 'Cloud Asset Domains', count: 0 },
    { key: 'live_web_server', label: 'Live Web Servers', count: 0 }
  ];

  useEffect(() => {
    if (show && activeTarget) {
      loadAttackSurfaceAssets();
    }
  }, [show, activeTarget]);

  useEffect(() => {
    applyFiltersAndSort();
  }, [attackSurfaceAssets, filters, sortColumn, sortDirection, activeTab]);

  const loadAttackSurfaceAssets = async () => {
    if (!activeTarget) return;
    
    setLoading(true);
    setError(null);
    
    try {
      const data = await fetchAttackSurfaceAssets(activeTarget);
      setAttackSurfaceAssets(data.assets || []);
    } catch (err) {
      setError('Failed to load attack surface assets');
      console.error('Error loading attack surface assets:', err);
    } finally {
      setLoading(false);
    }
  };

  const getAssetTypeCounts = () => {
    const counts = {};
    assetTypes.forEach(type => {
      counts[type.key] = attackSurfaceAssets.filter(asset => asset.asset_type === type.key).length;
    });
    return counts;
  };

  const applyFiltersAndSort = () => {
    let filtered = [...attackSurfaceAssets];

    filtered = filtered.filter(asset => asset.asset_type === activeTab);

    const activeFilters = filters.filter(filter => filter.searchTerm.trim() !== '');
    
    if (activeFilters.length > 0) {
      filtered = filtered.filter(asset => {
        const searchableFields = [
          asset.asset_identifier,
          asset.asn_number,
          asset.asn_organization,
          asset.asn_description,
          asset.asn_country,
          asset.cidr_block,
          asset.ip_address,
          asset.ip_type,
          asset.url,
          asset.domain,
          asset.port?.toString(),
          asset.status_code?.toString(),
          asset.title,
          asset.web_server,
          asset.cloud_provider,
          asset.cloud_service_type,
          asset.cloud_region,
          asset.fqdn,
          asset.root_domain,
          asset.subdomain,
          asset.registrar,
          asset.creation_date,
          asset.expiration_date,
          asset.ssl_expiry_date,
          asset.ssl_issuer,
          asset.ssl_subject,
          asset.ssl_version,
          asset.ssl_cipher_suite,
          asset.resolved_ips?.join(' '),
          asset.name_servers?.join(' '),
          asset.mail_servers?.join(' '),
          asset.spf_record,
          asset.dkim_record,
          asset.dmarc_record,
          asset.caa_records?.join(' '),
          asset.txt_records?.join(' '),
          asset.mx_records?.join(' '),
          asset.ns_records?.join(' '),
          asset.a_records?.join(' '),
          asset.aaaa_records?.join(' '),
          asset.cname_records?.join(' '),
          asset.ptr_records?.join(' '),
          asset.srv_records?.join(' '),
          asset.ssl_protocols?.join(' '),
          asset.status?.join(' '),
          asset.technologies?.join(' '),
          // Add new searchable fields for FQDN security assessment
          asset.a_records?.join(' '),
          asset.aaaa_records?.join(' '),
          asset.url,
          asset.status_code?.toString(),
          asset.title,
          asset.ssl_expiry_date,
          asset.ssl_issuer
        ].filter(Boolean).join(' ').toLowerCase();
        
        return activeFilters.every(filter => {
          const assetContainsSearch = searchableFields.includes(filter.searchTerm.toLowerCase());
          return filter.isNegative ? !assetContainsSearch : assetContainsSearch;
        });
      });
    }

    filtered.sort((a, b) => {
      let aValue = a[sortColumn];
      let bValue = b[sortColumn];

      if (aValue === null || aValue === undefined) aValue = '';
      if (bValue === null || bValue === undefined) bValue = '';

      if (typeof aValue === 'string') aValue = aValue.toLowerCase();
      if (typeof bValue === 'string') bValue = bValue.toLowerCase();

      if (aValue < bValue) return sortDirection === 'asc' ? -1 : 1;
      if (aValue > bValue) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });

    setFilteredAssets(filtered);
  };

  const addSearchFilter = () => {
    setFilters([...filters, { searchTerm: '', isNegative: false }]);
  };

  const removeSearchFilter = (index) => {
    if (filters.length > 1) {
      const newFilters = filters.filter((_, i) => i !== index);
      setFilters(newFilters);
    }
  };

  const updateSearchFilter = (index, field, value) => {
    const newFilters = [...filters];
    newFilters[index][field] = value;
    setFilters(newFilters);
  };

  const handleFilterChange = (filterKey, value) => {
    setFilters(prev => ({
      ...prev,
      [filterKey]: value
    }));
  };

  const clearFilters = () => {
    setFilters([{ searchTerm: '', isNegative: false }]);
  };

  const handlePopulateBurpsuite = async () => {
    if (activeTab !== 'live_web_server') {
      return;
    }

    const urls = filteredAssets
      .filter(asset => asset.asset_type === 'live_web_server' && asset.url)
      .map(asset => asset.url);

    if (urls.length === 0) {
      setError('No live web server URLs found to populate Burpsuite');
      return;
    }

    setIsPopulatingBurpsuite(true);
    setError(null);

    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/burpsuite/populate`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ urls }),
        }
      );

      if (!response.ok) {
        const errorData = await response.text();
        throw new Error(errorData || 'Failed to populate Burpsuite');
      }

      const data = await response.json();
      console.log('Burpsuite populated successfully:', data);
    } catch (err) {
      console.error('Error populating Burpsuite:', err);
      setError(`Failed to populate Burpsuite: ${err.message}`);
    } finally {
      setIsPopulatingBurpsuite(false);
    }
  };

  const handleSort = (column) => {
    if (sortColumn === column) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortColumn(column);
      setSortDirection('asc');
    }
  };

  const renderSortIcon = (column) => {
    if (sortColumn !== column) return null;
    return sortDirection === 'asc' ? ' ↑' : ' ↓';
  };

  const getAssetTypeBadgeVariant = (assetType) => {
    switch (assetType) {
      case 'asn': return 'primary';
      case 'network_range': return 'secondary';
      case 'ip_address': return 'info';
      case 'live_web_server': return 'success';
      case 'cloud_asset': return 'warning';
      case 'fqdn': return 'danger';
      default: return 'dark';
    }
  };

  const getAssetTypeDisplayName = (assetType) => {
    switch (assetType) {
      case 'asn': return 'ASNs';
      case 'network_range': return 'Network Ranges';
      case 'ip_address': return 'IP Addresses';
      case 'live_web_server': return 'Live Web Servers';
      case 'cloud_asset': return 'Cloud Asset Domains';
      case 'fqdn': return 'Domain Names';
      default: return assetType;
    }
  };

  const renderTableCell = (asset, key) => {
    switch (key) {
      case 'asn_number':
        return asset.asn_number ? <code>AS{asset.asn_number}</code> : <span className="text-white-50">-</span>;
      case 'asn_organization':
        return asset.asn_organization || <span className="text-white-50">-</span>;
      case 'asn_country':
        return asset.asn_country || <span className="text-white-50">-</span>;
      case 'asn_description':
        return asset.asn_description || <span className="text-white-50">-</span>;
      case 'cidr_block':
        return <code>{asset.cidr_block}</code>;
      case 'subnet_size':
        return asset.subnet_size ? asset.subnet_size.toLocaleString() : <span className="text-white-50">-</span>;
      case 'ip_address':
        return <code>{asset.ip_address}</code>;
      case 'resolved_ips':
        const allDNSRecords = [];
        
        if (asset.resolved_ips && asset.resolved_ips.length > 0) {
          asset.resolved_ips.forEach(record => {
            allDNSRecords.push({ type: 'Hostname', value: record, color: 'text-info' });
          });
        }
        
        if (asset.ptr_records && asset.ptr_records.length > 0) {
          asset.ptr_records.forEach(record => {
            allDNSRecords.push({ type: 'PTR', value: record, color: 'text-warning' });
          });
        }
        
        if (asset.a_records && asset.a_records.length > 0) {
          asset.a_records.forEach(record => {
            allDNSRecords.push({ type: 'A', value: record, color: 'text-success' });
          });
        }
        
        if (asset.aaaa_records && asset.aaaa_records.length > 0) {
          asset.aaaa_records.forEach(record => {
            allDNSRecords.push({ type: 'AAAA', value: record, color: 'text-danger' });
          });
        }
        
        if (allDNSRecords.length > 0) {
          return (
            <div style={{ maxWidth: '250px' }}>
              {allDNSRecords.map((record, index) => (
                <div key={index} className={`small ${record.color}`}>
                  <strong>{record.type}:</strong> {record.value}
                </div>
              ))}
            </div>
          );
        }
        return <span className="text-white-50">-</span>;
      case 'url':
        return (
          <div>
            <a href={asset.url} target="_blank" rel="noopener noreferrer" className="text-info">
              {asset.url}
            </a>
          </div>
        );
      case 'domain':
        return asset.domain || <span className="text-white-50">-</span>;
      case 'port':
        return asset.port || <span className="text-white-50">-</span>;
      case 'protocol':
        return asset.protocol || <span className="text-white-50">-</span>;
      case 'status_code':
        return asset.status_code ? (
          <Badge variant={asset.status_code >= 200 && asset.status_code < 300 ? "success" : "warning"}>
            {asset.status_code}
          </Badge>
        ) : <span className="text-white-50">-</span>;
      case 'title':
        return (
          <div style={{ maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {asset.title || <span className="text-white-50">-</span>}
          </div>
        );
      case 'cloud_provider':
        return asset.cloud_provider || <span className="text-white-50">-</span>;
      case 'cloud_service_type':
        return asset.cloud_service_type || <span className="text-white-50">-</span>;
      case 'cloud_region':
        return asset.cloud_region || <span className="text-white-50">-</span>;
      case 'asset_identifier':
        if (asset.asset_type === 'cloud_asset') {
          return <code className="text-info">{asset.asset_identifier}</code>;
        }
        return <code>{asset.asset_identifier}</code>;
      case 'fqdn':
        return <code>{asset.fqdn}</code>;
      case 'ip_address':
        // Check for A records (IPv4) first
        if (asset.a_records && asset.a_records.length > 0) {
          return (
            <div>
              {asset.a_records.map((ip, index) => (
                <div key={index} className="text-success">
                  <code>{ip}</code>
                </div>
              ))}
            </div>
          );
        }
        // Check for AAAA records (IPv6)
        if (asset.aaaa_records && asset.aaaa_records.length > 0) {
          return (
            <div>
              {asset.aaaa_records.map((ip, index) => (
                <div key={index} className="text-info">
                  <code>{ip}</code>
                </div>
              ))}
            </div>
          );
        }
        // Fallback to resolved_ips array if available
        if (asset.resolved_ips && asset.resolved_ips.length > 0) {
          return (
            <div>
              {asset.resolved_ips.map((ip, index) => (
                <div key={index} className="text-primary">
                  <code>{ip}</code>
                </div>
              ))}
            </div>
          );
        }
        // Final fallback to individual ip_address field
        if (asset.ip_address) {
          return <code>{asset.ip_address}</code>;
        }
        return <span className="text-white-50">-</span>;
      case 'http_response':
        if (asset.url) {
          return (
            <div>
              <div className="text-info">
                <a href={asset.url} target="_blank" rel="noopener noreferrer" className="text-info">
                  {asset.url}
                </a>
              </div>
              {asset.status_code && (
                <Badge variant={asset.status_code >= 200 && asset.status_code < 300 ? "success" : "warning"}>
                  {asset.status_code}
                </Badge>
              )}
              {asset.title && (
                <div className="small text-white-50 mt-1">
                  {asset.title}
                </div>
              )}
            </div>
          );
        }
        return <span className="text-white-50">-</span>;
      case 'ssl_status':
        if (asset.ssl_expiry_date) {
          const expiryDate = new Date(asset.ssl_expiry_date);
          const now = new Date();
          const daysUntilExpiry = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));
          
          let variant = "success";
          let status = "Valid";
          
          if (daysUntilExpiry < 0) {
            variant = "danger";
            status = "Expired";
          } else if (daysUntilExpiry < 30) {
            variant = "warning";
            status = "Expires Soon";
          }
          
          return (
            <div>
              <Badge variant={variant}>{status}</Badge>
              <div className="small text-white-50">
                {asset.ssl_issuer && <div>{asset.ssl_issuer}</div>}
                <div>Expires: {expiryDate.toLocaleDateString()}</div>
                {daysUntilExpiry >= 0 && <div>({daysUntilExpiry} days)</div>}
              </div>
            </div>
          );
        }
        return <span className="text-white-50">No SSL</span>;
      case 'http_status':
        if (asset.status_code) {
          const statusCode = asset.status_code;
          let variant = "secondary";
          
          if (statusCode >= 200 && statusCode < 300) {
            variant = "success";
          } else if (statusCode >= 300 && statusCode < 400) {
            variant = "info";
          } else if (statusCode >= 400 && statusCode < 500) {
            variant = "warning";
          } else if (statusCode >= 500) {
            variant = "danger";
          }
          
          return (
            <div>
              <Badge variant={variant}>{statusCode}</Badge>
              {asset.title && (
                <div className="small text-white-50 mt-1" style={{ maxWidth: '150px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {asset.title}
                </div>
              )}
              {asset.web_server && (
                <div className="small text-muted">
                  {asset.web_server}
                </div>
              )}
            </div>
          );
        }
        return <span className="text-white-50">No HTTP</span>;
      case 'dns_records':
        const dnsRecords = [];
        
        if (asset.a_records && asset.a_records.length > 0) {
          asset.a_records.forEach(record => {
            dnsRecords.push({ type: 'A', value: record, color: 'text-success' });
          });
        }
        
        if (asset.aaaa_records && asset.aaaa_records.length > 0) {
          asset.aaaa_records.forEach(record => {
            dnsRecords.push({ type: 'AAAA', value: record, color: 'text-info' });
          });
        }
        
        if (asset.cname_records && asset.cname_records.length > 0) {
          asset.cname_records.forEach(record => {
            dnsRecords.push({ type: 'CNAME', value: record, color: 'text-warning' });
          });
        }
        
        if (asset.mx_records && asset.mx_records.length > 0) {
          asset.mx_records.forEach(record => {
            dnsRecords.push({ type: 'MX', value: record, color: 'text-danger' });
          });
        }
        
        if (asset.ns_records && asset.ns_records.length > 0) {
          asset.ns_records.forEach(record => {
            dnsRecords.push({ type: 'NS', value: record, color: 'text-primary' });
          });
        }
        
        if (asset.txt_records && asset.txt_records.length > 0) {
          asset.txt_records.forEach(record => {
            dnsRecords.push({ type: 'TXT', value: record, color: 'text-secondary' });
          });
        }
        
        if (asset.ptr_records && asset.ptr_records.length > 0) {
          asset.ptr_records.forEach(record => {
            dnsRecords.push({ type: 'PTR', value: record, color: 'text-light' });
          });
        }
        
                if (asset.srv_records && asset.srv_records.length > 0) {
          asset.srv_records.forEach(record => {
            dnsRecords.push({ type: 'SRV', value: record, color: 'text-muted' });
          });
        }

        // Add special DNS records (SPF, DMARC, DKIM)
        if (asset.spf_record) {
          dnsRecords.push({ type: 'SPF', value: asset.spf_record, color: 'text-success' });
        }
        
        if (asset.dmarc_record) {
          dnsRecords.push({ type: 'DMARC', value: asset.dmarc_record, color: 'text-info' });
        }
        
        if (asset.dkim_record) {
          dnsRecords.push({ type: 'DKIM', value: asset.dkim_record, color: 'text-warning' });
        }

        if (dnsRecords.length > 0) {
          const maxWidth = asset.asset_type === 'fqdn' ? '400px' : (asset.asset_type === 'cloud_asset' ? '350px' : '300px');
          const maxRecords = asset.asset_type === 'fqdn' ? 8 : (asset.asset_type === 'cloud_asset' ? 3 : 5);
          
          return (
            <div style={{ maxWidth }}>
              {dnsRecords.slice(0, maxRecords).map((record, index) => {
                // Truncate long values (especially for SPF, DMARC, DKIM)
                const isLongRecord = ['SPF', 'DMARC', 'DKIM', 'TXT'].includes(record.type);
                const displayValue = isLongRecord && record.value.length > 50 
                  ? record.value.substring(0, 50) + '...' 
                  : record.value;
                
                return (
                  <div key={index} className={`small ${record.color}`} title={record.value}>
                    <strong>{record.type}:</strong> {displayValue}
                  </div>
                );
              })}
              {dnsRecords.length > maxRecords && (
                <div className="small text-muted">
                  +{dnsRecords.length - maxRecords} more records
                </div>
              )}
            </div>
          );
        }
        return <span className="text-white-50">-</span>;
      case 'asset_identifier':
        return <code>{asset.asset_identifier}</code>;
      case 'last_updated':
        return new Date(asset.last_updated).toLocaleDateString();
      default:
        return <span className="text-white-50">-</span>;
    }
  };



  const renderFiltersForTab = () => {
    return (
      <Row className="g-3">
        <Col>
          <div className="mb-3">
            <div className="d-flex justify-content-between align-items-center mb-2">
              <Form.Label className="text-white small mb-0">Search Filters</Form.Label>
              <div>
                <Button 
                  variant="outline-success" 
                  size="sm" 
                  onClick={addSearchFilter}
                  className="me-2"
                >
                  Add Filter
                </Button>
                <Button 
                  variant="outline-danger" 
                  size="sm" 
                  onClick={clearFilters}
                >
                  Clear Filters
                </Button>
              </div>
            </div>
            {filters.map((filter, index) => (
              <div key={index} className={index > 0 ? "mt-2" : ""}>
                <InputGroup>
                  <Form.Control
                    type="text"
                    placeholder="Search across all data points (ASN, IP, domain, organization, etc.)..."
                    value={filter.searchTerm}
                    onChange={(e) => updateSearchFilter(index, 'searchTerm', e.target.value)}
                    data-bs-theme="dark"
                  />
                  <InputGroup.Text className="bg-dark border-secondary">
                    <Form.Check
                      type="checkbox"
                      id={`negative-search-checkbox-${index}`}
                      label="Negative Search"
                      checked={filter.isNegative}
                      onChange={(e) => updateSearchFilter(index, 'isNegative', e.target.checked)}
                      className="text-white-50 small m-0"
                      disabled={!filter.searchTerm}
                    />
                  </InputGroup.Text>
                  {filter.searchTerm && (
                    <Button 
                      variant="outline-secondary" 
                      onClick={() => updateSearchFilter(index, 'searchTerm', '')}
                      title="Clear this search"
                    >
                      ×
                    </Button>
                  )}
                  {filters.length > 1 && (
                    <Button 
                      variant="outline-danger" 
                      onClick={() => removeSearchFilter(index)}
                      title="Remove this filter"
                    >
                      🗑️
                    </Button>
                  )}
                </InputGroup>
              </div>
            ))}
          </div>
        </Col>
      </Row>
    );
  };

  const renderTableHeaders = () => {
    switch (activeTab) {
      case 'asn':
        return [
          {
            key: 'asn_number',
            label: 'ASN Number',
            sortable: true
          },
          {
            key: 'asn_organization',
            label: 'Organization',
            sortable: true
          },
          {
            key: 'asn_country',
            label: 'Country',
            sortable: true
          },
          {
            key: 'asn_description',
            label: 'Description',
            sortable: true
          },
          {
            key: 'last_updated',
            label: 'Last Updated',
            sortable: true
          }
        ];
      case 'network_range':
        return [
          {
            key: 'cidr_block',
            label: 'CIDR Block',
            sortable: true
          },
          {
            key: 'asn_number',
            label: 'ASN',
            sortable: true
          },
          {
            key: 'asn_organization',
            label: 'Organization',
            sortable: true
          },
          {
            key: 'asn_country',
            label: 'Country',
            sortable: true
          },
          {
            key: 'asn_description',
            label: 'Description',
            sortable: true
          },
          {
            key: 'subnet_size',
            label: 'Subnet Size',
            sortable: true
          },
          {
            key: 'last_updated',
            label: 'Last Updated',
            sortable: true
          }
        ];
      case 'ip_address':
        return [
          {
            key: 'ip_address',
            label: 'IP Address',
            sortable: true
          },
          {
            key: 'asn_number',
            label: 'ASN',
            sortable: true
          },
          {
            key: 'asn_organization',
            label: 'Organization',
            sortable: true
          },
          {
            key: 'asn_country',
            label: 'Country',
            sortable: true
          },
          {
            key: 'resolved_ips',
            label: 'DNS Records',
            sortable: false
          },
          {
            key: 'last_updated',
            label: 'Last Updated',
            sortable: true
          }
        ];
      case 'live_web_server':
        return [
          {
            key: 'url',
            label: 'URL',
            sortable: true
          },
          {
            key: 'domain',
            label: 'Domain',
            sortable: true
          },
          {
            key: 'port',
            label: 'Port',
            sortable: true
          },
          {
            key: 'protocol',
            label: 'Protocol',
            sortable: true
          },
          {
            key: 'status_code',
            label: 'Status',
            sortable: true
          },
          {
            key: 'title',
            label: 'Title',
            sortable: true
          },
          {
            key: 'last_updated',
            label: 'Last Updated',
            sortable: true
          }
        ];
      case 'cloud_asset':
        return [
          {
            key: 'asset_identifier',
            label: 'Cloud Domain',
            sortable: true
          },
          {
            key: 'cloud_provider',
            label: 'Provider',
            sortable: true
          },
          {
            key: 'cloud_service_type',
            label: 'Service',
            sortable: true
          },
          {
            key: 'cloud_region',
            label: 'Region',
            sortable: true
          },
          {
            key: 'dns_records',
            label: 'DNS Records',
            sortable: false
          },
          {
            key: 'last_updated',
            label: 'Last Updated',
            sortable: true
          }
        ];
      case 'fqdn':
        return [
          {
            key: 'fqdn',
            label: 'FQDN',
            sortable: true
          },
          {
            key: 'ip_address',
            label: 'IP Address',
            sortable: true
          },
          {
            key: 'dns_records',
            label: 'DNS Records',
            sortable: false
          },
          {
            key: 'asn_number',
            label: 'ASN',
            sortable: true
          },
          {
            key: 'asn_organization',
            label: 'Organization',
            sortable: true
          },
          {
            key: 'ssl_status',
            label: 'SSL Status',
            sortable: true
          },
          {
            key: 'http_status',
            label: 'HTTP Status',
            sortable: true
          },
          {
            key: 'last_updated',
            label: 'Last Updated',
            sortable: true
          }
        ];
      default:
        return [
          {
            key: 'asset_identifier',
            label: 'Identifier',
            sortable: true
          },
          {
            key: 'last_updated',
            label: 'Last Updated',
            sortable: true
          }
        ];
    }
  };

  const counts = getAssetTypeCounts();

  return (
    <>
      <style>{`
        .modal-fullscreen .modal-dialog {
          max-width: 100vw !important;
          width: 100vw !important;
          height: 100vh !important;
          margin: 0 !important;
        }
        .modal-fullscreen .modal-content {
          height: 100vh !important;
          border-radius: 0 !important;
        }
        .modal-fullscreen .modal-body {
          overflow-y: auto !important;
          flex: 1 !important;
        }
        .nav-tabs .nav-link {
          color: #6c757d;
          border: none;
          border-bottom: 2px solid transparent;
        }
        .nav-tabs .nav-link:hover {
          color: #fff;
          border-bottom-color: #6c757d;
        }
        .nav-tabs .nav-link.active {
          color: #dc3545;
          border-bottom-color: #dc3545;
          background: transparent;
        }
        .nav-tabs {
          display: flex;
          width: 100%;
        }
        .nav-tabs .nav-item {
          flex: 1;
          text-align: center;
        }
        .nav-tabs .nav-link {
          width: 100%;
          text-align: center;
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
        }
      `}</style>
      <Modal 
        show={show} 
        onHide={handleClose} 
        size="xl" 
        data-bs-theme="dark"
        dialogClassName="modal-fullscreen"
      >
        <Modal.Header closeButton>
          <Modal.Title className="text-danger">Explore Attack Surface - {activeTarget?.scope_target}</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {loading && (
            <div className="text-center py-4">
              <div className="spinner-border text-danger" role="status">
                <span className="visually-hidden">Loading...</span>
              </div>
              <p className="mt-2 text-white">Loading attack surface assets...</p>
            </div>
          )}

          {error && (
            <Alert variant="danger" dismissible onClose={() => setError(null)}>
              {error}
            </Alert>
          )}

          {!loading && !error && (
            <>
              <Nav variant="tabs" className="mb-4" activeKey={activeTab} onSelect={(k) => setActiveTab(k)}>
                {assetTypes.map((type) => (
                  <Nav.Item key={type.key}>
                    <Nav.Link eventKey={type.key}>
                      {type.label} ({counts[type.key] || 0})
                    </Nav.Link>
                  </Nav.Item>
                ))}
              </Nav>

              <div className="mb-4 p-3 bg-dark rounded border">
                <div className="d-flex justify-content-between align-items-center mb-3">
                  <h6 className="text-white mb-0">
                    <i className="bi bi-funnel me-2"></i>
                    Filter Results
                  </h6>
                  <small className="text-white-50">
                    Showing {filteredAssets.length} of {counts[activeTab] || 0} assets
                    {(() => {
                      const activeFilters = filters.filter(filter => filter.searchTerm.trim() !== '');
                      if (activeFilters.length > 0) {
                        const filterDescriptions = activeFilters.map(filter => 
                          `${filter.isNegative ? 'excluding' : 'including'} "${filter.searchTerm}"`
                        );
                        return (
                          <span className="text-warning">
                            {' '}({filterDescriptions.join(', ')})
                          </span>
                        );
                      }
                      return null;
                    })()}
                  </small>
                </div>
                {renderFiltersForTab()}
              </div>

              <div className="table-responsive" style={{ maxHeight: '60vh', overflowY: 'auto' }}>
                <Table striped bordered hover variant="dark" responsive>
                  <thead>
                    <tr>
                      {renderTableHeaders().map((header) => (
                        <th 
                          key={header.key}
                          style={{ cursor: header.sortable ? 'pointer' : 'default', userSelect: 'none' }}
                          onClick={header.sortable ? () => handleSort(header.key) : undefined}
                        >
                          {header.label} {header.sortable && renderSortIcon(header.key)}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {filteredAssets.map((asset) => (
                      <tr key={asset.id}>
                        {renderTableHeaders().map((header) => (
                          <td key={header.key}>
                            {renderTableCell(asset, header.key)}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </div>

              {filteredAssets.length === 0 && !loading && (
                <div className="text-center py-4">
                  <p className="text-white-50">No assets found matching the current filters.</p>
                </div>
              )}
            </>
          )}
        </Modal.Body>
        <Modal.Footer>
          {activeTab === 'live_web_server' && (
            <Button
              variant="danger"
              onClick={handlePopulateBurpsuite}
              disabled={isPopulatingBurpsuite || filteredAssets.filter(asset => asset.asset_type === 'live_web_server' && asset.url).length === 0}
            >
              {isPopulatingBurpsuite ? (
                <>
                  <Spinner animation="border" size="sm" className="me-2" />
                  Populating...
                </>
              ) : (
                'Populate Burpsuite'
              )}
            </Button>
          )}
          <Button variant="outline-secondary" onClick={handleClose}>
            Close
          </Button>
        </Modal.Footer>
      </Modal>
    </>
  );
};

export default ExploreAttackSurfaceModal; 