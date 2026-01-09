import { useState, useEffect } from 'react';
import { Modal, Form, ListGroup, Button } from 'react-bootstrap';

const DNSRecordsModal = ({ showDNSRecordsModal, handleCloseDNSRecordsModal, dnsRecords = [] }) => {
  const [filterOptions, setFilterOptions] = useState({});
  const [filteredRecords, setFilteredRecords] = useState([]);

  useEffect(() => {
    try {
      const records = Array.isArray(dnsRecords) ? dnsRecords : [];
      const initialFilterOptions = records.reduce((acc, record) => {
        acc[record.type] = true;
        return acc;
      }, {});
      setFilterOptions(initialFilterOptions);
      setFilteredRecords(records);
    } catch {
      setFilterOptions({});
      setFilteredRecords([]);
    }
  }, [dnsRecords]);

  const handleFilterChange = (recordType) => {
    const updatedFilterOptions = {
      ...filterOptions,
      [recordType]: !filterOptions[recordType],
    };

    setFilterOptions(updatedFilterOptions);

    const updatedFilteredRecords = dnsRecords.filter(
      (record) => updatedFilterOptions[record.type]
    );
    setFilteredRecords(updatedFilteredRecords);
  };

  return (
    <Modal data-bs-theme="dark" show={showDNSRecordsModal} onHide={handleCloseDNSRecordsModal} size="lg">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">DNS Records</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <div className="mb-3 d-flex justify-content-center">
          <Button
            variant="outline-danger"
            className="w-75"
            onClick={() => alert('Testing for subdomain takeover')}
          >
            Test For Subdomain Takeover
          </Button>
        </div>
        <Form className="d-flex justify-content-between flex-wrap">
          {Array.isArray(dnsRecords) && dnsRecords.length > 0 ? (
            Array.from(new Set(dnsRecords.map((record) => record.type))).map((recordType) => (
              <Form.Check
                className="text-danger custom-checkbox"
                key={recordType}
                type="checkbox"
                label={recordType}
                checked={filterOptions[recordType] || false}
                onChange={() => handleFilterChange(recordType)}
              />
            ))
          ) : (
            <p>No DNS records available</p>
          )}
        </Form>
        <ListGroup className="mt-3">
          {filteredRecords.map((record) => (
            <ListGroup.Item key={record.id}>{record.record}</ListGroup.Item>
          ))}
        </ListGroup>
      </Modal.Body>
    </Modal>
  );
};

const SubdomainsModal = ({ showSubdomainsModal, handleCloseSubdomainsModal, subdomains = [] }) => {
  const subs = Array.isArray(subdomains) ? subdomains : [];
  return (
    <Modal data-bs-theme="dark" show={showSubdomainsModal} onHide={handleCloseSubdomainsModal} size="lg">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Subdomains</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <ListGroup className="mt-3">
          {subs.map((subdomain, index) => (
            <ListGroup.Item key={index}>{subdomain}</ListGroup.Item>
          ))}
        </ListGroup>
      </Modal.Body>
    </Modal>
  );
};

const CloudDomainsModal = ({ showCloudDomainsModal, handleCloseCloudDomainsModal, cloudDomains = [] }) => {
  const [filterOptions, setFilterOptions] = useState({});
  const [filteredDomains, setFilteredDomains] = useState([]);

  useEffect(() => {
    try {
      const domains = Array.isArray(cloudDomains) ? cloudDomains : [];
      const initialFilterOptions = domains.reduce((acc, domain) => {
        if (domain && domain.type) {
          acc[domain.type] = true;
        }
        return acc;
      }, {});
      setFilterOptions(initialFilterOptions);
      setFilteredDomains(domains);
    } catch (error) {
      console.error('Error processing cloud domains:', error);
      setFilterOptions({});
      setFilteredDomains([]);
    }
  }, [cloudDomains]);

  const handleFilterChange = (cloudType) => {
    const updatedFilterOptions = {
      ...filterOptions,
      [cloudType]: !filterOptions[cloudType],
    };

    setFilterOptions(updatedFilterOptions);

    const updatedFilteredDomains = (Array.isArray(cloudDomains) ? cloudDomains : []).filter(
      (domain) => domain && domain.type && updatedFilterOptions[domain.type]
    );
    setFilteredDomains(updatedFilteredDomains);
  };

  return (
    <Modal data-bs-theme="dark" show={showCloudDomainsModal} onHide={handleCloseCloudDomainsModal} size="lg">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Cloud Domains</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Form className="d-flex flex-wrap gap-5 justify-content-center px-3">
          {Array.from(new Set((Array.isArray(cloudDomains) ? cloudDomains : [])
            .filter(domain => domain && domain.type)
            .map((domain) => domain.type))).map((cloudType) => (
            <Form.Check
              className="text-primary custom-checkbox"
              key={cloudType}
              type="checkbox"
              label={cloudType}
              checked={filterOptions[cloudType] || false}
              onChange={() => handleFilterChange(cloudType)}
            />
          ))}
        </Form>

        <ListGroup className="mt-3">
          {(Array.isArray(filteredDomains) ? filteredDomains : []).map((domain, index) => (
            <ListGroup.Item key={index}>{domain && domain.name}</ListGroup.Item>
          ))}
        </ListGroup>
      </Modal.Body>
    </Modal>
  );
};

const InfrastructureMapModal = ({ showInfraModal, handleCloseInfraModal, scanId }) => {
  const [infraData, setInfraData] = useState({
    asns: [],
    serviceProviders: [],
    subnets: [],
    dnsRecords: []
  });

  useEffect(() => {
    if (scanId && scanId !== 'No scans available') {
      Promise.all([
        fetch(`/api/amass/${scanId}/asn`),
        fetch(`/api/amass/${scanId}/sp`),
        fetch(`/api/amass/${scanId}/subnet`),
        fetch(`/api/amass/${scanId}/dns`)
      ])
        .then(async ([asnRes, spRes, subnetRes, dnsRes]) => {
          try {
            const [asns, serviceProviders, subnets, dnsRecords] = await Promise.all([
              asnRes.json(),
              spRes.json(),
              subnetRes.json(),
              dnsRes.json()
            ]);

            // Ensure arrays and add null checks
            const safeAsns = Array.isArray(asns) ? asns : [];
            const safeServiceProviders = Array.isArray(serviceProviders) ? serviceProviders : [];
            const safeSubnets = Array.isArray(subnets) ? subnets : [];
            const safeDnsRecords = Array.isArray(dnsRecords) ? dnsRecords : [];

            // Remove duplicate ASNs based on ASN number
            const uniqueAsns = [...new Map(safeAsns
              .filter(item => item && item.raw_data)
              .map(item => {
                const match = item.raw_data.match(/^\d+/);
                const asnNumber = match ? match[0] : null;
                return asnNumber ? [asnNumber, item] : null;
              })
              .filter(Boolean))
              .values()];

            setInfraData({ 
              asns: uniqueAsns, 
              serviceProviders: safeServiceProviders, 
              subnets: safeSubnets, 
              dnsRecords: safeDnsRecords 
            });
          } catch (error) {
            console.error('Error processing infrastructure data:', error);
            setInfraData({
              asns: [],
              serviceProviders: [],
              subnets: [],
              dnsRecords: []
            });
          }
        })
        .catch(error => {
          console.error('Error fetching infrastructure data:', error);
          setInfraData({
            asns: [],
            serviceProviders: [],
            subnets: [],
            dnsRecords: []
          });
        });
    }
  }, [scanId]);

  const getSubnetsForAsn = (asn) => {
    try {
      if (!asn || !asn.raw_data) return [];
      const match = asn.raw_data.match(/^\d+/);
      if (!match) return [];
      const asnNumber = match[0];
      return (Array.isArray(infraData.subnets) ? infraData.subnets : [])
        .filter(subnet => subnet && subnet.raw_data && 
          subnet.raw_data.includes(`${asnNumber} (ASN) --> announces`));
    } catch (error) {
      console.error('Error getting subnets for ASN:', error);
      return [];
    }
  };

  const getDnsRecordsForSubnet = (subnet) => {
    try {
      if (!subnet || !subnet.raw_data) return [];
      const match = subnet.raw_data.match(/([0-9a-f:./]+)\s+\(Netblock\)/i);
      if (!match) return [];
      const subnetCidr = match[1];
      return (Array.isArray(infraData.dnsRecords) ? infraData.dnsRecords : [])
        .filter(record => {
          if (!record || !record.record) return false;
          const ipMatch = record.record.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
          if (!ipMatch) return false;
          
          const ip = ipMatch[0];
          const [subnetBase, mask] = subnetCidr.split('/');
          if (!subnetBase || !mask) return false;
          
          // Simple IP matching - could be enhanced with proper subnet calculation
          return ip.startsWith(subnetBase.split('.').slice(0, mask >= 24 ? 3 : 2).join('.'));
        });
    } catch (error) {
      console.error('Error getting DNS records for subnet:', error);
      return [];
    }
  };

  const getUnassociatedDnsRecords = () => {
    try {
      const allSubnets = (Array.isArray(infraData.subnets) ? infraData.subnets : [])
        .map(subnet => {
          if (!subnet || !subnet.raw_data) return null;
          const match = subnet.raw_data.match(/([0-9a-f:./]+)\s+\(Netblock\)/i);
          return match ? match[1] : null;
        })
        .filter(Boolean);

      return (Array.isArray(infraData.dnsRecords) ? infraData.dnsRecords : [])
        .filter(record => {
          if (!record || !record.record) return true; // Include records without valid data
          const ipMatch = record.record.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
          if (!ipMatch) return true; // Include records without IPs
          
          const ip = ipMatch[0];
          return !allSubnets.some(subnetCidr => {
            if (!subnetCidr) return false;
            const [subnetBase, mask] = subnetCidr.split('/');
            if (!subnetBase || !mask) return false;
            return ip.startsWith(subnetBase.split('.').slice(0, mask >= 24 ? 3 : 2).join('.'));
          });
        });
    } catch (error) {
      console.error('Error getting unassociated DNS records:', error);
      return [];
    }
  };

  return (
    <Modal 
      data-bs-theme="dark" 
      show={showInfraModal} 
      onHide={handleCloseInfraModal} 
      size="xl" 
      fullscreen={true}
    >
      <Modal.Header closeButton>
        <Modal.Title style={{ color: '#FF4500' }}>Infrastructure Map</Modal.Title>
      </Modal.Header>
      <Modal.Body style={{ backgroundColor: '#1a1a1a' }}>
        <div style={{ padding: '20px', overflowY: 'auto', height: 'calc(100vh - 120px)', fontFamily: 'monospace' }}>
          {(Array.isArray(infraData.asns) ? infraData.asns : []).map((asn, i) => (
            <div key={i} className="mb-4">
              <ul style={{ listStyleType: "none", padding: "0", margin: "0" }}>
                <li>
                  <span style={{ color: '#FF4500' }}>{asn && asn.raw_data}</span>
                  <ul style={{ listStyleType: "none", padding: "0", margin: "0" }}>
                    {getSubnetsForAsn(asn).map((subnet, j) => (
                      <li key={j} style={{ paddingLeft: "100px", color: '#FFD700' }}>
                        {subnet.raw_data}
                        <ul style={{ listStyleType: "none", padding: "0", margin: "0" }}>
                          {getDnsRecordsForSubnet(subnet).map((record, k) => (
                            <li key={k} style={{ paddingLeft: "100px", color: '#FF8C00' }}>
                              {record.record}
                              {record.record && record.record.split(" ")[0] && (
                                <span style={{ marginLeft: '10px', color: '#FF6B6B' }}>
                                  --- LINK: <a 
                                    href={`https://${record.record.split(" ")[0]}`} 
                                    target="_blank" 
                                    rel="noreferrer"
                                    style={{ color: '#FFA07A', textDecoration: 'none' }}
                                  >
                                    {`https://${record.record.split(" ")[0]}`}
                                  </a>
                                </span>
                              )}
                            </li>
                          ))}
                        </ul>
                      </li>
                    ))}
                  </ul>
                </li>
              </ul>
            </div>
          ))}
          {getUnassociatedDnsRecords().length > 0 && (
            <div className="mb-4">
              <ul style={{ listStyleType: "none", padding: "0", margin: "0" }}>
                <li>
                  <span style={{ color: '#FF4500' }}>Unknown ASN</span>
                  <ul style={{ listStyleType: "none", padding: "0", margin: "0" }}>
                    <li style={{ paddingLeft: "100px", color: '#FFD700' }}>
                      Unknown Subnet
                      <ul style={{ listStyleType: "none", padding: "0", margin: "0" }}>
                        {getUnassociatedDnsRecords().map((record, k) => (
                          <li key={k} style={{ paddingLeft: "100px", color: '#FF8C00' }}>
                            {record.record}
                            {record.record && record.record.split(" ")[0] && (
                              <span style={{ marginLeft: '10px', color: '#FF6B6B' }}>
                                --- LINK: <a 
                                  href={`https://${record.record.split(" ")[0]}`} 
                                  target="_blank" 
                                  rel="noreferrer"
                                  style={{ color: '#FFA07A', textDecoration: 'none' }}
                                >
                                  {`https://${record.record.split(" ")[0]}`}
                                </a>
                              </span>
                            )}
                          </li>
                        ))}
                      </ul>
                    </li>
                  </ul>
                </li>
              </ul>
            </div>
          )}
        </div>
      </Modal.Body>
    </Modal>
  );
};

export { DNSRecordsModal, SubdomainsModal, CloudDomainsModal, InfrastructureMapModal };
